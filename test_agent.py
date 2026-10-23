#!/usr/bin/env python3
"""
Plain-Python test for embroidery_agent.py — not part of `npm test`, since this agent has nothing
to do with the Cloudflare app itself.

These machines ("SmartStitch"-branded) speak a proprietary UDP discovery protocol and a
proprietary TCP JSON listing protocol, reverse-engineered from a real Wireshark capture — not
FTP. This test starts the real agent as a subprocess and exercises /ping, /discover (against a
throwaway UDP stub "machine"), and /list (against a throwaway TCP stub "machine", including a
multi-page response, since the real protocol pages results), /send (against a stub that speaks
the real upload protocol), /read (against a stub that sends a file back the way the machine
does), /delete (refused clearly, 501 — disabled in firmware), and the
lockdown that keeps any other web page from driving the agent (Origin/Host/Content-Type checks,
download-link and machine-IP allowlists). The agent runs with TEST_MODE = True so the stubs'
loopback addresses and port overrides are accepted.

Run: python3 test_agent.py
"""

import base64
import json
import os
import tempfile
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer

AGENT_PORT = 8797  # a different port than production's 8787, so this can run alongside it
AGENT_URL = f"http://127.0.0.1:{AGENT_PORT}"
results = []


def check(label, ok):
    results.append((label, ok))
    print(f"{label}: {ok}")


# ---- A throwaway UDP "machine" answering the discovery broadcast ----------------------------
class StubDiscoveryMachine:
    """Listens for the 4-byte discovery payload and replies with a crafted packet in the real
    reply shape (MAC at bytes 9:15, firmware at 20:45, model at 45:75)."""

    EXPECTED_PAYLOAD = bytes.fromhex("ff 04 02 fb")

    def __init__(self, mac="AA:BB:CC:DD:EE:FF", model="SmartStitch S1000", firmware="v2.3.1"):
        self.mac = mac
        self.model = model
        self.firmware = firmware
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _build_reply(self):
        # Mirror the real machine reply layout: MAC at 9:15, NUL-terminated firmware at byte 19,
        # NUL-terminated model at byte 51 (both variable length in the real captures).
        mac_bytes = bytes(int(b, 16) for b in self.mac.split(":"))
        packet = bytearray(84)
        packet[9:15] = mac_bytes
        fw = self.firmware.encode()[:31]
        packet[19:19 + len(fw)] = fw
        model = self.model.encode()[:29]
        packet[51:51 + len(model)] = model
        return bytes(packet)

    def _serve(self):
        self._sock.settimeout(0.2)
        while self._running:
            try:
                data, addr = self._sock.recvfrom(1024)
            except socket.timeout:
                continue
            except OSError:
                return
            if data == self.EXPECTED_PAYLOAD:
                self._sock.sendto(self._build_reply(), addr)

    def stop(self):
        self._running = False
        time.sleep(0.05)
        self._sock.close()


# ---- A throwaway TCP "machine" answering the paginated listing protocol ---------------------
class StubListingMachine:
    """Emits the file listing the way a real machine does: one JSON document
    ({"num":N,"files":[...]}) split into PAGES at arbitrary byte boundaries (not object boundaries),
    each page framed as `fa 01 <len16 LE> 01 00 cf 26 <page16> <field16> <up-to-CHUNK JSON bytes>
    <lrc>`. This exercises the agent's real reassembly: strip each page's 12-byte prefix and trailing
    LRC, concatenate, parse once. A page size small enough to split the JSON mid-object is used on
    purpose. After the last page, a header-only frame signals the end."""

    CHUNK = 64  # small, so the JSON splits mid-object across several pages

    def __init__(self, files):
        self.doc = json.dumps({"num": len(files), "files": files}).encode()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(5)
        self.port = self._sock.getsockname()[1]
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @staticmethod
    def _lrc(b):
        x = 0
        for c in b:
            x ^= c
        return x

    def _page_frame(self, page):
        start = (page - 1) * self.CHUNK
        chunk = self.doc[start:start + self.CHUNK]
        body = bytes([0x01, 0x00, 0xCF, 0x26]) + page.to_bytes(2, "little") + bytes([0x02, 0x00]) + chunk
        head = b"\xfa\x01" + (len(body) + 1).to_bytes(2, "little") + body
        return head + bytes([self._lrc(head)])

    def _serve(self):
        while self._running:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            conn.settimeout(2.0)
            while True:
                frame = conn.recv(11)
                if not frame or len(frame) < 11:
                    break
                page = frame[8] | (frame[9] << 8)
                if (page - 1) * self.CHUNK < len(self.doc):
                    conn.sendall(self._page_frame(page))
                else:
                    # Past the end: a header-only frame with no JSON chunk = "no more pages".
                    body = bytes([0x01, 0x00, 0xCF, 0x26]) + page.to_bytes(2, "little")
                    head = b"\xfa\x01" + (len(body) + 1).to_bytes(2, "little") + body
                    conn.sendall(head + bytes([self._lrc(head)]))
        except (OSError, ConnectionError):
            pass
        finally:
            conn.close()

    def stop(self):
        self._running = False
        try:
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("127.0.0.1", self.port))
        except OSError:
            pass
        self._sock.close()


# ---- A throwaway TCP "machine" that RECEIVES an upload the way the real one does -------------
class StubReceivingMachine:
    """Speaks the real send protocol back at the agent: validates every frame's LRC, acks the
    cf25 registration and each cf23 data block, and reassembles the streamed payload so the test
    can confirm the exact file bytes arrived in order."""

    def __init__(self):
        self.received = bytearray()
        self.registered_name = None
        self.bad_lrc = False
        self.block_count_fields = set()  # the total-block-count field seen on each data frame
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.port = self._sock.getsockname()[1]
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @staticmethod
    def _lrc(b):
        x = 0
        for c in b:
            x ^= c
        return x

    @classmethod
    def _reply(cls, body):
        head = b"\xfa\x01" + (len(body) + 1).to_bytes(2, "little") + body
        return head + bytes([cls._lrc(head)])

    def _read_frame(self, conn):
        header = b""
        while len(header) < 4:
            c = conn.recv(4 - len(header))
            if not c:
                return None
            header += c
        remaining = header[2] | (header[3] << 8)
        body = b""
        while len(body) < remaining:
            c = conn.recv(remaining - len(body))
            if not c:
                break
            body += c
        return header + body

    def _serve(self):
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return
        conn.settimeout(3.0)
        try:
            while self._running:
                frame = self._read_frame(conn)
                if not frame:
                    break
                if self._lrc(frame[:-1]) != frame[-1]:
                    self.bad_lrc = True
                op = frame[6:8]
                if op == bytes([0xCF, 0x25]):           # registration
                    self.registered_name = frame[9:-1].decode("ascii", "ignore")
                    body = bytes([0x01, 0x00, 0xCF, 0x22, 0x01, 0x00, 0x00]) + frame[9:-1]
                    conn.sendall(self._reply(body))
                elif op == bytes([0xCF, 0x23]):         # data block
                    page = frame[8] | (frame[9] << 8)
                    self.block_count_fields.add(frame[10] | (frame[11] << 8))
                    self.received += frame[12:-1]
                    conn.sendall(self._reply(bytes([0x01, 0x00, 0xCF, 0x22, (page + 1) & 0xFF, 0x00])))
        except (OSError, ConnectionError):
            pass
        finally:
            conn.close()

    def stop(self):
        self._running = False
        try:
            self._sock.close()
        except OSError:
            pass


# ---- A throwaway TCP "machine" that SENDS a file back the way the real one does -------------
class StubSendingMachine:
    """Answers the read request (01 00 cf 22 01 00 00 <name>) by streaming the file in cf23 blocks
    (page16, total16, up to 1024 bytes), waiting for the computer's cf22 <page+1> ack before each
    next block — the shapes in a capture of the vendor app copying a file off a machine. An unknown
    name gets cf e0; `corrupt_page` breaks one block's LRC."""

    def __init__(self, files, corrupt_page=None):
        self.files = files
        self.corrupt_page = corrupt_page
        self.requested = None
        self.acks = []
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.port = self._sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    _reply = StubReceivingMachine._reply
    _read_frame = StubReceivingMachine._read_frame

    def _serve(self):
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return
        conn.settimeout(3.0)
        try:
            f = self._read_frame(conn)
            if not f or f[6:11] != bytes([0xCF, 0x22, 0x01, 0x00, 0x00]):
                return
            self.requested = f[11:-1].decode("utf-8")
            data = self.files.get(self.requested)
            if data is None:
                conn.sendall(self._reply(bytes([0x01, 0x00, 0xCF, 0xE0])))
                return
            total = (len(data) + 1023) // 1024
            for page in range(1, total + 1):
                out = self._reply(bytes([0x01, 0x00, 0xCF, 0x23]) + page.to_bytes(2, "little")
                                  + total.to_bytes(2, "little") + data[(page - 1) * 1024:page * 1024])
                if page == self.corrupt_page:
                    out = out[:-1] + bytes([out[-1] ^ 0xFF])
                conn.sendall(out)
                if page < total:
                    ack = self._read_frame(conn)
                    if not ack:
                        return
                    self.acks.append(ack[6:-1].hex())
        except (OSError, ConnectionError):
            pass
        finally:
            conn.close()

    def stop(self):
        try:
            self._sock.close()
        except OSError:
            pass


class _FileServer(BaseHTTPRequestHandler):
    payload = b""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(self.payload)))
        self.end_headers()
        self.wfile.write(self.payload)

    def log_message(self, *a):
        pass


def start_file_server(payload):
    _FileServer.payload = payload
    httpd = HTTPServer(("127.0.0.1", 0), _FileServer)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


ADMIN_ORIGIN = "https://admin.example.com"
HERE = os.path.dirname(os.path.abspath(__file__))
_TMP = tempfile.mkdtemp(prefix="agent-test-")


def agent_script(test_mode=True, **replace):
    """A copy of the agent to run in a subprocess (a file, not `python -c`: the source is longer than
    Windows allows on a command line). test_mode flips TEST_MODE; `replace` swaps constants."""
    src = open(os.path.join(HERE, "embroidery_agent.py"), encoding="utf-8").read()
    if test_mode:
        src = src.replace("TEST_MODE = False", "TEST_MODE = True")
    for old, new in replace.items():
        assert old in src, old
        src = src.replace(old, new)
    path = os.path.join(_TMP, f"agent_{len(os.listdir(_TMP))}.py")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(src)
    return path


def get_json(url, timeout=15, headers=None):
    req = urllib.request.Request(url, headers={"Origin": ADMIN_ORIGIN} if headers is None else headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def post_json(url, payload, timeout=15, headers=None):
    hdrs = {"Content-Type": "application/json", "Origin": ADMIN_ORIGIN} if headers is None else headers
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST", headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


class StubRelaySite(BaseHTTPRequestHandler):
    """Stands in for /api/agent: hands out a scripted job list one per poll and records results."""
    jobs = []        # popped front-first, one per poll
    results = {}
    polls = 0
    bad_token = 0
    TOKEN = "x" * 40

    def do_POST(self):
        cls = StubRelaySite
        if self.headers.get("X-Agent-Token") != cls.TOKEN:
            cls.bad_token += 1
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        if "op=poll" in self.path:
            cls.polls += 1
            out = {"status": "ok", "job": cls.jobs.pop(0) if cls.jobs else None, "pollSeconds": 1}
        else:
            cls.results[body["id"]] = body
            out = {"status": "ok"}
        raw = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        pass


def relay_tests():
    """Relay mode: the agent connects OUT, runs jobs with the same code as the loopback server, and
    refuses a stale job."""
    now_ms = int(time.time() * 1000)
    payload = bytes(range(256)) * 5 + b"END"          # 1283 bytes -> 2 blocks
    httpd, file_port = start_file_server(payload)
    recv = StubReceivingMachine()
    StubRelaySite.jobs = [
        {"id": "stale0000000000000000", "type": "send", "issuedAt": now_ms - 600_000, "machineIp": "127.0.0.1",
         "downloadUrl": f"http://127.0.0.1:{file_port}/d.dst", "fileName": "OLD.DST"},
        {"id": "send00000000000000000", "type": "send", "issuedAt": now_ms, "machineIp": "127.0.0.1",
         "downloadUrl": f"http://127.0.0.1:{file_port}/d.dst", "fileName": "RELAY.DST"},
        {"id": "pub000000000000000000", "type": "list", "issuedAt": now_ms, "machineIp": "8.8.8.8"},
        {"id": "del000000000000000000", "type": "delete", "issuedAt": now_ms, "machineIp": "127.0.0.1", "fileName": "x.dst"},
        {"id": "bad000000000000000000", "type": "bogus", "issuedAt": now_ms},
    ]
    StubRelaySite.results = {}
    StubRelaySite.polls = 0
    StubRelaySite.bad_token = 0
    site = ThreadingHTTPServer(("127.0.0.1", 0), StubRelaySite)
    threading.Thread(target=site.serve_forever, daemon=True).start()
    # The stub machine listens on a high port; the real agent always uses 6000, so point the module's
    # constant at the stub for this run.
    src = agent_script(**{"TCP_LIST_PORT = 6000": f"TCP_LIST_PORT = {recv.port}"})
    agent = subprocess.Popen([sys.executable, src, "--relay", f"http://127.0.0.1:{site.server_address[1]}",
                              "--token", StubRelaySite.TOKEN], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        deadline = time.time() + 20
        while time.time() < deadline and len(StubRelaySite.results) < 4:
            time.sleep(0.2)
        time.sleep(0.3)
        res = StubRelaySite.results
        check("=== relay mode ===\nagent polls the site with the right token", StubRelaySite.polls >= 1 and StubRelaySite.bad_token == 0)
        check("a stale job (10 minutes old) is dropped, never run", "stale0000000000000000" not in res and recv.registered_name != "OLD.DST")
        sent = res.get("send00000000000000000", {})
        check("a send job runs the real upload and reports ok (200)", sent.get("httpStatus") == 200 and sent.get("body", {}).get("status") == "ok")
        check("the machine received the exact file, unpadded, with correct LRCs", bytes(recv.received) == payload and recv.bad_lrc is False)
        check("a public machine IP is refused (400)", res.get("pub000000000000000000", {}).get("httpStatus") == 400)
        check("delete reports firmware-unsupported (501)", res.get("del000000000000000000", {}).get("httpStatus") == 501)
        check("an unknown job type is refused (400)", res.get("bad000000000000000000", {}).get("httpStatus") == 400)
        check("the agent keeps polling after jobs (loop survives)", StubRelaySite.polls >= 5)
    finally:
        agent.terminate()
        try:
            agent.wait(timeout=5)
        except subprocess.TimeoutExpired:
            agent.kill()
        site.shutdown()
        recv.stop()
        httpd.shutdown()

    # Relay mode refuses to start with a short token, or pointed at a foreign host.
    base = agent_script(test_mode=False)
    p = subprocess.run([sys.executable, base, "--relay", "https://admin.example.com", "--token", "short"],
                       capture_output=True, text=True, timeout=10)
    check("a too-short token is refused at startup", p.returncode != 0 and "token" in (p.stderr + p.stdout).lower())
    p = subprocess.run([sys.executable, base, "--relay", "http://admin.example.com", "--token", "x" * 40],
                       capture_output=True, text=True, timeout=10)
    check("a relay that isn't https is refused at startup", p.returncode != 0 and "https://" in (p.stderr + p.stdout))
    p = subprocess.run([sys.executable, base, "--site", "https://admin.example.com/some/path"],
                       capture_output=True, text=True, timeout=10)
    check("a --site with a path is refused at startup", p.returncode != 0 and "just the site's address" in (p.stderr + p.stdout))
    p = subprocess.run([sys.executable, base, "--site", "http://admin.example.com"],
                       capture_output=True, text=True, timeout=10)
    check("an http:// --site is refused at startup", p.returncode != 0 and "https://" in (p.stderr + p.stdout))


def relay_read_tests():
    """A read job in relay mode: the agent copies the file off the machine and answers with it (base64); one
    bigger than the relay can carry is refused with a plain message."""
    now_ms = int(time.time() * 1000)
    small = b"LA:relay" + bytes(2000)
    sender = StubSendingMachine({"Relay Patch.005": small})
    StubRelaySite.jobs = [{"id": "read0000000000000000a", "type": "read", "issuedAt": now_ms, "machineIp": "127.0.0.1",
                           "fileName": "Relay Patch.005"}]
    StubRelaySite.results = {}
    site = ThreadingHTTPServer(("127.0.0.1", 0), StubRelaySite)
    threading.Thread(target=site.serve_forever, daemon=True).start()
    src = agent_script(**{"TCP_LIST_PORT = 6000": f"TCP_LIST_PORT = {sender.port}",
                          "RELAY_MAX_READ_BYTES = 1_000_000": "RELAY_MAX_READ_BYTES = 1_500"})
    agent = subprocess.Popen([sys.executable, src, "--relay", f"http://127.0.0.1:{site.server_address[1]}",
                              "--token", StubRelaySite.TOKEN], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        deadline = time.time() + 15
        while time.time() < deadline and "read0000000000000000a" not in StubRelaySite.results:
            time.sleep(0.2)
        res = StubRelaySite.results.get("read0000000000000000a", {})
        # The stub file is 2008 bytes and this run's relay limit is 1500, so it must be refused, not sent.
        check("=== relay read job ===\na file over the relay limit is refused with a plain message (413)",
              res.get("httpStatus") == 413 and "too big" in res.get("body", {}).get("message", "") and sender.requested == "Relay Patch.005")
    finally:
        agent.terminate()
        try:
            agent.wait(timeout=5)
        except subprocess.TimeoutExpired:
            agent.kill()
        sender.stop()

    # Same again with the real limit: the file comes back whole.
    sender = StubSendingMachine({"Relay Patch.005": small})
    StubRelaySite.jobs = [{"id": "read0000000000000000b", "type": "read", "issuedAt": int(time.time() * 1000),
                           "machineIp": "127.0.0.1", "fileName": "Relay Patch.005"}]
    src = agent_script(**{"TCP_LIST_PORT = 6000": f"TCP_LIST_PORT = {sender.port}"})
    agent = subprocess.Popen([sys.executable, src, "--relay", f"http://127.0.0.1:{site.server_address[1]}",
                              "--token", StubRelaySite.TOKEN], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        deadline = time.time() + 15
        while time.time() < deadline and "read0000000000000000b" not in StubRelaySite.results:
            time.sleep(0.2)
        res = StubRelaySite.results.get("read0000000000000000b", {})
        body = res.get("body", {})
        check("a read job copies the file off the machine and answers with it (200)",
              res.get("httpStatus") == 200 and base64.b64decode(body.get("dataBase64", "")) == small and body.get("ext") == "DSB")
    finally:
        agent.terminate()
        try:
            agent.wait(timeout=5)
        except subprocess.TimeoutExpired:
            agent.kill()
        sender.stop()
        site.shutdown()


def main():
    proc = subprocess.Popen(
        [sys.executable, agent_script(), "--site", "https://Admin.Example.com/", "--port", str(AGENT_PORT)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    time.sleep(0.5)  # give it a moment to bind

    try:
        # 1. /ping
        status, data = get_json(f"{AGENT_URL}/ping")
        check("=== /ping ===\nagent responds to /ping", data.get("ok") is True)

        # 2. /discover against the UDP stub — addressed directly (not broadcast; loopback
        #    broadcast isn't reliable across platforms), which is exactly what the override
        #    params exist for.
        stub_machine = StubDiscoveryMachine(mac="AA:BB:CC:DD:EE:FF", model="SmartStitch S1000", firmware="v2.3.1")
        status, data = get_json(
            f"{AGENT_URL}/discover?targetPort={stub_machine.port}&listenPort=0&windowSeconds=1&broadcastIp=127.0.0.1",
            timeout=10,
        )
        machines = data.get("machines", [])
        found = next((m for m in machines if m["mac"] == "AA:BB:CC:DD:EE:FF"), None)
        check("=== /discover ===\nfinds the stub machine", status == 200 and found is not None)
        check("MAC parsed correctly", found and found["mac"] == "AA:BB:CC:DD:EE:FF")
        check("model parsed correctly", found and found["model"] == "SmartStitch S1000")
        check("firmware parsed correctly", found and found["firmware"] == "v2.3.1")
        stub_machine.stop()

        # 3. /list — multi-page: 3 files, page 1 returns 2 as a full object, page 2 returns the
        #    3rd as a bare continuation fragment (the real capture's awkward shape).
        files = [
            {"name": "logo-a.dst", "size": 12345, "date": "2026-01-01"},
            {"name": "logo-b.dst", "size": 23456, "date": "2026-01-02"},
            {"name": "logo-c.dst", "size": 34567, "date": "2026-01-03"},
        ]
        stub_list = StubListingMachine(files)
        status, data = post_json(f"{AGENT_URL}/list", {"machineIp": "127.0.0.1", "machinePort": stub_list.port}, timeout=15)
        got_names = sorted(f["name"] for f in data.get("files", []))
        check("=== /list (multi-page) ===\nagent reports ok", status == 200 and data.get("status") == "ok")
        check("all 3 files across both pages are returned", got_names == ["logo-a.dst", "logo-b.dst", "logo-c.dst"])
        got = {f["name"]: f for f in data.get("files", [])}
        check("size/modified carried through for a page-1 file", got.get("logo-a.dst", {}).get("size") == 12345 and got.get("logo-a.dst", {}).get("modified") == "2026-01-01")
        check("size/modified carried through for the page-2 (continuation) file", got.get("logo-c.dst", {}).get("size") == 34567 and got.get("logo-c.dst", {}).get("modified") == "2026-01-03")
        stub_list.stop()

        # 4. /list — single page (fewer files than a page holds).
        stub_list2 = StubListingMachine([{"name": "only.dst", "size": 111, "date": "2026-02-01"}])
        status, data = post_json(f"{AGENT_URL}/list", {"machineIp": "127.0.0.1", "machinePort": stub_list2.port}, timeout=15)
        check("=== /list (single page) ===\nreturns exactly the one file", status == 200 and [f["name"] for f in data.get("files", [])] == ["only.dst"])
        stub_list2.stop()

        # 5. /list — unreachable machine, must fail clearly, not hang.
        start = time.time()
        status, data = post_json(f"{AGENT_URL}/list", {"machineIp": "10.255.255.1", "machinePort": 6000}, timeout=15)
        elapsed = time.time() - start
        check("=== /list unreachable machine ===\nfails with a clear error", status == 502 and "message" in data)
        check("times out within a bounded window (doesn't hang forever)", elapsed < 15)

        # 6. /send — end to end against a stub machine that speaks the real upload protocol.
        #    Payload spans 2+ pages so chunking and the short final block are both exercised.
        design_bytes = bytes(range(256)) * 9 + b"TAIL"   # 2308 bytes -> pages of 1024,1024,260
        httpd, file_port = start_file_server(design_bytes)
        recv = StubReceivingMachine()
        status, data = post_json(f"{AGENT_URL}/send", {
            "downloadUrl": f"http://127.0.0.1:{file_port}/design.dst",
            "machineIp": "127.0.0.1", "machinePort": recv.port, "fileName": "SENDTEST.DST",
        }, timeout=20)
        time.sleep(0.2)
        check("=== /send (real protocol against a stub machine) ===\nagent reports ok", status == 200 and data.get("status") == "ok")
        check("machine registered the exact filename", recv.registered_name == "SENDTEST.DST")
        check("every frame the agent sent had a correct LRC", recv.bad_lrc is False)
        check("all file bytes arrived in order, unpadded", bytes(recv.received) == design_bytes)
        check("agent reports the right block count (2308 bytes -> 3 blocks)", data.get("blocks") == 3)
        # Every data frame must declare the TOTAL block count (3) in the two bytes after the page
        # number — the machine uses it to know when to commit. Hardcoding it wrong is what made
        # real sends stall/never commit.
        check("every data frame carries the correct total-block-count field (3)",
              recv.block_count_fields == {3})
        recv.stop()
        httpd.shutdown()

        # /read — copy a file off a stub machine that sends it back the real way: 13 blocks, the
        # last one short, the computer acking every block but the last.
        design = b"LA:sample" + bytes(503) + bytes((i * 11) % 256 for i in range(12234))  # 12746 B
        sender = StubSendingMachine({"Sample Patch.002": design})
        status, data = post_json(f"{AGENT_URL}/read", {"machineIp": "127.0.0.1", "machinePort": sender.port,
                                                         "fileName": "Sample Patch.002"}, timeout=20)
        time.sleep(0.2)
        check("=== /read (real protocol against a stub machine) ===\nagent reports ok", status == 200 and data.get("status") == "ok")
        check("asked for the file by its listed name", sender.requested == "Sample Patch.002")
        check("the exact bytes came back (base64)", base64.b64decode(data.get("dataBase64", "")) == design)
        check("size, block count and .DSB extension reported",
              data.get("bytes") == 12746 and data.get("blocks") == 13 and data.get("ext") == "DSB")
        check("acked blocks 1-12 with cf22 <page+1>, nothing after the last",
              sender.acks == ["cf22" + (p + 1).to_bytes(2, "little").hex() for p in range(1, 13)])
        sender.stop()

        sender = StubSendingMachine({"马头机~1.008": b"LA:x" + bytes(600)})
        status, data = post_json(f"{AGENT_URL}/read", {"machineIp": "127.0.0.1", "machinePort": sender.port,
                                                         "fileName": "马头机~1.008"}, timeout=20)
        check("a non-ASCII name is sent as UTF-8 and a one-block file reads",
              status == 200 and sender.requested == "马头机~1.008" and data.get("bytes") == 604 and sender.acks == [])
        sender.stop()

        sender = StubSendingMachine({})
        status, data = post_json(f"{AGENT_URL}/read", {"machineIp": "127.0.0.1", "machinePort": sender.port,
                                                         "fileName": "Missing.009"}, timeout=20)
        check("an unknown file is refused clearly (502)", status == 502 and "refused to send" in data.get("message", ""))
        sender.stop()

        sender = StubSendingMachine({"Sample Patch.002": design}, corrupt_page=4)
        status, data = post_json(f"{AGENT_URL}/read", {"machineIp": "127.0.0.1", "machinePort": sender.port,
                                                         "fileName": "Sample Patch.002"}, timeout=20)
        check("a damaged block is reported, not returned (502)", status == 502 and "Block 4" in data.get("message", ""))
        sender.stop()

        status, data = post_json(f"{AGENT_URL}/read", {"machineIp": "127.0.0.1"})
        check("/read without a fileName is refused (400)", status == 400)
        status, _ = post_json(f"{AGENT_URL}/read", {"machineIp": "127.0.0.1", "fileName": "x.002"},
                              headers={"Content-Type": "application/json", "Origin": "https://evil.example"})
        check("/read from another site's Origin is refused (403)", status == 403)
        status, data = post_json(f"{AGENT_URL}/read", {"machineIp": "8.8.8.8", "fileName": "x.002"})
        check("/read to a public IP is refused (400)", status == 400)

        # /delete — the delete opcode (cf24) is present but disabled in firmware (see PROTOCOL.md
        # §6); must refuse clearly (501) rather than attempt a write.
        status, data = post_json(f"{AGENT_URL}/delete", {"machineIp": "127.0.0.1", "fileName": "x.dst"})
        check("=== /delete (firmware-disabled) ===\nrefuses clearly with 501", status == 501 and "isn't supported" in data.get("message", "").lower())

        # 7. Validation.
        status, data = post_json(f"{AGENT_URL}/list", {})
        check("=== validation ===\nmissing machineIp is rejected with 400", status == 400)

        # 8. Lockdown: any OTHER web page the operator visits can reach 127.0.0.1 too, so the
        #    agent must refuse anything that isn't the admin site, before doing any work.
        send_body = {"downloadUrl": "https://admin.example.com/api/design?k=x",
                     "machineIp": "192.168.1.50", "fileName": "X.DST"}
        status, _ = post_json(f"{AGENT_URL}/send", send_body,
                              headers={"Content-Type": "application/json", "Origin": "https://evil.example"})
        check("=== lockdown ===\na POST from another site's Origin is refused (403)", status == 403)
        status, _ = post_json(f"{AGENT_URL}/send", send_body, headers={"Content-Type": "application/json"})
        check("a POST with no Origin is refused (403)", status == 403)
        status, _ = post_json(f"{AGENT_URL}/send", send_body,
                              headers={"Content-Type": "text/plain", "Origin": ADMIN_ORIGIN})
        check("a text/plain (no-preflight) POST is refused (415)", status == 415)
        status, _ = post_json(f"{AGENT_URL}/send", send_body,
                              headers={"Content-Type": "application/json", "Origin": ADMIN_ORIGIN,
                                       "Host": "attacker.example:8787"})
        check("a rebinding-style Host header is refused (403)", status == 403)
        status, _ = get_json(f"{AGENT_URL}/discover", headers={"Origin": "https://evil.example"})
        check("/discover from another site's Origin is refused (403)", status == 403)
        status, data = get_json(f"{AGENT_URL}/ping", headers={})
        check("/ping still answers without an Origin (manual checks)", status == 200 and data.get("ok") is True)
        status, data = post_json(f"{AGENT_URL}/send", {**send_body, "downloadUrl": "file:///etc/passwd"})
        check("a file:// download link is refused (400)", status == 400 and "admin site" in data.get("message", ""))
        status, data = post_json(f"{AGENT_URL}/send", {**send_body, "downloadUrl": "https://evil.example/api/design"})
        check("a download link on another host is refused (400)", status == 400)
        status, data = post_json(f"{AGENT_URL}/send", {**send_body, "machineIp": "8.8.8.8"})
        check("a public (internet) machine IP is refused (400)", status == 400 and "shop network" in data.get("message", ""))
        status, data = post_json(f"{AGENT_URL}/list", {"machineIp": "not-an-ip"})
        check("a non-IP machine address is refused (400)", status == 400)

        # 9. An agent told no site at all: /ping answers, everything else is refused and says how to fix it.
        bare_port = AGENT_PORT + 1
        bare = subprocess.Popen([sys.executable, agent_script(), "--port", str(bare_port)],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            time.sleep(0.5)
            bare_url = f"http://127.0.0.1:{bare_port}"
            status, data = get_json(f"{bare_url}/ping", headers={})
            check("=== no --site ===\n/ping still answers", status == 200 and data.get("ok") is True)
            status, data = post_json(f"{bare_url}/list", {"machineIp": "127.0.0.1"})
            check("a browser call is refused (403) with a message naming --site", status == 403 and "--site" in data.get("message", ""))
            status, _ = get_json(f"{bare_url}/discover")
            check("/discover is refused too", status == 403)
        finally:
            bare.terminate()
            try:
                bare.wait(timeout=5)
            except subprocess.TimeoutExpired:
                bare.kill()

        # 10. The configured site is matched as an origin: case and a trailing slash don't matter
        #     (the agent above was started with "https://Admin.Example.com/").
        req = urllib.request.Request(f"{AGENT_URL}/ping", headers={"Origin": ADMIN_ORIGIN})
        with urllib.request.urlopen(req, timeout=5) as resp:
            allow = resp.headers.get("Access-Control-Allow-Origin")
        check("=== --site normalised ===\nthe site's origin gets the CORS header", allow == ADMIN_ORIGIN)

        relay_tests()
        relay_read_tests()

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    failed = [label for label, ok in results if not ok]
    if failed:
        print(f"\n{len(failed)} check(s) failed: {failed}")
        sys.exit(1)
    print(f"\nAll {len(results)} checks passed.")


if __name__ == "__main__":
    main()
