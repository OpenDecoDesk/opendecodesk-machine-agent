#!/usr/bin/env python3
"""
OpenDecoDesk machine agent — lets a web admin (OpenDecoDesk's Run Order and Machine Files screens,
or any site that speaks the same small API) find SmartStitch embroidery machines on the local
network, list their files, send a design to one and copy a file back off it.

WHY THIS EXISTS: a browser has no API to open a raw UDP/TCP socket, and a website's servers can't
reach a machine's private LAN address either. This is a small, dependency-free program that runs
on a computer on the SAME local network as the embroidery machines and speaks the machines' own
protocol directly.

THE PROTOCOL: these are "SmartStitch"-branded machines. They are NOT plain FTP servers. Discovery,
listing, upload and reading a file back were reverse-engineered from Wireshark captures of the
vendor's own software talking to a machine (full reference: PROTOCOL.md):
  - Discovery: a UDP broadcast on port 23 with a fixed 4-byte payload; each machine on the LAN
    replies with a packet carrying its MAC (bytes 9:15) and two NUL-terminated strings — firmware
    at byte 19 and model/name at byte 51.
  - Listing: a TCP connection on port 6000; the machine returns one JSON document
    ({"num":N,"files":[…]}) split across framed "pages" (11-byte command frame per page). The
    split falls at arbitrary byte boundaries, so list_machine_dir strips each page's 12-byte prefix
    and its 1-byte trailing LRC, concatenates the raw JSON chunks, and parses the whole thing once.

SENDING A DESIGN is implemented (see the SEND_* constants and send_design_to_machine below): it
was reverse-engineered byte-for-byte from a real Wireshark capture of the vendor's software
uploading a design, plus extra captures made specifically to expose how the frames' trailing
check byte is built. Every frame — list command, registration, data block, and the
machine's replies — is  fa 01 <len16 LE> <body> <lrc>,  where the trailing <lrc> is just the XOR
of all preceding bytes in the frame. Upload = register the filename (cf25), then stream the raw
design bytes 1024 per page (cf23), reading the machine's ack after each.

READING A FILE BACK is the upload run in reverse (decoded from a capture of the vendor app copying
a file off the machine): the computer names the file in a cf22 frame and the machine streams it in
cf23 blocks, which the computer acks. What comes back is the machine's stored form — a DST-style
header with Barudan (.DSB) records — whatever format was uploaded. See read_file_from_machine.

NOT AVAILABLE: deleting a file. The firmware has the command (cf24) but answers every use of it
with a refusal, so /delete returns a clear "not supported" rather than guessing at a write that
could wedge the machine (PROTOCOL.md §6). Files are cleared at the machine's touchscreen.

WHO MAY USE IT: only the admin site(s) given with --site (or ODD_AGENT_SITES). Two ways to run:
  - Loopback (default): listens on http://127.0.0.1:8787 — never reachable from another computer.
    Browsers treat localhost as "secure", so the HTTPS admin page may call it although it's plain
    HTTP; the site's Content-Security-Policy must allow connect-src http://127.0.0.1:8787.
  - Relay (--relay https://admin.yourshop.example --token …): connects OUT to the site's
    /api/agent and runs the jobs a phone or tablet queued there.

Endpoints:
  GET  /ping                          -> 200 {"ok": true}
  GET  /discover                      -> 200 {"status": "ok", "machines": [{"ip","mac","model","firmware"}]}
                                          (sweeps the LAN for ~1.5s; no request body)
  POST /list   body: {machineIp}      -> 200 {"status": "ok", "files": [{"name","size","modified"}]}
  POST /send   body: {downloadUrl, machineIp, fileName}
                                       -> 200 {"status": "ok", "fileName", "bytes", "blocks"}
  POST /read   body: {machineIp, fileName}   (fileName exactly as /list reports it, e.g. "LOGO.012")
                                       -> 200 {"status": "ok", "fileName", "bytes", "blocks", "ext": "DSB",
                                               "dataBase64"}   (also a relay job, up to RELAY_MAX_READ_BYTES)
  POST /delete body: {machineIp, fileName}
                                       -> 501 {"status": "error", "message": "..."} (not yet supported)

Run it:
  python3 embroidery_agent.py --site https://admin.yourshop.example
  python3 embroidery_agent.py --relay https://admin.yourshop.example --token <the site's AGENT_TOKEN>

No dependencies beyond the Python standard library (http.server + socket + urllib) — nothing to
pip install. See README.md for running it as a service.
"""

import base64
import ipaddress
import json
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_PORT = 8787
PORT = DEFAULT_PORT
AGENT_NAME = "opendecodesk-machine-agent"


def log(msg):
    """Print a timestamped line to the agent's console so sends/failures are visible in the field."""
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

# The admin site(s) allowed to use this agent, as origins ("https://admin.yourshop.example"), set by
# configure() from --site / --relay. Any other web page the operator happens to visit can also reach
# 127.0.0.1 (a text/plain "no-cors" POST needs no preflight), so this is an ACCESS check, not just a
# CORS-header choice: a request whose Origin isn't listed is refused before anything is fetched,
# listed or sent. The same origins are the only places a design file is downloaded from
# (<origin>/api/design, the site's signed-link endpoint). Empty = nobody (only /ping answers).
ALLOWED_ORIGINS = set()
ALLOWED_DOWNLOAD_PATH = "/api/design"

# Host headers this agent answers to. Checking it blocks DNS rebinding (an attacker's domain
# re-resolved to 127.0.0.1 would arrive with its own name in Host, and as a same-origin request).
ALLOWED_HOSTS = {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}

NO_SITE_MESSAGE = ("This agent hasn't been told which admin site may use it — start it with "
                   "--site https://admin.yourshop.example (or set ODD_AGENT_SITES).")


def site_origin(url):
    """The origin of an admin-site URL given on the command line ("https://admin.x.example/" →
    "https://admin.x.example"). https only (an http loopback site is allowed in test mode); no
    path, user name or password. Raises ValueError with a message for the operator."""
    try:
        u = urllib.parse.urlsplit(str(url).strip())
        port = u.port
    except ValueError:
        raise ValueError(f"Not a site address: {url!r}")
    loopback_test = TEST_MODE and u.scheme == "http" and u.hostname == "127.0.0.1"
    if (u.scheme != "https" and not loopback_test) or not u.hostname:
        raise ValueError(f"The admin site must be an https:// address: {url!r}")
    if u.username or u.password or u.path not in ("", "/") or u.query or u.fragment:
        raise ValueError(f"Give just the site's address, e.g. https://admin.yourshop.example: {url!r}")
    default = 443 if u.scheme == "https" else 80
    return f"{u.scheme}://{u.hostname.lower()}" + (f":{port}" if port and port != default else "")


def configure(sites, port=DEFAULT_PORT):
    """Sets who may use the agent and where it listens. `sites` are admin-site URLs."""
    global ALLOWED_ORIGINS, ALLOWED_HOSTS, PORT
    ALLOWED_ORIGINS = {site_origin(s) for s in sites if str(s).strip()}
    PORT = int(port)
    ALLOWED_HOSTS = {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}


# Set to True ONLY by test_agent.py (it rewrites this line before running the agent).
# Test mode re-allows what the stubs need — loopback machine IPs, an http://127.0.0.1 download
# link, and the machinePort / discovery overrides — none of which the real admin page ever sends.
TEST_MODE = False

DOWNLOAD_TIMEOUT_SECONDS = 30
MAX_DOWNLOAD_BYTES = 20 * 1024 * 1024

# ---- Machine discovery (UDP broadcast) --------------------------------------------------
UDP_BROADCAST_IP = "255.255.255.255"
UDP_TARGET_PORT = 23      # machine's listening discovery port
UDP_LISTEN_PORT = 60023   # this computer's listening port for replies
DISCOVERY_PAYLOAD = bytes.fromhex("ff 04 02 fb")
DISCOVERY_WINDOW_SECONDS = 1.5

# ---- File listing (TCP, port 6000) ------------------------------------------------------
TCP_LIST_PORT = 6000
LIST_CONNECT_TIMEOUT_SECONDS = 2.0
LIST_PAGE_READ_SECONDS = 2.0
MAX_LIST_PAGES = 64  # ~1024 JSON bytes/page, ~14 files/page -> safety cap well above any real machine
                     # (we stop early anyway once the machine's declared `num` files are all in)

# ---- Sending a design (TCP, port 6000) --------------------------------------------------
# Reverse-engineered byte-for-byte from a real Wireshark capture of the vendor's own software
# uploading a design, cross-checked against several more captures made on purpose
# (files named A.DST/B.DST/AA.DST/BB.DST specifically to expose how the trailing byte is built).
#
# Every frame in this protocol — list command, registration, data block, and the machine's
# replies — has the same shape:  fa 01 <len16 little-endian> <body...> <lrc>  where len16 is
# len(body)+1 (body plus the one lrc byte) and <lrc> is simply the XOR of every byte in the
# frame BEFORE it (fa, 01, both length bytes, and the whole body). That single fact was verified
# against 8 registration frames of differing names/lengths, both 1024-byte data frames from the
# capture, and every reply frame — it reproduces all of them exactly. (The old list-command
# "0x13 - page" formula was just this same XOR written a harder way.)
#
# Upload sequence, straight from the capture:
#   1. Register the filename:  body = 01 00 cf 25 00 <filename ASCII>
#      -> machine replies with a cf 22 frame echoing the name.
#   2. Send the raw design-file bytes in order, 1024 bytes per "page" (pages numbered from 1):
#      body = 01 00 cf 23 <page16 LE> <totalBlocks16 LE> <up to 1024 file bytes>
#      -> machine replies with a short cf 22 ack ("ready for the next page") after each block
#         EXCEPT the last, after which it just commits the file and TCP-acks (no cf 22). Waiting
#         for a cf 22 on the final block makes a whole, already-landed send look like it "timed
#         out". The LAST block carries only the remaining bytes and is NOT padded. The
#         <totalBlocks> field is constant for the whole
#         file (ceil(size/1024)); the machine uses it to know when the transfer is complete and to
#         commit the file — captures showed 0x0032 (50) for a 50-block file and 0x0016 (22) for a
#         22-block one. Getting it wrong makes the machine wait forever for blocks that never come
#         (declared too many) or reject the block past the declared count with a cf e1 error.
SEND_CONNECT_TIMEOUT_SECONDS = 3.0
SEND_ACK_TIMEOUT_SECONDS = 6.0
SEND_CHUNK_BYTES = 1024
_ERROR_STATUS_BYTE = 0xC9  # seen in a cf22 status frame when the machine rejects a transfer


# Reading a file back: what the machine sends is its stored form (a DST-style header followed by
# Barudan records), so it's named .DSB whatever was uploaded.
READ_EXT = "DSB"
MAX_READ_BLOCKS = MAX_DOWNLOAD_BYTES // SEND_CHUNK_BYTES


DELETE_UNSUPPORTED_MESSAGE = ("Deleting a file isn't supported by this machine's firmware "
                              "(the delete command, cf24, is present but disabled) — clear files "
                              "at the touchscreen. See PROTOCOL.md §6.")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """The signed design link never redirects; refusing redirects keeps a validated URL from
    being bounced somewhere else (another host, or another scheme)."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_download_opener = urllib.request.build_opener(_NoRedirect)


def validate_download_url(download_url):
    """Returns None if `download_url` is a link this agent may fetch, else an operator-facing
    reason. Only the admin site's own https signed-link endpoint is allowed (plus a loopback
    http stub in test mode) — never file://, ftp://, or an arbitrary host."""
    try:
        u = urllib.parse.urlsplit(download_url)
    except ValueError:
        return "Invalid download link."
    if TEST_MODE and u.scheme == "http" and u.hostname == "127.0.0.1":
        return None
    try:
        origin = site_origin(f"{u.scheme}://{u.netloc}")
    except ValueError:
        return "Download link must come from the admin site."
    if u.scheme != "https" or origin not in ALLOWED_ORIGINS:
        return "Download link must come from the admin site."
    if u.path != ALLOWED_DOWNLOAD_PATH or u.username or u.password:
        return "Download link must come from the admin site."
    return None


def validate_machine_ip(machine_ip):
    """Returns None if `machine_ip` is a private-network IPv4 address (where embroidery machines
    live), else an operator-facing reason. Keeps the agent from being pointed at a host on the
    internet, or (outside test mode) at this computer itself."""
    try:
        ip = ipaddress.ip_address(machine_ip)
    except ValueError:
        return "Machine IP must be an IPv4 address on the shop network."
    if ip.version != 4 or ip.is_multicast or ip.is_unspecified:
        return "Machine IP must be an IPv4 address on the shop network."
    if ip.is_loopback:
        return None if TEST_MODE else "Machine IP must be an address on the shop network."
    if not ip.is_private:
        return "Machine IP must be an address on the shop network (a private LAN address)."
    return None


def fetch_design_file(download_url):
    """Downloads the design file from the signed admin link. Raises RuntimeError with a message
    safe to show the operator on any failure."""
    problem = validate_download_url(download_url)
    if problem:
        raise RuntimeError(problem)
    req = urllib.request.Request(download_url, headers={"User-Agent": f"{AGENT_NAME}/{AGENT_VERSION}"})
    try:
        with _download_opener.open(req, timeout=DOWNLOAD_TIMEOUT_SECONDS) as resp:
            data = resp.read(MAX_DOWNLOAD_BYTES + 1)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise RuntimeError("Download link has expired — reopen the screen and try again.")
        raise RuntimeError(f"Could not download the design file (HTTP {e.code}).")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Could not reach the download link: {e.reason}")
    except socket.timeout:
        raise RuntimeError("Timed out downloading the design file.")
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise RuntimeError("Design file is larger than expected — refusing to send.")
    if not data:
        raise RuntimeError("Downloaded file was empty.")
    return data


def discover_machines(target_port=UDP_TARGET_PORT, listen_port=UDP_LISTEN_PORT,
                       window_seconds=DISCOVERY_WINDOW_SECONDS, broadcast_ip=UDP_BROADCAST_IP):
    """Broadcasts the discovery payload on the LAN and collects replies for `window_seconds`.
    Returns a list of {ip, mac, model, firmware} — one per distinct IP that answered. Raises
    RuntimeError if the discovery socket itself can't be opened (e.g. the port is already in use
    by another instance of this agent, or by the vendor's own software running at the same time).
    target_port/listen_port/broadcast_ip default to the real values (23 / 60023 / 255.255.255.255);
    overridable only so this can be exercised in tests against a throwaway stub on a high,
    unprivileged port addressed directly (loopback broadcast isn't reliable across platforms)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except AttributeError:
        pass  # not available on this platform; SO_REUSEADDR above is enough on most
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    try:
        sock.bind(("", listen_port))
    except OSError as e:
        raise RuntimeError(f"Could not listen for machine replies on UDP port {listen_port}: {e}")

    sock.settimeout(window_seconds)
    sock.sendto(DISCOVERY_PAYLOAD, (broadcast_ip, target_port))

    machines = []
    seen_ips = set()
    deadline = time.time() + window_seconds
    try:
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, addr = sock.recvfrom(1024)
            except socket.timeout:
                break
            ip_str = addr[0]
            if ip_str in seen_ips:
                continue
            seen_ips.add(ip_str)

            # Real reply layout, confirmed against two different machines (a 1201plus and a
            # 1501ultra): MAC at bytes 9:15, then a NUL-terminated firmware string starting at
            # byte 19, then a NUL-terminated model/name string starting at byte 51. Both string
            # fields are variable length (firmware prefixes seen so far: "JD…", "HH1S…"), so they
            # must be read as NUL-terminated strings, not sliced at a fixed end offset — an earlier
            # version sliced firmware at [20:45] (dropping its first character) and model at [45:75]
            # (which lands on the padding NULs before the name, losing the model entirely).
            def _cstr(buf, start):
                if start >= len(buf):
                    return ""
                return buf[start:].split(b"\x00")[0].decode("utf-8", errors="ignore").strip()

            mac_str = ":".join(f"{b:02X}" for b in data[9:15]) if len(data) >= 15 else ""
            firmware_str = _cstr(data, 19)
            model_str = _cstr(data, 51) or "SmartStitch Node"

            machines.append({"ip": ip_str, "mac": mac_str, "model": model_str, "firmware": firmware_str})
    finally:
        sock.close()

    return machines


def _build_list_command(page_num):
    """The 11-byte command frame requesting one page of a machine's file listing: the fixed header
    `fa 01 07 00 01 00 cf 21`, the page number, `00`, and the frame's LRC (XOR of all the preceding
    bytes — the same check every frame in this protocol uses). An earlier version wrote the last
    byte as `(0x13 - page)`, which happens to equal the LRC only for pages 1–3 (0x13 is the fixed
    header's XOR) and is WRONG for page 4 and up, so machines with more than ~3 pages of files
    couldn't be fully listed."""
    frame = [0xFA, 0x01, 0x07, 0x00, 0x01, 0x00, 0xCF, 0x21, page_num & 0xFF, 0x00]
    return bytes(frame + [_lrc(frame)])


def list_machine_dir(machine_ip, machine_port=TCP_LIST_PORT):
    """Fetch a machine's file list over one TCP connection.

    The machine returns the listing as a single JSON document ({"num":N,"files":[{name,size,date},
    ...]}) split across "pages": each page is a framed response
    `fa 01 <len16> 01 00 cf 26 <page16 LE> <field16> <JSON chunk> <lrc>` carrying up to 1024 bytes
    of the JSON byte-stream. The split happens at arbitrary byte boundaries (mid-object, even
    mid-key), so the pages CANNOT be parsed independently — we strip each page's 12-byte prefix and
    its 1-byte trailing LRC, concatenate the raw JSON chunks, and parse the whole thing once. (The
    earlier per-page "patch the fragment into valid JSON" approach silently dropped files and, on
    one machine, returned nothing at all — and it kept the trailing LRC byte, which corrupts the
    JSON exactly at each 1024-byte page seam.) Raises RuntimeError on connection failure."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(LIST_CONNECT_TIMEOUT_SECONDS)
    try:
        sock.connect((machine_ip, machine_port))
    except (socket.timeout, OSError) as e:
        sock.close()
        raise RuntimeError(f"Could not connect to {machine_ip}: {e}")

    try:
        time.sleep(0.15)  # matches the reference capture's timing between connect and first command
        sock.settimeout(LIST_PAGE_READ_SECONDS)
        chunks = []
        for page in range(1, MAX_LIST_PAGES + 1):
            sock.sendall(_build_list_command(page))
            try:
                frame = _recv_frame(sock)
            except socket.timeout:
                break
            if frame is None or len(frame) <= 13:  # a header-only / empty frame = no more pages
                break
            chunks.append(frame[12:-1])  # drop the 12-byte prefix and the trailing LRC byte
            # Stop as soon as the concatenated JSON is complete (all `num` files present), so we
            # don't wait on a trailing empty page.
            try:
                parsed = json.loads(b"".join(chunks).decode("utf-8", errors="ignore"))
                if len(parsed.get("files", [])) >= parsed.get("num", 0):
                    break
            except (ValueError, json.JSONDecodeError):
                pass  # still incomplete — read the next page

        try:
            parsed = json.loads(b"".join(chunks).decode("utf-8", errors="ignore"))
        except (ValueError, json.JSONDecodeError):
            return []
        return [{"name": f.get("name", ""), "size": f.get("size"), "modified": f.get("date")}
                for f in parsed.get("files", [])]
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _lrc(frame_without_trailer):
    """The trailing check byte on every frame in this protocol: XOR of all preceding bytes."""
    x = 0
    for b in frame_without_trailer:
        x ^= b
    return x


def _frame(body):
    """Wrap a body in the protocol's envelope: fa 01 <len16 LE> <body> <lrc>."""
    head = bytes([0xFA, 0x01]) + (len(body) + 1).to_bytes(2, "little") + body
    return head + bytes([_lrc(head)])


def _recv_frame(sock):
    """Read one whole reply frame (fa 01 <len16> <body+lrc>). Returns the frame bytes, or None
    if the machine sent nothing / an unparseable header before the socket timed out."""
    header = b""
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            return None
        header += chunk
    if header[0] != 0xFA or header[1] != 0x01:
        return None
    remaining = header[2] | (header[3] << 8)
    body = b""
    while len(body) < remaining:
        chunk = sock.recv(remaining - len(body))
        if not chunk:
            break
        body += chunk
    return header + body


def _reply_is_error(frame):
    """A cf22 status reply signals rejection with the error byte in its status slot."""
    if not frame or len(frame) < 10:
        return False
    if frame[6:8] != bytes([0xCF, 0x22]):
        return False
    return _ERROR_STATUS_BYTE in frame[8:11]


def send_design_to_machine(machine_ip, file_name, file_bytes, machine_port=TCP_LIST_PORT):
    """Upload a design file to a SmartStitch machine over its real protocol (see the block
    comment by the SEND_* constants for the full derivation). Raises RuntimeError with an
    operator-facing message on any failure. Returns a short status dict on success."""
    try:
        name_bytes = file_name.encode("ascii")
    except UnicodeEncodeError:
        raise RuntimeError("Machine filenames must be plain ASCII — rename the design's machine file.")
    if not name_bytes:
        raise RuntimeError("No machine filename to register with the machine.")

    total = len(file_bytes)
    total_blocks = (total + SEND_CHUNK_BYTES - 1) // SEND_CHUNK_BYTES
    log(f"SEND start: {machine_ip}:{machine_port} file={file_name!r} {total} bytes -> {total_blocks} blocks")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(SEND_CONNECT_TIMEOUT_SECONDS)
    try:
        sock.connect((machine_ip, machine_port))
    except (socket.timeout, OSError) as e:
        sock.close()
        log(f"SEND fail: could not connect to {machine_ip}: {e}")
        raise RuntimeError(f"Could not connect to {machine_ip}: {e}")

    try:
        time.sleep(0.15)  # match the capture's pause between connect and first frame
        sock.settimeout(SEND_ACK_TIMEOUT_SECONDS)

        # 1. Register the filename.
        registration = _frame(bytes([0x01, 0x00, 0xCF, 0x25, 0x00]) + name_bytes)
        log(f"  -> registration ({len(registration)} B): {registration.hex()}")
        sock.sendall(registration)
        ack = _recv_frame(sock)
        log(f"  <- registration reply: {ack.hex() if ack else '(none)'}")
        if ack is None:
            raise RuntimeError("Machine did not acknowledge the filename (no reply). Make sure the "
                               "vendor's own app is closed and the machine is idle.")
        if _reply_is_error(ack):
            raise RuntimeError("Machine rejected the filename registration.")

        # 2. Stream the raw file bytes, 1024 per page, pages numbered from 1. Last chunk is short.
        #    Every data frame declares the TOTAL block count (little-endian, constant per file) in
        #    the two bytes after the page number — the machine uses it to know when the transfer is
        #    complete and to commit the file. (A capture of a 50-block send carried 0x0032 here; a
        #    22-block send carried 0x0016. Hardcoding it wrong makes the machine either wait forever
        #    for blocks that never come, or reject the block past the count it was told to expect.)
        # The machine cf22-acks every block with "ready for the next page" — EXCEPT the final
        # block, after which it just commits the file and TCP-acks (no cf22 frame). So we wait for
        # an ack on every block but the last; waiting on the last is what made whole sends "time
        # out" even though the file had already landed (confirmed against a real capture: the last
        # data packet is followed only by a bare TCP ACK).
        total_field = total_blocks.to_bytes(2, "little")
        page = 1
        offset = 0
        while offset < total:
            chunk = file_bytes[offset:offset + SEND_CHUNK_BYTES]
            body = (bytes([0x01, 0x00, 0xCF, 0x23]) + page.to_bytes(2, "little")
                    + total_field + chunk)
            sock.sendall(_frame(body))
            is_last = page == total_blocks
            if is_last:
                # No cf22 ack expected. Peek briefly only to catch an explicit error reply.
                sock.settimeout(1.0)
                try:
                    tail = _recv_frame(sock)
                except socket.timeout:
                    tail = None
                sock.settimeout(SEND_ACK_TIMEOUT_SECONDS)
                log(f"  block {page}/{total_blocks} ({len(chunk)} B, final) -> "
                    f"{tail.hex() if tail else 'no cf22 ack (expected)'}")
                if _reply_is_error(tail):
                    raise RuntimeError(f"Machine rejected the final block of the design.")
                break
            block_ack = _recv_frame(sock)
            if page == 1 or block_ack is None or _reply_is_error(block_ack):
                log(f"  block {page}/{total_blocks} ({len(chunk)} B) <- ack: "
                    f"{block_ack.hex() if block_ack else '(none)'}")
            if block_ack is None:
                raise RuntimeError(f"Transfer stalled after block {page} (no acknowledgment).")
            if _reply_is_error(block_ack):
                raise RuntimeError(f"Machine rejected block {page} of the design.")
            offset += len(chunk)
            page += 1

        log(f"SEND ok: {file_name!r} delivered in {total_blocks} blocks")
        return {"fileName": file_name, "bytes": total, "blocks": total_blocks}
    except socket.timeout:
        log("SEND fail: timed out waiting for the machine")
        raise RuntimeError("Timed out waiting for the machine during the transfer.")
    finally:
        try:
            sock.close()
        except Exception:
            pass



def read_file_from_machine(machine_ip, stored_name, machine_port=TCP_LIST_PORT):
    """Copy one file off a machine, by the name its listing shows (sequence number included,
    e.g. "LOGO.012"). Decoded from a Wireshark capture of the vendor's app doing it, and checked
    byte-for-byte against that capture on a real machine:
      -> 01 00 cf 22 01 00 00 <stored name UTF-8>        (the shape of the upload-registration echo)
      <- 01 00 cf 23 <page16 LE> <totalBlocks16 LE> <up to 1024 bytes>   pages from 1
      -> 01 00 cf 22 <page+1 16 LE>                      ack each block EXCEPT the last
    Returns {"fileName", "data", "blocks", "ext"}. Raises RuntimeError with an operator-facing
    message on any failure."""
    name_bytes = stored_name.encode("utf-8")  # the listing JSON is UTF-8; non-ASCII names read fine
    if not name_bytes:
        raise RuntimeError("No file name to ask the machine for.")
    log(f"READ start: {machine_ip}:{machine_port} file={stored_name!r}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(SEND_CONNECT_TIMEOUT_SECONDS)
    try:
        sock.connect((machine_ip, machine_port))
    except (socket.timeout, OSError) as e:
        sock.close()
        raise RuntimeError(f"Could not connect to {machine_ip}: {e}")

    try:
        time.sleep(0.15)
        sock.settimeout(SEND_ACK_TIMEOUT_SECONDS)
        sock.sendall(_frame(bytes([0x01, 0x00, 0xCF, 0x22, 0x01, 0x00, 0x00]) + name_bytes))
        data = bytearray()
        page = 1
        while True:
            frame = _recv_frame(sock)
            if frame is None:
                if page == 1:
                    raise RuntimeError(f"The machine didn't send {stored_name}. Make sure the vendor's "
                                       "own app is closed and the machine is idle.")
                raise RuntimeError(f"The machine stopped sending {stored_name} after block {page - 1}.")
            if len(frame) < 13 or frame[6:8] != bytes([0xCF, 0x23]):
                raise RuntimeError(f"The machine refused to send {stored_name}.")
            if _lrc(frame[:-1]) != frame[-1]:
                raise RuntimeError(f"Block {page} of {stored_name} arrived damaged — try again.")
            got_page = frame[8] | (frame[9] << 8)
            total = frame[10] | (frame[11] << 8)
            if got_page != page or not 1 <= total <= MAX_READ_BLOCKS:
                raise RuntimeError(f"The machine sent {stored_name} out of order — try again.")
            data += frame[12:-1]
            if page >= total:
                break
            sock.sendall(_frame(bytes([0x01, 0x00, 0xCF, 0x22]) + (page + 1).to_bytes(2, "little")))
            page += 1
        if not data:
            raise RuntimeError(f"The machine sent {stored_name} empty.")
        log(f"READ ok: {stored_name!r} {len(data)} bytes in {page} blocks")
        return {"fileName": stored_name, "data": bytes(data), "blocks": page, "ext": READ_EXT}
    except socket.timeout:
        log("READ fail: timed out waiting for the machine")
        raise RuntimeError("Timed out waiting for the machine while copying the file.")
    finally:
        try:
            sock.close()
        except Exception:
            pass

class Handler(BaseHTTPRequestHandler):
    def _cors_origin(self):
        origin = self.headers.get("Origin", "")
        return origin if origin in ALLOWED_ORIGINS else None

    def _refuse_untrusted(self, require_origin=True):
        """Sends a 403 and returns True unless the request is addressed to this agent by its
        loopback name (blocks DNS rebinding) and — when `require_origin` — comes from one of the
        admin sites. Browsers always attach Origin to a cross-origin fetch, so a page on any other
        site is refused here before the agent does anything on its behalf."""
        if self.headers.get("Host", "") not in ALLOWED_HOSTS:
            self._send_json({"status": "error", "message": "Forbidden"}, 403)
            return True
        if require_origin and not ALLOWED_ORIGINS:
            self._send_json({"status": "error", "message": NO_SITE_MESSAGE}, 403)
            return True
        if require_origin and self.headers.get("Origin", "") not in ALLOWED_ORIGINS:
            self._send_json({"status": "error", "message": "Forbidden: only the configured admin site may use this agent."}, 403)
            return True
        return False

    def _send_json(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        origin = self._cors_origin()
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        origin = self._cors_origin()
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        # /ping only says "the agent is running", so it needs no Origin (handy for checking the
        # agent by hand) — but still the Host check, like everything else.
        if self._refuse_untrusted(require_origin=not self.path == "/ping"):
            return
        if self.path == "/ping":
            self._send_json({"ok": True})
        elif self.path.startswith("/discover"):
            # targetPort/listenPort/windowSeconds/broadcastIp are query-string overrides honored
            # ONLY in test mode — real discovery never needs them (the real machine ports are the
            # defaults); they exist so tests can point this at a throwaway stub on high ports.
            params = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query) if TEST_MODE else {}
            try:
                kwargs = {}
                if "targetPort" in params:
                    kwargs["target_port"] = int(params["targetPort"][0])
                if "listenPort" in params:
                    kwargs["listen_port"] = int(params["listenPort"][0])
                if "windowSeconds" in params:
                    kwargs["window_seconds"] = float(params["windowSeconds"][0])
                if "broadcastIp" in params:
                    kwargs["broadcast_ip"] = params["broadcastIp"][0]
                machines = discover_machines(**kwargs)
            except RuntimeError as e:
                self._send_json({"status": "error", "message": str(e)}, 502)
                return
            except Exception as e:
                self._send_json({"status": "error", "message": f"Unexpected error: {e}"}, 500)
                return
            self._send_json({"status": "ok", "machines": machines})
        else:
            self._send_json({"status": "error", "message": "Not found"}, 404)

    def do_POST(self):
        if self._refuse_untrusted():
            return
        if self.path not in ("/send", "/list", "/read", "/delete"):
            self._send_json({"status": "error", "message": "Not found"}, 404)
            return
        # JSON only: a cross-site page can POST text/plain without a CORS preflight, but not
        # application/json — so this is a second, independent barrier behind the Origin check.
        if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
            self._send_json({"status": "error", "message": "Content-Type must be application/json"}, 415)
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            self._send_json({"status": "error", "message": "Invalid request body"}, 400)
            return

        machine_ip = str(body.get("machineIp", "")).strip()
        if not machine_ip:
            self._send_json({"status": "error", "message": "Missing machineIp"}, 400)
            return
        ip_problem = validate_machine_ip(machine_ip)
        if ip_problem:
            self._send_json({"status": "error", "message": ip_problem}, 400)
            return
        # machinePort is a test-only override (stub machines on high ports); the real machines
        # always listen on 6000.
        machine_port = TCP_LIST_PORT
        if TEST_MODE:
            try:
                machine_port = int(body.get("machinePort") or TCP_LIST_PORT)
            except (TypeError, ValueError):
                machine_port = TCP_LIST_PORT

        if self.path == "/list":
            try:
                files = list_machine_dir(machine_ip, machine_port)
            except RuntimeError as e:
                self._send_json({"status": "error", "message": str(e)}, 502)
                return
            except Exception as e:
                self._send_json({"status": "error", "message": f"Unexpected error: {e}"}, 500)
                return
            self._send_json({"status": "ok", "files": files})

        elif self.path == "/send":
            download_url = str(body.get("downloadUrl", "")).strip()
            file_name = str(body.get("fileName", "")).strip()
            if not download_url or not file_name:
                self._send_json({"status": "error", "message": "Missing downloadUrl or fileName"}, 400)
                return
            url_problem = validate_download_url(download_url)
            if url_problem:
                self._send_json({"status": "error", "message": url_problem}, 400)
                return
            try:
                file_bytes = fetch_design_file(download_url)
                result = send_design_to_machine(machine_ip, file_name, file_bytes, machine_port)
                self._send_json({"status": "ok", "message": f"Sent {file_name} to the machine.", **result})
            except RuntimeError as e:
                log(f"SEND error: {e}")
                self._send_json({"status": "error", "message": str(e)}, 502)
            except Exception as e:
                log(f"SEND unexpected error: {e!r}")
                self._send_json({"status": "error", "message": f"Unexpected error: {e}"}, 500)

        elif self.path == "/read":
            file_name = str(body.get("fileName", "")).strip()
            if not file_name:
                self._send_json({"status": "error", "message": "Missing fileName"}, 400)
                return
            try:
                result = read_file_from_machine(machine_ip, file_name, machine_port)
            except RuntimeError as e:
                log(f"READ error: {e}")
                self._send_json({"status": "error", "message": str(e)}, 502)
                return
            except Exception as e:
                log(f"READ unexpected error: {e!r}")
                self._send_json({"status": "error", "message": f"Unexpected error: {e}"}, 500)
                return
            data = result.pop("data")
            self._send_json({"status": "ok", **result, "bytes": len(data),
                             "dataBase64": base64.b64encode(data).decode("ascii")})

        elif self.path == "/delete":
            # Probed (probe_delete.py): opcode cf24 is the file-management command the vendor app
            # doesn't expose, but this firmware stubs it — it returns error cf e0 for every
            # argument, so it can't delete. Refuse cleanly. If a firmware update ever enables cf24
            # (probe returns a cf22 ack), send `01 00 CF 24 00 <stored name>` here. See PROTOCOL.md §6.
            self._send_json({"status": "error", "message": DELETE_UNSUPPORTED_MESSAGE}, 501)

    def log_message(self, fmt, *args):
        # Quiet by default; uncomment to see every request while debugging.
        # sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))
        pass


# ---------------------------------------------------------------------------------------------
# Relay mode: instead of waiting for a browser on THIS computer, connect OUT to the site and ask
# "anything for me?". Lets a phone or tablet (which can't reach a LAN address, nor 127.0.0.1 on
# another device) drive the machines. Jobs live on the site for ~2 minutes only; this side also
# refuses a job older than that, so nothing is ever sent to a machine late.
# ---------------------------------------------------------------------------------------------
JOB_MAX_AGE_SECONDS = 120
RELAY_MAX_BACKOFF_SECONDS = 300
RELAY_HTTP_TIMEOUT_SECONDS = 20
AGENT_VERSION = "3"  # 3: read jobs
# The site keeps a relay result under 1.5 MB (functions/api/agent.js); base64 grows a file by a third.
RELAY_MAX_READ_BYTES = 1_000_000


def lan_ip_guess():
    """This computer's LAN address (the interface used to reach the internet); '' if unknown.
    A UDP connect() sends nothing — it only makes the OS pick the outgoing interface."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            return s.getsockname()[0]
    except OSError:
        return ""


def run_job(job):
    """Runs one relay job and returns (httpStatus, body) — the same shape the local HTTP handler
    answers with, so the browser code treats both paths alike."""
    jtype = job.get("type")
    try:
        if jtype == "discover":
            return 200, {"status": "ok", "machines": discover_machines()}
        machine_ip = str(job.get("machineIp", "")).strip()
        problem = validate_machine_ip(machine_ip)
        if problem:
            return 400, {"status": "error", "message": problem}
        if jtype == "list":
            return 200, {"status": "ok", "files": list_machine_dir(machine_ip)}
        if jtype == "send":
            file_name = str(job.get("fileName", "")).strip()
            download_url = str(job.get("downloadUrl", "")).strip()
            if not file_name or not download_url:
                return 400, {"status": "error", "message": "Missing downloadUrl or fileName"}
            problem = validate_download_url(download_url)
            if problem:
                return 400, {"status": "error", "message": problem}
            data = fetch_design_file(download_url)
            result = send_design_to_machine(machine_ip, file_name, data)
            return 200, {"status": "ok", "message": f"Sent {file_name} to the machine.", **result}
        if jtype == "read":
            file_name = str(job.get("fileName", "")).strip()
            if not file_name:
                return 400, {"status": "error", "message": "Missing fileName"}
            result = read_file_from_machine(machine_ip, file_name)
            data = result.pop("data")
            if len(data) > RELAY_MAX_READ_BYTES:
                return 413, {"status": "error", "message": f"{file_name} is too big to copy from a phone or tablet "
                             "— use the computer the machine agent runs on."}
            return 200, {"status": "ok", **result, "bytes": len(data),
                         "dataBase64": base64.b64encode(data).decode("ascii")}
        if jtype == "delete":
            return 501, {"status": "error", "message": DELETE_UNSUPPORTED_MESSAGE}
        return 400, {"status": "error", "message": "Unknown job type."}
    except RuntimeError as e:
        log(f"{jtype} error: {e}")
        return 502, {"status": "error", "message": str(e)}
    except Exception as e:  # never let one bad job kill the loop
        log(f"{jtype} unexpected error: {e!r}")
        return 500, {"status": "error", "message": f"Unexpected error: {e}"}


def _relay_post(relay_url, token, op, payload):
    req = urllib.request.Request(
        relay_url.rstrip("/") + "/api/agent?op=" + op,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Agent-Token": token, "User-Agent": f"{AGENT_NAME}/{AGENT_VERSION}"},
        method="POST")
    with _download_opener.open(req, timeout=RELAY_HTTP_TIMEOUT_SECONDS) as resp:
        return json.loads(resp.read(1024 * 1024) or b"{}")  # the site's answers are small


def relay_loop(relay_url, token, stop=lambda: False, sleep=time.sleep):
    """Poll → run → answer, forever. The site tells us how long to wait between polls (about a
    minute when idle, ~2 s while someone is using the machine screens). Server errors back off."""
    try:
        relay_url = site_origin(relay_url)
    except ValueError as e:
        raise SystemExit(f"--relay: {e}")
    if relay_url not in ALLOWED_ORIGINS:
        configure(sorted(ALLOWED_ORIGINS | {relay_url}), PORT)  # the relay's site may hand out download links
    hello = {"ip": lan_ip_guess(), "host": socket.gethostname(), "version": AGENT_VERSION}
    log(f"Relay mode: polling {relay_url} as {hello['host']} ({hello['ip'] or 'unknown ip'})")
    backoff = 0
    while not stop():
        wait = 5
        try:
            reply = _relay_post(relay_url, token, "poll", hello)
            backoff = 0
            wait = max(1, min(int(reply.get("pollSeconds", 60)), 300))
            job = reply.get("job")
            if job:
                age = time.time() - float(job.get("issuedAt", 0)) / 1000.0
                if age > JOB_MAX_AGE_SECONDS or age < -30:
                    log(f"Dropping stale job {job.get('id')} (age {age:.0f}s)")
                else:
                    status, body = run_job(job)
                    _relay_post(relay_url, token, "result", {"id": job.get("id"), "httpStatus": status, "body": body})
                wait = 0  # look for the next one straight away
        except urllib.error.HTTPError as e:
            backoff = min(max(backoff * 2, 10), RELAY_MAX_BACKOFF_SECONDS)
            wait = backoff
            log("Relay rejected the agent's token (check AGENT_TOKEN)." if e.code == 401 else f"Relay error HTTP {e.code}; retrying in {wait}s")
        except (urllib.error.URLError, OSError, ValueError) as e:
            backoff = min(max(backoff * 2, 10), RELAY_MAX_BACKOFF_SECONDS)
            wait = backoff
            log(f"Can't reach the relay ({e}); retrying in {wait}s")
        if wait and not stop():
            sleep(wait)


def main():
    import argparse
    import os
    env_sites = [x for x in os.environ.get("ODD_AGENT_SITES", "").split(",") if x.strip()]
    ap = argparse.ArgumentParser(description="OpenDecoDesk machine agent: lets an admin site use SmartStitch "
                                             "embroidery machines on this network.")
    ap.add_argument("--site", action="append", default=None, metavar="URL",
                    help="an admin site allowed to use this agent, e.g. https://admin.yourshop.example "
                         "(repeat for several; or set ODD_AGENT_SITES, comma-separated)")
    ap.add_argument("--relay", default=os.environ.get("ODD_AGENT_RELAY", ""), metavar="URL",
                    help="connect out to this admin site so phones/tablets can use the agent (or set ODD_AGENT_RELAY); "
                         "without it the agent serves browsers on THIS computer via http://127.0.0.1:PORT")
    ap.add_argument("--token", default=os.environ.get("ODD_AGENT_TOKEN", ""),
                    help="relay mode: the site's AGENT_TOKEN, 32+ characters (or set ODD_AGENT_TOKEN)")
    ap.add_argument("--port", type=int, default=int(os.environ.get("ODD_AGENT_PORT", DEFAULT_PORT)),
                    help=f"loopback port (default {DEFAULT_PORT}; the admin site expects {DEFAULT_PORT})")
    args = ap.parse_args()
    try:
        configure(args.site if args.site is not None else env_sites, args.port)
    except ValueError as e:
        raise SystemExit(f"--site: {e}")
    if args.relay:
        if len(args.token) < 32:
            raise SystemExit("Relay mode needs --token (or ODD_AGENT_TOKEN): the site's AGENT_TOKEN, 32+ characters.")
        try:
            relay_loop(args.relay, args.token)
        except KeyboardInterrupt:
            print("\nStopping.")
        return
    if not ALLOWED_ORIGINS:
        log("WARNING: " + NO_SITE_MESSAGE)
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"Machine agent listening on http://127.0.0.1:{PORT} for {', '.join(sorted(ALLOWED_ORIGINS)) or 'nobody'}"
          "  (Ctrl+C to stop)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
        server.shutdown()


if __name__ == "__main__":
    main()
