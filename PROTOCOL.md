# SmartStitch embroidery-controller LAN protocol

Reverse-engineered reference for the network protocol these machines speak, reconstructed from
real Wireshark captures of the vendor's own software talking to two machines (a SmartStitch
1201 Plus and a 1501 Ultra), plus extra captures made on purpose to expose how the check byte is built. This is
the description behind `embroidery_agent.py`; the stub machines in `test_agent.py` encode
the same frame shapes.

**These are NOT FTP servers.** An early build assumed FTP on port 21 — wrong hardware model. They
speak two proprietary protocols: UDP discovery on port 23, and a framed TCP request/response
protocol on port 6000 for listing files, uploading designs and reading them back.

---

## 1. The universal frame envelope (TCP, port 6000)

Every TCP frame, in **both** directions (command and reply), has one shape:

```
FA 01 <len16 LE> <body …> <lrc>
```

| Field      | Bytes | Meaning                                                             |
|------------|-------|--------------------------------------------------------------------|
| magic      | 2     | Always `FA 01`.                                                     |
| `len16`    | 2     | Little-endian length of **`body` + the 1 lrc byte** = `len(body)+1`. |
| `body`     | n     | The command/response payload (see §4).                             |
| `lrc`      | 1     | **XOR of every byte in the frame before it** (the `FA`, the `01`, both length bytes, and the whole body). |

The `lrc` is a longitudinal redundancy check (XOR), *not* a sum or two's-complement checksum.
This was verified against 8 registration frames of differing lengths, both 1024-byte data frames,
and every reply frame — it reproduces all of them exactly. (The old "list checksum = `0x13 - page`"
formula was just this same XOR written a harder way, and happened to match only for pages 1–3.)

Worked example — the real captured "register filename `CRM_TEST.DST`" frame:

```
FA 01 12 00 01 00 CF 25 00 43 52 4D 5F 54 45 53 54 2E 44 53 54 7A
└mag┘ └len┘ └───────────────── body (17 bytes) ─────────────────┘ └lrc┘
        18                                                          XOR
```
`len16 = 0x0012 = 18 = len(body)+1`; `XOR(FA…54) = 0x7A` ✓.

The `body` of a **command** always begins `01 00 CF <op>`; replies do too. The leading `01 00`
(little-endian `1`) is constant on everything captured — treat it as a fixed channel/request
tag, not a variable.

### Reading a reply frame
Read 4 header bytes, take `len16 = header[2] | header[3]<<8`, then read exactly `len16` more
bytes. That's the whole frame (`header + body + lrc`). See `_recv_frame` in `embroidery_agent.py`.

---

## 2. Discovery (UDP)

| Step    | Direction        | Packet                                                            |
|---------|------------------|------------------------------------------------------------------|
| Request | host → broadcast | UDP to `255.255.255.255:23`, payload `FF 04 02 FB` (4 bytes).     |
| Reply   | machine → host   | UDP back to the port the request came FROM, an ~84-byte packet (below). |

The vendor's app sends from (and listens on) port 60023, but the machines answer whatever port the
request came from: a scan sent from a random free port gets its replies on that port (checked on a
1201 Plus and a 1501 Ultra, three tries each). So a scanner needn't hold 60023 — which on Windows can
be taken by the vendor's app or reserved by the system (WinError 10013).

The reply is **not** an `FA 01` frame — it's a flat fixed-layout record:

| Field    | Offset    | Encoding                                                        |
|----------|-----------|----------------------------------------------------------------|
| MAC      | `[9:15]`  | 6 raw bytes.                                                    |
| firmware | `@19`     | NUL-terminated ASCII, variable length (seen: `JD…`, `HH1S…`).  |
| name     | `@51`     | NUL-terminated ASCII, variable length: the name entered on the machine (ours were set to `1201plus` and `1501ultra`), not a model number. `/discover` returns it as `model`. |

Read firmware/name as **NUL-terminated strings from their start offset**, never as a fixed
`[start:end]` slice — the fields are variable length, and an early fixed-slice build lost the
firmware's first character and the name entirely.

---

## 3. File listing (TCP, port 6000)

One TCP connection, one 11-byte command **per page**, over the same open socket:

```
Command (host → machine), 11 bytes:
FA 01 07 00 01 00 CF 21 <page8> 00 <lrc>
```
`page8` is the 1-based page number in a single byte; `lrc = XOR(FA…00) = 0x13 ^ page`.

```
Reply (machine → host), one framed page:
FA 01 <len16> 01 00 CF 26 <page16 LE> <field16> <JSON chunk ≤ ~1024 B> <lrc>
```

The machine returns **one JSON document** — `{"num":N,"files":[{"name","size","date"}, …]}` —
sliced across pages at **arbitrary byte boundaries** (mid-object, even mid-key). Pages therefore
**cannot be parsed independently**. Correct reassembly: for each page, drop the 12-byte prefix
(`FA 01 len16 01 00 CF 26 page16 field16`) and the 1 trailing `lrc` byte, concatenate the raw
JSON chunks, and `json.loads` the whole thing once. Stop when `len(files) >= num`, or on a
header-only frame (no JSON chunk) which signals "no more pages". See `list_machine_dir`.

`field16` (the 2 bytes after `page16`) was `02 00` in captures; its exact meaning is unconfirmed
(likely a record/type tag). It isn't needed for reassembly.

---

## 4. Uploading a design (TCP, port 6000) — implemented, verified

Two phases over one connection.

**Phase 1 — register the filename:**
```
host → machine:  body = 01 00 CF 25 00 <filename ASCII>
machine → host:  body = 01 00 CF 22 01 00 00 <filename ASCII>   (cf22 echo/ack)
```
Filename is plain ASCII (e.g. `CRM_TEST.DST`). The machine echoes it back in a `CF 22` frame.

**Phase 2 — stream the file, 1024 bytes per page, pages numbered from 1:**
```
host → machine:  body = 01 00 CF 23 <page16 LE> <totalBlocks16 LE> <up to 1024 file bytes>
machine → host:  body = 01 00 CF 22 <page+1 & 0xFF> 00            (cf22 "ready for next")
```
- `totalBlocks16 = ceil(size / 1024)`, **constant for the whole file** — the machine uses it to
  know when the transfer is complete and to commit. Captures: `0x0032` (50) for a 50-block file,
  `0x0016` (22) for a 22-block file. Wrong value → the machine waits forever for blocks that never
  come, or rejects the block past the declared count with a `CF E1` error.
- The **last block is short (not padded)** to the real remaining byte count.
- The machine `CF 22`-acks every block **except the last** — after the final block it just commits
  and TCP-acks, sending no `CF 22`. Waiting for one on the last block makes an already-landed send
  look "timed out". So: wait for an ack on every block but the last; on the last, only peek briefly
  for an explicit error.

See `send_design_to_machine`.

---

## 5. Opcode map (the byte after `CF`)

| Op   | Dir | Name / body                                   | Status                  |
|------|-----|-----------------------------------------------|-------------------------|
| `21` | →   | request file-list page (`… CF 21 page8 00`)   | known, used             |
| `22` | ↔   | ack / status / echo; host → machine `… CF 22 01 00 00 <name>` = **read a file** (§8) | known, used |
| `23` | ↔   | data block (`… CF 23 page16 total16 <bytes>`), both directions | known, used |
| `24` | →   | **recognized but DISABLED** (`… CF 24 00 <param>`) → always `CF E0`. The one unused slot in the file-management cluster; almost certainly the delete/file-management op the vendor app doesn't expose. See §6 below. | **found, stubbed** |
| `25` | →   | register filename (`… CF 25 00 <name>`)       | known, used             |
| `26` | ←   | file-list page response                       | known (reply)           |
| `E0` | ←   | "recognized command, refused" — returned by `CF 24` for every parameter | reply, observed |
| `E1` | ←   | "malformed / unexpected frame" — e.g. a data block past the declared count, or `CF 24` with a non-`00` sub-byte | reply, observed |
| `20`,`27`,`28`,`29`,`2A`,`2B`,… | ? | **unassigned — silently ignored** (no reply at all) | not implemented |

Also, within a `CF 22` status reply, the byte `0xC9` in the status slot has been seen to mean
"rejected" (`_reply_is_error` treats `0xC9` in bytes `[8:11]` as an error).

The file-management cluster is tightly packed — `21` list, `22` ack, `23` data, **`24` ???**,
`25` register, `26` list-response. File selection everywhere it's known (registration) is **by
ASCII name**, not by an index.

### Filenames & the upload-commit quirk (observed on real machines)
- A file uploaded as `<base>.DST` is **stored as `<base>.<NNN>`** — the machine strips the `.DST`
  and appends its own zero-padded **decimal** sequence number (`.001`, `.002`, …). A delete would
  therefore have to target the *stored* name (`ZZDELPROBE.031`), not the registration name.
- The machine **re-encodes** the uploaded design to a small internal form on commit (a ~2.4 KB DST
  came back listed as 346 bytes), so the listed `size` is the stored size, not the bytes sent.
- A **single-block** upload (`totalBlocks = 1`) was observed **not to commit** — no file appears.
  Multi-block uploads commit fine. (Cause unconfirmed; possibly the commit is tied to the
  block-count handshake.) A sender should list the machine afterwards and check the file is there.
- The listing JSON per file carries only `name`, `size`, `date` — no hidden id/handle field.

---

## 6. Delete — present but disabled

Opcode **`CF 24`** — the one unused slot in the file-management cluster — is the only unassigned
opcode the firmware answers (`20`, `27`–`2B` get no reply at all). Its grammar is
`01 00 CF 24 00 <param>` (any sub-byte other than `00` gets `CF E1`), but it returns **`CF E0`**
for *every* parameter: the real stored file name, a made-up one, even an empty one. A handler that
needed a valid file would answer those differently; one answer for all of them is the signature of
a stub that always refuses. Seen identically on the 1201 Plus (`JD20260617.1.3.1`) and 1501 Ultra
(`HH1S20260508.2.1.2`).

So delete is compiled in but disabled on this firmware, and the agent's `/delete` refuses it — files are
cleared at the machine's touchscreen. A newer firmware, or a capture of anything that does delete
over port 6000, could change that.

## 7. Frame quick-reference

```
Envelope:      FA 01 <len16 LE=len(body)+1> <body> <lrc = XOR of all prior bytes>
Discover req:  UDP → 255.255.255.255:23   payload FF 04 02 FB   (reply to the request's source port)
List page:     FA 01 07 00 01 00 CF 21 <page8> 00 <lrc>
List reply:    FA 01 <len> 01 00 CF 26 <page16> <field16> <JSON chunk> <lrc>
Register:      FA 01 <len> 01 00 CF 25 00 <name ASCII> <lrc>
Reg reply:     FA 01 <len> 01 00 CF 22 01 00 00 <name ASCII> <lrc>
Data block:    FA 01 <len> 01 00 CF 23 <page16> <total16> <≤1024 bytes> <lrc>
Block ack:     FA 01 <len> 01 00 CF 22 <page+1 & FF> 00 <lrc>   (none after the last block)
Delete:        CF 24 exists but is DISABLED on this firmware — FA 01 <len> 01 00 CF 24 00 <param>
               always returns CF E0 (recognized, refused) for any param. See §6.
Read request:  FA 01 <len> 01 00 CF 22 01 00 00 <stored name UTF-8> <lrc>
Read block:    FA 01 <len> 01 00 CF 23 <page16> <total16> <≤1024 bytes> <lrc>   (machine → host)
Read ack:      FA 01 07 00 01 00 CF 22 <page+1 16> <lrc>   (none after the last block)
```

## 8. Reading a file back (machine → computer) — implemented, verified

Decoded from a capture of the vendor's app copying `<name>.002` off a 1501 Ultra, then checked by
reading the same file with `read_file_from_machine` (`POST /read`): byte-for-byte identical. It is the upload (§4) run
in reverse, on the same port-6000 connection type.

```
host → machine:  body = 01 00 CF 22 01 00 00 <stored name>        (read request)
machine → host:  body = 01 00 CF 23 <page16 LE> <totalBlocks16 LE> <up to 1024 file bytes>
host → machine:  body = 01 00 CF 22 <page+1 16 LE>                (ack: "ready for the next")
… repeated; the host sends NO ack after the last block.
```
- The request names the file **exactly as the listing shows it**, sequence number included
  (`LOGO.012`). It has the same shape as the machine's reply to an upload registration
  (`CF 22 01 00 00 <name>`). Names are sent as UTF-8, like the listing JSON; a non-ASCII name
  (`马头机~1.008`) reads fine.
- In the capture the vendor app listed the files first on the same connection, but a read on a
  fresh connection works too.
- The data is the machine's **stored form**: a 512-byte DST-style header (`LA:`, `ST:`, `CO:`,
  `+X:` …) followed by Barudan (`.DSB`) stitch records — whatever format was uploaded. Its size is
  exactly `512 + 3 × (ST − 1)` (4079 stitches → 12,746 bytes). It is **not** the listed `size`
  (the listing said 16,698 for that file). Save it as `.DSB`.
- An unknown name is expected to get a `CF E0`/`CF E1` refusal (not seen in a capture);
  `read_file_from_machine` treats any non-`CF 23` reply as a refusal and checks every block's page
  number, block count and LRC.
