# OpenDecoDesk machine agent

A small program that lets a web admin use **SmartStitch** embroidery machines on your local network:
find them, list their files, send a design to one, and copy a file back off it. It's the piece of
[OpenDecoDesk](https://github.com/OpenDecoDesk) that talks to the machines — its Run Order and Machine
Files screens call it — and any site that speaks the same small HTTP API can use it.

A web page can't open raw network connections, and a website's servers can't reach a machine on your
shop's private network, so this runs on a computer **on the same network as the machines** and speaks
their protocol for the page. One Python file, standard library only — nothing to `pip install`.
Python 3.9 or newer.

> Just want to copy files between a folder and a machine, without a website? Use the desktop app,
> [opendecodesk-machine-files](https://github.com/OpenDecoDesk/opendecodesk-machine-files).

## Running it

**On the computer you use the admin site from** (loopback mode):

```bash
python3 embroidery_agent.py --site https://admin.yourshop.example
```

It listens on `http://127.0.0.1:8787`, reachable only from this computer. `--site` is the admin site
allowed to use it (repeat it for several, e.g. a test site too); every other web page is refused. The
admin page reaches it because browsers treat `127.0.0.1` as secure — the site's Content-Security-Policy
must allow `connect-src http://127.0.0.1:8787` (OpenDecoDesk's does).

**For phones and tablets** (relay mode): a phone can't reach `127.0.0.1` on another computer, so run
the agent on any always-on computer on the shop network, connecting *out* to the site:

```bash
ODD_AGENT_TOKEN='<the site's AGENT_TOKEN>' python3 embroidery_agent.py --relay https://admin.yourshop.example
```

The page queues a job on the site (`/api/agent`), the agent picks it up within a couple of seconds
while someone is on a machine screen (about a minute when idle), runs it and posts the answer back.
Jobs older than two minutes are dropped, so nothing is ever sent to a machine late. Both modes can run
at once.

| Setting | Environment variable | Meaning |
|---|---|---|
| `--site URL` (repeatable) | `ODD_AGENT_SITES` (comma-separated) | Admin sites allowed to use the loopback agent. Without one, only `/ping` answers. |
| `--relay URL` | `ODD_AGENT_RELAY` | Relay mode: the admin site to connect out to (https). |
| `--token` | `ODD_AGENT_TOKEN` | Relay mode: the site's `AGENT_TOKEN`, 32+ characters. Prefer the environment variable. |
| `--port` | `ODD_AGENT_PORT` | Loopback port; default 8787, which is what the admin site expects. |

Close the machine vendor's own app while the agent is scanning: both listen on the same UDP port for
the machines' replies.

## Run it as a service

**macOS** — installs a login service that starts automatically and restarts if it stops:

```bash
python3 install-service.py --site https://admin.yourshop.example
python3 install-service.py --relay https://admin.yourshop.example     # asks for the token
```

It copies the agent to `~/Library/Application Support/opendecodesk-machine-agent/` (macOS won't let a
background service read files in `~/Documents`), logs to `~/Library/Logs/`, and keeps the relay token
in a service file only you can read. Run it again after updating the agent; `--remove` takes it away.

**Linux (systemd, per user)** — `~/.config/systemd/user/opendecodesk-machine-agent.service`:

```ini
[Unit]
Description=OpenDecoDesk machine agent

[Service]
ExecStart=/usr/bin/python3 /opt/opendecodesk-machine-agent/embroidery_agent.py --site https://admin.yourshop.example
Restart=always

[Install]
WantedBy=default.target
```

then `systemctl --user enable --now opendecodesk-machine-agent`. For relay mode, put the token in an
`EnvironmentFile=` readable only by you.

**Windows** — Task Scheduler → Create Task: trigger *At log on*; action *Start a program* `pythonw.exe`
with arguments `C:\path\to\embroidery_agent.py --site https://admin.yourshop.example`; on the Settings
tab, *If the task fails, restart every 1 minute*. Allow it through Windows Firewall on private networks
when asked (the machine scan needs it).

## What it answers

All requests must come from an allowed site (see Security). `machineIp` is a machine's address from
`/discover`.

| Request | Answer |
|---|---|
| `GET /ping` | `{"ok": true}` — no Origin needed, for checking it's running |
| `GET /discover` | `{"status":"ok","machines":[{"ip","mac","model","firmware"}]}` — scans the network for about 1.5 s |
| `POST /list {machineIp}` | `{"status":"ok","files":[{"name","size","modified"}]}` |
| `POST /send {downloadUrl, machineIp, fileName}` | Downloads the design from the site's signed link (`<site>/api/design?…`) and sends it to the machine: `{"status":"ok","fileName","bytes","blocks"}` |
| `POST /read {machineIp, fileName}` | Copies a file off the machine (`fileName` exactly as `/list` shows it, e.g. `LOGO.012`): `{"status":"ok","fileName","bytes","blocks","ext":"DSB","dataBase64"}`. What comes back is the machine's own stored form (a DST-style header with Barudan records), whatever was sent to it. |
| `POST /delete` | `501` — the machines' firmware has the command but refuses it; clear files at the touchscreen |

Relay jobs are the same operations (`discover`, `list`, `send`, `read`, `delete`); a `read` over 1 MB
is refused in relay mode (the site keeps relay answers small). Every failure is a plain message the
page can show.

## Security

Any web page you visit can also send requests to `127.0.0.1`, so the agent checks every one before
doing anything:

- the `Host` header must be `127.0.0.1:<port>` or `localhost:<port>` (blocks DNS rebinding);
- the `Origin` must be one of the `--site`s — otherwise `403` (only `/ping` is exempt);
- `POST`s must be `application/json` (`415` otherwise — a cross-site form can't send that without the
  browser asking first);
- design downloads come only from `https://<an allowed site>/api/design`, redirects refused, 20 MB cap;
- `machineIp` must be a private-network IPv4 address — never the internet, never this computer.

In relay mode the agent only connects out, over https, to the one site, with its token.

## Tests

```bash
python3 test_agent.py
```

Starts the real agent and runs it against stub machines on this computer that speak the real protocol
(discovery, multi-page listing, an upload checked byte for byte, a file read back), plus the security
checks and relay mode with a stub site. Nothing touches a real machine.

## The protocol

[PROTOCOL.md](PROTOCOL.md) is the reverse-engineered reference: UDP discovery on port 23, and framed
TCP on port 6000 (`FA 01 <len> <body> <xor>`) for listing, uploading and reading files back. Tested
against the `1201plus` and `1501ultra` models.

SmartStitch is the machine vendor's brand; this project isn't affiliated with or endorsed by them.

## Licence

[GNU AGPL-3.0](LICENSE).
