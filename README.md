# OpenDecoDesk machine agent

A small program that lets a web admin use **SmartStitch** embroidery machines on your local network:
find them, list their files, send a design to one, and copy a file back off it. It's the piece of
[OpenDecoDesk](https://github.com/OpenDecoDesk) that talks to the machines — its Run Order and Machine
Files screens call it — and any site that speaks the same small HTTP API can use it.

A web page can't open raw network connections, and a website's servers can't reach a machine on your
shop's private network, so this runs on a computer **on the same network as the machines** and speaks
their protocol for the page. It's one program for Mac, Windows or Linux, with nothing else to install.

> Just want to copy files between a folder and a machine, without a website? Use the desktop app,
> [opendecodesk-machine-files](https://github.com/OpenDecoDesk/opendecodesk-machine-files).

## Install

On the computer you use the admin site from:

1. **Download** the one for your computer:
   - Mac: `OpenDecoDesk-Machine-Agent-macOS-….zip` (Apple Silicon and Intel, macOS 13 or newer)
   - Windows: `OpenDecoDesk-Machine-Agent-Windows-….exe` (Windows 10 or newer)
2. **Open it.**
   - Mac: double-click the zip, then double-click **OpenDecoDesk Machine Agent**. The first time, macOS
     says it can't check the app: click **Done**, open **System Settings → Privacy & Security**, scroll
     down, click **Open Anyway** next to OpenDecoDesk Machine Agent, then **Open**.
   - Windows: double-click the .exe. If Windows says "Windows protected your PC", click **More info**,
     then **Run anyway**.
3. **Your browser opens the setup page.** Type the address of your admin site
   (e.g. `https://admin.yourshop.example`) and click **Save**.
4. Click **Find my machines** to check it can see them. On Windows, the first time, tick **Private
   networks** and click **Allow** when Windows asks, then click the button again.

That's it: the agent now starts by itself whenever you log in. To get back to the setup page, open
OpenDecoDesk Machine Agent again. To update, download the new version and open it: it replaces the old
one and keeps your settings. To remove it, click **Remove from this computer** on the setup page (on
Windows it's also in **Settings → Apps**).

The warnings in step 2 appear because the downloads aren't signed with an Apple or Microsoft developer
certificate yet; they appear once.

**Phones and tablets** can't reach a program on another computer, so for them the agent connects *out*
to your site instead (relay mode). On the setup page, open **Phones and tablets**, enter the site and
its `AGENT_TOKEN`, and click **Turn on**. Use a computer that's always on. Both ways can run at once.

| | Mac | Windows |
|---|---|---|
| Program and settings | `~/Library/Application Support/OpenDecoDesk Machine Agent/` | `%LOCALAPPDATA%\OpenDecoDesk Machine Agent\` |
| Log | `~/Library/Logs/OpenDecoDesk Machine Agent.log` | `agent.log` in the folder above |
| Starts at login through | a launchd login item (`org.opendecodesk.machine-agent`) | Task Scheduler (`OpenDecoDesk Machine Agent`), restarted if it stops |

No admin password is needed anywhere. On a Mac that had the earlier Python agent installed with
`install-service.py`, the app takes over its sites and relay settings and removes it.

## From a terminal

The same program runs in the foreground with options, as the earlier Python agent did:

```bash
./opendecodesk-machine-agent --site https://admin.yourshop.example
ODD_AGENT_TOKEN='<the site's AGENT_TOKEN>' ./opendecodesk-machine-agent --relay https://admin.yourshop.example
```

(On a Mac the program is `OpenDecoDesk Machine Agent.app/Contents/MacOS/OpenDecoDesk Machine Agent`.)
In relay mode the page queues a job on the site (`/api/agent`), the agent picks it up within a couple
of seconds while someone is on a machine screen (about a minute when idle), runs it and posts the
answer back. Jobs older than two minutes are dropped, so nothing is ever sent to a machine late.

| Setting | Environment variable | Meaning |
|---|---|---|
| `--site URL` (repeatable) | `ODD_AGENT_SITES` (comma-separated) | Admin sites allowed to use the loopback agent. Without one, only `/ping` answers. |
| `--relay URL` | `ODD_AGENT_RELAY` | Relay mode: the admin site to connect out to (https). |
| `--token` | `ODD_AGENT_TOKEN` | Relay mode: the site's `AGENT_TOKEN`, 32+ characters. Prefer the environment variable. |
| `--port` | `ODD_AGENT_PORT` | Loopback port; default 8787, which is what the admin site expects. |

Other commands: `install [--site URL] [--relay URL] [--no-browser]` (what a double-click does),
`uninstall`, `run` (the installed service), `version`.

The machine vendor's own app can stay open: the agent hears the machines' replies on a port of its own
(any free one — the machines answer whichever port asked).

**Linux** (e.g. an always-on Raspberry Pi for relay mode): download
`opendecodesk-machine-agent-linux-amd64-…` or `…-arm64-…`, make it executable, and run
`./opendecodesk-machine-agent-linux-… install --no-browser --relay https://admin.yourshop.example` with
`ODD_AGENT_TOKEN` set. That sets up a systemd user service (`systemctl --user status
opendecodesk-machine-agent`; logs with `journalctl --user -u opendecodesk-machine-agent`). For it to run
without anyone logged in, run `loginctl enable-linger` once.

## What it answers

All requests must come from an allowed site (see Security). `machineIp` is a machine's address from
`/discover`.

| Request | Answer |
|---|---|
| `GET /ping` | `{"ok": true, "agent", "version"}` — no Origin needed, for checking it's running |
| `GET /discover` | `{"status":"ok","machines":[{"ip","mac","model","firmware"}]}` — scans the network for about 1.5 s; `model` is the name entered on the machine, not a model number |
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

The setup page (`/setup`, only while running as the installed service) changes who may use the agent,
so it's locked to itself:

- the same `Host` check;
- every setup call carries a random token written only into the page; other sites can't read the
  page (it never sends CORS headers), and can't send that header cross-site without a preflight,
  which is never approved;
- an `Origin`, when the browser sends one, must be the agent's own (`http://127.0.0.1:8787`);
- the page can't be framed (`X-Frame-Options: DENY`, `frame-ancestors 'none'`), so it can't be
  clickjacked;
- `settings.json` (which can hold the relay token) is readable only by you.

## Building

```bash
./build.sh
```

Needs [Go](https://go.dev/dl/) 1.22 or newer, nothing else (standard library only). It writes the Mac
zip, the Windows .exe and the Linux programs to `dist/`, with `SHA256SUMS.txt`. Every program is built
on any computer; the Mac app is put together only on a Mac (`lipo`, `codesign`, `ditto`). CI builds them
on every push; download them from the run's **installers** artifact.

## Tests

```bash
python3 test_agent.py
```

Builds the agent, starts it, and runs it against stub machines on this computer that speak the real
protocol (discovery, multi-page listing, an upload checked byte for byte, a file read back), plus the
security checks, relay mode with a stub site, and the setup page's lockdown. Nothing touches a real
machine or the real login service. Needs Go and Python 3.9+.

`embroidery_agent.py` is the original Python agent, kept as the reference until the Go program has
been tried on real machines; `ODD_AGENT_IMPL=python python3 test_agent.py` runs the same checks against
it.

## The protocol

[PROTOCOL.md](PROTOCOL.md) is the reverse-engineered reference: UDP discovery on port 23, and framed
TCP on port 6000 (`FA 01 <len> <body> <xor>`) for listing, uploading and reading files back.

## Compatibility
Tested on two SmartStitch machines, both with **Raynen** controllers:
- SmartStitch **1501 Ultra** (SD5314)
- SmartStitch **1201 Plus** (JD5315)

The agent talks to the Raynen controller, not to anything SmartStitch-specific, so it should also work
with other machines that have a Raynen controller speaking the same network protocol
([PROTOCOL.md](PROTOCOL.md)). That's untested so far: if you try one, a note in the issues saying whether
it worked helps.

SmartStitch and Raynen are their owners' brands; this project isn't affiliated with or endorsed by either.

## Licence

[GNU AGPL-3.0](LICENSE).
