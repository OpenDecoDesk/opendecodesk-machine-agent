#!/usr/bin/env python3
"""Install, update or remove the machine agent as a macOS login service (launchd).

    python3 install-service.py --site https://admin.yourshop.example     # loopback: the admin page on THIS Mac
    python3 install-service.py --relay https://admin.yourshop.example    # relay: phones and tablets
    python3 install-service.py --remove                                   # stop and remove the loopback one
    python3 install-service.py --remove --relay https://admin.yourshop.example

Both can be installed at once (they're separate services). The agent is copied to
~/Library/Application Support/opendecodesk-machine-agent/ and run from there: macOS won't let a background
service read files in ~/Documents, ~/Desktop or ~/Downloads. Run this again after updating the agent — it
copies the new file over and restarts the service.

Relay mode asks for the site's AGENT_TOKEN with hidden input (never printed, never on a command line, or set
ODD_AGENT_TOKEN), writes the service file readable only by you (mode 0600) with the token in its environment.
"""
import argparse
import getpass
import hashlib
import os
import plistlib
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
HOME = os.path.expanduser("~")
AGENT_DIR = os.path.join(HOME, "Library", "Application Support", "opendecodesk-machine-agent")
AGENTS_DIR = os.path.join(HOME, "Library", "LaunchAgents")
LOGS_DIR = os.path.join(HOME, "Library", "Logs")
LABEL = "org.opendecodesk.machine-agent"


def relay_label(url):
    # One relay service per site, so a test site and a live site can both be served.
    return LABEL + ".relay." + hashlib.sha256(url.encode()).hexdigest()[:8]


def python_path():
    # Apple's own Python is always there and isn't moved by package-manager upgrades.
    return "/usr/bin/python3" if os.path.exists("/usr/bin/python3") else sys.executable


def launchctl(*args, check=False):
    return subprocess.run(["launchctl", *args], check=check, stderr=None if check else subprocess.DEVNULL)


def main():
    if sys.platform != "darwin":
        sys.exit("This installer is for macOS. See README.md for Linux (systemd) and Windows (Task Scheduler).")
    ap = argparse.ArgumentParser(description="Install the OpenDecoDesk machine agent as a macOS login service.")
    ap.add_argument("--site", action="append", default=[], metavar="URL",
                    help="admin site allowed to use the loopback agent (repeat for several)")
    ap.add_argument("--relay", default="", metavar="URL", help="install the relay service for this admin site instead")
    ap.add_argument("--remove", action="store_true", help="stop and remove the service")
    args = ap.parse_args()

    sys.path.insert(0, HERE)
    import embroidery_agent as agent  # validates the addresses exactly as the agent will
    try:
        sites = [agent.site_origin(s) for s in args.site]
        relay = agent.site_origin(args.relay) if args.relay else ""
    except ValueError as e:
        sys.exit(str(e))

    label = relay_label(relay) if relay else LABEL
    plist_path = os.path.join(AGENTS_DIR, label + ".plist")
    uid = str(os.getuid())

    if args.remove:
        launchctl("bootout", f"gui/{uid}/{label}")
        if os.path.exists(plist_path):
            os.remove(plist_path)
        print(f"Removed {label}.")
        return

    if not relay and not sites:
        sys.exit("Give --site https://admin.yourshop.example (the admin site that may use the agent), or --relay.")
    os.makedirs(AGENT_DIR, exist_ok=True)
    os.makedirs(AGENTS_DIR, exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)
    installed = os.path.join(AGENT_DIR, "embroidery_agent.py")
    shutil.copyfile(os.path.join(HERE, "embroidery_agent.py"), installed)

    env = {"PYTHONUNBUFFERED": "1"}
    program = [python_path(), installed]
    if relay:
        token = os.environ.get("ODD_AGENT_TOKEN") or getpass.getpass(
            f"AGENT_TOKEN for {relay} (hidden, 32+ characters): ")
        token = token.strip()
        if len(token) < 32:
            sys.exit("That token is shorter than 32 characters — nothing changed.")
        env["ODD_AGENT_TOKEN"] = token
        program += ["--relay", relay]
    else:
        for s in sites:
            program += ["--site", s]

    log = os.path.join(LOGS_DIR, label + ".log")
    plist = {
        "Label": label,
        "ProgramArguments": program,
        "EnvironmentVariables": env,
        "WorkingDirectory": AGENT_DIR,
        "RunAtLoad": True,
        "KeepAlive": True,
        "StandardOutPath": log,
        "StandardErrorPath": log,
    }
    fd = os.open(plist_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        plistlib.dump(plist, fh)
    os.chmod(plist_path, 0o600)
    launchctl("bootout", f"gui/{uid}/{label}")
    launchctl("bootstrap", f"gui/{uid}", plist_path, check=True)
    what = f"relaying through {relay}" if relay else f"on http://127.0.0.1:{agent.DEFAULT_PORT} for {', '.join(sites)}"
    print(f"Installed and started {label} ({what}).\nLog: {log}")


if __name__ == "__main__":
    main()
