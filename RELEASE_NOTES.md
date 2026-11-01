The OpenDecoDesk machine agent: one program that installs itself and lets an OpenDecoDesk admin site
(Run Order, Machine Files) use SmartStitch embroidery machines on your shop's network: find them, list
their files, send a design, and copy a file back off a machine.

**This is an early release.** The version is the release's date and that day's build number
(YYYY.MM.DD.NN); the setup page shows it at the top.

## Downloads

- **Mac:** `OpenDecoDesk-Machine-Agent-macOS.zip`. One app for Apple silicon and Intel, macOS 13 or
  newer.
- **Windows:** `OpenDecoDesk-Machine-Agent-Windows.exe`. Windows 10 or newer.
- **Linux:** `opendecodesk-machine-agent-linux-amd64` and `opendecodesk-machine-agent-linux-arm64`, to
  run from a terminal.
- `SHA256SUMS.txt` has the checksums.

## Install

Open the download, and your browser opens the setup page. Type your admin site's address, click
**Save**, then **Find my machines**. From then on the agent starts by itself when you log in. To
update later, open a newer download: it replaces the old one and keeps your settings.

The downloads aren't signed yet, so macOS and Windows warn about them the first time:

- **Mac:** click **Done**, then go to *System Settings → Privacy & Security* and click **Open Anyway**.
- **Windows:** click *More info → Run anyway*.

The full steps, relay mode for phones and tablets, and Linux are in the
[README](https://github.com/OpenDecoDesk/opendecodesk-machine-agent#install).

## Tested so far

- Every system: the tests on Linux, macOS and Windows, against stand-in machines that speak the real
  protocol.
- Windows: a real install and removal on a Windows CI computer.

Not yet confirmed: sending to real machines with this Go version. The machines listed in the README
were tested with the earlier Python agent, which speaks the same protocol. If you try this one on a
machine, please say in an issue whether it worked.
