#!/usr/bin/env bash
# Builds the downloads into dist/:
#   OpenDecoDesk-Machine-Agent-macOS.zip     the Mac app (Apple Silicon + Intel in one)
#   OpenDecoDesk-Machine-Agent-Windows.exe   the Windows program
#   opendecodesk-machine-agent-linux-{amd64,arm64}
# The names carry no version, so a release's files are always at
# https://github.com/OpenDecoDesk/opendecodesk-machine-agent/releases/latest/download/<name>; the version is
# inside each program (`version`, the setup page, and the Mac app's Info.plist).
# The version is VERSION: a release's date and that day's build number, YYYY.MM.DD.NN, which CI works
# out (scripts/next-version.sh) when it makes a release. Built any other way it's `dev`.
# Needs Go. The Mac app is only put together on a Mac (it needs lipo, codesign and ditto); elsewhere
# the Mac programs are still compiled, as a check.
set -euo pipefail
cd "$(dirname "$0")"

VERSION="${VERSION:-dev}"
# The Mac app's version numbers can only be up to three whole numbers: YYYY.MM.DD to show, and
# YYYY.MM.DDNN so a day's second build counts as newer. Anything else (dev) is 0.0.0.
if [[ $VERSION =~ ^([0-9]{4}\.[0-9]{2}\.[0-9]{2})\.([0-9]{2})$ ]]; then
  SHORT_VERSION="${BASH_REMATCH[1]}"
  BUNDLE_VERSION="${BASH_REMATCH[1]}${BASH_REMATCH[2]}"
else
  SHORT_VERSION=0.0.0
  BUNDLE_VERSION=0.0.0
fi
APP_NAME="OpenDecoDesk Machine Agent"
DIST=dist
WORK="$DIST/work"
rm -rf "$DIST"
mkdir -p "$WORK"

build() { # GOOS GOARCH OUTPUT [extra ldflags]
  echo "  go build $1/$2"
  CGO_ENABLED=0 GOOS="$1" GOARCH="$2" go build -trimpath \
    -ldflags "-s -w -X main.version=$VERSION ${4:-}" -o "$3" .
}

echo "Building $VERSION"
build darwin arm64 "$WORK/agent-darwin-arm64"
build darwin amd64 "$WORK/agent-darwin-amd64"
build windows amd64 "$DIST/OpenDecoDesk-Machine-Agent-Windows.exe" "-H windowsgui"
build linux amd64 "$DIST/opendecodesk-machine-agent-linux-amd64"
build linux arm64 "$DIST/opendecodesk-machine-agent-linux-arm64"

if command -v lipo >/dev/null && command -v codesign >/dev/null && command -v ditto >/dev/null; then
  echo "  macOS app"
  APP="$WORK/$APP_NAME.app"
  mkdir -p "$APP/Contents/MacOS"
  lipo -create -output "$APP/Contents/MacOS/$APP_NAME" "$WORK/agent-darwin-arm64" "$WORK/agent-darwin-amd64"
  sed -e "s/__BUNDLE_VERSION__/$BUNDLE_VERSION/g" -e "s/__SHORT_VERSION__/$SHORT_VERSION/g" packaging/macos/Info.plist \
    > "$APP/Contents/Info.plist"
  # Ad-hoc signature: not a Developer ID (macOS still asks once, "Open Anyway"), but Apple Silicon
  # won't run a program with no signature at all.
  xattr -cr "$APP"  # codesign refuses extended attributes ("detritus")
  codesign --force --sign - "$APP"
  ditto -c -k --keepParent "$APP" "$DIST/OpenDecoDesk-Machine-Agent-macOS.zip"
else
  echo "  (not on a Mac: skipping the macOS app)"
fi

rm -rf "$WORK"
(cd "$DIST" && shasum -a 256 * > SHA256SUMS.txt 2>/dev/null || sha256sum * > SHA256SUMS.txt)
echo "Done:"
ls -lh "$DIST"
