#!/usr/bin/env bash
# Builds the downloads into dist/:
#   OpenDecoDesk-Machine-Agent-macOS-<version>.zip     the Mac app (Apple Silicon + Intel in one)
#   OpenDecoDesk-Machine-Agent-Windows-<version>.exe   the Windows program
#   opendecodesk-machine-agent-linux-{amd64,arm64}-<version>
# Needs Go. The Mac app is only put together on a Mac (it needs lipo, codesign and ditto); elsewhere
# the Mac programs are still compiled, as a check.
set -euo pipefail
cd "$(dirname "$0")"

VERSION="${VERSION:-$(date +%Y.%m.%d)-$(git rev-parse --short HEAD 2>/dev/null || echo local)}"
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
build windows amd64 "$DIST/OpenDecoDesk-Machine-Agent-Windows-$VERSION.exe" "-H windowsgui"
build linux amd64 "$DIST/opendecodesk-machine-agent-linux-amd64-$VERSION"
build linux arm64 "$DIST/opendecodesk-machine-agent-linux-arm64-$VERSION"

if command -v lipo >/dev/null && command -v codesign >/dev/null && command -v ditto >/dev/null; then
  echo "  macOS app"
  APP="$WORK/$APP_NAME.app"
  mkdir -p "$APP/Contents/MacOS"
  lipo -create -output "$APP/Contents/MacOS/$APP_NAME" "$WORK/agent-darwin-arm64" "$WORK/agent-darwin-amd64"
  sed -e "s/__VERSION__/$VERSION/g" -e "s/__SHORT_VERSION__/${VERSION%%-*}/g" packaging/macos/Info.plist \
    > "$APP/Contents/Info.plist"
  # Ad-hoc signature: not a Developer ID (macOS still asks once, "Open Anyway"), but Apple Silicon
  # won't run a program with no signature at all.
  xattr -cr "$APP"  # codesign refuses extended attributes ("detritus")
  codesign --force --sign - "$APP"
  ditto -c -k --keepParent "$APP" "$DIST/OpenDecoDesk-Machine-Agent-macOS-$VERSION.zip"
else
  echo "  (not on a Mac: skipping the macOS app)"
fi

rm -rf "$WORK"
(cd "$DIST" && shasum -a 256 * > SHA256SUMS.txt 2>/dev/null || sha256sum * > SHA256SUMS.txt)
echo "Done:"
ls -lh "$DIST"
