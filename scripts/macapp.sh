#!/usr/bin/env bash
# Package a double-clickable adX.app around a built macOS binary.
# Usage: scripts/macapp.sh [arm64|amd64]   (default: arm64)
set -euo pipefail
cd "$(dirname "$0")/.."

ARCH="${1:-arm64}"
BIN="dist/adx-darwin-$ARCH"
[ -f "$BIN" ] || { echo "missing $BIN — run scripts/build.sh first"; exit 1; }

APP="dist/adX.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

cp "$BIN" "$APP/Contents/Resources/adx"
chmod +x "$APP/Contents/Resources/adx"

cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>adX</string>
  <key>CFBundleDisplayName</key><string>adX</string>
  <key>CFBundleIdentifier</key><string>sh.adx.app</string>
  <key>CFBundleVersion</key><string>0.1.0</string>
  <key>CFBundleShortVersionString</key><string>0.1.0</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleExecutable</key><string>adX</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>LSUIElement</key><true/>
</dict>
</plist>
PLIST

# The launcher runs the server headless (no Terminal window) and opens the
# browser. adX quits itself when the browser tab closes, so there is nothing
# to stop by hand.
cat > "$APP/Contents/MacOS/adX" <<'LAUNCH'
#!/bin/bash
HERE="$(cd "$(dirname "$0")/../Resources" && pwd)"
exec "$HERE/adx" >/tmp/adx.log 2>&1
LAUNCH
chmod +x "$APP/Contents/MacOS/adX"

# Clear any quarantine so Gatekeeper does not nag on this machine.
xattr -cr "$APP" 2>/dev/null || true

echo "built $APP"
