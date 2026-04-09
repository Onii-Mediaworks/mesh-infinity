#!/usr/bin/env bash
# screenshot.sh — launch the app in a virtual framebuffer and capture a screenshot.
#
# Usage:
#   ./scripts/screenshot.sh [output.png] [WxH] [settle_seconds]
#
# Defaults: output = /tmp/mi_screenshot.png, size = 1280x800, settle = 12
#
# Requires: Xvfb, openbox, scrot  (sudo apt install xvfb openbox scrot)

set -euo pipefail

OUTFILE="${1:-/tmp/mi_screenshot.png}"
GEOMETRY="${2:-1280x800}"
SETTLE="${3:-12}"
DISPLAY_NUM=":99"
APP="build/intermediates/linux/debug/src/build/linux/x64/debug/bundle/mesh_infinity_frontend"

# Make sure the binary exists.
if [[ ! -f "$APP" ]]; then
  echo "Binary not found at $APP — run 'make linux-debug' first." >&2
  exit 1
fi

# Kill any leftover processes on :99.
pkill -f "Xvfb $DISPLAY_NUM" 2>/dev/null || true
pkill -f mesh_infinity_frontend 2>/dev/null || true
sleep 1

# Start virtual framebuffer.
Xvfb "$DISPLAY_NUM" -screen 0 "${GEOMETRY}x24" -ac &
XVFB_PID=$!
sleep 1

# Window manager — keeps the Flutter window managed.
# Suppress the missing-menu-file warning (Debian openbox quirk).
DISPLAY="$DISPLAY_NUM" openbox --sm-disable 2>/dev/null &
WM_PID=$!
sleep 0.5

# Launch the app; redirect output to a log so it doesn't clutter the terminal.
DISPLAY="$DISPLAY_NUM" "$APP" >/tmp/mi_app.log 2>&1 &
APP_PID=$!

# Wait for Flutter to render (first frame + settle time).
echo "Waiting ${SETTLE}s for Flutter to render..."
sleep "$SETTLE"

# Take the screenshot.
DISPLAY="$DISPLAY_NUM" scrot "$OUTFILE"
echo "Screenshot saved to $OUTFILE"

# Cleanup.
kill "$APP_PID" "$WM_PID" "$XVFB_PID" 2>/dev/null || true
