#!/usr/bin/env bash
# macOS does NOT auto-round app icons (unlike iOS). The .icns must already be the
# styled rounded "squircle" with padding. `tauri icon` only makes a flat icon, so
# this rebuilds the desktop icon (icns + the PNG sizes used by the window/other
# platforms) from the committed styled master.
#
# Runs automatically after `pnpm icon`. macOS only (uses sips + iconutil).
# To change the macOS look, edit src-tauri/icons/macos-master-1024.png and re-run.

set -euo pipefail

if ! command -v iconutil >/dev/null 2>&1 || ! command -v sips >/dev/null 2>&1; then
  echo "apply-desktop-icon: skipping (sips/iconutil not found - macOS only)"
  exit 0
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ICONS="$HERE/src-tauri/icons"
MASTER="$ICONS/macos-master-1024.png"

if [ ! -f "$MASTER" ]; then
  echo "ERROR: $MASTER not found." >&2
  exit 1
fi

# Build icon.icns from a standard iconset via iconutil.
TMP="$(mktemp -d)"; SET="$TMP/icon.iconset"; mkdir -p "$SET"
for s in 16 32 128 256 512; do
  sips -z "$s" "$s"       "$MASTER" --out "$SET/icon_${s}x${s}.png"     >/dev/null
  d=$((s * 2))
  sips -z "$d" "$d"       "$MASTER" --out "$SET/icon_${s}x${s}@2x.png"  >/dev/null
done
iconutil -c icns "$SET" -o "$ICONS/icon.icns"
rm -rf "$TMP"

# Styled PNG sizes (window icon / Linux / Windows fallback).
sips -z 32 32   "$MASTER" --out "$ICONS/32x32.png"       >/dev/null
sips -z 64 64   "$MASTER" --out "$ICONS/64x64.png"       >/dev/null
sips -z 128 128 "$MASTER" --out "$ICONS/128x128.png"     >/dev/null
sips -z 256 256 "$MASTER" --out "$ICONS/128x128@2x.png"  >/dev/null
sips -z 512 512 "$MASTER" --out "$ICONS/icon.png"        >/dev/null

echo "Desktop icon rebuilt from styled macOS master (icon.icns + PNG sizes)."
