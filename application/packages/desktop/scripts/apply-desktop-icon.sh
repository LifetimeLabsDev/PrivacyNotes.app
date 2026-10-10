#!/usr/bin/env bash
# macOS does NOT auto-round app icons (unlike iOS). The .icns must already be the
# rounded "squircle" with padding. `tauri icon` only makes a flat icon, so this
# rebuilds icon.icns from the squircle master that scripts/make-app-icons.py writes.
# The PNG sizes stay as `tauri icon` wrote them: the full tile that Windows and
# Linux show, where the squircle's grid margin made the icon look small.
#
# Runs automatically after `pnpm icon`. macOS only (uses sips + iconutil).

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

echo "Desktop icon.icns rebuilt from the macOS master."
