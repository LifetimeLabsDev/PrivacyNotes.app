#!/usr/bin/env bash
# Post-init iOS fixup, run AFTER `tauri ios init` (gen/apple is regenerated and
# gitignored, so this must re-run after every init): swaps the iOS app icon to a
# single 1024px icon with Light / Dark / Tinted appearance variants, because
# `tauri icon` only generates the light one.
#
# This script USED to also splice CFBundleURLTypes into the generated Info.plist,
# because the deep-link plugin does not inject it (`plugins.deep-link.mobile` is
# not translated into a URL scheme on iOS - only the desktop half is, and only by
# the macOS bundler). That job moved to `src-tauri/Info.ios.plist` on 2026-08-15,
# which Tauri merges at init. Two reasons for the move: the plist is declarative
# rather than a string-replace against generated XML that Tauri is free to
# reformat, and it applies even when someone runs `ios:init` without `ios:icons`.
# Do not re-add the splice here - a second writer would be invisible until the
# day the two disagreed.
#
# Run from packages/desktop:
#   bash scripts/apply-ios-appearance-icons.sh
#
# Safe to re-run. Requires the iOS project to already exist (gen/apple).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$HERE/src-tauri/icons/ios-appearances"
DEST="$HERE/src-tauri/gen/apple/Assets.xcassets/AppIcon.appiconset"

if [ ! -d "$HERE/src-tauri/gen/apple" ]; then
  echo "ERROR: src-tauri/gen/apple not found. Run 'pnpm tauri ios init' first." >&2
  exit 1
fi

mkdir -p "$DEST"
# Remove Tauri's multi-size icons + manifest so only our appearance set remains.
rm -f "$DEST"/*.png "$DEST"/Contents.json

cp "$SRC/AppIcon-light-1024.png"  "$DEST/"
cp "$SRC/AppIcon-dark-1024.png"   "$DEST/"
cp "$SRC/AppIcon-tinted-1024.png" "$DEST/"
cp "$SRC/Contents.json"           "$DEST/"

echo "Applied Light/Dark/Tinted app icons to:"
echo "  $DEST"

# The URL scheme comes from src-tauri/Info.ios.plist, which Tauri merges at BUILD
# time, not at init - so its absence here is expected and this is a note, not a
# failure. The check that matters runs against the BUILT bundle; see the iOS
# section of ops/docs/mobile-dev-runbook.md. Without the scheme, OAuth sign-in
# dead-ends with no error anywhere, so it is worth confirming before you ship.
PLIST="$(ls "$HERE"/src-tauri/gen/apple/*_iOS/Info.plist 2>/dev/null | head -1)"
if [ -n "${PLIST:-}" ] && ! grep -q "CFBundleURLTypes" "$PLIST"; then
  echo "note: CFBundleURLTypes not in the generated plist yet - Info.ios.plist merges at build."
fi

# Apple's privacy manifest. It MUST sit at the bundle root: dropping the file in
# the target's source directory does nothing (xcodegen ignores unknown types
# there), and gen/apple/assets is a folder reference, so anything inside it lands
# in PrivacyNotes.app/assets/ where Apple never looks. The only placement that
# works is an explicit resource entry in project.yml - which Tauri regenerates
# whenever gen/apple is deleted, hence this block.
GEN="$HERE/src-tauri/gen/apple"
cp "$HERE/src-tauri/PrivacyInfo.xcprivacy" "$GEN/PrivacyInfo.xcprivacy"
if ! grep -q "PrivacyInfo.xcprivacy" "$GEN/project.yml"; then
  python3 - "$GEN/project.yml" <<'PYEOF'
import sys
p = sys.argv[1]
s = open(p).read()
anchor = "      - path: LaunchScreen.storyboard\n"
add = "      - path: PrivacyInfo.xcprivacy\n        buildPhase: resources\n"
if anchor not in s:
    sys.exit("apply-ios-appearance-icons: project.yml anchor not found; "
             "Tauri changed its template, re-derive the resource entry by hand")
open(p, "w").write(s.replace(anchor, anchor + add, 1))
PYEOF
  # project.yml is only read by xcodegen, and Tauri already ran it during init -
  # so the edit above is invisible until xcodegen runs again. Do it here rather
  # than making the caller remember a second init.
  (cd "$GEN" && xcodegen generate --spec project.yml >/dev/null)
  echo "Registered PrivacyInfo.xcprivacy as a bundle resource and regenerated the Xcode project."
else
  echo "PrivacyInfo.xcprivacy already registered in project.yml, skipping."
fi

echo "Rebuild with 'pnpm ios:dev' or in Xcode to see the changes."
