#!/usr/bin/env bash
# Post-init iOS fixup, run AFTER `tauri ios init` (gen/apple is regenerated and
# gitignored, so this must re-run after every init): swaps the iOS app icon to a
# single 1024px icon with Light / Dark / Tinted appearance variants, because
# `tauri icon` only generates the light one.
#
# The iOS bundle registers no URL scheme, and this script must never splice
# CFBundleURLTypes into the generated Info.plist: any app can claim a scheme.
# Spec: ops/docs/plans/oauth-redirect-binding-handoff.md (section 13)
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

# Apple's privacy manifest. It MUST sit at the bundle root: dropping the file in
# the target's source directory does nothing (xcodegen ignores unknown types
# there), and gen/apple/assets is a folder reference, so anything inside it lands
# in PrivacyNotes.app/assets/ where Apple never looks. The only placement that
# works is an explicit resource entry in project.yml - which Tauri regenerates
# whenever gen/apple is deleted, hence this block.
GEN="$HERE/src-tauri/gen/apple"
cp "$HERE/src-tauri/PrivacyInfo.xcprivacy" "$GEN/PrivacyInfo.xcprivacy"
SPEC_CHANGED=0
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
  SPEC_CHANGED=1
  echo "Registered PrivacyInfo.xcprivacy as a bundle resource."
else
  echo "PrivacyInfo.xcprivacy already registered in project.yml, skipping."
fi

# The Externals folder holds the Rust library per configuration. Tauri's
# template lists it as a plain source folder, so xcodegen copies every
# libapp.a it finds there into the bundle as a resource, and Xcode refuses
# the build as soon as a debug and a release artifact both exist. A fresh
# init never sees that, because the wipe empties the folder; every later
# xcodegen run does. `buildPhase: none` keeps the folder in the navigator
# and out of every build phase; the library is linked through
# LIBRARY_SEARCH_PATHS. tests/desktopCapabilities.test.ts pins the line.
if ! grep -q "buildPhase: none" "$GEN/project.yml"; then
  python3 - "$GEN/project.yml" <<'PYEOF'
import sys
p = sys.argv[1]
s = open(p).read()
anchor = "      - path: Externals\n"
add = "        buildPhase: none\n"
if anchor not in s:
    sys.exit("apply-ios-appearance-icons: project.yml Externals entry not found; "
             "Tauri changed its template, re-derive the entry by hand")
open(p, "w").write(s.replace(anchor, anchor + add, 1))
PYEOF
  SPEC_CHANGED=1
  echo "Took the Externals folder out of every build phase."
else
  echo "Externals already carries buildPhase: none, skipping."
fi

# project.yml is only read by xcodegen, and Tauri already ran it during init -
# so an edit above is invisible until xcodegen runs again. Do it here rather
# than making the caller remember a second init.
if [ "$SPEC_CHANGED" = 1 ]; then
  (cd "$GEN" && xcodegen generate --spec project.yml >/dev/null)
  echo "Regenerated the Xcode project from the patched spec."
fi

echo "Rebuild with 'pnpm ios:dev' or in Xcode to see the changes."
