#!/usr/bin/env bash
#
# apply-android-icons.sh - copy the generated Android launcher icons
# (src-tauri/icons/android, produced by `pnpm icon`) into the regenerated
# gen/android project. `tauri android init` scaffolds res/ with Tauri's
# TEMPLATE icon and never pulls in ours, so a re-init (or a fresh CI
# checkout) ships the template swirl instead of the brand icon unless this
# runs. Wired into `android:init` and the `icon` pipeline; also exposed as
# `pnpm android:icons`. Safe to run any time; no-ops when gen/android does
# not exist yet.
#
# Also carries the adaptive-icon layer (mipmap-anydpi-v26/ic_launcher.xml +
# values/ic_launcher_background.xml), which the template lacks entirely -
# without it, Android 8+ launchers mask the legacy PNG instead of using the
# proper foreground/background adaptive icon.
#
# Spec: ops/docs/android-setup.md (launcher icons)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$SCRIPT_DIR/../src-tauri/icons/android"
DST="$SCRIPT_DIR/../src-tauri/gen/android/app/src/main/res"

[ -d "$SRC" ] || { echo "FATAL: $SRC missing - run pnpm icon first" >&2; exit 1; }
[ -d "$DST" ] || { echo "skip: gen/android not initialized yet (pnpm android:init)"; exit 0; }

cp -R "$SRC/." "$DST/"
echo "Applied Android launcher icons to gen/android: $(ls "$SRC" | tr '\n' ' ')"
