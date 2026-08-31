#!/usr/bin/env node
// Sync the native build version from the single source of truth (web/src/version.ts)
// into tauri.conf.json, Cargo.toml and the Android version stamp. Runs automatically
// before every Tauri dev/build (wired into beforeDevCommand/beforeBuildCommand in
// tauri.conf.json).
// Spec: ops/docs/commit-workflow.md (version single source)
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

// Resolve everything from this script's location so the cwd never matters.
const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');

const versionTsPath = resolve(root, 'packages/web/src/version.ts');
const versionTs = readFileSync(versionTsPath, 'utf8');
const match = versionTs.match(/export const VERSION = '([^']+)'/);
if (!match) {
  console.error('sync-version: could not find VERSION in', versionTsPath);
  process.exit(1);
}
const version = match[1];

const updated = [];

// tauri.conf.json: top-level "version": "x.y.z"
const confPath = resolve(root, 'packages/desktop/src-tauri/tauri.conf.json');
const conf = readFileSync(confPath, 'utf8');
const confNext = conf.replace(/^(\s*"version":\s*")[^"]+(")/m, `$1${version}$2`);
if (confNext !== conf) {
  writeFileSync(confPath, confNext);
  updated.push('tauri.conf.json');
}

// Cargo.toml: the version line inside the [package] section only
const cargoPath = resolve(root, 'packages/desktop/src-tauri/Cargo.toml');
const cargo = readFileSync(cargoPath, 'utf8');
const cargoNext = cargo.replace(/(\[package\][^[]*?\nversion\s*=\s*")[^"]+(")/, `$1${version}$2`);
if (cargoNext !== cargo) {
  writeFileSync(cargoPath, cargoNext);
  updated.push('Cargo.toml');
}

// gen/android/app/tauri.properties: the versionName/versionCode gradle actually reads.
// Tauri writes it at `android init` and does not reliably refresh it afterwards, so without
// this an AAB ships new code under the previous stamp, which Play rejects as a duplicate
// versionCode. Skipped when the Android project has never been generated on this machine.
// Spec: ops/docs/android-setup.md (Android version stamp)
const androidPropsPath = resolve(
  root,
  'packages/desktop/src-tauri/gen/android/app/tauri.properties',
);
if (existsSync(androidPropsPath)) {
  const [major, minor, patch] = version.split('.').map(Number);
  // The encoding gives minor and patch 3 digits each, so either one reaching 1000 would
  // silently collide with the next major. Fail the build instead: a duplicate versionCode
  // cannot be un-published once Play has seen it.
  if (![major, minor, patch].every(Number.isInteger) || minor > 999 || patch > 999) {
    console.error(`sync-version: cannot encode "${version}" as an Android versionCode`);
    process.exit(1);
  }
  const versionCode = major * 1000000 + minor * 1000 + patch;
  const props = readFileSync(androidPropsPath, 'utf8');
  const propsNext = props
    .replace(/^(tauri\.android\.versionName=).*$/m, `$1${version}`)
    .replace(/^(tauri\.android\.versionCode=).*$/m, `$1${versionCode}`);
  if (propsNext !== props) {
    writeFileSync(androidPropsPath, propsNext);
    updated.push(`tauri.properties (versionCode ${versionCode})`);
  }
}

console.log(
  `sync-version: ${version}` +
    (updated.length ? ` -> updated ${updated.join(', ')}` : ' (already in sync)'),
);
