import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

// Screenshots for the /changelog page. The pictures live under
// public/marketing/changelog/<version>/, which the app build deletes, so they
// never reach a binary; the app bundle carries only the `shot` key on an item.
//
// Every picture enters through ops/changelog-shots/ingest.mjs, which encodes
// it and records its size and SHA-256 in shots.json. This module refuses a
// file the manifest does not describe byte for byte, so a hand-copied PNG or a
// re-saved WebP cannot bypass the house encoding.
// Spec: ops/docs/plans/changelog-screenshots.md

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SHOTS_DIR = path.resolve(__dirname, 'public/marketing/changelog');
/** The public URL of SHOTS_DIR. */
const SHOTS_URL = '/marketing/changelog';

type Variant = { w: number; h: number; bytes: number; sha256: string };
type ManifestEntry = Variant & { dark?: Variant };
type ShotsManifest = Record<string, Record<string, ManifestEntry>>;

export type Shot = {
  key: string;
  /** Index of the item the shot illustrates, in release order. */
  item: number;
  alt: string;
  src: string;
  w: number;
  h: number;
  dark?: { src: string; w: number; h: number };
};

type Release = { version: string; items: Array<{ text: string; shot?: string | string[] }> };

/** Thrown for any state the ingest script would never produce. */
class ShotsError extends Error {}

/** The most shots one release may carry: the thumbnail row holds this many on one line.
 *  Spec: ops/docs/plans/changelog-screenshots.md */
const MAX_SHOTS = 7;

const FIX = 'Add pictures with node ops/changelog-shots/ingest.mjs, never by hand.';

function fileName(key: string, dark: boolean): string {
  return `${key}${dark ? '.dark' : ''}.webp`;
}

/**
 * Reads the manifest and the folder, checks one against the other and both
 * against the releases, and returns the shots per release version in item
 * order. Orphan pictures (in the manifest, named by no item) are returned in
 * `orphans` and left off the page: a half-finished drop must not block a
 * release. A missing, unlisted or altered file throws.
 */
export function loadShots(
  releases: Release[],
  dir: string = SHOTS_DIR,
): { byVersion: Map<string, Shot[]>; orphans: string[] } {
  const manifestPath = path.join(dir, 'shots.json');
  const manifest: ShotsManifest = fs.existsSync(manifestPath)
    ? JSON.parse(fs.readFileSync(manifestPath, 'utf8'))
    : {};

  // Every file on disk must be a manifest entry, and match it exactly.
  const expected = new Map<string, Variant>();
  for (const [version, entries] of Object.entries(manifest)) {
    for (const [key, entry] of Object.entries(entries)) {
      expected.set(`${version}/${fileName(key, false)}`, entry);
      if (entry.dark) expected.set(`${version}/${fileName(key, true)}`, entry.dark);
    }
  }
  // Every file counts but the manifest and the folder notes Finder writes, so
  // a stray file at the top or a dotfile in a version folder is refused too.
  const onDisk = new Set<string>();
  if (fs.existsSync(dir)) {
    for (const version of fs.readdirSync(dir, { withFileTypes: true })) {
      if (version.name === '.DS_Store') continue;
      if (!version.isDirectory()) {
        if (version.name !== 'shots.json') onDisk.add(version.name);
        continue;
      }
      for (const f of fs.readdirSync(path.join(dir, version.name))) {
        if (f === '.DS_Store') continue;
        onDisk.add(`${version.name}/${f}`);
      }
    }
  }
  for (const rel of onDisk) {
    const want = expected.get(rel);
    if (!want) throw new ShotsError(`changelog shots: ${rel} is not in shots.json. ${FIX}`);
    const buf = fs.readFileSync(path.join(dir, rel));
    const sha = createHash('sha256').update(buf).digest('hex');
    if (buf.length !== want.bytes || sha !== want.sha256)
      throw new ShotsError(`changelog shots: ${rel} does not match shots.json. ${FIX}`);
  }
  for (const rel of expected.keys()) {
    if (!onDisk.has(rel)) throw new ShotsError(`changelog shots: shots.json lists ${rel}, which is missing.`);
  }

  // Every shot key an item names must exist; unnamed pictures are orphans.
  const used = new Set<string>();
  const byVersion = new Map<string, Shot[]>();
  for (const r of releases) {
    const shots: Shot[] = [];
    r.items.forEach((it, item) => {
      for (const key of it.shot === undefined ? [] : [it.shot].flat()) {
        const entry = manifest[r.version]?.[key];
        if (!entry)
          throw new ShotsError(`changelog shots: v${r.version} names shot "${key}", which is not in shots.json.`);
        used.add(`${r.version}/${key}`);
        const base = `${SHOTS_URL}/${r.version}/`;
        shots.push({
          key,
          item,
          alt: it.text,
          src: base + fileName(key, false),
          w: entry.w,
          h: entry.h,
          dark: entry.dark ? { src: base + fileName(key, true), w: entry.dark.w, h: entry.dark.h } : undefined,
        });
      }
    });
    if (shots.length > MAX_SHOTS)
      throw new ShotsError(`changelog shots: v${r.version} has ${shots.length} shots, more than ${MAX_SHOTS}.`);
    if (shots.length) byVersion.set(r.version, shots);
  }
  const orphans: string[] = [];
  for (const [version, entries] of Object.entries(manifest))
    for (const key of Object.keys(entries)) if (!used.has(`${version}/${key}`)) orphans.push(`${version}/${key}`);

  return { byVersion, orphans };
}
