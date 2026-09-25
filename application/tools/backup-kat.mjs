/**
 * Known-answer tests for the .pnbackup format.
 *
 * WHY THIS EXISTS
 * ---------------
 * The encrypted backup is the user's last line of defence: if sync, the
 * database, and every device are gone, the .pnbackup file plus the 12-word
 * phrase must still reproduce the vault. Nothing else tested this. A
 * dependency bump or refactor that shifts the format by one byte does not
 * error today; it quietly writes backups that a future restore cannot read,
 * or stops reading the backups users already hold.
 *
 * Two guarantees, in order of importance:
 *
 *  1. COMPATIBILITY: tools/fixtures/backup-golden-v3.pnbackup is a frozen
 *     file standing in for every backup on a user's disk. It must decrypt,
 *     forever, with the key derived from the public all-abandon test phrase.
 *     If a change makes the golden test fail, the change broke existing
 *     backups. Do NOT regenerate the fixture to make the test pass; that is
 *     the alarm working. (Deliberate format migrations must delete the file
 *     consciously, ship a restore path for old files, and say so in the
 *     changelog.)
 *
 *  2. ROUND-TRIP: what buildBackupPayload/encodeBackup write today,
 *     decodeBackup must read back identically, across every note pillar.
 *
 * Runs against the compiled packages/shared/dist (the REAL format code, the
 * same functions packages/web/src/export.ts calls), node:test only, no new
 * dependencies:
 *
 *   pnpm test:backup
 *
 * KNOWN NON-GUARANTEES, on purpose:
 *  - No restore gates on the version: decodeBackup decodes a future-versioned
 *    payload and surfaces its version field, and importEncryptedBackup in
 *    notesView/useExports.ts never reads it. Asserted below so the contract
 *    is explicit.
 *  - Image/attachment blobs are not part of .pnbackup (raw pn:img/ and
 *    pn:file/ refs ride along in bodies); the zip backup covers blobs.
 *
 * Spec: ops/docs/dependency-migration.md (section 3), packages/shared/src/backup.ts
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import {
  phraseToSeed,
  deriveEncryptionKey,
  encryptJson,
  buildBackupPayload,
  encodeBackup,
  decodeBackup,
  BACKUP_VERSION,
  BACKUP_TOO_SMALL,
} from '../packages/shared/dist/index.js';

const here = path.dirname(fileURLToPath(import.meta.url));

/** Same public BIP-39 vector phrase as crypto-kat.mjs. */
const PHRASE =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const PHRASE_2 =
  'legal winner thank year wave sausage worth useful legal winner thank yellow';

const KEY = deriveEncryptionKey(phraseToSeed(PHRASE));
const WRONG_KEY = deriveEncryptionKey(phraseToSeed(PHRASE_2));

/** JSON-normalize: encryptJson stringifies the payload, and JSON.stringify
 *  drops undefined-valued fields, so a decoded payload never carries them.
 *  Comparisons must happen in JSON space or {starred: undefined} vs a missing
 *  key would fail deep-equality for a difference the format cannot express. */
const viaJson = (value) => JSON.parse(JSON.stringify(value));

/** Fixture rows shaped like the web client's LocalNote, one per pillar. */
const NOTES = [
  {
    id: 'n-unicode',
    title: 'Träume & Ziele 🚀',
    body: '# H\n\n[[note-link]] and <https://privacynotes.app> and äöü 日本語 🎉',
    tags: ['työ', '日本語'],
    createdAt: '2026-07-01T08:00:00.000Z',
    updatedAt: '2026-07-15T09:30:00.000Z',
    starred: 1,
    type: 'note',
    locked: 0,
    pinProtected: 0,
  },
  {
    id: 'n-task',
    title: 'Chores',
    body: '- [ ] water plants\n- [x] trash',
    tags: [],
    createdAt: '2026-07-02T08:00:00.000Z',
    updatedAt: '2026-07-14T10:00:00.000Z',
    starred: 0,
    type: 'task',
    locked: 0,
    pinProtected: 0,
    folderId: 'folder-a',
  },
  {
    id: 'n-journal',
    title: 'Journal',
    body: 'Slept fine.',
    tags: ['journal'],
    createdAt: '2026-07-03T21:00:00.000Z',
    updatedAt: '2026-07-03T21:05:00.000Z',
    starred: 0,
    type: 'journal',
    locked: 0,
    pinProtected: 0,
    trackers: { mood: 4, sleepHours: 7.5, activities: ['walk'] },
  },
  {
    id: 'n-login',
    title: 'Example login',
    body: '{"domain":"example.com","username":"synthetic","password":"not-real"}',
    tags: ['vault'],
    createdAt: '2026-07-04T12:00:00.000Z',
    updatedAt: '2026-07-04T12:00:00.000Z',
    starred: 0,
    type: 'login',
    locked: 1,
    pinProtected: 1,
  },
];

const FOLDERS = [
  { id: 'folder-a', name: 'Chores', parentId: null, order: 0 },
];

// ------------------------------------------------------------------------------------
// Round-trip: today's writer, today's reader
// ------------------------------------------------------------------------------------

test('encode/decode round-trips every pillar byte-faithfully (JSON space)', () => {
  const payload = buildBackupPayload(NOTES, FOLDERS, '2026-07-16T12:00:00.000Z');
  const out = decodeBackup(encodeBackup(payload, KEY), KEY);
  assert.deepEqual(out, viaJson(payload));
  assert.equal(out.version, BACKUP_VERSION);
  assert.equal(out.notes.length, NOTES.length);
  assert.deepEqual(out.folders, FOLDERS);
});

test('payload field rules: type defaults, empty folderId/trackers/folders are omitted', () => {
  const bare = buildBackupPayload(
    [
      {
        id: 'n-bare',
        title: 'no type',
        body: 'b',
        tags: [],
        createdAt: '2026-07-01T00:00:00.000Z',
        updatedAt: '2026-07-01T00:00:00.000Z',
        // no type, no folderId, no trackers: predates note types
      },
    ],
    [],
    '2026-07-16T12:00:00.000Z',
  );
  const note = bare.notes[0];
  assert.equal(note.type, 'note', 'missing type must default to note');
  assert.ok(!('folderId' in note), 'empty folderId must be omitted, not null');
  assert.ok(!('trackers' in note), 'empty trackers must be omitted');
  assert.ok(!('folders' in bare), 'no folders array when there are none');

  const out = decodeBackup(encodeBackup(bare, KEY), KEY);
  assert.deepEqual(out, viaJson(bare));
});

test('folder and tag looks ride along, and an empty map is omitted', () => {
  const looks = {
    'f:f1': { icon: { v: 'airplane', at: '2026-09-24T10:00:00.000Z' }, color: { v: 'teal', at: '2026-09-24T10:00:00.000Z' } },
    't:urgent': { color: { v: 'red', at: '2026-09-24T10:00:00.000Z' } },
  };
  const payload = buildBackupPayload(NOTES, FOLDERS, '2026-07-16T12:00:00.000Z', looks);
  const out = decodeBackup(encodeBackup(payload, KEY), KEY);
  assert.deepEqual(out.itemStyles, looks);
  const none = buildBackupPayload(NOTES, FOLDERS, '2026-07-16T12:00:00.000Z', {});
  assert.ok(!('itemStyles' in none), 'no itemStyles key when no folder or tag has a look');
});

test('empty vault round-trips', () => {
  const payload = buildBackupPayload([], [], '2026-07-16T12:00:00.000Z');
  const out = decodeBackup(encodeBackup(payload, KEY), KEY);
  assert.deepEqual(out.notes, []);
  assert.equal(out.version, BACKUP_VERSION);
});

test('every encode uses a fresh 24-byte nonce; both decodings agree', () => {
  const payload = buildBackupPayload(NOTES, FOLDERS, '2026-07-16T12:00:00.000Z');
  const a = encodeBackup(payload, KEY);
  const b = encodeBackup(payload, KEY);
  assert.notDeepEqual(a.slice(0, 24), b.slice(0, 24), 'nonce must not repeat');
  assert.deepEqual(decodeBackup(a, KEY), decodeBackup(b, KEY));
});

// ------------------------------------------------------------------------------------
// Compatibility: yesterday's file, tomorrow's reader. THE load-bearing test.
// ------------------------------------------------------------------------------------

test('golden v3 fixture decrypts to its committed expected payload', () => {
  const golden = new Uint8Array(
    readFileSync(path.join(here, 'fixtures', 'backup-golden-v3.pnbackup')),
  );
  const expected = JSON.parse(
    readFileSync(path.join(here, 'fixtures', 'backup-golden-v3.expected.json'), 'utf8'),
  );
  const out = decodeBackup(golden, KEY);
  // If this fails and you did not deliberately migrate the format: the change
  // you are testing breaks every existing user backup. Fix the change, do not
  // regenerate the fixture.
  assert.deepEqual(out, expected);
  assert.equal(out.version, 3);
  assert.equal(out.notes.length, 6);
});

test('app-exported golden decrypts: the real browser UI wrote these bytes', () => {
  // Captured 2026-07-16 from a DEMO session's Settings > Export > Encrypted
  // backup (v0.251.6 era). The demo phrase is the same public all-abandon
  // BIP-39 vector, so this fixture is decryptable in CI and contains only the
  // seeded demo content. Unlike backup-golden-v3.pnbackup (written by the
  // extracted functions), these bytes went through the full production glue:
  // Dexie rows -> NotesView -> exportEncryptedBackup -> file download. If
  // this fails while the synthetic golden passes, the browser-side wiring
  // drifted from the format core.
  const golden = new Uint8Array(
    readFileSync(path.join(here, 'fixtures', 'backup-golden-v3-app.pnbackup')),
  );
  const expected = JSON.parse(
    readFileSync(path.join(here, 'fixtures', 'backup-golden-v3-app.expected.json'), 'utf8'),
  );
  const out = decodeBackup(golden, KEY);
  assert.deepEqual(out, expected);
  assert.equal(out.version, 3);
  assert.equal(out.notes.length, 7);
  assert.equal(out.folders.length, 2);
});

// ------------------------------------------------------------------------------------
// Loud failure: wrong key, tampering, truncation
// ------------------------------------------------------------------------------------

test('wrong phrase must not decrypt (Poly1305 authenticates)', () => {
  const bytes = encodeBackup(buildBackupPayload(NOTES, FOLDERS), KEY);
  assert.throws(() => decodeBackup(bytes, WRONG_KEY));
});

test('a single flipped bit must fail authentication, not return garbage', () => {
  const bytes = encodeBackup(buildBackupPayload(NOTES, FOLDERS), KEY);
  const tampered = Uint8Array.from(bytes);
  tampered[tampered.length - 5] ^= 0x01;
  assert.throws(() => decodeBackup(tampered, KEY));
  const nonceTampered = Uint8Array.from(bytes);
  nonceTampered[3] ^= 0x01;
  assert.throws(() => decodeBackup(nonceTampered, KEY));
});

test('truncated input throws the stable BACKUP_TOO_SMALL code', () => {
  assert.throws(() => decodeBackup(new Uint8Array(0), KEY), new RegExp(BACKUP_TOO_SMALL));
  assert.throws(() => decodeBackup(new Uint8Array(24), KEY), new RegExp(BACKUP_TOO_SMALL));
});

// ------------------------------------------------------------------------------------
// Version handling contract
// ------------------------------------------------------------------------------------

test('decode surfaces an unknown future version instead of hiding it', () => {
  // Version gating is deliberately the caller's job (it owns the UI); the
  // format layer's contract is only that the field arrives intact.
  const future = { version: 4, exportedAt: '2027-01-01T00:00:00.000Z', notes: [] };
  const { ciphertext, nonce } = encryptJson(future, KEY);
  const bytes = new Uint8Array(nonce.length + ciphertext.length);
  bytes.set(nonce, 0);
  bytes.set(ciphertext, nonce.length);
  const out = decodeBackup(bytes, KEY);
  assert.equal(out.version, 4);
});
