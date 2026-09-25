/**
 * The per-field merge of two versions of one note against the version this
 * device last synced, its base. Pure: no database and no network, so
 * tests/noteMerge.test.ts drives every branch directly.
 *
 * sync.ts runs it when a push finds that the server row is no longer the
 * generation this device synced, and useSyncOrchestrator.ts runs it again
 * when the person answers the conflict dialog, over the row as it stands
 * then.
 *
 * Spec: ops/docs/sync-protocol.md (section 2, step 4)
 */
import type { EncryptedPayload, NoteType } from '@notes/shared';
import type { LocalNote } from './db';
import { mergeTrackers, trackersEqual } from './trackerTypes';

/** A note's encrypted payload with every field present, flags as booleans. */
export interface NoteFields {
  title: string;
  body: string;
  tags: string[];
  trashed: boolean;
  starred: boolean;
  locked: boolean;
  pinProtected: boolean;
  type: NoteType;
  folderId: string | null;
  trackers: Record<string, unknown> | undefined;
}

/** Every field but the body: the part the merge always settles itself. */
type NoteRest = Omit<NoteFields, 'body'>;

/** The fields the merge compares, in payload order. */
export const NOTE_FIELDS = [
  'title',
  'body',
  'tags',
  'trashed',
  'starred',
  'locked',
  'pinProtected',
  'type',
  'folderId',
  'trackers',
] as const;
type FieldName = (typeof NOTE_FIELDS)[number];

/**
 * What this device last synced of a note: one fingerprint per field, one
 * per tag, and the nonce of the server generation they describe. A
 * fingerprint answers one question, whether a field changed since that
 * generation, which is all a three-way merge asks, so no second copy of the
 * content is kept. At rest the base is sealed beside the row (localSeal.ts).
 */
export interface SyncBase {
  v: 1;
  /** Nonce of the server generation the fingerprints describe. */
  n: string;
  f: Record<FieldName, string>;
  /** One fingerprint per tag, for the set merge. */
  t: string[];
}

/**
 * A 53-bit string hash in base 36 (the cyrb53 construction, public
 * domain), seeded per kind of value. It is only ever compared with the
 * same row's own fingerprints, so a collision can hide one change to one
 * field, at odds near 2^-53 per comparison. Not a security primitive, and
 * it needs none.
 */
function hash53(seed: number, s: string): string {
  let h1 = 0xdeadbeef ^ seed;
  let h2 = 0x41c6ce57 ^ seed;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 2654435761);
    h2 = Math.imul(h2 ^ c, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507);
  h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507);
  h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(36);
}

/** Stable JSON: keys sorted and undefined members dropped, so key order
 *  never reads as a change. The same reading as trackersEqual. */
function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(',')}}`;
}

/** Strings hash as they are, with no copy of a long body; anything else
 *  hashes as stable JSON under another seed, so the two never meet. */
function fingerprint(value: unknown): string {
  return typeof value === 'string' ? hash53(1, value) : hash53(2, canonical(value));
}

/** A missing tracker payload and an empty one are the same payload. */
function comparable(fields: NoteFields, name: FieldName): unknown {
  return name === 'trackers' ? (fields.trackers ?? {}) : fields[name];
}

export function buildSyncBase(fields: NoteFields, nonce: string): SyncBase {
  const f = {} as Record<FieldName, string>;
  for (const name of NOTE_FIELDS) f[name] = fingerprint(comparable(fields, name));
  return { v: 1, n: nonce, f, t: fields.tags.map(fingerprint) };
}

/**
 * The stored base, when the row may merge against it: well formed, and
 * describing the generation the row records as synced. A base left behind
 * by a writer that moved `syncedNonce` without it (an older bundle's push,
 * a restore) reads as no base, never as a wrong one.
 */
export function trustedBase(raw: unknown, syncedNonce: string | undefined): SyncBase | undefined {
  if (syncedNonce == null || raw === null || typeof raw !== 'object') return undefined;
  const b = raw as Partial<SyncBase>;
  if (b.v !== 1 || b.n !== syncedNonce || !b.f || typeof b.f !== 'object') return undefined;
  if (!Array.isArray(b.t) || !b.t.every((x) => typeof x === 'string')) return undefined;
  const f = b.f as Record<string, unknown>;
  if (!NOTE_FIELDS.every((name) => typeof f[name] === 'string')) return undefined;
  return b as SyncBase;
}

/** A local row's payload, exactly as the push encrypts it. */
export function fieldsOfLocal(
  n: Pick<LocalNote, 'title' | 'body' | 'tags' | 'trashed' | 'starred' | 'locked' | 'pinProtected' | 'type' | 'folderId' | 'trackers'>,
): NoteFields {
  return {
    title: n.title,
    body: n.body,
    tags: n.tags,
    trashed: n.trashed === 1,
    starred: n.starred === 1,
    locked: n.locked === 1,
    pinProtected: n.pinProtected === 1,
    type: n.type ?? 'note',
    folderId: n.folderId ?? null,
    trackers: n.trackers,
  };
}

/** A decrypted server payload, with the defaults older ciphertexts need. */
export function fieldsOfPayload(p: EncryptedPayload): NoteFields {
  return {
    title: p.title,
    body: p.body,
    tags: p.tags,
    trashed: p.trashed,
    starred: p.starred,
    locked: p.locked ?? false,
    pinProtected: p.pinProtected ?? false,
    type: p.type ?? 'note',
    folderId: p.folderId ?? null,
    trackers: p.trackers,
  };
}

/** The server side of a queued conflict (sync.ts NoteConflict). */
export function serverFieldsOf(c: {
  serverTitle: string;
  serverBody: string;
  serverTags: string[];
  serverTrackers?: Record<string, unknown>;
  serverStarred: boolean;
  serverTrashed: boolean;
  serverLocked: boolean;
  serverPinProtected: boolean;
  serverType: NoteType;
  serverFolderId: string | null;
}): NoteFields {
  return {
    title: c.serverTitle,
    body: c.serverBody,
    tags: c.serverTags,
    trashed: c.serverTrashed,
    starred: c.serverStarred,
    locked: c.serverLocked,
    pinProtected: c.serverPinProtected,
    type: c.serverType,
    folderId: c.serverFolderId,
    trackers: c.serverTrackers,
  };
}

/** The fields as a local row stores them. */
export function localPatchOf(f: NoteFields): Pick<
  LocalNote,
  'title' | 'body' | 'tags' | 'trashed' | 'starred' | 'locked' | 'pinProtected' | 'type' | 'folderId' | 'trackers'
> {
  return {
    title: f.title,
    body: f.body,
    tags: f.tags,
    trashed: f.trashed ? 1 : 0,
    starred: f.starred ? 1 : 0,
    locked: f.locked ? 1 : 0,
    pinProtected: f.pinProtected ? 1 : 0,
    type: f.type,
    folderId: f.folderId,
    trackers: f.trackers,
  };
}

function sameList(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

export function fieldsEqual(a: NoteFields, b: NoteFields): boolean {
  return (
    a.title === b.title &&
    a.body === b.body &&
    sameList(a.tags, b.tags) &&
    a.trashed === b.trashed &&
    a.starred === b.starred &&
    a.locked === b.locked &&
    a.pinProtected === b.pinProtected &&
    a.type === b.type &&
    a.folderId === b.folderId &&
    trackersEqual(a.trackers, b.trackers)
  );
}

/** The later of two stamps, read as instants: a server stamp and a local
 *  one can be written in different formats for the same moment. */
export function laterStamp(a: string, b: string): string {
  const ta = Date.parse(a);
  const tb = Date.parse(b);
  if (!Number.isFinite(tb)) return a;
  if (!Number.isFinite(ta)) return b;
  return ta >= tb ? a : b;
}

/** One side of a merge: its payload and the stamp its row carries. */
export interface MergeSide {
  fields: NoteFields;
  updatedAt: string;
}

/**
 * Merge the local and the server version of a note, field by field.
 *
 * With a base: a field unchanged on both sides keeps its value; changed on
 * one side only, it takes that side; changed on both to the same value, it
 * takes that value. Changed on both to different values: the body is the
 * dialog's question (`body` null), tags merge as a set against the base,
 * trackers go through mergeTrackers, and every other field takes the side
 * whose row carries the later stamp. Without a base, a field equal on both
 * sides is kept and one that differs is decided as if both had changed it,
 * except tags, which cannot set-merge without a base and take the later
 * stamp. Trackers still go through mergeTrackers, the rule written for
 * exactly the case where no base says which side moved. An equal stamp
 * favours the server, which every other device already holds.
 */
export function mergeNoteFields(
  base: SyncBase | undefined,
  local: MergeSide,
  server: MergeSide,
): { rest: NoteRest; body: string | null } {
  const localLater = Date.parse(local.updatedAt) > Date.parse(server.updatedAt);
  const changed = (name: FieldName, fields: NoteFields) =>
    fingerprint(comparable(fields, name)) !== base!.f[name];

  function pick<K extends FieldName>(
    name: K,
    same: (a: NoteFields[K], b: NoteFields[K]) => boolean,
  ): { value: NoteFields[K]; bothChanged: boolean } {
    const lv = local.fields[name];
    const sv = server.fields[name];
    if (same(lv, sv)) return { value: sv, bothChanged: false };
    if (base) {
      const lc = changed(name, local.fields);
      const sc = changed(name, server.fields);
      if (lc && !sc) return { value: lv, bothChanged: false };
      if (sc && !lc) return { value: sv, bothChanged: false };
    }
    return { value: localLater ? lv : sv, bothChanged: true };
  }

  const eq = <T>(a: T, b: T) => a === b;
  const body = pick('body', eq);
  const tags = pick('tags', sameList);
  const trackers = pick('trackers', trackersEqual);
  return {
    rest: {
      title: pick('title', eq).value,
      tags: tags.bothChanged && base ? mergeTagSets(base, local.fields.tags, server.fields.tags) : tags.value,
      trashed: pick('trashed', eq).value,
      starred: pick('starred', eq).value,
      locked: pick('locked', eq).value,
      pinProtected: pick('pinProtected', eq).value,
      type: pick('type', eq).value,
      folderId: pick('folderId', eq).value,
      trackers: trackers.bothChanged
        ? mergeTrackers(local.fields.trackers, server.fields.trackers)
        : trackers.value,
    },
    body: body.bothChanged ? null : body.value,
  };
}

/** The base plus what either side added, minus what either side removed,
 *  in the server's order with this device's additions after it. */
function mergeTagSets(base: SyncBase, local: string[], server: string[]): string[] {
  const inBase = new Set(base.t);
  const localSet = new Set(local);
  const serverSet = new Set(server);
  const out = new Set<string>();
  for (const t of server) if (localSet.has(t) || !inBase.has(fingerprint(t))) out.add(t);
  for (const t of local) if (!serverSet.has(t) && !inBase.has(fingerprint(t))) out.add(t);
  return [...out];
}

/**
 * What one answer to the conflict dialog writes: the chosen body over every
 * other field merged exactly as the push merges them. "local" takes this
 * device's body; "server" and "both" put the other device's body on the
 * original note (for "both", forking this device's body into a copy is the
 * caller's job). `sameAsServer` means the result is the server's version as
 * it stands, so the row can be recorded clean at that generation rather than
 * pushed as a new one.
 */
export function resolveConflictFields(
  base: SyncBase | undefined,
  local: MergeSide,
  server: MergeSide,
  choice: 'local' | 'server' | 'both',
): { fields: NoteFields; sameAsServer: boolean } {
  const { rest } = mergeNoteFields(base, local, server);
  const fields: NoteFields = { ...rest, body: choice === 'local' ? local.fields.body : server.fields.body };
  return { fields, sameAsServer: fieldsEqual(fields, server.fields) };
}
