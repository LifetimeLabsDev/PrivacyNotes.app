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
import { sameContent } from './editStamp';

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
  archived: boolean;
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
  'archived',
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
  /** The day a journal entry is for, `journalDate` and `backfilled` as one
   *  pair, so a tracker merge can tell which side moved the entry. Absent on
   *  a base written before the field: the merge then takes the later stamp. */
  d?: string;
  /** The tracker values without that pair, so a side that only moved the day
   *  gives the day and nothing else. Absent on an older base: per key. */
  r?: string;
  /** One fingerprint per tracker key, the day pair aside, so a merge where
   *  both sides changed the trackers still takes each key from the side that
   *  changed it. Absent on an older base: a key both sides hold goes to the
   *  local side, as mergeTrackers decides. */
  k?: Record<string, string>;
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

/** The pair that says which day a journal entry is for. */
function dayPair(trackers: Record<string, unknown> | undefined): string {
  return fingerprint([trackers?.journalDate ?? null, trackers?.backfilled ?? null]);
}

/** Every tracker value but that pair. */
function dayless(trackers: Record<string, unknown> | undefined): string {
  const { journalDate: _day, backfilled: _back, ...rest } = trackers ?? {};
  return fingerprint(rest);
}

export function buildSyncBase(fields: NoteFields, nonce: string): SyncBase {
  const f = {} as Record<FieldName, string>;
  for (const name of NOTE_FIELDS) f[name] = fingerprint(comparable(fields, name));
  return {
    v: 1,
    n: nonce,
    f,
    t: fields.tags.map(fingerprint),
    d: dayPair(fields.trackers),
    r: dayless(fields.trackers),
    k: perKey(fields.trackers),
  };
}

/** A fingerprint of each tracker value, the day pair aside. */
function perKey(trackers: Record<string, unknown> | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(trackers ?? {})) {
    if (key === 'journalDate' || key === 'backfilled' || value === undefined) continue;
    out[key] = fingerprint(value);
  }
  return out;
}

/**
 * A field's fingerprint in the base. `archived` came after the first bases
 * were written, and no row was archived then, so a base without it means
 * "not archived" rather than "no base": every stored base stays usable.
 */
function baseFingerprint(base: SyncBase, name: FieldName): string {
  return base.f[name] ?? (name === 'archived' ? fingerprint(false) : '');
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
  if (b.d !== undefined && typeof b.d !== 'string') return undefined;
  if (b.r !== undefined && typeof b.r !== 'string') return undefined;
  if (b.k !== undefined && (b.k === null || typeof b.k !== 'object' || Array.isArray(b.k) || !Object.values(b.k).every((x) => typeof x === 'string'))) {
    return undefined;
  }
  const f = b.f as Record<string, unknown>;
  if (!NOTE_FIELDS.every((name) => typeof f[name] === 'string' || (name === 'archived' && f[name] === undefined))) {
    return undefined;
  }
  return b as SyncBase;
}

/** A local row's payload, exactly as the push encrypts it. */
export function fieldsOfLocal(
  n: Pick<LocalNote, 'title' | 'body' | 'tags' | 'trashed' | 'starred' | 'locked' | 'pinProtected' | 'type' | 'folderId' | 'trackers' | 'archived'>,
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
    archived: n.archived === 1,
  };
}

/**
 * A decrypted server payload, with the defaults older ciphertexts need.
 *
 * A payload without `archived` came from a client that predates Archive and
 * rebuilt the note without the field, or from a current device that took the
 * row from one and never learned the flag (sync.ts archiveUnknownOf); every
 * writer that knows the flag states it. That
 * writer said nothing about Archive, so the reader keeps what it already
 * knows (`archivedIfAbsent`: the local row's flag) instead of reading an
 * unarchive into the omission.
 */
export function fieldsOfPayload(p: EncryptedPayload, archivedIfAbsent = false): NoteFields {
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
    archived: p.archived ?? archivedIfAbsent,
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
  serverArchived: boolean;
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
    archived: c.serverArchived,
  };
}

/** The fields as a local row stores them. */
export function localPatchOf(f: NoteFields): Pick<
  LocalNote,
  'title' | 'body' | 'tags' | 'trashed' | 'starred' | 'locked' | 'pinProtected' | 'type' | 'folderId' | 'trackers' | 'archived'
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
    archived: f.archived ? 1 : 0,
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
    a.archived === b.archived &&
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

/** One side of a merge: its payload and the stamps its row carries. */
export interface MergeSide {
  fields: NoteFields;
  updatedAt: string;
  /** The side's "last edited" stamp, when its row or payload carries one. */
  editedAt?: string;
}

/**
 * The "last edited" stamp of a merged note, by the content rule of
 * editStamp.ts. A side's stamp is explicit when its row or payload carries
 * `editedAt`, and inferred (its `updatedAt`) when not. An inferred stamp can
 * be a metadata write, so an explicit one wins.
 * Content equal to both sides keeps the later explicit stamp, or this
 * device's own when neither side has one; content equal to one side takes
 * that side's stamp; content that mixes both takes the later of the two.
 */
export function mergedEditedAt(local: MergeSide, server: MergeSide, merged: NoteFields): string {
  const own = (side: MergeSide) => side.editedAt ?? side.updatedAt;
  const fromLocal = sameContent(merged, local.fields);
  const fromServer = sameContent(merged, server.fields);
  if (fromLocal && fromServer) {
    if (local.editedAt && server.editedAt) return laterStamp(local.editedAt, server.editedAt);
    return server.editedAt ?? own(local);
  }
  if (fromLocal) return own(local);
  if (fromServer) return own(server);
  return laterStamp(own(local), own(server));
}

/**
 * Whether a merged "last edited" stamp differs from the one the server's
 * payload carries, so equal fields still need a write for every device to
 * show one date. A payload without the stamp is left as it is: its readers
 * infer one from the row.
 */
export function editStampMoves(editedAt: string, serverEditedAt: string | undefined): boolean {
  if (serverEditedAt === undefined) return false;
  const a = Date.parse(editedAt);
  const b = Date.parse(serverEditedAt);
  // The same instant written two ways is the same date.
  return Number.isNaN(a) || Number.isNaN(b) ? editedAt !== serverEditedAt : a !== b;
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
 *
 * The day a journal entry is for (`journalDate` with `backfilled`) is no
 * tracker value to keep per key: when both sides changed the trackers, the
 * side that moved the day against the base gives it, and when both moved it,
 * or the base predates its fingerprint, the later stamp does. Otherwise a mood
 * logged on the old day would undo the move made on another device. The other
 * values come whole from the one side that changed them, so a side that only
 * moved the day cannot put its older values back; when both changed them, or
 * the base predates that fingerprint, they merge per key (mergeTrackers).
 */
export function mergeNoteFields(
  base: SyncBase | undefined,
  local: MergeSide,
  server: MergeSide,
): { rest: NoteRest; body: string | null } {
  const localLater = Date.parse(local.updatedAt) > Date.parse(server.updatedAt);
  const changed = (name: FieldName, fields: NoteFields) =>
    fingerprint(comparable(fields, name)) !== baseFingerprint(base!, name);

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

  /** The tracker values from the side that changed them, per key when both did. */
  function mergeValues(): Record<string, unknown> | undefined {
    const lt = local.fields.trackers;
    const st = server.fields.trackers;
    if (base?.r !== undefined) {
      const lc = dayless(lt) !== base.r;
      const sc = dayless(st) !== base.r;
      if (lc && !sc) return lt && { ...lt };
      if (sc && !lc) return st && { ...st };
    }
    const merged = mergeTrackers(lt, st);
    if (!base?.k || !merged) return merged;
    // Both sides changed something. A key only one of them changed is that
    // side's, a removal included; a key both changed keeps mergeTrackers'
    // answer. A side with no trackers at all is taken whole by mergeTrackers
    // and gives no key here.
    const keys = new Set([...Object.keys(lt ?? {}), ...Object.keys(st ?? {})]);
    for (const key of keys) {
      if (key === 'journalDate' || key === 'backfilled') continue;
      const lf = lt?.[key] === undefined ? undefined : fingerprint(lt[key]);
      const sf = st?.[key] === undefined ? undefined : fingerprint(st[key]);
      if (lf === sf) continue;
      const was = Object.hasOwn(base.k, key) ? base.k[key] : undefined;
      const from = lf !== was && sf === was ? lt : sf !== was && lf === was ? st : null;
      if (!from) continue;
      if (from[key] === undefined) delete merged[key];
      else merged[key] = from[key];
    }
    return merged;
  }

  /** The day of the side that moved it, over the merged values. A side with
   *  no day says nothing about it, so the day the app stamps at birth
   *  survives a write that dropped it, every value included. */
  function mergeDay(merged: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
    const lt = local.fields.trackers;
    const st = server.fields.trackers;
    if (dayPair(lt) === dayPair(st)) return merged;
    const lHas = lt?.journalDate !== undefined;
    const sHas = st?.journalDate !== undefined;
    const lc = base?.d === undefined || dayPair(lt) !== base.d;
    const sc = base?.d === undefined || dayPair(st) !== base.d;
    const from = lHas !== sHas ? (lHas ? lt : st) : lc && !sc ? lt : sc && !lc ? st : localLater ? lt : st;
    const out: Record<string, unknown> = { ...merged };
    for (const key of ['journalDate', 'backfilled'] as const) {
      if (from?.[key] === undefined) delete out[key];
      else out[key] = from[key];
    }
    return merged === undefined && Object.keys(out).length === 0 ? undefined : out;
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
      archived: pick('archived', eq).value,
      trackers: trackers.bothChanged ? mergeDay(mergeValues()) : trackers.value,
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
