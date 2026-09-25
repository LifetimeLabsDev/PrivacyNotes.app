/**
 * Local at-rest seal - the Dexie DBCore middleware that encrypts note
 * content in the device's own IndexedDB.
 *
 * Formats, on the raw stored row:
 *  - JSON tables (notes, editorDocCache):
 *      sv: 1, sealed: { n: <base64 nonce>, ct: <base64 ciphertext> }
 *    The content fields live inside the ciphertext as one JSON payload.
 *    Base64 STRINGS on purpose: Dexie's liveQuery cache does not
 *    preserve Uint8Array fields.
 *  - The notes side field (the sync base):
 *      syncBaseSealed: { n: <base64 nonce>, ct: <base64 ciphertext> }
 *    Its own envelope beside the blob, under its own AAD, and left
 *    sealed on reads (readSideField). A bundle without the field keeps
 *    the envelope on every write and still opens the row.
 *  - Bytes tables (imageCache, attachmentCache):
 *      sv: 1, sealed: { n: Uint8Array, ct: Uint8Array }
 *    The data bytes seal RAW - a JSON detour would multiply a 50 MB
 *    blob several-fold. The attachment meta seals beside the bytes as
 *    its own small JSON envelope (metaSealed). No liveQuery touches
 *    these tables.
 * Everything else stays plain: indexes and sync bookkeeping read it.
 * The AAD binds a per-table tag and the row id, so a ciphertext moved
 * onto another row or table fails authentication instead of decrypting.
 *
 * Rules proven by the build spike (tests/localSeal.test.ts pins them):
 *  - The sealed blob decides sealing, never the `sv` marker: the
 *    update/modify path hands mutate the full merged plaintext row
 *    carrying a stale `sv` and no blob.
 *  - A value can arrive as the raw sealed row with plaintext patch
 *    fields beside the blob; the seal step unseals, overlays, re-seals.
 *  - `criteria`/`changeSpec` are STRIPPED after sealing - a lower layer
 *    re-applies them as plaintext otherwise.
 *  - Rows are sealed into copies and unsealed into fresh objects; the
 *    caller's objects and Dexie's frozen cache rows are never mutated.
 *
 * The dirty fence: sealing a notes row maps `dirty: 1` to `dirty: 2`.
 * Every bundle without the seal reader pushes `where('dirty').equals(1)`
 * and therefore cannot see a sealed unsynced row - the mechanism that
 * keeps a stale tab from pushing gutted payloads. Current code reads
 * both values and clears to 0 on push success.
 *
 * The unseal memo: JSON-table reads are memoized per (table, id) and
 * validated by nonce AND ciphertext equality (a tampered ct under a
 * kept nonce must fail like any tamper, never be papered over by a
 * cache), so the recurring full-list reads (tab focus, post-sync
 * refresh) pay crypto only for rows that actually changed. The memo
 * holds plaintext in memory at the same trust level as the React notes
 * state beside it, and dies with the key.
 *
 * Failure policy: sealing has NO plaintext fallback (a write seals or
 * throws). Reading a sealed row with no key registered throws
 * LocalSealKeyMissing - loud, never a silently empty list. A row that
 * fails to open is dropped from list results with a breadcrumb when it
 * is isolated; a failing dirty row, or more than a handful per read,
 * throws instead, because dirty rows exist nowhere else and correlated
 * failure means the key or the format is wrong, not the row.
 *
 * Writes stay plaintext until `setSealedWrites(true)` - the reader
 * release ships with it off, the writer release turns it on at boot
 * (main.tsx). Demo mode bypasses the middleware entirely: the demo
 * phrase is a public constant, and the demo database is throwaway.
 *
 * Spec: ops/docs/plans/local-at-rest.md (sections 3.2 and 3.3)
 */
import type { DBCore, DBCoreTable, Middleware } from 'dexie';
import {
  encryptJsonAad,
  decryptJsonAad,
  encryptBytesAad,
  decryptBytesAad,
  bytesToBase64,
  base64ToBytes,
} from '@notes/shared';
import { localDataKeyCopy, onLocalDataKeyCleared } from './localKey';
import { isDemoMode } from './demo';
import { logAuthEvent } from './authDiag';

const SEAL_VERSION = 1;
const AAD_PREFIX = 'pn-local-v1';

type RawRow = Record<string, unknown> & {
  sv?: number;
  sealed?: { n: unknown; ct: unknown };
  metaSealed?: { n: string; ct: string };
};

interface TableSealConfig {
  /** Primary-key field, the AAD id source. */
  pk: string;
  /** AAD table tag - pinned by the format fixtures, never rename. */
  aad: string;
  mode: 'json' | 'bytes';
  /** json mode: content fields that move into the sealed payload. */
  fields?: readonly string[];
  /** bytes mode: the Uint8Array field sealed raw. */
  bytesField?: string;
  /** bytes mode: an optional JSON side field (attachment meta). */
  jsonField?: string;
  /** notes only: map dirty 1 -> 2 on seal (the stale-bundle fence). */
  fenceDirty?: boolean;
  /** json mode: a field sealed in its own envelope, `<field>Sealed`,
   *  and never unsealed by a read. It stays out of `fields` because a
   *  bundle that predates it refuses a payload carrying a key it does
   *  not know: an envelope it carries through untouched keeps a
   *  rollback or a stale tab able to open every row. */
  sideField?: string;
}

/** The tables the middleware covers, and what it seals in each. */
const SEALED_TABLES: Record<string, TableSealConfig> = {
  notes: {
    pk: 'id',
    aad: 'notes',
    mode: 'json',
    fields: ['title', 'body', 'tags', 'trackers'],
    fenceDirty: true,
    sideField: 'syncBase',
  },
  editorDocCache: { pk: 'noteId', aad: 'editorDocCache', mode: 'json', fields: ['body', 'json'] },
  imageCache: { pk: 'id', aad: 'img', mode: 'bytes', bytesField: 'data' },
  attachmentCache: { pk: 'id', aad: 'att', mode: 'bytes', bytesField: 'data', jsonField: 'meta' },
};

/** Thrown when a sealed row is read and no usable key is registered. */
export class LocalSealKeyMissing extends Error {
  constructor() {
    super('sealed row read with no local data key registered');
    this.name = 'LocalSealKeyMissing';
  }
}

/** Thrown when a sealed row fails to open (wrong key, tamper, moved blob). */
export class LocalSealReadError extends Error {
  constructor(table: string, id: unknown, cause?: unknown) {
    super(`sealed row failed to open: ${table}/${String(id)}`);
    this.name = 'LocalSealReadError';
    this.cause = cause;
  }
}

/**
 * Whether the shipped app writes sealed rows. main.tsx boots with it and
 * the sync simulator's devices start from it, so the suite runs the mode
 * users run. false is the reader release: sealed rows open, writes land
 * plaintext.
 * Spec: ops/docs/plans/local-at-rest.md (5.1, the two releases)
 */
export const SEALED_WRITES_IN_PRODUCTION = true;

let sealedWrites = false;

/** The mode switch main.tsx sets at boot from SEALED_WRITES_IN_PRODUCTION. */
export function setSealedWrites(on: boolean): void {
  sealedWrites = on;
}

/** True in the writer release. The writer-gen listener reads this so a
 *  sealed-writer tab never reloads itself on another writer's announce. */
export function sealedWritesOn(): boolean {
  return sealedWrites;
}

// ------------------------------------------------------------------
// Unseal memo - JSON tables only. Bytes tables would pin whole blobs
// in memory for reads that happen once per open; the recurring cost
// this memo kills is the full-LIST unseal on tab focus and post-sync
// refresh, which is a notes-table pattern.
// ------------------------------------------------------------------
const MEMO_MAX = 1000;
const memo = new Map<string, { n: string; ct: string; payload: Record<string, unknown> }>();

function memoKey(table: string, id: unknown): string {
  return `${table}:${String(id)}`;
}

function memoSet(table: string, id: unknown, n: string, ct: string, payload: Record<string, unknown>): void {
  const key = memoKey(table, id);
  if (memo.has(key)) memo.delete(key);
  memo.set(key, { n, ct, payload });
  if (memo.size > MEMO_MAX) {
    const oldest = memo.keys().next().value;
    if (oldest !== undefined) memo.delete(oldest);
  }
}

/** Plaintext leaves memory with the key - wired below via the key
 *  registry's cleared-callback, so no call site can forget it. */
function clearUnsealMemo(): void {
  memo.clear();
}
onLocalDataKeyCleared(clearUnsealMemo);

function aadFor(cfg: TableSealConfig, id: unknown): string {
  return `${AAD_PREFIX}:${cfg.aad}:${String(id)}`;
}

function requireKey(): Uint8Array {
  const key = localDataKeyCopy();
  if (!key) throw new LocalSealKeyMissing();
  return key;
}

function sideSlot(field: string): string {
  return `${field}Sealed`;
}

/** Its own AAD tag, so neither envelope authenticates in the other's slot. */
function sideAad(cfg: TableSealConfig, id: unknown): string {
  return `${AAD_PREFIX}:${cfg.aad}.${cfg.sideField}:${String(id)}`;
}

/** Move a plain side value into its envelope; a row without one comes
 *  back as it is. An explicit undefined drops the envelope as well. */
function sealSideField(cfg: TableSealConfig, row: RawRow): RawRow {
  const f = cfg.sideField;
  if (!f || !(f in row)) return row;
  const out: RawRow = { ...row };
  const value = out[f];
  delete out[f];
  if (value === undefined) {
    delete out[sideSlot(f)];
    return out;
  }
  const key = requireKey();
  try {
    const { ciphertext, nonce } = encryptJsonAad(value, key, sideAad(cfg, row[cfg.pk]));
    out[sideSlot(f)] = { n: bytesToBase64(nonce), ct: bytesToBase64(ciphertext) };
  } finally {
    key.fill(0);
  }
  return out;
}

// ------------------------------------------------------------------
// JSON mode
// ------------------------------------------------------------------

function sealJsonPayload(
  table: string,
  cfg: TableSealConfig,
  row: RawRow,
  payload: Record<string, unknown>,
): RawRow {
  const key = requireKey();
  const { ciphertext, nonce } = encryptJsonAad(payload, key, aadFor(cfg, row[cfg.pk]));
  key.fill(0);
  const n = bytesToBase64(nonce);
  const ct = bytesToBase64(ciphertext);
  const out: RawRow = { ...row, sv: SEAL_VERSION, sealed: { n, ct } };
  for (const f of cfg.fields!) delete out[f];
  if (cfg.fenceDirty && out.dirty === 1) out.dirty = 2;
  memoSet(table, row[cfg.pk], n, ct, payload);
  return out;
}

function openJsonPayload(table: string, cfg: TableSealConfig, row: RawRow): Record<string, unknown> {
  const n = row.sealed!.n as string;
  const ct = row.sealed!.ct as string;
  // A hit must match nonce AND ciphertext: a tampered ct under a kept
  // nonce must fail like any tamper, never be papered over by a cache.
  const cached = memo.get(memoKey(table, row[cfg.pk]));
  if (cached && cached.n === n && cached.ct === ct) return cached.payload;
  const key = requireKey();
  try {
    const payload = decryptJsonAad<Record<string, unknown>>(
      base64ToBytes(row.sealed!.ct as string),
      base64ToBytes(n),
      key,
      aadFor(cfg, row[cfg.pk]),
    );
    // A payload that decrypts but does not fit this table's shape is a
    // read failure, never a bag of foreign fields spread onto the row.
    if (
      payload === null ||
      typeof payload !== 'object' ||
      Array.isArray(payload) ||
      !Object.keys(payload).every((k) => cfg.fields!.includes(k))
    ) {
      throw new Error('payload shape does not match table');
    }
    memoSet(table, row[cfg.pk], n, ct, payload);
    return payload;
  } catch (err) {
    if (err instanceof LocalSealKeyMissing) throw err;
    throw new LocalSealReadError(table, row[cfg.pk], err);
  } finally {
    key.fill(0);
  }
}

// ------------------------------------------------------------------
// Bytes mode
// ------------------------------------------------------------------

function sealBytesRow(cfg: TableSealConfig, row: RawRow): RawRow {
  const key = requireKey();
  try {
    const out: RawRow = { ...row, sv: SEAL_VERSION };
    const data = row[cfg.bytesField!] as Uint8Array;
    const { ciphertext, nonce } = encryptBytesAad(data, key, aadFor(cfg, row[cfg.pk]));
    out.sealed = { n: nonce, ct: ciphertext };
    delete out[cfg.bytesField!];
    if (cfg.jsonField && cfg.jsonField in row) {
      const meta = encryptJsonAad(row[cfg.jsonField!], key, aadFor(cfg, row[cfg.pk]));
      out.metaSealed = { n: bytesToBase64(meta.nonce), ct: bytesToBase64(meta.ciphertext) };
      delete out[cfg.jsonField!];
    }
    return out;
  } finally {
    key.fill(0);
  }
}

function unsealBytesRow(table: string, cfg: TableSealConfig, row: RawRow): RawRow {
  const key = requireKey();
  try {
    const out: RawRow = { ...row };
    out[cfg.bytesField!] = decryptBytesAad(
      row.sealed!.ct as Uint8Array,
      row.sealed!.n as Uint8Array,
      key,
      aadFor(cfg, row[cfg.pk]),
    );
    delete out.sealed;
    if (cfg.jsonField && row.metaSealed) {
      out[cfg.jsonField!] = decryptJsonAad(
        base64ToBytes(row.metaSealed.ct),
        base64ToBytes(row.metaSealed.n),
        key,
        aadFor(cfg, row[cfg.pk]),
      );
      delete out.metaSealed;
    }
    delete out.sv;
    return out;
  } catch (err) {
    if (err instanceof LocalSealKeyMissing) throw err;
    throw new LocalSealReadError(table, row[cfg.pk], err);
  } finally {
    key.fill(0);
  }
}

// ------------------------------------------------------------------
// Row-level API (the middleware and the sweep share these)
// ------------------------------------------------------------------

/** True when the raw row is in the sealed format. */
export function isSealedRow(row: unknown): boolean {
  const r = row as RawRow | null | undefined;
  return !!r && r.sv === SEAL_VERSION && !!r.sealed;
}

/** Seal one row for storage. Also the sweep's conversion primitive. */
export function sealRow(table: string, row: RawRow): RawRow {
  const cfg = SEALED_TABLES[table];
  if (!cfg) return row;
  if (cfg.mode === 'bytes') {
    if (isSealedRow(row)) return row;
    return sealBytesRow(cfg, row);
  }
  const r = sealSideField(cfg, row);
  const present = cfg.fields!.filter((f) => f in r);
  if (isSealedRow(r)) {
    // A genuinely sealed raw row. Plaintext fields beside the blob mean
    // a lower layer patched the stored value: merge and re-seal.
    if (present.length === 0) return r;
    const payload = openJsonPayload(table, cfg, r);
    const merged = { ...payload };
    for (const f of present) merged[f] = r[f];
    return sealJsonPayload(table, cfg, r, merged);
  }
  // Plaintext row - including modify/update values, which carry a stale
  // sv marker and no blob. The blob decides, never the marker.
  const payload: Record<string, unknown> = {};
  for (const f of cfg.fields!) payload[f] = r[f];
  return sealJsonPayload(table, cfg, r, payload);
}

/**
 * A row's side field in whatever form the row holds it, the plain value or
 * its envelope, for a writer that rebuilds the row from scratch and must
 * keep it (a restore replacing a note it matched by id).
 */
export function carrySideField(table: string, row: object): Record<string, unknown> {
  const f = SEALED_TABLES[table]?.sideField;
  if (!f) return {};
  const r = row as RawRow;
  const out: Record<string, unknown> = {};
  if (r[f] !== undefined) out[f] = r[f];
  if (r[sideSlot(f)] !== undefined) out[sideSlot(f)] = r[sideSlot(f)];
  return out;
}

/**
 * A row's side field, for the one reader that needs it (sync.ts). Plain
 * when the row was written with sealed writes off, which is also the newer
 * value when a row carries both; opened from its envelope otherwise. An
 * envelope that does not open reads as absent: the field is advisory, and
 * a note never becomes unreadable over it.
 */
export function readSideField(table: string, row: object): unknown {
  const cfg = SEALED_TABLES[table];
  const f = cfg?.sideField;
  if (!cfg || !f) return undefined;
  const r = row as RawRow;
  if (r[f] !== undefined) return r[f];
  const env = r[sideSlot(f)] as { n?: unknown; ct?: unknown } | undefined;
  if (!env || typeof env.n !== 'string' || typeof env.ct !== 'string') return undefined;
  const key = localDataKeyCopy();
  if (!key) return undefined;
  try {
    return decryptJsonAad(base64ToBytes(env.ct), base64ToBytes(env.n), key, sideAad(cfg, r[cfg.pk]));
  } catch {
    logAuthEvent('seal:side-open-failed', { message: `${table}/${String(r[cfg.pk])}` });
    return undefined;
  } finally {
    key.fill(0);
  }
}

/** Open one raw row into the plaintext shape. Throws; never partial. */
export function unsealRow(table: string, row: RawRow): RawRow {
  const cfg = SEALED_TABLES[table];
  if (!cfg || !isSealedRow(row)) return row;
  if (cfg.mode === 'bytes') return unsealBytesRow(table, cfg, row);
  const payload = openJsonPayload(table, cfg, row);
  const out: RawRow = { ...row, ...payload };
  delete out.sealed;
  return out;
}

/**
 * List policy: open every row; drop an isolated bad row with a
 * breadcrumb; throw when a DIRTY row fails or failures stop looking
 * isolated. Key-missing always throws.
 *
 * `keyed` picks the shape of the answer. A scan returns whatever
 * opened, so a bad row simply leaves. A keyed read answers position
 * for position against the keys it was handed, so a bad row leaves an
 * `undefined` in its own slot: a caller pairing the result with its
 * key list by index would otherwise read every later row off by one.
 */
function unsealList(
  table: string,
  rows: (RawRow | undefined)[],
  keyed = false,
): (RawRow | undefined)[] {
  const out: (RawRow | undefined)[] = [];
  let failures = 0;
  for (const row of rows) {
    if (!row || !isSealedRow(row)) {
      out.push(row);
      continue;
    }
    try {
      out.push(unsealRow(table, row));
    } catch (err) {
      if (err instanceof LocalSealKeyMissing) throw err;
      if ((row as { dirty?: number }).dirty === 1 || (row as { dirty?: number }).dirty === 2) {
        throw err;
      }
      failures++;
      if (keyed) out.push(undefined);
      logAuthEvent('seal:row-open-failed', {
        message: `${table}/${String(row[SEALED_TABLES[table]!.pk])}`,
      });
    }
  }
  const sealedCount = rows.filter((r) => isSealedRow(r)).length;
  if (failures > 5 || (sealedCount > 0 && failures / sealedCount > 0.1)) {
    throw new LocalSealReadError(table, `${failures} of ${sealedCount} rows`, undefined);
  }
  return out;
}

/**
 * The DBCore middleware. Register on the Dexie instance BEFORE open.
 * Read surfaces always open sealed rows; mutate seals only when
 * sealed writes are on.
 */
export function localSealMiddleware(): Middleware<DBCore> {
  return {
    stack: 'dbcore',
    name: 'localSeal',
    create(down: DBCore): DBCore {
      if (isDemoMode()) return down;
      return {
        ...down,
        table(name: string): DBCoreTable {
          const t = down.table(name);
          const cfg = SEALED_TABLES[name];
          if (!cfg) return t;
          return {
            ...t,
            async get(req) {
              const row = (await t.get(req)) as RawRow | undefined;
              if (!row || !isSealedRow(row)) return row;
              return unsealRow(name, row);
            },
            async getMany(req) {
              const rows = (await t.getMany(req)) as (RawRow | undefined)[];
              return unsealList(name, rows, true);
            },
            async query(req) {
              const res = await t.query(req);
              if (!req.values) return res;
              return { ...res, result: unsealList(name, res.result as RawRow[]) };
            },
            async openCursor(req) {
              const cursor = await t.openCursor(req);
              if (!cursor) return cursor;
              // A Proxy with method binding, NOT Object.create: real
              // browsers brand-check cursor internals, and a method
              // invoked with a prototype-child as `this` throws
              // "Illegal invocation" (caught live in Chrome; the fake
              // IndexedDB in tests never enforces brands). Functions
              // bind to the original cursor; only `value` is rewritten.
              // A failing row throws from the value read: scans are the
              // systemic-read case, and a silently skipped value would
              // corrupt whatever the scan computes.
              return new Proxy(cursor, {
                get: (target, prop, receiver) => {
                  if (prop === 'value') {
                    const row = target.value as RawRow;
                    if (!isSealedRow(row)) return row;
                    return unsealRow(name, row);
                  }
                  const v = Reflect.get(target, prop, target);
                  return typeof v === 'function' ? v.bind(target) : v;
                },
              });
            },
            async mutate(req) {
              if (!sealedWrites) return t.mutate(req);
              if (req.type === 'add' || req.type === 'put') {
                const sealedReq = {
                  ...req,
                  values: (req.values as RawRow[]).map((v) => sealRow(name, v)),
                } as typeof req & { criteria?: unknown; changeSpec?: unknown };
                delete sealedReq.criteria;
                delete sealedReq.changeSpec;
                return t.mutate(sealedReq);
              }
              return t.mutate(req);
            },
          };
        },
      };
    },
  };
}
