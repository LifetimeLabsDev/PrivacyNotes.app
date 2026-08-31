/**
 * The at-rest sweep: every session verifies that stored rows are
 * sealed, and converts the ones that are not. A RESCAN, deliberately
 * not a one-shot with a completion flag: a rollback window or a stale
 * tab can write plaintext at any time, and a flag would hide those
 * rows forever, while a cheap scan self-heals them next session.
 *
 * What one pass does, in order:
 *  1. notes - keyset pages over the RAW connection (sv checks cost IO
 *     only), converting unsealed rows in per-page transactions with an
 *     in-transaction re-read (the sync pull's race guard). A conversion
 *     preserves every plain field: updatedAt and syncedNonce stay
 *     byte-identical (no sync storm, #156 intact); dirty 1 becomes 2
 *     via the seal itself (the stale-bundle fence).
 *  2. editorDocCache - unsealed rows are DELETED, not converted: the
 *     cache is derived, rebuildable, and capped at 12 rows.
 *  3. imageCache and attachmentCache - unsealed rows seal one row per
 *     transaction (a single blob can be tens of MB).
 *
 * Failure policy: ANY page failure ends the pass - one raw-connection
 * reopen absorbs the iOS severed-IndexedDB case, then stop with a
 * breadcrumb. The next session's pass is the retry; no hot loops. A
 * zeroed key (sign-out) aborts between pages. Demo never sweeps. A Web
 * Lock lets one tab do the work; without lock support the pass runs
 * anyway - conversions are idempotent and transactional.
 *
 * Module-scoped on purpose: a re-lock unmounts the UI but keys stay in
 * memory by the existing app-lock design, and the sweep keeps going.
 *
 * Spec: ops/docs/plans/local-at-rest.md (section 5.3)
 */
import { db, openRawDb } from './db';
import type { LocalNote } from './db';
import { isSealedRow, sealRow } from './localSeal';
import { localDataKeyCopy } from './localKey';
import { isDemoMode } from './demo';
import { logAuthEvent } from './authDiag';

const PAGE_ROWS = 200;
const PAGE_BYTES = 2_000_000;

let running = false;
let rawDb: ReturnType<typeof openRawDb> | null = null;

function raw(): ReturnType<typeof openRawDb> {
  rawDb ??= openRawDb();
  return rawDb;
}

function keyGone(): boolean {
  const copy = localDataKeyCopy();
  if (!copy) return true;
  copy.fill(0);
  return false;
}

async function sweepNotes(): Promise<void> {
  let last: string | null = null;
  for (;;) {
    if (keyGone()) throw new Error('key cleared mid-sweep');
    const page = (await (last === null
      ? raw().notes.orderBy(':id').limit(PAGE_ROWS).toArray()
      : raw().notes.where(':id').above(last).limit(PAGE_ROWS).toArray())) as LocalNote[];
    if (page.length === 0) return;
    last = page[page.length - 1]!.id;
    // Byte-capped chunks: 200 unbounded rows could be 100+ MB of
    // synchronous crypto inside one transaction.
    let chunk: string[] = [];
    let bytes = 0;
    const chunks: string[][] = [];
    for (const row of page) {
      if (isSealedRow(row)) continue;
      chunk.push(row.id);
      bytes += (row.body?.length ?? 0) + (row.title?.length ?? 0);
      if (chunk.length >= PAGE_ROWS || bytes >= PAGE_BYTES) {
        chunks.push(chunk);
        chunk = [];
        bytes = 0;
      }
    }
    if (chunk.length) chunks.push(chunk);
    for (const ids of chunks) {
      await raw().transaction('rw', raw().notes, async () => {
        // Re-read inside the transaction: an autosave or a pull can
        // land between the page read and this write; the fresh row
        // wins and an already-sealed row is skipped.
        const fresh = await raw().notes.bulkGet(ids);
        const updates: LocalNote[] = [];
        for (const row of fresh) {
          if (!row || isSealedRow(row)) continue;
          updates.push(sealRow('notes', row as never) as unknown as LocalNote);
        }
        if (updates.length) await raw().notes.bulkPut(updates);
      });
    }
  }
}

async function sweepDocCache(): Promise<void> {
  // Derived data, max 12 rows: deleting the unsealed backlog is free
  // and a converted stale row would be worthless.
  await raw().editorDocCache.filter((r) => !isSealedRow(r)).delete();
}

async function sweepBlobTable(table: 'imageCache' | 'attachmentCache'): Promise<void> {
  const ids = (await raw()[table].toCollection().primaryKeys()) as string[];
  for (const id of ids) {
    if (keyGone()) throw new Error('key cleared mid-sweep');
    await raw().transaction('rw', raw()[table], async () => {
      const row = await raw()[table].get(id);
      if (!row || isSealedRow(row)) return;
      await raw()[table].put(sealRow(table, row as never) as never);
    });
  }
}

async function sweepOnce(): Promise<void> {
  await sweepNotes();
  await sweepDocCache();
  await sweepBlobTable('imageCache');
  await sweepBlobTable('attachmentCache');
  // Telemetry only - nothing keys off this. The rescan next session is
  // what makes reappearing plaintext self-healing.
  await db.kv.put({ key: 'atRestSweepCleanAt', value: new Date().toISOString() });
}

/**
 * Run one sweep pass. Idempotent and re-entrant-safe; the UI calls it
 * on an idle delay after mount and never needs to await it.
 */
export async function runAtRestSweep(): Promise<void> {
  if (running || isDemoMode() || keyGone()) return;
  running = true;
  try {
    const doPass = async () => {
      try {
        await sweepOnce();
      } catch (err) {
        // One reopen absorbs a severed IndexedDB connection (the iOS
        // background-kill class); any second failure ends the pass.
        try {
          rawDb?.close();
        } catch {
          /* already closed */
        }
        rawDb = null;
        try {
          await sweepOnce();
        } catch (err2) {
          logAuthEvent('seal:sweep-stopped', {
            message: (err2 as Error | null)?.message ?? String(err),
          });
        }
      }
    };
    if (typeof navigator !== 'undefined' && 'locks' in navigator) {
      await navigator.locks.request('pn-at-rest-sweep', { ifAvailable: true }, async (lock) => {
        if (!lock) return;
        await doPass();
      });
    } else {
      await doPass();
    }
  } finally {
    running = false;
  }
}
