import { type SupabaseClient } from '@notes/shared';
import { db } from './db';
import { isDemoMode } from './demo';

/**
 * Point-in-time check that this device actually holds what the server
 * holds.
 *
 * Every real sync bug found on 2026-08-03/04 was found by hand-running
 * this comparison in a console: a client can sit silently stale for
 * weeks while its own status indicator reports "Synced", because
 * nothing in the app ever compares the two sides. This makes that check
 * a thing the app can do to itself, and a thing a user can be asked to
 * run when they report missing notes.
 *
 * Privacy: reads `id`, `updated_at` and `deleted_at` only. No
 * ciphertext leaves the server, nothing is decrypted, and the report
 * contains counts and ids - never note content.
 */

/** Rows are compared in pages; PostgREST caps a single response. */
const PAGE = 1000;

/** The all-zero UUID sorts before any real id, so it seeds the sweep. */
const ID_FLOOR = '00000000-0000-0000-0000-000000000000';

type SyncVerdict =
  /** Local matches the server exactly. */
  | 'in_sync'
  /** Local is behind or ahead; `divergent` counts say how. */
  | 'diverged'
  /**
   * Another device was writing while we measured, so any difference we
   * saw may simply be data in flight. Not a verdict - a retry.
   */
  | 'busy'
  /** The check could not complete (offline, auth, RLS). */
  | 'failed';

export type SyncReport = {
  verdict: SyncVerdict;
  /** Live rows on the server. */
  serverLive: number;
  /** Rows in the local database. */
  localTotal: number;
  /** Live on the server, absent locally. The "missing notes" case. */
  missingLocally: string[];
  /** Present locally but older than the server's copy. Silent staleness. */
  staleLocally: string[];
  /** Local rows the server has never seen. Unpushed work. */
  neverPushed: string[];
  /** Tombstoned server-side but still held locally. Pending delete. */
  pendingTombstones: string[];
  /** Local rows still flagged dirty, i.e. queued to push. */
  dirty: number;
  /** Raw cursor, for support threads. */
  cursor: string;
  /** Present when verdict is 'failed'. */
  error?: string;
};

/** Newest change-time on the server, used to detect concurrent writers. */
async function serverWatermark(
  supabase: SupabaseClient,
): Promise<string | null> {
  const { data, error } = await supabase
    .from('notes')
    .select('changed_at')
    .order('changed_at', { ascending: false })
    .limit(1);
  if (error) throw error;
  return (data?.[0] as { changed_at?: string } | undefined)?.changed_at ?? null;
}

/**
 * Page through every row the server holds for this account.
 *
 * Keyset on `id` rather than `range()` offsets, for the same reason the
 * pull does: an offset walk over a table someone else is writing skips
 * rows. A verification tool that under-reports is worse than none, and
 * this function got that wrong once before it was fixed.
 */
async function fetchServerRows(supabase: SupabaseClient) {
  const rows: Array<{ id: string; updated_at: string; deleted_at: string | null }> = [];
  let after = ID_FLOOR;
  // Bounded so a pathological account cannot spin here forever.
  for (let page = 0; page < 200; page++) {
    const { data, error } = await supabase
      .from('notes')
      .select('id,updated_at,deleted_at')
      .gt('id', after)
      .order('id', { ascending: true })
      .limit(PAGE);
    if (error) throw error;
    const batch = (data ?? []) as typeof rows;
    if (batch.length === 0) break;
    rows.push(...batch);
    const last = batch[batch.length - 1];
    if (!last) break;
    after = last.id;
    if (batch.length < PAGE) break;
  }
  return rows;
}

/**
 * Compare local against the server and report the difference.
 *
 * Takes a watermark before and after the read. If the server moved
 * underneath us, the comparison is not evidence of anything - it is a
 * snapshot of two moments - so it returns `busy` instead of a
 * divergence the user would reasonably panic about. Both of the false
 * alarms during this feature's own development were exactly that.
 */
export async function verifySync(supabase: SupabaseClient): Promise<SyncReport> {
  const cursor = localStorage.getItem('privacynotes.lastSync') ?? '(never synced)';
  const empty: SyncReport = {
    verdict: 'in_sync',
    serverLive: 0,
    localTotal: 0,
    missingLocally: [],
    staleLocally: [],
    neverPushed: [],
    pendingTombstones: [],
    dirty: 0,
    cursor,
  };

  if (isDemoMode()) return empty;

  try {
    const before = await serverWatermark(supabase);
    const server = await fetchServerRows(supabase);
    const local = await db.notes.toArray();
    const after = await serverWatermark(supabase);

    const localById = new Map(local.map((n) => [n.id, n]));
    const serverIds = new Set(server.map((r) => r.id));
    const tombstoned = new Set(
      server.filter((r) => r.deleted_at).map((r) => r.id),
    );
    const live = server.filter((r) => !r.deleted_at);

    const missingLocally: string[] = [];
    const staleLocally: string[] = [];
    for (const row of live) {
      const mine = localById.get(row.id);
      if (!mine) {
        missingLocally.push(row.id);
        continue;
      }
      // Compare as instants: the server serialises `+00:00` where the
      // client writes `Z`, so a string compare reports nonsense.
      if (Date.parse(mine.updatedAt) < Date.parse(row.updated_at)) {
        staleLocally.push(row.id);
      }
    }

    const neverPushed: string[] = [];
    const pendingTombstones: string[] = [];
    for (const mine of local) {
      if (tombstoned.has(mine.id)) pendingTombstones.push(mine.id);
      else if (!serverIds.has(mine.id)) neverPushed.push(mine.id);
    }

    const report: SyncReport = {
      verdict: 'in_sync',
      serverLive: live.length,
      localTotal: local.length,
      missingLocally,
      staleLocally,
      neverPushed,
      pendingTombstones,
      // Unsynced in either at-rest writer mode: 1 plaintext, 2 sealed.
      dirty: local.filter((n) => n.dirty === 1 || n.dirty === 2).length,
      cursor,
    };

    const diverged =
      missingLocally.length > 0 ||
      staleLocally.length > 0 ||
      pendingTombstones.length > 0 ||
      // Unpushed work is only a problem when it is not queued: a dirty
      // row is on its way, an undirty row the server has never seen is
      // a push that silently failed.
      neverPushed.some((id) => {
        const d = localById.get(id)?.dirty;
        return d !== 1 && d !== 2;
      });

    if (before !== after) report.verdict = 'busy';
    else if (diverged) report.verdict = 'diverged';
    return report;
  } catch (err) {
    return {
      ...empty,
      verdict: 'failed',
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Force the next sync to re-read everything from the beginning.
 *
 * The only repair for rows stranded behind the cursor: no filter can
 * match them, because the cursor is already past them. Safe to run at
 * any time - `processBatch` keeps local dirty rows and anything already
 * newer, so a full re-read cannot clobber pending work. Costs one full
 * pull.
 */
export function resetSyncCursor(): void {
  try {
    localStorage.removeItem('privacynotes.lastSync');
    sessionStorage.removeItem('privacynotes.lastSync');
  } catch {
    /* storage unavailable - the next sync just keeps its cursor */
  }
}
