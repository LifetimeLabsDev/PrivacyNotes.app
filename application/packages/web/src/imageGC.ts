/**
 * Blob garbage collection - deletes orphaned encrypted image and
 * attachment blobs when they are removed from notes or notes are
 * hard-deleted.
 *
 * Two triggers:
 * 1. On note body save: diff blob UUIDs before vs after. Any UUID
 *    that disappeared gets enqueued for deletion, UNLESS a history
 *    snapshot still references it.
 * 2. On note hard-delete: enqueue all blobs referenced in the note's
 *    body. (Versions cascade-delete via FK, so no orphan risk.)
 *
 * Deletion is two-phase (#125). A local mirror can be stale - a device
 * that has never pulled a note, or still carries an unconfirmed
 * tombstone for one, can wrongly conclude a blob referenced elsewhere
 * is orphaned. Since Storage removal is immediate and permanent (no
 * grace period like note tombstones get), that stale read would mean
 * a real, unrecoverable data loss. So:
 *
 * - Phase 1 (here, at GC time): local cache + dedup rows are removed
 *   and quota is decremented right away (unchanged UX), but the
 *   Supabase Storage object is left alone. The uuid is enqueued in
 *   db.blobGC instead - see ImageStore.deferDelete / AttachmentStore.deferDelete.
 * - Phase 2 (sweepBlobGC, below): runs only right after a sync pass
 *   whose pull completed cleanly, so the local mirror is as complete
 *   as it can be. Queue entries past the grace period get a fresh
 *   reference re-check against every local note row, including
 *   trashed and not-yet-confirmed tombstoned ones (an unconfirmed
 *   tombstone means the server may still be serving that note
 *   elsewhere). Still-referenced entries are cancelled and their quota
 *   re-credited; the rest have their Storage object actually removed.
 *
 * The actual object deletion depends on db.blobGC, which is device-local
 * and unreplicated, so a blob can still end up in Storage with nothing
 * local tracking it: the queue is wiped on sign-out and on any local-data
 * clear, and a few paths never enqueue at all (a note dropped by sync for
 * an invalid uuid, an import whose body rewrite matched nothing, a blob
 * whose last reference was a pruned version snapshot). Batch deletes are
 * not on that list: gcOnNotesDelete excludes the whole batch from the
 * reference check, so a shared blob cannot hide behind a batch-mate. The
 * server-side pending_blob_gc set (migration 0068, re-asserted by every
 * sweep pass) keeps the QUOTA honest through all of it, and the nightly
 * purge-pending-blobs edge function deletes pending objects no surviving
 * device ever swept. reconcileOrphanBlobs (below) is the backstop that
 * reclaims blobs nothing enqueued at all.
 *
 * The caller (NotesView / notesRepo integration) is responsible for
 * invoking these at the right time. This module just provides the
 * diffing + deletion logic.
 */

import { extractImageIds } from './imageProcessing';
import { extractAttachmentIds } from './EncryptedAttachment';
import type { ImageStore } from './imageStore';
import type { AttachmentStore } from './attachmentStore';
import { listNoteVersions } from './noteVersions';
import { decryptNote, base64ToBytes, type SupabaseClient } from '@notes/shared';
import { db } from './db';
import { isDemoMode } from './demo';
import { isServerWriteBlocked } from './syncPause';
import { fetchQuotaUsage, recalculateQuota } from './devices';

// Guards against overlapping sweeps: sweepBlobGC is fired unawaited after
// every successful sync pass, so a slow sweep could still be running when
// the next one starts. Two overlapping sweeps can both read the same
// still-referenced entry before either cancels it, and both re-credit
// quota for it - a double refund.
let sweepInFlight = false;

/** Grace period a deferred blob sits in the queue before it becomes
 * eligible for actual Storage removal. 24h:
 * the pending exclusion keeps the displayed figure honest from the moment
 * of the delete, so the grace only has to cover the cross-device restore
 * race, and one day of clean pulls is enough for any device that is
 * actually alive. Spec: ops/docs/design-decisions.md (deferred blob GC). */
const BLOB_GC_GRACE_MS = 24 * 60 * 60 * 1000;

/**
 * Check which blob UUIDs are still referenced by any note other than
 * the excluded one. Returns the subset of `uuids` that ARE still
 * referenced elsewhere - these must NOT be deleted.
 */
async function findRefsInOtherNotes(
  uuids: string[],
  excludeNoteIds: Set<string>,
): Promise<Set<string>> {
  if (uuids.length === 0) return new Set();

  const referenced = new Set<string>();
  const remaining = new Set(uuids);

  await db.notes
    .where('deleted')
    .equals(0)
    .each((note) => {
      if (excludeNoteIds.has(note.id) || remaining.size === 0) return;
      for (const uuid of remaining) {
        if (note.body.includes(uuid)) {
          referenced.add(uuid);
          remaining.delete(uuid);
        }
      }
    });

  return referenced;
}

/** Context needed to check image refs in note history snapshots. */
export type VersionCtx = {
  supabase: SupabaseClient;
  encryptionKey: Uint8Array;
  noteId: string;
};

/**
 * Compare the old and new body of a note. Delete any image/attachment
 * blobs that were in the old body but not in the new one - unless a
 * history snapshot still references them.
 *
 * Pass `versionCtx` for Pro users so version bodies are checked.
 * If version fetch fails, deletion is skipped entirely (conservative).
 */
export async function gcOnBodyChange(
  imageStore: ImageStore,
  oldBody: string,
  newBody: string,
  noteId: string,
  versionCtx?: VersionCtx,
  attachmentStore?: AttachmentStore | null,
): Promise<void> {
  // --- Images ---
  const oldImgIds = extractImageIds(oldBody);
  const newImgIds = extractImageIds(newBody);
  let imgCandidates: string[] = [];
  for (const id of oldImgIds) {
    if (!newImgIds.has(id)) imgCandidates.push(id);
  }

  // --- Attachments ---
  const oldAttIds = extractAttachmentIds(oldBody);
  const newAttIds = extractAttachmentIds(newBody);
  let attCandidates: string[] = [];
  for (const id of oldAttIds) {
    if (!newAttIds.has(id)) attCandidates.push(id);
  }

  if (imgCandidates.length === 0 && attCandidates.length === 0) return;

  // Don't delete blobs still referenced by other notes (e.g. copy-pasted).
  const refsElsewhere = await findRefsInOtherNotes(
    [...imgCandidates, ...attCandidates],
    new Set([noteId]),
  );
  if (refsElsewhere.size > 0) {
    imgCandidates = imgCandidates.filter((id) => !refsElsewhere.has(id));
    attCandidates = attCandidates.filter((id) => !refsElsewhere.has(id));
    if (imgCandidates.length === 0 && attCandidates.length === 0) return;
  }

  // Check history snapshots for blob references before deleting.
  if (versionCtx) {
    let versionImgIds: Set<string>;
    let versionAttIds: Set<string>;
    try {
      const versions = await listNoteVersions(
        versionCtx.supabase,
        versionCtx.encryptionKey,
        versionCtx.noteId,
      );
      versionImgIds = new Set<string>();
      versionAttIds = new Set<string>();
      for (const v of versions) {
        for (const id of extractImageIds(v.body)) versionImgIds.add(id);
        for (const id of extractAttachmentIds(v.body)) versionAttIds.add(id);
      }
    } catch {
      return;
    }
    const orphanedImgs = imgCandidates.filter((id) => !versionImgIds.has(id));
    if (orphanedImgs.length > 0) await imageStore.deferDelete(orphanedImgs);
    const orphanedAtts = attCandidates.filter((id) => !versionAttIds.has(id));
    if (orphanedAtts.length > 0 && attachmentStore) {
      await attachmentStore.deferDelete(orphanedAtts);
    }
    return;
  }

  if (imgCandidates.length > 0) await imageStore.deferDelete(imgCandidates);
  if (attCandidates.length > 0 && attachmentStore) {
    await attachmentStore.deferDelete(attCandidates);
  }
}

/**
 * Delete all image and attachment blobs referenced by a BATCH of notes
 * being permanently deleted together (empty trash, multi-select delete,
 * trash auto-delete). The whole batch is excluded from the
 * still-referenced check: running the single-note variant per note misses
 * every blob two batch members share, because each note's check sees the
 * other batch member still holding it and neither ever enqueues - a queue
 * gap the orphan reconcile would only mop up days later.
 */
export async function gcOnNotesDelete(
  imageStore: ImageStore,
  notes: Array<{ id: string; body: string }>,
  attachmentStore?: AttachmentStore | null,
): Promise<void> {
  const imgSet = new Set<string>();
  const attSet = new Set<string>();
  for (const n of notes) {
    for (const id of extractImageIds(n.body)) imgSet.add(id);
    for (const id of extractAttachmentIds(n.body)) attSet.add(id);
  }
  if (imgSet.size === 0 && attSet.size === 0) return;

  // Don't delete blobs still referenced by notes outside the batch.
  const refsElsewhere = await findRefsInOtherNotes(
    [...imgSet, ...attSet],
    new Set(notes.map((n) => n.id)),
  );
  const imgIds = [...imgSet].filter((id) => !refsElsewhere.has(id));
  const attIds = [...attSet].filter((id) => !refsElsewhere.has(id));

  if (imgIds.length > 0) {
    await imageStore.deferDelete(imgIds);
  }
  if (attIds.length > 0 && attachmentStore) {
    await attachmentStore.deferDelete(attIds);
  }
}

/**
 * Delete all image and attachment blobs referenced in a note's body.
 * Call this when a SINGLE note is permanently deleted; batch paths must
 * use gcOnNotesDelete so shared blobs cannot hide behind batch-mates.
 */
export async function gcOnNoteDelete(
  imageStore: ImageStore,
  body: string,
  noteId: string,
  attachmentStore?: AttachmentStore | null,
): Promise<void> {
  await gcOnNotesDelete(imageStore, [{ id: noteId, body }], attachmentStore);
}

/**
 * Check which blob UUIDs are still referenced by ANY local note row -
 * no `deleted` filter, no excluded note. Used by sweepBlobGC, where a
 * row still sitting locally with deleted=1 is an unconfirmed tombstone
 * (the server may have rejected the delete) and must count as a live
 * reference. Returns the subset of `uuids` that ARE still referenced.
 */
async function findRefsAnywhere(uuids: string[]): Promise<Set<string>> {
  if (uuids.length === 0) return new Set();

  const referenced = new Set<string>();
  const remaining = new Set(uuids);

  await db.notes.each((note) => {
    if (remaining.size === 0) return;
    for (const uuid of remaining) {
      if (note.body.includes(uuid)) {
        referenced.add(uuid);
        remaining.delete(uuid);
      }
    }
  });

  return referenced;
}

/**
 * Phase 2 of deferred blob GC: actually remove Storage objects for
 * queue entries that have cleared the grace period, after re-checking
 * references against the full local mirror. Must only be called right
 * after a sync pass whose pull completed cleanly - that's what makes
 * the reference re-check trustworthy (see module doc comment).
 */
export async function sweepBlobGC(
  imageStore: ImageStore,
  attachmentStore: AttachmentStore | null,
): Promise<void> {
  // Below the release floor server writes pause (see sync.ts) - and GC
  // deletes are the most dangerous write of all here, because an old client
  // is deleting blobs based on reference rules that may have changed.
  if (isDemoMode() || isServerWriteBlocked() || navigator.onLine === false) return;
  if (sweepInFlight) return;
  sweepInFlight = true;

  try {
    // Re-assert the server-side pending rows for the WHOLE queue before
    // anything else, grace or no grace: the delete-time enqueue is
    // best-effort, and a lost one otherwise leaves peers re-inflating the
    // quota row until the orphan reconcile mops it up days later.
    const queued = await db.blobGC.toArray();
    if (queued.length === 0) return;
    await imageStore.ensurePendingGC(queued.map((e) => e.uuid));

    const cutoff = new Date(Date.now() - BLOB_GC_GRACE_MS).toISOString();
    const entries = queued.filter((e) => e.enqueuedAt <= cutoff);
    if (entries.length === 0) return;

    const uuids = entries.map((e) => e.uuid);
    const referenced = await findRefsAnywhere(uuids);

    // Still-referenced entries: cancel the deletion and re-credit quota.
    // One batched call for the sweep, regardless of kind - quota is
    // tracked per account, not per bucket.
    const cancelled = entries.filter((e) => referenced.has(e.uuid));
    if (cancelled.length > 0) {
      await db.blobGC.bulkDelete(cancelled.map((e) => e.uuid));
      const totalRefund = cancelled.reduce((sum, e) => sum + e.size, 0);
      if (totalRefund > 0) {
        imageStore.adjustQuota(totalRefund).catch(() => {
          // Already logged inside adjustQuota.
        });
      }
    }

    // Not referenced: actually remove the Storage objects, grouped by kind.
    const toRemove = entries.filter((e) => !referenced.has(e.uuid));
    const imgUuids = toRemove.filter((e) => e.kind === 'image').map((e) => e.uuid);
    const attUuids = toRemove.filter((e) => e.kind === 'attachment').map((e) => e.uuid);

    const settled: string[] = [];
    if (imgUuids.length > 0) {
      const { removed } = await imageStore.removeRemoteOnly(imgUuids);
      if (removed.length > 0) await db.blobGC.bulkDelete(removed);
      settled.push(...removed);
    }
    if (attUuids.length > 0 && attachmentStore) {
      const { removed } = await attachmentStore.removeRemoteOnly(attUuids);
      if (removed.length > 0) await db.blobGC.bulkDelete(removed);
      settled.push(...removed);
    }

    // Retire the server-side pending rows for everything that is settled:
    // objects actually deleted, plus cancelled deletions whose blobs are
    // back in use (their rows must stop excluding real usage). The table
    // is per-account, so one store's client covers both kinds.
    // Spec: packages/supabase/migrations/history/0068_pending_blob_gc_server_side.sql
    const retire = settled.concat(cancelled.map((e) => e.uuid));
    if (retire.length > 0) {
      await imageStore.clearPendingGC(retire).catch(() => {
        // Already logged inside clearPendingGC.
      });
    }
  } finally {
    sweepInFlight = false;
  }
}

// ── Orphan reconcile ────────────────────────────────────────────────

let reconcileInFlight = false;

/** How often the orphan reconcile is allowed to run. Orphans are a slow leak,
 * not an urgent condition, and the pass costs a recalc, a quota read and a
 * full bucket listing. Spec: ops/docs/design-decisions.md (orphan blob
 * reconcile). */
const RECONCILE_INTERVAL_MS = 24 * 60 * 60 * 1000;
const RECONCILE_AT_KEY = 'privacynotes.blobReconcileAt';

/** Upper bound on version rows the reconcile will fetch and decrypt in one
 * pass. Versions are capped at 20 per note, so this covers accounts up to a
 * few thousand edited notes. Past it the reconcile aborts rather than delete
 * on an incomplete reference set. */
const VERSION_SCAN_MAX = 20000;

/** One page of a Supabase Storage listing. */
const LIST_PAGE = 1000;

/** Storage list rows carry only the fields we need; the client types them
 * loosely, so narrow here rather than casting at each use. */
type StorageObject = { name: string; created_at?: string | null };

/**
 * Reclaim Supabase Storage blobs that nothing references any more.
 *
 * This is the backstop for every orphan source db.blobGC cannot cover (see
 * the module doc). It compares the bucket against the local mirror instead of
 * against a queue, so it repairs history as well as future leaks, and it is
 * the only thing that can bring an account showing usage with zero notes back
 * to zero.
 *
 * Deleting a Storage object is immediate and permanent, so this only ever
 * runs with the local mirror provably complete. Five conditions must all
 * hold before a single object is removed:
 *
 * 1. No dirty local notes. A pending push means the server has not seen
 *    everything this device has, so counts cannot be compared.
 * 2. The local live-note count equals the server's note_count, taken from a
 *    fresh recalc so the comparison is against a recount rather than a
 *    delta-maintained counter that is allowed to drift. This is the actual
 *    proof that scanning local bodies yields the complete reference set - it
 *    is what the 24h grace in sweepBlobGC substitutes for, and what a device
 *    mid-first-sync will always fail.
 * 3. The uuid appears in no local note body, trashed and unconfirmed
 *    tombstones included (findRefsAnywhere).
 * 4. The uuid appears in no note_version snapshot. A blob removed from a
 *    live note's body is deliberately kept alive by its history (see
 *    gcOnBodyChange), and that reference exists only in encrypted server
 *    rows. If the versions cannot be read, the pass aborts.
 * 5. The object is older than BLOB_GC_GRACE_MS, which covers the window
 *    between an upload returning a uuid and that uuid reaching a saved body.
 *
 * Anything currently in db.blobGC is skipped outright: those blobs already
 * have an owner with its own grace period, and this pass must not shorten it.
 *
 * Best-effort throughout - every failure path returns without deleting.
 */
export async function reconcileOrphanBlobs(
  supabase: SupabaseClient,
  pubkey: string,
  encryptionKey: Uint8Array,
  imageStore: ImageStore,
): Promise<void> {
  // Same release-floor pause as sweepBlobGC above.
  if (isDemoMode() || isServerWriteBlocked() || navigator.onLine === false) return;
  if (reconcileInFlight) return;

  const last = Number(localStorage.getItem(RECONCILE_AT_KEY) ?? 0);
  if (Number.isFinite(last) && Date.now() - last < RECONCILE_INTERVAL_MS) return;

  reconcileInFlight = true;
  try {
    // Gate 1: nothing of ours is still unpushed.
    if ((await db.notes.where('dirty').anyOf(1, 2).count()) > 0) return;

    // Gate 2: the server agrees with us about how many notes exist. recalc
    // first so note_count is a recount, not a drifted delta counter.
    await recalculateQuota(supabase);
    const usage = await fetchQuotaUsage(supabase);
    const localLive = await db.notes.where('deleted').equals(0).count();
    if (localLive !== usage.noteCount) {
      console.warn(
        '[imageGC] reconcile skipped - local mirror incomplete',
        localLive, 'local vs', usage.noteCount, 'server',
      );
      return;
    }

    // Everything currently in the bucket under our prefix.
    const objects: StorageObject[] = [];
    for (let offset = 0; ; offset += LIST_PAGE) {
      const { data, error } = await supabase.storage
        .from('encrypted-images')
        .list(pubkey, { limit: LIST_PAGE, offset });
      if (error) {
        console.warn('[imageGC] reconcile listing failed:', error.message);
        return;
      }
      const page = (data ?? []) as StorageObject[];
      objects.push(...page);
      if (page.length < LIST_PAGE) break;
    }
    if (objects.length === 0) {
      localStorage.setItem(RECONCILE_AT_KEY, String(Date.now()));
      return;
    }

    // Gates 3 and 5, plus the blobGC hand-off.
    const cutoff = Date.now() - BLOB_GC_GRACE_MS;
    const aged = objects.filter((o) => {
      const created = o.created_at ? Date.parse(o.created_at) : NaN;
      return Number.isFinite(created) && created < cutoff;
    });
    if (aged.length === 0) {
      localStorage.setItem(RECONCILE_AT_KEY, String(Date.now()));
      return;
    }
    const queued = new Set((await db.blobGC.toArray()).map((e) => e.uuid));
    const referenced = await findRefsAnywhere(
      aged.map((o) => o.name).filter((n) => !queued.has(n)),
    );
    let candidates = aged
      .map((o) => o.name)
      .filter((n) => !queued.has(n) && !referenced.has(n));
    if (candidates.length === 0) {
      localStorage.setItem(RECONCILE_AT_KEY, String(Date.now()));
      return;
    }

    // Gate 4: history snapshots. Only paid for once something looks orphaned.
    const versionRefs = await collectVersionBlobRefs(supabase, encryptionKey);
    if (!versionRefs) return; // unreadable - never delete on a partial set
    candidates = candidates.filter((uuid) => !versionRefs.has(uuid));
    if (candidates.length === 0) {
      localStorage.setItem(RECONCILE_AT_KEY, String(Date.now()));
      return;
    }

    // Images and attachments share one bucket and one path shape, and the
    // object name does not say which is which - removeRemoteOnly is the same
    // call either way, so one store can remove both.
    const { removed } = await imageStore.removeRemoteOnly(candidates);
    if (removed.length > 0) {
      console.warn('[imageGC] reconcile reclaimed', removed.length, 'orphaned blobs');
      await recalculateQuota(supabase);
    }
    localStorage.setItem(RECONCILE_AT_KEY, String(Date.now()));
  } catch (err) {
    console.warn('[imageGC] reconcile failed:', err);
  } finally {
    reconcileInFlight = false;
  }
}

/**
 * Every blob uuid referenced by any note_version snapshot on the account.
 * Returns null when the set cannot be established - unreadable, oversized, or
 * short-read version data must abort the reconcile rather than let it delete
 * against an incomplete picture. RLS ('note_versions_owner_select', migration
 * 0014) scopes an unfiltered select to the caller's own rows.
 *
 * The row count is established first and every page is then read explicitly,
 * because a single big `.limit()` cannot tell "that is all of them" apart from
 * "PostgREST capped the response at db-max-rows". The first reads as a
 * complete reference set and would authorize deleting a blob that a version we
 * never saw still holds. Pages are ordered oldest-first so a snapshot written
 * mid-scan lands past the end instead of shifting rows across page boundaries.
 */
async function collectVersionBlobRefs(
  supabase: SupabaseClient,
  encryptionKey: Uint8Array,
): Promise<Set<string> | null> {
  const { count, error: countErr } = await supabase
    .from('note_versions')
    .select('id', { count: 'exact', head: true });
  if (countErr || count == null) {
    console.warn('[imageGC] reconcile version count failed:', countErr?.message);
    return null;
  }
  if (count === 0) return new Set();
  if (count > VERSION_SCAN_MAX) {
    console.warn('[imageGC] reconcile skipped -', count, 'version rows to scan');
    return null;
  }

  const refs = new Set<string>();
  let seen = 0;
  for (let from = 0; from < count; from += LIST_PAGE) {
    const { data, error } = await supabase
      .from('note_versions')
      .select('ciphertext, nonce')
      .order('created_at', { ascending: true })
      .order('id', { ascending: true })
      .range(from, from + LIST_PAGE - 1);
    if (error) {
      console.warn('[imageGC] reconcile version scan failed:', error.message);
      return null;
    }
    const rows = (data ?? []) as { ciphertext: string; nonce: string }[];
    if (rows.length === 0) break;
    seen += rows.length;
    for (const row of rows) {
      let body: string;
      try {
        body = decryptNote(
          base64ToBytes(row.ciphertext),
          base64ToBytes(row.nonce),
          encryptionKey,
        ).body ?? '';
      } catch {
        // A snapshot we cannot read is a reference we cannot rule out.
        return null;
      }
      for (const id of extractImageIds(body)) refs.add(id);
      for (const id of extractAttachmentIds(body)) refs.add(id);
    }
  }
  if (seen < count) {
    console.warn('[imageGC] reconcile version scan short:', seen, 'of', count);
    return null;
  }
  return refs;
}
