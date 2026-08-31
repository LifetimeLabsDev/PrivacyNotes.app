import { useEffect, useState } from 'react';
import { liveQuery } from 'dexie';
import { db } from './db';

export interface PendingUploads {
  /** Blobs (images + attachments) still queued for upload. */
  count: number;
  /** Subset known not to fit the storage quota (backlog #143). When every
   *  pending blob is blocked, no upload is actually running - the status
   *  surfaces say "doesn't fit" instead of "uploading". */
  blocked: number;
}

/**
 * Live count of blobs (images + attachments) still queued for upload.
 *
 * The single source the sync surfaces share: the footer pill, the STATUS
 * row in ID & Sync, and the verify result all read this same number, so
 * they can never contradict each other about whether data is still on
 * its way up ("Synced" next to "58 files waiting to upload" was exactly
 * that contradiction). Uploads drain on store init and after every sync
 * pass, so a non-zero count is an active state, not a stuck one - except
 * for quota-blocked rows, which wait for headroom and are reported
 * separately so the UI never claims an upload that cannot happen.
 */
/**
 * Live "kept on this device only" state for one blob: true while its
 * upload is pending AND known not to fit the storage quota. Drives the
 * amber chip on attachment cards (backlog #143).
 */
export function useBlobQuotaBlocked(uuid: string | null): boolean {
  const [blocked, setBlocked] = useState(false);
  useEffect(() => {
    if (!uuid) return;
    const sub = liveQuery(async () => {
      const img = await db.imageDedup.where('uuid').equals(uuid).first();
      const att = await db.attachmentDedup.where('uuid').equals(uuid).first();
      const row = img ?? att;
      return row?.pendingUpload === 1 && row?.quotaBlocked === 1;
    }).subscribe({
      next: setBlocked,
      error: () => setBlocked(false),
    });
    return () => sub.unsubscribe();
  }, [uuid]);
  return blocked;
}

/**
 * Live set of every quota-blocked blob uuid. The per-list variant of
 * useBlobQuotaBlocked: FilesList renders N rows from one map callback,
 * so it needs one query returning the whole set rather than one hook
 * per row (backlog #151).
 */
export function useQuotaBlockedUuids(): Set<string> {
  const [blocked, setBlocked] = useState<Set<string>>(() => new Set());
  useEffect(() => {
    const sub = liveQuery(async () => {
      const images = await db.imageDedup
        .filter((r) => r.pendingUpload === 1 && r.quotaBlocked === 1)
        .toArray();
      const attachments = await db.attachmentDedup
        .filter((r) => r.pendingUpload === 1 && r.quotaBlocked === 1)
        .toArray();
      return new Set([...images, ...attachments].map((r) => r.uuid));
    }).subscribe({
      next: setBlocked,
      error: () => setBlocked(new Set()),
    });
    return () => sub.unsubscribe();
  }, []);
  return blocked;
}

export function usePendingUploads(): PendingUploads {
  const [state, setState] = useState<PendingUploads>({ count: 0, blocked: 0 });
  useEffect(() => {
    const sub = liveQuery(async () => {
      const images = await db.imageDedup.filter((r) => r.pendingUpload === 1).toArray();
      const attachments = await db.attachmentDedup.filter((r) => r.pendingUpload === 1).toArray();
      const blocked =
        images.filter((r) => r.quotaBlocked === 1).length +
        attachments.filter((r) => r.quotaBlocked === 1).length;
      return { count: images.length + attachments.length, blocked };
    }).subscribe({
      next: setState,
      error: (err) => console.warn('[syncStatus] pending blob query failed:', err),
    });
    return () => sub.unsubscribe();
  }, []);
  return state;
}
