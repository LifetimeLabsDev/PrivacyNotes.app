import { useEffect, useRef } from 'react';
import type { AttachmentStore } from './attachmentStore';
import { gcOnNotesDelete } from './imageGC';
import type { ImageStore } from './imageStore';
import { purgeExpiredTrash, trashPurgeMayRun } from './trashPurge';
import { loadLocalSettings } from './userSettings';

/**
 * Runs the trash auto-purge once per app open, at the first render where it
 * may: after a sync pass in this session has pulled the notes and read the
 * settings from the server (`ready`, useSyncOrchestrator's trashPurgeReady),
 * or at once in demo mode, which has no sync. trashPurge.ts says why it may
 * never decide earlier.
 *
 * The day count comes from the settings cache, which that pass read from the
 * server. React state can lag it: a settings change made during the pass keeps
 * the pass from writing its result into state. `dayCount` is here only so a
 * change to the setting re-runs the check.
 *
 * The blob GC runs after the write, over the rows it tombstoned.
 */
export function useTrashAutoPurge({
  ready,
  demo,
  trashedCount,
  dayCount,
  imageStoreRef,
  attachmentStoreRef,
  refresh,
  runSync,
  refreshStorage,
}: {
  ready: boolean;
  demo: boolean;
  trashedCount: number;
  dayCount: number;
  imageStoreRef: { readonly current: ImageStore | null };
  attachmentStoreRef: { readonly current: AttachmentStore | null };
  refresh: () => Promise<unknown>;
  runSync: () => Promise<void>;
  refreshStorage: () => void;
}): void {
  const ranRef = useRef(false);
  useEffect(() => {
    if (ranRef.current) return;
    if (!trashPurgeMayRun(ready, demo)) return;
    if (trashedCount === 0) return;
    const days = loadLocalSettings().autoDeleteTrashDays;
    if (days <= 0) return;
    ranRef.current = true;
    void (async () => {
      const purged = await purgeExpiredTrash(days, demo);
      if (purged.length === 0) return;
      if (imageStoreRef.current) {
        void gcOnNotesDelete(imageStoreRef.current, purged, attachmentStoreRef.current);
      }
      await refresh();
      // Sync deletes to server, then refresh quota so the storage bar updates.
      runSync().then(refreshStorage);
    })();
  }, [ready, demo, trashedCount, dayCount, imageStoreRef, attachmentStoreRef, refresh, runSync, refreshStorage]);
}
