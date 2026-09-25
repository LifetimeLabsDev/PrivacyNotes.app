/**
 * The trash auto-purge ("Auto-delete after 30 days" in the Trash view).
 *
 * Each device purges its own copy, because the trashed flag and the day count
 * both live inside encrypted data. A purge tombstone is final on every device:
 * the tombstone push carries no stamp guard and a pulled tombstone overrides
 * any local edit. So the purge decides only on state that has pulled:
 *  - It waits for a sync pass in this app session that ran, finished its pull,
 *    and read the settings from the server in that same pass, so the settings
 *    cache has read the server's row in this pass. Before that, the local copy
 *    can still hold a note another device restored, and the cached day count
 *    can be a fresh device's default or an old value another device has changed.
 *  - It reads the rows inside the transaction that writes the tombstones.
 *  - It skips a row with an unpushed change: the pull never replaces a dirty
 *    row, so that copy is not what the server holds.
 * Demo mode has no sync, so its local state is the whole truth: there the
 * purge neither waits nor skips dirty rows.
 *
 * updatedAt is the age signal, which relies on every writer of trashed=1
 * stamping it at trash time (trashNote, trashNotesWithTag, applyImport).
 * Anything that sets trashed=1 while keeping an older updatedAt is purged by
 * the next run, with no undo.
 */
import { db, type LocalNote } from './db';
import { nextStamp } from './notesRepo';

const DAY_MS = 86_400_000;

/** The rows a purge with this day count takes at `now`. */
export function selectExpiredTrash<
  T extends Pick<LocalNote, 'trashed' | 'deleted' | 'dirty' | 'updatedAt'>,
>(rows: readonly T[], days: number, now: number, demo: boolean): T[] {
  if (!(days > 0)) return [];
  const cutoff = now - days * DAY_MS;
  return rows.filter(
    (n) =>
      n.trashed === 1 &&
      n.deleted === 0 &&
      // A demo row never syncs, so it never stops being dirty.
      (demo || n.dirty === 0) &&
      Date.parse(n.updatedAt) < cutoff,
  );
}

/** Whether a finished sync pass opens the purge: it ran, its notes pull
 *  completed, and it read the settings from the server (syncUserSettings'
 *  report.readServer for this pass). */
export function pullOpensTrashPurge(
  pass: { ran: boolean; pullOk: boolean },
  settingsRead: boolean,
): boolean {
  return pass.ran && pass.pullOk && settingsRead;
}

/** Whether the purge may run: a pass has opened it, or this is the demo. */
export function trashPurgeMayRun(opened: boolean, demo: boolean): boolean {
  return opened || demo;
}

/**
 * Tombstone every expired trashed row, reading and writing in one
 * transaction. Returns the rows it tombstoned, for the blob GC.
 */
export async function purgeExpiredTrash(
  days: number,
  demo: boolean,
  now: number = Date.now(),
): Promise<Array<{ id: string; body: string }>> {
  if (!(days > 0)) return [];
  const purged = await db.transaction('rw', db.notes, async () => {
    const trashed = await db.notes.where('trashed').equals(1).toArray();
    const expired = selectExpiredTrash(trashed, days, now, demo);
    for (const n of expired) {
      await db.notes.update(n.id, { deleted: 1, updatedAt: nextStamp(n.updatedAt), dirty: 1 });
    }
    return expired.map((n) => ({ id: n.id, body: n.body }));
  });
  // Parsed-doc cache rows are disposable, so they go outside the transaction.
  await db.editorDocCache.bulkDelete(purged.map((n) => n.id)).catch(() => { /* best-effort */ });
  return purged;
}
