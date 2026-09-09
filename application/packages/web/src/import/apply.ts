import { db, type LocalNote } from '../db';
import { linkDedupeKey, parseLinkBody } from '../linkBody';
import { addToContactMatchIndex, contactMatches, emptyContactMatchIndex } from '../contactBody';
import type { ApplyResult, ParsedImport } from './types';

/**
 * Write a ParsedImport into the local Dexie store as brand-new notes
 * with dirty=1, so the next sync pass will encrypt and upload them.
 *
 * Every imported note gets a fresh UUID - we deliberately do NOT try to
 * dedupe against existing rows. Two reasons:
 *   1. The source UUIDs are in a different namespace (SN uuids) and
 *      reusing them would risk collisions with real PrivacyNotes ids.
 *   2. If the user re-imports the same file, we want that to feel like
 *      "add everything again" rather than silently no-op. The UI warns
 *      about this before the user confirms.
 *
 * One carve-out (2026-08-22): BOOKMARKS ('link' rows) dedupe on exact URL
 * match against existing non-trashed bookmarks, and the summary reports
 * the skipped count. A bookmark has a natural identity its URL carries,
 * so a re-import doubling every row is a bug, not a feature, there.
 * CONTACTS ('contact' rows) do the same through the matcher in
 * contactBody.ts: uid first, then name plus a shared number, then a shared
 * email. A match is counted and left alone, never merged.
 * Generalizing this to other sources is backlog #155.
 *
 * We write in one Dexie transaction so the import is atomic - either
 * every note lands, or (on error) the whole thing rolls back and the
 * local DB is unchanged.
 */
export async function applyImport(
  parsed: ParsedImport,
  sourceTag?: string
): Promise<ApplyResult> {
  const errors: string[] = [];
  const now = new Date().toISOString();

  let incoming = parsed.notes;
  let skippedDuplicates = 0;
  if (incoming.some((n) => n.type === 'link')) {
    const existing = await db.notes
      .filter((n) => n.type === 'link' && n.deleted !== 1 && n.trashed !== 1)
      .toArray();
    const keys = new Set(existing.map((n) => linkDedupeKey(parseLinkBody(n.body).url)));
    incoming = incoming.filter((n) => {
      if (n.type !== 'link') return true;
      const key = linkDedupeKey(parseLinkBody(n.body).url);
      if (keys.has(key)) {
        skippedDuplicates++;
        return false;
      }
      // First occurrence wins inside one import file too.
      keys.add(key);
      return true;
    });
  }

  if (incoming.some((n) => n.type === 'contact')) {
    const existing = await db.notes
      .filter((n) => n.type === 'contact' && n.deleted !== 1 && n.trashed !== 1)
      .toArray();
    const index = emptyContactMatchIndex();
    for (const n of existing) addToContactMatchIndex(index, n.title, n.body);
    incoming = incoming.filter((n) => {
      if (n.type !== 'contact') return true;
      if (contactMatches(index, n.title, n.body)) {
        skippedDuplicates++;
        return false;
      }
      // The first card wins inside one file too.
      addToContactMatchIndex(index, n.title, n.body);
      return true;
    });
  }

  const rows: LocalNote[] = incoming.map((n) => {
    const tags = sourceTag && !n.tags.includes(sourceTag)
      ? [...n.tags, sourceTag]
      : n.tags;
    const trashed = n.trashed ? 1 : 0;
    return {
      id: crypto.randomUUID(),
      title: n.title,
      body: n.body,
      tags,
      createdAt: n.createdAt || now,
      // A trashed note's updatedAt doubles as "when it was trashed" -
      // that is the invariant trashNote() establishes, and the auto-purge
      // in NotesView reads updatedAt to decide what has outlived the
      // retention window. Imported notes carry the source app's original
      // timestamp, which for anything the user deleted a while ago is
      // already past the window, so honoring it here permanently deletes
      // every imported trashed note seconds after the import lands (the
      // purge effect runs on the very next mount). Stamp them as trashed
      // now: the note entered THIS trash today, so the user gets the full
      // retention window to rescue anything. createdAt is untouched, so
      // the note's origin date survives.
      updatedAt: trashed ? now : n.updatedAt || now,
      dirty: 1,
      deleted: 0,
      trashed,
      starred: n.starred ? 1 : 0,
      locked: n.locked ? 1 : 0,
      pinProtected: n.pinProtected ? 1 : 0,
      type: n.type || 'note',
      folderId: n.folderId ?? null,
      ...(n.trackers && Object.keys(n.trackers).length > 0 ? { trackers: n.trackers } : {}),
    };
  });

  try {
    await db.transaction('rw', db.notes, async () => {
      await db.notes.bulkPut(rows);
    });
  } catch (err) {
    errors.push(
      err instanceof Error
        ? err.message
        : 'Unknown error while writing to local database.'
    );
    return { imported: 0, errors, noteIds: [] };
  }

  return { imported: rows.length, errors, noteIds: rows.map((r) => r.id), ...(skippedDuplicates > 0 ? { skippedDuplicates } : {}) };
}
