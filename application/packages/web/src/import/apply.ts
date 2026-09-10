import { db, type LocalNote } from '../db';
import { linkDedupeKey, parseLinkBody } from '../linkBody';
import { addToContactMatchIndex, contactMatches, emptyContactMatchIndex } from '../contactBody';
import type { ApplyResult, ImportedNote, ParsedImport } from './types';

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
  // A note that carries its own id is matched on that id below, and the
  // match outranks these two lookalike rules: a contact from our own backup
  // with a newer phone number must update the row it IS, not be counted as a
  // duplicate of it. The rules keep their job for every other source.
  const ownsId = (n: ImportedNote) => typeof n.id === 'string' && n.id.length > 0;
  if (incoming.some((n) => n.type === 'link' && !ownsId(n))) {
    const existing = await db.notes
      .filter((n) => n.type === 'link' && n.deleted !== 1 && n.trashed !== 1)
      .toArray();
    const keys = new Set(existing.map((n) => linkDedupeKey(parseLinkBody(n.body).url)));
    incoming = incoming.filter((n) => {
      if (n.type !== 'link' || ownsId(n)) return true;
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

  if (incoming.some((n) => n.type === 'contact' && !ownsId(n))) {
    const existing = await db.notes
      .filter((n) => n.type === 'contact' && n.deleted !== 1 && n.trashed !== 1)
      .toArray();
    const index = emptyContactMatchIndex();
    for (const n of existing) addToContactMatchIndex(index, n.title, n.body);
    incoming = incoming.filter((n) => {
      if (n.type !== 'contact' || ownsId(n)) return true;
      if (contactMatches(index, n.title, n.body)) {
        skippedDuplicates++;
        return false;
      }
      // The first card wins inside one file too.
      addToContactMatchIndex(index, n.title, n.body);
      return true;
    });
  }

  // Our own backup formats carry each note's real id, and matching on it is
  // what makes a restore repair a vault instead of doubling it. Read the
  // local side once, in order, so a note's decision is made against the copy
  // the vault actually holds.
  const ownIds = incoming.map((n) => n.id).filter((id): id is string => !!id);
  const localById = new Map<string, LocalNote>();
  if (ownIds.length > 0) {
    const found = await db.notes.bulkGet(ownIds);
    // bulkGet answers positionally, one slot per key, so it is walked
    // alongside the ids rather than filtered first.
    ownIds.forEach((id, i) => {
      const row = found[i];
      if (row) localById.set(id, row);
    });
  }
  let updated = 0;
  let unchanged = 0;

  const rows: LocalNote[] = incoming.flatMap((n) => {
    const mine = n.id ? localById.get(n.id) : undefined;
    // The note's own id is reused ONLY when a live local row carries it. Two
    // states make reuse a silent, permanent failure: a tombstone, because the
    // server drops every write to a deleted note without an error, so a
    // restored copy under that id sits dirty for ever and never reaches
    // another device; and a row this account cannot see, which is what a
    // backup from a previous account looks like after a lost phrase, because
    // the id is the table's primary key and the insert collides. A fresh id
    // syncs in both cases. The cost is that a purged note comes back as a
    // new note rather than as itself, which is what a restore used to do.
    const live = !!mine && mine.deleted !== 1;
    if (live) {
      // The vault already has this note. Keep whichever copy is newer, which
      // is the same rule sync applies between two devices. A restore is for
      // repairing what is missing, so it never overwrites something the user
      // has edited since the backup was taken.
      const incomingAt = n.trashed ? '' : n.updatedAt || '';
      if (!(incomingAt > mine.updatedAt)) {
        unchanged++;
        return [];
      }
      updated++;
    }
    const tags = sourceTag && !n.tags.includes(sourceTag)
      ? [...n.tags, sourceTag]
      : n.tags;
    const trashed = n.trashed ? 1 : 0;
    return {
      id: live ? n.id! : crypto.randomUUID(),
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

  return {
    imported: rows.length - updated,
    errors,
    noteIds: rows.map((r) => r.id),
    ...(skippedDuplicates > 0 ? { skippedDuplicates } : {}),
    ...(updated > 0 ? { updated } : {}),
    ...(unchanged > 0 ? { unchanged } : {}),
  };
}
