import { db, type LocalNote } from '../db';
import { carrySideField } from '../localSeal';
import { nextStamp } from '../notesRepo';
import { oneLineTitle } from '../oneLineTitle';
import { linkDedupeKey, parseLinkBody } from '../linkBody';
import { addToContactMatchIndex, contactMatches, emptyContactMatchIndex } from '../contactBody';
import type { ApplyResult, ImportedNote, ParsedImport } from './types';

/**
 * Write a ParsedImport into the local Dexie store with dirty=1, so the next
 * sync pass encrypts and uploads it. Three rules decide what a note in the
 * file does to the vault, and the import preview names the one that applies
 * (PreviewPhase in ImportModal.tsx):
 *
 *   1. OUR OWN backups carry each note's id (ImportedNote.id), and it is
 *      matched first. The newer copy wins, a copy in the local trash comes
 *      back out, and a note the vault lacks is added under a fresh id, which
 *      a second restore of the same file finds again by its content, so a
 *      restore run twice changes nothing. The content match is exact: a note
 *      the first restore added and the user then edited is added again.
 *   2. BOOKMARKS ('link' rows) and CONTACTS ('contact' rows) without our id
 *      are matched as lookalikes, because each carries an identity of its
 *      own: a bookmark by its exact URL against the ones not in the trash, a
 *      contact through the matcher in contactBody.ts (uid first, then name
 *      plus a shared number, then a shared email). A match is counted as
 *      skipped and left alone, never merged. Generalizing this to other
 *      sources is backlog #155.
 *   3. Every other note lands under a fresh UUID and is never matched. Ids
 *      from another app live in another namespace, where reusing them would
 *      risk a collision with a real PrivacyNotes id, so importing the same
 *      file again adds everything again, which the preview warns about
 *      before the user confirms. A backup written before ids were carried
 *      has none, so it falls here too.
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
  const nowMs = Date.parse(now);
  // A timestamp read from a file is a claim about the past, and the one thing
  // this device can check is that it IS the past. A stamp later than this
  // clock is a wrong clock on the exporting device or a crafted file, and
  // either way it must not outrank the copy the vault holds, nor enter the
  // vault, where a stamp from the far future wins every later merge on every
  // device. A stamp that does not parse is refused the same way. Both land as
  // the time the note actually arrived. What this does not decide is a file
  // that claims a plausible recent time: a restore trusts the file it is
  // handed, and that is the feature.
  const stampFromPast = (iso: string | undefined): string | null => {
    if (!iso) return null;
    const at = Date.parse(iso);
    return Number.isNaN(at) || at > nowMs ? null : iso;
  };

  // Every title is stored on one line, whichever importer read it and from
  // what: the matching below and the stored row both see it that way. See
  // oneLineTitle for why a line break cannot stay in a title.
  let incoming = parsed.notes.map((n) => ({ ...n, title: oneLineTitle(n.title) }));
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
      if (row && row.deleted !== 1) localById.set(id, row);
    });
  }
  // A note the vault lacked comes in under a fresh id (see below), so a
  // second restore of the same file cannot find it by the backup's id and
  // would add it again. Its content still finds it: the same type, creation
  // time, title and body. A row the file names by its own id is left to
  // that match.
  const contentKey = (n: { type?: string; createdAt: string; title: string; body: string }) =>
    [n.type || 'note', n.createdAt, n.title, n.body].join('\u0000');
  const localByContent = new Map<string, LocalNote[]>();
  if (incoming.some((n) => n.id && !localById.has(n.id))) {
    const named = new Set(ownIds);
    for (const row of await db.notes.where('deleted').equals(0).toArray()) {
      if (named.has(row.id)) continue;
      const key = contentKey(row);
      localByContent.set(key, [...(localByContent.get(key) ?? []), row]);
    }
  }
  let updated = 0;
  let unchanged = 0;

  const rows: LocalNote[] = incoming.flatMap((n) => {
    // One copy in the vault answers for one note in the file.
    const mine = n.id
      ? localById.get(n.id) ?? localByContent.get(contentKey(n))?.shift()
      : undefined;
    const stamp = stampFromPast(n.updatedAt);
    // The note's own id is reused ONLY when a live local row carries it. Two
    // states make reuse a silent, permanent failure: a tombstone, because the
    // server drops every write to a deleted note without an error, so a
    // restored copy under that id sits dirty for ever and never reaches
    // another device; and a row this account cannot see, which is what a
    // backup from a previous account looks like after a lost phrase, because
    // the id is the table's primary key and the insert collides. A fresh id
    // syncs in both cases. The cost is that a purged note comes back as a
    // new note rather than as itself.
    if (mine) {
      // The vault already has this note. Keep whichever copy is newer, which
      // is the same rule sync applies between two devices. A restore is for
      // repairing what is missing, so it never overwrites something the user
      // has edited since the backup was taken.
      const incomingAt = n.trashed ? '' : (stamp ?? '');
      if (!(incomingAt > mine.updatedAt)) {
        // Moving a note to the trash stamps it, so a copy trashed after the
        // backup always reads as the newer one, and a restore is how a
        // person gets that note back. It leaves the trash with its own
        // content, which can hold edits the backup lacks, and goes to the
        // folder the backup gives it, as a newer backup copy would.
        if (mine.trashed === 1 && !n.trashed) {
          updated++;
          return [{
            ...mine,
            trashed: 0,
            folderId: n.folderId ?? null,
            updatedAt: nextStamp(mine.updatedAt),
            dirty: 1,
          }];
        }
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
      id: mine ? mine.id : crypto.randomUUID(),
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
      updatedAt: trashed ? now : (stamp ?? now),
      dirty: 1,
      deleted: 0,
      trashed,
      starred: n.starred ? 1 : 0,
      locked: n.locked ? 1 : 0,
      pinProtected: n.pinProtected ? 1 : 0,
      type: n.type || 'note',
      folderId: n.folderId ?? null,
      ...(n.trackers && Object.keys(n.trackers).length > 0 ? { trackers: n.trackers } : {}),
      // A copy that replaces the local row keeps that row's record of the
      // server version it last synced, and the base beside it: its push
      // then merges field by field against that version like any edit,
      // where a row with no record merges with no base, so its later stamp
      // decides every detail the server changed since the backup.
      ...(mine
        ? {
            ...(mine.syncedNonce != null ? { syncedNonce: mine.syncedNonce } : {}),
            ...carrySideField('notes', mine),
          }
        : {}),
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
