import { db, reopenDb, requestPersistence, type LocalNote } from './db';
import { bumpNotesCreated } from './notesCreated';
import { perfSpan } from './perf';
import { clearFaviconCache } from './faviconQueue';

/**
 * Pure Dexie CRUD. No network, and no crypto of its own: wire
 * encryption happens at the sync boundary, and the Dexie middleware in
 * localSeal.ts seals note content at rest underneath these calls.
 * These functions are what the UI calls.
 */

/** Max characters allowed in a single tag. Prevents layout blowouts and abuse. */
export const TAG_MAX_LENGTH = 30;

/**
 * Normalize a tag string: trim, strip leading #, remove control chars
 * and delimiters (comma, #), collapse whitespace, enforce length limit.
 * Preserves case and allows most printable characters (spaces, dots,
 * @, etc.) so tags from imports (Standard Notes, Obsidian) survive
 * without mangling.
 */
export function normalizeTag(raw: string): string {
  return raw
    .trim()
    .replace(/^#+/, '')
    .replace(/[,#]/g, '')           // strip delimiters
    .replace(/[\x00-\x1f\x7f]/g, '') // strip control chars
    .replace(/\s+/g, ' ')           // collapse whitespace runs
    .trim()                          // re-trim after stripping
    .slice(0, TAG_MAX_LENGTH);
}

/**
 * A note's tags in reading order: alphabetical, case-insensitive, with
 * digit runs compared as numbers so `tag2` precedes `tag10`. Same collator
 * settings as the folder sibling sorter, so a folder chip and the tag chips
 * beside it order their names by one rule.
 *
 * A DISPLAY order, never a stored one. The array on the note keeps the order
 * the tags were typed in, so nothing is rewritten and no note is marked dirty;
 * every existing note reads sorted from the moment it is drawn. Call it at
 * each place tags are rendered, and derive any position-based action (which
 * chip is last) from the result rather than from the note's own array.
 * Spec: issue #259.
 */
export function sortTags(tags: string[]): string[] {
  return tags
    .slice()
    .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base', numeric: true }));
}

/**
 * Tags out of a YAML front-matter block, in the three shapes Obsidian writes.
 *
 *   tags: [one, two]
 *   tags:
 *     - one
 *     - two
 *   tag: one
 *
 * Lives here rather than in either caller because both the Obsidian importer
 * and the Markdown folder adapter need exactly this, and had a line-walking
 * copy each. They are allowed to disagree about the BODY - the importer
 * rewrites it, the folder must not touch it - but the front matter is the same
 * grammar in both, and two parsers for one grammar drift.
 *
 * Takes the block WITHOUT its `---` fences. Values are normalized, so callers
 * get tags already trimmed, lowercased and length-capped.
 */
export function parseYamlTags(block: string): string[] {
  const tags: string[] = [];
  let inList = false;

  for (const line of block.split('\n')) {
    const trimmed = line.trim();

    // Continuation of a list under `tags:`.
    if (inList) {
      if (trimmed.startsWith('- ')) {
        const tag = normalizeTag(trimmed.slice(2).trim().replace(/^["']|["']$/g, ''));
        if (tag) tags.push(tag);
        continue;
      }
      inList = false;
    }

    const colonIdx = line.indexOf(':');
    if (colonIdx < 0) continue;
    const key = line.slice(0, colonIdx).trim().toLowerCase();
    if (key !== 'tags' && key !== 'tag') continue;

    const rawVal = line.slice(colonIdx + 1).trim();
    if (!rawVal) {
      inList = true;
    } else if (rawVal.startsWith('[')) {
      for (const t of rawVal.replace(/^\[/, '').replace(/\]$/, '').split(',')) {
        const tag = normalizeTag(t.trim().replace(/^["']|["']$/g, ''));
        if (tag) tags.push(tag);
      }
    } else {
      const tag = normalizeTag(rawVal.replace(/^["']|["']$/g, ''));
      if (tag) tags.push(tag);
    }
  }
  return tags;
}

/**
 * Inline `#tags` in a body, ignoring every place a `#` is not a tag.
 *
 * The ONE implementation, shared by the Markdown folder adapter (which reads
 * a file it does not own) and by the Obsidian and Markdown importers: one
 * grammar, one parser, so the callers cannot disagree about which `#` is a
 * tag - `[see](#custodial-mode)` and `#f46d24` are not tags anywhere.
 *
 * Skips fenced blocks and code spans, where a `#` is content. Skips link
 * DESTINATIONS, where it is an anchor or a fragment. Skips headings, where it
 * starts the line. Requires a leading letter or underscore, so `#1` and
 * `#1E40AF` stay numbers, and rejects anything shaped exactly like a CSS hex
 * colour, which costs us a six-letter tag made only of a-f and is worth it.
 *
 * `stripComments` is for the Obsidian importer alone: it removes the comment
 * TEXT later in the same pass, so a tag written inside `%%...%%` would
 * otherwise outlive the sentence that explained it (#146). The adapter must
 * NOT pass it - it reports what the file currently says, and the comment is
 * still in the file.
 */
export function extractInlineTags(
  body: string,
  opts?: { stripComments?: boolean },
): string[] {
  let cleaned = body
    .replace(/```[\s\S]*?```/g, '')
    .replace(/~~~[\s\S]*?~~~/g, '')
    .replace(/`[^`\n]*`/g, '')
    // Link DESTINATIONS, not link text. `[see](#custodial-mode)` is an anchor
    // and `[x](https://e.com/a#b)` is a fragment; both look exactly like a tag
    // and neither is one. Found on a real docs folder, where anchors alone
    // invented a dozen tags nobody had written.
    .replace(/\]\([^)]*\)/g, ']()')
    .replace(/^\s{0,3}#{1,6}\s.*$/gm, '');
  // Last, so a code span holding `%%` is already gone and cannot pair up with
  // a later one across ordinary text.
  if (opts?.stripComments) cleaned = cleaned.replace(/%%[\s\S]*?%%/g, '');

  const found = new Set<string>();
  for (const match of cleaned.matchAll(/(^|[\s[])#([\p{L}\p{N}_/-]+)/gu)) {
    const raw = match[2];
    // Must START with a letter or underscore, which rejects `#1E40AF`.
    if (!raw || !/^[\p{L}_]/u.test(raw)) continue;
    // ...but that alone still admits LOWERCASE hex, and `#f46d24` starts with a
    // letter. Reject anything shaped exactly like a CSS colour instead: the
    // three real lengths, hex digits only.
    if (/^([0-9a-f]{3}|[0-9a-f]{6}|[0-9a-f]{8})$/i.test(raw)) continue;
    const tag = normalizeTag(raw);
    if (tag) found.add(tag);
  }
  return [...found];
}

/**
 * Stamp for an edit to an EXISTING row: the wall clock, unless that would not
 * be strictly newer than the row's current stamp (a second edit in the same
 * millisecond, a clock that stepped back, a pulled server stamp from a skewed
 * peer) - then one millisecond past the current stamp. Strictly monotonic
 * per-row generations mean the sync guards (push `.lte`, pull-apply skip)
 * never see two of THIS device's generations carrying an equal stamp (#156).
 */
function nextStamp(current: string | undefined): string {
  const now = Date.now();
  const cur = current ? Date.parse(current) : NaN;
  return new Date(Number.isFinite(cur) && cur >= now ? cur + 1 : now).toISOString();
}

/**
 * Read-modify-write for single-note edits: bumps `updatedAt` monotonically
 * off the row's current stamp and flags it dirty, inside one transaction so
 * a concurrent writer can't interleave between the read and the write.
 * No-op when the note doesn't exist.
 */
async function touchNote(
  id: string,
  patch: Partial<LocalNote>
): Promise<void> {
  await db.transaction('rw', db.notes, async () => {
    const current = await db.notes.get(id);
    if (!current) return;
    await db.notes.update(id, {
      ...patch,
      updatedAt: nextStamp(current.updatedAt),
      dirty: 1,
    });
  });
}

/**
 * Return all notes that still exist locally (not hard-deleted tombstones).
 * Callers can filter for trashed / starred views themselves - it's cheap
 * enough to do in JS and keeps this function simple.
 */
export async function listNotes(): Promise<LocalNote[]> {
  const end = perfSpan('listNotes');
  const read = () =>
    db.notes.where('deleted').equals(0).reverse().sortBy('updatedAt');
  try {
    return await read();
  } catch {
    // iOS standalone: the IndexedDB connection may have been severed
    // while the app was backgrounded. Reopen and retry once before
    // surfacing the failure to the caller. (#112)
    await reopenDb();
    return await read();
  } finally {
    end();
  }
}

export async function getNote(id: string): Promise<LocalNote | undefined> {
  return db.notes.get(id);
}

export async function createNote(
  title = '',
  body = '',
  tags?: string[],
  starred = false,
  type: import('@notes/shared').NoteType = 'note',
  folderId: string | null = null,
): Promise<LocalNote> {
  // First real write is the contextual moment to ask for persistent
  // storage (no-op after the first call / in demo). See db.ts.
  void requestPersistence();
  const now = new Date().toISOString();
  const note: LocalNote = {
    id: crypto.randomUUID(),
    title,
    body,
    tags: tags ?? [],
    createdAt: now,
    updatedAt: now,
    dirty: 1,
    deleted: 0,
    trashed: 0,
    starred: starred ? 1 : 0,
    locked: 0,
    pinProtected: 0,
    type,
    folderId,
  };
  await db.notes.put(note);
  // Count the create for milestones. Only this path counts - the
  // importer writes rows directly, so an import never advances it.
  bumpNotesCreated();
  return note;
}

export async function updateNote(
  id: string,
  patch: Partial<Pick<LocalNote, 'title' | 'body' | 'tags' | 'type' | 'trackers' | 'folderId'>>,
  /** Pass an explicit timestamp to avoid bumping updatedAt (e.g. derived-title commit). */
  updatedAt?: string
): Promise<void> {
  void requestPersistence();
  if (updatedAt !== undefined) {
    await db.notes.update(id, { ...patch, updatedAt, dirty: 1 });
    return;
  }
  await touchNote(id, patch);
}

/**
 * Move a note to the trash. Does NOT delete it on the server - the note
 * is just flagged `trashed=1` and the flag is synced across devices.
 */
export async function trashNote(id: string): Promise<void> {
  await touchNote(id, { trashed: 1 });
}

/** Restore a trashed note. */
export async function restoreNote(id: string): Promise<void> {
  await touchNote(id, { trashed: 0 });
}

/**
 * Permanently delete a single note. Sets the `deleted=1` tombstone so
 * the next sync removes it from the server and then purges it locally.
 */
export async function permanentlyDelete(id: string): Promise<void> {
  await touchNote(id, { deleted: 1 });
  // Drop the parsed-doc cache row (#150) - stale rows are harmless (exact
  // body match) but a big note's row is ~3x its body in disk.
  await db.editorDocCache.delete(id).catch(() => { /* best-effort */ });
}

/** Hard-delete every trashed note. Used by the "Empty trash" button.
 *  Wrapped in a single Dexie transaction so a force-close mid-way
 *  can't leave the trash half-emptied (all-or-nothing). (#91) */
export async function emptyTrash(): Promise<number> {
  const trashed = await db.notes
    .where('trashed')
    .equals(1)
    .and((n) => n.deleted === 0)
    .toArray();
  if (trashed.length === 0) return 0;
  await db.transaction('rw', db.notes, async () => {
    for (const n of trashed) {
      await db.notes.update(n.id, { deleted: 1, updatedAt: nextStamp(n.updatedAt), dirty: 1 });
    }
  });
  // Same parsed-doc cache cleanup as permanentlyDelete (#150); outside the
  // transaction on purpose - cache rows are disposable, note tombstones are not.
  await db.editorDocCache.bulkDelete(trashed.map((n) => n.id)).catch(() => { /* best-effort */ });
  return trashed.length;
}

/**
 * Create a copy of an existing note - same body, tags, and starred flag,
 * new id and fresh timestamps. The copy's title is suffixed with
 * "(copy)" so it's easy to spot in the list. Returns the new note so the
 * caller can select it immediately.
 */
export async function duplicateNote(id: string): Promise<LocalNote | null> {
  const src = await db.notes.get(id);
  if (!src || src.deleted === 1) return null;
  const now = new Date().toISOString();
  const baseTitle = (src.title ?? '').trim();
  const newTitle = baseTitle ? `${baseTitle} (copy)` : '';
  const copy: LocalNote = {
    id: crypto.randomUUID(),
    title: newTitle,
    body: src.body,
    tags: [...src.tags],
    createdAt: now,
    updatedAt: now,
    dirty: 1,
    deleted: 0,
    trashed: 0,
    starred: src.starred,
    // Carry over pinProtected so sensitive data doesn't leak into
    // an unprotected copy. Read-only flag is NOT carried
    // over: the user is about to edit the duplicate.
    locked: 0,
    pinProtected: src.pinProtected,
    type: src.type ?? 'note',
    // The duplicate stays in the source note's folder.
    folderId: src.folderId ?? null,
    // Deep-copy tracker data so journal duplicates preserve mood/sleep/etc.
    ...(src.trackers ? { trackers: structuredClone(src.trackers) } : {}),
  };
  await db.notes.put(copy);
  return copy;
}

/** Toggle or set the starred flag on a note. */
export async function setStarred(id: string, starred: boolean): Promise<void> {
  await touchNote(id, { starred: starred ? 1 : 0 });
}

/**
 * Pro: move several notes into a folder in one transaction. Used by
 * folder deletion (reparent contents) and the bulk toolbar
 * (fast-follow). Returns the number of notes modified.
 */
export async function bulkMoveToFolder(ids: string[], folderId: string | null): Promise<number> {
  if (ids.length === 0) return 0;
  let count = 0;
  await db.transaction('rw', db.notes, async () => {
    for (const id of ids) {
      const note = await db.notes.get(id);
      if (!note) continue;
      await db.notes.update(id, { folderId, updatedAt: nextStamp(note.updatedAt), dirty: 1 });
      count++;
    }
  });
  return count;
}

/**
 * Pro: toggle the "read-only" flag. Editor treats locked=1 as
 * read-only. The flag is encrypted in the payload and
 * syncs like any other per-note bit.
 */
export async function setLocked(id: string, locked: boolean): Promise<void> {
  await touchNote(id, { locked: locked ? 1 : 0 });
}

/**
 * Pro: toggle the "PIN-protect" flag. Opening a protected note
 * requires a PIN unlock (shared with the phrase view via the
 * sessionStorage unlock timer + user-configurable timeout).
 */
export async function setPinProtected(
  id: string,
  pinProtected: boolean
): Promise<void> {
  await touchNote(id, { pinProtected: pinProtected ? 1 : 0 });
}

/**
 * Bulk variants for the multi-select toolbar. Each runs inside a single
 * Dexie transaction so the UI sees one consistent post-state (and sync
 * pushes one batch of dirty rows rather than N sequential updates).
 */
export async function bulkTrash(ids: string[]): Promise<number> {
  if (ids.length === 0) return 0;
  let count = 0;
  await db.transaction('rw', db.notes, async () => {
    for (const id of ids) {
      const note = await db.notes.get(id);
      if (!note) continue;
      // A read-only note stays out of the trash. The callers filter first,
      // because only they can say how many items were skipped, but the
      // check belongs to the write rather than to one route into it.
      if (note.locked === 1) continue;
      await db.notes.update(id, { trashed: 1, updatedAt: nextStamp(note.updatedAt), dirty: 1 });
      count++;
    }
  });
  return count;
}

export async function bulkRestore(ids: string[]): Promise<number> {
  if (ids.length === 0) return 0;
  let count = 0;
  await db.transaction('rw', db.notes, async () => {
    for (const id of ids) {
      const note = await db.notes.get(id);
      if (!note) continue;
      await db.notes.update(id, { trashed: 0, updatedAt: nextStamp(note.updatedAt), dirty: 1 });
      count++;
    }
  });
  return count;
}

export async function bulkPermanentlyDelete(ids: string[]): Promise<number> {
  if (ids.length === 0) return 0;
  let count = 0;
  await db.transaction('rw', db.notes, async () => {
    for (const id of ids) {
      const note = await db.notes.get(id);
      if (!note) continue;
      await db.notes.update(id, { deleted: 1, updatedAt: nextStamp(note.updatedAt), dirty: 1 });
      count++;
    }
  });
  return count;
}

/**
 * Set the read-only flag on every id. The caller decides the target: the
 * menus turn a selection off only when every item in it is already on,
 * which is the same rule the pin toggle follows.
 */
export async function bulkSetLocked(ids: string[], locked: boolean): Promise<number> {
  if (ids.length === 0) return 0;
  const value: 0 | 1 = locked ? 1 : 0;
  let count = 0;
  await db.transaction('rw', db.notes, async () => {
    for (const id of ids) {
      const note = await db.notes.get(id);
      if (!note) continue;
      await db.notes.update(id, { locked: value, updatedAt: nextStamp(note.updatedAt), dirty: 1 });
      count++;
    }
  });
  return count;
}

/**
 * Set the PIN-protect flag on every id. Both directions are gated before
 * this runs: turning protection on needs a PIN to exist, and taking it
 * off needs the PIN entered, the same bar a single note asks for.
 */
export async function bulkSetPinProtected(ids: string[], pinProtected: boolean): Promise<number> {
  if (ids.length === 0) return 0;
  const value: 0 | 1 = pinProtected ? 1 : 0;
  let count = 0;
  await db.transaction('rw', db.notes, async () => {
    for (const id of ids) {
      const note = await db.notes.get(id);
      if (!note) continue;
      await db.notes.update(id, { pinProtected: value, updatedAt: nextStamp(note.updatedAt), dirty: 1 });
      count++;
    }
  });
  return count;
}

/** Duplicate every id through the single-note path, so a copy made from a
 *  selection is the same copy the per-note action makes. */
export async function bulkDuplicate(ids: string[]): Promise<number> {
  let count = 0;
  for (const id of ids) {
    if (await duplicateNote(id)) count++;
  }
  return count;
}

/**
 * Set starred on every id. If any id in the set is currently unstarred
 * we star them all; only when every id is already starred do we unstar.
 * Caller decides the target value - this just applies it.
 */
export async function bulkSetStarred(ids: string[], starred: boolean): Promise<number> {
  if (ids.length === 0) return 0;
  const value: 0 | 1 = starred ? 1 : 0;
  let count = 0;
  await db.transaction('rw', db.notes, async () => {
    for (const id of ids) {
      const note = await db.notes.get(id);
      if (!note) continue;
      await db.notes.update(id, { starred: value, updatedAt: nextStamp(note.updatedAt), dirty: 1 });
      count++;
    }
  });
  return count;
}

/**
 * Write a new body to each note in `updates`, in ONE transaction.
 *
 * The rename pass (`useNoteEditing.handleTitleBlur`) is the caller: pointing
 * note-links at a renamed note can touch many notes at once, and a separate
 * `updateNote` per note is a separate transaction per note. Same shape and
 * same reasoning as the bulk helpers above. Returns the number written.
 */
export async function bulkSetBody(
  updates: Array<{ id: string; body: string }>,
): Promise<number> {
  if (updates.length === 0) return 0;
  void requestPersistence();
  let count = 0;
  await db.transaction('rw', db.notes, async () => {
    for (const { id, body } of updates) {
      const note = await db.notes.get(id);
      if (!note) continue;
      await db.notes.update(id, {
        body,
        updatedAt: nextStamp(note.updatedAt),
        dirty: 1,
      });
      count++;
    }
  });
  return count;
}

/**
 * Add a tag to every note in `ids` (idempotent - skips notes that
 * already have the tag). Returns the number of notes actually modified.
 */
export async function bulkAddTag(ids: string[], tag: string): Promise<number> {
  if (ids.length === 0 || !tag) return 0;
  const lower = tag.toLowerCase();
  let count = 0;
  await db.transaction('rw', db.notes, async () => {
    for (const id of ids) {
      const note = await db.notes.get(id);
      if (!note) continue;
      if (note.tags.some((t) => t.toLowerCase() === lower)) continue;
      await db.notes.update(id, {
        tags: [...note.tags, tag],
        updatedAt: nextStamp(note.updatedAt),
        dirty: 1,
      });
      count++;
    }
  });
  return count;
}

/**
 * Rename a tag across every note that carries it. If the target slug
 * is already present on a note, the rename degenerates into a remove
 * for that note (we don't want duplicate slugs in a single note's
 * `tags` array - set semantics). If the target slug ALREADY EXISTS as
 * a separate tag in the user's vault, this acts as a merge: all notes
 * previously tagged `oldTag` end up tagged `newTag` instead.
 *
 * Each touched note's `updatedAt` bumps and `dirty` gets set so the
 * next sync pushes the change to the server like any other edit.
 *
 * Returns the number of notes modified.
 */
export async function renameTagEverywhere(
  oldTag: string,
  newTag: string
): Promise<number> {
  let modifiedCount = 0;
  // Full table scan + filter in JS: `tags` isn't a multi-entry index
  // on the Dexie store, and we'd rather not bump the schema version
  // just for this. Hundreds of notes is instant in practice.
  await db.transaction('rw', db.notes, async () => {
    const all = await db.notes.toArray();
    for (const note of all) {
      if (!note.tags.includes(oldTag)) continue;
      const nextTags: string[] = [];
      for (const t of note.tags) {
        if (t === oldTag) {
          // Collapse into the target slug, avoiding duplicates.
          if (!nextTags.includes(newTag)) nextTags.push(newTag);
        } else if (!nextTags.includes(t)) {
          nextTags.push(t);
        }
      }
      await db.notes.update(note.id, {
        tags: nextTags,
        updatedAt: nextStamp(note.updatedAt),
        dirty: 1,
      });
      modifiedCount++;
    }
  });
  return modifiedCount;
}

/**
 * Trash every active (non-trashed, non-deleted) note that carries the
 * given tag. Used by the "Delete tag and notes" action in the tag menu.
 * A read-only note keeps the tag and stays where it is.
 * Returns the number of notes sent to trash.
 */
export async function trashNotesWithTag(tag: string): Promise<number> {
  let trashedCount = 0;
  await db.transaction('rw', db.notes, async () => {
    const all = await db.notes.toArray();
    for (const note of all) {
      if (note.deleted === 1 || note.trashed === 1) continue;
      if (note.locked === 1) continue;
      if (!note.tags.includes(tag)) continue;
      await db.notes.update(note.id, {
        trashed: 1,
        updatedAt: nextStamp(note.updatedAt),
        dirty: 1,
      });
      trashedCount++;
    }
  });
  return trashedCount;
}

/**
 * Strip a tag from every note that carries it. Does NOT trash or
 * delete the notes themselves - they remain, just with one fewer
 * tag. Returns the number of notes modified.
 */
export async function deleteTagEverywhere(tag: string): Promise<number> {
  let modifiedCount = 0;
  await db.transaction('rw', db.notes, async () => {
    const all = await db.notes.toArray();
    for (const note of all) {
      if (!note.tags.includes(tag)) continue;
      const nextTags = note.tags.filter((t) => t !== tag);
      await db.notes.update(note.id, {
        tags: nextTags,
        updatedAt: nextStamp(note.updatedAt),
        dirty: 1,
      });
      modifiedCount++;
    }
  });
  return modifiedCount;
}

/**
 * Wipe the notes table plus the decrypted blob caches that ride
 * alongside it. Used on sign-out and on pubkey-mismatch sign-in.
 *
 * Clears each table in place rather than calling db.delete() so the
 * Dexie instance stays usable - no reopen, no reload required. The
 * schema and version pointer survive.
 *
 * Cache tables (imageCache, attachmentCache, *Dedup) are wiped
 * because they carry the prior session's blobs and content hashes.
 * The blob bytes seal at rest, and rows written before the seal stay
 * plaintext until the sweep converts them, but either way they are
 * the prior account's data: leaving them also lets
 * processPendingUploads on the next sign-in re-encrypt cached blobs
 * under the new user's key (cross-account leak).
 */
export async function clearLocalDatabase(opts?: { keepUnsyncedNotes?: boolean }): Promise<void> {
  if (opts?.keepUnsyncedNotes) {
    // Forced sign-outs (device revoked, session expired) preserve rows
    // the server has not confirmed (either dirty value, pending
    // tombstones included): they exist nowhere else, so clearing them is
    // permanent data loss the user never chose. A same-pubkey
    // re-sign-in keeps them (the pubkey-owner check skips the mismatch
    // wipe) and the next sync pushes them; a different user signing in
    // still wipes them via the owner-mismatch path in auth.tsx.
    // Keys-only deletion, deliberately: this wipe runs AFTER sign-out
    // zeroes the local data key, and streaming row VALUES through the
    // seal middleware would throw on any sealed row. Index reads,
    // primaryKeys() and bulkDelete never touch values. Both dirty
    // values are unsynced data (2 = sealed, invisible to old bundles).
    // Spec: ops/docs/plans/local-at-rest.md (3.3, the key-free wipe)
    const allNoteIds = await db.notes.toCollection().primaryKeys();
    const keepNotes = new Set(await db.notes.where('dirty').anyOf(1, 2).primaryKeys());
    await db.notes.bulkDelete(allNoteIds.filter((id) => !keepNotes.has(id)));
    // Blobs that never reached the server (pendingUpload=1) are the
    // same class of data. Keep the dedup record AND its cached bytes
    // together - processPendingUploads needs both to finish the upload
    // after the same user signs back in (a dedup row without bytes is
    // deleted as an orphan on init, losing the blob). Everything the
    // server already has is wiped as usual. The dedup tables are never
    // sealed, so value filters are safe THERE; the cache tables are
    // deleted by key for the same reason as the notes above.
    const pendingImg = await db.imageDedup.filter((r) => r.pendingUpload === 1).toArray();
    const keepImg = new Set(pendingImg.map((r) => r.uuid));
    const imgIds = await db.imageCache.toCollection().primaryKeys();
    await db.imageCache.bulkDelete(imgIds.filter((id) => !keepImg.has(id)));
    await db.imageDedup.filter((r) => r.pendingUpload !== 1).delete();
    const pendingAtt = await db.attachmentDedup.filter((r) => r.pendingUpload === 1).toArray();
    const keepAtt = new Set(pendingAtt.map((r) => r.uuid));
    const attIds = await db.attachmentCache.toCollection().primaryKeys();
    await db.attachmentCache.bulkDelete(attIds.filter((id) => !keepAtt.has(id)));
    await db.attachmentDedup.filter((r) => r.pendingUpload !== 1).delete();
    // The parsed-doc cache holds note bodies (sealed at rest like the
    // notes) and is rebuildable derived data - clear it on every
    // sign-out, kept dirty rows included (they re-cache on next open).
    await db.editorDocCache.clear();
    // blobGC has no pendingUpload concept - every queue entry is
    // deferred-deletion metadata for a blob already gone from the note
    // body, never something a resuming same-user sign-in needs to
    // finish uploading. Clear it unconditionally like the wipe below.
    await db.blobGC.clear();
    // Favicons are derived, never unsynced user data, so a forced sign-out
    // clears them like any other sign-out.
    await clearFaviconCache();
    return;
  }
  await db.notes.clear();
  await db.imageCache.clear();
  await db.imageDedup.clear();
  await db.attachmentCache.clear();
  await db.attachmentDedup.clear();
  await db.blobGC.clear();
  await db.editorDocCache.clear();
  // The favicon cache is a separate IndexedDB, so it is not covered by any
  // db.*.clear() above. It holds a per-domain record derived from the user's
  // links, so it must go on sign-out too. See clearFaviconCache.
  await clearFaviconCache();
}

/** Count of local rows with unsynced changes (either dirty value),
 * pending tombstones included. Sign-out uses this to decide how hard
 * to try flushing before the wipe. */
export async function countUnsyncedNotes(): Promise<number> {
  return db.notes.where('dirty').anyOf(1, 2).count();
}

/**
 * Nuclear wipe: delete the entire IndexedDB database (all tables -
 * notes, imageCache, imageDedup, attachmentCache, attachmentDedup).
 * Used for account deletion. After this, the Dexie instance is dead
 * and the page must reload.
 */
export async function deleteEntireLocalDatabase(): Promise<void> {
  // db.delete() drops the Dexie database only; the favicon cache is its own
  // IndexedDB and would outlive account deletion by up to 90 days without this.
  await clearFaviconCache();
  await db.delete();
}
