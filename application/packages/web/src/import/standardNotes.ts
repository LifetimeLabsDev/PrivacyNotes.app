import JSZip from 'jszip';
import { normalizeTag } from '../notesRepo';
import { linkifyMarkdown } from './linkify';
import { ARCHIVED_TAG } from './types';
import type { Importer, ImportedNote, ParsedImport } from './types';

/**
 * Standard Notes import adapter.
 *
 * Reads Standard Notes' "decrypted data backup" format. Two accepted
 * shapes:
 *   (a) The official .zip export - contains a file named
 *       "Standard Notes Backup and Import File.txt" at the root.
 *   (b) That .txt file on its own - users sometimes unzip manually and
 *       just grab the JSON.
 *
 * Encrypted backups are NOT supported yet. Standard Notes also lets you
 * export "encrypted" which is per-item E2E ciphertext that needs the
 * user's SN password + keyParams to decrypt. We can add that later if
 * anyone asks - for V1, we tell them to re-export as "decrypted".
 * Detecting them is not optional: an encrypted backup is still valid
 * JSON with an items array, so without the isEncryptedBackup() guard it
 * imports as a pile of blank notes rather than failing.
 *
 * Flag mapping → PrivacyNotes:
 *   - pinned   → starred (SN has no separate "favorite")
 *   - trashed  → trashed
 *   - archived → active + `archived` tag (no archive view yet, and the
 *                trash auto-purges, so trashing them would delete them)
 *   - noteType "task" → our 'task' note type, body rewritten to `- [ ]`
 *
 * Format reference (version 004):
 *   {
 *     version: "004",
 *     items: [
 *       {
 *         content_type: "Note" | "Tag" | "SN|UserPreferences" | "SN|Component" | ...
 *         content: { title, text, noteType, references, ... },
 *         created_at: "2024-...",
 *         updated_at: "2024-...",
 *         deleted: false,
 *         uuid: "...",
 *       },
 *       ...
 *     ]
 *   }
 *
 * Tags carry their note membership as references:
 *   tag.content.references = [{ uuid: <noteUuid>, content_type: "Note" }, ...]
 * so we build a noteId → tagTitles map in one pass, then emit notes.
 */

// Standard Notes export schema shapes - intentionally loose, the backup
// format has a few optional/varying fields between SN releases.
interface SnItem {
  content_type: string;
  /** An encrypted export puts a "004:<nonce>:<ciphertext>…" string here
   *  instead of the object. parse() rejects those up front. */
  content?: SnContent | string | null;
  created_at?: string;
  updated_at?: string;
  deleted?: boolean;
  uuid?: string;
}
interface SnContent {
  title?: string;
  text?: string;
  /** "plain-text" | "task" | "super" | "code" | … */
  noteType?: string;
  /** e.g. "com.standardnotes.task-editor" - the only signal on older exports. */
  editorIdentifier?: string;
  references?: Array<{ uuid: string; content_type: string }>;
  /**
   * Top-level pinned/trashed flags. Newer SN versions write these
   * directly on content; older versions bury them under appData. We
   * check both (see readPinned/readTrashed below).
   */
  pinned?: boolean;
  trashed?: boolean;
  /**
   * SN's appData bucket. Per-app JSON namespaced by a reverse-DNS key
   * - the first-party note metadata lives under
   * "org.standardnotes.sn" with fields like pinned, trashed, archived,
   * locked, prefersPlainEditor, etc.
   */
  appData?: {
    'org.standardnotes.sn'?: {
      pinned?: boolean;
      trashed?: boolean;
      archived?: boolean;
      locked?: boolean;
      /** When the user last edited the note - see readUpdatedAt below. */
      client_updated_at?: string;
    };
  };
}
interface SnBackup {
  version?: string;
  items: SnItem[];
  /** Present only on encrypted exports, alongside per-item ciphertext. */
  auth_params?: unknown;
  keyParams?: unknown;
}

const BACKUP_FILENAME = 'Standard Notes Backup and Import File.txt';

export const standardNotesImporter: Importer = {
  id: 'standard-notes',
  label: 'Standard Notes',
  description:
    'Decrypted .zip or .txt backup from Standard Notes (File → Export → Decrypted).',
  accept: '.zip,.txt,application/zip,text/plain',
  enabled: true,
  sourceTag: 'standardnotes',

  async parse(file, onProgress) {
    onProgress?.('Reading file…');
    const jsonText = await extractBackupJson(file, onProgress);

    onProgress?.('Parsing JSON…');
    let backup: SnBackup;
    try {
      backup = JSON.parse(jsonText) as SnBackup;
    } catch (err) {
      throw new Error(
        'That file is not valid JSON. Make sure you exported as "Decrypted", not "Encrypted".'
      );
    }

    if (!backup || !Array.isArray(backup.items)) {
      throw new Error(
        'That file is missing the expected "items" array. Not a Standard Notes backup.'
      );
    }

    // An encrypted export is still valid JSON with a version and an
    // items array, so it sails past both checks above. The difference is
    // that every item's `content` is a ciphertext string rather than an
    // object, and reading .title/.text off a string yields undefined for
    // both, so an encrypted export imports as a pile of blank untitled
    // notes with no error at all. Reject it and say what to do instead.
    if (isEncryptedBackup(backup)) {
      throw new Error(
        'That backup is encrypted. In Standard Notes, export again and pick "Decrypted" - we never receive your Standard Notes password, so we cannot unlock this file.'
      );
    }

    const warnings: string[] = [];
    if (backup.version && backup.version !== '004') {
      warnings.push(
        `Unexpected backup format version "${backup.version}" (expected "004"). Parsing anyway.`
      );
    }

    onProgress?.('Mapping tags…');
    const noteIdToTags = buildTagIndex(backup.items);

    onProgress?.('Building notes…');
    const notes: ImportedNote[] = [];
    let emptyCount = 0;
    let untaggedCount = 0;
    let missingTitleCount = 0;
    let linkifiedCount = 0;
    let starredCount = 0;
    let trashedImportCount = 0;
    let archivedTaggedCount = 0;
    let checklistCount = 0;
    let checklistFailedCount = 0;

    for (const item of backup.items) {
      if (item.content_type !== 'Note') continue;
      // `item.deleted === true` in the SN backup means "permanently
      // deleted, kept as a tombstone for sync" - we skip those, they
      // are not recoverable notes. Soft-deleted notes ("moved to
      // trash") show up as normal notes with content.trashed = true.
      if (item.deleted) continue;

      const c = contentOf(item);
      const rawTitle = (c.title ?? '').trim();
      const rawBody = c.text ?? '';
      const rawTags = item.uuid ? (noteIdToTags.get(item.uuid) ?? []) : [];

      // Pinned in Standard Notes = starred in PrivacyNotes. SN doesn't
      // have a separate "favorite", and pinned is the closest flag -
      // it's the "this note matters" bit. Read top-level first, fall
      // back to the appData bucket for older exports.
      const snMeta = c.appData?.['org.standardnotes.sn'] ?? {};
      const pinned = c.pinned === true || snMeta.pinned === true;
      const trashed = c.trashed === true || snMeta.trashed === true;
      // Archived is a separate concept in SN: out of sight, but kept on
      // purpose. PrivacyNotes has no archive view, and routing these to
      // the trash would hand them straight to the auto-purge, which
      // permanently deletes anything that outlives the retention window
      // - so "archive" would quietly mean "delete in 30 days". Import
      // them as ordinary notes carrying an `archived` tag instead:
      // nothing is destroyed, and the tag gives a one-click filter that
      // behaves like the archive they came from.
      const archived = snMeta.archived === true;

      if (!rawTitle) missingTitleCount++;
      if (!rawBody.trim()) emptyCount++;
      if (rawTags.length === 0) untaggedCount++;
      if (pinned) starredCount++;
      if (trashed) trashedImportCount++;
      if (archived) archivedTaggedCount++;

      // SN checklists store their items as a JSON blob in the note text,
      // which would otherwise import as an unreadable wall of JSON.
      // Convert it to the `- [ ]` / `- [x]` markdown our Tasks pillar
      // parses, and type the note 'task' so it lands there.
      const checklist = isChecklistNote(c) ? snChecklistToMarkdown(rawBody) : null;
      if (isChecklistNote(c)) {
        if (checklist) checklistCount++;
        else checklistFailedCount++;
      }

      // Pre-wrap bare URLs in <...> autolink syntax so they load as
      // clickable links on first render, not after the user presses
      // Enter next to each one.
      //
      // Checklists go through it too. They used to be skipped on the
      // grounds that "converted checklists are ours, not user prose",
      // which is only half true: the `- [ ]` scaffolding is ours, but
      // every task description inside it was typed by the user and is
      // exactly as likely to hold a URL as any other note. Linkifying
      // the converted markdown is safe - the scaffolding carries no URLs
      // of its own, and the pass already skips code spans and existing
      // links. Caught in the v0.300.0 importer audit.
      const source = checklist ?? rawBody;
      const body = linkifyMarkdown(source);
      if (body !== source) linkifiedCount++;

      notes.push({
        // Pass title through verbatim - including empty. Standard Notes
        // leaves the title field empty when the user never set one, and
        // fabricating "Untitled" here would look like a real user-set
        // title and mask the live first-line derivation that handles
        // titleless notes everywhere else. An empty source title stays
        // empty and the derivation in NotesView does its job.
        title: rawTitle,
        body,
        tags: normalizeTagList(archived ? [...rawTags, ARCHIVED_TAG] : rawTags),
        createdAt: isoOrNow(item.created_at),
        // SN's item-level `updated_at` is the SERVER's sync timestamp -
        // it moves whenever the item is re-synced, including for
        // metadata-only changes like being added to a tag. The date SN's
        // own UI shows as "modified" is appData's client_updated_at, i.e.
        // when the user actually last edited the note. Prefer that and
        // fall back to the server value for pre-2019 exports that predate
        // the field.
        updatedAt: isoOrNow(
          snMeta.client_updated_at ?? item.updated_at ?? item.created_at
        ),
        starred: pinned,
        trashed,
        ...(checklist ? { type: 'task' as const } : {}),
      });
    }

    const transforms: string[] = [];
    if (linkifiedCount > 0) {
      transforms.push(
        `Made URLs clickable in ${linkifiedCount} note${linkifiedCount === 1 ? '' : 's'}.`
      );
    }
    if (starredCount > 0) {
      transforms.push(
        `Kept ${starredCount} pinned note${starredCount === 1 ? '' : 's'} as starred.`
      );
    }
    if (trashedImportCount > 0) {
      transforms.push(
        `Restored ${trashedImportCount} trashed note${trashedImportCount === 1 ? '' : 's'} into the trash.`
      );
    }
    if (archivedTaggedCount > 0) {
      transforms.push(
        `Tagged ${archivedTaggedCount} archived note${archivedTaggedCount === 1 ? '' : 's'} "${ARCHIVED_TAG}" and kept ${archivedTaggedCount === 1 ? 'it' : 'them'} out of the trash.`
      );
    }
    if (checklistCount > 0) {
      transforms.push(
        `Converted ${checklistCount} checklist${checklistCount === 1 ? '' : 's'} into tasks you can tick off.`
      );
    }

    if (checklistFailedCount > 0) {
      warnings.push(
        `${checklistFailedCount} checklist${checklistFailedCount === 1 ? '' : 's'} used a format we don't recognize. ${checklistFailedCount === 1 ? 'It was' : 'They were'} imported as plain text so nothing is lost.`
      );
    }

    if (missingTitleCount > 0) {
      warnings.push(
        `${missingTitleCount} note${missingTitleCount === 1 ? '' : 's'} had no title. A title will be derived from the first line.`
      );
    }

    const uniqueTags = new Set<string>();
    for (const n of notes) for (const t of n.tags) uniqueTags.add(t);

    const parsed: ParsedImport = {
      notes,
      warnings,
      transforms,
      stats: {
        totalNotes: notes.length,
        emptyNotes: emptyCount,
        untaggedNotes: untaggedCount,
        uniqueTags: uniqueTags.size,
      },
      source: 'standard-notes',
    };
    return parsed;
  },
};

/**
 * Get the JSON payload out of a file the user gave us. Supports:
 *   - .zip containing "Standard Notes Backup and Import File.txt"
 *   - that .txt file on its own
 *   - any .json file whose content smells like an SN backup
 */
async function extractBackupJson(
  file: File,
  onProgress?: (m: string) => void
): Promise<string> {
  const lowerName = file.name.toLowerCase();

  if (lowerName.endsWith('.zip')) {
    onProgress?.('Unzipping…');
    const zip = await JSZip.loadAsync(file);
    // Prefer the exact filename, but fall back to any .txt at the root
    // in case SN renames it in a future version.
    let entry = zip.file(BACKUP_FILENAME);
    if (!entry) {
      const candidates = Object.values(zip.files).filter(
        (f) =>
          !f.dir &&
          !f.name.includes('/') &&
          f.name.toLowerCase().endsWith('.txt')
      );
      if (candidates.length === 1) entry = candidates[0]!;
    }
    if (!entry) {
      throw new Error(
        `This zip doesn't contain a "${BACKUP_FILENAME}" file. Make sure you picked the Standard Notes export zip.`
      );
    }
    return entry.async('string');
  }

  // .txt or .json or anything else - read as text and hope for the best.
  return file.text();
}

/**
 * True if SN considered this note a checklist. Newer exports set
 * noteType; older ones only carry the editor id.
 */
function isChecklistNote(c: SnContent): boolean {
  if (c.noteType === 'task') return true;
  return (c.editorIdentifier ?? '').includes('task-editor');
}

/**
 * Convert an SN checklist body into `- [ ]` / `- [x]` markdown, which is
 * what our Tasks pillar parses out of a note body (see tasks.ts).
 *
 * The checklist editor stores its items as JSON in the note text:
 *   { schemaVersion, groups: [{ name, tasks: [{ description, completed }] }] }
 *
 * Returns null when the body is not that shape - the legacy "Simple Task
 * Editor" used a different encoding, and a checklist we cannot read is
 * far better left verbatim than rewritten into something wrong. Callers
 * fall back to the raw text and warn.
 */
function snChecklistToMarkdown(rawBody: string): string | null {
  const text = rawBody.trim();
  if (!text.startsWith('{')) return null;

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }

  const groups = (parsed as { groups?: unknown })?.groups;
  if (!Array.isArray(groups) || groups.length === 0) return null;

  const blocks: string[] = [];
  for (const group of groups) {
    const tasks = (group as { tasks?: unknown })?.tasks;
    if (!Array.isArray(tasks)) return null;

    const lines: string[] = [];
    for (const task of tasks) {
      const t = task as { description?: unknown; completed?: unknown };
      if (typeof t?.description !== 'string') return null;
      // Keep each item on one line - a description with newlines would
      // otherwise break out of its checkbox and become loose paragraphs.
      const desc = t.description.replace(/\s*\r?\n\s*/g, ' ').trim();
      lines.push(`- [${t.completed === true ? 'x' : ' '}] ${desc}`);
    }
    if (lines.length === 0) continue;

    // Only label groups when there is more than one - a single group is
    // the ordinary "flat checklist" case and the note title already
    // names it.
    const name =
      typeof (group as { name?: unknown }).name === 'string'
        ? (group as { name: string }).name.trim()
        : '';
    blocks.push(groups.length > 1 && name ? `## ${name}\n${lines.join('\n')}` : lines.join('\n'));
  }

  return blocks.length > 0 ? blocks.join('\n\n') : null;
}

/**
 * True if this is an encrypted export rather than a decrypted one.
 * Encrypted backups carry the key derivation params at the top level and
 * a ciphertext string in place of every item's content object.
 */
function isEncryptedBackup(backup: SnBackup): boolean {
  if (backup.auth_params || backup.keyParams) return true;
  return backup.items.some((i) => typeof i.content === 'string');
}

/**
 * Read an item's content object. parse() rejects encrypted backups up
 * front, so the string case here only exists to satisfy the type checker
 * and to keep a malformed item from taking the whole import down.
 */
function contentOf(item: SnItem): SnContent {
  return typeof item.content === 'object' && item.content !== null
    ? item.content
    : {};
}

/**
 * Walk all Tag items once and build a Map<noteUuid, tagTitles[]>. Tags
 * in the SN 004 format carry their note membership as content.references
 * entries with content_type: "Note".
 *
 * Standard Notes also supports nested tags in newer app versions, but
 * they show up as a flat list in the export - parent membership is
 * encoded via content.references where content_type: "Tag", which we
 * ignore for now. Every tag we see becomes a flat top-level tag in
 * PrivacyNotes.
 */
function buildTagIndex(items: SnItem[]): Map<string, string[]> {
  const map = new Map<string, string[]>();
  for (const item of items) {
    if (item.content_type !== 'Tag') continue;
    if (item.deleted) continue;
    const c = contentOf(item);
    const title = (c.title ?? '').trim();
    if (!title) continue;
    const refs = c.references ?? [];
    for (const ref of refs) {
      if (ref.content_type !== 'Note') continue;
      const arr = map.get(ref.uuid) ?? [];
      arr.push(title);
      map.set(ref.uuid, arr);
    }
  }
  return map;
}

/**
 * Normalize imported Standard Notes tags. normalizeTag() preserves case
 * and allows spaces/dots/@/etc., so this is a pass-through with
 * case-insensitive dedup so "Dev" and "dev" don't create two tags.
 */
function normalizeTagList(rawTags: string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of rawTags) {
    const tag = normalizeTag(raw);
    if (!tag) continue;
    const key = tag.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(tag);
  }
  return out;
}

function isoOrNow(s: string | undefined): string {
  if (!s) return new Date().toISOString();
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return new Date().toISOString();
  return d.toISOString();
}
