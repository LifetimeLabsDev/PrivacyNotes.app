import JSZip from 'jszip';
import { zipEntryText } from './zipEntry';
import { normalizeTag, TAG_MAX_LENGTH } from '../notesRepo';
import { createFolder, type FolderDef } from '../folders';
import { IMPORT_FOLDER_LIMIT } from './folderImport';
import { linkifyMarkdown } from './linkify';
import type { Importer, ImportBlob, ImportedNote, ParsedImport } from './types';
import { superToMarkdown, type SnLinkedItem } from './standardNotesSuper';
import { htmlNoteToMarkdown } from './notesnook';
import { serializeLoginBody } from '../LoginForm';

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
 *   - pinned, starred → starred
 *   - trashed  → trashed
 *   - archived → archived
 *   - locked   → locked (read-only)
 * Newer SN versions write these flags on `content`, older ones under
 * `content.appData["org.standardnotes.sn"]`; both are read.
 *
 * Note types, by `noteType`, or by `editorIdentifier` on older exports:
 *   - super          → markdown (standardNotesSuper.ts)
 *   - task           → our 'task' note type, body rewritten to `- [ ]`
 *   - code           → one fenced block in the language the editor chose
 *   - spreadsheet    → a pipe table per sheet
 *   - authentication → one Vault login per entry, the note itself dropped
 *   - rich-text      → markdown, through the Notesnook HTML converter
 *   - markdown, plain-text and anything unknown → the text as it is
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
 * and a nested tag carries its parent the same way, as a Tag reference
 * (`reference_type: "TagToParentTag"` on newer exports).
 *
 * Nested tags become BOTH: a folder tree, and full-path tags ("Work/Projects").
 * A note lands in the folder of its deepest nested tag, and keeps every tag.
 * A tag with no parent and no children stays a tag only, so a flat tag list
 * does not turn into a wall of folders. A path longer than a tag name may
 * be keeps the tag's own name; its folder still holds the full path.
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
  /** "plain-text" | "markdown" | "super" | "task" | "code" | "spreadsheet" | "authentication" | "rich-text" */
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
  archived?: boolean;
  starred?: boolean;
  locked?: boolean;
  /** An `SN|File` item's file name. */
  name?: string;
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
    /** Per-editor data, keyed by the editor; the code editor keeps `mode` here. */
    'org.standardnotes.sn.components'?: Record<string, unknown>;
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
    const tagIndex = buildTagIndex(backup.items);
    const noteIdToTags = tagIndex.noteTags;
    const linkedItems = buildItemIndex(backup.items);
    const blobs = new Map<string, ImportBlob>();

    onProgress?.('Building notes…');
    const notes: ImportedNote[] = [];
    let emptyCount = 0;
    let untaggedCount = 0;
    let missingTitleCount = 0;
    let linkifiedCount = 0;
    let starredCount = 0;
    let trashedImportCount = 0;
    let archivedCount = 0;
    let lockedCount = 0;
    let checklistCount = 0;
    let checklistFailedCount = 0;
    let superCount = 0;
    let superFailedCount = 0;
    let missingFileCount = 0;
    let codeCount = 0;
    let sheetCount = 0;
    let sheetFailedCount = 0;
    let richTextCount = 0;
    let authEntryCount = 0;
    let authFailedCount = 0;

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
      const noteTagIds = item.uuid ? (noteIdToTags.get(item.uuid) ?? []) : [];
      const rawTags = noteTagIds.map((id) => tagIndex.tagName.get(id)!);
      const folder = pickFolder(noteTagIds, tagIndex);

      // Pinned in Standard Notes = starred in PrivacyNotes, and so is SN's
      // own starred flag: both are the "this note matters" bit. Every flag
      // is read off content first and off the appData bucket second, where
      // older exports keep it.
      const snMeta = c.appData?.['org.standardnotes.sn'] ?? {};
      const pinned = c.pinned === true || snMeta.pinned === true || c.starred === true;
      const trashed = c.trashed === true || snMeta.trashed === true;
      const archived = c.archived === true || snMeta.archived === true;
      const locked = c.locked === true || snMeta.locked === true;
      const tagsFor = (extra: string[] = []) =>
        normalizeTagList([...rawTags, ...extra]);
      const createdAt = isoOrNow(item.created_at);
      // SN's item-level `updated_at` is the SERVER's sync timestamp -
      // it moves whenever the item is re-synced, including for
      // metadata-only changes like being added to a tag. The date SN's
      // own UI shows as "modified" is appData's client_updated_at, i.e.
      // when the user actually last edited the note. Prefer that and
      // fall back to the server value for pre-2019 exports that predate
      // the field.
      const updatedAt = isoOrNow(snMeta.client_updated_at ?? item.updated_at ?? item.created_at);
      const kind = noteKind(c);

      // The authenticator editor keeps a list of 2FA and password entries.
      // Each becomes a Vault login, which is what they are; the note that
      // held them has no text of its own worth keeping.
      if (kind === 'authentication') {
        const entries = parseAuthEntries(rawBody);
        if (entries) {
          for (const e of entries) {
            notes.push({
              title: e.service,
              body: serializeLoginBody({
                url: '',
                username: e.account,
                password: e.password,
                totp: e.secret,
                notes: e.notes,
              }),
              tags: tagsFor(),
              createdAt,
              updatedAt,
              trashed,
              ...(archived ? { archived: true } : {}),
              type: 'login',
              ...folder,
            });
          }
          authEntryCount += entries.length;
          if (rawTags.length === 0) untaggedCount += entries.length;
          if (trashed) trashedImportCount += entries.length;
          continue;
        }
        if (rawBody.trim()) authFailedCount++;
      }

      let source = rawBody;
      let extraTags: string[] = [];
      let type: 'task' | undefined;
      switch (kind) {
        case 'super': {
          const res = superToMarkdown(rawBody, { items: linkedItems, blobs });
          if (res) {
            source = res.markdown;
            extraTags = res.hashtags;
            missingFileCount += res.missingFiles;
            superCount++;
          } else if (rawBody.trim()) {
            superFailedCount++;
          }
          break;
        }
        case 'task': {
          // SN checklists store their items as a JSON blob in the note text,
          // which would otherwise import as an unreadable wall of JSON.
          // Convert it to the `- [ ]` / `- [x]` markdown our Tasks pillar
          // parses, and type the note 'task' so it lands there.
          const checklist = snChecklistToMarkdown(rawBody) ?? simpleTasksToMarkdown(rawBody);
          if (checklist) {
            source = checklist;
            type = 'task';
            checklistCount++;
          } else {
            checklistFailedCount++;
          }
          break;
        }
        case 'code':
          if (rawBody.trim()) {
            source = fence(rawBody, codeLanguage(c));
            codeCount++;
          }
          break;
        case 'spreadsheet': {
          const table = sheetsToMarkdown(rawBody);
          if (table !== null) {
            source = table;
            sheetCount++;
          } else if (rawBody.trim()) {
            sheetFailedCount++;
          }
          break;
        }
        case 'rich-text':
          if (rawBody.trim()) {
            source = htmlNoteToMarkdown(rawBody).trim();
            richTextCount++;
          }
          break;
      }

      const tags = tagsFor(extraTags);
      if (!rawTitle) missingTitleCount++;
      if (!source.trim()) emptyCount++;
      if (rawTags.length === 0 && extraTags.length === 0) untaggedCount++;
      if (pinned) starredCount++;
      if (trashed) trashedImportCount++;
      if (archived) archivedCount++;
      if (locked) lockedCount++;

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
        tags,
        createdAt,
        updatedAt,
        starred: pinned,
        trashed,
        ...(archived ? { archived: true } : {}),
        ...(locked ? { locked: true } : {}),
        ...(type ? { type } : {}),
        ...folder,
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
    if (archivedCount > 0) {
      transforms.push(
        `Kept ${archivedCount} archived note${archivedCount === 1 ? '' : 's'} in the archive.`
      );
    }
    if (checklistCount > 0) {
      transforms.push(
        `Converted ${checklistCount} checklist${checklistCount === 1 ? '' : 's'} into tasks you can tick off.`
      );
    }
    if (superCount > 0) {
      transforms.push(
        `Converted ${superCount} Super note${superCount === 1 ? '' : 's'}, with headings, lists, tables and formatting kept.`
      );
    }
    if (codeCount > 0) {
      transforms.push(`Kept ${codeCount} code note${codeCount === 1 ? '' : 's'} as code blocks.`);
    }
    if (sheetCount > 0) {
      transforms.push(`Converted ${sheetCount} spreadsheet${sheetCount === 1 ? '' : 's'} into tables.`);
    }
    if (richTextCount > 0) {
      transforms.push(
        `Converted ${richTextCount} rich-text note${richTextCount === 1 ? '' : 's'} with their formatting.`
      );
    }
    if (authEntryCount > 0) {
      transforms.push(
        `Moved ${authEntryCount} authenticator entr${authEntryCount === 1 ? 'y' : 'ies'} into the Vault as logins.`
      );
    }
    if (lockedCount > 0) {
      transforms.push(
        `Kept ${lockedCount} locked note${lockedCount === 1 ? '' : 's'} read-only.`
      );
    }
    if (tagIndex.folders.length > 0) {
      transforms.push(
        `Rebuilt your nested tags as ${tagIndex.folders.length} folder${tagIndex.folders.length === 1 ? '' : 's'}, and kept them as tags too.`
      );
    }
    if (tagIndex.shortened > 0) {
      transforms.push(
        `${tagIndex.shortened} nested tag${tagIndex.shortened === 1 ? '' : 's'} had a path too long for a tag and kept ${tagIndex.shortened === 1 ? 'its' : 'their'} own name. The folder shows the full path.`
      );
    }
    if (blobs.size > 0) {
      transforms.push(`Imported ${blobs.size} embedded file${blobs.size === 1 ? '' : 's'}.`);
    }

    if (checklistFailedCount > 0) {
      warnings.push(
        `${checklistFailedCount} checklist${checklistFailedCount === 1 ? '' : 's'} used a format we don't recognize. ${checklistFailedCount === 1 ? 'It was' : 'They were'} imported as plain text so nothing is lost.`
      );
    }

    if (superFailedCount > 0) {
      warnings.push(
        `${superFailedCount} Super note${superFailedCount === 1 ? '' : 's'} could not be read. ${superFailedCount === 1 ? 'It was' : 'They were'} imported as plain text so nothing is lost.`
      );
    }
    if (sheetFailedCount > 0) {
      warnings.push(
        `${sheetFailedCount} spreadsheet${sheetFailedCount === 1 ? '' : 's'} could not be read. ${sheetFailedCount === 1 ? 'It was' : 'They were'} imported as plain text so nothing is lost.`
      );
    }
    if (authFailedCount > 0) {
      warnings.push(
        `${authFailedCount} authenticator note${authFailedCount === 1 ? '' : 's'} could not be read. ${authFailedCount === 1 ? 'It was' : 'They were'} imported as plain text so nothing is lost.`
      );
    }
    if (missingFileCount > 0) {
      warnings.push(
        `${missingFileCount} uploaded file${missingFileCount === 1 ? ' is' : 's are'} not in the backup, because Standard Notes backups never include file contents. Each note marks where a file was. Download the files from Standard Notes and add them again.`
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
    if (tagIndex.folders.length > 0) parsed.folders = tagIndex.folders;
    if (blobs.size > 0) {
      parsed.blobs = blobs;
      parsed.blobBytes = [...blobs.values()].reduce((sum, b) => sum + b.data.length, 0);
    }
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
    return zipEntryText(entry);
  }

  // .txt or .json or anything else - read as text and hope for the best.
  return file.text();
}

type SnNoteKind = 'super' | 'task' | 'code' | 'spreadsheet' | 'authentication' | 'rich-text' | 'text';

/**
 * Which editor wrote this note. Newer exports set `noteType`; older ones
 * only carry the editor id. The ids are Standard Notes' feature
 * identifiers (`NativeFeatureIdentifier.ts` in their app repository).
 */
function noteKind(c: SnContent): SnNoteKind {
  switch (c.noteType) {
    case 'super':
    case 'task':
    case 'code':
    case 'spreadsheet':
    case 'authentication':
    case 'rich-text':
      return c.noteType;
    case 'plain-text':
    case 'markdown':
      return 'text';
  }
  const id = c.editorIdentifier ?? '';
  if (id.includes('super-editor')) return 'super';
  if (id.includes('task-editor') || id.includes('advanced-checklist')) return 'task';
  if (id.includes('code-editor')) return 'code';
  if (id.includes('standard-sheets')) return 'spreadsheet';
  if (id.includes('token-vault')) return 'authentication';
  if (id.includes('plus-editor') || id.includes('bold-editor')) return 'rich-text';
  return 'text';
}

/**
 * The older Simple Task Editor stores one task per line, each already in
 * markdown's `- [ ]` / `- [x]` form (it also accepts `[X]`). Returns null
 * when any non-empty line is not a task, so a body we do not recognise is
 * never half-rewritten.
 */
function simpleTasksToMarkdown(rawBody: string): string | null {
  const lines = rawBody.split(/\r?\n/).filter((l) => l.trim() !== '');
  if (lines.length === 0) return null;
  const out: string[] = [];
  for (const line of lines) {
    const m = /^- \[([ xX])\] (.*)$/.exec(line);
    if (!m) return null;
    out.push(`- [${m[1] === ' ' ? ' ' : 'x'}] ${m[2]!.trim()}`);
  }
  return out.join('\n');
}

/** A fenced block long enough that no backtick run inside it can close it. */
function fence(code: string, language: string): string {
  const run = Math.max(2, ...(code.match(/`{3,}/g) ?? []).map((r) => r.length));
  const marks = '`'.repeat(run + 1);
  return `${marks}${language}\n${code.replace(/\n+$/, '')}\n${marks}`;
}

/**
 * The language the code editor showed the note in. The editor keeps it as
 * `mode`, a CodeMirror language name ("JavaScript", "C++"), in its own slot
 * of the note's appData. Returned as a fence info string.
 */
function codeLanguage(c: SnContent): string {
  const slots = c.appData?.['org.standardnotes.sn.components'] ?? {};
  for (const slot of Object.values(slots)) {
    const mode = (slot as { mode?: unknown } | null)?.mode;
    if (typeof mode !== 'string' || !mode.trim()) continue;
    const name = mode.trim().toLowerCase();
    const known: Record<string, string> = {
      'c++': 'cpp',
      'c#': 'csharp',
      'objective-c': 'objectivec',
      'plain text': '',
      shell: 'bash',
    };
    return name in known ? known[name]! : name.replace(/[^a-z0-9+#-]/g, '');
  }
  return '';
}

/**
 * The spreadsheet editor stores its workbook as Kendo UI's JSON:
 * `{ sheets: [{ name, rows: [{ index, cells: [{ index, value, formula }] }] }] }`,
 * where rows and cells carry their own index and empty ones are left out.
 * Each sheet with any content becomes a pipe table, its first row the
 * header; a workbook of more than one sheet gets a heading per sheet.
 * Returns null when the text is not that shape.
 */
function sheetsToMarkdown(rawBody: string): string | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBody);
  } catch {
    return null;
  }
  const sheets = (parsed as { sheets?: unknown })?.sheets;
  if (!Array.isArray(sheets)) return null;

  const cellText = (cell: { value?: unknown; formula?: unknown }): string => {
    const v = cell.value ?? (typeof cell.formula === 'string' ? `=${cell.formula}` : '');
    return String(v).replace(/\|/g, '\\|').replace(/\r?\n/g, '<br>').trim();
  };

  const blocks: string[] = [];
  for (const sheet of sheets as Array<{ name?: unknown; rows?: unknown }>) {
    const grid: string[][] = [];
    const rows = Array.isArray(sheet?.rows) ? sheet.rows : [];
    rows.forEach((row: { index?: unknown; cells?: unknown }, ri: number) => {
      const r = typeof row?.index === 'number' ? row.index : ri;
      const cells = Array.isArray(row?.cells) ? row.cells : [];
      cells.forEach((cell: { index?: unknown; value?: unknown; formula?: unknown }, ci: number) => {
        const text = cellText(cell ?? {});
        if (!text) return;
        const col = typeof cell?.index === 'number' ? cell.index : ci;
        (grid[r] ??= [])[col] = text;
      });
    });
    const used = grid.flatMap((row, r) => (row ? [r] : []));
    if (used.length === 0) continue;
    // `grid` is sparse, and map() keeps its holes, so the width is read off the used rows.
    const width = Math.max(...used.map((r) => grid[r]!.length));
    const lines: string[] = [];
    for (let r = used[0]!; r <= used[used.length - 1]!; r++) {
      const row = grid[r] ?? [];
      lines.push(`| ${Array.from({ length: width }, (_, i) => row[i] ?? '').join(' | ')} |`);
      if (lines.length === 1) lines.push(`|${' --- |'.repeat(width)}`);
    }
    const name = typeof sheet.name === 'string' ? sheet.name.trim() : '';
    blocks.push(sheets.length > 1 && name ? `## ${name}\n\n${lines.join('\n')}` : lines.join('\n'));
  }
  return blocks.join('\n\n');
}

interface AuthEntry {
  service: string;
  account: string;
  secret: string;
  password: string;
  notes: string;
}

/**
 * The authenticator editor stores a JSON array of entries, each
 * `{ service, account, secret, password, notes, color }`: a 2FA entry
 * carries the base32 `secret`, a password entry carries `password`.
 * Returns null when the text is not that shape.
 */
function parseAuthEntries(rawBody: string): AuthEntry[] | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBody);
  } catch {
    return null;
  }
  if (!Array.isArray(parsed)) return null;
  const str = (v: unknown) => (typeof v === 'string' ? v : '');
  const out: AuthEntry[] = [];
  for (const raw of parsed) {
    const e = raw as Record<string, unknown> | null;
    if (!e || typeof e !== 'object' || !('service' in e)) return null;
    out.push({
      service: str(e.service).trim(),
      account: str(e.account).trim(),
      secret: str(e.secret).replace(/\s/g, '').toUpperCase(),
      password: str(e.password),
      notes: str(e.notes),
    });
  }
  return out;
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
 * Every note, tag and uploaded file by uuid, so a Super note's link to
 * another item can name it.
 */
function buildItemIndex(items: SnItem[]): Map<string, SnLinkedItem> {
  const map = new Map<string, SnLinkedItem>();
  for (const item of items) {
    if (item.deleted || !item.uuid) continue;
    const c = contentOf(item);
    if (item.content_type === 'Note') map.set(item.uuid, { kind: 'note', title: (c.title ?? '').trim() });
    else if (item.content_type === 'Tag') map.set(item.uuid, { kind: 'tag', title: (c.title ?? '').trim() });
    else if (item.content_type === 'SN|File') map.set(item.uuid, { kind: 'file', name: (c.name ?? '').trim() || 'file' });
  }
  return map;
}

interface TagIndex {
  /** Note uuid -> the uuids of the tags it belongs to. */
  noteTags: Map<string, string[]>;
  /** Tag uuid -> the tag name the note carries: its full path when it fits. */
  tagName: Map<string, string>;
  /** Tag uuid -> its path from the root, one segment per tag. */
  tagPath: Map<string, string[]>;
  /** Tag uuid -> the folder built for it, for tags that sit in a hierarchy. */
  tagFolder: Map<string, string>;
  folders: FolderDef[];
  /** Tags whose full path was too long to be a tag name. */
  shortened: number;
}

/**
 * Walk all Tag items once. Membership is each tag's Note references; a
 * Tag reference on a tag is its parent. Tags in a hierarchy also become a
 * folder tree, capped in depth and count like every import: a folder that
 * cannot be created hands its notes to the nearest ancestor that was.
 */
function buildTagIndex(items: SnItem[]): TagIndex {
  const titles = new Map<string, string>();
  const parentOf = new Map<string, string>();
  const noteTags = new Map<string, string[]>();
  for (const item of items) {
    if (item.content_type !== 'Tag' || item.deleted || !item.uuid) continue;
    const title = (contentOf(item).title ?? '').trim();
    if (!title) continue;
    titles.set(item.uuid, title);
  }
  for (const item of items) {
    if (item.content_type !== 'Tag' || !item.uuid || !titles.has(item.uuid)) continue;
    for (const ref of contentOf(item).references ?? []) {
      if (ref.content_type === 'Note') {
        const list = noteTags.get(ref.uuid) ?? [];
        list.push(item.uuid);
        noteTags.set(ref.uuid, list);
      } else if (ref.content_type === 'Tag' && titles.has(ref.uuid) && !parentOf.has(item.uuid)) {
        parentOf.set(item.uuid, ref.uuid);
      }
    }
  }

  const tagPath = new Map<string, string[]>();
  const pathOf = (id: string): string[] => {
    const cached = tagPath.get(id);
    if (cached) return cached;
    const chain: string[] = [];
    const seen = new Set<string>();
    for (let cur: string | undefined = id; cur && !seen.has(cur); cur = parentOf.get(cur)) {
      seen.add(cur);
      chain.unshift(titles.get(cur)!);
    }
    tagPath.set(id, chain);
    return chain;
  };

  const tagName = new Map<string, string>();
  let shortened = 0;
  for (const id of titles.keys()) {
    const full = pathOf(id).join('/');
    if (full.length > TAG_MAX_LENGTH) {
      tagName.set(id, titles.get(id)!);
      shortened++;
    } else {
      tagName.set(id, full);
    }
  }

  // Only tags that are part of a hierarchy get a folder.
  const hasChildren = new Set(parentOf.values());
  const nested = [...titles.keys()].filter((id) => parentOf.has(id) || hasChildren.has(id));
  const byPath = (a: string, b: string) => pathOf(a).join('/').localeCompare(pathOf(b).join('/'));
  let folders: FolderDef[] = [];
  const tagFolder = new Map<string, string>();
  for (const id of nested.sort((a, b) => pathOf(a).length - pathOf(b).length || byPath(a, b))) {
    const parent = parentOf.get(id);
    const parentFolder = parent ? (tagFolder.get(parent) ?? null) : null;
    const res = folders.length < IMPORT_FOLDER_LIMIT ? createFolder(folders, titles.get(id)!, parentFolder) : null;
    if (res) {
      folders = res.folders;
      tagFolder.set(id, res.created.id);
    } else if (parentFolder) {
      tagFolder.set(id, parentFolder);
    }
  }

  return { noteTags, tagName, tagPath, tagFolder, folders, shortened };
}

/**
 * The folder a note lands in: the one of its deepest nested tag, the first
 * by path on a tie. A note with no nested tag stays out of the tree.
 */
function pickFolder(tagIds: string[], index: TagIndex): { folderId?: string; folderPath?: string[] } {
  const candidates = tagIds
    .filter((id) => index.tagFolder.has(id))
    .sort(
      (a, b) =>
        index.tagPath.get(b)!.length - index.tagPath.get(a)!.length ||
        index.tagPath.get(a)!.join('/').localeCompare(index.tagPath.get(b)!.join('/')),
    );
  const best = candidates[0];
  return best ? { folderId: index.tagFolder.get(best)!, folderPath: index.tagPath.get(best)! } : {};
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
