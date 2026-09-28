import JSZip from 'jszip';
import { zipEntryBytes } from './zipEntry';
import { normalizeTag } from '../notesRepo';
import { createFolder, type FolderDef } from '../folders';
import { IMPORT_FOLDER_LIMIT } from './folderImport';
import { linkifyMarkdown } from './linkify';
import { noteLinkTarget } from '../noteLinks';
import { isBlobReferenced, mimeFromExt } from './blobImport';
import { htmlNoteToMarkdown } from './notesnook';
import type { ImportBlob, ImportedNote, ParsedImport } from './types';

/**
 * Joplin importer.
 *
 * Reads the JEX export (File > Export all > "JEX - Joplin Export File"), which is an uncompressed
 * tar of Joplin's raw item files, and the same files as a zipped "RAW -
 * Joplin Export Directory". Joplin writes both through its raw exporter
 * (`InteropService_Exporter_Raw.ts` in the Joplin repository): one
 * `<id>.md` per item and every attachment as `resources/<id>.<ext>`.
 *
 * An item file is `BaseItem.serialize` output:
 *
 *   Title line
 *
 *   Body, for notes only, any number of lines
 *
 *   id: 32 hex
 *   parent_id: ...
 *   type_: 1
 *
 * The properties are the lines after the LAST blank line. `type_` says what
 * the item is: 1 note, 2 notebook, 4 resource, 5 tag, 6 note-tag link.
 * Property values escape newlines as `\n`; bodies are written raw.
 *
 * Mapping:
 *   notebooks            -> folders, nested, depth-capped like every import
 *   note-tag links       -> tags
 *   `:/<id>` links       -> note-links for a note, imported files for a resource
 *   `<img src=":/<id>">` -> an image (Joplin writes this when a picture is resized)
 *   is_todo              -> a checkbox line in front of the body
 *   markup_language 2    -> an HTML note, through the Notesnook converter
 *   deleted_time         -> trashed
 *   user_*_time          -> the dates the user sees, over the sync dates
 */

const TYPE_NOTE = 1;
const TYPE_FOLDER = 2;
const TYPE_RESOURCE = 4;
const TYPE_TAG = 5;
const TYPE_NOTE_TAG = 6;

/** A tar archive past this many entries is not a notebook export. */
const TAR_ENTRY_LIMIT = 500_000;

type Props = Record<string, string>;

interface JoplinItem {
  props: Props;
  title: string;
  body: string;
}

/** Undo Joplin's property escaping. Only property values are escaped. */
function unescapeProp(value: string): string {
  return value.replace(/\\(\\n|\\r|n|r)/g, (_, c: string) =>
    c === 'n' ? '\n' : c === 'r' ? '\r' : c === '\\n' ? '\\n' : '\\r',
  );
}

/** `BaseItem.unserialize`, reading only what we use. Null for a file that is not an item. */
function parseItem(text: string): JoplinItem | null {
  const lines = text.replace(/\r\n/g, '\n').split('\n');
  const props: Props = {};
  let bodyLines: string[] = lines;
  let i = lines.length - 1;
  for (; i >= 0; i--) {
    const line = lines[i]!.trim();
    if (line === '') {
      bodyLines = lines.slice(0, i);
      break;
    }
    const p = line.indexOf(':');
    if (p < 0) return null;
    props[line.slice(0, p).trim()] = unescapeProp(line.slice(p + 1).trim());
  }
  if (i < 0) bodyLines = [];
  if (!props.type_ || !props.id) return null;
  const title = bodyLines[0] ?? '';
  return { props, title, body: bodyLines.slice(2).join('\n') };
}

/**
 * The entries of a ustar archive, as written by node-tar. A PAX header can
 * carry the next entry's path or size; a GNU long-name entry can carry its
 * path. Everything that is not a regular file is skipped.
 */
function readTar(buf: Uint8Array): Map<string, Uint8Array> {
  const files = new Map<string, Uint8Array>();
  const ascii = (from: number, len: number) => {
    let s = '';
    for (let i = from; i < from + len && buf[i] !== 0; i++) s += String.fromCharCode(buf[i]!);
    return s;
  };
  const utf8 = (from: number, len: number) => new TextDecoder().decode(buf.subarray(from, from + len));
  let pos = 0;
  let nextPath: string | null = null;
  let nextSize: number | null = null;
  while (pos + 512 <= buf.length && files.size < TAR_ENTRY_LIMIT) {
    if (buf.subarray(pos, pos + 512).every((b) => b === 0)) break;
    const name = ascii(pos, 100);
    const size = nextSize ?? parseInt(ascii(pos + 124, 12).trim() || '0', 8);
    const type = String.fromCharCode(buf[pos + 156] ?? 0);
    const prefix = ascii(pos + 257, 6).startsWith('ustar') ? ascii(pos + 345, 155) : '';
    if (!Number.isFinite(size) || size < 0) throw new Error('This .jex file is damaged.');
    const start = pos + 512;
    const end = start + size;
    if (end > buf.length) throw new Error('This .jex file is cut short. Export it from Joplin again.');
    pos = start + Math.ceil(size / 512) * 512;

    if (type === 'x') {
      // PAX records: "<length> <key>=<value>\n", repeated.
      for (const rec of utf8(start, size).split('\n')) {
        const m = /^\d+ ([^=]+)=(.*)$/.exec(rec);
        if (m?.[1] === 'path') nextPath = m[2]!;
        if (m?.[1] === 'size') nextSize = Number(m[2]);
      }
      continue;
    }
    if (type === 'L') {
      nextPath = utf8(start, size).replace(/\0+$/, '');
      continue;
    }
    const path = nextPath ?? (prefix ? `${prefix}/${name}` : name);
    nextPath = null;
    nextSize = null;
    if (type === '0' || type === '\0') files.set(path.replace(/^\.\//, ''), buf.subarray(start, end));
  }
  return files;
}

async function readZip(file: File): Promise<Map<string, Uint8Array>> {
  const zip = await JSZip.loadAsync(file);
  const entries = Object.values(zip.files).filter((f) => !f.dir);
  // A zipped export directory usually has one folder around it.
  const roots = new Set(entries.map((f) => (f.name.includes('/') ? f.name.split('/')[0] : '')));
  const strip = roots.size === 1 && !roots.has('') && !roots.has('resources') ? `${[...roots][0]}/` : '';
  const files = new Map<string, Uint8Array>();
  for (const entry of entries) {
    const path = strip && entry.name.startsWith(strip) ? entry.name.slice(strip.length) : entry.name;
    files.set(path, await zipEntryBytes(entry, Infinity));
  }
  return files;
}

function isoOr(value: string | undefined, fallback: string): string {
  if (!value) return fallback;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? fallback : d.toISOString();
}

export async function parseJoplin(file: File, onProgress?: (msg: string) => void): Promise<ParsedImport> {
  onProgress?.('Reading file…');
  const lower = file.name.toLowerCase();
  const files = lower.endsWith('.zip')
    ? await readZip(file)
    : readTar(new Uint8Array(await file.arrayBuffer()));

  onProgress?.('Reading items…');
  const decoder = new TextDecoder();
  const notesRaw: JoplinItem[] = [];
  const folders = new Map<string, JoplinItem>();
  const resources = new Map<string, JoplinItem>();
  const tagTitles = new Map<string, string>();
  const noteTags: Array<[string, string]> = [];
  let encryptedCount = 0;

  for (const [path, data] of files) {
    if (path.includes('/') || !path.endsWith('.md')) continue;
    const item = parseItem(decoder.decode(data));
    if (!item) continue;
    if (item.props.encryption_applied === '1') {
      encryptedCount++;
      continue;
    }
    switch (Number(item.props.type_)) {
      case TYPE_NOTE:
        notesRaw.push(item);
        break;
      case TYPE_FOLDER:
        folders.set(item.props.id!, item);
        break;
      case TYPE_RESOURCE:
        resources.set(item.props.id!, item);
        break;
      case TYPE_TAG:
        tagTitles.set(item.props.id!, item.title);
        break;
      case TYPE_NOTE_TAG:
        if (item.props.note_id && item.props.tag_id) noteTags.push([item.props.note_id, item.props.tag_id]);
        break;
    }
  }

  if (notesRaw.length === 0 && folders.size === 0) {
    throw new Error(
      encryptedCount > 0
        ? 'Every note in this export is still encrypted. Let Joplin finish decrypting, then export again.'
        : 'No Joplin notes found. In Joplin, pick File > Export all > "JEX - Joplin Export File", then drop the .jex file here.',
    );
  }

  // Resource files are named by id, with the extension Joplin knew.
  const resourceFiles = new Map<string, Uint8Array>();
  for (const [path, data] of files) {
    const m = /^resources\/([0-9a-f]{32})(?:\.[^/]*)?$/i.exec(path);
    if (m) resourceFiles.set(m[1]!.toLowerCase(), data);
  }

  onProgress?.('Rebuilding notebooks…');
  let folderDefs: FolderDef[] = [];
  const folderIdMap = new Map<string, string>();
  const folderPathOf = new Map<string, string[]>();
  let droppedFolders = 0;
  const live = [...folders.values()].filter((f) => !Number(f.props.deleted_time));
  const childrenOf = (parent: string) =>
    live
      .filter((f) => (folders.has(f.props.parent_id ?? '') ? f.props.parent_id : '') === parent)
      .sort((a, b) => a.title.localeCompare(b.title));
  const walk = (parentJoplin: string, parentOurs: string | null, path: string[]) => {
    for (const f of childrenOf(parentJoplin)) {
      const id = f.props.id!;
      const segs = [...path, f.title.trim() || 'Untitled'];
      folderPathOf.set(id, segs);
      const res = folderDefs.length < IMPORT_FOLDER_LIMIT ? createFolder(folderDefs, segs[segs.length - 1]!, parentOurs) : null;
      if (res) {
        folderDefs = res.folders;
        folderIdMap.set(id, res.created.id);
        walk(id, res.created.id, segs);
      } else {
        // Too deep or too many: the notes keep the nearest folder that exists.
        if (parentOurs) folderIdMap.set(id, parentOurs);
        droppedFolders++;
        walk(id, parentOurs, segs);
      }
    }
  };
  walk('', null, []);

  const tagsByNote = new Map<string, string[]>();
  for (const [noteId, tagId] of noteTags) {
    const title = tagTitles.get(tagId);
    if (!title) continue;
    const list = tagsByNote.get(noteId) ?? [];
    list.push(title);
    tagsByNote.set(noteId, list);
  }

  const noteTitles = new Map(notesRaw.map((n) => [n.props.id!, n.title.trim()]));
  const blobs = new Map<string, ImportBlob>();
  const resourceKey = new Map<string, string>();
  let missingResources = 0;

  const keyFor = (resId: string): string | null => {
    const cached = resourceKey.get(resId);
    if (cached) return cached;
    const data = resourceFiles.get(resId);
    if (!data) return null;
    const r = resources.get(resId);
    const ext = r?.props.file_extension ? `.${r.props.file_extension}` : '';
    const name = r?.props.filename || r?.title || `${resId}${ext}`;
    const key = `jpatt:${String(resourceKey.size + 1).padStart(6, '0')}`;
    resourceKey.set(resId, key);
    blobs.set(key, {
      data: new Uint8Array(data),
      mime: r?.props.mime || mimeFromExt(name),
      name,
    });
    return key;
  };

  const noteLink = (id: string, label: string): string | null => {
    const title = noteTitles.get(id);
    if (title === undefined) return null;
    const target = noteLinkTarget(title);
    const clean = label.replace(/[[\]]/g, '').trim();
    if (!target) return clean;
    return !clean || clean === target ? `[[${target}]]` : `[[${target}|${clean}]]`;
  };

  /** Rewrite every `:/<id>` reference to a note-link or an imported file. */
  const rewriteRefs = (md: string): string =>
    md
      .replace(/<img\b[^>]*?\bsrc=["']:\/([0-9a-fA-F]{32})["'][^>]*>/g, (tag, id: string) => {
        const key = keyFor(id.toLowerCase());
        if (!key) {
          missingResources++;
          return tag;
        }
        const alt = (/\balt=["']([^"']*)["']/.exec(tag)?.[1] ?? '').replace(/[[\]]/g, '');
        return `![${alt}](${key})`;
      })
      .replace(
        /(!?)\[([^\]]*)\]\((?::\/|joplin:\/\/x-callback-url\/openNote\?id=)([0-9a-fA-F]{32})(#[^)\s]*)?(?:\s+"[^"]*")?\)/g,
        (whole, bang: string, label: string, rawId: string) => {
          const id = rawId.toLowerCase();
          if (!bang) {
            const link = noteLink(id, label);
            if (link !== null) return link;
          }
          const key = keyFor(id);
          if (key) return `${bang}[${label.replace(/[[\]]/g, '')}](${key})`;
          if (resources.has(id)) missingResources++;
          return whole;
        },
      );

  onProgress?.('Building notes…');
  const now = new Date().toISOString();
  const notes: ImportedNote[] = [];
  let todoCount = 0;
  let htmlCount = 0;
  let trashedCount = 0;
  let conflictCount = 0;
  let linkifiedCount = 0;
  let emptyCount = 0;
  let untaggedCount = 0;

  for (const raw of notesRaw) {
    const p = raw.props;
    let body = raw.body;
    if (p.markup_language === '2') {
      body = htmlNoteToMarkdown(body).trim();
      htmlCount++;
    }
    body = rewriteRefs(body);

    let type: 'task' | undefined;
    if (p.is_todo === '1') {
      const done = Number(p.todo_completed) > 0;
      const due = Number(p.todo_due) > 0 ? ` (due ${new Date(Number(p.todo_due)).toISOString().slice(0, 10)})` : '';
      const line = `- [${done ? 'x' : ' '}] ${raw.title.trim().replace(/\s*\n\s*/g, ' ')}${due}`;
      body = body.trim() ? `${line}\n\n${body}` : line;
      type = 'task';
      todoCount++;
    }

    const linked = linkifyMarkdown(body);
    if (linked !== body) linkifiedCount++;

    const tags = [...(tagsByNote.get(p.id!) ?? [])];
    if (p.is_conflict === '1') {
      tags.push('conflict');
      conflictCount++;
    }
    const seen = new Set<string>();
    const normTags = tags
      .map((t) => normalizeTag(t))
      .filter((t) => t && !seen.has(t.toLowerCase()) && seen.add(t.toLowerCase()));
    if (normTags.length === 0) untaggedCount++;

    const trashed = Number(p.deleted_time) > 0;
    if (trashed) trashedCount++;
    if (!linked.trim()) emptyCount++;

    const createdAt = isoOr(p.user_created_time, isoOr(p.created_time, now));
    const parent = p.parent_id ?? '';
    notes.push({
      title: raw.title.trim(),
      body: linked,
      tags: normTags,
      createdAt,
      updatedAt: isoOr(p.user_updated_time, isoOr(p.updated_time, createdAt)),
      trashed,
      folderId: folderIdMap.get(parent) ?? null,
      ...(folderPathOf.has(parent) ? { folderPath: folderPathOf.get(parent)! } : {}),
      ...(type ? { type } : {}),
    });
  }

  // A resource no note points at is quota spent on nothing, as notesnook.ts found.
  for (const [key] of [...blobs]) {
    if (!notes.some((n) => isBlobReferenced(key, n.body))) blobs.delete(key);
  }

  const transforms: string[] = [];
  const warnings: string[] = [];
  const s = (n: number, one = '', many = 's') => (n === 1 ? one : many);
  if (folderDefs.length > 0) transforms.push(`Rebuilt ${folderDefs.length} notebook${s(folderDefs.length)} as folders.`);
  if (blobs.size > 0) transforms.push(`Imported ${blobs.size} attachment${s(blobs.size)}.`);
  if (todoCount > 0) transforms.push(`Turned ${todoCount} to-do${s(todoCount)} into tasks you can tick off.`);
  if (htmlCount > 0) transforms.push(`Converted ${htmlCount} HTML note${s(htmlCount)} with their formatting.`);
  if (trashedCount > 0) transforms.push(`Restored ${trashedCount} trashed note${s(trashedCount)} into the trash.`);
  if (linkifiedCount > 0) transforms.push(`Made URLs clickable in ${linkifiedCount} note${s(linkifiedCount)}.`);
  if (conflictCount > 0) {
    warnings.push(`${conflictCount} note${s(conflictCount)} came from Joplin's Conflicts notebook and carr${s(conflictCount, 'ies', 'y')} the tag "conflict".`);
  }
  if (encryptedCount > 0) {
    warnings.push(`${encryptedCount} item${s(encryptedCount)} ${s(encryptedCount, 'was', 'were')} still encrypted and skipped. Let Joplin finish decrypting, then export again.`);
  }
  if (missingResources > 0) {
    warnings.push(`${missingResources} attachment link${s(missingResources)} point${s(missingResources, 's', '')} at a file that is not in the export. ${s(missingResources, 'It stays', 'They stay')} as a link.`);
  }
  if (droppedFolders > 0) {
    warnings.push(`${droppedFolders} notebook${s(droppedFolders)} nested too deep ${s(droppedFolders, 'was', 'were')} merged into ${s(droppedFolders, 'its', 'their')} parent.`);
  }

  const uniqueTags = new Set(notes.flatMap((n) => n.tags));
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
    source: 'joplin',
  };
  if (folderDefs.length > 0) parsed.folders = folderDefs;
  if (blobs.size > 0) {
    parsed.blobs = blobs;
    parsed.blobBytes = [...blobs.values()].reduce((sum, b) => sum + b.data.length, 0);
  }
  return parsed;
}
