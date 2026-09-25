/**
 * PrivacyNotes backup importer - restores a full backup .zip produced
 * by exportAllMarkdownZip (v0.113.0+), and a .pnbackupz once it is
 * decrypted into that zip.
 *
 * Detection: zip contains manifest.json with format: "privacynotes-backup".
 *
 * Flow:
 *   1. Read manifest.json → require format "privacynotes-backup". The
 *      manifest's `version` is not read: a backup from a newer build parses
 *      with the front-matter keys this build knows and drops the rest. A
 *      note count that differs from the manifest's is a warning.
 *   2. Parse each .md file in the zip root → extract YAML frontmatter
 *      (id, type, starred, trashed, locked, pinProtected, trackers, tags,
 *      timestamps, folder and folderId). The id is what applyImport matches
 *      a restore on; a backup written before ids were carried has none, and
 *      its notes come in as new ones.
 *   3. Rewrite body refs from relative paths back to pn:img/ and pn:file/ format.
 *   4. Return ParsedImport for applyImport (writes notes to Dexie).
 *   5. After applyImport: restoreBlobs() reads image/attachment files from
 *      the zip and writes them to IndexedDB with pendingUpload=1 so the
 *      next sync uploads them to Supabase.
 */

import JSZip from 'jszip';
import { zipEntryText } from './zipEntry';
import type { BackupManifest, MissingBlob } from '../export';
import { stripFrontMatterPadding, unescapeQuotes } from '../noteMarkdown';
import { FRONT_MATTER } from '../markdownFolder/adapter';
import type { ParsedImport, ImportedNote } from './types';
import type { NoteType } from '@notes/shared';
import { db } from '../db';
import type { AttachmentMeta } from '../attachmentStore';
import { sha256hex } from './blobImport';
import { createFolder, type FolderDef } from '../folders';
import { IMPORT_FOLDER_LIMIT, parseFolderPath } from './folderImport';

// ─── YAML frontmatter parser (minimal, no dependency) ────────────────

/** Extract YAML frontmatter from a markdown string. Returns { meta, body }. */
function parseFrontmatter(md: string): { meta: Record<string, unknown>; body: string } {
  const match = md.match(FRONT_MATTER);
  if (!match) return { meta: {}, body: md };

  const yamlBlock = match[1]!;
  // The blank line after the closing fence is the format's, not the note's.
  // Keeping it grew every restored note by one blank line per backup cycle
  // (#148); see stripFrontMatterPadding for why this is not `.trim()`.
  const body = stripFrontMatterPadding(match[2]!);
  const meta: Record<string, unknown> = {};

  for (const line of yamlBlock.split('\n')) {
    const colon = line.indexOf(':');
    if (colon < 0) continue;
    const key = line.slice(0, colon).trim();
    let val = line.slice(colon + 1).trim();
    if (!key) continue;

    // A folder path is text whatever it looks like, so it is kept exactly as
    // written for parseFolderPath, which owns its quoting and escapes: a root
    // folder named 2024, true or [draft] is a name.
    if (key === 'folder') meta[key] = val;
    // Handle quoted strings
    else if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      meta[key] = unescapeQuotes(val.slice(1, -1));
    }
    // Handle YAML arrays [a, b, c]
    else if (val.startsWith('[') && val.endsWith(']')) {
      meta[key] = val.slice(1, -1).split(',').map((s) => s.trim()).filter(Boolean);
    }
    // Handle booleans
    else if (val === 'true') meta[key] = true;
    else if (val === 'false') meta[key] = false;
    // Handle JSON (for trackers)
    else if (val.startsWith('{')) {
      try { meta[key] = JSON.parse(val); } catch { meta[key] = val; }
    }
    // Handle numbers
    else if (/^-?\d+(\.\d+)?$/.test(val)) meta[key] = Number(val);
    // Default: string
    else meta[key] = val;
  }

  return { meta, body };
}

// ─── Body rewriting (import direction) ────────────────────────────────

/** Rewrite relative paths back to pn:img/<uuid> refs. */
function rewriteImagesForImport(body: string): string {
  // images/<uuid>.<ext> → pn:img/<uuid>  (handles .webp, .jpg, .jpeg, .png)
  return body.replace(/images\/([0-9a-f-]{36})\.[a-z]+/g, 'pn:img/$1');
}

/**
 * Rewrite relative attachment paths back to [name|size|mime](pn:file/<uuid>) refs.
 * Uses manifest attachment metadata to reconstruct the full link syntax.
 *
 * v2 backups name files by their original name (manifest.file); v1 backups
 * named them <uuid>.<ext>. Both resolve via a path -> uuid reverse map.
 */
function rewriteAttachmentsForImport(
  body: string,
  manifest: BackupManifest,
): string {
  // Reverse-map each on-disk path to its uuid.
  const pathToUuid = new Map<string, string>();
  for (const [uuid, info] of Object.entries(manifest.attachments || {})) {
    const file = info.file ?? `${uuid}.${extFromName(info.name)}`;
    pathToUuid.set(`${info.folder}/${file}`, uuid);
  }
  // Match [name](target) or [name](<target>); the angle-bracket form carries
  // names with spaces or parens. target points into an attachment folder.
  // A leading `!` is a picture placed from Files, which shows the file
  // rather than listing it, so it goes back to a picture of the same blob.
  return body.replace(
    /(!?)\[([^\]]*)\]\((?:<((?:audio|video|docs|files)\/[^>]+)>|((?:audio|video|docs|files)\/[^)\s]+))\)/g,
    (match, bang: string, name: string, bracketed: string | undefined, bare: string | undefined) => {
      const target = bracketed ?? bare;
      if (!target) return match;
      const uuid = pathToUuid.get(target);
      if (!uuid) return match;
      if (bang) return `![${name}](pn:file/${uuid})`;
      const info = manifest.attachments[uuid]!;
      const sizeStr = formatSize(info.size);
      // The link's own text first: one file can be referenced twice under
      // two names, and the manifest holds room for only one of them.
      return `[${name || info.name}|${sizeStr}|${info.mime}](pn:file/${uuid})`;
    },
  );
}

/** Format bytes as human-readable size (matching the app's format). */
function formatSize(bytes: number): string {
  if (bytes < 1000) return `${bytes} B`;
  if (bytes < 1000 * 1000) return `${(bytes / 1000).toFixed(1)} KB`;
  return `${(bytes / (1000 * 1000)).toFixed(1)} MB`;
}

/** File extension from a name, lowercased; 'bin' when absent. Mirrors the
 *  exporter's fallback so v1 backups (files named <uuid>.<ext>) resolve. */
function extFromName(name: string): string {
  const dot = name.lastIndexOf('.');
  return dot >= 0 ? name.slice(dot + 1).toLowerCase() : 'bin';
}

// sha256hex imported from blobImport.ts (shared across all importers)

// ─── Folder tree (import direction) ───────────────────────────────────

/**
 * Rebuild the folder tree the backup's notes name, and point each note that
 * carries a path at its folder in it.
 *
 * A folder is known by its parent and its whole name, never by a joined path:
 * a name may hold a slash, and a string split on slashes again cuts it in
 * two. Two siblings may also share a name, and only the `folderId` each note
 * saved tells them apart, so a folder already claimed by one saved id gives a
 * note with another its own folder of that name. `originalIds` holds the
 * claims, rebuilt id to saved id, and `reconcileImportedFolders` reuses a
 * folder still live under its saved id before it matches any name, which is
 * what puts a restore into the account that wrote the backup back exactly
 * where it was. In a vault that holds none of those ids the names decide, so
 * same-named siblings arrive there as one folder.
 */
function rebuildFolders(notes: ImportedNote[]): {
  folders: FolderDef[];
  originalIds: Map<string, string>;
} {
  let folders: FolderDef[] = [];
  const known = new Map<string, string>();
  const originalIds = new Map<string, string>();
  // Sorted by path, so siblings land in a stable, predictable order.
  const byPath = notes
    .map((note) => ({ note, key: (note.folderPath ?? []).join('/') }))
    .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  for (const { note } of byPath) {
    const path = note.folderPath ?? [];
    let parentId: string | null = null;
    for (let depth = 0; depth < path.length; depth++) {
      const name = path[depth]!;
      const saved = depth === path.length - 1 ? note.folderId : null;
      let key = JSON.stringify([parentId, name]);
      let id = known.get(key);
      const claimed = id ? originalIds.get(id) : undefined;
      if (saved && claimed && claimed !== saved) {
        key = JSON.stringify([parentId, name, saved]);
        id = known.get(key);
      }
      if (!id) {
        if (folders.length >= IMPORT_FOLDER_LIMIT) break;
        const res = createFolder(folders, name, parentId);
        if (!res) break;
        folders = res.folders;
        id = res.created.id;
        known.set(key, id);
      }
      if (saved && !originalIds.has(id)) originalIds.set(id, saved);
      parentId = id;
    }
    if (parentId) note.folderId = parentId;
  }
  return { folders, originalIds };
}

// ─── Parse function (returns ParsedImport for applyImport) ────────────

export async function parsePrivacyNotesBackup(
  file: File,
  onProgress?: (msg: string) => void,
): Promise<ParsedImport> {
  onProgress?.('Reading backup...');
  const zip = await JSZip.loadAsync(await file.arrayBuffer());

  // Validate manifest
  const manifestFile = zip.file('manifest.json');
  if (!manifestFile) {
    throw new Error(
      "This doesn't look like a PrivacyNotes backup. No manifest.json found. " +
      'If this is a generic markdown zip, try the "Markdown files" importer instead.',
    );
  }

  const manifest: BackupManifest = JSON.parse(await zipEntryText(manifestFile));
  if (manifest.format !== 'privacynotes-backup') {
    throw new Error(
      `Unrecognized backup format: "${manifest.format}". Expected "privacynotes-backup".`,
    );
  }

  onProgress?.('Parsing notes...');

  // Parse all .md files in the zip root (not in subdirectories)
  const notes: ImportedNote[] = [];
  const warnings: string[] = [];
  const allTags = new Set<string>();
  let emptyNotes = 0;
  let untaggedNotes = 0;

  const mdFiles = Object.keys(zip.files).filter(
    (name) => name.endsWith('.md') && !name.includes('/'),
  );

  for (const filename of mdFiles) {
    const content = await zipEntryText(zip.file(filename)!);
    const { meta, body } = parseFrontmatter(content);

    // The KEY decides, not its value. A backup always writes a `title` line,
    // so an empty one is a note whose author gave it no name, and the filename
    // beside it is a slug OF that title: "untitled.md", "untitled-2.md" carry
    // nothing to recover. Taking a filename there stores a stand-in as the
    // user's own title and syncs it to every device (GitHub #337). The filename
    // answers only for a zip with no title line, which this app never writes.
    const title = 'title' in meta ? String(meta.title ?? '') : filename.replace(/\.md$/, '');
    const tags = Array.isArray(meta.tags) ? (meta.tags as string[]) : [];
    tags.forEach((t) => allTags.add(t));
    if (tags.length === 0) untaggedNotes++;

    // Rewrite body refs back to internal format
    let importBody = rewriteImagesForImport(body);
    importBody = rewriteAttachmentsForImport(importBody, manifest);

    if (!importBody.trim() && !title.trim()) {
      emptyNotes++;
    }

    const note: ImportedNote = {
      ...(typeof meta.id === 'string' && meta.id ? { id: meta.id } : {}),
      title,
      body: importBody,
      tags,
      createdAt: (meta.created as string) || new Date().toISOString(),
      updatedAt: (meta.updated as string) || new Date().toISOString(),
      starred: meta.starred === true,
      trashed: meta.trashed === true,
      type: (meta.type as NoteType) || 'note',
      locked: meta.locked === true,
      pinProtected: meta.pinProtected === true,
      trackers: (meta.trackers && typeof meta.trackers === 'object')
        ? meta.trackers as Record<string, unknown>
        : undefined,
      folderId: typeof meta.folderId === 'string' && meta.folderId ? meta.folderId : null,
    };

    // The readable folder path, when the backup carries one. `folderId` is a
    // UUID from the account that WROTE the backup and names nothing in any
    // other vault, so the path is rebuilt into real folders below, and the
    // saved id rides along to be preferred wherever it is still a folder. A
    // backup without a `folder:` line keeps the saved id alone.
    const folderPath = parseFolderPath(
      typeof meta.folder === 'string' ? meta.folder : undefined,
    );
    if (folderPath.length > 0) note.folderPath = folderPath;

    notes.push(note);
  }

  const { folders: rebuiltFolders, originalIds } = rebuildFolders(notes);

  if (notes.length === 0) {
    throw new Error('No markdown files found in the backup zip.');
  }

  if (notes.length !== manifest.noteCount) {
    warnings.push(
      `Manifest says ${manifest.noteCount} notes but found ${notes.length} .md files.`,
    );
  }

  // Sum blob sizes for the quota preflight, from the zip entries rather than
  // from the manifest. jszip verifies an entry's uncompressed size against
  // the bytes it inflates, so that number cannot be lied about; the
  // manifest's own `size` field is whatever the file says. The declared
  // number is the fallback for an entry that is missing, where the restore
  // will skip the blob anyway.
  let blobBytes = 0;
  for (const [uuid, att] of Object.entries(manifest.attachments)) {
    const zipPath = att.file
      ? `${att.folder}/${att.file}`
      : `${att.folder}/${uuid}.${extFromName(att.name)}`;
    const entry = zip.files[zipPath] as unknown as
      | { _data?: { uncompressedSize?: number } }
      | undefined;
    blobBytes += entry?._data?.uncompressedSize ?? att.size;
  }
  // For images, sum uncompressed sizes from zip entry metadata.
  for (const [path, entry] of Object.entries(zip.files)) {
    if (!entry.dir && path.startsWith('images/')) {
      const internal = (entry as unknown as { _data?: { uncompressedSize?: number } })._data;
      if (internal?.uncompressedSize) {
        blobBytes += internal.uncompressedSize;
      } else {
        // Fallback: conservative estimate per image (200 KB average JPEG).
        blobBytes += 200 * 1024;
      }
    }
  }

  return {
    folders: rebuiltFolders,
    originalFolderIds: originalIds,
    notes,
    warnings,
    transforms: [],
    stats: {
      totalNotes: notes.length,
      emptyNotes,
      untaggedNotes,
      uniqueTags: allTags.size,
    },
    source: 'privacynotes',
    blobBytes,
  };
}

// ─── Blob restoration (called after applyImport) ─────────────────────

/**
 * Restore images and attachments from the backup zip into IndexedDB.
 *
 * Writes to imageCache/imageDedup and attachmentCache/attachmentDedup
 * with pendingUpload=1 so the next sync pass uploads them to Supabase.
 * `missing` is every blob the manifest lists that the zip does not carry,
 * plus every blob the export itself could not read (the manifest's own
 * `missing`), which the caller reports: the notes that show it come back
 * without it.
 *
 * Call this AFTER applyImport has written the notes.
 */
export async function restoreBlobs(
  file: File,
  onProgress?: (msg: string) => void,
): Promise<{ images: number; attachments: number; missing: Pick<MissingBlob, 'id' | 'kind'>[] }> {
  const zip = await JSZip.loadAsync(await file.arrayBuffer());
  const manifestFile = zip.file('manifest.json');
  if (!manifestFile) return { images: 0, attachments: 0, missing: [] };

  const manifest: BackupManifest = JSON.parse(await zipEntryText(manifestFile));
  let imgCount = 0;
  let attCount = 0;
  const missing: Pick<MissingBlob, 'id' | 'kind'>[] = [];
  const now = new Date().toISOString();

  // Restore images
  const imageUuids = Object.keys(manifest.images || {});
  for (const uuid of imageUuids) {
    // Try multiple extensions - the exporter names the file after the
    // stored format (.jpg, .png, or the source's own format when the space
    // saver was off); older backups used .webp.
    const imgFile = zip.file(`images/${uuid}.webp`)
      || zip.file(`images/${uuid}.jpg`)
      || zip.file(`images/${uuid}.jpeg`)
      || zip.file(`images/${uuid}.png`)
      || zip.file(`images/${uuid}.gif`)
      || zip.file(`images/${uuid}.bmp`);
    if (!imgFile) {
      missing.push({ id: uuid, kind: 'image' });
      continue;
    }
    // The ids come out of the archive, and a `put` replaces. Every other
    // importer mints its own id for exactly this reason, so a blob the
    // account already holds is left alone here rather than swapped for
    // whatever the file carries under the same name. Restoring your own
    // backup finds the identical bytes and loses nothing.
    if (await db.imageCache.get(uuid)) continue;
    const data = new Uint8Array(await imgFile.async('uint8array'));
    const hash = await sha256hex(data);

    await db.imageCache.put({ id: uuid, data, cachedAt: now });
    // Keyed by hash, so the same rule applies one table over: a dedup row
    // the account already has points at a blob it can actually read.
    if (!(await db.imageDedup.get(hash))) {
      await db.imageDedup.put({ hash, uuid, encryptedSize: 0, pendingUpload: 1 });
    }
    imgCount++;
    onProgress?.(`Restoring images... ${imgCount} of ${imageUuids.length}`);
  }

  // Restore attachments
  const attEntries = Object.entries(manifest.attachments || {});
  for (const [uuid, info] of attEntries) {
    // v2 backups store the on-disk filename; v1 named files <uuid>.<ext>.
    const zipPath = info.file
      ? `${info.folder}/${info.file}`
      : `${info.folder}/${uuid}.${extFromName(info.name)}`;

    const attFile = zip.file(zipPath);
    if (!attFile) {
      missing.push({ id: uuid, kind: 'file' });
      continue;
    }
    if (await db.attachmentCache.get(uuid)) continue;
    const data = new Uint8Array(await attFile.async('uint8array'));
    const hash = await sha256hex(data);
    // The size is measured, not read from the manifest: the quota preflight
    // and the per-file ceiling both consume it, and the archive declares its
    // own number. `blobImport` measures the bytes it just read for the same
    // reason.
    const meta: AttachmentMeta = { name: info.name, mime: info.mime, size: data.length };

    await db.attachmentCache.put({ id: uuid, meta, data, cachedAt: now });
    if (!(await db.attachmentDedup.get(hash))) {
      await db.attachmentDedup.put({ hash, uuid, encryptedSize: 0, pendingUpload: 1 });
    }
    attCount++;
    onProgress?.(`Restoring files... ${attCount} of ${attEntries.length}`);
  }

  // The manifest comes from the file, so only well-formed entries count.
  for (const entry of Array.isArray(manifest.missing) ? manifest.missing : []) {
    if (typeof entry?.id === 'string' && (entry.kind === 'image' || entry.kind === 'file')) {
      missing.push({ id: entry.id, kind: entry.kind });
    }
  }

  return { images: imgCount, attachments: attCount, missing };
}
