import JSZip from 'jszip';
import { normalizeTag } from '../notesRepo';
import { linkifyMarkdown } from './linkify';
import { importBlobs } from './blobImport';
import type { ImportedNote, ParsedImport } from './types';

/**
 * Apple Notes importer.
 *
 * Supports two export formats:
 *
 * 1. macOS "Exporter" app - single zip with account/folder nesting:
 *      account/Folder/Note Title.md
 *      account/Folder/images/image-file.jpg
 *
 * 2. iOS share-sheet - per-note zip:
 *      Note Title/Note Title.md
 *      Note Title/Attachments/UUID.jpeg
 *      Note Title/Attachments/UUID.m4a
 *
 * Each .md file has a `# Title` heading followed by the note body.
 * Tables are GFM pipe tables. Checklists use `- [ ]` / `- [x]`.
 * Images and attachments are imported into encrypted storage and
 * references rewritten to pn:img/ and pn:file/ URIs.
 */

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

/** Folders and files to skip. */
function shouldSkip(path: string): boolean {
  const lower = path.toLowerCase();
  if (lower.startsWith('__macosx/') || lower.includes('/__macosx/')) return true;
  const name = path.split('/').pop() ?? '';
  if (name.startsWith('.')) return true;
  return false;
}

/** Account labels the Exporter app writes as the top folder. */
function looksLikeAccount(segment: string): boolean {
  return segment.includes('@') || /^(icloud|on my mac|on my iphone|on my ipad)$/i.test(segment);
}

/**
 * How many leading segments of the post-prefix paths are the ACCOUNT rather
 * than a folder. Decided once per zip, never per path, because the answer
 * depends on what the user selected when zipping:
 *
 *  - the prefix strip in `parseZip` already ate one shared level, so if THAT
 *    level was the account there is nothing left here to drop;
 *  - otherwise the account, if the export has one, is the level every note
 *    shares, since the Exporter app nests everything under it;
 *  - a level the notes do NOT share is a folder, and so is the single level
 *    of an iOS share-sheet zip.
 *
 * One shape structure alone cannot answer: an account root holding exactly
 * one folder, where `Recipes/Cake.md` and `iCloud/Cake.md` are the same
 * shape. The name test above breaks that tie.
 */
function accountSegmentsToDrop(prefix: string, relPaths: string[]): number {
  if (looksLikeAccount(prefix.replace(/\/$/, ''))) return 0;
  if (relPaths.length === 0) return 0;
  const firsts = relPaths
    .map((p) => p.split('/'))
    .filter((parts) => parts.length >= 2)
    .map((parts) => parts[0]!);
  // A note sitting at the root has no leading level, so no level is shared.
  if (firsts.length !== relPaths.length) return 0;
  return firsts.every((f) => f === firsts[0]) ? 1 : 0;
}

/**
 * Convert folder segments to tags. `dropLeading` comes from
 * `accountSegmentsToDrop` and this function never re-derives it - that split
 * is the whole point. The account used to be dropped BOTH here and, whenever
 * it happened to be the zip root, again by the prefix strip in `parseZip`, so
 * the same export imported with or without its folder tags depending only on
 * how many levels the user happened to select when zipping.
 *
 * Example: "user@example.com/Recipes/Cake.md", dropLeading 1 -> ["Recipes"]
 *          "Recipes/Cake.md",                  dropLeading 0 -> ["Recipes"]
 *          "Weekend plan.md",                  dropLeading 0 -> []
 *
 * Case is preserved: `normalizeTag` strips delimiters and collapses
 * whitespace but does not lower-case. (This comment claimed it did until
 * `tests/importAppleNotes.test.ts` asserted the real output.)
 */
function tagsFromPath(relativePath: string, dropLeading: number): string[] {
  const parts = relativePath.split('/');
  // Everything between the account and the filename is a folder.
  return parts
    .slice(dropLeading, -1)
    .map((p) => normalizeTag(p))
    .filter((t): t is string => !!t);
}

/**
 * The Exporter app duplicates the title: the first line is `# Title`
 * and the body often starts with the same text as a plain paragraph.
 * Strip that duplicate so imported notes aren't redundant.
 */
function stripDuplicateTitle(title: string, body: string): string {
  if (!title) return body;
  const lines = body.split('\n');
  // Check if the first non-empty line matches the title exactly
  const firstIdx = lines.findIndex((l) => l.trim().length > 0);
  if (firstIdx >= 0 && lines[firstIdx]!.trim() === title) {
    lines.splice(firstIdx, 1);
    // Also remove a blank line right after if present
    if (firstIdx < lines.length && lines[firstIdx]!.trim() === '') {
      lines.splice(firstIdx, 1);
    }
    return lines.join('\n').trim();
  }
  return body;
}

/* ------------------------------------------------------------------ */
/* Single file parser                                                 */
/* ------------------------------------------------------------------ */

function parseOneNote(
  content: string,
  relativePath: string,
  dropLeading: number,
  zipDate: Date | null,
): ImportedNote & { hadUnderline: boolean } {
  // The entry's own modified time, the way obsidian.ts, markdown.ts and
  // samsungNotes.ts all read it. Import time is the last resort: stamping
  // every note with it destroys the library's real history, and the export
  // is usually deleted before anyone notices.
  const stamp = (zipDate ?? new Date()).toISOString();

  // Title: first `# ` heading, fall back to filename
  let title = '';
  let body = content;

  const headingMatch = content.match(/^# (.+)$/m);
  if (headingMatch) {
    title = headingMatch[1]!.trim();
    // Remove the heading line from body
    body = content.slice(headingMatch.index! + headingMatch[0].length).trim();
  } else {
    const filename = relativePath.split('/').pop() ?? '';
    title = filename.replace(/\.md$/i, '').trim();
  }

  // Strip duplicate title line
  body = stripDuplicateTitle(title, body);

  // Convert ++underline++ to HTML <u> tags (TipTap Underline extension)
  const hadUnderline = /\+\+.+?\+\+/.test(body);
  body = body.replace(/\+\+(.+?)\+\+/g, '<u>$1</u>');

  // Convert ==highlight== to bold (no highlight extension)
  body = body.replace(/==(.+?)==/g, '**$1**');

  // NOTE: image/attachment references (images/... and Attachments/...)
  // are left intact - the blob import step rewrites them to pn:img/ and
  // pn:file/ URIs after uploading. If no blobs are present in the zip,
  // orphan refs are cleaned up post-apply.

  // Tags from folder path
  const tags = tagsFromPath(relativePath, dropLeading);

  // Linkify bare URLs
  body = linkifyMarkdown(body.trim());

  return {
    title,
    body,
    tags,
    createdAt: stamp,
    updatedAt: stamp,
    hadUnderline,
  };
}

/* ------------------------------------------------------------------ */
/* Zip parser                                                         */
/* ------------------------------------------------------------------ */

const MD_EXT = /\.md$/i;
const ATTACHMENT_EXT = /\.(png|jpe?g|gif|webp|svg|bmp|pdf|mp3|mp4|webm|ogg|wav|m4a)$/i;

/** MIME type from extension. */
function mimeFromExt(path: string): string {
  const ext = path.split('.').pop()?.toLowerCase() ?? '';
  const map: Record<string, string> = {
    png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg',
    gif: 'image/gif', webp: 'image/webp', svg: 'image/svg+xml', bmp: 'image/bmp',
    pdf: 'application/pdf',
    mp3: 'audio/mpeg', m4a: 'audio/mp4', ogg: 'audio/ogg', wav: 'audio/wav',
    mp4: 'video/mp4', webm: 'video/webm',
  };
  return map[ext] ?? 'application/octet-stream';
}

interface ParseZipResult {
  notes: ImportedNote[];
  strippedUnderline: number;
  blobs: Map<string, { data: Uint8Array; mime: string; name: string }>;
  blobBytes: number;
}

async function parseZip(
  file: File,
  onProgress?: (msg: string) => void,
): Promise<ParseZipResult> {
  onProgress?.('Reading zip...');
  const buf = await file.arrayBuffer();
  const zip = await JSZip.loadAsync(buf);

  // Collect all file paths, skipping hidden/system files
  const allPaths: string[] = [];
  zip.forEach((path, entry) => {
    if (!entry.dir && !shouldSkip(path)) allPaths.push(path);
  });

  // Detect common root prefix (the zip often wraps everything in one folder)
  let prefix = '';
  if (allPaths.length > 0) {
    const firstSlash = allPaths[0]!.indexOf('/');
    if (firstSlash > 0) {
      const candidate = allPaths[0]!.slice(0, firstSlash + 1);
      if (allPaths.every((p) => p.startsWith(candidate))) {
        prefix = candidate;
      }
    }
  }

  const mdFiles: [string, JSZip.JSZipObject][] = [];
  const blobFiles: [string, JSZip.JSZipObject][] = [];

  zip.forEach((path, entry) => {
    if (entry.dir || shouldSkip(path)) return;
    const rel = prefix ? path.slice(prefix.length) : path;
    if (MD_EXT.test(rel)) {
      mdFiles.push([rel, entry]);
    } else if (ATTACHMENT_EXT.test(rel)) {
      blobFiles.push([rel, entry]);
    }
  });

  onProgress?.(`Found ${mdFiles.length} note${mdFiles.length === 1 ? '' : 's'}...`);

  // Decide the account level ONCE, from every note path at once. Doing it per
  // path is what let the answer depend on how deep the zip was taken.
  const dropLeading = accountSegmentsToDrop(prefix, mdFiles.map(([rel]) => rel));

  // Parse markdown notes
  const notes: ImportedNote[] = [];
  let strippedUnderline = 0;
  for (let i = 0; i < mdFiles.length; i++) {
    const [rel, entry] = mdFiles[i]!;
    const text = await entry.async('string');
    const parsed = parseOneNote(text, rel, dropLeading, entry.date ?? null);
    if (parsed.hadUnderline) strippedUnderline++;
    notes.push(parsed);
    if ((i + 1) % 50 === 0) {
      onProgress?.(`Parsed ${i + 1} of ${mdFiles.length}...`);
    }
  }

  // Extract attachment/image blobs
  const blobs = new Map<string, { data: Uint8Array; mime: string; name: string }>();
  let blobBytes = 0;
  if (blobFiles.length > 0) {
    onProgress?.(`Extracting ${blobFiles.length} attachment${blobFiles.length === 1 ? '' : 's'}...`);
  }
  for (let i = 0; i < blobFiles.length; i++) {
    const [rel, entry] = blobFiles[i]!;
    const data = new Uint8Array(await entry.async('uint8array'));
    const name = rel.split('/').pop() ?? rel;
    blobs.set(rel, { data, mime: mimeFromExt(rel), name });
    blobBytes += data.length;
    if ((i + 1) % 20 === 0) {
      onProgress?.(`Extracted ${i + 1} of ${blobFiles.length} attachments...`);
    }
  }

  return { notes, strippedUnderline, blobs, blobBytes };
}

/* ------------------------------------------------------------------ */
/* Public importer                                                    */
/* ------------------------------------------------------------------ */

export async function parseAppleNotes(
  file: File,
  onProgress?: (msg: string) => void,
): Promise<ParsedImport> {
  const { notes, strippedUnderline, blobs, blobBytes } = await parseZip(file, onProgress);

  const uniqueTags = new Set(notes.flatMap((n) => n.tags));
  const emptyNotes = notes.filter(
    (n) => !n.title.trim() && !n.body.trim()
  ).length;
  const untaggedNotes = notes.filter((n) => n.tags.length === 0).length;

  // Count images vs non-image attachments
  let imageCount = 0;
  let attachmentCount = 0;
  for (const [, blob] of blobs) {
    if (blob.mime.startsWith('image/')) imageCount++;
    else attachmentCount++;
  }

  const warnings: string[] = [];

  const transforms: string[] = [];
  const withTags = notes.filter((n) => n.tags.length > 0).length;
  if (withTags > 0) {
    transforms.push(
      `Converted Apple Notes folders to tags on ${withTags} note${withTags === 1 ? '' : 's'}.`
    );
  }
  const withTables = notes.filter((n) => /\|.*\|/.test(n.body)).length;
  if (withTables > 0) {
    transforms.push(
      `Preserved tables in ${withTables} note${withTables === 1 ? '' : 's'}.`
    );
  }
  const withTasks = notes.filter((n) => /- \[[ x]\]/.test(n.body)).length;
  if (withTasks > 0) {
    transforms.push(
      `Preserved checklists in ${withTasks} note${withTasks === 1 ? '' : 's'}.`
    );
  }
  if (strippedUnderline > 0) {
    transforms.push(
      `Converted underline formatting in ${strippedUnderline} note${strippedUnderline === 1 ? '' : 's'}.`
    );
  }
  if (imageCount > 0) {
    transforms.push(
      `Found ${imageCount} image${imageCount === 1 ? '' : 's'} to import.`
    );
  }
  if (attachmentCount > 0) {
    transforms.push(
      `Found ${attachmentCount} attachment${attachmentCount === 1 ? '' : 's'} to import.`
    );
  }
  transforms.push('Made bare URLs clickable.');

  return {
    notes,
    warnings,
    transforms,
    stats: {
      totalNotes: notes.length,
      emptyNotes,
      untaggedNotes,
      uniqueTags: uniqueTags.size,
    },
    source: 'apple-notes',
    blobBytes,
    blobs: blobs.size > 0 ? blobs : undefined,
  };
}
