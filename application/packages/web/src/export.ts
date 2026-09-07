// jszip is ~95 KB minified and only needed when the user actually
// exports a zip, so it is imported dynamically inside the two zip
// functions instead of statically here.
import {
  buildBackupPayload,
  encodeBackup,
  decodeBackup,
  encodeZipBackup,
  BACKUP_TOO_SMALL,
} from '@notes/shared';
import type { BackupPayload } from '@notes/shared';
import i18n from './i18n';
import { trackerRows, trackerHeading } from './trackerExport';
import { loadLocalSettings } from './userSettings';
import { intlLocale } from './languages';
import { saveBlob } from './saveFile';
import { detectPlatform } from './devices';
import type { LocalNote } from './db';
import { noteToMarkdown } from './noteMarkdown';
import type { ImageStore } from './imageStore';
import type { AttachmentStore } from './attachmentStore';
import { extractImageIds } from './imageProcessing';
import { escapeHtml, renderMarkdown, prepareRender, inlineSameOriginImages, inlineRenderedFavicons } from './markdownRender';
import { parseLoginBody, domainFromUrl } from './LoginForm';
import { parseCardBody, detectCardNetwork } from './CardForm';
import { parseSshKeyBody } from './SshKeyForm';
import { vaultContent, vaultToMarkdown } from './vaultFields';
import type { VaultContent } from './vaultFields';
import { folderNamePath, type FolderDef } from './folders';
import { linkExportMarkdown } from './linkBody';
import { slugify, zipEntryStems } from './exportNames';

/** Export helpers. All exports are generated client-side as Blob downloads. */

// ─── Image resolution helpers ──────────────────────────────────────────
//
// All export paths that output note body content need to resolve
// `pn:img/<uuid>` references into real images. Two strategies:
//
// 1. Data URI - inline `data:image/jpeg;base64,...` for single-file
//    exports (.md, .html) and JSON.
// 2. Bundled files - `images/<uuid>.jpg` alongside the note in zip
//    exports, with the body rewritten to use relative paths.

const IMAGE_URI_RE = /pn:img\/([0-9a-f-]{36})/g;

/**
 * Resolve all pn:img/ references in a body, returning a Map of uuid → Uint8Array.
 * Missing or failed images are silently skipped (logged to console).
 */
async function resolveImages(
  body: string,
  imageStore: ImageStore,
): Promise<Map<string, Uint8Array>> {
  const ids = extractImageIds(body);
  const resolved = new Map<string, Uint8Array>();
  await Promise.all(
    [...ids].map(async (uuid) => {
      try {
        const data = await imageStore.getImage(uuid);
        if (data) resolved.set(uuid, data);
        else console.warn(`Export: image ${uuid} not found, skipping`);
      } catch (err) {
        console.warn(`Export: failed to resolve image ${uuid}:`, err);
      }
    }),
  );
  return resolved;
}

/** Sniff image MIME from magic bytes. Stored images are JPEG or, when the
 *  source carried transparency, PNG (see imageProcessing.ts). Defaults to
 *  JPEG for any pre-existing/unknown blob. */
function sniffImageMime(bytes: Uint8Array): 'image/png' | 'image/jpeg' {
  return bytes.length >= 4 &&
    bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47
    ? 'image/png'
    : 'image/jpeg';
}

/** File extension matching the sniffed image format. */
function sniffImageExt(bytes: Uint8Array): 'png' | 'jpg' {
  return sniffImageMime(bytes) === 'image/png' ? 'png' : 'jpg';
}

/** Convert Uint8Array to base64 string. */
function uint8ToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

/** Replace pn:img/<uuid> refs with data URIs in a body string. */
function replaceWithDataUris(
  body: string,
  images: Map<string, Uint8Array>,
): string {
  return body.replace(IMAGE_URI_RE, (match, uuid: string) => {
    const data = images.get(uuid);
    if (!data) return match; // leave as-is if unresolved
    return `data:${sniffImageMime(data)};base64,${uint8ToBase64(data)}`;
  });
}

/** Resolve all pn:img/ references in a body to inline data URIs. No-op if no imageStore or no images. */
async function resolveBodyImages(body: string, imageStore?: ImageStore | null): Promise<string> {
  if (!imageStore) return body;
  const ids = extractImageIds(body);
  if (!ids.size) return body;
  const images = await resolveImages(body, imageStore);
  return replaceWithDataUris(body, images);
}

// ─── Attachment resolution helpers ────────────────────────────────────
//
// File attachments use `[name|size|mime](pn:file/<uuid>)` in note bodies.
// The full backup zip resolves these into real files in organized folders.

/** Matches attachment links: [name|size|mime](pn:file/<uuid>).
 *  Groups exclude newlines so the name can't span lines and swallow
 *  preceding task-checkbox text into the exported filename. */
const ATTACHMENT_LINK_RE = /\[([^|\n]*)\|([^|\n]*)\|([^\]\n]*)\]\(pn:file\/([0-9a-f-]{36})\)/g;

/** Extract attachment metadata from all pn:file/ links in a body. */
function extractAttachmentLinks(body: string): Map<string, { name: string; size: string; mime: string }> {
  const map = new Map<string, { name: string; size: string; mime: string }>();
  let m: RegExpExecArray | null;
  ATTACHMENT_LINK_RE.lastIndex = 0;
  while ((m = ATTACHMENT_LINK_RE.exec(body)) !== null) {
    map.set(m[4]!, { name: m[1]!, size: m[2]!, mime: m[3]! });
  }
  return map;
}

/** Determine export folder for an attachment based on MIME type. */
function attachmentFolder(mime: string): 'audio' | 'video' | 'docs' | 'files' {
  if (mime.startsWith('audio/')) return 'audio';
  if (mime.startsWith('video/')) return 'video';
  if (
    mime === 'application/pdf' ||
    mime.startsWith('application/msword') ||
    mime.startsWith('application/vnd.openxmlformats') ||
    mime.startsWith('application/vnd.apple.') ||
    mime === 'text/plain' ||
    mime === 'text/markdown' ||
    mime === 'text/csv' ||
    mime === 'text/rtf' ||
    mime === 'application/rtf'
  ) return 'docs';
  return 'files';
}

/** Get file extension from a filename, or guess from MIME. */
function extensionFromName(name: string, mime?: string): string {
  const dot = name.lastIndexOf('.');
  if (dot >= 0) return name.slice(dot + 1).toLowerCase();
  // Fallback: guess from MIME
  if (mime) {
    const sub = mime.split('/')[1];
    if (sub === 'mpeg') return 'mp3';
    if (sub === 'mp4') return 'mp4';
    if (sub === 'pdf') return 'pdf';
    if (sub === 'plain') return 'txt';
    if (sub) return sub.split('+')[0]!.split(';')[0]!;
  }
  return 'bin';
}

/** Sanitize an attachment's original name into a zip-safe filename and make
 *  sure it carries the right extension. Strips path separators and
 *  filesystem-illegal characters, collapses whitespace, and drops leading
 *  dots so the file can't become hidden or empty. */
function safeAttachmentName(name: string, ext: string): string {
  let safe = name
    .replace(/[/\\]+/g, '-')
    // eslint-disable-next-line no-control-regex
    .replace(/[\x00-\x1f<>:"|?*]+/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/^\.+/, '');
  if (!safe) safe = 'file';
  if (ext && !safe.toLowerCase().endsWith(`.${ext.toLowerCase()}`)) {
    safe = `${safe}.${ext}`;
  }
  return safe;
}

/** Per-export-unique filename for an attachment. On collision within the
 *  same folder, insert -2, -3, ... before the extension. Dedup is
 *  case-insensitive so it also holds on case-insensitive filesystems.
 *  `taken` accumulates the lowercased folder/name paths already used. */
function uniqueAttachmentName(
  name: string,
  ext: string,
  folder: string,
  taken: Set<string>,
): string {
  const base = safeAttachmentName(name, ext);
  const dot = base.lastIndexOf('.');
  const stem = dot > 0 ? base.slice(0, dot) : base;
  const tail = dot > 0 ? base.slice(dot) : '';
  let candidate = base;
  let n = 1;
  while (taken.has(`${folder}/${candidate}`.toLowerCase())) {
    n += 1;
    candidate = `${stem}-${n}${tail}`;
  }
  taken.add(`${folder}/${candidate}`.toLowerCase());
  return candidate;
}

/** Wrap a markdown link destination in <> when it contains a space or paren,
 *  which would otherwise break a bare link target. */
function mdLinkTarget(path: string): string {
  return /[ ()]/.test(path) ? `<${path}>` : path;
}

/** Manifest shape for the full backup zip. */
export interface BackupManifest {
  version: number;
  format: 'privacynotes-backup';
  exportedAt: string;
  noteCount: number;
  images: Record<string, { folder: string }>;
  attachments: Record<string, {
    name: string;
    mime: string;
    size: number;
    folder: string;
    file?: string;
  }>;
}

/**
 * Rewrite pn:img/ and pn:file/ refs in a note body to relative paths
 * for the full backup zip. Returns the rewritten body.
 */
function rewriteBodyForExport(
  body: string,
  resolvedImageExts: Map<string, string>,
  attachmentMap: Map<string, { path: string; name: string }>,
): string {
  // Rewrite images: pn:img/<uuid> → images/<uuid>.<ext> (jpg or png)
  let result = body.replace(IMAGE_URI_RE, (match, uuid: string) => {
    const ext = resolvedImageExts.get(uuid);
    if (!ext) return match;
    return `images/${uuid}.${ext}`;
  });
  // Rewrite attachments: [name|size|mime](pn:file/<uuid>) → [name](<folder/original name.ext>)
  result = result.replace(ATTACHMENT_LINK_RE, (match, _name: string, _size: string, _mime: string, uuid: string) => {
    const info = attachmentMap.get(uuid);
    if (!info) return match;
    return `[${info.name}](${mdLinkTarget(info.path)})`;
  });
  return result;
}

/** Cross-platform save: web anchor-download trick, native Save As dialog.
 *  Returns the save promise - every caller must propagate it, because on
 *  native this is the step that can fail (issue #193) and a dropped promise
 *  turns a failed export into a silent one. */
function downloadBlob(blob: Blob, filename: string): Promise<void> {
  return saveBlob(blob, filename);
}

// noteToMarkdown lives in ./noteMarkdown so the round-trip test can drive it
// without going through a browser download - see that file's header.

/**
 * Export a single note as .md. If an ImageStore is provided, pn:img/
 * references are resolved to inline data URIs so the .md file is
 * self-contained. Without an ImageStore, images are left as-is.
 */
export async function exportSingleMarkdown(
  note: LocalNote,
  imageStore?: ImageStore | null,
  folders: FolderDef[] = [],
): Promise<void> {
  // A vault item is written out readable here, and as its stored JSON in the
  // backup zip below. Nothing reads a single .md back as a vault item - it
  // carries no `type` line and `import/markdown.ts` reads none - so the blob
  // would restore nothing and hide every field. See vaultToMarkdown.
  const vault = vaultContent(note);
  // A bookmark exports as its bare autolink - readable as text in the
  // .md file, clickable everywhere markdown renders. See linkExportMarkdown.
  const body = linkExportMarkdown(note)
    ?? (vault
      ? vaultToMarkdown(vault)
      : await resolveBodyImages(note.body, imageStore));
  const md = noteToMarkdown({ ...note, body }, false, folderNamePath(folders, note.folderId));
  await downloadBlob(
    new Blob([md], { type: 'text/markdown;charset=utf-8' }),
    `${slugify(note.title)}.md`
  );
}

/**
 * Full backup zip - the canonical lossless backup format.
 *
 * Structure:
 *   manifest.json                    - format version, attachment metadata
 *   images/<uuid>.jpg                - all images
 *   audio/<uuid>.<ext>               - audio attachments
 *   video/<uuid>.<ext>               - video attachments
 *   docs/<uuid>.<ext>                - document attachments
 *   files/<uuid>.<ext>               - other file attachments
 *   <slug>.md                        - one markdown file per note (full frontmatter)
 *
 * Images and attachments are resolved one at a time (streamed) so peak
 * memory is one file + the growing zip buffer, not the entire account.
 */
async function buildFullBackupZip(
  notes: LocalNote[],
  imageStore?: ImageStore | null,
  attachmentStore?: AttachmentStore | null,
  onProgress?: (msg: string) => void,
  folders: FolderDef[] = [],
): Promise<Blob> {
  const { default: JSZip } = await import('jszip');
  const zip = new JSZip();

  // ── 1. Collect all unique image + attachment UUIDs across all notes ──

  const allImageIds = new Set<string>();
  // Map<uuid, { name, size, mime }> - merged from all notes
  const allAttLinks = new Map<string, { name: string; size: string; mime: string }>();

  for (const note of notes) {
    for (const id of extractImageIds(note.body)) allImageIds.add(id);
    for (const [uuid, meta] of extractAttachmentLinks(note.body)) {
      if (!allAttLinks.has(uuid)) allAttLinks.set(uuid, meta);
    }
  }

  // ── 2. Resolve and add images to zip ────────────────────────────────

  const resolvedImageExts = new Map<string, string>();
  const manifestImages: BackupManifest['images'] = {};

  if (imageStore && allImageIds.size > 0) {
    let done = 0;
    for (const uuid of allImageIds) {
      onProgress?.(i18n.t('importExport:exportProgress.imagesProgress', { done: ++done, total: allImageIds.size }));
      try {
        const data = await imageStore.getImage(uuid);
        if (data) {
          const ext = sniffImageExt(data);
          zip.file(`images/${uuid}.${ext}`, data);
          resolvedImageExts.set(uuid, ext);
          manifestImages[uuid] = { folder: 'images' };
        } else {
          console.warn(`Export: image ${uuid} not found, skipping`);
        }
      } catch (err) {
        console.warn(`Export: failed to resolve image ${uuid}:`, err);
      }
    }
  }

  // ── 3. Resolve and add attachments to zip ───────────────────────────

  // Map<uuid, { path, name }> - path is the zip-relative file path (used to
  // rewrite body links), name is the original display name (link text).
  const attachmentMap = new Map<string, { path: string; name: string }>();
  const manifestAttachments: BackupManifest['attachments'] = {};
  // Lowercased folder/name paths already written, so two attachments sharing
  // a name get -2, -3 suffixes instead of overwriting each other.
  const takenAttPaths = new Set<string>();

  if (attachmentStore && allAttLinks.size > 0) {
    let done = 0;
    for (const [uuid] of allAttLinks) {
      onProgress?.(i18n.t('importExport:exportProgress.filesProgress', { done: ++done, total: allAttLinks.size }));
      try {
        const att = await attachmentStore.getAttachment(uuid);
        if (att) {
          const folder = attachmentFolder(att.meta.mime);
          const ext = extensionFromName(att.meta.name, att.meta.mime);
          const filename = uniqueAttachmentName(att.meta.name, ext, folder, takenAttPaths);
          const path = `${folder}/${filename}`;
          zip.file(path, att.data);
          attachmentMap.set(uuid, { path, name: att.meta.name });
          manifestAttachments[uuid] = {
            name: att.meta.name,
            mime: att.meta.mime,
            size: att.meta.size,
            folder,
            file: filename,
          };
        } else {
          console.warn(`Export: attachment ${uuid} not found, skipping`);
        }
      } catch (err) {
        console.warn(`Export: failed to resolve attachment ${uuid}:`, err);
      }
    }
  }

  // ── 4. Add notes as .md files with rewritten body refs ──────────────

  onProgress?.(i18n.t('importExport:exportProgress.building'));

  const stems = zipEntryStems(notes);
  for (const [i, note] of notes.entries()) {
    const stem = stems[i]!;

    const body = rewriteBodyForExport(note.body, resolvedImageExts, attachmentMap);
    zip.file(`${stem}.md`, noteToMarkdown({ ...note, body }, true, folderNamePath(folders, note.folderId)));
  }

  // ── 5. Add manifest.json ────────────────────────────────────────────

  const manifest: BackupManifest = {
    version: 2,
    format: 'privacynotes-backup',
    exportedAt: new Date().toISOString(),
    noteCount: notes.length,
    images: manifestImages,
    attachments: manifestAttachments,
  };
  zip.file('manifest.json', JSON.stringify(manifest, null, 2));

  // ── 6. Generate and download ────────────────────────────────────────

  onProgress?.(i18n.t('importExport:exportProgress.compressing'));
  return zip.generateAsync({ type: 'blob' });
}

export async function exportAllMarkdownZip(
  notes: LocalNote[],
  imageStore?: ImageStore | null,
  attachmentStore?: AttachmentStore | null,
  onProgress?: (msg: string) => void,
  folders: FolderDef[] = [],
): Promise<void> {
  const blob = await buildFullBackupZip(notes, imageStore, attachmentStore, onProgress, folders);
  const stamp = new Date().toISOString().slice(0, 10);
  await downloadBlob(blob, `privacynotes-backup-${stamp}.zip`);
}

/**
 * The full backup, sealed: the exact zip exportAllMarkdownZip writes,
 * encrypted as one blob under the sync encryption key (.pnbackupz,
 * format in packages/shared/src/backup.ts). It opens with the phrase on
 * any device, like the .pnbackup - and unlike it, carries the blobs.
 */
export async function exportEncryptedFullBackup(
  notes: LocalNote[],
  imageStore: ImageStore | null,
  attachmentStore: AttachmentStore | null,
  encryptionKey: Uint8Array,
  onProgress?: (msg: string) => void,
  folders: FolderDef[] = [],
): Promise<void> {
  const blob = await buildFullBackupZip(notes, imageStore, attachmentStore, onProgress, folders);
  const sealed = encodeZipBackup(new Uint8Array(await blob.arrayBuffer()), encryptionKey);
  const stamp = new Date().toISOString().slice(0, 10);
  await downloadBlob(
    new Blob([sealed as BlobPart], { type: 'application/octet-stream' }),
    `privacynotes-backup-${stamp}.pnbackupz`,
  );
}

/**
 * JSON text backup (v3). All note metadata, no image/attachment blobs.
 *
 * Body text keeps raw pn:img/ and pn:file/ references as-is so the
 * file is small and fast to generate regardless of account size.
 * For a full backup with blobs, use exportAllMarkdownZip.
 */
export async function exportAllJson(
  notes: LocalNote[],
  folders: FolderDef[] = [],
): Promise<void> {
  // Same payload builder as the encrypted .pnbackup, folders included since
  // 2026-08-26. It used to pass none, which meant every note carried a
  // `folderId` pointing at a folder the file did not contain: a restore had
  // the membership and no tree to hang it on. The field is additive, so an
  // older reader ignores it.
  const payload = buildBackupPayload(notes, folders);
  const blob = new Blob([JSON.stringify(payload, null, 2)], {
    type: 'application/json',
  });
  const stamp = new Date().toISOString().slice(0, 10);
  await downloadBlob(blob, `privacynotes-backup-${stamp}.json`);
}

/**
 * Bookmarks as a Netscape bookmark file - the one format Chrome, Firefox,
 * Safari and Edge all import. Writes the folder tree with them, minus the
 * importer's own "Bookmarks" root, so an export and a re-import land the
 * same shape they started in. See ./bookmarksNetscape for the format.
 */
export async function exportBookmarksHtml(
  notes: LocalNote[],
  folders: FolderDef[]
): Promise<void> {
  const bookmarks = notes.filter(
    (n) => n.type === 'link' && n.deleted !== 1 && n.trashed !== 1
  );
  // Loaded on demand, the way jszip is above: the writer is only ever
  // reached by a click on the export row, and export.ts sits on the boot
  // path, where the chunk budget is measured.
  const { buildBookmarksHtml } = await import('./bookmarksNetscape');
  const html = buildBookmarksHtml(bookmarks, folders);
  const stamp = new Date().toISOString().slice(0, 10);
  await downloadBlob(
    new Blob([html], { type: 'text/html;charset=utf-8' }),
    `privacynotes-bookmarks-${stamp}.html`
  );
}

// ─── Printable HTML export ─────────────────────────────────────────────
//
// Pure client-side: renders the note's markdown body into a standalone
// HTML document with embedded print CSS, then hands the user a .html
// download. Nothing about this file ever hits a PrivacyNotes server.
// The markdown → HTML converter lives in markdownRender.ts and is
// shared with the Burn-After-Reading viewer.

function formatDate(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleString(intlLocale(), {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return iso;
  }
}

/**
 * Build a standalone printable HTML document for one note.
 *
 * - White background, black serif body, readable line length.
 * - @media print rules so File → Print produces A4-friendly output
 *   with no browser chrome and a sensible title in the header.
 * - Embedded CSS only (no external fonts, no CDN calls) so the file
 *   works fully offline after download.
 */
/** Render a vault item's fields as a table instead of its raw JSON body. */
function renderVaultHtml(vault: VaultContent): string {
  let html = '<table class="vault-fields">' +
    vault.fields
      .map(
        (f) =>
          `<tr><th>${escapeHtml(f.label)}</th><td${f.mono ? ' class="mono"' : ''}>${escapeHtml(f.value)}</td></tr>`,
      )
      .join('') +
    '</table>';
  if (vault.notes) {
    html += `<div class="vault-notes"><strong>${escapeHtml(vault.notesLabel)}</strong><p>${escapeHtml(vault.notes)}</p></div>`;
  }
  return html;
}

/**
 * Two notes on the vault-table CSS in the stylesheet below, both learned the
 * hard way.
 *
 * The frame is drawn by the TABLE box and every line inside it is a cell's top
 * or right edge, never a bottom one. Collapsed borders put the last row's
 * bottom line half outside that row's box, and a print engine that paginates
 * drops the outside half - which is how the PDF lost the line that closes the
 * table while the same document looked right on screen.
 *
 * The `.content` prefix on those rules is load-bearing. `.content table`
 * earlier in the sheet is more specific than a bare `.vault-fields`, so
 * without it that rule keeps winning `border-collapse` and no frame appears.
 */
function buildNoteHtmlDocument(note: LocalNote, folderPath: string[] = []): string {
  const title = note.title.trim() || 'Untitled';
  const vault = vaultContent(note);
  const linkMd = linkExportMarkdown(note);
  const bodyHtml = linkMd
    ? renderMarkdown(linkMd)
    : vault
      ? renderVaultHtml(vault)
      : renderMarkdown(note.body || '');
  const tagsHtml =
    note.tags.length > 0
      ? `<div class="tags">${note.tags
          .map((t) => `<span class="tag">#${escapeHtml(t)}</span>`)
          .join('')}</div>`
      : '';
  // Where the note lived. A printed page that says only "Kyoto" loses the
  // one piece of context the sidebar was giving it for free.
  const folderHtml =
    folderPath.length > 0
      ? `<div class="note-folder">${escapeHtml(folderPath.join(' / '))}</div>`
      : '';
  // A printed journal entry without its mood, sleep and step count is
  // missing half of what the entry recorded. HTML and print are terminal
  // formats (nothing reads them back), so this is the readable rendering;
  // the machine-readable copy rides in the markdown front-matter instead.
  const rows = trackerRows(note.trackers, loadLocalSettings().trackerSettings.weightUnit);
  const trackersHtml =
    rows.length > 0
      ? `<section class="trackers">
      <h2 class="trackers-title">${escapeHtml(trackerHeading())}</h2>
      <dl class="tracker-list">${rows
        .map(
          (r) =>
            `<div class="tracker-row"><dt>${escapeHtml(r.label)}</dt><dd>${escapeHtml(r.value)}</dd></div>`,
        )
        .join('')}</dl>
    </section>`
      : '';

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>${escapeHtml(title)}</title>
<style>
  :root {
    color-scheme: light;
    /* The editor's own two stacks, so an exported note reads as the note
       that was written. The body used to be Georgia while every other
       element here was already sans, which is the mismatch that made the
       export look like a different document from the editor rather than a
       printed version of it. Both stacks are what the app computes
       (Tailwind's defaults, no webfont anywhere) - change them together
       with the app or the two drift apart again.
       Spec: ops/docs/design-decisions.md (export typography) */
    --pn-sans: -apple-system, "system-ui", "Segoe UI", Roboto, "Helvetica Neue", "Noto Sans", Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol", "Noto Color Emoji";
    --pn-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  }
  html, body {
    margin: 0;
    padding: 0;
    background: #ffffff;
    color: #111111;
    font-family: var(--pn-sans);
    font-size: 16px;
    line-height: 1.7;
    /* The app renders with class="antialiased" on its own body. Without
       the same two declarations the very same stack renders heavier here
       than in the editor on macOS, which reads as a different, muddier
       face. No backticks in this comment on purpose: the whole stylesheet
       is one template literal and a backtick ends it. */
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
  }
  .page {
    max-width: 720px;
    margin: 0 auto;
    padding: 48px 32px 64px;
  }
  header.note-head {
    border-bottom: 1px solid #e5e5e5;
    padding-bottom: 16px;
    margin-bottom: 24px;
  }
  h1.note-title {
    font-size: 2.4rem;
    line-height: 1.2;
    margin: 0 0 8px;
    font-weight: 700;
  }
  .meta {
    font-size: 0.85rem;
    color: #666;
    font-family: var(--pn-sans);
  }
  .tags {
    margin-top: 8px;
    font-family: var(--pn-sans);
    font-size: 0.8rem;
  }
  .tag {
    display: inline-block;
    margin-right: 6px;
    color: #555;
  }
  .content h1, .content h2, .content h3,
  .content h4, .content h5, .content h6 {
    font-family: var(--pn-sans);
    font-weight: 600;
    line-height: 1.3;
    margin-top: 1.6em;
    margin-bottom: 0.4em;
    color: #000;
  }
  /* The editor's heading ladder, same six ratios against body copy (the
     editor anchors on --pn-editor-body, here body copy is the 16px root).
     H4, H5 and H6 all read 1rem until v0.422.0, so three of the six levels
     exported as the same size as each other AND as the paragraph under
     them. The note title above sits a step clear of a body H1.
     Spec: ops/docs/design-decisions.md (editor heading scale) */
  .content h1 { font-size: 1.867rem; }
  .content h2 { font-size: 1.667rem; }
  .content h3 { font-size: 1.493rem; }
  .content h4 { font-size: 1.333rem; }
  .content h5 { font-size: 1.2rem; }
  .content h6 { font-size: 1.067rem; }
  .content {
    /* A pasted URL or an unbroken long word must wrap, not push the page
       sideways (or off the printable area). Inherited, so it covers
       paragraphs, list items, links and table cells alike. */
    overflow-wrap: break-word;
  }
  /* Per-block direction resolution, mirroring the editor's rule in
     index.css: each block reads its own text and resolves LTR or RTL from
     its first strong character, so an Arabic paragraph right-aligns in the
     export and the PDF exactly as it does in the editor. Explicit
     text-align styles keep winning on top, unchanged. */
  .content p, .content h1, .content h2, .content h3,
  .content h4, .content h5, .content h6, .content li {
    unicode-bidi: plaintext;
  }
  /* Code stays LTR always, even inside an RTL note - same as the editor:
     identifiers and syntax are not bidi text, and isolate keeps a code span
     from perturbing the surrounding RTL runs. */
  .content pre, .content code {
    direction: ltr;
    unicode-bidi: isolate;
  }
  .content p {
    margin: 0 0 1em;
  }
  .content ul, .content ol {
    margin: 0 0 1em 1.5em;
    padding: 0;
  }
  .content li {
    margin-bottom: 0.25em;
  }
  .content blockquote {
    border-left: 3px solid #ccc;
    margin: 0 0 1em;
    padding: 0.1em 0 0.1em 1em;
    color: #444;
    font-style: italic;
  }
  .content a {
    color: #2060c0;
    text-decoration: underline;
  }
  /* Highlights. The document had no rule at all, so a plain ==highlight==
     fell back to the browser's flat yellow instead of the wash the editor
     shows. These values mirror the light-theme mark rule in index.css -
     the exported page is always a white page, so there is no dark pair. A
     COLORED highlight carries its own inline background-color, which beats
     this rule, so one declaration serves both. */
  .content mark {
    background: rgb(250 224 108 / 0.55);
    color: inherit;
    border-radius: 2px;
    padding: 0 0.1em;
    -webkit-box-decoration-break: clone;
    box-decoration-break: clone;
  }
  .content code {
    font-family: var(--pn-mono);
    background: #f3f3f3;
    padding: 0.1em 0.35em;
    border-radius: 3px;
    font-size: 0.92em;
  }
  /* Code blocks are a dark panel with the editor's own syntax palette -
     the editor's panel is dark in BOTH app themes, so the export matches
     what the note looks like where it was written. */
  .content pre {
    background: #262626;
    color: #e5e5e5;
    border: none;
    padding: 12px 16px;
    overflow-x: auto;
    border-radius: 6px;
    margin: 0 0 1em;
  }
  .content pre code {
    background: transparent;
    padding: 0;
    font-size: 0.9em;
  }
  /* hljs token colors, mirroring the hand-picked palette in index.css
     (the .prose pre .hljs-* block) - change the two together. */
  .content pre .hljs-comment, .content pre .hljs-quote { color: #8b949e; font-style: italic; }
  .content pre .hljs-keyword, .content pre .hljs-selector-tag, .content pre .hljs-meta { color: #c297ff; }
  .content pre .hljs-string, .content pre .hljs-regexp, .content pre .hljs-addition { color: #7ee787; }
  .content pre .hljs-number, .content pre .hljs-literal, .content pre .hljs-deletion { color: #ffa657; }
  .content pre .hljs-title, .content pre .hljs-section { color: #79c0ff; }
  .content pre .hljs-title.class_, .content pre .hljs-type, .content pre .hljs-built_in { color: #f2cc60; }
  .content pre .hljs-attr, .content pre .hljs-attribute, .content pre .hljs-variable,
  .content pre .hljs-template-variable, .content pre .hljs-selector-class, .content pre .hljs-selector-id { color: #6fd7e4; }
  .content pre .hljs-symbol, .content pre .hljs-bullet { color: #f1a5c0; }
  .content pre .hljs-emphasis { font-style: italic; }
  .content pre .hljs-strong { font-weight: 600; }
  .content img {
    max-width: 100%;
    border-radius: 4px;
    margin: 0.5em 0;
  }
  .content table {
    border-collapse: collapse;
    width: 100%;
    /* Equal columns, matching the editor. Sizing from content here would give
       the same table different proportions on paper than on screen. */
    table-layout: fixed;
    margin: 1em 0;
  }
  .content th, .content td {
    border: 1px solid #d4d4d4;
    padding: 6px 10px;
    text-align: left;
  }
  .content th {
    font-weight: 600;
    background: #f8f8f8;
  }
  .content hr {
    border: none;
    border-top: 1px solid #ddd;
    margin: 2em 0;
  }
  /* Frame on the table box, inner lines on cell top/right edges only, and
     the .content prefix is required - see the note above this function. */
  .content .vault-fields {
    border-collapse: separate;
    border-spacing: 0;
    border: 1px solid #d4d4d4;
    width: 100%;
    margin: 0 0 1.5em;
    table-layout: fixed;
  }
  .content .vault-fields th {
    width: 140px;
    font-weight: 600;
    text-align: left;
    padding: 8px 12px;
    border: none;
    border-right: 1px solid #d4d4d4;
    background: #f8f8f8;
    font-family: var(--pn-sans);
    font-size: 0.9em;
    vertical-align: top;
  }
  .content .vault-fields td {
    padding: 8px 12px;
    border: none;
    word-break: break-word;
    overflow-wrap: break-word;
  }
  .content .vault-fields tr + tr th,
  .content .vault-fields tr + tr td {
    border-top: 1px solid #d4d4d4;
  }
  .content .vault-fields td.mono {
    font-family: var(--pn-mono);
    font-size: 0.85em;
    word-break: break-all;
  }
  .vault-notes {
    margin-top: 1em;
  }
  .vault-notes strong {
    display: block;
    margin-bottom: 4px;
    font-family: var(--pn-sans);
    font-size: 0.9em;
  }
  .vault-notes p {
    margin: 0;
    white-space: pre-wrap;
  }
  summary.pn-callout-summary::-webkit-details-marker { display: none }
  summary.pn-callout-summary { list-style: none }
  details.pn-callout:not([open]) > summary .pn-arrow-in { display: none }
  details.pn-callout:not([open]) > summary .pn-arrow-out { display: inline !important }
  @media print {
    @page {
      size: A4;
      margin: 0;
    }
    html, body {
      background: #ffffff;
      color: #000;
      font-size: 12pt;
      margin: 0;
      padding: 0;
    }
    .page {
      max-width: none;
      margin: 0;
      padding: 20mm;
      -webkit-box-decoration-break: clone;
      box-decoration-break: clone;
    }
    .content a {
      color: #000;
      text-decoration: underline;
    }
    .content code {
      background: #f3f3f3 !important;
    }
    /* The dark code panel and its token colors survive printing - print
       engines drop backgrounds unless told not to, same as the callout and
       highlight rules below. The inline-code chip above stays light. */
    .content pre, .content pre code {
      background: #262626 !important;
      -webkit-print-color-adjust: exact;
      print-color-adjust: exact;
    }
    .content pre code {
      background: transparent !important;
    }
    /* Checkbox fill and check glyph are backgrounds too. */
    .content input[type="checkbox"] {
      -webkit-print-color-adjust: exact;
      print-color-adjust: exact;
    }
    .content pre, .content blockquote, .content img,
    .content ul, .content ol, .content table {
      break-inside: avoid;
    }
    details.pn-callout { break-inside: avoid; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    /* Print engines drop background colors unless asked not to, which is why
       the callout rule above exists - and why a highlight printed as plain
       text, its whole point gone, both before the palette shipped and after. */
    .content mark { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    details.pn-callout:not([open]) > .pn-callout-body { display: block !important; }
    .content h1, .content h2, .content h3,
    .content h4, .content h5, .content h6 {
      break-after: avoid;
    }
    .content p, .content li {
      orphans: 3;
      widows: 3;
    }
  }
  .note-folder {
    margin-top: 0.35rem;
    font-family: var(--pn-sans);
    font-size: 0.8rem;
    color: #6b6660;
  }
  /* Trackers - a quiet data block between the header and the prose, so a
     printed journal entry carries what the pill row shows in the app. */
  .trackers {
    margin: 0 0 1.75rem;
    padding: 0.85rem 1rem;
    border: 1px solid #e6e3dd;
    border-radius: 8px;
    background: #fbfaf8;
    break-inside: avoid;
    page-break-inside: avoid;
  }
  .trackers-title {
    margin: 0 0 0.6rem;
    font-family: var(--pn-sans);
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: #6b6660;
  }
  .tracker-list {
    margin: 0;
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr));
    gap: 0.4rem 1.25rem;
  }
  .tracker-row {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    gap: 0.75rem;
    border-bottom: 1px solid #eeece7;
    padding-bottom: 0.3rem;
  }
  .tracker-row dt {
    font-family: var(--pn-sans);
    font-size: 0.82rem;
    color: #6b6660;
  }
  .tracker-row dd {
    margin: 0;
    font-family: var(--pn-sans);
    font-size: 0.82rem;
    font-weight: 600;
    color: #1c1917;
    text-align: end;
    font-variant-numeric: tabular-nums;
  }
</style>
</head>
<body>
  <div class="page">
    <header class="note-head">
      <h1 class="note-title">${escapeHtml(title)}</h1>
      <div class="meta">${escapeHtml(formatDate(note.updatedAt))}</div>
      ${folderHtml}
      ${tagsHtml}
    </header>
    ${trackersHtml}
    <article class="content">
${bodyHtml}
    </article>
  </div>
</body>
</html>
`;
}

/**
 * Export a single note as self-contained .html with images embedded
 * as data URIs. Falls back to pn:img/ refs if no ImageStore provided.
 */
export async function exportSingleHtml(
  note: LocalNote,
  imageStore?: ImageStore | null,
  folders: FolderDef[] = [],
): Promise<void> {
  let body = await resolveBodyImages(note.body, imageStore);
  // Fetch and inline any remaining same-origin image paths
  // (e.g. /onboarding/japan.jpg) so the .html is self-contained
  // when opened from disk.
  body = await inlineSameOriginImages(body);
  // KaTeX and lowlight are fetched on demand, only for a body that needs them.
  await prepareRender(body);
  let html = buildNoteHtmlDocument({ ...note, body }, folderNamePath(folders, note.folderId));
  // Inline favicon images so the .html works fully offline.
  html = await inlineRenderedFavicons(html);
  await downloadBlob(
    new Blob([html], { type: 'text/html;charset=utf-8' }),
    `${slugify(note.title)}.html`
  );
}

/**
 * Bulk HTML export: one self-contained .html per note, zipped.
 * Each file is identical in layout to the single-note export -
 * white page, serif body, embedded print CSS, no external calls.
 */
/**
 * Bulk HTML zip. Images are embedded as data URIs in each .html file
 * so every file is self-contained and works offline.
 */
export async function exportAllHtmlZip(
  notes: LocalNote[],
  imageStore?: ImageStore | null,
  folders: FolderDef[] = [],
): Promise<void> {
  const { default: JSZip } = await import('jszip');
  const zip = new JSZip();
  const stems = zipEntryStems(notes);
  for (const [i, note] of notes.entries()) {
    const filename = `${stems[i]!}.html`;

    let body = await resolveBodyImages(note.body, imageStore);
    body = await inlineSameOriginImages(body);
    await prepareRender(body);
    let noteHtml = buildNoteHtmlDocument({ ...note, body }, folderNamePath(folders, note.folderId));
    noteHtml = await inlineRenderedFavicons(noteHtml);
    zip.file(filename, noteHtml);
  }
  const blob = await zip.generateAsync({ type: 'blob' });
  const stamp = new Date().toISOString().slice(0, 10);
  await downloadBlob(blob, `privacynotes-backup-${stamp}-html.zip`);
}

declare global {
  interface Window {
    /** Installed by MainActivity.kt in the Android app; absent everywhere else. */
    __pnPrint?: { print: (html: string, jobName: string) => void };
  }
}

/**
 * Hand the document to the OS print UI in the native apps.
 *
 * Three of the four native webviews ignore JavaScript's `window.print()`: the
 * call returns without opening anything and without an error, so the iframe
 * path below printed nothing at all in the macOS, iOS and Android apps. Each
 * needs its own native route, and they are not reachable the same way:
 * macOS and iOS go through Rust (packages/desktop/src-tauri/src/print.rs),
 * while Android has no Rust route to take - wry's Android `print()` is an
 * empty stub - so it goes through the `__pnPrint` bridge in MainActivity.kt.
 * Either way the document handed over is the one built above, so a printout
 * looks the same everywhere.
 *
 * False means "print it yourself": the web build, and the Windows and Linux
 * apps, whose webviews do implement `window.print()` and are left on that path.
 */
async function printViaOs(html: string, jobName: string): Promise<boolean> {
  if (detectPlatform() === 'web') return false;
  const android = window.__pnPrint;
  if (android) {
    android.print(html, jobName);
    return true;
  }
  try {
    const { invoke } = await import('@tauri-apps/api/core');
    await invoke('print_html', { html, jobName });
    return true;
  } catch {
    return false;
  }
}

/**
 * Print a single note (opens the print dialog → "Save as PDF").
 *
 * Renders the same standalone HTML document used by exportSingleHtml, then
 * either hands it to the OS (native Apple apps) or opens it in a hidden iframe
 * and triggers window.print(). The @media print CSS in buildNoteHtmlDocument
 * produces A4-friendly output either way.
 */
export async function printNote(
  note: LocalNote,
  imageStore?: ImageStore | null,
  folders: FolderDef[] = [],
): Promise<void> {
  let body = await resolveBodyImages(note.body, imageStore);
  body = await inlineSameOriginImages(body);
  // KaTeX and lowlight are fetched on demand, only for a body that needs them.
  await prepareRender(body);
  let html = buildNoteHtmlDocument({ ...note, body }, folderNamePath(folders, note.folderId));
  // Inline favicons so they appear in the printed/PDF output.
  html = await inlineRenderedFavicons(html);

  if (await printViaOs(html, note.title.trim() || 'Untitled')) return;

  // Use a hidden iframe so the print dialog targets only the note,
  // not the app itself.
  const iframe = document.createElement('iframe');
  iframe.style.position = 'fixed';
  iframe.style.left = '-9999px';
  iframe.style.top = '-9999px';
  iframe.style.width = '0';
  iframe.style.height = '0';
  document.body.appendChild(iframe);

  const iframeDoc = iframe.contentDocument ?? iframe.contentWindow?.document;
  if (!iframeDoc) {
    document.body.removeChild(iframe);
    return;
  }

  iframeDoc.open();
  iframeDoc.write(html);
  iframeDoc.close();

  // Wait for every <img> in the iframe to finish decoding (data-URI
  // favicons and inlined images need a decode pass before the print
  // dialog captures the page), then print.
  //
  // Run-once guard: print() fires either when images finish loading OR
  // from the safety timeout. Without the guard both paths fire, so the
  // print dialog reopens on its own right after the user dismisses the
  // first one. printed=true + clearing the timer makes print() happen
  // exactly once.
  let printed = false;
  let safetyTimer: ReturnType<typeof setTimeout> | undefined;
  const doPrint = () => {
    if (printed) return;
    printed = true;
    if (safetyTimer) clearTimeout(safetyTimer);
    try {
      iframe.contentWindow?.print();
    } finally {
      setTimeout(() => document.body.removeChild(iframe), 1000);
    }
  };

  const waitForImages = () => {
    const images = Array.from(iframeDoc!.querySelectorAll('img'));
    const pending = images.filter((img) => !img.complete);
    if (pending.length === 0) { doPrint(); return; }
    let loaded = 0;
    const check = () => { if (++loaded >= pending.length) doPrint(); };
    for (const img of pending) {
      img.addEventListener('load', check);
      img.addEventListener('error', check);
    }
    // Safety timeout - don't block indefinitely on broken images.
    safetyTimer = setTimeout(doPrint, 3000);
  };

  if (iframeDoc.readyState === 'complete') {
    waitForImages();
  } else {
    iframe.onload = () => waitForImages();
  }
}

// ─── Encrypted backup export/import ───────────────────────────────────
//
// Binary format: [24-byte nonce][xchacha20poly1305 ciphertext]
// The plaintext is the same JSON structure as exportAllJson.
// Extension: .pnbackup (PrivacyNotes backup - distinct from .json
// so users don't confuse encrypted and plaintext exports).
//
// The format itself (payload assembly, encode, decode) lives in
// packages/shared/src/backup.ts so tools/backup-kat.mjs can test the real
// code headlessly; this file only adds the browser glue: file download and
// translated error messages.

/**
 * Encrypted text backup. All note metadata, no image/attachment blobs.
 *
 * Same payload structure as JSON v3 but encrypted with xchacha20poly1305.
 * Binary format: [24-byte nonce][ciphertext]. See packages/shared/src/backup.ts.
 */
export async function exportEncryptedBackup(
  notes: LocalNote[],
  encryptionKey: Uint8Array,
  /** Folder definitions (userSettings.folders) so a restore can rebuild
   *  the tree, not just the per-note membership pointers. */
  folders: FolderDef[] = []
): Promise<void> {
  const out = encodeBackup(buildBackupPayload(notes, folders), encryptionKey);

  const stamp = new Date().toISOString().slice(0, 10);
  await downloadBlob(
    new Blob([out as BlobPart], { type: 'application/octet-stream' }),
    `privacynotes-backup-${stamp}.pnbackup`
  );
}

/** Decoded .pnbackup contents. Alias of the shared format type; kept under
 *  the old name for existing importers. */
export type DecryptedBackup = BackupPayload;

/**
 * Decrypt a .pnbackup file with the user's encryption key.
 *
 * Every failure here is translated before it leaves. The raw ones are library
 * strings written for cryptographers - noble-ciphers says "invalid tag" for
 * both a wrong key and a damaged file - and that text was reaching users
 * verbatim in the import dialog (issue #193). Which of the two happened is not
 * knowable from the failure itself, by design: an authentication tag that does
 * not verify tells you nothing about why. So the message names both causes and
 * leads with the one that is far more common, restoring into the wrong account.
 */
export function decryptBackup(
  data: Uint8Array,
  encryptionKey: Uint8Array
): DecryptedBackup {
  try {
    return decodeBackup(data, encryptionKey);
  } catch (e) {
    // Truncated below one nonce + one tag. Our own check covers < 25 bytes;
    // noble rejects the 25..39 range with a length message of its own. Both
    // mean the same thing to a user, and an empty file lands here.
    const msg = e instanceof Error ? e.message : '';
    if (msg === BACKUP_TOO_SMALL || msg.includes('tagLength')) {
      throw new Error(
        i18n.t('importExport:decryptErrors.tooSmall', { size: data.length }),
      );
    }
    throw new Error(i18n.t('importExport:decryptErrors.notThisAccount'));
  }
}

// ─── Bitwarden-compatible vault export ───────────────────────────────
//
// Exports only vault items (login, card, ssh-key) in Bitwarden's
// unencrypted JSON format. The output is importable by Bitwarden,
// 1Password, KeePass, and most other password managers.
//
// Bitwarden item types: 1=Login, 2=SecureNote, 3=Card, 5=SshKey
// (type 4=Identity is not used here - we don't store identities).

interface BwExportUri {
  match: null;
  uri: string;
}

interface BwExportLogin {
  uris: BwExportUri[];
  username: string;
  password: string;
  totp: string | null;
}

interface BwExportCard {
  cardholderName: string;
  brand: string;
  number: string;
  expMonth: string;
  expYear: string;
  code: string;
}

interface BwExportSshKey {
  privateKey: string;
  publicKey: string;
  keyFingerprint: string;
}

interface BwExportItem {
  id: string;
  organizationId: null;
  folderId: null;
  type: number;
  reprompt: number;
  name: string;
  notes: string;
  favorite: boolean;
  login?: BwExportLogin | null;
  card?: BwExportCard | null;
  sshKey?: BwExportSshKey | null;
  creationDate: string;
  revisionDate: string;
}

interface BwExportPayload {
  encrypted: false;
  folders: [];
  items: BwExportItem[];
}

/**
 * Export vault items (logins, cards, SSH keys) in Bitwarden's
 * unencrypted JSON format. Non-vault notes are excluded.
 */
export async function exportVaultBitwarden(notes: LocalNote[]): Promise<void> {
  const vaultNotes = notes.filter(
    (n) => n.type === 'login' || n.type === 'card' || n.type === 'ssh-key',
  );

  const items: BwExportItem[] = vaultNotes.map((note) => {
    const base: BwExportItem = {
      id: note.id,
      organizationId: null,
      folderId: null,
      type: 1,
      reprompt: note.pinProtected === 1 ? 1 : 0,
      name: note.title || 'Untitled',
      notes: '',
      favorite: note.starred === 1,
      creationDate: note.createdAt,
      revisionDate: note.updatedAt,
    };

    if (note.type === 'login') {
      const login = parseLoginBody(note.body);
      base.type = 1;
      base.notes = login.notes;
      base.login = {
        uris: login.url ? [{ match: null, uri: login.url }] : [],
        username: login.username,
        password: login.password,
        totp: login.totp || null,
      };
    } else if (note.type === 'card') {
      const card = parseCardBody(note.body);
      base.type = 3;
      base.notes = card.notes;
      base.card = {
        cardholderName: card.cardholderName,
        brand: detectCardNetwork(card.cardNumber),
        number: card.cardNumber,
        expMonth: card.expMonth,
        expYear: card.expYear,
        code: card.cvv,
      };
    } else if (note.type === 'ssh-key') {
      const key = parseSshKeyBody(note.body);
      base.type = 5;
      base.notes = key.notes;
      base.sshKey = {
        privateKey: key.privateKey,
        publicKey: key.publicKey,
        keyFingerprint: '',
      };
    }

    return base;
  });

  const payload: BwExportPayload = {
    encrypted: false,
    folders: [],
    items,
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], {
    type: 'application/json',
  });
  const stamp = new Date().toISOString().slice(0, 10);
  await downloadBlob(blob, `privacynotes-vault-${stamp}.json`);
}
