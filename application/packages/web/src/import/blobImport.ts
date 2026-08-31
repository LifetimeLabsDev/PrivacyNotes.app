import { db } from '../db';
import type { AttachmentMeta } from '../attachmentStore';
import { formatFileSize } from '../attachmentValidation';

/* ------------------------------------------------------------------ */
/* SHA-256 helper (was duplicated in appleNotes, googleKeep, privacynotes) */
/* ------------------------------------------------------------------ */

export async function sha256hex(data: Uint8Array): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', data as ArrayBufferView<ArrayBuffer>);
  const arr = new Uint8Array(buf);
  let hex = '';
  for (const b of arr) hex += b.toString(16).padStart(2, '0');
  return hex;
}

/* ------------------------------------------------------------------ */
/* Shared MIME-from-extension lookup                                   */
/* ------------------------------------------------------------------ */

/** MIME from file extension. Sources attach arbitrary files, so the
 *  fallback is a generic binary rather than a skip. Shared by the
 *  Notesnook and UpNote importers. */
export function mimeFromExt(path: string): string {
  const ext = path.split('.').pop()?.toLowerCase() ?? '';
  const map: Record<string, string> = {
    png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif',
    webp: 'image/webp', svg: 'image/svg+xml', bmp: 'image/bmp', avif: 'image/avif',
    heic: 'image/heic', tiff: 'image/tiff', ico: 'image/x-icon',
    pdf: 'application/pdf', zip: 'application/zip', json: 'application/json',
    txt: 'text/plain', csv: 'text/csv', md: 'text/markdown',
    doc: 'application/msword',
    docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    xls: 'application/vnd.ms-excel',
    xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    ppt: 'application/vnd.ms-powerpoint',
    pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    mp3: 'audio/mpeg', m4a: 'audio/mp4', ogg: 'audio/ogg', wav: 'audio/wav',
    opus: 'audio/opus', flac: 'audio/flac',
    mp4: 'video/mp4', webm: 'video/webm', mov: 'video/quicktime',
  };
  return map[ext] ?? 'application/octet-stream';
}

/* ------------------------------------------------------------------ */
/* Shared attachment allow-list                                        */
/* ------------------------------------------------------------------ */

/**
 * Non-markdown files a folder-shaped import carries across as an image or
 * an attachment.
 *
 * Deliberately an allow-list rather than "everything that is not .md": a
 * real notes folder also holds editor state, lock files, sync databases and
 * whatever the user happened to leave there, and importing those would burn
 * the account's storage quota on junk the app can never render. Shared by
 * obsidian.ts and markdown.ts so the two agree on what an attachment is.
 */
export const ATTACHMENT_EXT =
  /\.(png|jpe?g|gif|webp|svg|bmp|avif|heic|heif|tiff?|ico|pdf|mp3|m4a|wav|ogg|opus|flac|mp4|webm|mov|docx?|xlsx?|pptx?|csv)$/i;

/* ------------------------------------------------------------------ */
/* Shared blob import + body-rewrite                                   */
/* ------------------------------------------------------------------ */

/**
 * A path plus its percent-encoded and percent-decoded spellings, deduped.
 * `decodeURI` throws on a malformed escape (a literal `%` in a filename),
 * which is a normal thing for a user to have, so it degrades to no variant
 * rather than failing the whole import.
 */
function encodingVariants(path: string): string[] {
  const out = [path];
  const encoded = encodeURI(path);
  if (encoded !== path) out.push(encoded);
  try {
    const decoded = decodeURI(path);
    if (decoded !== path) out.push(decoded);
  } catch {
    /* malformed escape sequence - the raw path is the only spelling */
  }
  return out;
}

/**
 * Every spelling of a blob key that `importBlobs` will look for in a note
 * body: the full key, its last two path segments, and its basename, each
 * percent-encoded and decoded. Filesystem-style keys (Apple Notes, a zipped
 * notes folder) are longer than the reference the note itself carries.
 */
function blobKeyCandidates(key: string): string[] {
  const segments = key.split('/');
  const paths = [key];
  if (segments.length >= 2) paths.push(segments.slice(-2).join('/'));
  if (segments.length >= 1) paths.push(segments[segments.length - 1]!);
  return [...new Set(paths.flatMap(encodingVariants))];
}

/** A markdown image or link whose target is `search`, angle brackets
 *  tolerated (`mdLinkTarget` in export.ts wraps a target holding a space). */
function blobRefPattern(search: string, keepAlt: boolean): RegExp {
  const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(
    keepAlt ? `!\\[([^\\]]*)\\]\\(<?${escaped}>?\\)` : `!?\\[[^\\]]*\\]\\(<?${escaped}>?\\)`,
    'g',
  );
}

/**
 * Would `importBlobs` rewrite a reference to this key inside `text`?
 *
 * The question an importer has to answer BEFORE shipping a blob: a notes
 * folder holds images nothing links to any more, and an unreferenced blob is
 * pure quota burn (notesnook.ts learned this first). Sharing the predicate
 * with the rewrite is the point - a looser test here ships blobs that then
 * never get rewritten, which is the same waste with an extra step.
 */
export function isBlobReferenced(key: string, text: string): boolean {
  return blobKeyCandidates(key).some((c) => blobRefPattern(c, false).test(text));
}

/**
 * Generic post-apply blob import for any importer that populates
 * `ParsedImport.blobs`.
 *
 * 1. Stores each blob in imageCache/imageDedup (images) or
 *    attachmentCache/attachmentDedup (non-images) with pendingUpload=1.
 * 2. Rewrites note bodies: replaces every blob key that appears inside
 *    a markdown image `![…](KEY)` or link `[…](KEY)` with the
 *    corresponding `pn:img/UUID` or `pn:file/UUID` URI.
 *
 * Blob map keys are opaque strings that must appear literally in the
 * markdown bodies produced by the importer's parse step. Examples:
 *   - Apple Notes: `"SomeFolder/Attachments/UUID.jpeg"`
 *   - Google Keep: `"keepimg:photo.jpg"`
 *   - Samsung Notes: `"samsungimg:rId2"`
 *
 * Returns counts of images and attachments imported.
 */
export async function importBlobs(
  blobs: Map<string, { data: Uint8Array; mime: string; name: string }>,
  noteIds: string[],
  onProgress?: (msg: string) => void,
): Promise<{ images: number; attachments: number }> {
  const now = new Date().toISOString();
  let imgCount = 0;
  let attCount = 0;

  // Store each blob and build key -> pn: URI mapping.
  const keyToUri = new Map<string, string>();
  const entries = [...blobs.entries()];

  for (let i = 0; i < entries.length; i++) {
    const [key, { data, mime, name }] = entries[i]!;
    const hash = await sha256hex(data);
    const uuid = crypto.randomUUID();
    const isImage = mime.startsWith('image/');

    if (isImage) {
      const existing = await db.imageDedup.get(hash);
      if (existing) {
        keyToUri.set(key, `pn:img/${existing.uuid}`);
      } else {
        await db.imageCache.put({ id: uuid, data, cachedAt: now });
        await db.imageDedup.put({ hash, uuid, encryptedSize: 0, pendingUpload: 1 });
        keyToUri.set(key, `pn:img/${uuid}`);
      }
      imgCount++;
    } else {
      const existing = await db.attachmentDedup.get(hash);
      if (existing) {
        keyToUri.set(key, `pn:file/${existing.uuid}`);
      } else {
        const meta: AttachmentMeta = { name, mime, size: data.length };
        await db.attachmentCache.put({ id: uuid, meta, data, cachedAt: now });
        await db.attachmentDedup.put({ hash, uuid, encryptedSize: 0, pendingUpload: 1 });
        keyToUri.set(key, `pn:file/${uuid}`);
      }
      attCount++;
    }

    if ((i + 1) % 10 === 0) {
      onProgress?.(`Importing attachments... ${i + 1} of ${entries.length}`);
    }
  }

  // Rewrite note bodies: replace blob keys with pn: URIs.
  if (keyToUri.size > 0 && noteIds.length > 0) {
    onProgress?.('Updating image references...');
    await db.transaction('rw', db.notes, async () => {
      for (const noteId of noteIds) {
        const note = await db.notes.get(noteId);
        if (!note) continue;

        let body = note.body;
        let changed = false;

        for (const [key, uri] of keyToUri) {
          const isImage = uri.startsWith('pn:img/');

          const candidates = blobKeyCandidates(key);

          if (isImage) {
            // Images: pn:img/<uuid> carries only the uuid, so a literal swap
            // of the key inside ![alt](key) preserves the alt text. Covers
            // keepimg: style placeholders and any scheme where the key
            // appears literally.
            if (body.includes(key)) {
              body = body.split(key).join(uri);
              changed = true;
              continue;
            }
            for (const search of candidates) {
              const replaced = body.replace(blobRefPattern(search, true), `![$1](${uri})`);
              if (replaced !== body) { body = replaced; changed = true; }
            }
            continue;
          }

          // Attachments: the editor recovers filename, size, and MIME from
          // the link TEXT as `name|size|mime` (see EncryptedAttachment
          // parseHTML). Rebuild the full link from the blob's real metadata
          // so imported audio/files keep their extension, MIME, and play
          // back. The source link text (e.g. Apple's "New Recording") is
          // discarded in favour of the real attachment name.
          const blob = blobs.get(key);
          const linkText = blob
            ? `${blob.name}|${formatFileSize(blob.data.length)}|${blob.mime}`
            : 'Attachment||';
          const replacement = `[${linkText}](${uri})`;
          for (const search of candidates) {
            // `keepAlt: false` tolerates a leading `!` so a mislabelled
            // ![text](path) audio ref still becomes a clean attachment link,
            // not a broken image.
            const replaced = body.replace(blobRefPattern(search, false), replacement);
            if (replaced !== body) { body = replaced; changed = true; }
          }
        }

        if (changed) {
          await db.notes.update(noteId, { body, dirty: 1 });
        }
      }
    });
  }

  return { images: imgCount, attachments: attCount };
}
