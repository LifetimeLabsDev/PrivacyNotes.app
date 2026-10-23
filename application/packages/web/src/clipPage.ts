/**
 * One clip from start to end: download the page, run the clip engine, then
 * download, store and place its pictures. The screens call these steps; the
 * note itself is written by the caller, which knows the folder, the space and
 * the bookmark.
 *
 * Pictures are downloaded first and stored only when the person saves, so
 * the Clip page window can show their count and size before anything lands
 * in the account. A picture that is not stored stays as a text link that
 * nothing loads.
 * Spec: ops/docs/archive/web-clipper-stage1.md (sections 3.2 and 3.3)
 */
import type { Clip, ClipMode, PictureOutcome } from '@notes/clipper';
import { clipDownload, decodePage, ClipError, type TokenSource } from './clipDownload';
import { storePictureQuietly } from './EncryptedImage';

export type { ClipMode } from '@notes/clipper';

/** A downloaded page, ready for either mode. */
export interface ClipSource {
  html: string;
  /** The address after redirects. */
  url: string;
}

/** A clip with its pictures downloaded and not yet stored. */
export interface ClipDraft {
  clip: Clip;
  source: ClipSource;
  /** One entry per picture of `clip.images`. */
  held: Held[];
  /** Bytes of the downloaded pictures. */
  pictureBytes: number;
}

type Held = { bytes: Uint8Array; contentType: string } | { failure: 'limit' | 'failed' | 'skipped' };

const engine = () => import('@notes/clipper');

export async function downloadPage(url: string, token: TokenSource): Promise<ClipSource> {
  const page = await clipDownload(url, 'page', token);
  const source = { html: decodePage(page.bytes, page.contentType), url: page.url };
  // A redirect page names the real one; it is followed once, through the
  // same download and the same address checks.
  const { refreshTarget } = await engine();
  const next = refreshTarget(source.html, source.url);
  if (!next || next === source.url) return source;
  const moved = await clipDownload(next, 'page', token);
  return { html: decodePage(moved.bytes, moved.contentType), url: moved.url };
}

/** The clip of a downloaded page in one mode, or null when that mode finds
 *  no text. */
export async function clipOf(source: ClipSource, mode: ClipMode): Promise<Clip | null> {
  const { clipHtml } = await engine();
  return clipHtml(source.html, source.url, mode);
}

/** Whether a clip's text fits in one note, whatever happens to its pictures. */
export async function clipFitsNote(clip: Clip): Promise<boolean> {
  const { clipFits } = await engine();
  return clipFits(clip.markdown, clip.images);
}

/** Download a clip's pictures inside the per-clip limits; with `pictures`
 *  off, none is downloaded and the note leaves them out. */
export async function downloadPictures(
  clip: Clip,
  source: ClipSource,
  token: TokenSource,
  onProgress?: (done: number, total: number) => void,
  pictures = true,
): Promise<ClipDraft> {
  if (!pictures) return { clip, source, held: clip.images.map(() => ({ failure: 'skipped' })), pictureBytes: 0 };
  const { savePictures } = await engine();
  const kept: { bytes: Uint8Array; contentType: string }[] = [];
  const outcomes = await savePictures(clip.images, {
    download: async (src) => {
      const got = await clipDownload(src, 'image', token);
      return { bytes: got.bytes, contentType: got.contentType };
    },
    // Not stored yet: the index into `kept` stands in for the picture.
    store: async (bytes, contentType) => {
      kept.push({ bytes, contentType });
      return { uuid: String(kept.length - 1) };
    },
    onProgress,
  });
  const held: Held[] = outcomes.map((o) => ('uuid' in o ? kept[Number(o.uuid)]! : { failure: o.failure === 'limit' ? 'limit' : 'failed' }));
  return { clip, source, held, pictureBytes: kept.reduce((sum, k) => sum + k.bytes.length, 0) };
}

export interface SavedClip {
  title: string;
  body: string;
  /** Pictures stored with the note. */
  saved: number;
  /** Pictures left as links because the storage is full. */
  storageFull: number;
  /** Pictures left as links for any other reason. */
  failed: number;
}

/** Store the held pictures and write the note body. */
export async function finishClip(
  draft: ClipDraft,
  labels: { source: string; image: string; formatDate: (d: Date) => string },
  onProgress?: (done: number, total: number) => void,
): Promise<SavedClip> {
  const { bodyFits, clipNoteBody, countFailures, isSafeMarkdown, placePictures } = await engine();
  const outcomes: PictureOutcome[] = [];
  let full = false;
  let reserved = 0;
  const total = draft.held.filter((h) => 'bytes' in h).length;
  let done = 0;
  for (let i = 0; i < draft.held.length; i++) {
    const h = draft.held[i]!;
    if (!('bytes' in h)) {
      outcomes.push({ failure: h.failure });
      continue;
    }
    if (full) {
      outcomes.push({ failure: 'storage' });
      continue;
    }
    const name = pictureName(draft.clip.images[i]?.src ?? '', h.contentType);
    const out = await storePictureQuietly(new File([h.bytes as BlobPart], name, { type: h.contentType.split(';')[0]!.trim() }), reserved);
    if ('failure' in out) {
      if (out.failure === 'storage') full = true;
      outcomes.push(out);
    } else {
      reserved += out.stored;
      outcomes.push({ uuid: out.uuid });
    }
    onProgress?.(++done, total);
  }
  const markdown = placePictures(draft.clip.markdown, draft.clip.images, outcomes, labels.image);
  const body = clipNoteBody({ ...draft.clip, markdown }, draft.source.url, { sourceLabel: labels.source, formatDate: labels.formatDate });
  // The pictures already stored stay as orphans when this refuses, and the
  // orphan reconcile (imageGC.ts) reclaims them.
  if (!bodyFits(body)) throw new ClipError('too-large');
  if (!isSafeMarkdown(body)) throw new ClipError('failed');
  const counts = countFailures(outcomes);
  return { title: draft.clip.title, body, saved: counts.saved, storageFull: counts.storage, failed: counts.other };
}

/** A file name for a stored picture: the last part of its address, with an
 *  extension that matches its type. */
function pictureName(src: string, contentType: string): string {
  let stem = 'image';
  try {
    stem = decodeURIComponent(new URL(src).pathname.split('/').pop() ?? '').replace(/\.[a-z0-9]+$/i, '') || 'image';
  } catch {
    // Keep the default name.
  }
  const ext = /image\/(png|gif|webp|bmp|avif|tiff|heic)/i.exec(contentType)?.[1]?.toLowerCase() ?? 'jpg';
  return `${stem.slice(0, 80)}.${ext}`;
}

