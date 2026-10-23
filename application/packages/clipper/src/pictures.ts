/**
 * The pictures of a clip: download each one, store it, and put the result
 * into the note text.
 *
 * A clip never keeps a remote picture that loads when the note opens. Each
 * token becomes either a stored picture (`pn:img/<uuid>`) or a plain text
 * link to the original address, which nothing loads.
 * Spec: ops/docs/archive/web-clipper-stage1.md (section 3.3)
 */
import { IMAGE_TOKEN_SCHEME, escapeAlt, type ClipImage } from './markdown';

/** At most this many pictures are downloaded per clip. */
export const CLIP_MAX_PICTURES = 20;
/** At most this many bytes of pictures, as downloaded, per clip. */
export const CLIP_MAX_PICTURE_BYTES = 10_000_000;

/** Why a picture was not stored. `storage`: the account's storage is full.
 *  `limit`: past the per-clip count or byte limit. `failed`: the download,
 *  the type, the size or the processing refused it. `skipped`: the person
 *  clips without pictures, so the picture leaves no trace in the note. */
export type PictureFailure = 'storage' | 'limit' | 'failed' | 'skipped';

export type PictureOutcome = { uuid: string } | { failure: PictureFailure };

export interface PictureDeps {
  /** Download one picture. Throws on any refusal. */
  download: (src: string) => Promise<{ bytes: Uint8Array; contentType: string }>;
  /** Process and store one picture. Returns its uuid, or why it was not stored. */
  store: (bytes: Uint8Array, contentType: string, src: string) => Promise<{ uuid: string } | { failure: 'storage' | 'failed' }>;
  /** Called after each picture, with how many are done and how many there are. */
  onProgress?: (done: number, total: number) => void;
}

/**
 * Download and store `images` in page order, one at a time, inside the per
 * clip limits. After a storage refusal no further picture is downloaded:
 * the account is full for all of them.
 */
export async function savePictures(images: ClipImage[], deps: PictureDeps): Promise<PictureOutcome[]> {
  const outcomes: PictureOutcome[] = [];
  let bytes = 0;
  let full = false;
  const total = Math.min(images.length, CLIP_MAX_PICTURES);
  for (let i = 0; i < images.length; i++) {
    if (i >= CLIP_MAX_PICTURES || bytes >= CLIP_MAX_PICTURE_BYTES) {
      outcomes.push({ failure: 'limit' });
      continue;
    }
    if (full) {
      outcomes.push({ failure: 'storage' });
      continue;
    }
    const image = images[i]!;
    let outcome: PictureOutcome;
    try {
      const got = await deps.download(image.src);
      bytes += got.bytes.length;
      if (bytes > CLIP_MAX_PICTURE_BYTES) outcome = { failure: 'limit' };
      else outcome = await deps.store(got.bytes, got.contentType, image.src);
    } catch {
      outcome = { failure: 'failed' };
    }
    if ('failure' in outcome && outcome.failure === 'storage') full = true;
    outcomes.push(outcome);
    deps.onProgress?.(Math.min(i + 1, total), total);
  }
  return outcomes;
}

/**
 * Replace each picture token in `markdown` by its outcome: a stored picture,
 * nothing for a skipped one, or a text link `[<label>: alt](address)` for one
 * that was not stored. A token with no outcome is treated as not stored, so
 * no token ever survives.
 */
export function placePictures(markdown: string, images: ClipImage[], outcomes: PictureOutcome[], label: string): string {
  const placed = placeEach(markdown, images, outcomes, label);
  // A skipped picture that sat inside a link leaves that link empty. Page
  // text never holds an unescaped `[]`, so this matches only those.
  return outcomes.some((o) => 'failure' in o && o.failure === 'skipped')
    ? placed.replace(/(^|[^\\!])\[\]\((?:\\.|[^)\\])*\)/g, '$1')
    : placed;
}

function placeEach(markdown: string, images: ClipImage[], outcomes: PictureOutcome[], label: string): string {
  const token = new RegExp(`!\\[((?:\\\\.|[^\\]\\\\])*)\\]\\(${escapeRegExp(IMAGE_TOKEN_SCHEME)}(\\d+)\\)`, 'g');
  return markdown.replace(token, (_whole, alt: string, index: string) => {
    const i = Number(index);
    const outcome = outcomes[i];
    if (outcome && 'uuid' in outcome) return `![${alt}](pn:img/${outcome.uuid})`;
    if (outcome?.failure === 'skipped') return '';
    const image = images[i];
    const plainAlt = image?.alt ?? '';
    const text = escapeAlt(plainAlt ? `${label}: ${plainAlt}` : label);
    if (!image) return `\\[${text}\\]`;
    return `[${text}](${image.src.replace(/[()]/g, (c) => `\\${c}`)})`;
  });
}

/** How many pictures were stored, and how many each failure left as links.
 *  Skipped pictures count as neither. */
export function countFailures(outcomes: PictureOutcome[]): { saved: number; storage: number; other: number } {
  let saved = 0;
  let storage = 0;
  let other = 0;
  for (const o of outcomes) {
    if ('uuid' in o) saved++;
    else if (o.failure === 'skipped') continue;
    else if (o.failure === 'storage') storage++;
    else other++;
  }
  return { saved, storage, other };
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
