/**
 * Client-side image processing for encrypted image uploads.
 *
 * Every image door in the app (paste, drop, the image button, the attach
 * button, the Files pillar, every importer) hands its file to
 * `processImage` with the options from `currentImageOptions()`, which
 * mirror the two app-wide switches in Settings > Images:
 *
 *   fitBox set   -> decode, fit inside the box, encode JPEG at
 *                   IMAGE_JPEG_QUALITY (PNG when the source carries
 *                   transparency). The canvas round trip drops every
 *                   metadata block. When the user keeps metadata, the
 *                   source EXIF is copied back with its orientation reset,
 *                   because the encoder already rotated the pixels.
 *   fitBox null  -> the source bytes and format are kept. Metadata is then
 *                   cut out by a lossless container walk (imageMetadata.ts)
 *                   or left in place.
 *
 * HEIC and TIFF have no raw state: the browser cannot draw either and the
 * lossless walk has no reader for them, so both are always converted at
 * the space-saver ceiling. Backup restore never comes through here; it
 * writes its blobs byte for byte (import/privacynotes.ts).
 *
 * Output format: JPEG by default. WebP is ~20% smaller but iOS WebKit
 * can't encode it (silently falls back to lossless PNG), so JPEG is the
 * universal baseline - identical on every browser and OS, negligible
 * quality loss at 0.85 for our storage budgets.
 *
 * Exception: JPEG has no alpha channel, so a transparent source would be
 * flattened onto black. When the input can carry alpha (PNG/WebP/GIF) and
 * actually contains a transparent pixel, we encode PNG instead to keep it.
 *
 * All processing happens in the browser via canvas. No unprocessed image
 * data ever leaves the client.
 *
 * Spec: ops/docs/plans/image-quality-handoff.md
 */

import type { ImageFormat } from './imageMetadata';

// The container walkers load on the first image operation, not at boot:
// every editor session carries this module, and most sessions never
// touch an image.
type MetadataModule = typeof import('./imageMetadata');
let metadataModule: Promise<MetadataModule> | null = null;
function loadMetadata(): Promise<MetadataModule> {
  metadataModule ??= import('./imageMetadata');
  return metadataModule;
}

// Dynamic import - heic-to is only loaded when a HEIC file is encountered.
// The /csp entry point avoids Function() eval, so it works under strict CSP.
type HeicToFn = (opts: { blob: Blob; type: string; quality?: number }) => Promise<Blob>;
let heicToFn: HeicToFn | null = null;
async function loadHeicTo(): Promise<HeicToFn> {
  if (!heicToFn) {
    const mod = await import('heic-to/csp' as string);
    heicToFn = (mod.heicTo ?? mod.default) as HeicToFn;
  }
  return heicToFn;
}

/** Check whether a File is HEIC/HEIF (by MIME or extension). */
function isHeic(file: File): boolean {
  if (file.type === 'image/heic' || file.type === 'image/heif') return true;
  const ext = file.name.split('.').pop()?.toLowerCase() ?? '';
  return ext === 'heic' || ext === 'heif';
}

/** Formats that can carry an alpha channel. Others (JPEG, BMP) never do,
 *  so we skip the per-pixel transparency scan for them. */
const ALPHA_CAPABLE_TYPES = new Set(['image/png', 'image/webp', 'image/gif']);
const ALPHA_CAPABLE_EXTENSIONS = new Set(['png', 'webp', 'gif']);

/** Whether a File's format is capable of holding transparency. Uses MIME,
 *  falling back to extension (mobile pickers often give an empty type). */
function mayHaveAlpha(file: File): boolean {
  if (file.type) return ALPHA_CAPABLE_TYPES.has(file.type);
  const ext = file.name.split('.').pop()?.toLowerCase() ?? '';
  return ALPHA_CAPABLE_EXTENSIONS.has(ext);
}

/** Scan a drawn canvas for any non-opaque pixel. Returns true on the first
 *  pixel with alpha < 255, so fully-opaque images bail out fast. */
function canvasHasAlpha(
  ctx: OffscreenCanvasRenderingContext2D | CanvasRenderingContext2D,
  width: number,
  height: number,
): boolean {
  const { data } = ctx.getImageData(0, 0, width, height);
  for (let i = 3; i < data.length; i += 4) {
    if (data[i] !== 255) return true;
  }
  return false;
}

/** The longest edge a space-saved image fits inside, in pixels. */
// Spec: ops/docs/plans/image-quality-handoff.md (section 3, space saver)
export const IMAGE_FIT_PX = 2048;

/** JPEG quality (0-1). 0.85 is roughly Google Photos "Storage saver". */
// Spec: ops/docs/plans/image-quality-handoff.md (section 3, space saver)
export const IMAGE_JPEG_QUALITY = 0.85;

/** The box a contact photo fits inside while "Keep contact photos small"
 *  is on: a ceiling, never a target, and never an upscale. The largest
 *  size the app draws a contact photo. */
// Spec: ops/docs/plans/contacts-pillar.md (section 7.4, one photo per contact)
export const CONTACT_PHOTO_PX = 512;

/**
 * Ceiling on a re-encoded image. A picture that fits IMAGE_FIT_PX and came
 * back larger than this is a decode gone wrong, not a large photo. A
 * picture stored as it arrived is capped by the per-file tier ladder at
 * the door instead (attachmentValidation.ts), the same cap every other
 * file obeys.
 * Spec: ops/docs/design-decisions.md (image size limits: one ladder, not two)
 */
const MAX_PROCESSED_BYTES = 5 * 1000 * 1000;

/** Largest file the canvas is asked to decode. */
const MAX_DECODE_BYTES = 50 * 1000 * 1000;

/** Allowed input MIME types. */
const ALLOWED_TYPES = new Set([
  'image/jpeg',
  'image/png',
  'image/webp',
  'image/gif',
  'image/bmp',
  'image/tiff',
  'image/heic',
  'image/heif',
]);

/** Allowed file extensions (lowercase, without dot). Fallback when MIME is empty. */
const ALLOWED_EXTENSIONS = new Set([
  'jpg', 'jpeg', 'png', 'webp', 'gif', 'bmp', 'tiff', 'tif',
  'heic', 'heif',
]);

/** MIME per sniffed container, for a picture stored in its own format. */
const FORMAT_MIME: Record<Exclude<ImageFormat, 'unknown'>, string> = {
  jpeg: 'image/jpeg',
  png: 'image/png',
  webp: 'image/webp',
  gif: 'image/gif',
  bmp: 'image/bmp',
  tiff: 'image/tiff',
  heic: 'image/heic',
};

/** Extensions that already say what a stored MIME is; the first one is
 *  used when the name has to change. */
const MIME_EXTENSIONS: Record<string, string[]> = {
  'image/jpeg': ['jpg', 'jpeg'],
  'image/png': ['png'],
  'image/webp': ['webp'],
  'image/gif': ['gif'],
  'image/bmp': ['bmp'],
};

/**
 * What one door asks for. `fitBox` is the longest edge in pixels; null
 * keeps the source bytes and format. `stripMetadata` drops EXIF, XMP and
 * every other metadata block, whichever branch runs.
 */
export type ImageOptions = {
  fitBox: number | null;
  stripMetadata: boolean;
};

type ImagePolicy = { spaceSaver: boolean; stripMetadata: boolean; contactCeiling: boolean };

/** Every switch on: the behaviour every editor image path always had. */
let policy: ImagePolicy = { spaceSaver: true, stripMetadata: true, contactCeiling: true };

/**
 * NotesView mirrors the two synced switches here whenever they change. A
 * module-level policy rather than a React context, because the doors are
 * ProseMirror plugins and importers with no component above them.
 */
export function setImagePolicy(next: ImagePolicy): void {
  policy = next;
}

/** The options a door passes, derived from the two app-wide switches.
 *  `overrides` narrows them for a caller with a tighter ceiling. */
export function currentImageOptions(overrides: Partial<ImageOptions> = {}): ImageOptions {
  return {
    fitBox: policy.spaceSaver ? IMAGE_FIT_PX : null,
    stripMetadata: policy.stripMetadata,
    ...overrides,
  };
}

/**
 * The options a contact photo passes: the space-saver options with the box
 * pulled in to CONTACT_PHOTO_PX while "Keep contact photos small" is on.
 * Off, a contact photo is any other image.
 * Spec: ops/docs/plans/image-quality-handoff.md (section 7)
 */
export function contactPhotoOptions(): ImageOptions {
  const base = currentImageOptions();
  return policy.contactCeiling ? { ...base, fitBox: CONTACT_PHOTO_PX } : base;
}

/**
 * Whether a File is one this module reads: by MIME, or by extension when
 * the picker left the type empty or generic (mobile galleries often do).
 */
export function isSupportedImage(file: File): boolean {
  if (file.type && ALLOWED_TYPES.has(file.type)) return true;
  const ext = file.name.split('.').pop()?.toLowerCase() ?? '';
  return ALLOWED_EXTENSIONS.has(ext);
}

/**
 * The file name a stored picture carries: the source name when its
 * extension already matches the stored MIME, else the same stem with the
 * matching extension. A chip, a download and an export all print this
 * name, so a PNG that was stored as JPEG must not keep saying .png.
 */
function honestName(name: string, mime: string): string {
  const allowed = MIME_EXTENSIONS[mime] ?? [];
  const dot = name.lastIndexOf('.');
  const ext = dot >= 0 ? name.slice(dot + 1).toLowerCase() : '';
  if (dot >= 0 && allowed.includes(ext)) return name;
  const stem = dot >= 0 ? name.slice(0, dot) : name;
  return `${stem || 'image'}.${allowed[0] ?? 'bin'}`;
}

type ProcessedImage = {
  /** The bytes to encrypt and store. */
  data: Uint8Array;
  /** MIME of `data`: the source type only when the bytes were kept. */
  mime: string;
  /** A file name whose extension matches `mime`. */
  name: string;
  /** Size of `data` in bytes. */
  sizeBytes: number;
};

type ImageProcessingError = {
  ok: false;
  error: string;
};

export type ImageProcessingResult =
  | { ok: true; image: ProcessedImage }
  | ImageProcessingError;

/**
 * Process a File (from paste, drop, a picker or an importer) into the
 * bytes the app stores, per the options.
 */
export async function processImage(file: File, opts: ImageOptions): Promise<ImageProcessingResult> {
  if (!isSupportedImage(file)) {
    return {
      ok: false,
      error: `Unsupported image type: ${file.type || 'unknown'}. Supported: JPEG, PNG, WebP, GIF, BMP, TIFF, HEIC.`,
    };
  }

  try {
    if (opts.fitBox === null) {
      const meta = await loadMetadata();
      const bytes = new Uint8Array(await file.arrayBuffer());
      const format = meta.sniffImageFormat(bytes);
      const kept = keepSource(meta, bytes, format, opts.stripMetadata);
      if (kept && format !== 'unknown') {
        const mime = FORMAT_MIME[format];
        return {
          ok: true,
          image: { data: kept, mime, name: honestName(file.name, mime), sizeBytes: kept.length },
        };
      }
      // No raw state for this container: convert at the ceiling and keep
      // the metadata choice.
      return await reencode(file, { fitBox: IMAGE_FIT_PX, stripMetadata: opts.stripMetadata }, bytes);
    }
    return await reencode(file, { fitBox: opts.fitBox, stripMetadata: opts.stripMetadata }, null);
  } catch (err) {
    return {
      ok: false,
      error: `Failed to process image: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

/**
 * The source bytes of a container the browser draws as it is, unchanged
 * or with the metadata cut out. null when the container has no raw state
 * (TIFF, HEIC, unknown) or the walk could not read it.
 */
function keepSource(
  meta: MetadataModule,
  bytes: Uint8Array,
  format: ImageFormat,
  strip: boolean,
): Uint8Array | null {
  if (format === 'tiff' || format === 'heic' || format === 'unknown') return null;
  return strip ? meta.stripImageMetadata(bytes) : bytes;
}

/**
 * Decode, fit inside the box, encode. `source` is the file's bytes when
 * the caller already read them, so the EXIF copy-back does not read the
 * file twice.
 */
async function reencode(
  file: File,
  opts: { fitBox: number; stripMetadata: boolean },
  source: Uint8Array | null,
): Promise<ImageProcessingResult> {
  if (file.size > MAX_DECODE_BYTES) {
    return { ok: false, error: 'Image too large (over 50 MB). Please use a smaller image.' };
  }

  // HEIC/HEIF: browsers (except Safari) can't decode these natively.
  // Convert to JPEG blob first via heic-to, then proceed as normal.
  let decodable: Blob = file;
  if (isHeic(file)) {
    const heicTo = await loadHeicTo();
    decodable = await heicTo({ blob: file, type: 'image/jpeg', quality: 0.92 });
  }

  // Decode to ImageBitmap - raw pixels, no metadata, orientation applied.
  const bitmap = await createImageBitmap(decodable);

  // Fit inside the box. A box of 0 keeps the source dimensions.
  let { width, height } = bitmap;
  if (opts.fitBox > 0 && (width > opts.fitBox || height > opts.fitBox)) {
    const scale = opts.fitBox / Math.max(width, height);
    width = Math.round(width * scale);
    height = Math.round(height * scale);
  }

  // Draw to canvas, then pick the output format. JPEG has no alpha
  // channel: re-encoding a transparent source to JPEG composites the
  // transparent pixels onto black. So when the source can carry alpha
  // (PNG/WebP/GIF) AND actually does, encode PNG to preserve it.
  // Everything else stays JPEG (smaller, identical on every platform).
  // Draw once; the output format is chosen at encode time, so the same
  // drawn pixels are scanned for alpha and then encoded.
  const useOffscreen = typeof OffscreenCanvas !== 'undefined';
  const canvas: OffscreenCanvas | HTMLCanvasElement = useOffscreen
    ? new OffscreenCanvas(width, height)
    : Object.assign(document.createElement('canvas'), { width, height });
  const ctx = canvas.getContext('2d') as
    | OffscreenCanvasRenderingContext2D
    | CanvasRenderingContext2D
    | null;
  if (!ctx) {
    bitmap.close();
    return { ok: false, error: 'Failed to create canvas context.' };
  }
  ctx.drawImage(bitmap, 0, 0, width, height);
  bitmap.close();

  // Only PNG/WebP/GIF can carry alpha; skip the pixel scan for the rest.
  const keepAlpha = mayHaveAlpha(file) && canvasHasAlpha(ctx, width, height);
  const outType: 'image/png' | 'image/jpeg' = keepAlpha ? 'image/png' : 'image/jpeg';

  let blob: Blob;
  if (canvas instanceof OffscreenCanvas) {
    blob = await canvas.convertToBlob(
      outType === 'image/png' ? { type: outType } : { type: outType, quality: IMAGE_JPEG_QUALITY },
    );
  } else {
    blob = await new Promise<Blob>((resolve, reject) => {
      // PNG ignores the quality arg; passing it is harmless.
      canvas.toBlob(
        (b) => (b ? resolve(b) : reject(new Error('Canvas toBlob failed'))),
        outType,
        IMAGE_JPEG_QUALITY,
      );
    });
  }

  let data: Uint8Array = new Uint8Array(await blob.arrayBuffer());

  // The encoder wrote no metadata. Keeping it means carrying the source
  // EXIF over with its orientation reset to 1: the pixels above are
  // already rotated, and a copied orientation would rotate them twice.
  // A HEIC source carries nothing over, because the walk has no reader
  // for that container.
  if (!opts.stripMetadata) {
    const meta = await loadMetadata();
    const exif = meta.extractExif(source ?? new Uint8Array(await file.arrayBuffer()));
    if (exif) data = meta.attachExif(data, exif);
  }

  if (data.length > MAX_PROCESSED_BYTES) {
    return {
      ok: false,
      error: `Processed image is ${(data.length / (1000 * 1000)).toFixed(1)} MB, exceeds the 5 MB limit. Try a smaller image.`,
    };
  }

  return {
    ok: true,
    image: {
      data,
      mime: outType,
      name: honestName(file.name, outType),
      sizeBytes: data.length,
    },
  };
}

/**
 * Extract image UUIDs from a markdown body. Used for GC diffing.
 * Matches `pn:img/<uuid>` patterns in markdown image syntax.
 */
export function extractImageIds(body: string): Set<string> {
  const ids = new Set<string>();
  const re = /pn:img\/([0-9a-f-]{36})/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(body)) !== null) {
    const id = match[1];
    if (id) ids.add(id);
  }
  return ids;
}

/** Check whether a note body contains any embedded media (images or file attachments). */
export function hasMedia(body: string): boolean {
  return /pn:(img|file)\/[0-9a-f-]{36}/.test(body);
}

/**
 * Strip image and attachment references from a markdown body.
 * Removes full markdown image syntax `![...](pn:img/<uuid>)` and
 * link syntax `[...](pn:file/<uuid>)`, then collapses leftover blank lines.
 */
export function stripMediaReferences(body: string): string {
  return body
    .replace(/!\[[^\]]*\]\(pn:img\/[0-9a-f-]{36}\)(?:\{[^}]*\})?\n?/g, '')
    .replace(/\[[^\]]*\]\(pn:file\/[0-9a-f-]{36}\)\n?/g, '')
    // Clean up orphaned hard-break markers (\ on a line by itself)
    // left behind when the stripped media was preceded by a hard break.
    .replace(/^\\\s*$/gm, '')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}
