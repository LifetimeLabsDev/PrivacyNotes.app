/**
 * Client-side image processing for encrypted image uploads.
 *
 * Pipeline: decode -> strip EXIF (by re-encoding) -> resize -> encode
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
 * All processing happens in the browser via canvas. The output is a
 * Uint8Array (JPEG, or PNG when transparency is present) ready for
 * encryption + upload. No unprocessed image data ever leaves the client.
 */

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

/** Maximum dimension (longest edge) after resize. */
const MAX_DIMENSION = 2048;

/** JPEG quality (0-1). 0.85 is roughly Google Photos "Storage saver". */
const JPEG_QUALITY = 0.85;

/** Maximum processed size in bytes (5 MB). Reject if exceeded. */
const MAX_PROCESSED_BYTES = 5 * 1000 * 1000;

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

type ProcessedImage = {
  /** JPEG bytes, ready for encryption. */
  data: Uint8Array;
  /** Original filename (for display, not stored on server). */
  originalName: string;
  /** Processed dimensions. */
  width: number;
  height: number;
  /** Processed size in bytes. */
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
 * Validate that the file is an allowed image type.
 * On mobile, file.type is frequently empty even for valid images picked
 * from the gallery - fall back to extension check.
 */
function validateFile(file: File): string | null {
  const typeOk = file.type ? ALLOWED_TYPES.has(file.type) : false;
  if (!typeOk) {
    // Fallback: check file extension (mobile often gives empty type).
    const ext = file.name.split('.').pop()?.toLowerCase() ?? '';
    if (!ALLOWED_EXTENSIONS.has(ext)) {
      return `Unsupported image type: ${file.type || 'unknown'}. Supported: JPEG, PNG, WebP, GIF, BMP, TIFF, HEIC.`;
    }
  }
  // Reject files over 50 MB before even decoding (DoS guard).
  if (file.size > 50 * 1000 * 1000) {
    return 'Image too large (over 50 MB). Please use a smaller image.';
  }
  return null;
}

/**
 * Process a File (from paste, drop, or file picker) into an encrypted-ready
 * JPEG Uint8Array. Strips EXIF by decoding to bitmap and re-encoding.
 */
export async function processImage(file: File): Promise<ImageProcessingResult> {
  const validationError = validateFile(file);
  if (validationError) {
    return { ok: false, error: validationError };
  }

  try {
    // HEIC/HEIF: browsers (except Safari) can't decode these natively.
    // Convert to JPEG blob first via heic2any, then proceed as normal.
    let decodable: Blob = file;
    if (isHeic(file)) {
      const heicTo = await loadHeicTo();
      decodable = await heicTo({ blob: file, type: 'image/jpeg', quality: 0.92 });
    }

    // Decode to ImageBitmap - this strips EXIF because we get raw pixels.
    const bitmap = await createImageBitmap(decodable);

    // Calculate resize dimensions (fit within MAX_DIMENSION box).
    // When MAX_DIMENSION is 0, keep original dimensions (no resize).
    let { width, height } = bitmap;
    if (MAX_DIMENSION > 0 && (width > MAX_DIMENSION || height > MAX_DIMENSION)) {
      const scale = MAX_DIMENSION / Math.max(width, height);
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
        outType === 'image/png' ? { type: outType } : { type: outType, quality: JPEG_QUALITY },
      );
    } else {
      blob = await new Promise<Blob>((resolve, reject) => {
        // PNG ignores the quality arg; passing it is harmless.
        canvas.toBlob(
          (b) => (b ? resolve(b) : reject(new Error('Canvas toBlob failed'))),
          outType,
          JPEG_QUALITY,
        );
      });
    }

    const buffer = await blob.arrayBuffer();
    const data = new Uint8Array(buffer);

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
        originalName: file.name,
        width,
        height,
        sizeBytes: data.length,
      },
    };
  } catch (err) {
    return {
      ok: false,
      error: `Failed to process image: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
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
