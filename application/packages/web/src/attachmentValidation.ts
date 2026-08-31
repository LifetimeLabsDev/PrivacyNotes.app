/**
 * File size validation for attachments.
 *
 * The encrypted vault stores the user's own files as opaque, client-side
 * encrypted blobs - the server never sees file names, types, or contents,
 * and vault files are never shared externally. Any file type is therefore
 * allowed; the only limit is per-file size (a quota/cost constraint, not a
 * security one).
 */

import { formatBytes } from './formatBytes';

/** Accept string for file inputs - all file types allowed. */
export const FILE_ACCEPT = '*/*';

/** Category-scoped accept strings - used when uploading from a filtered view. */
export const FILE_ACCEPT_IMAGE = '.jpg,.jpeg,.png,.gif,.webp,.heic,.heif,.svg,.tiff,.bmp,.avif';
export const FILE_ACCEPT_AUDIO = '.mp3,.m4a,.wav,.ogg,.aac,.flac,.webm,.opus,.aiff';
export const FILE_ACCEPT_DOCUMENT = '.pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.pages,.numbers,.key,.txt,.rtf,.csv,.md,.odt,.ods,.odp,.json,.html';

/** Per-file size limits in bytes. */
const FILE_SIZE_LIMIT_FREE = 5 * 1000 * 1000;   // 5 MB
export const FILE_SIZE_LIMIT_PRO = 50 * 1000 * 1000;    // 50 MB
// Spec: ops/docs/file-size-storage-upsell.md (storage-sub holders get 100 MB/file)
export const FILE_SIZE_LIMIT_STORAGE = 100 * 1000 * 1000; // 100 MB

/** Resolve the per-file size limit for a user's tier. Exported so the
 *  import preflight can warn about blobs the server will refuse instead of
 *  re-deriving the ladder and drifting from it. */
export function perFileLimit(isPro: boolean, hasStorageSub: boolean): number {
  if (!isPro) return FILE_SIZE_LIMIT_FREE;
  return hasStorageSub ? FILE_SIZE_LIMIT_STORAGE : FILE_SIZE_LIMIT_PRO;
}

export type ValidationResult =
  | { ok: true }
  | { ok: false; error: string };

export function validateAttachment(
  file: File,
  isPro: boolean,
  hasStorageSub = false,
): ValidationResult {
  const limit = perFileLimit(isPro, hasStorageSub);
  if (file.size > limit) {
    const limitMB = limit / (1000 * 1000);
    return {
      ok: false,
      error: `File is too large (${formatFileSize(file.size)}). Maximum is ${limitMB} MB${isPro ? '' : ' on the free plan'}.`,
    };
  }

  return { ok: true };
}

/**
 * Check if a file is an image type that should be handled by the
 * existing image pipeline (processImage → EncryptedImage node)
 * rather than the generic attachment pipeline.
 */
export function isImageFile(file: File): boolean {
  return file.type.startsWith('image/');
}

/**
 * Alias of formatBytes. One decimal formatter is the single source of truth
 * for every size the user sees, so per-file sizes and the storage quota can
 * never drift apart. Kept as a named export for existing call sites.
 */
export const formatFileSize = formatBytes;
