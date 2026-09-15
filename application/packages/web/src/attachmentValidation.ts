/**
 * File size validation for attachments.
 *
 * The encrypted vault stores the user's own files as opaque, client-side
 * encrypted blobs - the server never sees file names, types, or contents,
 * and vault files are never shared externally. Any file type is therefore
 * allowed; the only limit is per-file size (a quota/cost constraint, not a
 * security one). A file input that takes everything therefore carries no
 * `accept` attribute at all, which is the only portable way to say so.
 */

import { formatBytes } from './formatBytes';

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
