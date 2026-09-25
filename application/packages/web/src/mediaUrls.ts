/**
 * A displayable URL for any picture reference a note can hold, for the views
 * that show pictures outside the editor: the viewer, the Files grid and the
 * Files picture picker. Both stores keep their own session cache of decrypted
 * object URLs, so a picture opened from any of them is decrypted once.
 */
import { loadEncryptedImageUrl, saveStoredImage } from './EncryptedImage';
import { loadAttachmentData, loadAttachmentUrl } from './EncryptedAttachment';
import { FILE_REF_PREFIX, IMAGE_REF_PREFIX, type MediaRef } from './mediaRefs';
import { saveBlob, type SaveResult } from './saveFile';

/**
 * Null when the blob is neither here nor on the server. Any other source is
 * a path or URL the note already renders as it stands, so it is used as-is.
 */
export async function loadPictureUrl(src: string): Promise<string | null> {
  if (src.startsWith(IMAGE_REF_PREFIX)) return loadEncryptedImageUrl(src.slice(IMAGE_REF_PREFIX.length));
  if (src.startsWith(FILE_REF_PREFIX)) return loadAttachmentUrl(src.slice(FILE_REF_PREFIX.length));
  return src;
}

/** Whether the viewer can save this item: it names a blob one of the stores holds. */
export function canSaveMedia(ref: MediaRef): boolean {
  return ref.src.startsWith(FILE_REF_PREFIX) || ref.src.startsWith(IMAGE_REF_PREFIX);
}

/**
 * Save the item under the name the note gives it, which is what its chip
 * saves too. Null when the blob cannot be read.
 */
export async function saveMedia(ref: MediaRef): Promise<SaveResult | null> {
  if (ref.src.startsWith(IMAGE_REF_PREFIX)) {
    return saveStoredImage(ref.src.slice(IMAGE_REF_PREFIX.length), ref.name);
  }
  if (!ref.src.startsWith(FILE_REF_PREFIX)) return null;
  const att = await loadAttachmentData(ref.src.slice(FILE_REF_PREFIX.length));
  if (!att) return null;
  const mime = att.meta.mime || 'application/octet-stream';
  return saveBlob(new Blob([att.data as BlobPart], { type: mime }), ref.name || att.meta.name || 'download');
}
