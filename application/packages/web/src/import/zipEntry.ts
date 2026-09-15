/**
 * Bounded reads of the text an importer takes out of a zip.
 *
 * jszip checks an entry's declared uncompressed size against the bytes it
 * inflates, so the declared number cannot be lied about, and reading it before
 * the inflation bounds the one place an import can grow without the user
 * seeing it: a few hundred compressed bytes that expand into gigabytes of text.
 * Every text entry is parsed whole on the UI thread, so such an entry freezes
 * the app before any preview appears, and no real export carries a single text
 * file of that size. Binary entries stay unbounded on purpose: an attachment
 * above the per-file ladder is refused at upload, and one long video in a
 * journal export must not abort the rest of the import.
 *
 * The UpNote snapshot is compressed twice, a gzip member inside the zip, and
 * the inner layer declares no size, so it is counted as it inflates instead.
 * Spec: ops/docs/security-backlog.md (SEC-67)
 */

import type JSZip from 'jszip';
import { formatBytes } from '../formatBytes';

/** The most text one zip entry may expand to before the import refuses it. */
const ZIP_TEXT_ENTRY_LIMIT = 256 * 1024 * 1024;

function declaredSize(entry: JSZip.JSZipObject): number | null {
  const internal = (entry as unknown as { _data?: { uncompressedSize?: number } })._data;
  return typeof internal?.uncompressedSize === 'number' ? internal.uncompressedSize : null;
}

/** Thrown before or during an inflation that would exceed the limit; an importer must not swallow it. */
export class ImportTooLargeError extends Error {}

function tooLarge(name: string, limit: number, size?: number): ImportTooLargeError {
  const grows = size === undefined ? 'expands past' : `expands to ${formatBytes(size)}, more than`;
  return new ImportTooLargeError(
    `${name} ${grows} the ${formatBytes(limit)} an import can read at once. Remove it from the export and try again.`,
  );
}

function refuseOverLimit(entry: JSZip.JSZipObject, limit: number): void {
  const size = declaredSize(entry);
  if (size !== null && size > limit) throw tooLarge(entry.name, limit, size);
}

/** The text of one entry, refused before inflation when it declares more than `limit`. */
export async function zipEntryText(entry: JSZip.JSZipObject, limit = ZIP_TEXT_ENTRY_LIMIT): Promise<string> {
  refuseOverLimit(entry, limit);
  return entry.async('string');
}

/**
 * The bytes of one entry that is itself a compressed text container (a gzip
 * member, a zip inside the zip), refused before inflation the same way.
 */
export async function zipEntryBytes(entry: JSZip.JSZipObject, limit = ZIP_TEXT_ENTRY_LIMIT): Promise<Uint8Array<ArrayBuffer>> {
  refuseOverLimit(entry, limit);
  return new Uint8Array(await entry.async('uint8array'));
}

/**
 * Gunzip through the platform's DecompressionStream, decoding and counting the
 * output and refusing past `limit`. jsdom and some older embedders lack
 * Blob.stream(), so the source is a hand-rolled ReadableStream rather than
 * blob.stream(). The reader is drained by hand rather than through
 * `new Response(stream).text()`, because a throw inside a piped transform
 * reaches that Response as an opaque "Failed to fetch", losing the typed error
 * the caller needs to tell a refusal from a corrupt file.
 */
export async function gunzipText(
  data: Uint8Array<ArrayBuffer>,
  name: string,
  limit = ZIP_TEXT_ENTRY_LIMIT,
): Promise<string> {
  const src = new ReadableStream<BufferSource>({
    start(controller) {
      controller.enqueue(data);
      controller.close();
    },
  });
  const reader = src.pipeThrough(new DecompressionStream('gzip')).getReader();
  const decoder = new TextDecoder();
  let out = '';
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > limit) throw tooLarge(name, limit);
      out += decoder.decode(value, { stream: true });
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  return out + decoder.decode();
}
