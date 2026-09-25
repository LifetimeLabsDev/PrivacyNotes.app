/**
 * Bounded reads of the text an importer takes out of a zip.
 *
 * A zip entry declares its uncompressed size in the central directory, and
 * jszip compares that number with the bytes it inflates. The comparison runs
 * at the END of the stream, after every byte has been produced, so a forged
 * small number passes any test made before the inflation, and the work is
 * done by the time the lie is caught. The bound is therefore a running count
 * of the bytes actually produced: the stream is paused and the read refused
 * the moment it passes the limit. The declared size is still read first,
 * because it refuses an honest oversize entry for free.
 *
 * What that bounds is the one place an import can grow without the user
 * seeing it: a few hundred compressed bytes that expand into gigabytes of
 * text. Every text entry is parsed whole on the UI thread, so such an entry
 * freezes the app before any preview appears, and no real export carries a
 * single text file of that size. Binary entries stay unbounded on purpose: an
 * attachment above the per-file ladder is refused at upload, and one long
 * video in a journal export must not abort the rest of the import.
 *
 * The UpNote snapshot is compressed twice, a gzip member inside the zip, and
 * the inner layer declares no size, so it is counted the same way.
 */

import type JSZip from 'jszip';
import { formatBytes } from '../formatBytes';

/** The most text one zip entry may expand to before the import refuses it. */
const ZIP_TEXT_ENTRY_LIMIT = 256 * 1024 * 1024;

/** The chunked read jszip's own `async()` is built on; absent from its typings. */
type EntryStream = {
  internalStream(type: 'uint8array'): JSZip.JSZipStreamHelper<Uint8Array>;
};

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

/**
 * The inflated bytes of one entry, refused past `limit` as they are produced.
 * A refusal pauses the stream, which stops the inflater before its next
 * block; the block in flight still arrives and is dropped, so the overshoot
 * is bounded by what one compressed block can expand to.
 */
function inflateBounded(entry: JSZip.JSZipObject, limit: number): Promise<Uint8Array<ArrayBuffer>> {
  refuseOverLimit(entry, limit);
  return new Promise((resolve, reject) => {
    const chunks: Uint8Array[] = [];
    let total = 0;
    let settled = false;
    const stream = (entry as unknown as EntryStream).internalStream('uint8array');
    stream
      .on('data', (chunk) => {
        if (settled) return;
        total += chunk.byteLength;
        if (total > limit) {
          settled = true;
          stream.pause();
          reject(tooLarge(entry.name, limit));
          return;
        }
        chunks.push(chunk);
      })
      .on('error', (err) => {
        if (settled) return;
        settled = true;
        reject(err);
      })
      .on('end', () => {
        if (settled) return;
        settled = true;
        const out = new Uint8Array(total);
        let at = 0;
        for (const chunk of chunks) {
          out.set(chunk, at);
          at += chunk.byteLength;
        }
        resolve(out);
      })
      .resume();
  });
}

/** The text of one entry, refused when it declares or produces more than `limit`. */
export async function zipEntryText(entry: JSZip.JSZipObject, limit = ZIP_TEXT_ENTRY_LIMIT): Promise<string> {
  // A byte-order mark stays in the text, which is how jszip's own decoder reads it.
  return new TextDecoder('utf-8', { ignoreBOM: true }).decode(await inflateBounded(entry, limit));
}

/**
 * The bytes of one entry that is itself a compressed text container (a gzip
 * member, a zip inside the zip), bounded the same way.
 */
export async function zipEntryBytes(entry: JSZip.JSZipObject, limit = ZIP_TEXT_ENTRY_LIMIT): Promise<Uint8Array<ArrayBuffer>> {
  return inflateBounded(entry, limit);
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
