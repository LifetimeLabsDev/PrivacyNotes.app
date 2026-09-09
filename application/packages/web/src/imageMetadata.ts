/**
 * Lossless metadata removal for image containers, plus the EXIF round trip
 * the re-encode path needs. Pure byte walking over a Uint8Array: no decode,
 * no DOM, and no throw on malformed input (null instead, so the caller can
 * fall back to a re-encode).
 *
 * JPEG keep list: APP0 (JFIF, JFXX), APP2 carrying an ICC_PROFILE identifier
 * (the colour profile changes how the pixels render), APP14 (Adobe colour
 * transform flag), and every table, frame and scan segment. Cut list: every
 * other APPn segment, COM, and everything after the EOI marker, where motion
 * photos append a video.
 *
 * The one piece of metadata that survives a strip is the EXIF orientation.
 * Phone photos are stored in sensor orientation with the tag set, so without
 * it they render sideways; it is rewritten into a minimal EXIF block that
 * carries nothing else.
 */

export type ImageFormat = 'jpeg' | 'png' | 'webp' | 'gif' | 'bmp' | 'tiff' | 'heic' | 'unknown';

const EXIF_PREFIX = ascii('Exif\0\0');
const ICC_PROFILE = ascii('ICC_PROFILE\0');
const PNG_SIGNATURE = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const HEIC_BRANDS = new Set(['heic', 'heix', 'hevc', 'hevx', 'heim', 'heis', 'hevm', 'hevs', 'mif1', 'msf1']);

/** Largest EXIF payload a JPEG APP1 segment can hold: 65535 minus the
 *  2-byte length field minus the 6-byte "Exif\0\0" prefix. */
const MAX_JPEG_EXIF_BYTES = 65527;

const ORIENTATION_TAG = 0x0112;
const TIFF_SHORT = 3;

/** Identify the container from its magic bytes. */
export function sniffImageFormat(bytes: Uint8Array): ImageFormat {
  if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return 'jpeg';
  if (startsWith(bytes, PNG_SIGNATURE.subarray(0, 4))) return 'png';
  if (bytes.length >= 12 && startsWith(bytes, ascii('RIFF')) && startsWith(bytes.subarray(8), ascii('WEBP'))) {
    return 'webp';
  }
  if (startsWith(bytes, ascii('GIF8'))) return 'gif';
  if (startsWith(bytes, ascii('BM'))) return 'bmp';
  if (isTiffHeader(bytes)) return 'tiff';
  if (bytes.length >= 12 && startsWith(bytes.subarray(4), ascii('ftyp'))) {
    const brand = String.fromCharCode(...bytes.subarray(8, 12)).toLowerCase();
    if (HEIC_BRANDS.has(brand)) return 'heic';
  }
  return 'unknown';
}

/**
 * Lossless metadata removal. Returns the same pixels in the same container
 * with every metadata block dropped. Returns null when the format is not
 * handled (tiff, heic, unknown) or the file is malformed, so the caller can
 * fall back to a re-encode. gif and bmp are returned unchanged (same array).
 */
export function stripImageMetadata(bytes: Uint8Array): Uint8Array | null {
  try {
    switch (sniffImageFormat(bytes)) {
      case 'jpeg':
        return stripJpeg(bytes);
      case 'png':
        return stripPng(bytes);
      case 'webp':
        return stripWebp(bytes);
      case 'gif':
      case 'bmp':
        return bytes;
      default:
        return null;
    }
  } catch {
    return null;
  }
}

/**
 * The EXIF payload of a jpeg, png or webp: the TIFF structure that starts
 * with "II*\0" or "MM\0*", without any "Exif\0\0" prefix. null when absent
 * or malformed.
 */
export function extractExif(bytes: Uint8Array): Uint8Array | null {
  try {
    let raw: Uint8Array | null = null;
    switch (sniffImageFormat(bytes)) {
      case 'jpeg': {
        const parts = walkJpeg(bytes);
        raw = parts && findJpegExif(bytes, parts);
        break;
      }
      case 'png': {
        const chunk = walkPng(bytes)?.find((c) => c.type === 'eXIf');
        raw = chunk ? withoutExifPrefix(bytes.subarray(chunk.dataStart, chunk.dataEnd)) : null;
        break;
      }
      case 'webp': {
        const chunk = walkWebp(bytes)?.find((c) => c.fourcc === 'EXIF');
        raw = chunk ? withoutExifPrefix(bytes.subarray(chunk.dataStart, chunk.dataEnd)) : null;
        break;
      }
      default:
        return null;
    }
    return raw && isTiffHeader(raw) ? raw.slice() : null;
  } catch {
    return null;
  }
}

/**
 * Put an EXIF payload into a freshly encoded jpeg or png, with the
 * orientation tag forced to 1 (the encoder already applied the rotation to
 * the pixels, so a copied orientation would rotate the picture twice).
 * Returns the input unchanged when the payload does not fit a JPEG segment
 * (payload over 65527 bytes) or the container is not jpeg or png.
 */
export function attachExif(image: Uint8Array, exif: Uint8Array): Uint8Array {
  try {
    if (exif.length > MAX_JPEG_EXIF_BYTES || !isTiffHeader(exif)) return image;
    const payload = withOrientationReset(exif);
    switch (sniffImageFormat(image)) {
      case 'jpeg': {
        const parts = walkJpeg(image);
        if (!parts) return image;
        // A second EXIF block would leave readers to pick one; the payload
        // being attached replaces whatever the encoder wrote.
        const kept = parts.filter((p) => !isJpegExif(image, p));
        return assembleJpeg(image, kept, jpegSegment(0xe1, concat([EXIF_PREFIX, payload])));
      }
      case 'png': {
        const chunks = walkPng(image);
        if (!chunks) return image;
        const kept = chunks.filter((c) => c.type !== 'eXIf');
        return assemblePng(image, kept, pngChunk('eXIf', payload));
      }
      default:
        return image;
    }
  } catch {
    return image;
  }
}

// ── JPEG ───────────────────────────────────────────────────────────────

/** One marker segment, or the entropy-coded data behind a scan (marker
 *  ENTROPY). `start` is the FF that opens the marker; `end` is exclusive. */
type JpegPart = { marker: number; start: number; end: number };
const ENTROPY = -1;
const SOI = 0xd8;
const EOI = 0xd9;
const SOS = 0xda;
const APP0 = 0xe0;
const APP1 = 0xe1;

/**
 * Split a JPEG into its parts, from SOI through EOI. Anything after EOI is
 * not returned. Null on any structural fault: a segment running past the
 * end, no scan, no EOI, a stray byte where a marker belongs.
 */
function walkJpeg(bytes: Uint8Array): JpegPart[] | null {
  const len = bytes.length;
  if (len < 4 || bytes[0] !== 0xff || bytes[1] !== SOI) return null;
  const parts: JpegPart[] = [{ marker: SOI, start: 0, end: 2 }];
  let pos = 2;
  let sawScan = false;
  for (;;) {
    // Any number of FF fill bytes may precede a marker.
    if (bytes[pos] !== 0xff) return null;
    while (pos < len && bytes[pos] === 0xff) pos++;
    if (pos >= len) return null;
    const marker = bytes[pos]!;
    const start = pos - 1;
    pos++;
    if (marker === EOI) {
      if (!sawScan) return null;
      parts.push({ marker, start, end: pos });
      return parts;
    }
    if (marker === 0x00 || marker === SOI) return null;
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      parts.push({ marker, start, end: pos });
      continue;
    }
    if (pos + 2 > len) return null;
    const end = pos + readU16BE(bytes, pos);
    if (end < pos + 2 || end > len) return null;
    parts.push({ marker, start, end });
    pos = end;
    if (marker !== SOS) continue;
    sawScan = true;
    // Entropy-coded data ends at the first marker that is neither a stuffed
    // byte (FF 00), a restart marker (FF D0 to FF D7) nor a fill FF. What
    // follows may be EOI, or more tables and scans in a progressive file.
    const dataStart = pos;
    for (;;) {
      if (pos + 1 >= len) return null;
      if (bytes[pos] !== 0xff) {
        pos++;
        continue;
      }
      const next = bytes[pos + 1]!;
      if (next === 0x00 || (next >= 0xd0 && next <= 0xd7)) {
        pos += 2;
        continue;
      }
      if (next === 0xff) {
        pos++;
        continue;
      }
      break;
    }
    parts.push({ marker: ENTROPY, start: dataStart, end: pos });
  }
}

function jpegPayload(bytes: Uint8Array, part: JpegPart): Uint8Array {
  return bytes.subarray(part.start + 4, part.end);
}

function isJpegExif(bytes: Uint8Array, part: JpegPart): boolean {
  return part.marker === APP1 && startsWith(jpegPayload(bytes, part), EXIF_PREFIX);
}

/** The TIFF structure inside the first EXIF APP1, or null. */
function findJpegExif(bytes: Uint8Array, parts: JpegPart[]): Uint8Array | null {
  const part = parts.find((p) => isJpegExif(bytes, p));
  return part ? jpegPayload(bytes, part).subarray(EXIF_PREFIX.length) : null;
}

function keepJpegPart(bytes: Uint8Array, part: JpegPart): boolean {
  const m = part.marker;
  if (m === 0xfe) return false;
  if (m < 0xe0 || m > 0xef) return true;
  if (m === APP0 || m === 0xee) return true;
  if (m === 0xe2) return startsWith(jpegPayload(bytes, part), ICC_PROFILE);
  return false;
}

function stripJpeg(bytes: Uint8Array): Uint8Array | null {
  const parts = walkJpeg(bytes);
  if (!parts) return null;
  const exif = findJpegExif(bytes, parts);
  const orientation = exif ? readOrientation(exif) : null;
  const kept = parts.filter((p) => keepJpegPart(bytes, p));
  const insert = needsOrientation(orientation)
    ? jpegSegment(APP1, concat([EXIF_PREFIX, orientationTiff(orientation)]))
    : null;
  return assembleJpeg(bytes, kept, insert);
}

/**
 * Concatenate the parts, placing `insert` after the leading run of APP0
 * segments when there is one, else directly after SOI. JFXX must follow the
 * JFIF APP0 immediately, which is why the whole run is skipped.
 */
function assembleJpeg(bytes: Uint8Array, parts: JpegPart[], insert: Uint8Array | null): Uint8Array {
  const pieces = parts.map((p) => bytes.subarray(p.start, p.end));
  if (insert) {
    let at = 1;
    while (at < parts.length && parts[at]?.marker === APP0) at++;
    pieces.splice(at, 0, insert);
  }
  return concat(pieces);
}

function jpegSegment(marker: number, payload: Uint8Array): Uint8Array {
  const length = payload.length + 2;
  return concat([new Uint8Array([0xff, marker, length >> 8, length & 0xff]), payload]);
}

// ── PNG ────────────────────────────────────────────────────────────────

type PngChunk = { type: string; start: number; end: number; dataStart: number; dataEnd: number };
const PNG_CUT = new Set(['eXIf', 'tEXt', 'zTXt', 'iTXt', 'tIME']);

/** Chunks from the signature through IEND. Null when a chunk runs past the
 *  end, IEND never comes, or there is no IDAT to put an eXIf in front of. */
function walkPng(bytes: Uint8Array): PngChunk[] | null {
  if (!startsWith(bytes, PNG_SIGNATURE)) return null;
  const chunks: PngChunk[] = [];
  let pos = PNG_SIGNATURE.length;
  for (;;) {
    if (pos + 8 > bytes.length) return null;
    const length = readU32BE(bytes, pos);
    const end = pos + 12 + length;
    if (end > bytes.length) return null;
    const type = String.fromCharCode(...bytes.subarray(pos + 4, pos + 8));
    chunks.push({ type, start: pos, end, dataStart: pos + 8, dataEnd: pos + 8 + length });
    if (type === 'IEND') break;
    pos = end;
  }
  return chunks.some((c) => c.type === 'IDAT') ? chunks : null;
}

function stripPng(bytes: Uint8Array): Uint8Array | null {
  const chunks = walkPng(bytes);
  if (!chunks) return null;
  const exif = chunks.find((c) => c.type === 'eXIf');
  const orientation = exif
    ? readOrientation(withoutExifPrefix(bytes.subarray(exif.dataStart, exif.dataEnd)))
    : null;
  const kept = chunks.filter((c) => !PNG_CUT.has(c.type));
  const insert = needsOrientation(orientation) ? pngChunk('eXIf', orientationTiff(orientation)) : null;
  return assemblePng(bytes, kept, insert);
}

/** Signature plus the chunks, with `insert` placed before the first IDAT. */
function assemblePng(bytes: Uint8Array, chunks: PngChunk[], insert: Uint8Array | null): Uint8Array {
  const pieces: Uint8Array[] = [PNG_SIGNATURE];
  for (const c of chunks) {
    if (insert && c.type === 'IDAT') {
      pieces.push(insert);
      insert = null;
    }
    pieces.push(bytes.subarray(c.start, c.end));
  }
  return concat(pieces);
}

function pngChunk(type: string, data: Uint8Array): Uint8Array {
  const body = concat([ascii(type), data]);
  return concat([u32be(data.length), body, u32be(crc32(body))]);
}

let crcTable: Uint32Array | null = null;

function crc32(bytes: Uint8Array): number {
  if (!crcTable) {
    crcTable = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      crcTable[n] = c;
    }
  }
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) {
    crc = crcTable[(crc ^ bytes[i]!) & 0xff]! ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

// ── WebP ───────────────────────────────────────────────────────────────

type RiffChunk = { fourcc: string; start: number; dataStart: number; dataEnd: number };
const VP8X_EXIF_FLAG = 0x08;
const VP8X_XMP_FLAG = 0x04;

/** Chunks inside the RIFF container, bounded by the RIFF size field so any
 *  trailing bytes are left behind. Null when truncated or when no image
 *  chunk exists. */
function walkWebp(bytes: Uint8Array): RiffChunk[] | null {
  const end = 8 + readU32LE(bytes, 4);
  if (end > bytes.length) return null;
  const chunks: RiffChunk[] = [];
  let pos = 12;
  while (pos + 8 <= end) {
    const size = readU32LE(bytes, pos + 4);
    const dataStart = pos + 8;
    const dataEnd = dataStart + size;
    if (dataEnd > end) return null;
    const fourcc = String.fromCharCode(...bytes.subarray(pos, pos + 4));
    chunks.push({ fourcc, start: pos, dataStart, dataEnd });
    pos = dataEnd + (size & 1);
  }
  const hasImage = chunks.some((c) => c.fourcc === 'VP8 ' || c.fourcc === 'VP8L' || c.fourcc === 'VP8X');
  return hasImage ? chunks : null;
}

function stripWebp(bytes: Uint8Array): Uint8Array | null {
  const chunks = walkWebp(bytes);
  if (!chunks) return null;
  const exif = chunks.find((c) => c.fourcc === 'EXIF');
  const orientation = exif
    ? readOrientation(withoutExifPrefix(bytes.subarray(exif.dataStart, exif.dataEnd)))
    : null;
  // An EXIF chunk is only read from the extended format, so without VP8X
  // there is no flag to keep and nothing that honoured the tag anyway.
  const keepOrientation = needsOrientation(orientation) && chunks.some((c) => c.fourcc === 'VP8X');
  const pieces: Uint8Array[] = [];
  for (const c of chunks) {
    if (c.fourcc === 'EXIF' || c.fourcc === 'XMP ') continue;
    if (c.fourcc === 'VP8X') {
      const data = bytes.slice(c.dataStart, c.dataEnd);
      data[0] = ((data[0] ?? 0) & ~(VP8X_EXIF_FLAG | VP8X_XMP_FLAG)) | (keepOrientation ? VP8X_EXIF_FLAG : 0);
      pieces.push(riffChunk(c.fourcc, data));
      continue;
    }
    pieces.push(riffChunk(c.fourcc, bytes.subarray(c.dataStart, c.dataEnd)));
  }
  if (keepOrientation) pieces.push(riffChunk('EXIF', orientationTiff(orientation)));
  const body = concat([ascii('WEBP'), ...pieces]);
  return concat([ascii('RIFF'), u32le(body.length), body]);
}

/** Header, data, and the pad byte that keeps the next chunk on an even offset. */
function riffChunk(fourcc: string, data: Uint8Array): Uint8Array {
  const pieces = [ascii(fourcc), u32le(data.length), data];
  if (data.length & 1) pieces.push(new Uint8Array(1));
  return concat(pieces);
}

// ── TIFF (the EXIF payload) ────────────────────────────────────────────

function isTiffHeader(bytes: Uint8Array): boolean {
  return startsWith(bytes, ascii('II*\0')) || startsWith(bytes, ascii('MM\0*'));
}

function withoutExifPrefix(bytes: Uint8Array): Uint8Array {
  return startsWith(bytes, EXIF_PREFIX) ? bytes.subarray(EXIF_PREFIX.length) : bytes;
}

/**
 * Where the orientation value sits inside IFD0, with the byte order the
 * header declares. Every read is bounds-checked; an offset outside the
 * payload means "no orientation", never a throw.
 */
function locateOrientation(tiff: Uint8Array): { offset: number; le: boolean } | null {
  if (tiff.length < 8) return null;
  const le = tiff[0] === 0x49 && tiff[1] === 0x49;
  if (!le && !(tiff[0] === 0x4d && tiff[1] === 0x4d)) return null;
  if (readTiff16(tiff, 2, le) !== 42) return null;
  const ifd = readTiff32(tiff, 4, le);
  if (ifd + 2 > tiff.length) return null;
  const count = readTiff16(tiff, ifd, le);
  for (let i = 0; i < count; i++) {
    const entry = ifd + 2 + i * 12;
    if (entry + 12 > tiff.length) return null;
    if (readTiff16(tiff, entry, le) !== ORIENTATION_TAG) continue;
    if (readTiff16(tiff, entry + 2, le) !== TIFF_SHORT || readTiff32(tiff, entry + 4, le) !== 1) return null;
    return { offset: entry + 8, le };
  }
  return null;
}

function readOrientation(tiff: Uint8Array): number | null {
  const found = locateOrientation(tiff);
  return found ? readTiff16(tiff, found.offset, found.le) : null;
}

/** A copy of the payload with the orientation entry, if any, set to 1. */
function withOrientationReset(tiff: Uint8Array): Uint8Array {
  const copy = tiff.slice();
  const found = locateOrientation(copy);
  if (found) {
    copy[found.offset] = found.le ? 1 : 0;
    copy[found.offset + 1] = found.le ? 0 : 1;
  }
  return copy;
}

/** Values 2 to 8 rotate or mirror; 1 is upright and anything else is undefined. */
function needsOrientation(orientation: number | null): orientation is number {
  return orientation !== null && orientation > 1 && orientation <= 8;
}

/** A big-endian TIFF whose IFD0 holds exactly one entry, the orientation. */
function orientationTiff(orientation: number): Uint8Array {
  return new Uint8Array([
    0x4d, 0x4d, 0x00, 0x2a, // "MM\0*"
    0x00, 0x00, 0x00, 0x08, // IFD0 at offset 8
    0x00, 0x01, // one entry
    0x01, 0x12, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, orientation, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, // no next IFD
  ]);
}

function readTiff16(tiff: Uint8Array, offset: number, le: boolean): number {
  if (offset + 2 > tiff.length) return -1;
  return le ? readU16LE(tiff, offset) : readU16BE(tiff, offset);
}

function readTiff32(tiff: Uint8Array, offset: number, le: boolean): number {
  if (offset + 4 > tiff.length) return -1;
  return le ? readU32LE(tiff, offset) : readU32BE(tiff, offset);
}

// ── Bytes ──────────────────────────────────────────────────────────────

function ascii(text: string): Uint8Array {
  return Uint8Array.from(text, (ch) => ch.charCodeAt(0));
}

function startsWith(bytes: Uint8Array, prefix: Uint8Array): boolean {
  if (bytes.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) {
    if (bytes[i] !== prefix[i]) return false;
  }
  return true;
}

function concat(pieces: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of pieces) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of pieces) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** Callers check bounds before reading; a short read past the end yields 0. */
function readU16BE(bytes: Uint8Array, o: number): number {
  return ((bytes[o] ?? 0) << 8) | (bytes[o + 1] ?? 0);
}

function readU16LE(bytes: Uint8Array, o: number): number {
  return (bytes[o] ?? 0) | ((bytes[o + 1] ?? 0) << 8);
}

function readU32BE(bytes: Uint8Array, o: number): number {
  return (((bytes[o] ?? 0) << 24) | ((bytes[o + 1] ?? 0) << 16) | ((bytes[o + 2] ?? 0) << 8) | (bytes[o + 3] ?? 0)) >>> 0;
}

function readU32LE(bytes: Uint8Array, o: number): number {
  return ((bytes[o] ?? 0) | ((bytes[o + 1] ?? 0) << 8) | ((bytes[o + 2] ?? 0) << 16) | ((bytes[o + 3] ?? 0) << 24)) >>> 0;
}

function u32be(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

function u32le(n: number): Uint8Array {
  return new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
}
