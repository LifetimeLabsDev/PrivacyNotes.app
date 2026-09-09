import JSZip from 'jszip';
import { linkifyMarkdown } from './linkify';
import { currentImageOptions, processImage } from '../imageProcessing';
import { EMOTION_TAGS } from '../trackerTypes';
import { toLocalIso } from '../notesViewUtils';
import type { ImportBlob, ImportedNote, ParsedImport } from './types';

/**
 * Apple Journal importer.
 *
 * Journal's File > Export writes a folder (usually zipped) with three
 * parts:
 *
 *   index.html              a link list, ignored - it carries nothing the
 *                           entries do not already say
 *   Entries/<date>_<title>.html   one file per entry
 *   Resources/<uuid>.<ext>  every photo, video, voice memo, and a JSON
 *                           sidecar per asset
 *
 * Each entry file is Cocoa HTML Writer output: Journal's own markup
 * (`.pageHeader`, `.assetGrid`, `.title`, `.bodyText`) pasted inside a
 * `<p><span>` wrapper, with all text styling pushed into per-file CSS
 * classes in the `<style>` block. The class names are NOT stable across
 * files - `span.s2` is bold in one entry and plain body text in the next
 * - so the style block has to be parsed per entry and the resulting
 * class -> marks map consulted while walking the body. Reading the class
 * name alone silently bolds half an import.
 *
 * Entries import as JOURNAL entries, not notes: type `journal` plus
 * `trackers.journalDate`, so they land in the Journal pillar on the day
 * they were written rather than in a flat pile of notes.
 *
 * Assets, by `assetType_*` class on the grid item:
 *   photo, livePhoto  -> inline image. Apple ships HEIC, which no browser
 *                        except Safari can decode, so every photo goes
 *                        through the same processImage() pipeline as a
 *                        drag-and-drop upload (HEIC -> JPEG always; size
 *                        and metadata follow the two image switches). The
 *                        blob is marked processed so the shared blob
 *                        import does not shrink it a second time.
 *   video             -> attachment (.mov), kept as-is
 *   audio             -> attachment (.caf). Apple's transcript sidecar is
 *                        dropped: the exporter strips the spaces out of it
 *   multiPinMap       -> dropped as an image, replaced by real map links
 *                        built from the `visits` sidecar
 *   stateOfMind       -> mood + emotion trackers where Apple's labels map
 *                        onto ours, the remainder as a text line
 *   everything else   -> the card's own overlay text as a text line
 *                        (contacts, workouts, motion, third-party media)
 *
 * Locations are the one thing Journal shows that we have no node for, so
 * they become links: a `visits` entry carries real coordinates and gets a
 * pin link, a bare `placeName` gets an OpenStreetMap search link. Both
 * land in a `Places` list at the end of the entry.
 */

/* ------------------------------------------------------------------ */
/* Paths                                                              */
/* ------------------------------------------------------------------ */

/** Files and folders that are never export content. */
function shouldSkip(path: string): boolean {
  const lower = path.toLowerCase();
  if (lower.startsWith('__macosx/') || lower.includes('/__macosx/')) return true;
  const name = path.split('/').pop() ?? '';
  return name.startsWith('.');
}

/**
 * Journal's own chrome, shipped in Resources/ alongside the user's media:
 * the waveform behind a voice memo, the play button, the quote bubble, and
 * the placeholder shown for a photo that did not export. None of them is
 * content, and all four would otherwise import as images.
 */
const CHROME_ASSETS = new Set([
  'audioplaybutton',
  'audiowave',
  'photos_icon',
  'quotebubble',
]);

function isChromeAsset(name: string): boolean {
  const base = (name.split('/').pop() ?? name).replace(/\.[^.]*$/, '');
  return CHROME_ASSETS.has(base.toLowerCase());
}

/** MIME from file extension, for the formats a Journal export can hold. */
function mimeFromExt(path: string): string {
  const ext = path.split('.').pop()?.toLowerCase() ?? '';
  const map: Record<string, string> = {
    heic: 'image/heic', heif: 'image/heif',
    jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png',
    gif: 'image/gif', webp: 'image/webp', tiff: 'image/tiff',
    mov: 'video/quicktime', mp4: 'video/mp4', m4v: 'video/x-m4v',
    caf: 'audio/x-caf', m4a: 'audio/mp4', mp3: 'audio/mpeg', wav: 'audio/wav',
  };
  return map[ext] ?? 'application/octet-stream';
}

/** ISO BMFF brands that mean "this is a HEIF image". */
const HEIF_BRANDS = new Set([
  'heic', 'heix', 'hevc', 'hevx', 'heim', 'heis', 'hevm', 'hevs', 'mif1', 'msf1',
]);

/**
 * The format an image really is, read from its first bytes.
 *
 * Journal names each exported photo after the format it was ORIGINALLY
 * shot in and then writes today's HEIC bytes into it, so an export is
 * dotted with `.png` and `.jpeg` files that are actually HEIF. Trusting
 * the extension made every one of them fail to decode - eight of
 * eighty-seven in the export this was built against - and the failure is
 * quiet, because a stored-but-undecodable image looks like an import that
 * worked until you open the note.
 *
 * Returns null for anything unrecognized so the caller falls back to the
 * extension.
 */
function sniffImageMime(b: Uint8Array): string | null {
  if (b.length < 12) return null;
  const tag = (at: number, len: number) => String.fromCharCode(...b.subarray(at, at + len));
  if (b[0] === 0x89 && tag(1, 3) === 'PNG') return 'image/png';
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'image/jpeg';
  if (tag(0, 3) === 'GIF') return 'image/gif';
  if (tag(0, 4) === 'RIFF' && tag(8, 4) === 'WEBP') return 'image/webp';
  if (tag(4, 4) === 'ftyp' && HEIF_BRANDS.has(tag(8, 4).toLowerCase())) return 'image/heic';
  if (tag(0, 4) === 'II\x2a\x00' || tag(0, 4) === 'MM\x00\x2a') return 'image/tiff';
  if (tag(0, 2) === 'BM') return 'image/bmp';
  return null;
}

/** The same filename with an extension that matches the given type, so a
 *  photo the user downloads actually opens. */
function nameForMime(name: string, mime: string): string {
  const ext = (mime.split('/')[1] ?? 'bin').replace('jpeg', 'jpg');
  return `${name.replace(/\.[^.]*$/, '')}.${ext}`;
}

/* ------------------------------------------------------------------ */
/* Dates                                                              */
/* ------------------------------------------------------------------ */

/**
 * The calendar date an entry belongs to.
 *
 * Two sources disagree, on purpose: the filename is stamped in UTC while
 * the `.pageHeader` line is the local date Journal shows above the entry,
 * and in this export five of thirty-seven entries were a day apart. A
 * journal entry belongs to the day its writer was living, so the header
 * wins - but only when it parses to something within a day of the
 * filename, since the header is written in the exporting device's
 * language and `Date.parse` only understands a few of them.
 */
function entryDate(header: string | null, filename: string): Date {
  const stamp = filename.match(/(\d{4})-(\d{2})-(\d{2})/);
  const fromName = stamp
    ? new Date(Number(stamp[1]), Number(stamp[2]) - 1, Number(stamp[3]), 12)
    : null;

  if (header) {
    const parsed = new Date(header.replace(/\s+/g, ' ').trim());
    if (!Number.isNaN(parsed.getTime())) {
      const local = new Date(parsed.getFullYear(), parsed.getMonth(), parsed.getDate(), 12);
      if (!fromName || Math.abs(local.getTime() - fromName.getTime()) <= 2 * 86400000) {
        return local;
      }
    }
  }
  // Noon, not midnight: the timestamp is only ever read back as a local
  // calendar date, and midnight is the one wall-clock time some zones
  // skip on a DST boundary.
  return fromName ?? new Date();
}

/* ------------------------------------------------------------------ */
/* Per-file style map                                                 */
/* ------------------------------------------------------------------ */

/** The marks one `span.sN` class carries. */
interface SpanStyle {
  bold: boolean;
  italic: boolean;
  underline: boolean;
  strike: boolean;
  /** Hex color, or null when the class sets none. */
  color: string | null;
}

/**
 * Read the entry's `<style>` block into a class -> marks map.
 *
 * Cocoa writes one class per distinct run of formatting, so this is the
 * only place bold, italic, underline, strikethrough and text color are
 * recorded anywhere in the file.
 */
export function parseSpanStyles(css: string): Map<string, SpanStyle> {
  const out = new Map<string, SpanStyle>();
  const rule = /span\.([\w-]+)\s*\{([^}]*)\}/g;
  let m: RegExpExecArray | null;
  while ((m = rule.exec(css)) !== null) {
    const cls = m[1]!;
    const decl = m[2]!;
    const decoration = decl.match(/text-decoration\s*:\s*([^;}]*)/i)?.[1] ?? '';
    // `-apple-system` and friends make `color:` a substring of
    // `background-color:`, so anchor on a declaration boundary.
    const color = decl.match(/(?:^|;)\s*color\s*:\s*(#[0-9a-fA-F]{3,8})/)?.[1] ?? null;
    out.set(cls, {
      bold: /font-weight\s*:\s*(bold|[6-9]00)/i.test(decl),
      italic: /font-style\s*:\s*italic/i.test(decl),
      underline: /underline/i.test(decoration),
      strike: /line-through/i.test(decoration),
      color,
    });
  }
  return out;
}

/** Wrap already-converted inline markdown in the marks a span carries. */
function applyMarks(inner: string, style: SpanStyle | undefined): string {
  if (!style || !inner.trim()) return inner;
  // Leading and trailing whitespace has to stay outside the markers, or
  // `** bold **` renders as literal asterisks.
  const lead = inner.match(/^\s*/)![0];
  const tail = inner.match(/\s*$/)![0];
  let core = inner.slice(lead.length, inner.length - tail.length);

  if (style.underline) core = `<u>${core}</u>`;
  if (style.strike) core = `~~${core}~~`;
  if (style.italic) core = `*${core}*`;
  if (style.bold) core = `**${core}**`;
  // Matches how the editor serializes its own colored text (see
  // TextStyleMarkdown in Editor.tsx), so it round-trips on the next save.
  if (style.color) core = `<span style="color: ${style.color}">${core}</span>`;
  return lead + core + tail;
}

/* ------------------------------------------------------------------ */
/* Places                                                             */
/* ------------------------------------------------------------------ */

/** One place harvested from an entry's assets. */
interface Place {
  label: string;
  latitude?: number;
  longitude?: number;
}

/**
 * A map link for a place.
 *
 * With coordinates this drops a pin at the exact spot; with only a name
 * it falls back to an OpenStreetMap search, which is all Journal gives us
 * for a photo's `placeName`.
 */
export function placeUrl(place: Place): string {
  const { latitude: lat, longitude: lon } = place;
  if (typeof lat === 'number' && typeof lon === 'number') {
    const at = `${lat}/${lon}`;
    return `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=17/${at}`;
  }
  return `https://www.openstreetmap.org/search?query=${encodeURIComponent(place.label)}`;
}

/* ------------------------------------------------------------------ */
/* State of mind                                                      */
/* ------------------------------------------------------------------ */

/** Apple's own emotion words, mapped onto our 24 emotion tags. Anything
 *  absent here is kept as text instead of being forced into a near-miss. */
const EMOTION_ALIASES: Record<string, string> = {
  amused: 'happy',
  annoyed: 'irritable',
  ashamed: 'guilty',
  brave: 'confident',
  content: 'relaxed',
  disappointed: 'sad',
  discouraged: 'sad',
  drained: 'tired',
  excited: 'energetic',
  indifferent: 'numb',
  irritated: 'irritable',
  joyful: 'happy',
  passionate: 'motivated',
  peaceful: 'calm',
  proud: 'confident',
  relieved: 'relaxed',
  satisfied: 'happy',
  scared: 'anxious',
  worried: 'anxious',
};

/** Apple's seven valence steps on our 1-10 mood scale. */
const VALENCE_MOOD: Record<string, number> = {
  'very unpleasant': 1,
  unpleasant: 3,
  'slightly unpleasant': 4,
  neutral: 5,
  'slightly pleasant': 6,
  pleasant: 8,
  'very pleasant': 10,
};

const EMOTION_KEYS = new Set(EMOTION_TAGS.map((t) => t.key));

/** Split one of Journal's comma-joined label strings. */
function splitLabels(raw: unknown): string[] {
  if (typeof raw !== 'string') return [];
  return raw.split(',').map((s) => s.trim()).filter(Boolean);
}

/* ------------------------------------------------------------------ */
/* HTML -> markdown                                                   */
/* ------------------------------------------------------------------ */

/** Formatting noticed while converting, surfaced as transforms. */
interface ConvFlags {
  bold: number;
  italic: number;
  underline: number;
  strike: number;
  color: number;
  lists: number;
  quotes: number;
}

/**
 * Convert one entry's `.bodyText` to the markdown our editor stores.
 *
 * Journal's writing surface is deliberately small: paragraphs, bulleted
 * and numbered lists, block quotes, and the five inline marks above. It
 * has no headings, no tables, no code blocks and no links, so this walker
 * is correspondingly short - anything unexpected falls through to its
 * text.
 */
function bodyToMarkdown(root: Element, styles: Map<string, SpanStyle>, flags: ConvFlags): string {
  function inlineOnly(text: string): string {
    return text.replace(/\s*\n+\s*/g, ' ').trim();
  }

  function renderList(el: Element, indent: string): string {
    const ordered = el.tagName.toLowerCase() === 'ol';
    flags.lists++;
    const lines: string[] = [];
    let n = 1;

    for (const li of Array.from(el.children)) {
      if (li.tagName.toLowerCase() !== 'li') continue;
      // A dashed list is still a `<ul>` (Journal only changes
      // `list-style-type`), so every unordered flavour renders as a
      // plain bullet.
      const marker = ordered ? `${n++}. ` : '- ';
      const nested: string[] = [];
      let inline = '';
      for (const child of Array.from(li.childNodes)) {
        const tag = child.nodeType === Node.ELEMENT_NODE
          ? (child as Element).tagName.toLowerCase()
          : '';
        if (tag === 'ul' || tag === 'ol') {
          nested.push(renderList(child as Element, `${indent}  `));
        } else {
          inline += walk(child, indent);
        }
      }
      lines.push(indent + marker + inlineOnly(inline));
      for (const block of nested) {
        const trimmed = block.replace(/\n+$/, '');
        if (trimmed) lines.push(trimmed);
      }
    }
    return lines.length > 0 ? `${lines.join('\n')}\n\n` : '';
  }

  function walk(node: Node, indent: string): string {
    if (node.nodeType === Node.TEXT_NODE) return node.textContent ?? '';
    if (node.nodeType !== Node.ELEMENT_NODE) return '';

    const el = node as Element;
    const tag = el.tagName.toLowerCase();
    const children = () => Array.from(el.childNodes).map((c) => walk(c, indent)).join('');

    switch (tag) {
      case 'style':
      case 'script':
      case 'audio':
      case 'video':
      case 'source':
        return '';

      case 'br':
        return '\n';

      case 'span': {
        const inner = children();
        // Cocoa puts every class on the element; only one of them is ever
        // a style class, and `Apple-converted-space` is not.
        for (const cls of Array.from(el.classList)) {
          const style = styles.get(cls);
          if (!style) continue;
          if (style.bold) flags.bold++;
          if (style.italic) flags.italic++;
          if (style.underline) flags.underline++;
          if (style.strike) flags.strike++;
          if (style.color) flags.color++;
          return applyMarks(inner, style);
        }
        return inner;
      }

      case 'ul':
      case 'ol':
        return renderList(el, indent);

      case 'li':
        // Only reached for a stray item outside a list.
        return `- ${inlineOnly(children())}\n`;

      case 'blockquote': {
        const inner = children().trim();
        if (!inner) return '';
        flags.quotes++;
        const quoted = inner.split('\n').map((l) => (l.trim() ? `> ${l}` : '>')).join('\n');
        return `\n${quoted}\n\n`;
      }

      case 'p':
      case 'div':
      default: {
        const inner = children();
        if (!inner.trim()) return '\n';
        return `${inner.trim()}\n\n`;
      }
    }
  }

  return Array.from(root.childNodes)
    .map((c) => walk(c, ''))
    .join('')
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

/* ------------------------------------------------------------------ */
/* Entry parsing                                                      */
/* ------------------------------------------------------------------ */

/** Blob placeholder token. Fixed width so no key is a prefix of another
 *  (the shared blob rewrite does a literal substring swap for images). */
function blobToken(index: number): string {
  return `ajblob:${String(index).padStart(6, '0')}`;
}

/** Text of the first matching child, trimmed, or ''. */
function textOf(root: Element, selector: string): string {
  return (root.querySelector(selector)?.textContent ?? '').replace(/\s+/g, ' ').trim();
}

interface Counters {
  photos: number;
  /** Photos that came out of the pipeline as a displayable JPEG. */
  converted: number;
  videos: number;
  audio: number;
  places: number;
  moods: number;
  cards: number;
  failedPhotos: number;
  missingAssets: number;
}

/** A photo waiting for its turn in the conversion pool. */
interface PhotoJob {
  token: string;
  name: string;
  entry: JSZip.JSZipObject;
}

interface AssetCtx {
  /** Lowercased Resources basename -> zip entry. */
  resources: Map<string, JSZip.JSZipObject>;
  /** Lowercased Resources basename (no extension) -> parsed sidecar JSON. */
  sidecars: Map<string, Record<string, unknown>>;
  /** Blob token -> blob, shared across the whole import. */
  blobs: Map<string, ImportBlob>;
  /** Photos are converted after every entry has been read, so the progress
   *  bar can count them against a real total. */
  photoJobs: PhotoJob[];
  /** Tokens handed out so far. Not `blobs.size`: a photo's token is issued
   *  while its entry is read and only filled in once the pool reaches it. */
  nextToken: number;
  counters: Counters;
}

/** Look a `../Resources/NAME.ext` reference up, case-insensitively. */
function resourceOf(ctx: AssetCtx, src: string | null): JSZip.JSZipObject | null {
  if (!src) return null;
  const base = decodeURIComponent(src.split('/').pop() ?? '').toLowerCase();
  return ctx.resources.get(base) ?? null;
}

/** Sidecar JSON for a grid item, keyed by the item's own id. */
function sidecarOf(ctx: AssetCtx, id: string | null): Record<string, unknown> | null {
  if (!id) return null;
  return ctx.sidecars.get(id.toLowerCase()) ?? null;
}

/** What one entry's asset grid produced. */
interface GridResult {
  /** Markdown for the media that renders in the note, in grid order. */
  media: string[];
  places: Place[];
  /** One-line summaries of cards that carry text but no media. */
  cards: string[];
  emotions: string[];
  mood: number | null;
}

async function readGrid(grid: Element | null, ctx: AssetCtx): Promise<GridResult> {
  const out: GridResult = { media: [], places: [], cards: [], emotions: [], mood: null };
  if (!grid) return out;

  for (const item of Array.from(grid.querySelectorAll('.gridItem'))) {
    const kind = Array.from(item.classList)
      .find((c) => c.startsWith('assetType_'))
      ?.slice('assetType_'.length) ?? '';
    const id = item.getAttribute('id');
    const sidecar = sidecarOf(ctx, id);

    // Every asset can carry a place name, whatever else it is.
    const placeName = typeof sidecar?.['placeName'] === 'string' ? sidecar['placeName'] : '';

    if (kind === 'photo' || kind === 'livePhoto') {
      const src = item.querySelector('img.asset_image')?.getAttribute('src') ?? null;
      if (src && !isChromeAsset(src)) {
        const token = queuePhoto(ctx, src);
        if (token) out.media.push(`![](${token})`);
      }
      if (placeName) out.places.push({ label: placeName });
      continue;
    }

    if (kind === 'video') {
      const src = item.querySelector('source')?.getAttribute('src') ?? null;
      const token = await storeFile(ctx, src);
      if (token) {
        out.media.push(`[Video](${token})`);
        ctx.counters.videos++;
      }
      if (placeName) out.places.push({ label: placeName });
      continue;
    }

    if (kind === 'audio') {
      const src = item.querySelector('source')?.getAttribute('src') ?? null;
      const token = await storeFile(ctx, src);
      if (token) {
        out.media.push(`[Voice recording](${token})`);
        ctx.counters.audio++;
      }
      // The sidecar carries Apple's transcript, and it is deliberately
      // left behind: the exporter strips every space between the words,
      // so what it hands over is one unbroken run of characters. It is
      // not searchable, not readable, and not repairable, and importing
      // it would only put a wall of text under every recording.
      continue;
    }

    if (kind === 'multiPinMap') {
      // The card's image is a rendered map thumbnail. The sidecar holds
      // the real coordinates, so link the places instead of importing a
      // picture of them.
      const visits = Array.isArray(sidecar?.['visits']) ? sidecar['visits'] : [];
      let added = 0;
      for (const raw of visits) {
        const v = raw as Record<string, unknown>;
        const name = typeof v['placeName'] === 'string' ? v['placeName'] : '';
        const city = typeof v['city'] === 'string' ? v['city'] : '';
        const label = [name, city].filter(Boolean).join(', ');
        if (!label) continue;
        const lat = typeof v['latitude'] === 'number' ? v['latitude'] : undefined;
        const lon = typeof v['longitude'] === 'number' ? v['longitude'] : undefined;
        out.places.push({ label, latitude: lat, longitude: lon });
        added++;
      }
      // No sidecar (or an empty one): the card's own caption is the only
      // place name we have.
      if (added === 0) {
        const caption = textOf(item, '.gridItemOverlayFooter') || placeName;
        if (caption) out.places.push({ label: caption });
      }
      continue;
    }

    if (kind === 'stateOfMind') {
      const labels = splitLabels(sidecar?.['labels']);
      const associations = splitLabels(sidecar?.['associations']);
      const leftover: string[] = [];
      for (const label of labels) {
        const key = label.toLowerCase();
        // Own property only: the label comes out of the file, and an
        // inherited name would return a function that is not undefined.
        const mood = Object.hasOwn(VALENCE_MOOD, key) ? VALENCE_MOOD[key] : undefined;
        if (mood !== undefined) {
          out.mood = mood;
          continue;
        }
        const mapped = EMOTION_KEYS.has(key)
          ? key
          : Object.hasOwn(EMOTION_ALIASES, key)
            ? EMOTION_ALIASES[key]
            : undefined;
        if (mapped && !out.emotions.includes(mapped)) {
          out.emotions.push(mapped);
          continue;
        }
        leftover.push(label);
      }
      // Only what found no structured home is repeated as text, so a
      // mapped emotion does not show up twice.
      if (leftover.length > 0) out.cards.push(`State of mind: ${leftover.join(', ')}`);
      // Apple's own framing for the life areas it asks you to tag. They
      // have no tracker of their own, so they always stay as text.
      if (associations.length > 0) out.cards.push(`Biggest impact: ${associations.join(', ')}`);
      continue;
    }

    // Contacts, workouts, motion, third-party media: cards whose image is
    // an icon or a chart. Their overlay text is the content.
    const line = [
      textOf(item, '.activityType'),
      textOf(item, '.gridItemOverlayHeader'),
      textOf(item, '.mediaTitle'),
      textOf(item, '.mediaCategory'),
      textOf(item, '.activityMetrics'),
      textOf(item, '.gridItemOverlayFooter'),
    ].filter(Boolean).join(' - ');
    if (line) {
      out.cards.push(line);
      ctx.counters.cards++;
    }
    if (placeName) out.places.push({ label: placeName });
  }

  // Every photo in an entry usually carries the SAME place name, so an
  // entry with six photos would otherwise list one town six times. Dedupe
  // here rather than at render time so the count the preview reports is
  // the count the user actually gets: 77 raw place names in the export
  // this was built against are 27 distinct links.
  const seen = new Set<string>();
  out.places = out.places.filter((p) => {
    const key = p.label.toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return out;
}

/** Claim a token for a photo and queue the conversion. */
function queuePhoto(ctx: AssetCtx, src: string): string | null {
  const entry = resourceOf(ctx, src);
  if (!entry) {
    ctx.counters.missingAssets++;
    return null;
  }
  const token = blobToken(ctx.nextToken++);
  ctx.photoJobs.push({ token, name: src.split('/').pop() ?? 'photo', entry });
  ctx.counters.photos++;
  return token;
}

/**
 * How many photos to convert at once.
 *
 * Journal exports HEIC, which no browser but Safari can decode, so every
 * photo goes through the app's own image pipeline (HEIC -> JPEG, EXIF
 * stripped, resized into the 2048px box) exactly as a drag-and-drop upload
 * would. That costs a few seconds each and a full-resolution bitmap of
 * headroom while it runs, which is why this is a small pool rather than a
 * Promise.all over the whole export: four at a time measured 1.78x faster
 * than one at a time on a ten-core machine, and a phone reporting four
 * cores runs two rather than trying to hold four 12-megapixel bitmaps.
 */
function poolSize(): number {
  const cores = typeof navigator !== 'undefined' ? navigator.hardwareConcurrency : 0;
  return Math.min(4, Math.max(2, (cores || 4) - 2));
}

/**
 * Convert every queued photo, `poolSize()` at a time.
 *
 * Returns the tokens whose bytes could not be read at all, so the entries
 * that referenced them do not end up showing a broken image. A photo that
 * reads but fails to convert keeps its original bytes instead - a HEIC the
 * user can still download beats a photo that silently vanished.
 */
async function runPhotoQueue(
  ctx: AssetCtx,
  onProgress?: (msg: string) => void,
): Promise<Set<string>> {
  const dropped = new Set<string>();
  const total = ctx.photoJobs.length;
  if (total === 0) return dropped;

  let next = 0;
  let done = 0;

  async function worker(): Promise<void> {
    for (;;) {
      const job = ctx.photoJobs[next++];
      if (!job) return;
      try {
        const raw = new Uint8Array(await job.entry.async('uint8array'));
        const mime = sniffImageMime(raw) ?? mimeFromExt(job.name);
        const result = await processImage(new File([raw], job.name, { type: mime }), currentImageOptions());
        if (result.ok) {
          ctx.counters.converted++;
          ctx.blobs.set(job.token, {
            data: result.image.data,
            mime: result.image.mime,
            name: result.image.name,
            processed: true,
          });
        } else {
          ctx.counters.failedPhotos++;
          ctx.blobs.set(job.token, { data: raw, mime, name: nameForMime(job.name, mime) });
        }
      } catch {
        ctx.counters.photos--;
        dropped.add(job.token);
      }
      done++;
      onProgress?.(`Converting photo ${done} of ${total}...`);
    }
  }

  await Promise.all(Array.from({ length: Math.min(poolSize(), total) }, () => worker()));
  return dropped;
}

/** Store a video or voice memo as an attachment blob, byte for byte. */
async function storeFile(ctx: AssetCtx, src: string | null): Promise<string | null> {
  const entry = resourceOf(ctx, src);
  if (!entry || !src) {
    if (src) ctx.counters.missingAssets++;
    return null;
  }
  const name = src.split('/').pop() ?? 'attachment';
  const data = new Uint8Array(await entry.async('uint8array'));
  const token = blobToken(ctx.nextToken++);
  ctx.blobs.set(token, { data, mime: mimeFromExt(name), name });
  return token;
}

/** Assemble one entry's markdown from its parts. */
function assemble(grid: GridResult, body: string): string {
  const blocks: string[] = [];
  if (grid.media.length > 0) blocks.push(grid.media.join('\n\n'));
  if (body) blocks.push(body);
  if (grid.cards.length > 0) {
    blocks.push(`**Also in this entry**\n\n${grid.cards.map((c) => `- ${c}`).join('\n')}`);
  }
  if (grid.places.length > 0) {
    const lines = grid.places.map((p) => `- [${p.label}](${placeUrl(p)})`);
    blocks.push(`**Places**\n\n${lines.join('\n')}`);
  }
  return blocks.join('\n\n');
}

/* ------------------------------------------------------------------ */
/* Zip parser                                                         */
/* ------------------------------------------------------------------ */

/** Journal's export is a FOLDER, and a file input cannot select one, so
 *  every error that sends the user back to Journal has to name the
 *  compress step - otherwise they re-export and hit the same wall. */
const EXPORT_HINT =
  'In Journal on your Mac choose File > Export, right-click the AppleJournal folder it writes and choose Compress, then pick that .zip here.';

export async function parseAppleJournal(
  file: File,
  onProgress?: (msg: string) => void,
): Promise<ParsedImport> {
  onProgress?.('Reading zip...');
  let zip: JSZip;
  try {
    zip = await JSZip.loadAsync(await file.arrayBuffer());
  } catch {
    throw new Error(`Could not read that file as a zip. ${EXPORT_HINT}`);
  }

  // Locate the export root by finding the Entries folder, wherever the
  // user's zip happens to have nested it.
  const paths: string[] = [];
  zip.forEach((path, entry) => {
    if (!entry.dir && !shouldSkip(path)) paths.push(path);
  });
  if (paths.length === 0) throw new Error('That zip is empty.');

  const anyEntry = paths.find((p) => /(^|\/)Entries\/[^/]+\.html?$/i.test(p));
  if (!anyEntry) {
    throw new Error(
      `That zip has no Entries folder, so it is not an Apple Journal export. ${EXPORT_HINT}`,
    );
  }
  const prefix = anyEntry.slice(0, anyEntry.toLowerCase().lastIndexOf('entries/'));

  const entryFiles: [string, JSZip.JSZipObject][] = [];
  const resources = new Map<string, JSZip.JSZipObject>();
  const sidecarFiles: [string, JSZip.JSZipObject][] = [];

  zip.forEach((path, entry) => {
    if (entry.dir || shouldSkip(path) || !path.startsWith(prefix)) return;
    const rel = path.slice(prefix.length);
    if (/^Entries\/[^/]+\.html?$/i.test(rel)) {
      entryFiles.push([rel, entry]);
    } else if (/^Resources\//i.test(rel)) {
      const base = (rel.split('/').pop() ?? '').toLowerCase();
      if (!base) return;
      if (base.endsWith('.json')) sidecarFiles.push([base, entry]);
      else resources.set(base, entry);
    }
  });

  if (entryFiles.length === 0) {
    throw new Error(`That export has no entries in it. ${EXPORT_HINT}`);
  }
  entryFiles.sort((a, b) => a[0].localeCompare(b[0]));

  // Sidecars first: every asset consults them, and they are tiny.
  onProgress?.('Reading locations...');
  const sidecars = new Map<string, Record<string, unknown>>();
  for (const [base, entry] of sidecarFiles) {
    try {
      const parsed: unknown = JSON.parse(await entry.async('string'));
      if (parsed && typeof parsed === 'object') {
        sidecars.set(base.replace(/\.json$/, ''), parsed as Record<string, unknown>);
      }
    } catch {
      // A malformed sidecar costs a place name, never the entry.
    }
  }

  const counters: Counters = {
    photos: 0, converted: 0, videos: 0, audio: 0, places: 0,
    moods: 0, cards: 0, failedPhotos: 0, missingAssets: 0,
  };
  const flags: ConvFlags = {
    bold: 0, italic: 0, underline: 0, strike: 0, color: 0, lists: 0, quotes: 0,
  };
  const blobs = new Map<string, ImportBlob>();
  const ctx: AssetCtx = {
    resources, sidecars, blobs, photoJobs: [], nextToken: 0, counters,
  };

  const notes: ImportedNote[] = [];
  let untitled = 0;

  for (let i = 0; i < entryFiles.length; i++) {
    const [rel, entry] = entryFiles[i]!;
    onProgress?.(`Reading entry ${i + 1} of ${entryFiles.length}...`);

    const doc = new DOMParser().parseFromString(await entry.async('string'), 'text/html');
    const styles = parseSpanStyles(doc.querySelector('style')?.textContent ?? '');

    const header = doc.querySelector('.pageHeader')?.textContent ?? null;
    const filename = rel.split('/').pop() ?? rel;
    const when = entryDate(header, filename);

    let title = (doc.querySelector('.title')?.textContent ?? '').replace(/\s+/g, ' ').trim();
    if (!title) {
      // Journal lets an entry go untitled; the date it was written is a
      // better handle than a wall of "Untitled".
      title = header?.replace(/\s+/g, ' ').trim() || toLocalIso(when);
      untitled++;
    }

    const grid = await readGrid(doc.querySelector('.assetGrid'), ctx);
    counters.places += grid.places.length;
    if (grid.mood !== null || grid.emotions.length > 0) counters.moods++;

    // Journal's markup is pasted inside a `<p><span>` wrapper, which the
    // HTML parser unwinds into `.bodyText` holding the prose. Falling back
    // to the whole document (minus the chrome) keeps a future layout
    // change from importing empty entries.
    let region = doc.querySelector('.bodyText');
    if (!region) {
      region = doc.body;
      for (const chrome of Array.from(region.querySelectorAll('.pageHeader, .assetGrid, .title'))) {
        chrome.remove();
      }
    }
    const body = assemble(grid, bodyToMarkdown(region, styles, flags));

    notes.push({
      title,
      body: linkifyMarkdown(body),
      tags: [],
      createdAt: when.toISOString(),
      updatedAt: when.toISOString(),
      type: 'journal',
      trackers: {
        // The Journal pillar groups by this, not by createdAt: an entry
        // belongs to the day it is about.
        journalDate: toLocalIso(when),
        ...(grid.mood !== null ? { mood: grid.mood } : {}),
        ...(grid.emotions.length > 0 ? { emotions: grid.emotions } : {}),
      },
    });
  }

  // Photos last: every entry has claimed its tokens by now, so the pool
  // knows the real total and the progress line can count against it.
  const dropped = await runPhotoQueue(ctx, onProgress);
  if (dropped.size > 0) {
    counters.missingAssets += dropped.size;
    for (const note of notes) {
      for (const token of dropped) {
        if (!note.body.includes(token)) continue;
        note.body = note.body.split(`![](${token})`).join('').replace(/\n{3,}/g, '\n\n').trim();
      }
    }
  }

  let blobBytes = 0;
  for (const blob of blobs.values()) blobBytes += blob.data.length;

  const plural = (n: number) => (n === 1 ? '' : 's');
  const warnings: string[] = [];
  if (counters.failedPhotos > 0) {
    warnings.push(
      `${counters.failedPhotos} photo${plural(counters.failedPhotos)} could not be converted out of Apple's HEIC format and were kept as-is, so they may not display.`,
    );
  }
  if (counters.missingAssets > 0) {
    warnings.push(
      `${counters.missingAssets} photo${plural(counters.missingAssets)} or video${plural(counters.missingAssets)} referenced by an entry was not in the export and had to be skipped.`,
    );
  }
  if (untitled > 0) {
    warnings.push(
      `${untitled} entr${untitled === 1 ? 'y' : 'ies'} had no title in Journal and were titled with their date.`,
    );
  }

  const transforms: string[] = [
    `Imported ${notes.length} entr${notes.length === 1 ? 'y' : 'ies'} as journal entries, dated the day each was written.`,
  ];
  if (counters.photos > 0) {
    transforms.push(
      `Converted ${counters.photos} photo${plural(counters.photos)} from HEIC so they display everywhere.`,
    );
  }
  if (counters.videos > 0) {
    transforms.push(`Found ${counters.videos} video${plural(counters.videos)} to import.`);
  }
  if (counters.audio > 0) {
    transforms.push(
      `Found ${counters.audio} voice recording${plural(counters.audio)} to import.`,
    );
  }
  if (counters.places > 0) {
    transforms.push(
      `Turned ${counters.places} location${plural(counters.places)} into map links.`,
    );
  }
  if (counters.moods > 0) {
    transforms.push(
      `Filled in the mood tracker on ${counters.moods} entr${counters.moods === 1 ? 'y' : 'ies'} from your State of Mind.`,
    );
  }
  if (flags.bold + flags.italic + flags.underline + flags.strike > 0) {
    transforms.push('Preserved bold, italic, underline, and strikethrough.');
  }
  if (flags.color > 0) {
    transforms.push(`Preserved text color on ${flags.color} run${plural(flags.color)} of text.`);
  }
  if (flags.lists > 0) {
    transforms.push(`Preserved ${flags.lists} list${plural(flags.lists)}.`);
  }
  if (flags.quotes > 0) {
    transforms.push(`Preserved ${flags.quotes} block quote${plural(flags.quotes)}.`);
  }
  transforms.push('Made bare URLs clickable.');

  return {
    notes,
    warnings,
    transforms,
    stats: {
      totalNotes: notes.length,
      emptyNotes: notes.filter((n) => !n.title.trim() && !n.body.trim()).length,
      untaggedNotes: notes.length,
      uniqueTags: 0,
    },
    source: 'apple-journal',
    blobBytes,
    blobs: blobs.size > 0 ? blobs : undefined,
  };
}
