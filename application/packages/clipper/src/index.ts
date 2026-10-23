/**
 * The clip engine: a downloaded web page in, note Markdown out.
 *
 * Shared by the in-app clipper and, later, the browser extension. It reads a
 * stranger's HTML, so it parses with `DOMParser` only (inert, no script, no
 * loads) and never renders the page. Load it with a dynamic `import()`: it
 * is not part of the app's boot path.
 * Spec: ops/docs/archive/web-clipper-stage1.md (section 3.2)
 */
import { Readability } from '@mozilla/readability';
import { baseOf, cleanPage, httpAddress, parsePage } from './clean';
import { readMetadata } from './metadata';
import { IMAGE_TOKEN_SCHEME, escapeAlt, toMarkdown, type ClipImage } from './markdown';
import { isSafeMarkdown, plainMarkdown } from './safety';

export type { ClipImage } from './markdown';
export { countFailures, placePictures, savePictures, CLIP_MAX_PICTURES, CLIP_MAX_PICTURE_BYTES } from './pictures';
export { isSafeMarkdown } from './safety';
export type { PictureOutcome, PictureDeps, PictureFailure } from './pictures';

/** `main`: the main text of the page (Readability). `page`: the whole
 *  cleaned body. */
export type ClipMode = 'main' | 'page';

export interface Clip {
  title: string;
  byline: string;
  siteName: string;
  published: string;
  description: string;
  /** The note text, with each picture as a `pn-clip:<index>` token. */
  markdown: string;
  /** The pictures in page order; token `<index>` names entry `<index>`. */
  images: ClipImage[];
}

/**
 * Clip `html`, downloaded from `finalUrl` (the address after redirects).
 * Returns null in `main` mode when no main text is found.
 */
export function clipHtml(html: string, finalUrl: string, mode: ClipMode): Clip | null {
  const doc = parsePage(html, finalUrl);
  const meta = readMetadata(doc);
  cleanPage(doc);
  const base = baseOf(doc);

  let root: Node | null = doc.body;
  let readable: ReturnType<Readability<Node>['parse']> = null;
  if (mode === 'main') {
    // Classes stay: they name a code block's language and its line elements.
    // The conversion writes no class into the note.
    readable = new Readability<Node>(doc, { serializer: (node) => node, keepClasses: true }).parse();
    root = readable?.content ?? null;
    if (!root || !readable?.textContent?.trim()) return null;
  }
  if (!root) return null;

  let { markdown, images } = toMarkdown(root, base, finalUrl);
  if (mode === 'main' && meta.isArticle) ({ markdown, images } = withLeadPicture(markdown, images, meta.image, base));
  // A page that slips markup past the conversion rules keeps its text only.
  if (!isSafeMarkdown(markdown)) {
    markdown = plainMarkdown(textOf(root));
    images = [];
  }
  if (!markdown.trim()) return null;
  // Readability takes these from the page text, line breaks included; the
  // note's source line must stay one line.
  const line = (s: string | null | undefined) => (s ?? '').replace(/\s+/g, ' ').trim().slice(0, 300);
  return {
    title: meta.title || line(readable?.title),
    byline: meta.byline || line(readable?.byline),
    siteName: meta.siteName || line(readable?.siteName),
    published: meta.published || line(readable?.publishedTime),
    description: meta.description || line(readable?.excerpt),
    markdown,
    images,
  };
}

/**
 * The address a redirect page sends the reader on to (`<meta http-equiv=
 * "refresh" content="0; url=...">` with a delay of a few seconds at most),
 * or null. The caller downloads it once more through the same checks.
 */
export function refreshTarget(html: string, finalUrl: string): string | null {
  const tag = /<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*>/i.exec(html.slice(0, 20000))?.[0];
  const content = tag && /content\s*=\s*["']([^"']*)["']/i.exec(tag)?.[1];
  const m = content && /^\s*(\d+)\s*[;,]\s*url\s*=\s*['"]?([^'"]+)/i.exec(content);
  if (!m || Number(m[1]) > 5) return null;
  return httpAddress(m[2]!, finalUrl);
}

/** The largest note body a clip may save, in UTF-8 bytes. The encrypted row
 *  must stay under the server's 1 MiB row ceiling.
 *  Spec: ops/docs/archive/web-clipper-stage1.md (section 3.2, Size) */
export const CLIP_MAX_BODY_BYTES = 700 * 1024;

/** How many bytes a stored picture address adds over its token. */
const STORED_GROWTH = 64;

const utf8 = (s: string) => new TextEncoder().encode(s).length;

/** Whether a clip's text stays under the cap whatever happens to its
 *  pictures: each token is counted as the larger of a stored address and the
 *  text link a picture that was not stored becomes. The longest label any
 *  language uses for that link is far under the 32 bytes allowed for it. */
export function clipFits(markdown: string, images: readonly ClipImage[]): boolean {
  let size = utf8(markdown);
  const token = new RegExp(`${IMAGE_TOKEN_SCHEME}(\\d+)\\)`, 'g');
  for (const m of markdown.matchAll(token)) {
    const image = images[Number(m[1])];
    const link = image ? utf8(escapeAlt(image.alt)) + utf8(image.src.replace(/[()]/g, '\\$&')) + 32 : 0;
    size += Math.max(STORED_GROWTH, link);
  }
  return size <= CLIP_MAX_BODY_BYTES;
}

/** Below this much text, a clip is often a sign-in, cookie or check page
 *  rather than the page itself, and the app suggests a bookmark. It is a
 *  suggestion only: a short post is a real page too.
 *  Spec: ops/docs/archive/web-clipper-stage1.md (D14) */
export const CLIP_SHORT_TEXT = 300;

/** Whether a clip holds less text than a reader would expect of a page.
 *  Pictures, link addresses and Markdown marks do not count; a Chinese,
 *  Japanese or Korean character counts three times, as it carries about a
 *  word. */
export function isShortText(markdown: string): boolean {
  const text = markdown
    .replace(/!\[(?:\\.|[^\]\\])*\]\([^)]*\)/g, '')
    .replace(/\]\((?:\\.|[^)\\])*\)/g, ']')
    .replace(/[\\#*_`[\]|>~=-]/g, '')
    .replace(/\s+/g, '');
  const dense = text.match(/[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}]/gu)?.length ?? 0;
  return [...text].length + dense * 2 < CLIP_SHORT_TEXT;
}

/** Whether a finished note body is under the cap. */
export function bodyFits(body: string): boolean {
  return utf8(body) <= CLIP_MAX_BODY_BYTES;
}

/**
 * The start of a note body for a preview, about `limit` characters long. It
 * keeps whole blocks; only a first block too long to show is cut, at a word,
 * and before a link or picture it would leave open, so the preview never
 * shows Markdown as text.
 */
export function previewOf(body: string, limit: number): string {
  const out: string[] = [];
  let size = 0;
  for (const block of body.split(/\n{2,}/)) {
    if (size + block.length <= limit) {
      out.push(block);
      size += block.length + 2;
      continue;
    }
    // The source line alone says nothing: cut the first block of text.
    if (out.length <= 1) {
      const cut = block.slice(0, Math.max(0, limit - size)).replace(/\s+\S*$/, '');
      out.push(`${cut.replace(/(?:^|(?<=[^\\]))!?\[(?:\\.|[^\]\\])*(?:\]\([^)]*)?$/, '').trimEnd()} …`);
    }
    break;
  }
  return out.join('\n\n');
}

/** The visible text of a node, one block per paragraph-like element. */
function textOf(root: Node): string {
  const doc = root.ownerDocument ?? (root as Document);
  const copy = root.cloneNode(true) as Element;
  for (const el of Array.from(copy.querySelectorAll?.('p, div, li, h1, h2, h3, h4, h5, h6, pre, blockquote, tr, br, section, article') ?? [])) {
    el.after(doc.createTextNode('\n\n'));
  }
  return copy.textContent ?? '';
}

export interface SourceLineParts {
  /** The link text of the source link ("Source"), in the reader's language. */
  sourceLabel: string;
  /** A published date as the reader's locale writes it. */
  formatDate: (date: Date) => string;
}

/**
 * The note body: one source line, a blank line, then the text.
 * `[Source](url) · example.com · Ana Reyes · 12 Oct 2026`. The parts that
 * are missing are left out.
 */
export function clipNoteBody(clip: Clip, url: string, parts: SourceLineParts): string {
  const line = [`[${escapeText(parts.sourceLabel)}](${url.replace(/[()]/g, (c) => `\\${c}`)})`];
  const host = hostOf(url);
  if (host) line.push(escapeText(host));
  if (clip.byline) line.push(escapeText(clip.byline));
  const date = parseDate(clip.published);
  if (date) line.push(escapeText(parts.formatDate(date)));
  return `${line.join(' · ')}\n\n${clip.markdown}`;
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, '');
  } catch {
    return '';
  }
}

/** The day a page names, as that calendar day: `2026-10-18T22:30:00Z` is
 *  the 18th wherever the reader is, as the page itself shows it. */
function parseDate(value: string): Date | null {
  if (!value) return null;
  const day = /^(\d{4})-(\d{2})-(\d{2})/.exec(value);
  if (day) return new Date(Number(day[1]), Number(day[2]) - 1, Number(day[3]));
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

/** Whether two picture addresses name one picture, perhaps at another size:
 *  the same address without its query, or the same file name once a size
 *  mark (`1280px-`, `-640x480`, `@2x`) and every extension are removed. */
function samePicture(a: string, b: string): boolean {
  try {
    const x = new URL(a);
    const y = new URL(b);
    if (`${x.origin}${x.pathname}` === `${y.origin}${y.pathname}`) return true;
    const stem = (u: URL) =>
      decodeURIComponent(u.pathname.split('/').pop() ?? '')
        .replace(/^\d{2,4}px-/, '')
        .replace(/(?:\.[a-z0-9]{2,5})+$/i, '')
        .replace(/(?:[-_]\d{2,5}x\d{2,5}|@\dx)$/i, '');
    const s = stem(x);
    return s.length >= 12 && s === stem(y);
  } catch {
    return a === b;
  }
}

/**
 * Put the page's lead picture first when the main text does not carry it.
 * Readability keeps the text of an article and often drops the photo above
 * it, which sits outside the text; the page names that photo in its Open
 * Graph or JSON-LD tags.
 */
function withLeadPicture(markdown: string, images: ClipImage[], lead: string, base: string): { markdown: string; images: ClipImage[] } {
  const src = lead ? httpAddress(lead, base) : null;
  if (!src || images.some((i) => samePicture(i.src, src))) return { markdown, images };
  const shifted = markdown.replace(new RegExp(`${IMAGE_TOKEN_SCHEME}(\\d+)\\)`, 'g'), (_m, n: string) => `${IMAGE_TOKEN_SCHEME}${Number(n) + 1})`);
  return { markdown: `![](${IMAGE_TOKEN_SCHEME}0)\n\n${shifted}`, images: [{ src, alt: '' }, ...images] };
}

/** Plain text that Markdown must read as text: its control characters and
 *  `<` escaped. */
function escapeText(text: string): string {
  return text.replace(/[\\`*_[\]<>#|~$=]/g, (c) => `\\${c}`);
}

