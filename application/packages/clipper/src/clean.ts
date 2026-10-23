/**
 * Turn a downloaded HTML string into an inert document that holds only what
 * a reader of the page would see.
 *
 * `DOMParser` builds a document that runs no script and loads nothing, so a
 * stranger's page is safe to walk. It also has no layout, so nothing here can
 * ask the browser whether an element is visible: the attribute and inline
 * style checks below stand in for that.
 */

/** Elements that never carry text a reader sees, or that run or embed code. */
// Not <form>: some sites wrap the whole page in one, article included. Its
// controls (inputs, buttons) are dropped during the conversion instead.
const DROPPED = 'script, style, noscript, template, iframe, frame, frameset, object, embed, link, svg, canvas, dialog';

/** Hidden by markup rather than by a style sheet, or text meant for screen
 *  readers only ("list 1 of 3", "Skip links"), which a style sheet hides by
 *  one of these common class names. */
const HIDDEN = [
  '[hidden]', '[aria-hidden="true"]',
  '.screen-reader-text', '.screen-reader-only', '.sr-only', '.visually-hidden', '.visuallyhidden', '.a11y-hidden', '.assistive-text',
].join(', ');

const HIDDEN_STYLE = /(?:^|;)\s*(?:display\s*:\s*none|visibility\s*:\s*hidden)\b/i;

/** Attributes a lazy loader keeps the real picture address in. */
const LAZY_SRC = ['data-src', 'data-lazy-src', 'data-original', 'data-url', 'data-hi-res-src'];
const LAZY_SRCSET = ['data-srcset', 'data-lazy-srcset'];

/** Parse `html` and point its base at `finalUrl`, so every relative address
 *  resolves against the page's own location after redirects. A `<base>` the
 *  page carries is kept, resolved against that same location. */
export function parsePage(html: string, finalUrl: string): Document {
  const doc = new DOMParser().parseFromString(html, 'text/html');
  const own = doc.querySelector('base[href]')?.getAttribute('href');
  let base = finalUrl;
  if (own) {
    try {
      const resolved = new URL(own, finalUrl);
      if (resolved.protocol === 'https:' || resolved.protocol === 'http:') base = resolved.href;
    } catch {
      // A broken base falls back to the page address.
    }
  }
  for (const el of Array.from(doc.querySelectorAll('base'))) el.remove();
  const el = doc.createElement('base');
  el.setAttribute('href', base);
  (doc.head ?? doc.documentElement).prepend(el);
  return doc;
}

/** The address the document resolves relative addresses against. */
export function baseOf(doc: Document): string {
  return doc.querySelector('base')?.getAttribute('href') ?? '';
}

/** Remove everything a reader would not see, and give every lazily loaded
 *  picture its real address. Changes `doc` in place. */
export function cleanPage(doc: Document): void {
  for (const el of Array.from(doc.querySelectorAll(DROPPED))) el.remove();
  for (const el of Array.from(doc.querySelectorAll(HIDDEN))) el.remove();
  for (const el of Array.from(doc.querySelectorAll('[style]'))) {
    if (HIDDEN_STYLE.test(el.getAttribute('style') ?? '')) el.remove();
  }
  for (const img of Array.from(doc.querySelectorAll('img'))) fixLazyImage(img);
}

function fixLazyImage(img: Element): void {
  const src = img.getAttribute('src') ?? '';
  const placeholder = !src || src.startsWith('data:') || /(?:^|\/)(?:blank|spacer|pixel|placeholder|transparent)\.(?:gif|png)/i.test(src);
  if (placeholder) {
    const lazy = LAZY_SRC.map((name) => img.getAttribute(name)).find((v) => v && !v.startsWith('data:'));
    if (lazy) img.setAttribute('src', lazy);
  }
  if (!img.getAttribute('srcset')) {
    const lazySet = LAZY_SRCSET.map((name) => img.getAttribute(name)).find(Boolean);
    if (lazySet) img.setAttribute('srcset', lazySet);
  }
}

/**
 * The address to download for one picture: its `src`, or when that is
 * missing the widest `srcset` candidate up to 2048 pixels (the stored size),
 * else the narrowest one above it. Resolved against `base`. Null for an
 * address that is not http or https.
 */
export function pictureAddress(img: Element, base: string): string | null {
  const raw = img.getAttribute('src')?.trim() || pickFromSrcset(img.getAttribute('srcset') ?? '');
  if (!raw || raw.startsWith('data:')) return null;
  return httpAddress(raw, base);
}

function pickFromSrcset(srcset: string): string {
  const candidates = srcset
    .split(/,\s+(?=\S)/)
    .map((part) => {
      const [url = '', descriptor = ''] = part.trim().split(/\s+/);
      const width = /^(\d+)w$/.exec(descriptor);
      const density = /^([\d.]+)x$/.exec(descriptor);
      return { url, size: width ? Number(width[1]) : density ? Number(density[1]) * 1000 : 0 };
    })
    .filter((c) => c.url);
  if (candidates.length === 0) return '';
  const fitting = candidates.filter((c) => c.size <= 2048).sort((a, b) => b.size - a.size);
  if (fitting[0]) return fitting[0].url;
  return candidates.sort((a, b) => a.size - b.size)[0]!.url;
}

/** `raw` resolved against `base`, when the result is an http or https
 *  address; null for every other scheme. */
export function httpAddress(raw: string, base: string): string | null {
  try {
    const url = new URL(raw.trim(), base || undefined);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : null;
  } catch {
    return null;
  }
}
