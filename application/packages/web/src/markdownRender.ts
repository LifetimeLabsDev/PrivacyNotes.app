/**
 * Markdown → HTML renderer - single source of truth for all non-editor
 * rendering: Burn-After-Reading viewer, HTML export, and PDF (print).
 *
 * The editor produces a well-known subset (tiptap starter-kit +
 * tiptap-markdown): headings, bold/italic/strike, inline code, fenced
 * code, blockquotes, ul/ol (incl. GFM task lists), hr, links, images,
 * paragraphs. That's what we handle. Unknown syntax falls through as
 * plain paragraph text.
 *
 * Deliberately no new dependency - the subset is small enough that a
 * scoped hand-rolled renderer is less churn than pulling in marked / etc.
 */

import { faviconUrl } from './favicon';
import { unescapeMarkdownText } from './fileNames';
import { getFavicons } from './theme';

// ─── Obsidian callout types ────────────────────────────────────────────
//
// A blockquote whose first line is `[!type]` renders as a collapsible
// callout (<details>). Each canonical type has a hex accent color, the
// same color as an "R G B" triple for the translucent border/background,
// and a default label used when the callout has no title. Aliases below
// fold Obsidian's many synonyms down to these nine.

interface CalloutType {
  hex: string;
  rgb: string;
  label: string;
}

const CALLOUT_TYPES: Record<string, CalloutType> = {
  info: { hex: '1971c2', rgb: '25,113,194', label: 'Info' },
  success: { hex: '2f9e44', rgb: '47,158,68', label: 'Success' },
  warning: { hex: 'e8590c', rgb: '232,89,12', label: 'Warning' },
  tip: { hex: '0c8599', rgb: '12,133,153', label: 'Tip' },
  danger: { hex: 'e03131', rgb: '224,49,49', label: 'Danger' },
  question: { hex: 'f08c00', rgb: '240,140,0', label: 'Question' },
  quote: { hex: '868e96', rgb: '134,142,150', label: 'Quote' },
  example: { hex: '7048e8', rgb: '112,72,232', label: 'Example' },
  bug: { hex: 'c2255c', rgb: '194,37,92', label: 'Bug' },
  note: { hex: '1971c2', rgb: '25,113,194', label: 'Note' },
  abstract: { hex: '0c8599', rgb: '12,133,153', label: 'Abstract' },
  failure: { hex: 'e03131', rgb: '224,49,49', label: 'Failure' },
};

const CALLOUT_ALIASES: Record<string, string> = {
  info: 'info', note: 'note', todo: 'info', abstract: 'abstract', summary: 'abstract', tldr: 'abstract',
  success: 'success', check: 'success', done: 'success',
  warning: 'warning', caution: 'warning', attention: 'warning',
  tip: 'tip', hint: 'tip', important: 'tip',
  danger: 'danger', error: 'danger', failure: 'failure', fail: 'failure', missing: 'failure',
  question: 'question', help: 'question', faq: 'question',
  quote: 'quote', cite: 'quote',
  example: 'example',
  bug: 'bug',
};

// Phosphor arrows-in-simple / arrows-out-simple (regular weight, 256 viewBox).
// The export/print callout summary shows these as the collapse/expand
// affordance; the details[open] rule in export.ts toggles which is visible.
const CALLOUT_ARROW_IN = 'M213.66,53.66,163.31,104H192a8,8,0,0,1,0,16H144a8,8,0,0,1-8-8V64a8,8,0,0,1,16,0V92.69l50.34-50.35a8,8,0,0,1,11.32,11.32ZM112,136H64a8,8,0,0,0,0,16H92.69L42.34,202.34a8,8,0,0,0,11.32,11.32L104,163.31V192a8,8,0,0,0,16,0V144A8,8,0,0,0,112,136Z';
const CALLOUT_ARROW_OUT = 'M216,48V96a8,8,0,0,1-16,0V67.31l-50.34,50.35a8,8,0,0,1-11.32-11.32L188.69,56H160a8,8,0,0,1,0-16h48A8,8,0,0,1,216,48ZM106.34,138.34,56,188.69V160a8,8,0,0,0-16,0v48a8,8,0,0,0,8,8H96a8,8,0,0,0,0-16H67.31l50.35-50.34a8,8,0,0,0-11.32-11.32Z';

export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Allowlist a CSS color for the inline color spans emitted by the
 * editor's text-color feature. Returns the trimmed value if it is a plain
 * hex or rgb/rgba/hsl/hsla color, otherwise null. Intentionally strict:
 * it rejects semicolons, url(), and anything that could append a second
 * CSS declaration, so a malicious note can't smuggle styles through the
 * one span we let past the HTML escaper. This matters because this
 * renderer also powers the burn-after-reading viewer, which renders
 * untrusted sender-supplied markdown.
 */
function sanitizeColor(input: string): string | null {
  const c = input.trim();
  if (/^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/.test(c)) return c;
  if (/^(?:rgb|rgba|hsl|hsla)\([0-9.,%\s/]+\)$/i.test(c)) return c;
  return null;
}

/**
 * The other two things a `textStyle` span can carry (editorColors.ts):
 * a font size in `em`, and one of three generic family stacks. Same
 * strictness as sanitizeColor - no semicolons, no url(), no parens - so
 * neither can append a second declaration.
 */
function sanitizeFontSize(input: string): string | null {
  const v = input.trim();
  return /^\d+(?:\.\d+)?(?:em|rem|px|%)$/i.test(v) ? v : null;
}

function sanitizeFontFamily(input: string): string | null {
  const v = input.trim();
  return /^[a-zA-Z0-9 ,'-]+$/.test(v) ? v : null;
}

/** One of the four keywords TextAlign can store, or null. */
function sanitizeAlign(input: string): string | null {
  const v = input.trim().toLowerCase();
  return v === 'left' || v === 'center' || v === 'right' || v === 'justify' ? v : null;
}

/**
 * Reject URL schemes that can execute script when clicked. Applies to
 * `<a href>` values specifically - burn notes render untrusted
 * sender-provided markdown, so we must neuter `javascript:`,
 * `vbscript:`, and any `data:` payload (which can be text/html).
 *
 * Accept same-origin paths, absolute http(s), mailto, tel, and
 * fragment links. Everything else collapses to `#`.
 */
/**
 * Normalize a URL the way the browser's parser will, BEFORE deciding whether
 * it is safe. The parser strips leading C0 controls and spaces, and removes
 * ASCII tab, newline and carriage return from anywhere in the string.
 * JavaScript does neither: `trim()` leaves U+0001-U+0008 and U+000E-U+001F in
 * place, and `\s` does not match them either. So a scheme test run against the
 * raw attribute sees `\u0001javascript:alert(1)` as having no scheme, lets it
 * through as a relative path, and the parser then executes it.
 *
 * Two values come out of this. `cleaned` has every control character removed
 * and is what may be emitted, so nothing downstream ever sees one. `probe` also
 * has whitespace removed and is what the scheme test runs against. Spaces are
 * kept in `cleaned` because they are legitimate inside a path.
 */
function stripUrlControls(value: string): string {
  return value.replace(/[\u0000-\u001F\u007F]/g, '');
}

function sanitizeLinkHref(href: string): string {
  const cleaned = stripUrlControls(href).trim();
  if (cleaned === '') return '#';
  const probe = cleaned.replace(/\s/g, '');
  if (/^[a-z][a-z0-9+.-]*:/i.test(probe)) {
    if (/^(https?|mailto|tel):/i.test(probe)) return cleaned;
    return '#';
  }
  // No scheme - relative, root-relative, fragment, or query.
  return cleaned;
}

/**
 * Same idea for `<img src>`. Allow http(s), relative paths, our own
 * `pn:img/` scheme, and `data:image/…` (used by the inliner). Reject
 * everything else.
 */
function sanitizeImageSrc(src: string): string | null {
  const trimmed = src.trim();
  if (trimmed === '') return null;
  if (/^data:image\//i.test(trimmed)) return trimmed;
  if (/^pn:img\//i.test(trimmed)) return trimmed;
  if (/^https?:\/\//i.test(trimmed)) return trimmed;
  if (/^[a-z][a-z0-9+.-]*:/i.test(trimmed)) return null;
  return trimmed;
}

/**
 * Extract a hostname from a (possibly HTML-escaped) href for favicon lookup.
 * Returns null for non-http(s), relative, or unparseable URLs.
 */
function domainFromHref(href: string): string | null {
  try {
    const raw = href.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"');
    const url = new URL(raw);
    if (url.protocol === 'http:' || url.protocol === 'https:') return url.hostname;
    return null;
  } catch {
    return null;
  }
}

/**
 * Math rendering for exports, the burn viewer and print.
 *
 * The editor stores math as `$..$` / `$$..$$` LaTeX, and this renderer had
 * no case for either, so every formula exported as its literal source - the
 * same class of bug the 2026-08-11 audit found for underline and alignment,
 * missed then because math had shipped as a node type rather than a mark.
 *
 * KaTeX is asked for MATHML rather than its usual HTML. That output needs no
 * stylesheet and no fonts, which is the whole reason it works here: an
 * exported .html is a standalone file opened from disk with no external
 * calls, and embedding KaTeX's CSS plus its woff2 faces would add a quarter
 * of a megabyte to every export. Browsers render MathML natively, print
 * included.
 *
 * The import is DYNAMIC and only happens for markdown that actually contains
 * a `$`. KaTeX is ~82 KB gz and today lives only in the editor chunk; a
 * static import here would put it in the burn viewer's chunk too, which is
 * the one page a stranger loads from a link. See ops/docs/bundle-size.md.
 *
 * Callers await prepareMath(body) before renderMarkdown(body). Skipping that
 * is not fatal: renderTex returns null and the formula falls back to the
 * literal source it printed before, which is why the loader can stay off the
 * synchronous render path.
 */
type KatexRender = (tex: string, options: Record<string, unknown>) => string;
let katexRender: KatexRender | null = null;

async function prepareMath(md: string): Promise<void> {
  if (katexRender || !md.includes('$')) return;
  const mod = await import('katex');
  katexRender = mod.default.renderToString as unknown as KatexRender;
}

/**
 * renderMarkdown, degraded to escaped source if it throws.
 *
 * For the burn viewer, whose row is consumed before the page paints: the app
 * carries no error boundary, so a throw under it blanks the screen and the
 * one-time note is gone. Plain text the reader can still copy beats nothing.
 * Nothing in the renderer is known to throw, which is what a net is for.
 */
export function renderMarkdownSafe(md: string): string {
  try {
    return renderMarkdown(md);
  } catch (err) {
    console.error('[render] falling back to plain text:', err);
    return `<pre>${escapeHtml(md)}</pre>`;
  }
}

function renderTex(tex: string, display: boolean): string | null {
  if (!katexRender || !tex.trim()) return null;
  try {
    // throwOnError renders bad LaTeX in red rather than throwing, matching
    // what the editor shows for the same source (Editor.tsx katexOptions).
    return katexRender(tex, { output: 'mathml', displayMode: display, throwOnError: false });
  } catch {
    return null;
  }
}

/**
 * Syntax highlighting for fenced code, the same shape as the KaTeX loader
 * above: a DYNAMIC import behind a prepare call, because a highlighter has
 * no business in the burn viewer's chunk for notes without code - and the
 * import goes through markdownHighlight.ts rather than the 'lowlight'
 * package directly, because a dynamic namespace import keeps every grammar
 * alive (the module header there has the full story). Skipping
 * prepareRender degrades to the plain uncolored block this renderer always
 * produced.
 */
let highlightCode: ((code: string, lang: string) => string | null) | null = null;

async function prepareCodeHighlight(md: string): Promise<void> {
  // A fence with a language is ``` followed by a tag character; a bare
  // fence has nothing to highlight and must not cost the download.
  if (highlightCode || !/```[^\s`]/.test(md)) return;
  const mod = await import('./markdownHighlight');
  highlightCode = mod.highlightCode;
}

/** Everything the three export paths and the burn viewer await before renderMarkdown. */
export async function prepareRender(md: string): Promise<void> {
  await Promise.all([prepareMath(md), prepareCodeHighlight(md)]);
}

function renderFenceCode(code: string, lang: string): string | null {
  if (!highlightCode || !lang) return null;
  return highlightCode(code, lang);
}

/**
 * Inline `$..$`, mirroring `inlineMathRule` in editorExtensions.ts guard for
 * guard: no `$$`, no space just inside either delimiter, no newline, and no
 * digit after the closing `$` so "$5 and $10" stays prose. Written as a
 * scanner rather than a regex for one reason - the editor's version is a
 * scanner, and the two drifting apart is exactly how a price becomes a
 * formula in someone's PDF.
 *
 * Runs before the backslash-escape pass in renderInline, which would
 * otherwise eat the `\{`, `\}` and `\\` that LaTeX is made of.
 */
function extractInlineMath(raw: string, keep: (html: string) => string): string {
  let out = '';
  let i = 0;
  while (i < raw.length) {
    const open = raw.indexOf('$', i);
    if (open < 0) { out += raw.slice(i); break; }

    // A code span outranks a math delimiter, the same way markdown-it's own
    // code rule outranks the editor's math rule. Without this, `echo $HOME`
    // and `$var = 1` on one line pair their two dollars across the backticks
    // and render a formula inside the code - shell variables in inline code
    // being about the most ordinary thing a note can contain. Backtick runs
    // are matched the same single-backtick way the code-span pass below does,
    // so the two agree on what a code span is.
    const tick = raw.indexOf('`', i);
    if (tick >= 0 && tick < open) {
      const closeTick = raw.indexOf('`', tick + 1);
      if (closeTick > tick) {
        out += raw.slice(i, closeTick + 1);
        i = closeTick + 1;
        continue;
      }
    }

    out += raw.slice(i, open);
    if (raw[open + 1] === '$' || /\s/.test(raw[open + 1] ?? '') || open + 1 >= raw.length) {
      out += '$';
      i = open + 1;
      continue;
    }
    // Closing delimiter, skipping any escaped \$.
    let search = open + 1;
    let close = -1;
    while (search < raw.length) {
      const idx = raw.indexOf('$', search);
      if (idx < 0) break;
      if (raw[idx - 1] === '\\') { search = idx + 1; continue; }
      close = idx;
      break;
    }
    const tex = close > open + 1 ? raw.slice(open + 1, close) : '';
    const ok =
      close > open + 1 &&
      !/\s/.test(raw[close - 1] ?? '') &&
      !/\d/.test(raw[close + 1] ?? '') &&
      !tex.includes('\n');
    const html = ok ? renderTex(tex, false) : null;
    if (!html) {
      out += '$';
      i = open + 1;
      continue;
    }
    out += keep(html);
    i = close + 1;
  }
  return out;
}

function renderInline(raw: string): string {
  // The editor serializes empty paragraphs as the literal entity &nbsp;
  // (see EmptyParagraphSerializer). escapeHtml() below would turn it into
  // visible "&nbsp;" text in HTML/PDF export, so decode it to a real
  // non-breaking space up front - escapeHtml leaves U+00A0 untouched.
  // Spec: GitHub #103.
  raw = raw.replace(/&nbsp;/g, '\u00A0');

  // Inline math comes out FIRST: its LaTeX is made of the very characters
  // the backslash-escape pass below consumes, and its rendered MathML is
  // made of the tags escapeHtml would turn into visible text. Held behind a
  // sentinel until every pass has run, then restored raw.
  const mathHtml: string[] = [];
  raw = extractInlineMath(raw, (html: string) => {
    const idx = mathHtml.length;
    mathHtml.push(html);
    return `\x01M${idx}\x01`;
  });

  // Handle backslash escapes before HTML-escaping so \\ → \, \[ → [, etc.
  // Stash escaped characters behind sentinels so they survive all passes.
  const bsEscapes: string[] = [];
  const preprocessed = raw.replace(/\\([\\`*_{}[\]()#+\-.!|~>])/g, (_m: string, c: string) => {
    const idx = bsEscapes.length;
    bsEscapes.push(c);
    return `\x01E${idx}\x01`;
  });

  let t = escapeHtml(preprocessed);

  // Protect inline code spans first - content inside backticks should
  // not receive any further formatting passes.
  const codeSpans: string[] = [];
  t = t.replace(/`([^`]+)`/g, (_m: string, code: string) => {
    const idx = codeSpans.length;
    codeSpans.push(code);
    return `\x01C${idx}\x01`;
  });

  // Emitted <a>/<img> tags contain `_blank` and other characters that
  // the emphasis passes below would chew through. Stash completed
  // tags behind a sentinel and splice them back in at the end.
  const tagBuf: string[] = [];
  const stash = (html: string): string => {
    const idx = tagBuf.length;
    tagBuf.push(html);
    return `\x01T${idx}\x01`;
  };

  // Images ![alt](src) or ![alt](src){width=N} - must come before link
  // handling since the syntax is similar. Optional {width=N} suffix from
  // tiptap-markdown is captured and applied as an inline style.
  t = t.replace(
    /!\[([^\]]*)\]\(([^)\s]+)\)(?:\{([^}]*)\})?/g,
    (match: string, alt: string, src: string, attrs: string | undefined) => {
      const clean = sanitizeImageSrc(src);
      if (clean === null) return match; // leave raw - safer than emitting a broken <img>
      // Parse width from {width=N} attribute block if present. The editor
      // stores image width as a percentage of the container (presets
      // 25/50/75/100) and serializes it as a bare number, e.g. {width=50}.
      // A unit-less value is therefore a percentage, not pixels - emitting
      // px here made XS/S/M collapse to 25/50/75px (near-identical thumbs)
      // in HTML/PDF export. Spec: GitHub #103.
      const widthMatch = attrs?.match(/width=["']?(\d+%?)["']?/);
      const w = widthMatch?.[1];
      const widthStyle = w ? `width:${w.endsWith('%') ? w : `${w}%`};` : '';
      // `align=X` in the same suffix. An image is an inline element inside
      // its paragraph, so the alignment has to become a block box with auto
      // margins - putting text-align on the <img> itself does nothing.
      const align = sanitizeAlign(attrs?.match(/align=["']?([a-z]+)["']?/)?.[1] ?? '');
      const alignStyle =
        align === 'center' ? 'display:block;margin-left:auto;margin-right:auto;'
        : align === 'right' ? 'display:block;margin-left:auto;margin-right:0;'
        : '';
      return stash(`<img src="${clean}" alt="${alt}" style="max-width:100%;border-radius:4px;${widthStyle}${alignStyle}" />`);
    }
  );

  // Encrypted file attachments [name|size|mime](pn:file/<uuid>) - render
  // as a descriptive label since the encrypted blob can't be resolved
  // outside the app. Includes a tooltip explaining why.
  t = t.replace(
    /\[([^|]*)\|([^|]*)\|([^\]]*)\]\(pn:file\/[0-9a-f-]{36}\)/g,
    (_m: string, rawName: string, size: string, _mime: string) => {
      // Raw body text, so the name arrives markdown-escaped.
      const name = unescapeMarkdownText(rawName);
      return stash(`<span title="This attachment is encrypted and only accessible within PrivacyNotes. Use the full backup (zip) export to include file attachments." style="display:inline-flex;align-items:center;gap:0.4em;padding:0.15em 0.5em;background:#f3f3f3;border-radius:4px;font-size:0.9em;cursor:help">&#128206; ${name} (${size})</span>`);
    }
  );

  // Note-links [[target]] or [[target|label]] - render as plain text
  // since note-to-note links can't work outside the app.
  t = t.replace(/\[\[([^\]|]+)\|([^\]]+)\]\]/g, (_m: string, _target: string, label: string) => `<em>${label}</em>`);
  t = t.replace(/\[\[([^\]]+)\]\]/g, (_m: string, target: string) => `<em>${target}</em>`);

  // Links [text](url). URL itself is already HTML-escaped by the
  // initial pass, which is fine for href attribute safety.
  // Includes a favicon image when the href is an http(s) URL.
  //
  // Only the open and close tags are stashed. The label stays in the
  // stream, the way the textStyle span and the mark below also hold their
  // inner text there, so a label the editor wrote as `**bold**`, `==lit==`
  // or `<u>x</u>` reaches the passes that turn those into real tags. A
  // label stashed whole reaches none of them and shows its markers as
  // literal text. The label arrives HTML-escaped and stays that way: the
  // only passes that let a tag back through rebuild it from a fixed list
  // and validate every value, so a burn note cannot smuggle markup in
  // through a link label. Spec: GitHub #328.
  t = t.replace(
    /\[([^\]]+)\]\(([^)\s]+)\)/g,
    (_m: string, label: string, href: string) => {
      const domain = domainFromHref(href);
      const fav = domain && getFavicons() ? faviconUrl(domain) : '';
      const favicon = fav
        ? `<img src="${fav}" width="14" height="14" style="display:inline-block;vertical-align:middle;margin:0 3px 0 0;border-radius:2px;max-width:none" onerror="this.style.display='none'" />`
        : '';
      return (
        stash(`<a href="${sanitizeLinkHref(href)}" target="_blank" rel="noopener noreferrer">${favicon}`) +
        label +
        stash('</a>')
      );
    }
  );

  // Autolinks <http://…>. They come in HTML-escaped as &lt;http…&gt;, which
  // means every `&` inside the URL reads `&amp;` here - so the character
  // class must let `&amp;` through or the match dies at the first query
  // parameter, the URL stays literal text, and its `utm_source`-style
  // underscores get chewed into <em> by the emphasis passes below.
  t = t.replace(
    /&lt;(https?:\/\/(?:[^&\s]|&amp;)+)&gt;/g,
    (_m: string, url: string) => {
      const domain = domainFromHref(url);
      const fav = domain && getFavicons() ? faviconUrl(domain) : '';
      const favicon = fav
        ? `<img src="${fav}" width="14" height="14" style="display:inline-block;vertical-align:middle;margin:0 3px 0 0;border-radius:2px;max-width:none" onerror="this.style.display='none'" />`
        : '';
      // The icon is a box of its own, and CSS offers a line break right
      // after one. The text here is a whole URL, which is a single word, so
      // a column too narrow to hold it takes that break and strands the icon
      // on the line above. The first character carries the icon inside one
      // unbreakable span instead, which is safe on this branch alone: the
      // pattern guarantees the URL opens with `h`, never with a markdown
      // marker that a split would tear in half. Spec: GitHub #328.
      const text = favicon
        ? `<span style="white-space:nowrap">${favicon}${url.slice(0, 1)}</span>${url.slice(1)}`
        : url;
      return stash(`<a href="${sanitizeLinkHref(url)}" target="_blank" rel="noopener noreferrer">${text}</a>`);
    }
  );

  // Email autolinks <user@host>. CommonMark implies the mailto:, and the
  // serializer strips it back off (the autolink form is written whenever the
  // link text equals the href minus its scheme), so this is exactly the
  // shape a linkified email address is stored as. The character classes
  // admit nothing that needs escaping inside an href attribute.
  t = t.replace(
    /&lt;([A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,})&gt;/g,
    (_m: string, addr: string) => stash(`<a href="mailto:${addr}">${addr}</a>`),
  );

  // Inline style spans from the editor's Font popover: color, size and
  // family all hang off the one textStyle mark, so a span can carry any
  // combination of the three (`<span style="color: X; font-size: Y">`).
  // escapeHtml() above already turned the literal tags into their
  // &lt;/&quot;/&gt; forms, so we match the escaped form. Each declaration
  // is re-emitted only if its own sanitizer clears it and everything else
  // in the style is dropped, so this can't inject arbitrary HTML/CSS even
  // for untrusted burn-after-reading content. The inner text stays in the
  // stream so nested emphasis/links still render; the open/close tags are
  // stashed so the passes below leave them alone.
  //
  // Matching the whole style at once matters: the previous pattern ended
  // at the closing quote right after the color, so a run that was BOTH
  // colored and resized rendered as visible escaped tags, and font size
  // and family never rendered in an export at all.
  t = t.replace(
    /&lt;span style=&quot;([^&]*)&quot;&gt;([\s\S]*?)&lt;\/span&gt;/gi,
    (_m: string, style: string, inner: string) => {
      const decls: string[] = [];
      for (const part of style.split(';')) {
        const [rawProp, ...rest] = part.split(':');
        const prop = (rawProp ?? '').trim().toLowerCase();
        const value = rest.join(':');
        if (!prop || !value) continue;
        const safe =
          prop === 'color' ? sanitizeColor(value)
          : prop === 'font-size' ? sanitizeFontSize(value)
          : prop === 'font-family' ? sanitizeFontFamily(value)
          : null;
        if (safe) decls.push(`${prop}:${safe}`);
      }
      if (decls.length === 0) return inner;
      return stash(`<span style="${decls.join(';')}">`) + inner + stash('</span>');
    }
  );

  // Marks the editor writes as bare inline HTML: underline, superscript
  // and subscript. No attributes to sanitize - the tag name IS the whole
  // meaning - so they are simply let back through the escaper. Without
  // this an underlined word exported as the literal text `<u>word</u>`.
  t = t.replace(/&lt;(\/?)(u|sup|sub)&gt;/gi, (_m: string, slash: string, tag: string) =>
    stash(`<${slash}${tag.toLowerCase()}>`),
  );

  // Colored highlights. `==text==` cannot carry a color, so the editor
  // writes those runs as inline <mark style="background-color: ...">
  // (HighlightWithMarkdown). Same escaped-form matching and the same
  // single-declaration rebuild as the textStyle span above: the value is
  // re-validated through sanitizeColor and everything else in the style
  // is dropped, so an untrusted burn note cannot smuggle CSS through the
  // tag we let past the escaper. Runs before the `==` pass below, which
  // would otherwise never see these, and before the emphasis passes.
  t = t.replace(
    /&lt;mark style=&quot;([^&]*)&quot;&gt;([\s\S]*?)&lt;\/mark&gt;/gi,
    (_m: string, style: string, inner: string) => {
      const [rawProp, ...rest] = style.split(':');
      const prop = (rawProp ?? '').trim().toLowerCase();
      const safe = prop === 'background-color' ? sanitizeColor(rest.join(':')) : null;
      if (!safe) return stash('<mark>') + inner + stash('</mark>');
      return stash(`<mark style="background-color:${safe}">`) + inner + stash('</mark>');
    }
  );

  // ==highlight== (Obsidian syntax, HighlightWithMarkdown). Runs before
  // the emphasis passes so the doubled `=` can never be chewed up.
  t = t.replace(/==([^=]+)==/g, (_m: string, inner: string) =>
    stash('<mark>') + inner + stash('</mark>'),
  );

  // Strong+em (three asterisks), strong, em, strike. Underscores follow
  // CommonMark's intraword rule - a `_` flanked by word characters opens
  // nothing, so `utm_source=a&utm_medium=b` and `snake_case_names` stay
  // literal the way markdown-it keeps them in the editor. Asterisks are
  // deliberately NOT restricted the same way: intraword `**bold**` is
  // valid CommonMark and the editor renders it.
  t = t.replace(/\*\*\*([^*]+)\*\*\*/g, '<strong><em>$1</em></strong>');
  t = t.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  t = t.replace(/(^|[^*])\*([^*\s][^*]*?)\*(?!\*)/g, '$1<em>$2</em>');
  t = t.replace(/(^|\W)__([^_]+)__(?!\w)/g, '$1<strong>$2</strong>');
  t = t.replace(/(^|\W)_([^_\s][^_]*?)_(?!\w)/g, '$1<em>$2</em>');
  t = t.replace(/~~([^~]+)~~/g, '<del>$1</del>');

  // Restore stashed tags.
  t = t.replace(/\x01T(\d+)\x01/g, (_m: string, i: string) => tagBuf[Number(i)] ?? '');

  // Restore inline code last so its contents stay literal.
  t = t.replace(/\x01C(\d+)\x01/g, (_m: string, i: string) => {
    const span = codeSpans[Number(i)] ?? '';
    // Content is already escaped from the initial escapeHtml(raw) pass.
    return `<code>${span}</code>`;
  });

  // Restore backslash-escaped characters very last - they're literal
  // text that should not be interpreted by any pass above.
  t = t.replace(/\x01E(\d+)\x01/g, (_m: string, i: string) => escapeHtml(bsEscapes[Number(i)] ?? ''));

  // Math last of all: the MathML carries the original LaTeX in its
  // <annotation> element, so restoring it any earlier would hand the
  // emphasis passes a string full of underscores and asterisks.
  t = t.replace(/\x01M(\d+)\x01/g, (_m: string, i: string) => mathHtml[Number(i)] ?? '');

  return t;
}

/**
 * Neutralize an HTML block before it is passed through to the page.
 *
 * The editor writes real HTML for the things markdown cannot express -
 * tables it cannot draw as a pipe table, aligned blocks, an aligned task
 * list - and this renderer hands those straight to the burn viewer's
 * `dangerouslySetInnerHTML` and to the exported .html file. The block is
 * SENDER-supplied for a burn note (anyone can type raw HTML into the
 * markdown source view), so it is scrubbed on the way through.
 *
 * On the app origin the CSP does the heavy lifting already: `script-src`
 * carries no `unsafe-inline`, so an `onclick` never fires there. This
 * covers the two places that CSP does not reach - an exported .html file
 * opened from disk, where nothing constrains inline handlers - and the
 * one attack CSP was never going to stop: a `position: fixed` overlay
 * impersonating the app's own UI.
 *
 * Deliberately a denylist rather than an allowlist. Everything here is
 * something no editor feature emits; an allowlist would silently drop the
 * next attribute a TipTap upgrade starts writing (colwidth, colspan,
 * data-*) and break a feature quietly, which is the failure mode this
 * whole audit exists to fix.
 */
// Properties that let inline content reposition or overlay other content,
// which is how a crafted note or a stranger's burn note would build a
// clickjacking overlay on the origin that holds the phrase. `inset` is the
// shorthand for top/right/bottom/left, and `translate`/`rotate`/`scale` are
// the individual transform properties (CSS Transforms Level 2) that do what
// `transform` does, so blocking `transform` alone left the door open. Added
// 2026-08-28 after the pre-launch audit. `margin` is deliberately NOT here:
// the renderer emits `margin` in its own favicon image styles, and a nudge
// is not an overlay; the positioning vectors above are the real risk.
const UNSAFE_CSS_PROPS =
  /^(position|z-index|top|right|bottom|left|inset|transform|translate|rotate|scale|pointer-events)$/i;

function sanitizeEditorHtml(html: string): string {
  const doc = new DOMParser().parseFromString(`<body>${html}</body>`, 'text/html');
  // `noscript` is here for a reason the others are not: this parser runs with
  // scripting disabled, so it reads the element's content as markup and an
  // attribute inside it as an attribute, while the browser that renders the
  // serialized output reads the same bytes as text. Anything left inside one
  // therefore re-parses differently on the other side, handlers included.
  doc.body
    .querySelectorAll(
      'script,style,iframe,object,embed,link,meta,base,form,input[type="image"],noscript',
    )
    .forEach((el) => el.remove());
  doc.body.querySelectorAll('*').forEach((el) => {
    for (const attr of [...el.attributes]) {
      const name = attr.name.toLowerCase();
      if (name.startsWith('on')) {
        el.removeAttribute(attr.name);
      } else if (
        (name === 'href' || name === 'src' || name === 'xlink:href') &&
        // Test the parser-normalized form, never the raw attribute. See
        // stripUrlControls above for why the raw string cannot be trusted:
        // both an embedded tab and a leading control character defeat a
        // scheme test that the browser's own parser would see straight
        // through.
        /^(?:javascript|vbscript|data:text)/i.test(
          stripUrlControls(attr.value).replace(/\s/g, ''),
        )
      ) {
        el.removeAttribute(attr.name);
      } else if (name === 'style') {
        const kept = attr.value
          .split(';')
          .filter((decl) => {
            const prop = decl.split(':')[0]?.trim() ?? '';
            return prop !== '' && !UNSAFE_CSS_PROPS.test(prop) && !/url\s*\(/i.test(decl);
          })
          .join(';');
        if (kept.trim()) el.setAttribute('style', kept);
        else el.removeAttribute('style');
      }
    }
  });
  return doc.body.innerHTML;
}

/**
 * The editor's checkbox, restated as inline styles for the export and the
 * burn viewer: an appearance:none rounded box (the editor's 1.45em /
 * 0.33em / 1.5px proportions), filled with the brand accent and a white
 * check when checked. The editor fills with the active theme's accent; a
 * standalone exported file has no theme, so it gets the brand default.
 * Checked task TEXT dims and strikes through exactly as in the editor -
 * on an inner span only, so a nested sub-list under a checked task does
 * not inherit the strike (the editor scopes it the same way).
 * Spec: ops/docs/design-decisions.md (brand accent)
 */
const TASK_CHECK_SVG =
  "url('data:image/svg+xml;utf8,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 16 16%22><path d=%22M3.5 8.5l3 3 6-7%22 fill=%22none%22 stroke=%22%23fff%22 stroke-width=%222.4%22 stroke-linecap=%22round%22 stroke-linejoin=%22round%22/></svg>')";

const TASK_DONE_TEXT = 'text-decoration:line-through;color:#a3a3a3';

function taskCheckboxHtml(checked: boolean): string {
  const base =
    'appearance:none;-webkit-appearance:none;flex-shrink:0;width:1.45em;height:1.45em;margin:0;transform:translateY(0.15em);border-radius:0.33em;border:1.5px solid #a3a3a3;background:transparent';
  const fill = `background-color:#1e40af;border-color:#1e40af;background-image:${TASK_CHECK_SVG};background-size:0.82em;background-position:center;background-repeat:no-repeat`;
  return `<input type="checkbox" disabled${checked ? ' checked' : ''} style="${base}${checked ? `;${fill}` : ''}" />`;
}

/** Task text, struck through and dimmed when done - sub-lists stay outside. */
function taskTextHtml(checked: boolean, body: string, subHtml: string): string {
  const text = checked ? `<span style="${TASK_DONE_TEXT}">${body}</span>` : body;
  return `<span>${text}${subHtml}</span>`;
}

/**
 * Re-render an aligned task list into the same inline-styled markup the
 * markdown path produces for `- [ ] item`.
 *
 * A task list with an aligned item is stored as one HTML block (see
 * TaskListWithMarkdown in editorExtensions.ts). Passing that through raw
 * would export a checklist that only looks right with the app's own CSS
 * loaded - a bullet, a checkbox and the text on separate lines. Returns
 * null for any other list, which then takes the ordinary path.
 */
function renderTaskListHtml(block: string): string | null {
  const doc = new DOMParser().parseFromString(`<body>${block}</body>`, 'text/html');
  const list = doc.body.querySelector('ul[data-type="taskList"]');
  if (!list) return null;
  const items = [...list.children].map((li) => {
    const checked = li.getAttribute('data-checked') === 'true';
    const holder = li.querySelector('div');
    const para = holder?.querySelector('p');
    const align = sanitizeAlign(para?.style.textAlign ?? '');
    const inner = sanitizeEditorHtml((para ?? holder)?.innerHTML ?? '');
    const justify =
      align === 'center' ? ';justify-content:center'
      : align === 'right' ? ';justify-content:flex-end'
      : '';
    return (
      `<li style="list-style:none;display:flex;align-items:baseline;gap:0.5em;margin:0.2em 0${justify}">` +
        taskCheckboxHtml(checked) +
        taskTextHtml(checked, inner, '') +
      `</li>`
    );
  });
  // margin-left too: this path only runs for a list that HAS an aligned item,
  // and the surrounding stylesheet's own list indent would otherwise shift
  // the centring axis (see parseListBlock's closing tags for the long form).
  return `<ul style="list-style:none;padding-left:0;margin-left:0">${items.join('')}</ul>`;
}

/**
 * The list gutter an ALIGNED item's negative margin has to cancel exactly.
 * Only lists that contain one state it (see parseListBlock), so ordinary
 * exported lists keep whatever indent the surrounding stylesheet gives them.
 *
 * `rem`, NOT `em`, and that is the whole point: the padding is set on the
 * list and the negative margin on the item, and an `em` resolves against
 * whichever element it sits on. Wherever those two font sizes differ - they
 * do in the editor, 18px on the list and 15px on the item - an em-for-em
 * cancel leaves the item a few px off centre, which is exactly what the
 * first attempt at this shipped. rem is the same length in both places.
 * 1.828rem is Tailwind prose's own 1.625em at the list's 18px.
 */
const LIST_GUTTER = '1.828rem';

// ─── Nested list parser ───────────────────────────────────────────────
//
// tiptap-markdown serializes nested lists with indentation (2 spaces per
// level). The old flat parser only matched items at column 0 and dropped
// everything else into the paragraph collector. This recursive version
// handles arbitrary nesting depth.

interface ParsedListItem {
  indent: number;
  ordered: boolean;
  content: string;
  isTask: boolean;
  checked: boolean;
}

function detectListItem(line: string): ParsedListItem | null {
  const indent = line.length - line.trimStart().length;
  const trimmed = line.trimStart();

  const ulMatch = trimmed.match(/^[-*+]\s+(.*)/);
  if (ulMatch) {
    const content = ulMatch[1]!;
    const taskMatch = content.match(/^\[([ xX])\]\s+(.*)/s);
    if (taskMatch) {
      return { indent, ordered: false, content: taskMatch[2]!, isTask: true, checked: taskMatch[1]!.toLowerCase() === 'x' };
    }
    return { indent, ordered: false, content, isTask: false, checked: false };
  }

  const olMatch = trimmed.match(/^\d+\.\s+(.*)/);
  if (olMatch) {
    return { indent, ordered: true, content: olMatch[1]!, isTask: false, checked: false };
  }

  return null;
}

/**
 * Recursively parse a list block starting at `startI`. Items at
 * `baseIndent` are siblings; deeper-indented items form sub-lists.
 * Returns [html, nextIndex].
 */
function parseListBlock(lines: string[], startI: number, baseIndent: number): [string, number] {
  const first = detectListItem(lines[startI]!);
  if (!first) return ['', startI];

  const isOrdered = first.ordered;
  const firstIsTask = first.isTask;
  let hasTask = false;
  // Set by an aligned item below: the negative margin that pulls it out of
  // the gutter is only exact if the gutter itself is a known number, and
  // out here it is whatever the consumer's CSS says (Tailwind prose in the
  // burn viewer, the export stylesheet in a saved .html, the UA default in
  // neither). So a list that contains an aligned item states its own.
  let gutterPinned = false;
  const items: string[] = [];
  let i = startI;

  while (i < lines.length) {
    // A blank line between items makes the list LOOSE, not two lists. The
    // editor writes tight lists normally, so this went unnoticed until
    // alignment: a list holding an aligned item is always serialized loose,
    // and every item became its own <ol> - which restarted the numbering at
    // 1 on every line of an exported numbered list.
    if ((lines[i] ?? '').trim() === '') {
      let ahead = i;
      while (ahead < lines.length && (lines[ahead] ?? '').trim() === '') ahead++;
      const next = ahead < lines.length ? detectListItem(lines[ahead]!) : null;
      if (!next || next.indent !== baseIndent || next.ordered !== isOrdered || next.isTask !== firstIsTask) break;
      i = ahead;
      continue;
    }
    const item = detectListItem(lines[i]!);
    if (!item || item.indent < baseIndent) break;
    // Skip items indented deeper than expected (shouldn't happen at
    // this level - they're handled by recursion from the parent item).
    if (item.indent > baseIndent) break;
    // A marker of a different kind starts a NEW list, exactly as the editor
    // splits them into separate nodes: `1.` after a bullet used to be
    // swallowed into the <ul> and render as a bullet, and a task item after
    // a plain bullet turned the whole list marker-less.
    if (item.ordered !== isOrdered || item.isTask !== firstIsTask) break;

    i++;

    // Check for a sub-list: the next ITEM at a deeper indent belongs to the
    // item just emitted. The search skips blank lines, because the editor
    // serializes lists LOOSE - a blank line between every item, the nested
    // ones included - so the line directly after a parent is almost always
    // empty. A lookahead that read only `lines[i]` therefore found no child,
    // the loop returned to the blank-line branch above, that branch saw an
    // indent it did not expect and ended the list, and the orphaned child
    // fell through to the paragraph collector and rendered as the literal
    // text `- [ ] child` in the .html, the PDF and the burn viewer. Nested
    // checklists made in the editor were unreadable everywhere outside it.
    // The scan stops at the first non-blank line, so a paragraph between two
    // lists still separates them.
    let subHtml = '';
    {
      let ahead = i;
      while (ahead < lines.length && (lines[ahead] ?? '').trim() === '') ahead++;
      const next = ahead < lines.length ? detectListItem(lines[ahead]!) : null;
      if (next && next.indent > baseIndent) {
        const [sub, newI] = parseListBlock(lines, ahead, next.indent);
        subHtml = sub;
        i = newI;
      }
    }

    // An aligned item arrives as `- <p style="text-align: center">text</p>`,
    // because alignment has no markdown syntax and the editor writes the
    // block as HTML. Lift the alignment onto the <li> and render what was
    // inside the wrapper - it is already HTML (marks come out of the editor
    // as <strong>/<a>), so it is sanitized rather than parsed as markdown.
    const wrapped = item.content.match(
      /^<p style="text-align:\s*([a-z]+);?"\s*>([\s\S]*)<\/p>\s*$/i,
    );
    const align = wrapped ? sanitizeAlign(wrapped[1] ?? '') : null;
    const body = wrapped && align
      ? sanitizeEditorHtml(wrapped[2] ?? '')
      : renderInline(item.content.replace(/\\$/, ''));
    // Same three-part treatment as the editor (ui-patterns.md section 65):
    // the marker moves inside the content box so it can share the text's
    // line, the alignment goes on the item, and the gutter it no longer
    // needs comes back out via a negative margin - without that the item
    // sits half a gutter right of a centred heading. The wrapper paragraph
    // is already stripped above, so nothing here has to be made inline.
    const itemAlign =
      align === 'center' || align === 'right'
        ? `;list-style-position:inside;text-align:${align};margin-left:-${LIST_GUTTER}`
        : align === 'justify' ? ';text-align:justify'
        : '';
    if (align === 'center' || align === 'right') gutterPinned = true;

    if (item.isTask) {
      hasTask = true;
      items.push(
        `<li style="list-style:none;display:flex;align-items:baseline;gap:0.5em;margin:0.2em 0${
          align === 'center' ? ';justify-content:center' : align === 'right' ? ';justify-content:flex-end' : ''
        }">` +
          taskCheckboxHtml(item.checked) +
          taskTextHtml(item.checked, body, subHtml) +
        `</li>`
      );
    } else {
      items.push(`<li style="margin:0.15em 0${itemAlign}">${body}${subHtml}</li>`);
    }
  }

  // `margin-left:0` is not decoration. The export stylesheet indents lists
  // with `margin: 0 0 1em 1.5em` and Tailwind prose has its own; an aligned
  // item can only cancel the PADDING it can see, so whatever margin the
  // surrounding stylesheet adds shifts the centring axis right by that much
  // and the item lands off centre in the .html and the PDF while looking
  // correct in the editor. Pinned only for a list that holds an aligned
  // item, so ordinary exported lists keep the indent they have always had.
  const gutter = gutterPinned ? ` style="padding-left:${LIST_GUTTER};margin-left:0"` : '';
  if (isOrdered) return [`<ol${gutter}>${items.join('')}</ol>`, i];
  if (hasTask) {
    const taskStyle = `list-style:none;padding-left:0${gutterPinned ? ';margin-left:0' : ''}`;
    return [`<ul style="${taskStyle}">${items.join('')}</ul>`, i];
  }
  return [`<ul${gutter}>${items.join('')}</ul>`, i];
}

/**
 * Render a markdown string to HTML. Covers the editor's output subset.
 * Inline styles are used for task-list styling so the HTML renders
 * correctly in both the standalone export .html (no Tailwind) and
 * inside the Burn viewer (Tailwind prose) without style coordination.
 */
export function renderMarkdown(md: string): string {
  // Strip control characters used as internal sentinels to prevent
  // crafted input from colliding with the stash/restore mechanism.
  const text = md.replace(/\r\n?/g, '\n').replace(/[\x01\x02]/g, '');

  // Pull fenced code blocks out of the flow first so nothing inside
  // them gets treated as markdown. A language tag goes through lowlight
  // when prepareRender has loaded it (hljs token spans, the same classes
  // the editor emits); a bare fence, an unknown language, or an unloaded
  // highlighter all fall back to the plain escaped block.
  const fences: string[] = [];
  const withoutFences = text.replace(
    /```([^\n]*)\n([\s\S]*?)```/g,
    (_m: string, lang: string, body: string) => {
      const idx = fences.length;
      const code = body.replace(/\n$/, '');
      const langId = lang.trim().split(/\s+/)[0] ?? '';
      const highlighted = renderFenceCode(code, langId);
      fences.push(`<pre><code>${highlighted ?? escapeHtml(code)}</code></pre>`);
      return `\x02F${idx}\x02`;
    }
  );

  // Display math `$$..$$`, both the one-line form our serializer writes and
  // the multi-line form Obsidian and pandoc write (blockMathRule in
  // editorExtensions.ts reads both, so this has to as well). It runs AFTER
  // the fence pass, so a `$$` inside a code block is already behind a
  // sentinel and stays literal. The result is pushed into the same `fences`
  // array: both are block HTML that is finished before the line loop starts,
  // so the placeholder the loop already understands is the whole mechanism.
  const withoutMath = withoutFences.replace(
    /^\$\$([\s\S]*?)\$\$[ \t]*$/gm,
    (whole: string, tex: string) => {
      const html = renderTex(tex.trim(), true);
      if (!html) return whole;
      const idx = fences.length;
      // A block-level wrapper, centred inline because the exported document
      // has no stylesheet of ours to lean on.
      fences.push(`<div style="text-align:center;margin:1em 0">${html}</div>`);
      return `\x02F${idx}\x02`;
    }
  );

  const lines = withoutMath.split('\n');
  const out: string[] = [];
  let i = 0;

  const isTableRow = (line: string): boolean => /^\|.+\|$/.test(line.trim());
  const isTableSep = (line: string): boolean => /^\|[\s:|-]+\|$/.test(line.trim());

  // Block-level HTML the editor writes for what markdown cannot express.
  // p / h1-6 / ul / ol joined the original four when alignment shipped:
  // an aligned block is stored as `<p style="text-align: center">…</p>`
  // and an aligned checklist as one `<ul data-type="taskList">` block, and
  // without them here both exported as their own literal tags.
  const isHtmlBlock = (line: string): boolean =>
    /^<(table|div|details|figure|p|h[1-6]|ul|ol)\b/i.test(line.trim());

  const isOrphanClose = (line: string): boolean =>
    /^\s*<\/(table|div|details|figure|thead|tbody|tfoot|tr|th|td)>\s*$/i.test(line);

  const isBlockStart = (line: string): boolean =>
    /^(#{1,6})\s+/.test(line) ||
    /^>\s?/.test(line) ||
    /^\s*[-*+]\s+/.test(line) ||
    /^\s*\d+\.\s+/.test(line) ||
    /^\s*(---+|\*\*\*+|___+)\s*$/.test(line) ||
    /^\x02F\d+\x02$/.test(line) ||
    isTableRow(line) ||
    isHtmlBlock(line) ||
    isOrphanClose(line);

  while (i < lines.length) {
    const line = lines[i] ?? '';

    // Fence placeholder - emit as-is, it's already rendered.
    const fenceMatch = line.match(/^\x02F(\d+)\x02$/);
    if (fenceMatch && fenceMatch[1]) {
      out.push(fences[Number(fenceMatch[1])] ?? '');
      i++;
      continue;
    }

    // HTML block pass-through (e.g. tables serialized as HTML by tiptap-markdown).
    if (isHtmlBlock(line)) {
      const tagMatch = line.trim().match(/^<(\w+)/);
      const tag = tagMatch?.[1]?.toLowerCase() ?? '';
      const closeRe = new RegExp(`</${tag}>`, 'i');
      const htmlBuf: string[] = [line];
      if (!closeRe.test(line)) {
        i++;
        while (i < lines.length) {
          htmlBuf.push(lines[i] ?? '');
          if (closeRe.test(lines[i] ?? '')) { i++; break; }
          i++;
        }
      } else {
        i++;
      }
      let block = sanitizeEditorHtml(htmlBuf.join('\n'));
      // An aligned checklist comes through here as one <ul> block; give it
      // the same inline-styled markup the `- [ ] item` path produces so it
      // exports as a checklist rather than as app-CSS-dependent markup.
      if (tag === 'ul') {
        const tasks = renderTaskListHtml(block);
        if (tasks) {
          out.push(tasks);
          continue;
        }
      }
      // Add inline border styles to HTML tables that lack them - tiptap
      // serializes tables as raw HTML without styling. The export CSS
      // covers it via class selectors, but the burn viewer (Tailwind
      // prose) needs inline styles for consistent dark-mode borders.
      if (tag === 'table') {
        block = block
          .replace(/<table(?![^>]*style)/gi, '<table style="border-collapse:collapse;width:100%;margin:1em 0"')
          .replace(/<th(?![^>]*style)/gi, '<th style="border:1px solid #d4d4d4;padding:6px 10px;text-align:left;font-weight:600"')
          .replace(/<td(?![^>]*style)/gi, '<td style="border:1px solid #d4d4d4;padding:6px 10px"');
      }
      out.push(block);
      continue;
    }

    // Orphaned closing HTML block tags (e.g. </table> left over when
    // tiptap-markdown serializes tables and the closing tag lands outside
    // the block collector above). Strip silently - they have no semantic
    // value and would otherwise render as visible escaped text.
    if (isOrphanClose(line)) {
      i++;
      continue;
    }

    // Heading.
    const h = line.match(/^(#{1,6})\s+(.*)$/);
    if (h && h[1] && h[2] !== undefined) {
      const level = h[1].length;
      out.push(`<h${level}>${renderInline(h[2].trim())}</h${level}>`);
      i++;
      continue;
    }

    // Horizontal rule (allow leading whitespace - tiptap-markdown indents
    // HRs inside list items by the list continuation indent).
    if (/^\s*(---+|\*\*\*+|___+)\s*$/.test(line)) {
      out.push('<hr />');
      i++;
      continue;
    }

    // Blockquote (recursively render the quoted content). A blockquote
    // whose first de-prefixed line is `[!type]` is an Obsidian callout and
    // renders as a collapsible <details> instead.
    if (/^>\s?/.test(line)) {
      const buf: string[] = [];
      while (i < lines.length) {
        const cur = lines[i] ?? '';
        if (!/^>\s?/.test(cur)) break;
        buf.push(cur.replace(/^>\s?/, ''));
        i++;
      }
      const callout = buf[0]?.match(/^\[!(\w+)\]([+-]?)\s?(.*)$/);
      if (callout) {
        // Own-property only. A plain object answers every name on
        // Object.prototype, and `constructor` and `__proto__` are already
        // lower case, so the toLowerCase above does not save them: the
        // lookup returned a function, the `?? 'info'` fallback saw a truthy
        // value, and the type lookup below then read a property off
        // undefined. `toString` and its siblings survive by accident,
        // because lowercasing them produces a name nothing defines.
        const alias = callout[1]!.toLowerCase();
        const canon = Object.hasOwn(CALLOUT_ALIASES, alias)
          ? CALLOUT_ALIASES[alias]!
          : 'info';
        const t = CALLOUT_TYPES[canon]!;
        const title = callout[3]!.trim();
        const titleHtml = title ? renderInline(title) : escapeHtml(t.label);
        const bodyMd = buf.slice(1).join('\n');
        const bodyHtml = bodyMd.trim() === '' ? '' : renderMarkdown(bodyMd);
        const detailsStyle = `margin:1em 0;border:1px solid rgba(${t.rgb},0.35);border-left:3px solid #${t.hex};border-radius:6px;background:rgba(${t.rgb},0.09);overflow:hidden`;
        const summaryStyle = `cursor:pointer;list-style:none;display:flex;align-items:center;justify-content:space-between;gap:0.5em;padding:0.4em 0.85em;font-weight:600;color:#${t.hex}`;
        const arrows = `<span class="pn-callout-arrows" style="flex-shrink:0;line-height:0" aria-hidden="true"><svg class="pn-arrow-in" viewBox="0 0 256 256" width="15" height="15" fill="currentColor"><path d="${CALLOUT_ARROW_IN}"/></svg><svg class="pn-arrow-out" viewBox="0 0 256 256" width="15" height="15" fill="currentColor" style="display:none"><path d="${CALLOUT_ARROW_OUT}"/></svg></span>`;
        // The `-` suffix carries the fold state into the export and the burn
        // viewer, the same as the editor: a folded callout starts closed and
        // the reader clicks it open (the :not([open]) rules swap the arrow).
        // Print is the exception and handles itself in CSS: the export
        // stylesheet's print block force-shows every callout body, because
        // paper cannot be clicked.
        const folded = callout[2] === '-';
        out.push(
          `<details class="pn-callout pn-callout-${canon}"${folded ? '' : ' open'} style="${detailsStyle}">` +
            `<summary class="pn-callout-summary" style="${summaryStyle}"><span>${titleHtml}</span>${arrows}</summary>` +
            `<div class="pn-callout-body" style="padding:0.15em 0.85em 0.55em">${bodyHtml}</div>` +
          `</details>`
        );
        continue;
      }
      out.push(`<blockquote>${renderMarkdown(buf.join('\n'))}</blockquote>`);
      continue;
    }

    // List (unordered, ordered, or task) - recursive, handles nesting.
    const listItem = detectListItem(line);
    if (listItem && listItem.indent === 0) {
      const [listHtml, newI] = parseListBlock(lines, i, 0);
      out.push(listHtml);
      i = newI;
      continue;
    }

    // Indented code block (4 spaces or a tab), the other spelling of a code
    // block an imported file or a burn note can carry. Guarded on the nearest
    // preceding non-blank line NOT being a list item: a nested item's
    // continuation text is indented this deep too, and per CommonMark it
    // belongs to the list, not to a code block. An indented line directly
    // after a paragraph never reaches here either - the paragraph collector
    // below absorbs it, which is also CommonMark's rule.
    if (/^(?: {4}|\t)/.test(line) && line.trim() !== '') {
      let prev: string | null = null;
      for (let k = i - 1; k >= 0; k--) {
        const s = lines[k] ?? '';
        if (s.trim() !== '') { prev = s; break; }
      }
      if (prev === null || !detectListItem(prev)) {
        const buf: string[] = [];
        while (i < lines.length) {
          const cur = lines[i] ?? '';
          if (/^(?: {4}|\t)/.test(cur)) { buf.push(cur.replace(/^(?: {4}|\t)/, '')); i++; continue; }
          if (cur.trim() === '') {
            // A blank line stays inside the block only when more indented
            // code follows; otherwise the block ends before it.
            let ahead = i;
            while (ahead < lines.length && (lines[ahead] ?? '').trim() === '') ahead++;
            if (ahead < lines.length && /^(?: {4}|\t)/.test(lines[ahead] ?? '')) {
              for (let k = i; k < ahead; k++) buf.push('');
              i = ahead;
              continue;
            }
          }
          break;
        }
        out.push(`<pre><code>${escapeHtml(buf.join('\n'))}</code></pre>`);
        continue;
      }
    }

    // GFM pipe table.
    if (isTableRow(line)) {
      const rows: string[] = [line];
      i++;
      while (i < lines.length && isTableRow(lines[i] ?? '')) {
        rows.push(lines[i] ?? '');
        i++;
      }
      // Parse cells: split on `|`, trim, drop empty first/last.
      const parseCells = (row: string): string[] =>
        row.split('|').map((c) => c.trim()).filter((_, idx, arr) => idx > 0 && idx < arr.length - 1);

      // Row 2 is the separator (|---|---|) - detect it.
      const hasSep = rows.length >= 2 && isTableSep(rows[1]!);
      const headerRow = parseCells(rows[0]!);
      const bodyRows = hasSep ? rows.slice(2) : rows.slice(1);

      // Column alignment rides on the separator's colons (`:---:` center,
      // `---:` right). It used to be dropped whole: every th hardcoded
      // text-align:left and every td inherited the stylesheet's left, so an
      // aligned column looked right in the editor and left in the PDF.
      const aligns: (string | null)[] = hasSep
        ? parseCells(rows[1]!).map((sep) => {
            const colonLeft = sep.startsWith(':');
            const colonRight = sep.endsWith(':');
            return colonLeft && colonRight ? 'center' : colonRight ? 'right' : null;
          })
        : [];

      const tableHtml: string[] = ['<table style="border-collapse:collapse;width:100%;margin:1em 0">'];
      if (hasSep) {
        tableHtml.push('<thead><tr>');
        headerRow.forEach((cell, idx) => {
          tableHtml.push(`<th style="border:1px solid #d4d4d4;padding:6px 10px;text-align:${aligns[idx] ?? 'left'};font-weight:600">${renderInline(cell)}</th>`);
        });
        tableHtml.push('</tr></thead>');
      }
      tableHtml.push('<tbody>');
      const startRows = hasSep ? bodyRows : rows;
      for (const row of startRows) {
        const cells = parseCells(row);
        tableHtml.push('<tr>');
        cells.forEach((cell, idx) => {
          const align = aligns[idx] ? `;text-align:${aligns[idx]}` : '';
          tableHtml.push(`<td style="border:1px solid #d4d4d4;padding:6px 10px${align}">${renderInline(cell)}</td>`);
        });
        tableHtml.push('</tr>');
      }
      tableHtml.push('</tbody></table>');
      out.push(tableHtml.join(''));
      continue;
    }

    // Blank line - paragraph break.
    if (line.trim() === '') {
      i++;
      continue;
    }

    // Paragraph - collect consecutive non-empty, non-block-start lines.
    const para: string[] = [line];
    i++;
    while (i < lines.length) {
      const cur = lines[i] ?? '';
      if (cur.trim() === '' || isBlockStart(cur)) break;
      para.push(cur);
      i++;
    }
    // EVERY line boundary inside a paragraph is a hard break, because that
    // is what the editor shows: it parses with breaks:true (Editor.tsx), so
    // a bare source newline is a visible new line there, and this renderer
    // joining continuation lines with a space reflowed every never-edited
    // import (and every multi-line blockquote) into one long paragraph in
    // the PDF. The explicit markers are stripped before the break so they
    // never show: a trailing `\` is what the serializer writes, trailing
    // two-spaces is what an imported file carries verbatim.
    // Sentinel \x02B survives renderInline passes without interference.
    const withBreaks = para.map((l, idx) => {
      if (idx < para.length - 1) {
        if (l.endsWith('\\') && !l.endsWith('\\\\')) return l.slice(0, -1) + '\x02B';
        return l.replace(/[ \t]+$/, '') + '\x02B';
      }
      return l;
    }).join(' ');
    out.push(`<p>${renderInline(withBreaks).replace(/\x02B/g, '<br />')}</p>`);
  }

  return out.join('\n');
}

// ─── Same-origin image inlining ────────────────────────────────────────
//
// Exports / burn payloads that embed markdown images with absolute paths
// like `/onboarding/japan.jpg` work fine when viewed on privacynotes.app
// but break when the .html file is opened from disk (file:// has no
// way to resolve a root-relative path). Pre-walking the body and
// replacing same-origin paths with data URIs makes the output
// self-contained.
//
// We skip `pn:img/<uuid>` (those have their own resolver pipeline) and
// anything that isn't same-origin (leave the URL; user chose it).

function isSameOriginPath(src: string): boolean {
  if (src.startsWith('data:')) return false;
  if (src.startsWith('pn:img/')) return false;
  if (src.startsWith('/') && !src.startsWith('//')) return true;
  try {
    const u = new URL(src, window.location.origin);
    return u.origin === window.location.origin;
  } catch {
    return false;
  }
}

function blobToDataUri(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result ?? ''));
    r.onerror = () => reject(r.error);
    r.readAsDataURL(blob);
  });
}

/**
 * Fetch every same-origin `![alt](src)` image and replace with a data
 * URI. Anything that fails to fetch or isn't same-origin is left
 * untouched.
 *
 * @param maxTotalBytes optional cap - if inlining would push the body
 *   past this many bytes, skip the remaining images and leave them as
 *   URL refs. Useful for the burn payload's 32KB limit.
 */
export async function inlineSameOriginImages(
  body: string,
  maxTotalBytes?: number,
): Promise<string> {
  const re = /!\[([^\]]*)\]\(([^)\s]+)\)/g;
  const seen = new Set<string>();
  const targets: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) !== null) {
    const src = m[2];
    if (!src || seen.has(src)) continue;
    if (!isSameOriginPath(src)) continue;
    seen.add(src);
    targets.push(src);
  }
  if (targets.length === 0) return body;

  const resolved = new Map<string, string>();
  await Promise.all(
    targets.map(async (src) => {
      try {
        const res = await fetch(src);
        if (!res.ok) return;
        const blob = await res.blob();
        const dataUri = await blobToDataUri(blob);
        resolved.set(src, dataUri);
      } catch {
        // Silent - leave the URL ref in place.
      }
    }),
  );

  if (resolved.size === 0) return body;

  let projected = body.length;
  return body.replace(re, (match: string, _alt: string, src: string) => {
    const data = resolved.get(src);
    if (!data) return match;
    const delta = data.length - src.length;
    if (maxTotalBytes !== undefined && projected + delta > maxTotalBytes) {
      return match; // would overflow the cap - keep the URL ref
    }
    projected += delta;
    return match.replace(src, data);
  });
}

/**
 * Inline `/favicon?domain=...` images in rendered HTML as data URIs.
 * Used by the HTML export and print paths so files are self-contained.
 * No-op if no favicon images are present in the HTML.
 */
export async function inlineRenderedFavicons(html: string): Promise<string> {
  const re = /src="[^"]*\/favicon\?domain=([^"]+)"/g;
  const domains = new Set<string>();
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    domains.add(decodeURIComponent(m[1]!));
  }
  if (domains.size === 0) return html;

  const resolved = new Map<string, string>();
  await Promise.all(
    [...domains].map(async (domain) => {
      try {
        const res = await fetch(faviconUrl(domain));
        if (!res.ok) return;
        const blob = await res.blob();
        const dataUri = await blobToDataUri(blob);
        resolved.set(domain, dataUri);
      } catch {
        // Silent - leave the URL ref.
      }
    }),
  );

  if (resolved.size === 0) return html;

  return html.replace(
    /src="[^"]*\/favicon\?domain=([^"]+)"/g,
    (match: string, encoded: string) => {
      const domain = decodeURIComponent(encoded);
      const dataUri = resolved.get(domain);
      if (!dataUri) return match;
      return `src="${dataUri}"`;
    }
  );
}
