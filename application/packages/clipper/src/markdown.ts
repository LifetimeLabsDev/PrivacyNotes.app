/// <reference path="./gfm.d.ts" />
/**
 * Cleaned page markup to note Markdown.
 *
 * The note editor parses Markdown with raw HTML switched on, so the output of
 * this module must never hold HTML: text gets its `<` escaped, every element
 * Turndown would otherwise keep as markup is converted to its text, and a
 * table without a heading row gets its first row promoted so the table rule
 * takes it. Links keep only http, https and mailto targets. Pictures are
 * collected, not linked: each one becomes a token that the picture step
 * replaces with a stored picture or a text link that loads nothing.
 */
import TurndownService from 'turndown';
import { strikethrough, tables, taskListItems } from 'turndown-plugin-gfm';
import { httpAddress, pictureAddress } from './clean';

export interface ClipImage {
  src: string;
  alt: string;
}

/** The address a picture token carries: `pn-clip:<index>`. */
export const IMAGE_TOKEN_SCHEME = 'pn-clip:';

const LINK_SCHEMES = new Set(['http:', 'https:', 'mailto:']);

export function toMarkdown(root: Node, base: string, page = base): { markdown: string; images: ClipImage[] } {
  const images: ClipImage[] = [];
  const indexBySrc = new Map<string, number>();
  if ('querySelectorAll' in root) {
    unwrapLayoutTables(root as ParentNode);
    promoteHeaderRows(root as ParentNode);
    dropMarkerBrackets(root as ParentNode, base, page);
  }

  const service = new TurndownService({
    headingStyle: 'atx',
    hr: '---',
    bulletListMarker: '-',
    codeBlockStyle: 'fenced',
    emDelimiter: '*',
    strongDelimiter: '**',
    // A kept element would reach the note as raw HTML. Keep its text only.
    keepReplacement: (content, node) => ((node as { isBlock?: boolean }).isBlock ? `\n\n${content}\n\n` : content),
  });
  const escapeMarkdown = service.escape.bind(service);
  // `<` would open raw HTML. A `!` that ends a run of text would join the
  // link or picture that follows it into a picture of its own. `$`, `=` and
  // `|` open the editor's own pair rules (math, highlight, spoiler), and a
  // pair that reaches into a code span would end that span early.
  // A character Turndown escaped already keeps its one backslash.
  service.escape = (s: string) =>
    escapeMarkdown(s)
      .replace(/(\\*)([<$=|])/g, (whole, slashes: string, c: string) => (slashes.length % 2 ? whole : `${slashes}\\${c}`))
      .replace(/!$/, '\\!');

  service.use([tables, taskListItems]);
  strikethrough(service);
  service.addRule('strikethrough', {
    filter: ['del', 's', 'strike'] as (keyof HTMLElementTagNameMap)[],
    replacement: (content) => (content.trim() ? `~~${content}~~` : content),
  });
  service.addRule('tableCell', {
    filter: ['th', 'td'],
    replacement: (content, node) => {
      const cells = Array.from(node.parentNode?.childNodes ?? []);
      const prefix = cells.indexOf(node as ChildNode) === 0 ? '| ' : ' ';
      const cell = content.replace(/\s*\n+\s*/g, ' ').replace(/(\\*)\|/g, (whole, slashes: string) => (slashes.length % 2 ? whole : `${slashes}\\|`));
      return `${prefix}${cell.trim()} |`;
    },
  });

  // A fence longer than any run of backticks inside the code, wherever the
  // run sits: CommonMark closes a fence on an indented line too, and text
  // after an early close would be read as Markdown and HTML.
  // Every <pre> is code, with or without a <code> inside: documentation
  // sites and GitHub mark up highlighted code as <pre> full of spans.
  service.addRule('fencedCodeBlock', {
    filter: (node) => node.nodeName === 'PRE',
    replacement: (_content, node) => {
      const pre = node as Element;
      const code = pre.querySelector('code');
      const text = codeText(pre).replace(/\n$/, '');
      if (!text.trim()) return '';
      const classes = `${code?.getAttribute('class') ?? ''} ${pre.getAttribute('class') ?? ''} ${pre.parentElement?.getAttribute('class') ?? ''}`;
      const named = /(?:language|lang|highlight-source|highlight)-([\w+#]{1,30})|\bbrush:\s*([\w+#]{1,30})/.exec(classes);
      const lang = named?.[1] ?? named?.[2] ?? '';
      const longest = Math.max(0, ...(text.match(/`+/g) ?? []).map((run) => run.length));
      const fence = '`'.repeat(Math.max(3, longest + 1));
      return `\n\n${fence}${lang}\n${text}\n${fence}\n\n`;
    },
  });

  // `- item` rather than Turndown's `-   item`, the way the editor writes lists.
  service.addRule('listItem', {
    filter: 'li',
    replacement: (content, node, options) => {
      const parent = node.parentNode as Element | null;
      let prefix = `${options.bulletListMarker} `;
      if (parent?.nodeName === 'OL') {
        const start = Number(parent.getAttribute('start')) || 1;
        prefix = `${start + Array.from(parent.children).indexOf(node as Element)}. `;
      }
      const trimmed = content.replace(/^\n+/, '').replace(/\n+$/, '\n');
      // Lines of plain text inside one item (a quantity and its note in a
      // recipe) read as one line; a nested list, heading or code stays apart.
      const parts = trimmed.split(/\n\s*\n/).map((p) => p.trim()).filter(Boolean);
      const plain = parts.length > 1 && parts.every((p) => !p.includes('\n') && !/^(?:[-*+>#|]|\d+\.|```|!\[)/.test(p));
      const joined = plain ? `${parts.join(' ')}\n` : trimmed;
      // Indent every line but the item's last, which would otherwise end the
      // item with a line of spaces.
      const body = joined.replace(/\n(?!$)/g, `\n${' '.repeat(prefix.length)}`);
      return prefix + body + (node.nextSibling && !body.endsWith('\n') ? '\n' : '');
    },
  });

  service.addRule('link', {
    filter: (node) => node.nodeName === 'A',
    replacement: (content, node) => {
      const raw = (node as Element).getAttribute('href') ?? '';
      const href = linkTarget(raw, base);
      const text = content.trim();
      // A link into the page itself (a heading's own anchor, a citation, a
      // table of contents) means nothing in a note: its text stays, and a
      // bare marker such as a pilcrow, `[43]` or `[note 1]` goes.
      if (raw.trim().startsWith('#') || (href && samePage(href, page))) {
        return /^(?:\\?\[?\d{1,4}\\?\]?|[¶#§↑^]|🔗|\\#|\\\[[^\]\\]{1,12}\\\])$/u.test(text) ? '' : content;
      }
      if (!href || !text) return content;
      return `[${text}](${destination(href)})`;
    },
  });

  service.addRule('image', {
    filter: 'img',
    replacement: (_content, node) => {
      const alt = altText((node as Element).getAttribute('alt') ?? '');
      // An icon, a flag, an emoji or a tracking pixel is not a picture worth
      // storing: its alt text stands in for it, and it spends none of the
      // clip's pictures.
      if (isTiny(node as Element)) return service.escape(alt);
      const src = pictureAddress(node as Element, base);
      if (!src) return '';
      let index = indexBySrc.get(src);
      if (index === undefined) {
        index = images.length;
        images.push({ src, alt });
        indexBySrc.set(src, index);
      }
      return `![${escapeAlt(alt)}](${IMAGE_TOKEN_SCHEME}${index})`;
    },
  });

  // Figures, pictures and media wrappers carry no Markdown of their own.
  service.remove(['button', 'input', 'select', 'textarea', 'video', 'audio', 'source', 'track', 'map', 'area']);

  const converted = service
    .turndown(root as HTMLElement)
    .replace(/\n{3,}/g, '\n\n')
    .trim();
  return keepPlacedPictures(converted, images);
}

/** Drop the pictures whose token a parent rule threw away (a picture inside
 *  a button or a code block), and number the rest again, so no picture is
 *  downloaded or stored that the note never shows. */
function keepPlacedPictures(markdown: string, images: ClipImage[]): { markdown: string; images: ClipImage[] } {
  const token = new RegExp(`(!\\[(?:\\\\.|[^\\]\\\\])*\\]\\()${IMAGE_TOKEN_SCHEME}(\\d+)\\)`, 'g');
  const renumber = new Map<number, number>();
  const kept: ClipImage[] = [];
  const out = markdown.replace(token, (_whole, head: string, index: string) => {
    const old = Number(index);
    let next = renumber.get(old);
    if (next === undefined) {
      next = kept.length;
      kept.push(images[old]!);
      renumber.set(old, next);
    }
    return `${head}${IMAGE_TOKEN_SCHEME}${next})`;
  });
  return { markdown: out, images: kept };
}

/** Elements a Markdown table cell cannot hold: a cell is one line. */
const CELL_BLOCKS = 'table, p, h1, h2, h3, h4, h5, h6, pre, blockquote, hr';

/**
 * A table that lays out a page rather than holding data becomes its cells,
 * one after the other. That is a table of one column, or one whose cells
 * hold paragraphs, headings, code or other tables: a Markdown cell is a
 * single line, so such a table would come out as one endless row.
 */
function unwrapLayoutTables(root: ParentNode): void {
  for (const table of Array.from(root.querySelectorAll('table'))) {
    const rows = Array.from((table as HTMLTableElement).rows ?? []).filter((r) => r.closest('table') === table);
    const oneColumn = rows.every((r) => r.cells.length <= 1);
    const cells = rows.flatMap((r) => Array.from(r.cells));
    const holdsBlocks = cells.some((c) => c.querySelector(CELL_BLOCKS) || /<br\s*\/?>\s*<br/i.test(c.innerHTML));
    if (!oneColumn && !holdsBlocks) continue;
    const doc = table.ownerDocument;
    const out = doc.createElement('div');
    for (const cell of cells) {
      const block = doc.createElement('div');
      while (cell.firstChild) block.appendChild(cell.firstChild);
      out.appendChild(block);
    }
    const caption = table.querySelector(':scope > caption');
    if (caption) out.prepend(Object.assign(doc.createElement('p'), { textContent: caption.textContent ?? '' }));
    table.replaceWith(out);
  }
  // Readability turns a layout table it keeps into a <div> and leaves its
  // rows inside. A row with no table around it is layout too.
  for (const row of Array.from(root.querySelectorAll('tr'))) {
    if (row.closest('table')) continue;
    const doc = row.ownerDocument;
    const out = doc.createElement('div');
    for (const cell of Array.from(row.children)) {
      const block = doc.createElement('div');
      while (cell.firstChild) block.appendChild(cell.firstChild);
      out.appendChild(block);
    }
    row.replaceWith(out);
  }
}

/** A table the GitHub-flavoured rule would skip, because its first row is
 *  not all header cells, gets that row turned into header cells. */
function promoteHeaderRows(root: ParentNode): void {
  for (const table of Array.from(root.querySelectorAll('table'))) {
    const first = (table as HTMLTableElement).rows?.[0];
    if (!first) continue;
    if (first.parentElement?.nodeName === 'THEAD') continue;
    for (const cell of Array.from(first.cells)) {
      if (cell.nodeName === 'TH') continue;
      const th = table.ownerDocument.createElement('th');
      while (cell.firstChild) th.appendChild(cell.firstChild);
      cell.replaceWith(th);
    }
  }
}

/** The text of a code block. Editors such as CodeMirror draw each line as its
 *  own element with no newline in the text, and some sites use <br>; both
 *  become line ends. */
function codeText(pre: Element): string {
  const copy = pre.cloneNode(true) as Element;
  const doc = pre.ownerDocument;
  for (const br of Array.from(copy.querySelectorAll('br'))) br.replaceWith(doc.createTextNode('\n'));
  const lines = Array.from(copy.querySelectorAll('div, p, li, [class~="line"], [class*="cm-line"], [class*="code-line"]'));
  for (const line of lines) {
    if (!(line.textContent ?? '').endsWith('\n') && line.nextSibling) line.after(doc.createTextNode('\n'));
  }
  return copy.textContent ?? '';
}

/** Whether a link points into the page itself. */
function intoPage(link: Element, base: string, page: string): boolean {
  const raw = (link.getAttribute('href') ?? '').trim();
  const href = linkTarget(raw, base);
  return raw.startsWith('#') || (href !== null && samePage(href, page));
}

/** A footnote number linked into the page, with its brackets outside the
 *  link (`[<a href="#f1">1</a>]`), loses the brackets too: the link rule
 *  drops the number, and `[]` alone would stay in the text. */
function dropMarkerBrackets(root: ParentNode, base: string, page: string): void {
  for (const link of Array.from(root.querySelectorAll('a[href]'))) {
    if (!/^\d{1,4}$/.test((link.textContent ?? '').trim()) || !intoPage(link, base, page)) continue;
    const before = link.previousSibling;
    const after = link.nextSibling;
    if (before?.nodeType !== 3 || after?.nodeType !== 3) continue;
    const open = before as Text;
    const close = after as Text;
    if (!/\[\s*$/.test(open.data) || !/^\s*\]/.test(close.data)) continue;
    open.data = open.data.replace(/\[\s*$/, '');
    close.data = close.data.replace(/^\s*\]/, '');
  }
}

/** Whether `href` points into the page at `page`, at a fragment of it. */
function samePage(href: string, page: string): boolean {
  try {
    const a = new URL(href);
    const b = new URL(page);
    return a.hash !== '' && a.origin === b.origin && a.pathname === b.pathname && a.search === b.search;
  } catch {
    return false;
  }
}

/** A link target the note may keep, or null to keep only the text. */
function linkTarget(raw: string, base: string): string | null {
  const value = raw.trim();
  if (!value || value.startsWith('#')) return null;
  if (/^mailto:/i.test(value)) {
    try {
      const url = new URL(value);
      return LINK_SCHEMES.has(url.protocol) ? url.href : null;
    } catch {
      return null;
    }
  }
  return httpAddress(value, base);
}

/** A link destination Markdown reads as one token. `URL.href` encodes
 *  spaces and angle brackets for http addresses but not inside a mailto
 *  address, so those are encoded here; parentheses are escaped. */
function destination(href: string): string {
  return href.replace(/[ <>]/g, (c) => encodeURIComponent(c)).replace(/[()]/g, (c) => `\\${c}`);
}

/** The largest size, in pixels, at which a picture the page declares is
 *  taken for an icon. */
const TINY_PICTURE = 48;

/** Whether the page declares a picture no larger than an icon. */
function isTiny(img: Element): boolean {
  const sizes = ['width', 'height']
    .map((name) => img.getAttribute(name)?.trim() ?? '')
    .filter((v) => /^\d+(?:px)?$/.test(v))
    .map((v) => Number.parseInt(v, 10));
  return sizes.length > 0 && sizes.every((n) => n <= TINY_PICTURE);
}

function altText(raw: string): string {
  return raw.replace(/\s+/g, ' ').trim().slice(0, 200);
}

/** Alt text inside `![...]`: brackets, backslashes, `<` and the editor's
 *  pair characters escaped. */
export function escapeAlt(alt: string): string {
  return alt.replace(/[\\[\]<$=|]/g, (c) => `\\${c}`);
}
