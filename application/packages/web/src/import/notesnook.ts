import JSZip from 'jszip';
import type { FolderDef } from '../folders';
import { normalizeTag } from '../notesRepo';
import { FRONT_MATTER } from '../markdownFolder/adapter';
import { buildFolderTree } from './folderImport';
import { BARE_LINKABLE_RE, linkifyMarkdown } from './linkify';
// Aliased: this file already has a `noteLinkTarget(ctx, href)` that resolves
// an href to a note TITLE. The shared one sanitizes a title into a writable
// link target. Two different jobs, one obvious name.
import { noteLinkTarget as sanitizeLinkTarget } from '../noteLinks';
import { importBlobs, mimeFromExt } from './blobImport';
import type { ImportedNote, ParsedImport } from './types';

/**
 * Notesnook importer.
 *
 * Notesnook's "Export all notes" (Settings > Backup & export) writes a
 * .zip with one file per note, nested in the notebook folders the note
 * belongs to, plus a flat `attachments/` folder. Four formats are on
 * offer; we accept the three that carry note content:
 *
 * 1. **HTML** (preferred). Full tiptap markup, so underline, checklists,
 *    tables, code blocks, and font styling all survive. Metadata rides
 *    in `<meta>` tags:
 *      <meta name="created-at" content="14-07-2026 07:11 PM" />
 *      <meta name="updated-at" content="14-07-2026 07:20 PM" />
 *      <meta name="tags" content="formatting, recipes" />
 *
 * 2. **Markdown + Frontmatter**. Same metadata as YAML frontmatter
 *    (`title`, `created_at`, `updated_at`, `tags`), but Notesnook has
 *    already flattened the note to basic markdown: underline, font
 *    family, font size, and text alignment are gone before we see it.
 *
 * 3. **Markdown**. As above, minus the frontmatter, so tags and the
 *    original timestamps are lost. Titles come from the leading `# `.
 *
 * The fourth export ("Text") has no structure worth parsing and is not
 * accepted. A full backup (.nnbackupz) is detected and rejected with a
 * pointer at the HTML export: its attachments are individually
 * encrypted (xchacha20-poly1305), which is a crypto dependency the
 * export path does not need.
 *
 * What we do with each format:
 *   - Notebook folders (the zip's directory nesting) are rebuilt as real
 *     folders via the shared buildFolderTree, at any depth. Same treatment
 *     the Obsidian vault importer gets (#178).
 *   - Internal note links (relative .html / .md hrefs) become [[note
 *     links]], resolved against the other notes in the zip so the target
 *     title is the real one, not the filename slug.
 *   - `attachments/` files are imported into encrypted storage; body
 *     references are rewritten to pn:img/ and pn:file/ URIs by the shared
 *     blob pipeline.
 *   - Highlights, math, and text alignment map onto the editor's own
 *     nodes (==highlight==, $..$/$$..$$, aligned HTML blocks - same
 *     contract as the UpNote importer). Formatting we have no node for
 *     (font family, font size, text color) is dropped, keeping the text.
 */

/* ------------------------------------------------------------------ */
/* Shared helpers                                                     */
/* ------------------------------------------------------------------ */

/** Files and folders that are never note content. */
function shouldSkip(path: string): boolean {
  const lower = path.toLowerCase();
  if (lower.startsWith('__macosx/') || lower.includes('/__macosx/')) return true;
  const name = path.split('/').pop() ?? '';
  if (name.startsWith('.')) return true;
  return false;
}

const HTML_EXT = /\.html?$/i;
const MD_EXT = /\.md$/i;
/** Notesnook writes every attachment to one `attachments/` folder at the
 *  export root; notebook folders sit beside it. Anchored so a notebook
 *  that happens to be named "attachments" further down the tree keeps its
 *  notes. */
const ATTACHMENT_DIR = /^attachments\//i;

/**
 * Notesnook stamps dates as `DD-MM-YYYY hh:mm AM/PM` (its own format, not
 * anything Date.parse understands). Returns an ISO string, or null when
 * the shape does not match so the caller can fall back to the zip entry's
 * mtime.
 */
function parseNotesnookDate(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const m = raw
    .trim()
    .match(/^(\d{1,2})-(\d{1,2})-(\d{4})[,\s]+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(AM|PM)?$/i);
  if (!m) return null;

  const day = Number(m[1]);
  const month = Number(m[2]);
  const year = Number(m[3]);
  let hour = Number(m[4]);
  const minute = Number(m[5]);
  const second = m[6] ? Number(m[6]) : 0;
  const meridiem = m[7]?.toUpperCase();

  if (month < 1 || month > 12 || day < 1 || day > 31) return null;
  if (meridiem === 'PM' && hour < 12) hour += 12;
  if (meridiem === 'AM' && hour === 12) hour = 0;
  if (hour > 23 || minute > 59 || second > 59) return null;

  const d = new Date(year, month - 1, day, hour, minute, second);
  if (Number.isNaN(d.getTime()) || d.getDate() !== day) return null;
  return d.toISOString();
}

/** Split a `tags` value ("a, b, c") into normalized tags. */
function splitTags(raw: string | null | undefined): string[] {
  if (!raw) return [];
  const out: string[] = [];
  for (const part of raw.split(',')) {
    const tag = normalizeTag(part.replace(/^["']|["']$/g, ''));
    if (tag && !out.includes(tag)) out.push(tag);
  }
  return out;
}

/** The directory portion of a zip-relative path ("" for a root file). */
function dirOf(rel: string): string {
  return rel.split('/').slice(0, -1).filter(Boolean).join('/');
}

/**
 * Resolve a relative href against the linking note's directory and
 * normalize `.` / `..` away, so `./../Sub3-Note.html` seen from
 * `A/B/C/note.html` comes back as `A/B/Sub3-Note.html`. Returns null for
 * anything absolute or external.
 */
function resolveRelative(baseDir: string, href: string): string | null {
  if (!href) return null;
  // Anything with a scheme, a protocol-relative prefix, or a root anchor
  // is not a link into the export.
  if (/^[a-z][a-z0-9+.-]*:/i.test(href) || href.startsWith('//') || href.startsWith('/')) {
    return null;
  }
  let clean = href.split('#')[0]!.split('?')[0]!;
  if (!clean) return null;
  try {
    clean = decodeURIComponent(clean);
  } catch {
    // Malformed percent-escapes: fall through with the raw string.
  }
  const segs = [...baseDir.split('/').filter(Boolean), ...clean.split('/')];
  const out: string[] = [];
  for (const seg of segs) {
    if (!seg || seg === '.') continue;
    if (seg === '..') { out.pop(); continue; }
    out.push(seg);
  }
  return out.join('/');
}

/**
 * Language for a code block's markdown fence.
 *
 * Notesnook names it in the class ("language-Plaintext" on the <pre>),
 * capitalized, rather than in a data attribute. Fences want a lowercase
 * token, and an explicit "plaintext" is the same as no language at all,
 * so it collapses to an unlabelled fence.
 */
function codeLanguage(pre: Element): string {
  const raw =
    pre.getAttribute('data-language') ??
    (`${pre.getAttribute('class') ?? ''} ${pre.querySelector('code')?.getAttribute('class') ?? ''}`.match(
      /(?:^|\s)language-([A-Za-z0-9+#-]+)/
    )?.[1] ??
      '');
  const lang = raw.trim().toLowerCase();
  return lang === 'plaintext' || lang === 'text' || lang === 'none' ? '' : lang;
}

/** Blob placeholder token. Fixed width so no key is a prefix of another
 *  (the shared blob rewrite does a literal substring swap for images). */
function blobToken(index: number): string {
  return `nnatt:${String(index).padStart(6, '0')}`;
}

/** Strip Notesnook's `<xxh64hash>-` filename prefix off an attachment. */
function attachmentName(rel: string): string {
  const base = rel.split('/').pop() ?? rel;
  return base.replace(/^[0-9a-f]{8,32}-/i, '') || base;
}

/* ------------------------------------------------------------------ */
/* Conversion context                                                 */
/* ------------------------------------------------------------------ */

/** Formatting we noticed while converting, surfaced as transforms. */
interface ConvFlags {
  underline: number;
  highlights: number;
  checklists: number;
  tables: number;
  codeBlocks: number;
  aligned: number;
  droppedStyling: number;
  droppedAlign: number;
  noteLinks: number;
  math: number;
}

/**
 * Notesnook marks a note both "Pinned" and "Favorite"; we have a single
 * starred flag, which the UI labels "Pinned". Either Notesnook flag maps
 * onto it, so a favorited note does not lose its mark. Matches how the
 * Keep, Simplenote, and Standard Notes importers map their pins.
 */
function isStarred(pinned: string | null, favorite: string | null): boolean {
  return pinned === 'true' || favorite === 'true';
}

interface ConvCtx {
  /** Directory of the note being converted (for relative link resolution). */
  baseDir: string;
  /** Normalized attachment path -> blob placeholder token. */
  attachmentTokens: Map<string, string>;
  /** Normalized note path -> that note's real title. */
  pathToTitle: Map<string, string>;
  flags: ConvFlags;
}

/** Resolve an href to a note-link target title, or null if it is not one. */
function noteLinkTarget(ctx: ConvCtx, href: string): string | null {
  const resolved = resolveRelative(ctx.baseDir, href);
  if (!resolved) return null;
  if (!HTML_EXT.test(resolved) && !MD_EXT.test(resolved)) return null;
  return ctx.pathToTitle.get(resolved.toLowerCase()) ?? null;
}

/** Resolve an href to an attachment placeholder, or null. */
function attachmentToken(ctx: ConvCtx, href: string): string | null {
  const resolved = resolveRelative(ctx.baseDir, href);
  if (!resolved) return null;
  return ctx.attachmentTokens.get(resolved.toLowerCase()) ?? null;
}

/**
 * Build a `[[target]]` / `[[target|label]]` note-link.
 *
 * The target goes through the shared sanitizer because a Notesnook title
 * can hold a pipe or a bracket, and writing one raw produces a link that
 * parses as a different target with different text. The sanitized target
 * still resolves: `noteLinkKey` compares it to the note's real title through
 * the same rule. Spec: packages/web/src/noteLinks.ts
 */
function noteLink(target: string, label: string): string {
  const t = sanitizeLinkTarget(target);
  const l = label.replace(/[[\]]/g, '').trim();
  if (!t) return l;
  if (!l || l === t) return `[[${t}]]`;
  return `[[${t}|${l}]]`;
}

const ALIGN_RE = /text-align:\s*(center|right|justify)/i;

/** Block-level tags an aligned HTML block cannot contain. */
const ALIGN_BLOCKERS = new Set([
  'p', 'div', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
  'ul', 'ol', 'table', 'pre', 'blockquote', 'hr', 'img', 'iframe', 'embed',
]);

/**
 * Can this aligned block be emitted as an aligned HTML block? Only simple
 * inline content qualifies: markdown inside an HTML block is not parsed,
 * so anything that must become markdown syntax (note-links, attachments,
 * math) forces the plain path and the alignment is dropped. A bare URL or
 * email anywhere in the text disqualifies too - the mandatory linkify
 * pass would wrap it in `<...>`, which inside an HTML block reads as a
 * broken tag and eats the address (BARE_LINKABLE_RE lives in linkify.ts
 * for exactly this reason). Same contract as the UpNote importer's.
 */
function isSimpleAlignable(el: Element, ctx: ConvCtx): boolean {
  if (BARE_LINKABLE_RE.test(el.textContent ?? '')) return false;
  for (const child of Array.from(el.childNodes)) {
    if (child.nodeType === Node.TEXT_NODE) continue;
    if (child.nodeType !== Node.ELEMENT_NODE) continue;
    const c = child as Element;
    const tag = c.tagName.toLowerCase();
    if (tag === 'br') continue;
    if (ALIGN_BLOCKERS.has(tag)) return false;
    if (/math-(?:block|inline)/i.test(c.getAttribute('class') ?? '')) return false;
    if (tag === 'a') {
      // Only plain external links can ride along as HTML; anything that
      // resolves inside the export becomes markdown syntax.
      const href = c.getAttribute('href') ?? '';
      if (!/^(?:https?:|mailto:)/i.test(href)) return false;
      if (attachmentToken(ctx, href) || noteLinkTarget(ctx, href)) return false;
    } else if (!['b', 'strong', 'i', 'em', 'u', 's', 'del', 'strike', 'code', 'kbd', 'span', 'sub', 'sup', 'mark'].includes(tag)) {
      return false;
    }
    if (!isSimpleAlignable(c, ctx)) return false;
  }
  return true;
}

function escapeHtml(s: string): string {
  // Escapes the double quote as well, because this value is
  // interpolated into an href attribute below (a <a href="...">).
  // Without it a URL that passes the scheme test but carries a quote,
  // for example https://x\" onmouseover=\"..., breaks out of the
  // attribute. Matches the canonical escapeHtml in markdownRender.ts.
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** Render simple inline content as sanitized HTML for an aligned block. */
function renderInlineHtml(node: Node, ctx: ConvCtx): string {
  if (node.nodeType === Node.TEXT_NODE) {
    return escapeHtml(node.textContent ?? '');
  }
  if (node.nodeType !== Node.ELEMENT_NODE) return '';
  const el = node as Element;
  const tag = el.tagName.toLowerCase();
  const children = () =>
    Array.from(el.childNodes).map((c) => renderInlineHtml(c, ctx)).join('');

  switch (tag) {
    case 'br':
      return '<br>';
    case 'b':
    case 'strong':
      return `<strong>${children()}</strong>`;
    case 'i':
    case 'em':
      return `<em>${children()}</em>`;
    case 'u':
      ctx.flags.underline++;
      return `<u>${children()}</u>`;
    case 's':
    case 'del':
    case 'strike':
      return `<s>${children()}</s>`;
    case 'code':
    case 'kbd':
      return `<code>${children()}</code>`;
    case 'sub':
      return `<sub>${children()}</sub>`;
    case 'sup':
      return `<sup>${children()}</sup>`;
    case 'mark':
      ctx.flags.highlights++;
      return `<mark>${children()}</mark>`;
    case 'a': {
      const href = el.getAttribute('href') ?? '';
      if (!/^(?:https?:|mailto:)/i.test(href)) return children();
      return `<a href="${escapeHtml(href)}">${children()}</a>`;
    }
    default:
      // Styling wrappers (font family, size, color): keep the text.
      return children();
  }
}

/* ------------------------------------------------------------------ */
/* HTML -> markdown                                                   */
/* ------------------------------------------------------------------ */

/**
 * Convert one exported Notesnook note body (tiptap HTML) to the markdown
 * our editor stores.
 *
 * Mapping, in the order the walker checks it:
 *   <h1>..<h6>                  -> # .. ######
 *   <strong>/<b>                -> **bold**
 *   <em>/<i>                    -> *italic*
 *   <u>                         -> <u> (HTML passthrough, TipTap Underline)
 *   <s>/<del>/<strike>          -> ~~strike~~
 *   <mark>                      -> ==highlight==
 *   <code>/<kbd>                -> `code`
 *   <pre class="codeblock">     -> fenced block (data-language honored)
 *   <ul>/<ol>/<li>              -> - / 1. (nesting preserved)
 *   .checklist / .simple-checklist -> - [ ] / - [x] (li.checked)
 *   <blockquote>                -> >
 *   <hr>                        -> ---
 *   <table>                     -> GFM pipe table
 *   <img src="attachments/..">  -> ![alt](nnatt:NNNNNN)
 *   <a href="attachments/..">   -> [name](nnatt:NNNNNN)
 *   <a href="./other.html">     -> [[Other note title]]
 *   <a href="https://..">       -> [text](url)
 *   <iframe src>                -> the src as a link on its own line
 *   .math-inline / .math-block  -> $latex$ / $$latex$$ math nodes
 *   text-align on simple blocks -> <p style="text-align: ...;"> HTML
 *   <span data-font-family>,
 *   font-size, color            -> dropped, inner text kept
 */
function htmlToMarkdown(bodyEl: Element, ctx: ConvCtx): string {
  function inlineOnly(text: string): string {
    return text.replace(/\s*\n+\s*/g, ' ').trim();
  }

  /** LaTeX source out of a KaTeX render, which embeds it in MathML. */
  function latexOf(el: Element): string {
    const ann = el.querySelector('annotation[encoding="application/x-tex"]');
    const src = (ann?.textContent ?? el.textContent ?? '').trim();
    return src;
  }

  /**
   * Is this checklist item ticked?
   *
   * Notesnook ships two checklist flavors and marks the ticked state
   * differently in each: a bare `checked` class on `.checklist` items, and
   * a BEM `--checked` suffix on `.simple-checklist` ones. The word-boundary
   * test catches both (and does not match "unchecked"). The data attribute
   * and the input fallback cover the editor's other renderings.
   */
  function isChecked(li: Element): boolean {
    if (/\bchecked\b/i.test(li.getAttribute('class') ?? '')) return true;
    if (li.getAttribute('data-checked') === 'true') return true;
    const box = li.querySelector('input[type="checkbox"]');
    return box !== null && box.hasAttribute('checked');
  }

  function renderList(el: Element, indent: string): string {
    const cls = el.getAttribute('class') ?? '';
    const isChecklist = /checklist/i.test(cls);
    const ordered = el.tagName.toLowerCase() === 'ol';
    if (isChecklist) ctx.flags.checklists++;

    const items = Array.from(el.children).filter(
      (c) => c.tagName.toLowerCase() === 'li'
    );
    const lines: string[] = [];
    let n = Number(el.getAttribute('start') ?? '1');
    if (!Number.isFinite(n) || n < 1) n = 1;

    for (const li of items) {
      const marker = isChecklist
        ? isChecked(li)
          ? '- [x] '
          : '- [ ] '
        : ordered
          ? `${n++}. `
          : '- ';

      // Nested lists render underneath the item, everything else inline.
      const nested: string[] = [];
      let inline = '';
      for (const child of Array.from(li.childNodes)) {
        const tag =
          child.nodeType === Node.ELEMENT_NODE
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

  function renderTable(el: Element): string {
    const rows = Array.from(el.querySelectorAll('tr'));
    if (rows.length === 0) return '';
    ctx.flags.tables++;

    const cellsOf = (tr: Element) =>
      Array.from(tr.children)
        .filter((c) => /^(td|th)$/i.test(c.tagName))
        .map((c) =>
          inlineOnly(walk(c, '')).replace(/\|/g, '\\|').replace(/^$/, ' ')
        );

    const grid = rows.map(cellsOf).filter((r) => r.length > 0);
    if (grid.length === 0) return '';
    const width = Math.max(...grid.map((r) => r.length));
    const pad = (r: string[]) => {
      const copy = [...r];
      while (copy.length < width) copy.push(' ');
      return copy;
    };

    // GFM needs a header row. Notesnook emits <th> in the first row; when
    // it does not, synthesize a blank one so the table still parses.
    const firstIsHeader = rows[0]!.querySelector('th') !== null;
    const header = firstIsHeader ? pad(grid[0]!) : new Array(width).fill(' ');
    const bodyRows = (firstIsHeader ? grid.slice(1) : grid).map(pad);

    const lines = [
      `| ${header.join(' | ')} |`,
      `| ${new Array(width).fill('---').join(' | ')} |`,
      ...bodyRows.map((r) => `| ${r.join(' | ')} |`),
    ];
    return `\n${lines.join('\n')}\n\n`;
  }

  function renderAnchor(el: Element, indent: string): string {
    const href = el.getAttribute('href') ?? '';
    const inner = inlineOnly(
      Array.from(el.childNodes).map((c) => walk(c, indent)).join('')
    );
    const label = inner || href;

    // Attachment link, e.g. [obsidian.zip](./attachments/<hash>-obsidian.zip)
    const token = attachmentToken(ctx, href);
    if (token) return `[${label}](${token})`;

    // Internal note link.
    const target = noteLinkTarget(ctx, href);
    if (target) {
      ctx.flags.noteLinks++;
      return noteLink(target, label);
    }

    // A relative .html/.md href we could not resolve still reads as an
    // internal link in Notesnook, so keep it as one rather than emitting
    // a dead file:// style link.
    const resolved = resolveRelative(ctx.baseDir, href);
    if (resolved && (HTML_EXT.test(resolved) || MD_EXT.test(resolved))) {
      ctx.flags.noteLinks++;
      return noteLink(label, label);
    }

    if (!href) return label;
    return `[${label}](${href})`;
  }

  function walk(node: Node, indent: string): string {
    if (node.nodeType === Node.TEXT_NODE) {
      return node.textContent ?? '';
    }
    if (node.nodeType !== Node.ELEMENT_NODE) return '';

    const el = node as Element;
    const tag = el.tagName.toLowerCase();
    const cls = el.getAttribute('class') ?? '';
    const style = el.getAttribute('style') ?? '';

    // Math nodes carry their LaTeX inside the KaTeX MathML annotation.
    // The editor has real math nodes ($$..$$ block, $..$ inline), so the
    // source lands there and renders again instead of sitting in a code
    // fence.
    if (/math-block/i.test(cls)) {
      const src = latexOf(el);
      if (!src) return '';
      ctx.flags.math++;
      return `\n$$${src}$$\n\n`;
    }
    if (/math-inline/i.test(cls)) {
      const src = latexOf(el);
      if (!src) return '';
      ctx.flags.math++;
      return `$${src}$`;
    }

    const children = () =>
      Array.from(el.childNodes).map((c) => walk(c, indent)).join('');

    switch (tag) {
      case 'script':
      case 'style':
      case 'head':
      case 'title':
      case 'meta':
      case 'link':
      case 'colgroup':
      case 'col':
        return '';

      case 'h1':
      case 'h2':
      case 'h3':
      case 'h4':
      case 'h5':
      case 'h6': {
        const align = style.match(ALIGN_RE)?.[1]?.toLowerCase();
        if (align && isSimpleAlignable(el, ctx)) {
          const html = inlineOnly(
            Array.from(el.childNodes).map((c) => renderInlineHtml(c, ctx)).join('')
          );
          if (html.replace(/<br>/g, '').trim()) {
            ctx.flags.aligned++;
            return `\n<${tag} style="text-align: ${align};">${html}</${tag}>\n\n`;
          }
        }
        if (align) ctx.flags.droppedAlign++;
        const text = inlineOnly(children());
        if (!text) return '';
        return `\n${'#'.repeat(Number(tag[1]))} ${text}\n\n`;
      }

      case 'strong':
      case 'b': {
        const inner = children();
        return inner.trim() ? `**${inner.trim()}**` : inner;
      }
      case 'em':
      case 'i': {
        const inner = children();
        return inner.trim() ? `*${inner.trim()}*` : inner;
      }
      case 'u': {
        const inner = children();
        if (!inner.trim()) return inner;
        ctx.flags.underline++;
        return `<u>${inner.trim()}</u>`;
      }
      case 's':
      case 'del':
      case 'strike': {
        const inner = children();
        return inner.trim() ? `~~${inner.trim()}~~` : inner;
      }
      case 'mark': {
        const inner = children();
        if (!inner.trim()) return inner;
        ctx.flags.highlights++;
        return `==${inner.trim()}==`;
      }
      case 'code': {
        // A <code> inside <pre> is handled by the <pre> branch.
        const inner = inlineOnly(children());
        return inner ? `\`${inner}\`` : '';
      }
      case 'kbd': {
        const inner = inlineOnly(children());
        return inner ? `\`${inner}\`` : '';
      }

      case 'pre': {
        const code = (el.textContent ?? '').replace(/\n+$/, '');
        if (!code.trim()) return '';
        ctx.flags.codeBlocks++;
        return `\n\`\`\`${codeLanguage(el)}\n${code}\n\`\`\`\n\n`;
      }

      case 'br':
        return '\n';

      case 'hr':
        return '\n---\n\n';

      case 'p':
      case 'div': {
        const align = style.match(ALIGN_RE)?.[1]?.toLowerCase();
        if (align && isSimpleAlignable(el, ctx)) {
          const html = inlineOnly(
            Array.from(el.childNodes).map((c) => renderInlineHtml(c, ctx)).join('')
          );
          if (html.replace(/<br>/g, '').trim()) {
            ctx.flags.aligned++;
            return `\n<p style="text-align: ${align};">${html}</p>\n\n`;
          }
        }
        if (align) ctx.flags.droppedAlign++;
        const inner = children();
        if (!inner.trim()) return '\n';
        return `${inner.trim()}\n\n`;
      }

      case 'ul':
      case 'ol':
        return renderList(el, indent);

      case 'li':
        // Only reached for a stray <li> outside a list.
        return `- ${inlineOnly(children())}\n`;

      case 'blockquote': {
        const inner = children().trim();
        if (!inner) return '';
        const quoted = inner
          .split('\n')
          .map((l) => (l.trim() ? `> ${l}` : '>'))
          .join('\n');
        return `\n${quoted}\n\n`;
      }

      case 'table':
        return renderTable(el);

      case 'img': {
        const src = el.getAttribute('src') ?? '';
        const alt = (el.getAttribute('alt') ?? '').replace(/[[\]]/g, '');
        const token = attachmentToken(ctx, src);
        if (token) return `\n\n![${alt}](${token})\n\n`;
        if (!src) return '';
        return `\n\n![${alt}](${src})\n\n`;
      }

      case 'a':
        return renderAnchor(el, indent);

      case 'iframe':
      case 'embed': {
        const src = el.getAttribute('src') ?? '';
        return src ? `\n[${src}](${src})\n\n` : '';
      }

      case 'span':
      default: {
        // Everything else is a styling wrapper we have no node for:
        // font family, font size, text color, background color. Keep the
        // text, drop the styling.
        const inner = children();
        if (
          inner.trim() &&
          (el.hasAttribute('data-font-family') ||
            /font-size|font-family|(?<!-)color\s*:/i.test(style))
        ) {
          ctx.flags.droppedStyling++;
        }
        return inner;
      }
    }
  }

  const md = Array.from(bodyEl.childNodes)
    .map((c) => walk(c, ''))
    .join('');

  return md
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

/* ------------------------------------------------------------------ */
/* Per-format note readers                                            */
/* ------------------------------------------------------------------ */

/** Everything we can learn about a note before conversion runs. */
interface RawNote {
  rel: string;
  /** Raw file text. */
  text: string;
  title: string;
  tags: string[];
  createdAt: string | null;
  updatedAt: string | null;
  /** Notesnook's Pin or Favorite property. */
  starred: boolean;
  fileDate: Date | null;
  /** Parsed document, HTML format only. */
  doc: Document | null;
  /** Body with frontmatter stripped, markdown formats only. */
  mdBody: string;
}

/** Read the `<meta>`/`<title>` header of an exported HTML note. */
function readHtmlNote(text: string, rel: string, fileDate: Date | null): RawNote {
  const doc = new DOMParser().parseFromString(text, 'text/html');
  const meta = (name: string) =>
    doc.querySelector(`meta[name="${name}"]`)?.getAttribute('content') ?? null;

  const filenameTitle = titleFromFilename(rel);
  const title = (doc.querySelector('title')?.textContent ?? '').trim() || filenameTitle;

  // The exporter repeats the title as the body's leading <h1>. Drop it so
  // the note does not open with its own name twice.
  const body = doc.body;
  const firstEl = body?.firstElementChild;
  if (
    firstEl &&
    firstEl.tagName.toLowerCase() === 'h1' &&
    (firstEl.textContent ?? '').trim() === title
  ) {
    firstEl.remove();
  }

  return {
    rel,
    text,
    title,
    tags: splitTags(meta('tags')),
    createdAt: parseNotesnookDate(meta('created-at')),
    updatedAt: parseNotesnookDate(meta('updated-at')),
    starred: isStarred(meta('pinned'), meta('favorite')),
    fileDate,
    doc,
    mdBody: '',
  };
}

/** Title from a Notesnook filename slug ("Sub4-Note-Title.md"). */
function titleFromFilename(rel: string): string {
  const base = (rel.split('/').pop() ?? rel).replace(/\.(html?|md)$/i, '').trim();
  if (!base || base.toLowerCase() === 'untitled') return '';
  return base;
}

/**
 * Read a markdown note, with or without Notesnook's frontmatter block.
 * The frontmatter is a fixed, flat set of keys (title, created_at,
 * updated_at, tags, pinned, favorite), so a line reader is enough.
 */
function readMarkdownNote(text: string, rel: string, fileDate: Date | null): RawNote {
  const fm = text.match(FRONT_MATTER);
  const meta: Record<string, string> = {};
  let body = text;

  if (fm && fm[1] !== undefined) {
    body = fm[2] ?? '';
    for (const line of fm[1].split('\n')) {
      const idx = line.indexOf(':');
      if (idx < 0) continue;
      const key = line.slice(0, idx).trim().toLowerCase();
      const val = line.slice(idx + 1).trim().replace(/^["']|["']$/g, '');
      if (key) meta[key] = val;
    }
  }

  let title = meta['title'] ?? '';

  // The exporter repeats the title as the body's leading `# ` heading.
  // With no frontmatter that heading is the only title we get.
  const heading = body.match(/^\s*#\s+(.+?)\s*$/m);
  if (heading && (heading.index ?? 0) < 4) {
    const headingTitle = heading[1]!.trim();
    if (!title) title = headingTitle;
    if (headingTitle === title) {
      body = body.slice((heading.index ?? 0) + heading[0].length);
    }
  }
  if (!title) title = titleFromFilename(rel);

  return {
    rel,
    text,
    title,
    tags: splitTags(meta['tags']),
    createdAt: parseNotesnookDate(meta['created_at']),
    updatedAt: parseNotesnookDate(meta['updated_at']),
    starred: isStarred(meta['pinned'] ?? null, meta['favorite'] ?? null),
    fileDate,
    doc: null,
    mdBody: body,
  };
}

/**
 * Rewrite the links in an already-markdown Notesnook note.
 *
 * The exporter writes both attachment and note links in angle-bracket
 * form with an optional title:
 *   ![name](<./attachments/<hash>-name.jpeg>)
 *   [obsidian.zip](<./attachments/<hash>-obsidian.zip> "obsidian.zip")
 *   [Sub3 Note Title](<./../Sub3-Note-Title.md> "Sub3 Note Title")
 */
function rewriteMarkdownLinks(body: string, ctx: ConvCtx): string {
  const LINK_RE = /(!?)\[([^\]]*)\]\(\s*<?([^)>]*?)>?(?:\s+"([^"]*)")?\s*\)/g;

  return body.replace(LINK_RE, (whole, bang: string, label: string, href: string) => {
    const target = href.trim();
    if (!target) return whole;

    const token = attachmentToken(ctx, target);
    if (token) return `${bang}[${label}](${token})`;

    const noteTitle = noteLinkTarget(ctx, target);
    if (noteTitle) {
      ctx.flags.noteLinks++;
      return noteLink(noteTitle, label);
    }

    const resolved = resolveRelative(ctx.baseDir, target);
    if (resolved && (HTML_EXT.test(resolved) || MD_EXT.test(resolved))) {
      ctx.flags.noteLinks++;
      return noteLink(label, label);
    }

    // External link: drop the angle brackets so tiptap-markdown parses it.
    return `${bang}[${label}](${target})`;
  });
}

/* ------------------------------------------------------------------ */
/* Backup (.nnbackupz) detection                                      */
/* ------------------------------------------------------------------ */

/**
 * A Notesnook full backup is a zip carrying a `.nnbackup` marker and
 * numbered chunk files. Its note content is reachable, but every
 * attachment inside it is separately encrypted with xchacha20-poly1305,
 * which the export path does not require. Detect it and point the user at
 * the export instead of failing on an unrecognized zip.
 */
function isBackupArchive(zip: JSZip, filename: string): boolean {
  if (/\.nnbackupz?$/i.test(filename)) return true;
  let found = false;
  zip.forEach((path) => {
    const name = path.split('/').pop() ?? '';
    if (name === '.nnbackup' || /^\d+-(plain|encrypted)-[0-9a-f]+$/i.test(name)) {
      found = true;
    }
  });
  return found;
}

const BACKUP_ERROR =
  'This is a Notesnook backup (.nnbackupz), not an export. Backups store every attachment in Notesnook\'s own encrypted format, so they cannot be read here. In Notesnook go to Settings > Backup & export, use "Export all notes", pick HTML from the "Export as" dropdown, and drop that .zip in instead.';

/* ------------------------------------------------------------------ */
/* Zip parser                                                         */
/* ------------------------------------------------------------------ */

interface ParseZipResult {
  notes: ImportedNote[];
  folders: FolderDef[];
  blobs: Map<string, { data: Uint8Array; mime: string; name: string }>;
  blobBytes: number;
  format: 'html' | 'markdown';
  hadFrontMatter: boolean;
  flags: ConvFlags;
  imageCount: number;
  attachmentCount: number;
}

async function parseZip(
  file: File,
  onProgress?: (msg: string) => void
): Promise<ParseZipResult> {
  onProgress?.('Reading zip...');
  const buf = await file.arrayBuffer();
  let zip: JSZip;
  try {
    zip = await JSZip.loadAsync(buf);
  } catch {
    throw new Error(
      'Could not read that file as a zip. Export from Notesnook with Settings > Backup & export > Export all notes, pick HTML, and drop the .zip it produces.'
    );
  }

  if (isBackupArchive(zip, file.name)) throw new Error(BACKUP_ERROR);

  // Collect candidate paths so we can strip a wrapping folder if the user
  // zipped the export directory rather than its contents.
  const allPaths: string[] = [];
  zip.forEach((path, entry) => {
    if (!entry.dir && !shouldSkip(path)) allPaths.push(path);
  });
  if (allPaths.length === 0) throw new Error('That zip is empty.');

  let prefix = '';
  const firstSlash = allPaths[0]!.indexOf('/');
  if (firstSlash > 0) {
    const candidate = allPaths[0]!.slice(0, firstSlash + 1);
    if (allPaths.every((p) => p.startsWith(candidate))) prefix = candidate;
  }

  const htmlFiles: [string, JSZip.JSZipObject][] = [];
  const mdFiles: [string, JSZip.JSZipObject][] = [];
  const blobFiles: [string, JSZip.JSZipObject][] = [];

  zip.forEach((path, entry) => {
    if (entry.dir || shouldSkip(path)) return;
    const rel = prefix ? path.slice(prefix.length) : path;
    if (!rel) return;
    if (ATTACHMENT_DIR.test(rel)) {
      blobFiles.push([rel, entry]);
    } else if (HTML_EXT.test(rel)) {
      htmlFiles.push([rel, entry]);
    } else if (MD_EXT.test(rel)) {
      mdFiles.push([rel, entry]);
    }
  });

  // Prefer HTML when a zip somehow carries both: it is the lossless one.
  const format: 'html' | 'markdown' = htmlFiles.length > 0 ? 'html' : 'markdown';
  const noteFiles = format === 'html' ? htmlFiles : mdFiles;

  if (noteFiles.length === 0) {
    throw new Error(
      'No notes found in that zip. Export from Notesnook with Settings > Backup & export > Export all notes and pick HTML (or Markdown), then drop the .zip here. The "Text" export is not supported.'
    );
  }

  onProgress?.(`Found ${noteFiles.length} note${noteFiles.length === 1 ? '' : 's'}...`);

  // Attachments first: the note conversion needs the placeholder map.
  const blobs = new Map<string, { data: Uint8Array; mime: string; name: string }>();
  const attachmentTokens = new Map<string, string>();

  if (blobFiles.length > 0) {
    onProgress?.(
      `Extracting ${blobFiles.length} attachment${blobFiles.length === 1 ? '' : 's'}...`
    );
  }
  for (let i = 0; i < blobFiles.length; i++) {
    const [rel, entry] = blobFiles[i]!;
    const data = new Uint8Array(await entry.async('uint8array'));
    const token = blobToken(i);
    blobs.set(token, { data, mime: mimeFromExt(rel), name: attachmentName(rel) });
    attachmentTokens.set(rel.toLowerCase(), token);
    if ((i + 1) % 20 === 0) {
      onProgress?.(`Extracted ${i + 1} of ${blobFiles.length} attachments...`);
    }
  }

  // Pass 1: read every note's header so note-links can resolve to the
  // target's real title rather than its filename slug.
  const raws: RawNote[] = [];
  let hadFrontMatter = false;
  for (let i = 0; i < noteFiles.length; i++) {
    const [rel, entry] = noteFiles[i]!;
    const text = await entry.async('string');
    const fileDate = entry.date ?? null;
    if (format === 'html') {
      raws.push(readHtmlNote(text, rel, fileDate));
    } else {
      const raw = readMarkdownNote(text, rel, fileDate);
      if (/^---\r?\n/.test(text)) hadFrontMatter = true;
      raws.push(raw);
    }
    if ((i + 1) % 50 === 0) {
      onProgress?.(`Reading ${i + 1} of ${noteFiles.length}...`);
    }
  }

  const pathToTitle = new Map<string, string>();
  for (const raw of raws) {
    if (raw.title) pathToTitle.set(raw.rel.toLowerCase(), raw.title);
  }

  // Notebook nesting -> real folders, at any depth.
  const { folders, dirToFolderId } = buildFolderTree(raws.map((r) => dirOf(r.rel)));

  // Pass 2: convert bodies.
  const flags: ConvFlags = {
    underline: 0,
    highlights: 0,
    checklists: 0,
    tables: 0,
    codeBlocks: 0,
    aligned: 0,
    droppedStyling: 0,
    droppedAlign: 0,
    noteLinks: 0,
    math: 0,
  };
  const notes: ImportedNote[] = [];

  for (let i = 0; i < raws.length; i++) {
    const raw = raws[i]!;
    const ctx: ConvCtx = {
      baseDir: dirOf(raw.rel),
      attachmentTokens,
      pathToTitle,
      flags,
    };

    let body: string;
    if (raw.doc && raw.doc.body) {
      body = htmlToMarkdown(raw.doc.body, ctx);
    } else {
      body = rewriteMarkdownLinks(raw.mdBody, ctx).trim();
    }
    body = linkifyMarkdown(body);

    const fallback =
      raw.fileDate && !Number.isNaN(raw.fileDate.getTime())
        ? raw.fileDate.toISOString()
        : new Date().toISOString();
    const createdAt = raw.createdAt ?? fallback;
    const updatedAt = raw.updatedAt ?? raw.createdAt ?? fallback;

    const note: ImportedNote = {
      title: raw.title,
      body,
      tags: raw.tags,
      createdAt,
      updatedAt,
      starred: raw.starred,
    };

    const dir = dirOf(raw.rel);
    if (dir) {
      note.folderId = dirToFolderId.get(dir) ?? null;
      note.folderPath = dir.split('/').filter(Boolean);
    }
    notes.push(note);

    if ((i + 1) % 50 === 0) {
      onProgress?.(`Parsed ${i + 1} of ${raws.length}...`);
    }
  }

  // Only ship blobs the notes actually reference; an orphaned attachment
  // would otherwise burn quota with no way to reach it. Sizes and counts
  // are taken from this set, not the raw zip, so the quota preflight and
  // the preview both describe what really lands.
  const referenced = new Map<string, { data: Uint8Array; mime: string; name: string }>();
  let blobBytes = 0;
  let imageCount = 0;
  let attachmentCount = 0;
  for (const [token, blob] of blobs) {
    if (!notes.some((n) => n.body.includes(token))) continue;
    referenced.set(token, blob);
    blobBytes += blob.data.length;
    if (blob.mime.startsWith('image/')) imageCount++;
    else attachmentCount++;
  }

  return {
    notes,
    folders,
    blobs: referenced,
    blobBytes,
    format,
    hadFrontMatter,
    flags,
    imageCount,
    attachmentCount,
  };
}

/* ------------------------------------------------------------------ */
/* Public importer                                                    */
/* ------------------------------------------------------------------ */

export async function parseNotesnook(
  file: File,
  onProgress?: (msg: string) => void
): Promise<ParsedImport> {
  const {
    notes,
    folders,
    blobs,
    blobBytes,
    format,
    hadFrontMatter,
    flags,
    imageCount,
    attachmentCount,
  } = await parseZip(file, onProgress);

  const uniqueTags = new Set(notes.flatMap((n) => n.tags));
  const emptyNotes = notes.filter((n) => !n.title.trim() && !n.body.trim()).length;
  const untaggedNotes = notes.filter((n) => n.tags.length === 0).length;
  const plural = (n: number) => (n === 1 ? '' : 's');

  const warnings: string[] = [];
  if (format === 'markdown') {
    warnings.push(
      hadFrontMatter
        ? 'This is Notesnook\'s "Markdown + Frontmatter" export, which drops underline, font sizes, and text alignment before the file is written. Re-export as HTML to keep them.'
        : 'This is Notesnook\'s plain "Markdown" export: it carries no tags and no original dates, and it drops underline, font sizes, and text alignment. Re-export as "HTML" to keep all of it, or "Markdown + Frontmatter" for at least the tags and dates.'
    );
  }
  const transforms: string[] = [];
  if (folders.length > 0) {
    const filed = notes.filter((n) => n.folderId).length;
    transforms.push(
      `Rebuilt ${folders.length} folder${plural(folders.length)} from your notebooks (${filed} note${plural(filed)} filed).`
    );
  }
  const tagged = notes.filter((n) => n.tags.length > 0).length;
  if (tagged > 0) {
    transforms.push(`Kept the tags on ${tagged} note${plural(tagged)}.`);
  }
  const starred = notes.filter((n) => n.starred).length;
  if (starred > 0) {
    transforms.push(
      `Marked ${starred} pinned or favorited note${plural(starred)} as Pinned.`
    );
  }
  if (flags.noteLinks > 0) {
    transforms.push(
      `Converted ${flags.noteLinks} internal link${plural(flags.noteLinks)} into note-links.`
    );
  }
  if (flags.checklists > 0) {
    transforms.push(
      `Converted ${flags.checklists} checklist${plural(flags.checklists)} into native task lists.`
    );
  }
  if (flags.tables > 0) {
    transforms.push(`Preserved ${flags.tables} table${plural(flags.tables)}.`);
  }
  if (flags.codeBlocks > 0) {
    transforms.push(`Preserved ${flags.codeBlocks} code block${plural(flags.codeBlocks)}.`);
  }
  if (flags.underline > 0) {
    transforms.push('Preserved underline formatting.');
  }
  if (flags.highlights > 0) {
    transforms.push('Preserved highlights.');
  }
  if (flags.math > 0) {
    transforms.push(`Preserved ${flags.math} math formula${plural(flags.math)}.`);
  }
  if (flags.aligned > 0) {
    transforms.push('Preserved text alignment.');
  }
  if (flags.droppedAlign > 0) {
    transforms.push('Dropped alignment on blocks the editor cannot align, keeping the text.');
  }
  if (flags.droppedStyling > 0) {
    transforms.push(
      'Dropped custom fonts, font sizes, and text colors, keeping the text.'
    );
  }
  if (imageCount > 0) {
    transforms.push(`Found ${imageCount} image${plural(imageCount)} to import.`);
  }
  if (attachmentCount > 0) {
    transforms.push(
      `Found ${attachmentCount} attachment${plural(attachmentCount)} to import.`
    );
  }
  transforms.push('Made bare URLs clickable.');

  return {
    notes,
    warnings,
    transforms,
    stats: {
      totalNotes: notes.length,
      emptyNotes,
      untaggedNotes,
      uniqueTags: uniqueTags.size,
    },
    source: 'notesnook',
    blobBytes,
    blobs: blobs.size > 0 ? blobs : undefined,
    folders,
  };
}
