import JSZip from 'jszip';
import type { FolderDef } from '../folders';
import { normalizeTag } from '../notesRepo';
import { TEXT_COLORS, HIGHLIGHT_COLORS } from '../editorColors';
import { buildFolderTree } from './folderImport';
import { BARE_LINKABLE_RE, linkifyMarkdown } from './linkify';
import { noteLinkTarget } from '../noteLinks';
import { mimeFromExt } from './blobImport';
import type { ImportedNote, ParsedImport } from './types';

/**
 * UpNote importer.
 *
 * Reads the backup folder UpNote writes via Settings > Backup > "Backup
 * now", zipped whole. This is the one export route UpNote offers without
 * a Premium purchase, and it is also the richest: the folder carries
 *
 *   data/<epoch-ms>.upnx   - one gzipped NDJSON snapshot per backup run:
 *                            a `version:2` header line, then one JSON
 *                            record per line (user, notebooks, lists,
 *                            tags, files, notes). The NEWEST parseable
 *                            snapshot is the source of truth - it holds
 *                            every note's title, full rich-text HTML,
 *                            timestamps, tags, pin/trash flags, notebook
 *                            membership, and note links by target id.
 *   files/<id>.<ext>       - attachment and image bytes, referenced from
 *                            the HTML via localhost URLs and data-file-id.
 *   Markdown/...           - UpNote's own markdown rendering of each note.
 *                            Deliberately IGNORED: it silently flattens
 *                            underline, colors, highlights, collapsible
 *                            sections, sub/superscript and alignment, and
 *                            double-escapes math. The HTML in the snapshot
 *                            keeps all of it.
 *   revisions/...          - UpNote's automatic version history. Ignored.
 *
 * The snapshot HTML is converted to the markdown our editor stores,
 * targeting what the editor can actually represent today:
 *   <b>/<i>/<strike>                 -> ** * ~~
 *   <u>, <sub>, <sup>                -> HTML passthrough marks
 *   <span class="shine-highlight*">  -> ==highlight==, or a colored
 *                                       <mark> when UpNote named a color
 *                                       we have in HIGHLIGHT_COLORS
 *   <span class="shine-text-COLOR">  -> <span style="color: #hex"> mapped
 *                                       onto the editor's own palette
 *   <span data-upnote-formula>       -> $latex$ ($$latex$$ when alone in
 *                                       its block)
 *   .shine-collapsible-section       -> > [!note]+ callout (- when the
 *                                       section was collapsed)
 *   <li data-checked>                -> - [ ] / - [x]
 *   text-align on simple blocks      -> <p style="text-align: ...;"> HTML
 *   <a data-note-id>                 -> [[target title]] note-links
 *   <a data-upnote-tag>              -> the literal #tag text
 *   <img>/<a data-file-id>           -> blob placeholders the shared blob
 *                                       pipeline rewrites to pn:img/file
 *
 * SECOND FORMAT: the per-note export (HTML preferred, Markdown accepted),
 * the only route UpNote's phone apps offer. See the "Per-note export"
 * section below.
 */

/* ------------------------------------------------------------------ */
/* Snapshot records                                                   */
/* ------------------------------------------------------------------ */

/** UpNote serializes JS Sets as {__type__:'Set', __value__:[...]}. */
function setValues(raw: unknown): string[] {
  if (Array.isArray(raw)) return raw.filter((v): v is string => typeof v === 'string');
  if (raw && typeof raw === 'object' && Array.isArray((raw as { __value__?: unknown }).__value__)) {
    return (raw as { __value__: unknown[] }).__value__.filter(
      (v): v is string => typeof v === 'string'
    );
  }
  return [];
}

interface UpNoteRecord {
  id: string;
  title: string;
  html: string;
  text: string;
  createdAt: number | null;
  updatedAt: number | null;
  pinned: boolean;
  bookmarked: boolean;
  trashed: boolean;
  isTemplate: boolean;
  tags: string[];
}

interface UpNotebook {
  id: string;
  title: string;
  parent: string;
}

interface Snapshot {
  notes: Map<string, UpNoteRecord>;
  notebooks: Map<string, UpNotebook>;
  /** notebook id -> ordered note ids (the `lists` records). */
  members: Map<string, string[]>;
  /** file id ("uuid__ext") -> original filename. */
  fileNames: Map<string, string>;
}

/**
 * Gunzip via the platform's DecompressionStream. jsdom (and some older
 * embedders) lack Blob.stream(), so the source is a hand-rolled
 * ReadableStream rather than blob.stream().
 */
async function gunzip(data: Uint8Array<ArrayBuffer>): Promise<string> {
  const src = new ReadableStream<BufferSource>({
    start(controller) {
      controller.enqueue(data);
      controller.close();
    },
  });
  const out = src.pipeThrough(new DecompressionStream('gzip'));
  return await new Response(out).text();
}

/**
 * Parse one .upnx snapshot (NDJSON after a `version:N` header line).
 * Individual malformed lines are skipped; the caller treats a snapshot
 * with zero usable records as unreadable and falls back to an older one.
 */
function parseSnapshot(text: string): Snapshot | null {
  const snap: Snapshot = {
    notes: new Map(),
    notebooks: new Map(),
    members: new Map(),
    fileNames: new Map(),
  };
  let records = 0;

  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('{')) continue;
    let obj: { type?: string; data?: Record<string, unknown> };
    try {
      obj = JSON.parse(trimmed);
    } catch {
      continue;
    }
    const d = obj.data;
    if (!obj.type || !d || typeof d !== 'object') continue;
    records++;

    if (obj.type === 'notes' && typeof d.id === 'string') {
      if (d.deleted === true) continue;
      snap.notes.set(d.id, {
        id: d.id,
        title: typeof d.title === 'string' ? d.title : '',
        html: typeof d.html === 'string' ? d.html : '',
        text: typeof d.text === 'string' ? d.text : '',
        createdAt: typeof d.createdAt === 'number' ? d.createdAt : null,
        updatedAt: typeof d.updatedAt === 'number' ? d.updatedAt : null,
        pinned: d.pinned === true,
        bookmarked: d.bookmarked === true,
        trashed: d.trashed === true,
        isTemplate: d.isTemplate === true,
        tags: setValues(d.tagLinks).map(normalizeTag).filter(Boolean),
      });
    } else if (obj.type === 'notebooks' && typeof d.id === 'string') {
      if (d.deleted === true) continue;
      snap.notebooks.set(d.id, {
        id: d.id,
        title: typeof d.title === 'string' ? d.title : '',
        parent: typeof d.parent === 'string' ? d.parent : '',
      });
    } else if (obj.type === 'lists' && typeof d.id === 'string') {
      // Notebook membership rides in `lists` records named
      // notebooks_<notebookId> whose content is a JSON-encoded id array.
      // (The notebooks records' own `notes` arrays are always empty.)
      const m = d.id.match(/^notebooks_(.+)$/);
      if (m && typeof d.content === 'string') {
        try {
          const ids = JSON.parse(d.content);
          if (Array.isArray(ids)) {
            snap.members.set(
              m[1]!,
              ids.filter((v): v is string => typeof v === 'string')
            );
          }
        } catch {
          // Unreadable membership list: notes fall back to the root.
        }
      }
    } else if (obj.type === 'files' && typeof d.id === 'string') {
      if (d.deleted === true) continue;
      if (typeof d.name === 'string' && d.name) snap.fileNames.set(d.id, d.name);
    }
  }

  return records > 0 ? snap : null;
}

/* ------------------------------------------------------------------ */
/* HTML -> markdown                                                   */
/* ------------------------------------------------------------------ */

/** UpNote's text-color classes, mapped onto the editor's own palette so
 *  imported colors match what the toolbar swatches produce. UpNote has no
 *  teal, so that palette entry simply goes unused. */
const SHINE_TEXT_COLOR: Record<string, string> = Object.fromEntries(
  TEXT_COLORS.map((c) => [c.name.toLowerCase(), c.value])
);

const BLOCK_TAGS = new Set([
  'div', 'p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
  'ul', 'ol', 'blockquote', 'pre', 'hr', 'table',
]);

/** Formatting we noticed while converting, surfaced as transforms. */
interface ConvFlags {
  underline: number;
  highlights: number;
  colors: number;
  checklists: number;
  tables: number;
  codeBlocks: number;
  callouts: number;
  math: number;
  noteLinks: number;
  aligned: number;
  droppedStyling: number;
  missingFiles: number;
}

interface ConvCtx {
  /** File basename (lowercased) -> blob placeholder token. */
  blobTokens: Map<string, string>;
  /** UpNote file id ("uuid__ext", lowercased) -> blob placeholder token. */
  fileIdTokens: Map<string, string>;
  /** Note id -> title, for [[note link]] resolution. */
  noteTitles: Map<string, string>;
  /**
   * True while rendering a table cell: attachments and images flatten to
   * their visible text there, because the blob rewrite (blobImport.ts)
   * later replaces an attachment link's text with `name|size|mime`, whose
   * raw pipes would split the markdown table.
   */
  plainMedia: boolean;
  flags: ConvFlags;
}

function normalizeText(s: string): string {
  return s.replace(/\u00a0/g, ' ');
}

/** Collapse an inline run onto one line. */
function inlineOnly(text: string): string {
  return text.replace(/\s*\n+\s*/g, ' ').trim();
}

/**
 * Wrap an inline run in markers, expelling boundary whitespace OUTSIDE
 * them. UpNote keeps the space separating two runs INSIDE the first run's
 * tag (`<i>velit est </i><u>sint...`), so trimming and wrapping would glue
 * the words together, and markdown emphasis is broken by inner boundary
 * whitespace anyway. Same rule prosemirror-markdown calls
 * expelEnclosingWhitespace.
 */
function wrapMark(inner: string, open: string, close: string): string {
  const m = inner.match(/^(\s*)([\s\S]*?)(\s*)$/)!;
  if (!m[2]) return inner;
  return `${m[1]}${open}${m[2]}${close}${m[3]}`;
}

/**
 * The basename of a media reference. Two shapes reach this: the backup
 * snapshot's HTML uses localhost content URLs
 * ("http://localhost:9425/files/x.png"), and the per-note HTML export
 * writes bare relative paths ("SCR-1.png") to the media zipped beside it.
 */
function localFileBasename(href: string): string | null {
  let raw: string | null = null;
  const m = href.match(/^https?:\/\/(?:localhost|127\.0\.0\.1)(?::\d+)?\/(?:files|images)\/([^/?#]+)/i);
  if (m) {
    raw = m[1]!;
  } else if (
    href &&
    !/^[a-z][a-z0-9+.-]*:/i.test(href) &&
    !href.startsWith('/') &&
    !href.startsWith('#')
  ) {
    raw = href.split('#')[0]!.split('?')[0]!.split('/').pop() || null;
  }
  if (!raw) return null;
  try {
    return decodeURIComponent(raw).toLowerCase();
  } catch {
    return raw.toLowerCase();
  }
}

/** Resolve an <img>/<a> reference to a blob token, or null. */
function tokenFor(ctx: ConvCtx, el: Element): string | null {
  const fileId = el.getAttribute('data-file-id');
  if (fileId) {
    const hit = ctx.fileIdTokens.get(fileId.toLowerCase());
    if (hit) return hit;
  }
  const href = el.getAttribute('href') ?? el.getAttribute('src') ?? '';
  const base = localFileBasename(href);
  if (base) return ctx.blobTokens.get(base) ?? null;
  return null;
}

/** True when the reference points into the backup but the bytes are absent. */
function isLocalRef(el: Element): boolean {
  if (el.getAttribute('data-file-id')) return true;
  const href = el.getAttribute('href') ?? el.getAttribute('src') ?? '';
  return localFileBasename(href) !== null;
}

const ALIGN_RE = /text-align:\s*(center|right|justify)/i;

/**
 * Can this aligned block be emitted as an aligned HTML block? Only simple
 * inline content qualifies: markdown inside an HTML block is not parsed,
 * so anything that must become markdown syntax (note-links, tags, images,
 * attachments, math) forces the plain path and the alignment is dropped.
 * A bare URL or email anywhere in the text disqualifies too: the
 * mandatory linkify pass would wrap it in `<...>`, which inside an HTML
 * block reads as a broken tag and eats the address.
 */
function isSimpleAlignable(el: Element): boolean {
  if (BARE_LINKABLE_RE.test(el.textContent ?? '')) return false;
  for (const child of Array.from(el.childNodes)) {
    if (child.nodeType === Node.TEXT_NODE) continue;
    if (child.nodeType !== Node.ELEMENT_NODE) continue;
    const c = child as Element;
    const tag = c.tagName.toLowerCase();
    if (tag === 'br') continue;
    if (tag === 'img' || BLOCK_TAGS.has(tag)) return false;
    if (c.hasAttribute('data-upnote-formula')) return false;
    if (tag === 'a') {
      if (c.hasAttribute('data-note-id') || c.hasAttribute('data-upnote-tag') || isLocalRef(c)) {
        return false;
      }
    } else if (!['b', 'strong', 'i', 'em', 'u', 's', 'del', 'strike', 'code', 'span', 'sub', 'sup', 'mark'].includes(tag)) {
      return false;
    }
    if (!isSimpleAlignable(c)) return false;
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
    return escapeHtml(normalizeText(node.textContent ?? ''));
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
    case 'span': {
      const color = shineColor(el);
      if (color) {
        ctx.flags.colors++;
        return `<span style="color: ${color}">${children()}</span>`;
      }
      const hl = shineHighlight(el);
      if (hl) {
        ctx.flags.highlights++;
        return hl.color
          ? `${markOpen(hl.color)}${children()}</mark>`
          : `<mark>${children()}</mark>`;
      }
      return children();
    }
    default:
      return children();
  }
}

function shineColor(el: Element): string | null {
  const m = (el.getAttribute('class') ?? '').match(/(?:^|\s)shine-text-([a-z]+)/i);
  if (!m) return null;
  return SHINE_TEXT_COLOR[m[1]!.toLowerCase()] ?? null;
}

/**
 * UpNote names its highlight colors in the class itself
 * (`shine-highlight-yellow`), from the same small vocabulary as its text
 * colors, so they map onto HIGHLIGHT_COLORS by name exactly as
 * SHINE_TEXT_COLOR maps the text ones. Yellow is our default highlight and
 * carries no stored color, which is why the map's values are nullable and
 * lookups test membership rather than truthiness.
 */
const SHINE_HIGHLIGHT_COLOR: Record<string, string | null> = Object.fromEntries(
  HIGHLIGHT_COLORS.map((c) => [c.name.toLowerCase(), c.value])
);

/**
 * The highlight a `shine-highlight*` class asks for, or null when the
 * element is not a highlight at all. `{ color: null }` is a highlight in
 * our DEFAULT color - both the unsuffixed `shine-highlight` and any color
 * name UpNote has and we do not, which degrades to a plain highlight
 * rather than dropping the emphasis.
 */
function shineHighlight(el: Element): { color: string | null } | null {
  const cls = el.getAttribute('class') ?? '';
  const m = cls.match(/(?:^|\s)shine-highlight(?:-([a-z]+))?(?=\s|$)/i);
  if (!m) return null;
  const name = m[1]?.toLowerCase();
  return { color: (name && SHINE_HIGHLIGHT_COLOR[name]) || null };
}

/** The opening tag for a colored highlight; `==` has no color to carry. */
function markOpen(color: string): string {
  return `<mark style="background-color: ${color}">`;
}

/** Inline walker for the normal (markdown) path. */
function walkInline(node: Node, ctx: ConvCtx): string {
  if (node.nodeType === Node.TEXT_NODE) {
    // Pretty-printed HTML (UpNote's stock notes, web-clipper captures)
    // carries per-line indentation inside text nodes. Left in place, four
    // spaces after a newline become an indented code block once the run
    // is quoted or emitted, so the markdown shows literal `**` markers.
    return normalizeText(node.textContent ?? '').replace(/\n[ \t]+/g, '\n');
  }
  if (node.nodeType !== Node.ELEMENT_NODE) return '';
  const el = node as Element;
  const tag = el.tagName.toLowerCase();

  // Inline math. A formula alone in its block is handled by the block
  // walker before this runs, so anything reaching here is truly inline.
  const formula = el.getAttribute('data-upnote-formula');
  if (formula !== null) {
    const latex = formula.trim();
    if (!latex) return '';
    ctx.flags.math++;
    return `$${latex}$`;
  }

  const children = () =>
    Array.from(el.childNodes).map((c) => walkInline(c, ctx)).join('');

  switch (tag) {
    case 'script':
    case 'style':
      return '';

    case 'br':
      return '\n';

    case 'b':
    case 'strong': {
      const inner = children();
      return inner.trim() ? wrapMark(inner, '**', '**') : inner;
    }
    case 'i':
    case 'em': {
      const inner = children();
      return inner.trim() ? wrapMark(inner, '*', '*') : inner;
    }
    case 'u': {
      const inner = children();
      if (!inner.trim()) return inner;
      ctx.flags.underline++;
      return wrapMark(inner, '<u>', '</u>');
    }
    case 's':
    case 'del':
    case 'strike': {
      const inner = children();
      return inner.trim() ? wrapMark(inner, '~~', '~~') : inner;
    }
    case 'sub': {
      const inner = children();
      return inner.trim() ? wrapMark(inner, '<sub>', '</sub>') : inner;
    }
    case 'sup': {
      const inner = children();
      return inner.trim() ? wrapMark(inner, '<sup>', '</sup>') : inner;
    }
    case 'code': {
      const inner = inlineOnly(children());
      return inner ? `\`${inner}\`` : '';
    }
    case 'mark': {
      const inner = children();
      if (!inner.trim()) return inner;
      ctx.flags.highlights++;
      return wrapMark(inner, '==', '==');
    }

    case 'span': {
      const color = shineColor(el);
      if (color) {
        const inner = children();
        if (!inner.trim()) return inner;
        ctx.flags.colors++;
        return wrapMark(inner, `<span style="color: ${color}">`, '</span>');
      }
      const hl = shineHighlight(el);
      if (hl) {
        const inner = children();
        if (!inner.trim()) return inner;
        ctx.flags.highlights++;
        return hl.color
          ? wrapMark(inner, markOpen(hl.color), '</mark>')
          : wrapMark(inner, '==', '==');
      }
      return children();
    }

    case 'a':
      return renderAnchor(el, ctx);

    case 'img':
      return renderImage(el, ctx);

    default:
      return children();
  }
}

function renderAnchor(el: Element, ctx: ConvCtx): string {
  const label = inlineOnly(
    Array.from(el.childNodes).map((c) => walkInline(c, ctx)).join('')
  );
  // For [label](target) emissions the label must not carry brackets: a
  // "]" ends the link early AND breaks blobImport's rewrite regex, which
  // would leave the raw upnatt: token as dead text in the note.
  const linkLabel = label.replace(/[[\]]/g, '');

  // Inline hashtag. The tag itself already arrived via tagLinks; the body
  // keeps the literal #text so the note reads the way it did in UpNote
  // (matching how the Obsidian importer leaves inline tags in place).
  const tagAttr = el.getAttribute('data-upnote-tag');
  if (tagAttr) return label || tagAttr;

  // Note link: resolve the target id to that note's real title.
  const noteId =
    el.getAttribute('data-note-id') ??
    (el.getAttribute('href') ?? '').match(/^upnote:\/\/[^?]*openNote\?noteId=([^&]+)/i)?.[1] ??
    null;
  if (noteId) {
    ctx.flags.noteLinks++;
    const title = noteLinkTarget(ctx.noteTitles.get(noteId) ?? '');
    const l = noteLinkTarget(label);
    if (!title) return l ? `[[${l}]]` : '';
    if (!l || l === title) return `[[${title}]]`;
    return `[[${title}|${l}]]`;
  }

  // Attachment shipped in the backup's files/ folder.
  const token = tokenFor(ctx, el);
  if (token) {
    // Inside a table cell the attachment flattens to its visible text
    // (see ConvCtx.plainMedia); the blob rewrite's pipes would split the
    // table otherwise.
    if (ctx.plainMedia) return label;
    return `[${linkLabel}](${token})`;
  }
  if (isLocalRef(el)) {
    // Referenced but not in the backup (UpNote had not downloaded it to
    // this device). A localhost link would be dead; keep the visible text.
    ctx.flags.missingFiles++;
    return label;
  }

  const href = el.getAttribute('href') ?? '';
  if (!href) return label;
  if (/^upnote:/i.test(href)) return label;
  // Parens or spaces in the target break [label](target); angle brackets
  // are markdown's own escape hatch for that.
  const target = /[\s()]/.test(href) ? `<${href}>` : href;
  return `[${linkLabel || href}](${target})`;
}

function renderImage(el: Element, ctx: ConvCtx): string {
  const alt = (el.getAttribute('alt') ?? '').replace(/[[\]]/g, '');
  // Images cannot live inside a markdown table cell; keep the alt text.
  if (ctx.plainMedia) return alt;
  const token = tokenFor(ctx, el);
  if (token) return `\n\n![${alt}](${token})\n\n`;
  if (isLocalRef(el)) {
    ctx.flags.missingFiles++;
    return '';
  }
  const src = el.getAttribute('src') ?? '';
  if (!/^https?:/i.test(src)) return '';
  return `\n\n![${alt}](${src})\n\n`;
}

/** True when the element contains block-level structure. */
function hasBlockChildren(el: Element): boolean {
  return Array.from(el.children).some((c) => {
    const tag = c.tagName.toLowerCase();
    return BLOCK_TAGS.has(tag) || /(?:^|\s)shine-(?:collapsible-section|table-wrapper)/.test(c.getAttribute('class') ?? '');
  });
}

function renderList(el: Element, ctx: ConvCtx, indent: string): string {
  const ordered = el.tagName.toLowerCase() === 'ol';
  const children = Array.from(el.children);
  const items = children.filter((c) => c.tagName.toLowerCase() === 'li');
  // UpNote marks checklists per item (data-checked on the <li>), not on
  // the list element.
  const isChecklist = items.some((li) => li.hasAttribute('data-checked'));
  if (isChecklist) ctx.flags.checklists++;

  const lines: string[] = [];
  let n = Number(el.getAttribute('start') ?? '1');
  if (!Number.isFinite(n) || n < 1) n = 1;
  // A nested list must indent past its parent item's MARKER, because
  // CommonMark measures nesting from the content column: two spaces sit
  // inside a "- " item but NOT inside a "1. " one, whose child list would
  // silently split into flat sibling lists.
  let prevMarkerWidth = 2;

  const pushNested = (list: Element) => {
    const block = renderList(list, ctx, indent + ' '.repeat(prevMarkerWidth)).replace(/\n+$/, '');
    if (block) lines.push(block);
  };

  for (const child of children) {
    const tag = child.tagName.toLowerCase();
    if (tag === 'ul' || tag === 'ol') {
      // UpNote serializes a nested list as a SIBLING of its parent <li>,
      // after it has closed - not inside it. It belongs to the item above;
      // skipping non-li children here silently dropped every nested list.
      pushNested(child);
      continue;
    }
    if (tag !== 'li') continue;
    const li = child;

    const marker = isChecklist
      ? li.getAttribute('data-checked') === 'true'
        ? '- [x] '
        : '- [ ] '
      : ordered
        ? `${n++}. `
        : '- ';
    prevMarkerWidth = marker.length;

    const nested: Element[] = [];
    let inline = '';
    for (const sub of Array.from(li.childNodes)) {
      const subTag =
        sub.nodeType === Node.ELEMENT_NODE
          ? (sub as Element).tagName.toLowerCase()
          : '';
      if (subTag === 'ul' || subTag === 'ol') {
        nested.push(sub as Element);
      } else {
        inline += walkInline(sub, ctx);
      }
    }

    let text = inlineOnly(inline);
    // An empty checklist line ("- [ ]" with nothing after it) parses as a
    // plain bullet showing literal "[ ]". The editor repairs that shape on
    // load (fixEmptyTaskItems), but only at line start, which a callout
    // body's "> " prefix defeats - so carry the same zero-width space the
    // repair would insert.
    if (isChecklist && !text) text = '​';
    lines.push(indent + marker + text);
    for (const list of nested) pushNested(list);
  }
  return lines.length > 0 ? `${lines.join('\n')}\n\n` : '';
}

/**
 * UpNote has no header-cell semantics (every cell is a <td>), but its
 * convention for a header row is unmistakable: every non-empty cell of
 * the first row is wrapped whole in <b>. Promote that row to the real
 * header - leaving it as a body row under a synthesized blank header
 * renders an empty first row and a "header" that looks like data.
 */
function isAllBoldRow(tr: Element): boolean {
  let sawText = false;
  for (const cell of Array.from(tr.children)) {
    if (!/^(td|th)$/i.test(cell.tagName)) continue;
    for (const node of Array.from(cell.childNodes)) {
      if (node.nodeType === Node.TEXT_NODE) {
        if ((node.textContent ?? '').trim()) return false;
      } else if (node.nodeType === Node.ELEMENT_NODE) {
        const tag = (node as Element).tagName.toLowerCase();
        if (tag !== 'b' && tag !== 'strong') return false;
        if ((node.textContent ?? '').trim()) sawText = true;
      }
    }
  }
  return sawText;
}

function renderTable(el: Element, ctx: ConvCtx): string {
  const rows = Array.from(el.querySelectorAll('tr'));
  if (rows.length === 0) return '';
  ctx.flags.tables++;

  const cellsOf = (tr: Element) => {
    const cells: string[] = [];
    for (const c of Array.from(tr.children)) {
      if (!/^(td|th)$/i.test(c.tagName)) continue;
      ctx.plainMedia = true;
      const text = inlineOnly(walkInline(c, ctx)).replace(/\|/g, '\\|').replace(/^$/, ' ');
      ctx.plainMedia = false;
      cells.push(text);
      // Markdown has no cell spans; empty placeholder cells keep the later
      // cells of a colspanned row in their original columns. rowspan is
      // not represented - those cells drift up, which is the inherent
      // degradation of flattening to a grid.
      let span = Number(c.getAttribute('colspan') ?? '1');
      if (!Number.isFinite(span)) span = 1;
      for (let s = 1; s < Math.min(span, 10); s++) cells.push(' ');
    }
    return cells;
  };

  const grid = rows.map(cellsOf).filter((r) => r.length > 0);
  if (grid.length === 0) return '';
  const width = Math.max(...grid.map((r) => r.length));
  const pad = (r: string[]) => {
    const copy = [...r];
    while (copy.length < width) copy.push(' ');
    return copy;
  };

  // A first row of all-bold cells is UpNote's header convention and
  // becomes the real header row. Otherwise a blank header is synthesized
  // (GFM requires one) so every row survives as data.
  const firstIsHeader = rows[0]!.querySelector('th') !== null || isAllBoldRow(rows[0]!);
  const header = firstIsHeader ? pad(grid[0]!) : new Array(width).fill(' ');
  const bodyRows = (firstIsHeader ? grid.slice(1) : grid).map(pad);

  const lines = [
    `| ${header.join(' | ')} |`,
    `| ${new Array(width).fill('---').join(' | ')} |`,
    ...bodyRows.map((r) => `| ${r.join(' | ')} |`),
  ];
  return `\n${lines.join('\n')}\n\n`;
}

/** A collapsible section becomes a callout, keeping its fold state. */
function renderCollapsible(el: Element, ctx: ConvCtx): string {
  ctx.flags.callouts++;
  const collapsed = /(?:^|\s)shine-section-collapsed(?:\s|$)/.test(el.getAttribute('class') ?? '');
  const titleEl = el.querySelector('.shine-section-title-inner');
  const contentEl = el.querySelector('.shine-section-content-inner');

  const title = titleEl ? inlineOnly(normalizeText(titleEl.textContent ?? '')) : '';
  const body = contentEl ? renderBlocks(contentEl, ctx).trim() : '';

  const head = `> [!note]${collapsed ? '-' : '+'}${title ? ` ${title}` : ''}`;
  if (!body) return `\n${head}\n\n`;
  const quoted = body
    .split('\n')
    .map((l) => (l.trim() ? `> ${l}` : '>'))
    .join('\n');
  return `\n${head}\n${quoted}\n\n`;
}

/** One block element to markdown. */
function renderBlock(el: Element, ctx: ConvCtx): string {
  const tag = el.tagName.toLowerCase();
  const cls = el.getAttribute('class') ?? '';
  const style = el.getAttribute('style') ?? '';

  if (/(?:^|\s)shine-collapsible-section(?:\s|$)/.test(cls)) {
    return renderCollapsible(el, ctx);
  }
  if (/(?:^|\s)shine-table-wrapper(?:\s|$)/.test(cls)) {
    return renderBlocks(el, ctx);
  }

  switch (tag) {
    case 'hr':
      return '\n---\n\n';

    case 'pre': {
      const code = normalizeText(el.textContent ?? '').replace(/\n+$/, '');
      if (!code.trim()) return '';
      ctx.flags.codeBlocks++;
      const lang =
        (`${cls} ${el.querySelector('code')?.getAttribute('class') ?? ''}`.match(
          /(?:^|\s)language-([A-Za-z0-9+#-]+)/
        )?.[1] ?? '').toLowerCase();
      const fenceLang = lang === 'plaintext' || lang === 'text' || lang === 'none' ? '' : lang;
      return `\n\`\`\`${fenceLang}\n${code}\n\`\`\`\n\n`;
    }

    case 'ul':
    case 'ol':
      return renderList(el, ctx, '');

    case 'blockquote': {
      const inner = (hasBlockChildren(el) ? renderBlocks(el, ctx) : walkInline(el, ctx)).trim();
      if (!inner) return '';
      const quoted = inner
        .split('\n')
        .map((l) => (l.trim() ? `> ${l}` : '>'))
        .join('\n');
      return `\n${quoted}\n\n`;
    }

    case 'table':
      return renderTable(el, ctx);

    case 'h1':
    case 'h2':
    case 'h3':
    case 'h4':
    case 'h5':
    case 'h6': {
      const align = style.match(ALIGN_RE)?.[1]?.toLowerCase();
      if (align && isSimpleAlignable(el)) {
        const inner = inlineOnly(
          Array.from(el.childNodes).map((c) => renderInlineHtml(c, ctx)).join('')
        );
        if (!inner.replace(/<br>/g, '').trim()) return '';
        ctx.flags.aligned++;
        return `\n<${tag} style="text-align: ${align};">${inner}</${tag}>\n\n`;
      }
      if (align) ctx.flags.droppedStyling++;
      const text = inlineOnly(walkInline(el, ctx));
      if (!text) return '';
      return `\n${'#'.repeat(Number(tag[1]))} ${text}\n\n`;
    }

    case 'div':
    case 'p': {
      if (hasBlockChildren(el)) {
        return renderBlocks(el, ctx);
      }
      // A formula alone in its block reads as display math.
      const lone = el.childElementCount === 1 ? el.firstElementChild! : null;
      const loneFormula = lone?.getAttribute('data-upnote-formula');
      if (
        loneFormula &&
        loneFormula.trim() &&
        inlineOnly(normalizeText(el.textContent ?? '')) ===
          inlineOnly(normalizeText(lone!.textContent ?? ''))
      ) {
        ctx.flags.math++;
        return `\n$$${loneFormula.trim()}$$\n\n`;
      }
      const align = style.match(ALIGN_RE)?.[1]?.toLowerCase();
      if (align && isSimpleAlignable(el)) {
        const inner = inlineOnly(
          Array.from(el.childNodes).map((c) => renderInlineHtml(c, ctx)).join('')
        );
        if (!inner.replace(/<br>/g, '').trim()) return '';
        ctx.flags.aligned++;
        return `\n<p style="text-align: ${align};">${inner}</p>\n\n`;
      }
      if (align) ctx.flags.droppedStyling++;
      const inner = walkInline(el, ctx).trim();
      if (!inner) return '\n';
      return `${inner}\n\n`;
    }

    default:
      return `${walkInline(el, ctx).trim()}\n\n`;
  }
}

/**
 * Walk a container's children, accumulating loose inline runs (UpNote's
 * body can open with a bare text node) into paragraphs between blocks.
 */
function renderBlocks(container: Element, ctx: ConvCtx): string {
  const parts: string[] = [];
  let inlineRun = '';

  const flush = () => {
    const text = inlineRun.trim();
    inlineRun = '';
    if (text) parts.push(`${text}\n\n`);
  };

  for (const node of Array.from(container.childNodes)) {
    if (node.nodeType === Node.ELEMENT_NODE) {
      const el = node as Element;
      const tag = el.tagName.toLowerCase();
      const cls = el.getAttribute('class') ?? '';
      if (
        BLOCK_TAGS.has(tag) ||
        /(?:^|\s)shine-(?:collapsible-section|table-wrapper)/.test(cls)
      ) {
        flush();
        parts.push(renderBlock(el, ctx));
        continue;
      }
    }
    inlineRun += walkInline(node, ctx);
  }
  flush();

  return parts.join('');
}

function htmlToMarkdown(html: string, title: string, ctx: ConvCtx): string {
  const doc = new DOMParser().parseFromString(html, 'text/html');
  const body = doc.body;
  if (!body) return '';

  stripLeadingTitle(body, title);

  // The whitespace cleanup must not reach inside fenced code, where blank
  // lines and trailing spaces are content - so it runs per non-fence
  // segment. Fences only ever come from our own <pre> branch, so a plain
  // split is reliable.
  return renderBlocks(body, ctx)
    .split(/(```[\s\S]*?```)/)
    .map((seg, i) =>
      i % 2 === 1 ? seg : seg.replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n')
    )
    .join('')
    .trim();
}

/**
 * UpNote has no separate title field in the editor - the first line of a
 * note IS its title, and the snapshot repeats it at the top of the HTML
 * (as a bare text run, a <div>, or a heading). Remove that first line so
 * the note does not open with its own name; it lives in our title field.
 */
function stripLeadingTitle(body: Element, title: string): void {
  const want = inlineOnly(normalizeText(title));
  if (!want) return;

  // Leading run of inline nodes (bare text, spans, marks) up to the first
  // block element.
  const leading: Node[] = [];
  let firstBlock: Element | null = null;
  for (const node of Array.from(body.childNodes)) {
    if (node.nodeType === Node.ELEMENT_NODE) {
      const tag = (node as Element).tagName.toLowerCase();
      if (BLOCK_TAGS.has(tag) || /(?:^|\s)shine-/.test((node as Element).getAttribute('class') ?? '')) {
        firstBlock = node as Element;
        break;
      }
    }
    leading.push(node);
  }

  const leadingText = inlineOnly(
    normalizeText(leading.map((n) => n.textContent ?? '').join(''))
  );
  if (leadingText && leadingText === want) {
    for (const n of leading) body.removeChild(n);
    return;
  }
  if (leadingText) return; // Real content before any block: not a title line.

  if (
    firstBlock &&
    !hasBlockChildren(firstBlock) &&
    inlineOnly(normalizeText(firstBlock.textContent ?? '')) === want
  ) {
    firstBlock.remove();
  }
}

/* ------------------------------------------------------------------ */
/* Per-note export (the phone route)                                   */
/* ------------------------------------------------------------------ */

/**
 * UpNote's iOS and Android apps cannot write a backup folder - they only
 * export one note at a time (Export behind the note's three-dot menu).
 * Both flavors are a title-named file (truncated, "/" replaced by "_"),
 * zipped together with the note's media flat beside it under the
 * ORIGINAL filenames, referenced by bare basename. Several such export
 * zips can themselves be zipped together (Files app > select > Compress)
 * and import in one go.
 *
 * "Export to HTML" is the one to prefer and the one the guide steers to:
 * it is the SAME rich shine-* markup the backup snapshot carries, so the
 * existing HTML walker converts it with nothing lost.
 *
 * "Export to Markdown" is UpNote's own flavor and needs repairs before
 * it reads cleanly in the editor:
 *   - the first line repeats the title (a heading, or bare text)
 *   - standalone `<br>` lines pad the spacing, and empty headings are
 *     written as `#### <br>`
 *   - every backslash in math is doubled (`$$\\frac{a}{b}$$`)
 *   - `==highlight==`, `[[note links]]`, and inline #tags pass through
 *     natively; callouts, colors, alignment, and sub/superscript were
 *     already flattened by UpNote before the file was written
 */

/** Basename shape of the BACKUP's Markdown folder files (internal ids).
 *  A zip made of only these is someone zipping the backup's Markdown
 *  folder alone - the full backup is the better import, so that zip
 *  keeps the error steering there. */
const UUID_MD_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.md$/i;

/** Markdown link/image, target either bare or angle-bracketed. */
const MD_LINK_RE = /(!?)\[([^\]]*)\]\(\s*(?:<([^>]*)>|([^)\s]+))\s*\)/g;

/** Run a transform on the segments OUTSIDE fenced code blocks. */
function outsideFences(text: string, fn: (seg: string) => string): string {
  return text
    .split(/(```[\s\S]*?```|~~~[\s\S]*?~~~)/)
    .map((seg, i) => (i % 2 === 1 ? seg : fn(seg)))
    .join('');
}

/** Inline #tags, mirroring the backup path (where tagLinks carries them).
 *  Code is stripped first so a #define in a snippet is not a tag. */
function extractUpNoteInlineTags(body: string): string[] {
  const cleaned = body
    .replace(/```[\s\S]*?```/g, '')
    .replace(/`[^`\n]*`/g, '');
  const tags: string[] = [];
  for (const m of cleaned.matchAll(/(?:^|\s)#([a-zA-Z0-9][\w-]*)/g)) {
    const tag = normalizeTag(m[1] ?? '');
    if (tag && !tags.includes(tag)) tags.push(tag);
  }
  return tags;
}

/** Strip markdown escapes UpNote writes into headings and labels. */
function unescapeMd(s: string): string {
  return s.replace(/\\([\\`*_{}[\]()#+.!|~<>-])/g, '$1');
}

/** The cells of a markdown table row, outer pipes dropped. */
function rowCells(line: string): string[] | null {
  const t = line.trim();
  if (!t.startsWith('|') || !t.endsWith('|') || t.length < 2) return null;
  return t.slice(1, -1).split('|');
}

/**
 * UpNote's markdown export writes a table's header row as BLANK cells and
 * puts the real headers, fully bolded, in the first body row (its editor
 * has no header-cell semantics, only the all-bold convention). Promote
 * that row into the header slot - the same call renderTable makes on the
 * backup path - so the imported table does not open with an empty row.
 */
function promoteTableHeaders(text: string): string {
  const lines = text.split('\n');
  for (let i = 0; i + 2 < lines.length; i++) {
    const header = rowCells(lines[i]!);
    if (!header || header.some((c) => c.trim())) continue;
    const sep = rowCells(lines[i + 1]!);
    if (!sep || !sep.every((c) => /^\s*:?-{3,}:?\s*$/.test(c))) continue;
    const bold = rowCells(lines[i + 2]!);
    if (!bold) continue;
    const nonEmpty = bold.filter((c) => c.trim());
    // Every non-empty cell must be one whole bold run, nothing else.
    if (nonEmpty.length === 0 || !nonEmpty.every((c) => /^\*\*[^*]+\*\*$/.test(c.trim()))) {
      continue;
    }
    lines[i] = lines[i + 2]!;
    lines.splice(i + 2, 1);
  }
  return lines.join('\n');
}

interface SingleConv {
  title: string;
  body: string;
  tags: string[];
}

/**
 * The first line of a per-note export is the note's title (UpNote's
 * first-line-is-title model): a heading when the title line was
 * heading-styled, bare text otherwise. A first line that is STRUCTURE
 * (list, quote, table, fence, HTML block, math, image) stays in the body
 * and the filename covers the title.
 */
function takeTitleFromFirstLine(
  text: string,
  filename: string
): { title: string; body: string } {
  const lines = text.split('\n');
  let start = 0;
  while (start < lines.length && !lines[start]!.trim()) start++;
  const first = lines[start]?.trim() ?? '';
  let title = '';
  const heading = first.match(/^#{1,6}\s+(.*)$/);
  if (heading) {
    title = unescapeMd(heading[1]!.trim());
    lines.splice(start, 1);
  } else if (first && !/^(?:[-*+>|<!$]|\d+\.|```)/.test(first)) {
    title = unescapeMd(first);
    lines.splice(start, 1);
  }
  if (!title) title = filename.replace(/\.(?:md|html?)$/i, '');
  return { title, body: lines.join('\n') };
}

/**
 * One per-note markdown export to a clean note. `blobTokens` maps a media
 * basename (lowercased) to its placeholder token; `flags` accumulates the
 * same counters the backup path reports.
 */
function convertSingleMarkdown(
  raw: string,
  filename: string,
  blobTokens: Map<string, string>,
  flags: ConvFlags
): SingleConv {
  let text = raw.replace(/\r\n?/g, '\n');

  text = outsideFences(text, (seg) =>
    seg
      // Empty headings ("#### <br>") and standalone <br> spacer lines.
      .replace(/^#{1,6}\s*(?:<br\s*\/?>\s*)+$/gim, '')
      .replace(/^(?:\s*<br\s*\/?>\s*)+$/gim, '')
      // Leftover inline <br> (table cells): delete with the whitespace
      // before it, so "**header  <br>**" closes its bold cleanly.
      .replace(/\s*<br\s*\/?>/gi, '')
      // UpNote doubles every backslash inside math on export.
      .replace(/\$\$([\s\S]*?)\$\$/g, (_m, inner: string) => `$$${inner.replace(/\\\\/g, '\\')}$$`)
      .replace(/\$([^$\n]+)\$/g, (_m, inner: string) => `$${inner.replace(/\\\\/g, '\\')}$`)
  );

  const taken = takeTitleFromFirstLine(text, filename);
  const title = taken.title;
  let body = taken.body;

  // Media references: bare basenames beside the .md in the zip.
  body = outsideFences(body, (seg) =>
    seg.replace(MD_LINK_RE, (whole, bang: string, label: string, angled?: string, bare?: string) => {
      let target = (angled ?? bare ?? '').trim();
      if (!target || /^[a-z][a-z0-9+.-]*:/i.test(target) || target.startsWith('#')) {
        return whole; // external, anchored, or empty: not ours
      }
      try {
        target = decodeURIComponent(target);
      } catch {
        // Keep the raw form.
      }
      const base = (target.split('/').pop() ?? '').toLowerCase();
      const token = blobTokens.get(base);
      if (token) {
        return `${bang ? '!' : ''}[${label.replace(/[[\]]/g, '')}](${token})`;
      }
      // A relative media reference whose bytes are not in the zip: a dead
      // link helps nobody, keep the visible text.
      if (/\.[a-z0-9]{1,8}$/i.test(base) && !/\.md$/i.test(base)) {
        flags.missingFiles++;
        return bang ? '' : label;
      }
      return whole;
    })
  );

  body = outsideFences(body, promoteTableHeaders);
  body = body.replace(/\n{3,}/g, '\n\n').trim();
  const tags = extractUpNoteInlineTags(body);

  return { title, body, tags };
}

/**
 * One per-note HTML export ("Export to HTML" on the phone) to a clean
 * note. Unlike the Markdown flavor this is the SAME rich shine-* markup
 * the backup snapshot carries - colors, highlights, collapsible sections,
 * alignment, sub/superscript, clean math - wrapped in a standalone
 * document and referencing its media by bare relative basename, which
 * localFileBasename resolves against the zip. The existing HTML walker
 * does all the work; only the title is unknown up front, so it is taken
 * from the first line of the produced markdown afterwards.
 */
function convertSingleHtml(
  raw: string,
  filename: string,
  ctx: ConvCtx
): SingleConv {
  const md = htmlToMarkdown(raw, '', ctx);
  const { title, body: taken } = takeTitleFromFirstLine(md, filename);
  const body = taken.replace(/\n{3,}/g, '\n\n').trim();
  return { title, body, tags: extractUpNoteInlineTags(body) };
}

/** A per-note export file waiting for conversion. */
interface SingleInput {
  name: string;
  text: string;
  date: Date | null;
  kind: 'md' | 'html';
}

/**
 * Parse the per-note export shape: .md or .html files named by title with
 * media flat beside them. `mediaFiles` carries every other zip entry by
 * lowercased basename; only referenced ones are extracted.
 */
async function parseSingleExports(
  texts: SingleInput[],
  mediaFiles: Map<string, JSZip.JSZipObject>,
  onProgress?: (msg: string) => void
): Promise<ParsedImport> {
  onProgress?.(
    `Found ${texts.length} exported note${texts.length === 1 ? '' : 's'}...`
  );

  // Collect which media the notes reference, so an unrelated file in the
  // zip is never imported.
  const referenced = new Set<string>();
  for (const { text, kind } of texts) {
    if (kind === 'html') {
      for (const m of text.matchAll(/(?:src|href)="([^"]*)"/gi)) {
        const base = localFileBasename(m[1] ?? '');
        if (base) referenced.add(base);
      }
      continue;
    }
    for (const m of text.matchAll(MD_LINK_RE)) {
      let target = (m[3] ?? m[4] ?? '').trim();
      if (!target || /^[a-z][a-z0-9+.-]*:/i.test(target)) continue;
      try {
        target = decodeURIComponent(target);
      } catch {
        // Keep the raw form.
      }
      const base = (target.split('/').pop() ?? '').toLowerCase();
      if (base) referenced.add(base);
    }
  }

  const blobs = new Map<string, { data: Uint8Array; mime: string; name: string }>();
  const blobTokens = new Map<string, string>();
  // The HTML export's data-file-id carries UpNote's INTERNAL id while the
  // media beside it is named by original filename, so id lookups cannot
  // resolve here - references resolve via their relative href/src instead.
  const blobFileIdTokens = new Map<string, string>();
  let blobBytes = 0;
  let imageCount = 0;
  let attachmentCount = 0;
  let i = 0;
  for (const [base, entry] of mediaFiles) {
    if (!referenced.has(base)) continue;
    const data = new Uint8Array(await entry.async('uint8array'));
    const token = blobToken(i++);
    const mime = mimeFromExt(base);
    const name = entry.name.split('/').pop() ?? base;
    blobs.set(token, { data, mime, name });
    blobTokens.set(base, token);
    blobBytes += data.length;
    if (mime.startsWith('image/')) imageCount++;
    else attachmentCount++;
  }

  const flags: ConvFlags = {
    underline: 0, highlights: 0, colors: 0, checklists: 0, tables: 0,
    codeBlocks: 0, callouts: 0, math: 0, noteLinks: 0, aligned: 0,
    droppedStyling: 0, missingFiles: 0,
  };

  const ctx: ConvCtx = {
    blobTokens,
    fileIdTokens: blobFileIdTokens,
    noteTitles: new Map(),
    plainMedia: false,
    flags,
  };

  const out: ImportedNote[] = [];
  let mdCount = 0;
  for (const { name, text, date, kind } of texts) {
    const base = name.split('/').pop() ?? name;
    let conv: SingleConv;
    if (kind === 'html') {
      conv = convertSingleHtml(text, base, ctx);
    } else {
      mdCount++;
      conv = convertSingleMarkdown(text, base, blobTokens, flags);
    }
    const fallback =
      date && !Number.isNaN(date.getTime()) ? date.toISOString() : new Date().toISOString();
    out.push({
      title: conv.title,
      // The single funnel for this branch's bodies (rule in linkify.ts).
      body: linkifyMarkdown(conv.body),
      tags: conv.tags,
      createdAt: fallback,
      updatedAt: fallback,
    });
  }

  const plural = (n: number) => (n === 1 ? '' : 's');
  const uniqueTags = new Set(out.flatMap((n) => n.tags));

  const warnings: string[] = [
    mdCount > 0
      ? 'This is UpNote\'s per-note Markdown export. It keeps text, lists, tables, code, math, links, images, and attachments - but UpNote flattens callouts, text colors, alignment, and sub/superscript before writing it, and it carries no notebooks, pins, or original dates. On the phone, "Export to HTML" keeps that formatting; on a computer, Settings > Backup keeps everything.'
      : 'These are UpNote\'s per-note HTML exports: formatting, images, and attachments come across in full. Per-note exports carry no notebooks, pins, or original dates - on a computer, Settings > Backup produces a backup folder that keeps those too.',
  ];
  if (flags.missingFiles > 0) {
    warnings.push(
      `${flags.missingFiles === 1 ? '1 file was' : `${flags.missingFiles} files were`} referenced by the notes but not in the zip. Export the note again and share the whole zip UpNote produces, without unpacking it.`
    );
  }

  const transforms: string[] = [];
  const tagged = out.filter((n) => n.tags.length > 0).length;
  if (tagged > 0) transforms.push(`Kept the inline #tags on ${tagged} note${plural(tagged)}.`);
  if (flags.noteLinks > 0) {
    transforms.push(`Converted ${flags.noteLinks} internal link${plural(flags.noteLinks)} into note-links.`);
  }
  if (flags.checklists > 0) {
    transforms.push(`Converted ${flags.checklists} checklist${plural(flags.checklists)} into native task lists.`);
  }
  if (flags.callouts > 0) {
    transforms.push(
      `Converted ${flags.callouts} collapsible section${plural(flags.callouts)} into callouts, keeping their fold state.`
    );
  }
  if (flags.tables > 0) transforms.push(`Preserved ${flags.tables} table${plural(flags.tables)}.`);
  if (flags.codeBlocks > 0) {
    transforms.push(`Preserved ${flags.codeBlocks} code block${plural(flags.codeBlocks)}.`);
  }
  if (flags.math > 0) transforms.push(`Preserved ${flags.math} math formula${plural(flags.math)}.`);
  if (flags.highlights > 0) transforms.push('Preserved highlights.');
  if (flags.colors > 0) transforms.push('Matched text colors to the editor palette.');
  if (flags.underline > 0) transforms.push('Preserved underline formatting.');
  if (flags.aligned > 0) transforms.push('Preserved text alignment.');
  if (imageCount > 0) transforms.push(`Found ${imageCount} image${plural(imageCount)} to import.`);
  if (attachmentCount > 0) {
    transforms.push(`Found ${attachmentCount} attachment${plural(attachmentCount)} to import.`);
  }
  if (mdCount > 0) {
    transforms.push('Repaired UpNote\'s markdown quirks (spacer tags, escaped math).');
  }
  transforms.push('Made bare URLs clickable.');

  return {
    notes: out,
    warnings,
    transforms,
    stats: {
      totalNotes: out.length,
      emptyNotes: out.filter((n) => !n.title.trim() && !n.body.trim()).length,
      untaggedNotes: out.filter((n) => n.tags.length === 0).length,
      uniqueTags: uniqueTags.size,
    },
    source: 'upnote',
    blobBytes,
    blobs: blobs.size > 0 ? blobs : undefined,
  };
}

/* ------------------------------------------------------------------ */
/* Zip parsing                                                        */
/* ------------------------------------------------------------------ */

/** Blob placeholder token. Fixed width so no key is a prefix of another. */
function blobToken(index: number): string {
  return `upnatt:${String(index).padStart(6, '0')}`;
}

const NOT_A_BACKUP =
  'No UpNote snapshot found in that zip. In UpNote open Settings > Backup, click "Backup now", then "View backup folder", and zip EVERYTHING in that folder (the data and files folders together). The data folder is the one that carries your notes\' formatting, notebooks, and tags.';

export async function parseUpNote(
  file: File,
  onProgress?: (msg: string) => void
): Promise<ParsedImport> {
  // A bare .md or .html is a per-note export shared without its zip (a
  // note that carries no media exports as just the file).
  const bareKind = /\.html?$/i.test(file.name) ? 'html' : /\.md$/i.test(file.name) ? 'md' : null;
  if (bareKind) {
    const text = await file.text();
    return await parseSingleExports(
      [{ name: file.name, text, date: null, kind: bareKind }],
      new Map(),
      onProgress
    );
  }

  onProgress?.('Reading zip...');
  const buf = await file.arrayBuffer();
  let zip: JSZip;
  try {
    zip = await JSZip.loadAsync(buf);
  } catch {
    throw new Error(
      'Could not read that file as a zip. In UpNote open Settings > Backup, click "Backup now" and then "View backup folder", zip everything in that folder, and drop the .zip here. On the phone, use the note\'s three-dot menu > Export > "Export to HTML" and drop what UpNote shares.'
    );
  }

  // Locate the data/ snapshots anywhere in the zip: the user may have
  // zipped the backup folder's contents, the folder itself, or a parent -
  // and a stray .DS_Store beside the wrapper must not derail detection.
  // The snapshot location decides the backup root that files/ is resolved
  // against too.
  const isJunk = (path: string) =>
    path.startsWith('__MACOSX/') ||
    path.includes('/__MACOSX/') ||
    (path.split('/').pop() ?? '').startsWith('.');

  let anyEntry = false;
  const snapshotsByRoot = new Map<string, { ts: number; entry: JSZip.JSZipObject }[]>();
  zip.forEach((path, entry) => {
    if (entry.dir) return;
    anyEntry = true;
    if (isJunk(path)) return;
    const m = path.match(/^(|.*\/)data\/(\d+)\.upnx$/i);
    if (!m) return;
    const list = snapshotsByRoot.get(m[1]!) ?? [];
    list.push({ ts: Number(m[2]), entry });
    snapshotsByRoot.set(m[1]!, list);
  });
  if (!anyEntry) throw new Error('That zip is empty.');

  if (snapshotsByRoot.size === 0) {
    // Not a backup. The other shape UpNote produces is the per-note
    // export (the only route on iOS and Android): a title-named .html or
    // .md with its media flat beside it. A zip of ONLY uuid-named .md
    // files is the backup's Markdown folder zipped alone - that user has
    // the full backup one folder up, so the error keeps steering them
    // there rather than importing the flattened rendering.
    const noteFiles: { name: string; entry: JSZip.JSZipObject; kind: 'md' | 'html' }[] = [];
    const mediaFiles = new Map<string, JSZip.JSZipObject>();
    const outerZips: { base: string; entry: JSZip.JSZipObject }[] = [];
    const classify = (path: string, entry: JSZip.JSZipObject, outer: boolean) => {
      const base = path.split('/').pop() ?? '';
      if (!base) return;
      if (/\.html?$/i.test(base)) noteFiles.push({ name: path, entry, kind: 'html' });
      else if (/\.md$/i.test(base)) noteFiles.push({ name: path, entry, kind: 'md' });
      else if (/\.zip$/i.test(base) && outer) outerZips.push({ base, entry });
      else mediaFiles.set(base.toLowerCase(), entry);
    };
    zip.forEach((path, entry) => {
      if (entry.dir || isJunk(path)) return;
      classify(path, entry, true);
    });

    // "Select the exports in Files, Compress" on the phone produces a zip
    // OF the export zips - expand those one level so that flow just
    // works. Only when the outer zip carries no note files of its own,
    // though: with a note file at the top, a nested .zip is that note's
    // ATTACHMENT and expanding it would destroy it. (Media basenames are
    // assumed unique across one batch; a collision keeps the last file.)
    if (noteFiles.length === 0) {
      for (const { entry: nz } of outerZips) {
        try {
          const inner = await JSZip.loadAsync(await nz.async('uint8array'));
          inner.forEach((path, entry) => {
            if (entry.dir || isJunk(path)) return;
            classify(path, entry, false);
          });
        } catch {
          // Not a readable zip: leave it alone.
        }
      }
    } else {
      for (const { base, entry } of outerZips) mediaFiles.set(base.toLowerCase(), entry);
    }

    // A note exported as both .html and .md (same stem) imports once,
    // from the HTML - it is the lossless one.
    const htmlStems = new Set(
      noteFiles
        .filter((f) => f.kind === 'html')
        .map((f) => (f.name.split('/').pop() ?? '').replace(/\.html?$/i, '').toLowerCase())
    );
    const picked = noteFiles.filter(
      (f) =>
        f.kind === 'html' ||
        !htmlStems.has((f.name.split('/').pop() ?? '').replace(/\.md$/i, '').toLowerCase())
    );

    if (
      picked.length > 0 &&
      !picked.every(
        ({ name, kind }) => kind === 'md' && UUID_MD_RE.test(name.split('/').pop() ?? '')
      )
    ) {
      const texts: SingleInput[] = [];
      for (const { name, entry, kind } of picked) {
        texts.push({ name, text: await entry.async('string'), date: entry.date ?? null, kind });
      }
      return await parseSingleExports(texts, mediaFiles, onProgress);
    }
    throw new Error(NOT_A_BACKUP);
  }

  // Several roots would mean several backups zipped together (rare); the
  // one holding the newest snapshot wins.
  let root = '';
  let bestTs = -1;
  for (const [r, list] of snapshotsByRoot) {
    const newest = Math.max(...list.map((s) => s.ts));
    if (newest > bestTs) {
      bestTs = newest;
      root = r;
    }
  }
  const snapshotEntries = snapshotsByRoot.get(root)!.sort((a, b) => b.ts - a.ts);

  // Newest parseable snapshot wins. Each backup run writes a complete
  // snapshot named by epoch ms, but an interrupted or empty run leaves an
  // unusable artifact behind - the one seen in the wild is a complete
  // 29-byte gzip holding only the version header, and a truncated torso
  // is equally possible - so fall back through older snapshots until one
  // yields records.
  onProgress?.('Reading backup snapshot...');
  let snap: Snapshot | null = null;
  for (const { entry } of snapshotEntries) {
    try {
      const bytes = new Uint8Array(await entry.async('uint8array'));
      snap = parseSnapshot(await gunzip(bytes));
      if (snap) break;
    } catch {
      // Truncated or corrupt snapshot: try the next older one.
    }
  }
  if (!snap) {
    throw new Error(
      'The backup\'s data snapshots could not be read. Run "Back up now" in UpNote again and zip the fresh backup folder.'
    );
  }

  const notes = [...snap.notes.values()];
  onProgress?.(`Found ${notes.length} note${notes.length === 1 ? '' : 's'}...`);

  /* ---------------- attachments ---------------- */

  const fileEntries: { base: string; entry: JSZip.JSZipObject }[] = [];
  zip.forEach((path, entry) => {
    if (entry.dir || isJunk(path) || !path.startsWith(root)) return;
    const r = path.slice(root.length);
    if (!/^files\//i.test(r)) return;
    const base = r.split('/').pop() ?? '';
    if (base) fileEntries.push({ base, entry });
  });

  // Which basenames do the notes actually reference? Extract only those,
  // so an orphaned leftover in files/ does not burn quota.
  const referenced = new Set<string>();
  const refRe = /(?:localhost|127\.0\.0\.1)(?::\d+)?\/(?:files|images)\/([^"'\s?#]+)/gi;
  for (const n of notes) {
    for (const m of n.html.matchAll(refRe)) {
      let base = m[1]!;
      try {
        base = decodeURIComponent(base);
      } catch {
        // Keep the raw form.
      }
      referenced.add(base.toLowerCase());
    }
  }

  const blobs = new Map<string, { data: Uint8Array; mime: string; name: string }>();
  const blobTokens = new Map<string, string>();
  const fileIdTokens = new Map<string, string>();

  const wanted = fileEntries.filter((f) => referenced.has(f.base.toLowerCase()));
  if (wanted.length > 0) {
    onProgress?.(
      `Extracting ${wanted.length} attachment${wanted.length === 1 ? '' : 's'}...`
    );
  }
  for (let i = 0; i < wanted.length; i++) {
    const { base, entry } = wanted[i]!;
    const data = new Uint8Array(await entry.async('uint8array'));
    const token = blobToken(i);
    const mime = mimeFromExt(base);
    // The snapshot's files records carry the original filename; the bytes
    // on disk are named by UpNote's internal id ("<uuid>.<ext>", file id
    // "<uuid>__<ext>"). Prefer the original name.
    const dot = base.lastIndexOf('.');
    const fileId = dot > 0 ? `${base.slice(0, dot)}__${base.slice(dot + 1)}` : base;
    const name = snap.fileNames.get(fileId) ?? base;

    blobs.set(token, { data, mime, name });
    blobTokens.set(base.toLowerCase(), token);
    fileIdTokens.set(fileId.toLowerCase(), token);
    if ((i + 1) % 20 === 0) {
      onProgress?.(`Extracted ${i + 1} of ${wanted.length} attachments...`);
    }
  }

  /* ---------------- notebooks -> folders ---------------- */

  // Full path ("A/B/C") per notebook, walking parent links. Titles keep
  // their text but lose "/" (it is the path separator here).
  const nbPath = new Map<string, string[]>();
  const pathOf = (id: string): string[] => {
    const cached = nbPath.get(id);
    if (cached) return cached;
    const segs: string[] = [];
    let cur = snap!.notebooks.get(id);
    const seen = new Set<string>();
    while (cur && !seen.has(cur.id)) {
      seen.add(cur.id);
      segs.unshift(cur.title.replace(/\//g, '-').trim() || 'Notebook');
      cur = cur.parent ? snap!.notebooks.get(cur.parent) : undefined;
    }
    nbPath.set(id, segs);
    return segs;
  };

  // A note can live in several notebooks in UpNote; we file it under the
  // first and keep the extra notebooks as tags so nothing is lost.
  const primaryNotebook = new Map<string, string>();
  const extraTags = new Map<string, string[]>();
  for (const [nbId, noteIds] of snap.members) {
    if (!snap.notebooks.has(nbId)) continue;
    for (const noteId of noteIds) {
      if (!snap.notes.has(noteId)) continue;
      if (!primaryNotebook.has(noteId)) {
        primaryNotebook.set(noteId, nbId);
      } else if (primaryNotebook.get(noteId) !== nbId) {
        const tag = normalizeTag(snap.notebooks.get(nbId)!.title);
        if (tag) {
          const list = extraTags.get(noteId) ?? [];
          if (!list.includes(tag)) {
            list.push(tag);
            extraTags.set(noteId, list);
          }
        }
      }
    }
  }
  // Notes (not tag pairs) that lived in more than one notebook.
  const multiHomed = extraTags.size;

  const usedPaths = [...new Set([...primaryNotebook.values()].map((nbId) => pathOf(nbId).join('/')))];
  const { folders, dirToFolderId } = buildFolderTree(usedPaths);

  /* ---------------- notes ---------------- */

  const noteTitles = new Map<string, string>();
  for (const n of notes) noteTitles.set(n.id, n.title.trim());

  const flags: ConvFlags = {
    underline: 0,
    highlights: 0,
    colors: 0,
    checklists: 0,
    tables: 0,
    codeBlocks: 0,
    callouts: 0,
    math: 0,
    noteLinks: 0,
    aligned: 0,
    droppedStyling: 0,
    missingFiles: 0,
  };
  const ctx: ConvCtx = { blobTokens, fileIdTokens, noteTitles, plainMedia: false, flags };

  const out: ImportedNote[] = [];
  let templates = 0;
  let trashedCount = 0;

  for (let i = 0; i < notes.length; i++) {
    const n = notes[i]!;

    let body: string;
    if (n.html.trim()) {
      body = htmlToMarkdown(n.html, n.title, ctx);
    } else {
      // No rich body in the snapshot: fall back to the plain-text field.
      body = normalizeText(n.text).trim();
      const want = inlineOnly(normalizeText(n.title));
      if (want && body.startsWith(want)) body = body.slice(want.length).trim();
    }
    body = linkifyMarkdown(body);

    const tags = [...n.tags];
    for (const t of extraTags.get(n.id) ?? []) if (!tags.includes(t)) tags.push(t);
    if (n.isTemplate) {
      templates++;
      const t = normalizeTag('template');
      if (!tags.includes(t)) tags.push(t);
    }
    if (n.trashed) trashedCount++;

    const fallback = new Date().toISOString();
    const toIso = (ms: number | null) => {
      if (ms === null) return null;
      const d = new Date(ms);
      return Number.isNaN(d.getTime()) ? null : d.toISOString();
    };
    const createdAt = toIso(n.createdAt) ?? fallback;
    const updatedAt = toIso(n.updatedAt) ?? createdAt;

    const note: ImportedNote = {
      title: n.title.trim(),
      body,
      tags,
      createdAt,
      updatedAt,
      trashed: n.trashed,
      starred: n.pinned || n.bookmarked,
    };

    const nbId = primaryNotebook.get(n.id);
    if (nbId) {
      const segs = pathOf(nbId);
      note.folderId = dirToFolderId.get(segs.join('/')) ?? null;
      note.folderPath = segs;
    }
    out.push(note);

    if ((i + 1) % 50 === 0) {
      onProgress?.(`Parsed ${i + 1} of ${notes.length}...`);
    }
  }

  /* ---------------- blobs actually referenced ---------------- */

  // Ship only blobs some body still carries a token for: a file whose only
  // reference sat where the token could not be emitted (a table cell)
  // would otherwise land in storage unreachable and burn quota. Counts
  // and blobBytes describe this final set, which is what the quota
  // preflight and the preview must see.
  let blobBytes = 0;
  let imageCount = 0;
  let attachmentCount = 0;
  for (const [token, blob] of [...blobs]) {
    if (!out.some((n) => n.body.includes(token))) {
      blobs.delete(token);
      continue;
    }
    blobBytes += blob.data.length;
    if (blob.mime.startsWith('image/')) imageCount++;
    else attachmentCount++;
  }

  /* ---------------- summary ---------------- */

  const plural = (n: number) => (n === 1 ? '' : 's');
  const uniqueTags = new Set(out.flatMap((n) => n.tags));
  const emptyNotes = out.filter((n) => !n.title.trim() && !n.body.trim()).length;
  const untaggedNotes = out.filter((n) => n.tags.length === 0).length;

  const warnings: string[] = [];
  if (flags.missingFiles > 0) {
    warnings.push(
      `${flags.missingFiles === 1 ? '1 attached file was' : `${flags.missingFiles} attached files were`} referenced by notes but missing from the backup folder, so ${flags.missingFiles === 1 ? 'it' : 'they'} could not be imported. In UpNote, enable "Backup attachments" under Settings > Backup, run "Backup now" again, and re-import the fresh zip.`
    );
  }
  const transforms: string[] = [];
  if (folders.length > 0) {
    const filed = out.filter((n) => n.folderId).length;
    transforms.push(
      `Rebuilt ${folders.length} notebook${plural(folders.length)} as folders (${filed} note${plural(filed)} filed).`
    );
  }
  if (multiHomed > 0) {
    transforms.push(
      `${multiHomed} note${plural(multiHomed)} lived in more than one notebook; kept the first as the folder and the others as tags.`
    );
  }
  const tagged = out.filter((n) => n.tags.length > 0).length;
  if (tagged > 0) transforms.push(`Kept the tags on ${tagged} note${plural(tagged)}.`);
  const starred = out.filter((n) => n.starred).length;
  if (starred > 0) {
    transforms.push(`Marked ${starred} pinned or bookmarked note${plural(starred)} as Pinned.`);
  }
  if (trashedCount > 0) {
    transforms.push(`Moved ${trashedCount} trashed note${plural(trashedCount)} to the trash.`);
  }
  if (templates > 0) {
    transforms.push(`Imported ${templates} template${plural(templates)} as notes tagged #template.`);
  }
  if (flags.noteLinks > 0) {
    transforms.push(`Converted ${flags.noteLinks} internal link${plural(flags.noteLinks)} into note-links.`);
  }
  if (flags.checklists > 0) {
    transforms.push(`Converted ${flags.checklists} checklist${plural(flags.checklists)} into native task lists.`);
  }
  if (flags.callouts > 0) {
    transforms.push(
      `Converted ${flags.callouts} collapsible section${plural(flags.callouts)} into callouts, keeping their fold state.`
    );
  }
  if (flags.tables > 0) transforms.push(`Preserved ${flags.tables} table${plural(flags.tables)}.`);
  if (flags.codeBlocks > 0) {
    transforms.push(`Preserved ${flags.codeBlocks} code block${plural(flags.codeBlocks)}.`);
  }
  if (flags.math > 0) transforms.push(`Preserved ${flags.math} math formula${plural(flags.math)}.`);
  if (flags.highlights > 0) transforms.push('Preserved highlights.');
  if (flags.colors > 0) transforms.push('Matched text colors to the editor palette.');
  if (flags.underline > 0) transforms.push('Preserved underline formatting.');
  if (flags.aligned > 0) transforms.push('Preserved text alignment.');
  if (flags.droppedStyling > 0) {
    transforms.push('Dropped alignment on blocks the editor cannot align, keeping the text.');
  }
  if (imageCount > 0) transforms.push(`Found ${imageCount} image${plural(imageCount)} to import.`);
  if (attachmentCount > 0) {
    transforms.push(`Found ${attachmentCount} attachment${plural(attachmentCount)} to import.`);
  }
  transforms.push('Made bare URLs clickable.');

  return {
    notes: out,
    warnings,
    transforms,
    stats: {
      totalNotes: out.length,
      emptyNotes,
      untaggedNotes,
      uniqueTags: uniqueTags.size,
    },
    source: 'upnote',
    blobBytes,
    blobs: blobs.size > 0 ? blobs : undefined,
    folders,
  };
}
