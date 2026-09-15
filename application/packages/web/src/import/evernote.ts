import JSZip from 'jszip';
import { zipEntryText } from './zipEntry';
import { normalizeTag } from '../notesRepo';
import { buildFolderTree } from './folderImport';
import { linkifyMarkdown } from './linkify';
import { noteLinkTarget } from '../noteLinks';
import { importBlobs } from './blobImport';
import type { ImportedNote, ParsedImport } from './types';

/**
 * Evernote importer (.enex).
 *
 * Evernote offers four export formats; only one of them is worth
 * parsing, and this importer takes that one.
 *
 *   - **ENEX (.enex)** - what we read. One XML file per notebook, with
 *     every note's ENML body inline and every attachment embedded as
 *     base64 next to its real filename and MIME type. Self-contained.
 *   - *Multiple web pages (.html)* - the only format that carries
 *     Evernote **Tasks**, but it writes ~900 KB per note (476 KB of that
 *     is the same CSS and SVG sprite repeated in every file) and it
 *     drops the filename and the link for every non-image attachment.
 *     A large library would exhaust memory before it finished.
 *   - *Single web page (.html)* - as above, concatenated, with no
 *     reliable note boundary.
 *   - *PDF* - every note fused into one document. No structure at all.
 *
 * What ENEX carries, and what we do with it:
 *   - Title, created, updated, and tags map straight across.
 *   - ENML is walked into the markdown the editor stores. Evernote marks
 *     its non-HTML blocks with CSS custom properties rather than real
 *     elements, so the walker keys off `--en-codeblock`, `--en-todo`,
 *     `--en-highlight`, `--en-formulablock`, and friends.
 *   - `<resource>` blobs are decoded and matched to their `<en-media>`
 *     by MD5, which is how ENML references them. There is no hash in the
 *     XML, so we compute it (see md5hex).
 *   - `evernote://view-note/<guid>` links become [[note links]]. The GUID
 *     is not exported anywhere, but Evernote writes the target note's
 *     title as the anchor text, so the title is what we resolve against.
 *   - Voice notes keep their auto-transcription, which rides along in the
 *     `--en-transcription` style blob on the `<en-media>` element.
 *   - Each .enex file becomes a folder named after it, since Evernote
 *     names the export after the notebook. Zip several together to
 *     rebuild a whole account's notebook list in one go.
 *
 * What ENEX does not carry, and we therefore cannot import:
 *   - **Tasks.** Evernote replaces every task block with a "Content not
 *     supported" placeholder. The titles, due dates, and completion
 *     states are simply absent from the file. We strip the placeholder
 *     and tell the user how many blocks were lost. (Checklists are a
 *     different Evernote feature and do survive - they import as native
 *     task lists.)
 *   - Encrypted text blocks (`<en-crypt>`), which stay encrypted with a
 *     passphrase Evernote never exports.
 *   - Fonts, font sizes, and text alignment: no editor node for them, so
 *     the text is kept and the styling is dropped. Text color does come
 *     across (see colorOf).
 */

/* ------------------------------------------------------------------ */
/* Shared helpers                                                     */
/* ------------------------------------------------------------------ */

const ENEX_EXT = /\.enex$/i;

/** Files and folders that are never note content. */
function shouldSkip(path: string): boolean {
  const lower = path.toLowerCase();
  if (lower.startsWith('__macosx/') || lower.includes('/__macosx/')) return true;
  const name = path.split('/').pop() ?? '';
  if (name.startsWith('.')) return true;
  return false;
}

/** Notebook name from an .enex filename: "Work/Recipes.enex" -> "Recipes". */
function notebookName(path: string): string {
  const base = path.split('/').pop() ?? path;
  return base.replace(ENEX_EXT, '').trim();
}

/**
 * Evernote timestamps are basic-format ISO 8601 in UTC:
 * `20260731T125725Z`. Date.parse does not accept the basic form in every
 * engine, so we expand it to the extended form first. Returns null when
 * the shape does not match, so the caller can fall back.
 */
function parseEnexDate(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const m = raw
    .trim()
    .match(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z?$/);
  if (!m) {
    const loose = Date.parse(raw);
    return Number.isNaN(loose) ? null : new Date(loose).toISOString();
  }
  const iso = `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}Z`;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : new Date(t).toISOString();
}

/** Local-date label for a reminder line, e.g. "2026-08-05". */
function dueLabel(iso: string): string {
  return iso.slice(0, 10);
}

/** Blob placeholder token. Fixed width so no key is a prefix of another. */
function blobToken(index: number): string {
  return `evatt:${String(index).padStart(6, '0')}`;
}

/* ------------------------------------------------------------------ */
/* Text color                                                         */
/* ------------------------------------------------------------------ */

/**
 * The color forms the app's own sanitizer accepts (`sanitizeColor` in
 * markdownRender.ts): hex, and the rgb/hsl functional notations.
 *
 * Anything outside this set is dropped rather than passed through. A
 * color the editor accepts but the sanitizer does not would render in the
 * editor and then silently flatten to plain text in the HTML export and
 * the burn-after-reading viewer, which is a worse outcome than being
 * consistently uncolored.
 */
// Spec: packages/web/src/markdownRender.ts (sanitizeColor)
const COLOR_OK =
  /^(?:#(?:[0-9a-f]{3,4}|[0-9a-f]{6}|[0-9a-f]{8})|(?:rgb|rgba|hsl|hsla)\([0-9.,%\s/]+\))$/i;

/** The 16 CSS level-1 names, which is what Evernote's older `<font color>`
 *  markup emits. Anything the current editor writes is already rgb(). */
const NAMED_COLORS: Record<string, string> = {
  black: '#000000', silver: '#c0c0c0', gray: '#808080', white: '#ffffff',
  maroon: '#800000', red: '#ff0000', purple: '#800080', fuchsia: '#ff00ff',
  green: '#008000', lime: '#00ff00', olive: '#808000', yellow: '#ffff00',
  navy: '#000080', blue: '#0000ff', teal: '#008080', aqua: '#00ffff',
};

/**
 * Text color off a `<span style="color:…">` (current Evernote) or a
 * `<font color="…">` (notes written years ago).
 *
 * The leading `(?:^|[;\s])` is what keeps `background-color` and
 * Evernote's own `--inversion-type-color` out of the match: both carry a
 * `-` immediately before `color`, so neither can start the group. Getting
 * that wrong would paint every highlighted run in its highlight color.
 */
function colorOf(el: Element, style: string): string | null {
  const raw =
    style.match(/(?:^|[;\s])color\s*:\s*([^;]+)/i)?.[1] ??
    el.getAttribute('color') ??
    '';
  const c = raw.trim().toLowerCase();
  if (!c) return null;
  if (COLOR_OK.test(c)) return c;
  // Own property only: the name comes out of the export, and an inherited one
  // answers with a function that `?? null` cannot see.
  return Object.hasOwn(NAMED_COLORS, c) ? NAMED_COLORS[c]! : null;
}

/** Extension for a resource that has no filename, derived from its MIME. */
function extFromMime(mime: string): string {
  const map: Record<string, string> = {
    'image/png': 'png', 'image/jpeg': 'jpg', 'image/gif': 'gif',
    'image/webp': 'webp', 'image/svg+xml': 'svg', 'image/bmp': 'bmp',
    'image/heic': 'heic', 'image/tiff': 'tiff',
    'application/pdf': 'pdf', 'application/zip': 'zip',
    'audio/webm': 'webm', 'audio/mpeg': 'mp3', 'audio/mp4': 'm4a',
    'audio/wav': 'wav', 'audio/x-wav': 'wav', 'audio/ogg': 'ogg',
    'video/mp4': 'mp4', 'video/webm': 'webm', 'video/quicktime': 'mov',
    'text/plain': 'txt', 'text/csv': 'csv', 'text/html': 'html',
  };
  return map[mime.toLowerCase()] ?? 'bin';
}

/**
 * Decode a base64 payload that Evernote has hard-wrapped at column 80.
 * atob rejects embedded whitespace, so it has to come out first.
 */
function decodeBase64(raw: string): Uint8Array {
  const clean = raw.replace(/[^A-Za-z0-9+/=]/g, '');
  const bin = atob(clean);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/* ------------------------------------------------------------------ */
/* MD5                                                                */
/* ------------------------------------------------------------------ */

/**
 * MD5 of a byte array, lowercase hex.
 *
 * ENML references each attachment by `<en-media hash="...">`, where the
 * hash is the MD5 of the resource bytes. ENEX does not store that hash
 * anywhere in the XML, so the only way to connect a `<resource>` to its
 * placement in the note is to compute it. WebCrypto does not implement
 * MD5 (rightly - it is broken for security), and this is not a security
 * use: it is a content address defined by someone else's file format.
 *
 * Positional matching was the alternative and it is wrong: Evernote
 * stores one `<resource>` for an image used twice in a note, so the
 * counts do not line up as soon as anyone duplicates an image.
 */
function md5hex(bytes: Uint8Array): string {
  const S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
  ];
  const K = new Int32Array(64);
  for (let i = 0; i < 64; i++) {
    K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296);
  }

  const len = bytes.length;
  // Message + 0x80 + zero padding to 56 mod 64 + 8-byte little-endian length.
  const padded = new Uint8Array((((len + 8) >> 6) + 1) << 6);
  padded.set(bytes);
  padded[len] = 0x80;
  const bitLen = len * 8;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, bitLen >>> 0, true);
  view.setUint32(padded.length - 4, Math.floor(bitLen / 4294967296), true);

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const M = new Int32Array(16);

  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) M[i] = view.getInt32(off + i * 4, true);
    let A = a0, B = b0, C = c0, D = d0;

    for (let i = 0; i < 64; i++) {
      let F: number;
      let g: number;
      if (i < 16) {
        F = (B & C) | (~B & D);
        g = i;
      } else if (i < 32) {
        F = (D & B) | (~D & C);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        F = B ^ C ^ D;
        g = (3 * i + 5) % 16;
      } else {
        F = C ^ (B | ~D);
        g = (7 * i) % 16;
      }
      F = (F + A + K[i]! + M[g]!) | 0;
      A = D;
      D = C;
      C = B;
      const s = S[i]!;
      B = (B + ((F << s) | (F >>> (32 - s)))) | 0;
    }

    a0 = (a0 + A) | 0;
    b0 = (b0 + B) | 0;
    c0 = (c0 + C) | 0;
    d0 = (d0 + D) | 0;
  }

  let hex = '';
  for (const word of [a0, b0, c0, d0]) {
    for (let i = 0; i < 4; i++) {
      hex += ((word >>> (i * 8)) & 0xff).toString(16).padStart(2, '0');
    }
  }
  return hex;
}

/* ------------------------------------------------------------------ */
/* ENML pre-processing                                                */
/* ------------------------------------------------------------------ */

/**
 * ENML claims to be XHTML, so its void elements are self-closed:
 * `<en-media … />`, `<en-todo checked="true"/>`. An HTML parser has
 * never heard of those tags, does not treat them as void, and therefore
 * makes every following sibling a child of them - one stray `<en-media/>`
 * near the top of a note would nest the entire rest of the body inside
 * it.
 *
 * Parsing as XML instead would respect the self-closing syntax, but ENML
 * bodies routinely contain named HTML entities (`&nbsp;` above all) that
 * an XML parser rejects outright, because the DTD that declares them is
 * external and never fetched. One `&nbsp;` and the whole note fails.
 *
 * So: rewrite Evernote's void tags into HTML ones the parser already
 * knows are void, and keep the forgiving HTML path. `<img>` and `<input>`
 * are chosen because they are void, and because they carry arbitrary
 * data attributes through untouched.
 *
 * The attribute run is matched quote-aware rather than as `[^>]*`,
 * because an `<en-media>` on a voice note carries the whole transcript
 * inside its style attribute, and a transcript is free text that can
 * perfectly well contain a `>`.
 */
const ATTR_RUN = `(?:"[^"]*"|'[^']*'|[^>"'])*?`;

function normalizeEnml(enml: string): string {
  return enml
    .replace(
      new RegExp(`<en-media\\b(${ATTR_RUN})/?>`, 'gi'),
      '<img data-en-media="1"$1>'
    )
    .replace(/<\/en-media\s*>/gi, '')
    .replace(
      new RegExp(`<en-todo\\b(${ATTR_RUN})/?>`, 'gi'),
      '<input data-en-todo="1"$1>'
    )
    .replace(/<\/en-todo\s*>/gi, '');
}

/**
 * Pull the transcript out of a voice note's `--en-transcription` blob.
 *
 * The attribute holds a JSON document that has been string-escaped and
 * then HTML-escaped, so by the time getAttribute hands it back it looks
 * like `--en-transcription:"{\"segments\":[{\"text\":\"…\"}]}"`. Feeding
 * the inner run back through JSON.parse twice unwraps both layers.
 */
function transcriptOf(style: string): string {
  const m = style.match(/--en-transcription:\s*"((?:[^"\\]|\\.)*)"/);
  if (!m?.[1]) return '';
  try {
    const json = JSON.parse(`"${m[1]}"`) as string;
    const data = JSON.parse(json) as {
      segments?: { text?: string }[];
    };
    return (data.segments ?? [])
      .map((s) => (s.text ?? '').trim())
      .filter(Boolean)
      .join(' ')
      .trim();
  } catch {
    return '';
  }
}

/* ------------------------------------------------------------------ */
/* Conversion context                                                 */
/* ------------------------------------------------------------------ */

/** Formatting we noticed while converting, surfaced as transforms. */
interface ConvFlags {
  underline: number;
  checklists: number;
  tables: number;
  codeBlocks: number;
  formulas: number;
  highlights: number;
  colors: number;
  droppedStyling: number;
  noteLinks: number;
  taskBlocks: number;
  encrypted: number;
  transcripts: number;
  reminders: number;
  sourceUrls: number;
}

function emptyFlags(): ConvFlags {
  return {
    underline: 0, checklists: 0, tables: 0, codeBlocks: 0, formulas: 0,
    highlights: 0, colors: 0, droppedStyling: 0, noteLinks: 0, taskBlocks: 0,
    encrypted: 0, transcripts: 0, reminders: 0, sourceUrls: 0,
  };
}

interface ConvCtx {
  /** en-media MD5 hash -> blob placeholder token. */
  hashToToken: Map<string, string>;
  /** Blob token -> the resource's real filename and MIME. */
  blobs: Map<string, { data: Uint8Array; mime: string; name: string }>;
  flags: ConvFlags;
}

/**
 * Build a `[[target]]` / `[[target|label]]` note-link.
 *
 * The target goes through `noteLinkTarget` because an Evernote title really
 * can hold a pipe or a bracket, and writing one raw produces a link that
 * parses as a different target with different text. The sanitized target
 * still resolves: `noteLinkKey` compares it to the note's real title through
 * the same rule. Spec: packages/web/src/noteLinks.ts
 */
function noteLink(target: string, label: string): string {
  const t = noteLinkTarget(target);
  const l = label.replace(/[[\]]/g, '').trim();
  if (!t) return l;
  if (!l || l === t) return `[[${t}]]`;
  return `[[${t}|${l}]]`;
}

/* ------------------------------------------------------------------ */
/* ENML -> markdown                                                   */
/* ------------------------------------------------------------------ */

/**
 * Convert one note's ENML body to the markdown our editor stores.
 *
 * Evernote's newer editor expresses most of its block types as a plain
 * `<div>` carrying a CSS custom property, not as a distinct element, so
 * a tag-name switch alone would flatten code blocks, formulas, and
 * checklists into paragraphs. The style checks run before the switch for
 * that reason.
 *
 * Mapping:
 *   <h1>..<h6>                      -> # .. ######
 *   <b>/<strong>                    -> **bold**
 *   <i>/<em>                        -> *italic*
 *   <u>                             -> <u> (HTML passthrough, TipTap Underline)
 *   <s>/<del>/<strike>              -> ~~strike~~
 *   <sup>/<sub>                     -> <sup>/<sub> (HTML passthrough)
 *   span[--en-highlight] / <mark>   -> ==highlight==
 *   div[--en-codeblock]             -> fenced code block
 *   div[--en-formulablock]          -> $$latex$$
 *   div[--en-task-group]            -> dropped (see the file header)
 *   ul[--en-todo] + li[--en-checked]-> - [ ] / - [x]
 *   <en-todo checked>               -> - [ ] / - [x] (legacy inline form)
 *   <ul>/<ol>/<li>                  -> - / 1. (nesting preserved)
 *   <blockquote>                    -> >
 *   <hr>                            -> ---
 *   <table>                         -> GFM pipe table
 *   en-media image/*                -> ![](evatt:NNNNNN)
 *   en-media anything else          -> [name](evatt:NNNNNN), plus the
 *                                      transcript as a quote for audio
 *   a[evernote://view-note/…]       -> [[Target note title]]
 *   a[http…]                        -> [text](url)
 *   <en-crypt>                      -> a marker line; we cannot decrypt it
 *   color / font / alignment        -> dropped, inner text kept
 */
function enmlToMarkdown(bodyEl: Element, ctx: ConvCtx): string {
  function inlineOnly(text: string): string {
    return text.replace(/\s*\n+\s*/g, ' ').trim();
  }

  /**
   * Evernote writes one `<div>` per visual line inside a code block, so
   * the text content of the container would run every line together.
   * Reading the child divs individually keeps the line breaks. Blocks
   * that hold a single text run have no child divs and fall back to
   * textContent.
   */
  function blockText(el: Element): string {
    const lines = Array.from(el.children)
      .filter((c) => /^(div|p)$/i.test(c.tagName))
      .map((c) => c.textContent ?? '');
    if (lines.length === 0) return (el.textContent ?? '').replace(/\n+$/, '');
    return lines.join('\n').replace(/\n+$/, '');
  }

  /** Is this checklist item ticked? Absence of the property means no. */
  function isChecked(li: Element): boolean {
    const style = li.getAttribute('style') ?? '';
    if (/--en-checked:\s*true/i.test(style)) return true;
    return li.getAttribute('data-checked') === 'true';
  }

  function renderList(el: Element, indent: string): string {
    const style = el.getAttribute('style') ?? '';
    const isChecklist = /--en-todo:\s*true/i.test(style);
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
          child.nodeType === 1
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

  /**
   * Evernote tables have no header semantics in ENML - every cell is a
   * `<td>`, even the row the user styled as a header. GFM has no way to
   * express a headerless table, so one row has to become the header
   * whatever we do. We promote the first row rather than synthesizing a
   * blank one: an Evernote table's first row is nearly always its
   * header, and an empty header bar on every imported table is a worse
   * default than occasionally promoting a data row.
   */
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

    const header = pad(grid[0]!);
    const bodyRows = grid.slice(1).map(pad);

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

    // Internal note link. The GUID in the href is meaningless outside
    // Evernote - it is not exported on the target note - but Evernote
    // writes the target's title as the link text, so that is the handle
    // we resolve against.
    if (/^evernote:/i.test(href)) {
      const label = inner || 'Untitled';
      ctx.flags.noteLinks++;
      return noteLink(label, label);
    }

    const label = inner || href;
    if (!href) return label;
    return `[${label}](${href})`;
  }

  /** An `<en-media>` reference, resolved through the MD5 -> token map. */
  function renderMedia(el: Element, style: string): string {
    const hash = (el.getAttribute('hash') ?? '').toLowerCase();
    const mime = (el.getAttribute('type') ?? '').toLowerCase();
    const token = ctx.hashToToken.get(hash);

    // A reference with no matching <resource> is a note Evernote exported
    // while the attachment was still only in the cloud. Nothing to link.
    if (!token) return '';

    if (mime.startsWith('image/')) return `\n\n![](${token})\n\n`;

    const name = ctx.blobs.get(token)?.name ?? 'Attachment';
    let out = `\n\n[${name}](${token})\n\n`;

    // Voice notes carry Evernote's auto-transcription. It is real content
    // the user can search, so it comes across as a quote under the audio.
    const transcript = transcriptOf(style);
    if (transcript) {
      ctx.flags.transcripts++;
      out += `> ${transcript}\n\n`;
    }
    return out;
  }

  function walk(node: Node, indent: string): string {
    if (node.nodeType === 3) return node.textContent ?? '';
    if (node.nodeType !== 1) return '';

    const el = node as Element;
    const tag = el.tagName.toLowerCase();
    const style = el.getAttribute('style') ?? '';

    // The note's theme blob and any other hidden scaffolding. Evernote
    // parks a base64 `--en-chs` payload in a display:none div at the top
    // of every note written by the current editor.
    if (/display:\s*none/i.test(style)) return '';

    // Task blocks. Evernote exported a "Content not supported" notice in
    // place of the real tasks; there is nothing here to recover, so the
    // notice goes and the count is reported to the user instead.
    if (/--en-task-group:\s*true/i.test(style)) {
      ctx.flags.taskBlocks++;
      return '';
    }

    if (/--en-codeblock:\s*true/i.test(style)) {
      const code = blockText(el);
      if (!code.trim()) return '';
      ctx.flags.codeBlocks++;
      return `\n\`\`\`\n${code}\n\`\`\`\n\n`;
    }

    if (/--en-formulablock:\s*true/i.test(style)) {
      const src = blockText(el).trim();
      if (!src) return '';
      ctx.flags.formulas++;
      return `\n$$${src}$$\n\n`;
    }

    if (/--en-highlight/i.test(style)) {
      const inner = Array.from(el.childNodes)
        .map((c) => walk(c, indent))
        .join('');
      if (!inner.trim()) return inner;
      ctx.flags.highlights++;
      return `==${inner.trim()}==`;
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

      case 'en-note':
        return children();

      case 'en-crypt':
        // Encrypted with a passphrase Evernote does not export. Leaving a
        // marker beats silently dropping a paragraph the user wrote.
        ctx.flags.encrypted++;
        return '\n`[encrypted text - decrypt it in Evernote and re-export]`\n\n';

      case 'h1':
      case 'h2':
      case 'h3':
      case 'h4':
      case 'h5':
      case 'h6': {
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
      case 'sup': {
        const inner = inlineOnly(children());
        return inner ? `<sup>${inner}</sup>` : '';
      }
      case 'sub': {
        const inner = inlineOnly(children());
        return inner ? `<sub>${inner}</sub>` : '';
      }
      case 'code': {
        const inner = inlineOnly(children());
        return inner ? `\`${inner}\`` : '';
      }

      case 'pre': {
        const code = (el.textContent ?? '').replace(/\n+$/, '');
        if (!code.trim()) return '';
        ctx.flags.codeBlocks++;
        return `\n\`\`\`\n${code}\n\`\`\`\n\n`;
      }

      case 'br':
        return '\n';

      case 'hr':
        return '\n---\n\n';

      case 'img': {
        if (el.hasAttribute('data-en-media')) return renderMedia(el, style);
        const src = el.getAttribute('src') ?? '';
        const alt = (el.getAttribute('alt') ?? '').replace(/[[\]]/g, '');
        return src ? `\n\n![${alt}](${src})\n\n` : '';
      }

      case 'input': {
        // Legacy inline checkbox: `<en-todo checked="true"/>text`. The
        // marker is emitted here and the sibling text follows it on the
        // same line, which is exactly the shape a task line needs.
        if (!el.hasAttribute('data-en-todo')) return '';
        ctx.flags.checklists++;
        const checked = /^(true|checked)$/i.test(
          el.getAttribute('checked') ?? ''
        );
        return checked ? '- [x] ' : '- [ ] ';
      }

      case 'div':
      case 'p': {
        const inner = children();
        if (!inner.trim()) return '\n';
        if (/text-align|padding-left|margin-left/i.test(style)) {
          ctx.flags.droppedStyling++;
        }
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

      case 'a':
        return renderAnchor(el, indent);

      case 'font':
      case 'span':
      default: {
        const inner = children();
        if (!inner.trim()) return inner;

        // Text color survives. The editor stores it as exactly this inline
        // span (TextStyleMarkdown in Editor.tsx), and Markdown({html:true})
        // hands the raw tag back to ProseMirror's DOMParser on load, which
        // rebuilds the TextStyle mark. Only span and font are checked: a
        // color on a block element would need the span to wrap that block's
        // whole markdown, and Evernote does not put it there anyway.
        if (tag === 'span' || tag === 'font') {
          const color = colorOf(el, style);
          if (color) {
            ctx.flags.colors++;
            // Push the surrounding whitespace outside the span, the way the
            // editor's own serializer does (expelEnclosingWhitespace), so a
            // trailing space inside the tag cannot weld two words together.
            const [, lead = '', body = '', trail = ''] =
              inner.match(/^(\s*)([\s\S]*?)(\s*)$/) ?? [];
            return `${lead}<span style="color: ${color}">${body}</span>${trail}`;
          }
        }

        if (/font-size|font-family|(?<!-)color\s*:|background-color/i.test(style)) {
          ctx.flags.droppedStyling++;
        }
        return inner;
      }
    }
  }

  const md = Array.from(bodyEl.childNodes)
    .map((c) => walk(c, ''))
    .join('');

  return (
    md
      // Evernote pads with non-breaking spaces where it wants visual
      // spacing. They are invisible in the editor but would survive into
      // the stored markdown as U+00A0, where they break word wrapping and
      // any later search on the text.
      .replace(/ /g, ' ')
      .replace(/[ \t]+\n/g, '\n')
      .replace(/\n{3,}/g, '\n\n')
      // The legacy inline checkbox is one `<div>` per item, and every
      // `<div>` becomes its own paragraph, so a run of them would come out
      // as N single-item task lists instead of one list of N. Pulling the
      // adjacent lines together is enough for tiptap-markdown to parse them
      // as one. The lookahead leaves the blank line before whatever follows
      // the run, so the paragraph after a checklist is not swallowed into it.
      .replace(/^([-*+] \[[ xX]\][^\n]*)\n\n(?=[-*+] \[[ xX]\])/gm, '$1\n')
      .trim()
  );
}

/* ------------------------------------------------------------------ */
/* ENEX parsing                                                       */
/* ------------------------------------------------------------------ */

/**
 * Split an ENEX document into its `<note>` … `</note>` chunks.
 *
 * A whole-file XML parse would hold the entire export - including every
 * base64 attachment, decoded into DOM text nodes - in memory at once. A
 * real Evernote account runs to gigabytes. Scanning for the boundaries
 * and parsing one note at a time keeps the peak at a single note.
 *
 * The delimiters are unambiguous: ENML's own root is `<en-note>`, whose
 * open and close tags contain neither `<note>` nor `</note>` as
 * substrings, so a CDATA body can never produce a false boundary.
 */
function splitNotes(xml: string): string[] {
  const chunks: string[] = [];
  let from = 0;
  for (;;) {
    const start = xml.indexOf('<note>', from);
    if (start === -1) break;
    const end = xml.indexOf('</note>', start);
    if (end === -1) break;
    chunks.push(xml.slice(start, end + '</note>'.length));
    from = end + '</note>'.length;
  }
  return chunks;
}

/** One `<resource>` from an ENEX note. */
interface EnexResource {
  data: Uint8Array;
  mime: string;
  name: string;
}

interface EnexNote {
  title: string;
  enml: string;
  tags: string[];
  createdAt: string | null;
  updatedAt: string | null;
  sourceUrl: string;
  reminderTime: string | null;
  reminderDone: string | null;
  reminderOrder: string | null;
  resources: EnexResource[];
}

/**
 * Parse one `<note>` chunk.
 *
 * XML mode, not HTML mode: the ENML body arrives inside a CDATA section,
 * and the HTML parser turns CDATA into a bogus comment, which would
 * discard every note's content. The chunk is small (one note) and
 * self-contained, so a parse failure costs one note rather than the file.
 */
function parseNoteChunk(chunk: string): EnexNote | null {
  const doc = new DOMParser().parseFromString(chunk, 'application/xml');
  if (doc.querySelector('parsererror')) return null;
  const note = doc.documentElement;
  if (!note) return null;

  const text = (sel: string): string =>
    (note.querySelector(sel)?.textContent ?? '').trim();

  const attrs = note.querySelector('note-attributes');
  const attr = (name: string): string =>
    (attrs?.querySelector(name)?.textContent ?? '').trim();

  const resources: EnexResource[] = [];
  for (const res of Array.from(note.querySelectorAll('resource'))) {
    const dataEl = res.querySelector('data');
    const raw = dataEl?.textContent ?? '';
    if (!raw.trim()) continue;
    let data: Uint8Array;
    try {
      data = decodeBase64(raw);
    } catch {
      continue;
    }
    if (data.length === 0) continue;
    const mime = (res.querySelector('mime')?.textContent ?? '').trim()
      || 'application/octet-stream';
    const fileName = (
      res.querySelector('resource-attributes > file-name')?.textContent ?? ''
    ).trim();
    resources.push({
      data,
      mime,
      name: fileName || `attachment.${extFromMime(mime)}`,
    });
  }

  return {
    title: text('title'),
    enml: (note.querySelector('content')?.textContent ?? '').trim(),
    tags: Array.from(note.querySelectorAll('tag'))
      .map((t) => normalizeTag(t.textContent ?? ''))
      .filter(Boolean),
    createdAt: parseEnexDate(text('created')),
    updatedAt: parseEnexDate(text('updated')),
    sourceUrl: attr('source-url'),
    reminderTime: parseEnexDate(attr('reminder-time')),
    reminderDone: parseEnexDate(attr('reminder-done-time')),
    reminderOrder: attr('reminder-order') || null,
    resources,
  };
}

/* ------------------------------------------------------------------ */
/* File reading                                                       */
/* ------------------------------------------------------------------ */

/** An .enex document plus the notebook name we derived from its filename. */
interface EnexFile {
  notebook: string;
  xml: string;
}

async function readInput(
  file: File,
  onProgress?: (msg: string) => void
): Promise<EnexFile[]> {
  const name = file.name.toLowerCase();

  if (ENEX_EXT.test(name)) {
    onProgress?.('Reading export...');
    return [{ notebook: notebookName(file.name), xml: await file.text() }];
  }

  if (!name.endsWith('.zip')) {
    throw new Error(
      'Unrecognized file. Export from Evernote as ENEX (.enex), or zip several .enex files together.'
    );
  }

  onProgress?.('Reading zip...');
  const zip = await JSZip.loadAsync(file);
  const entries = Object.entries(zip.files).filter(
    ([path, entry]) => !entry.dir && !shouldSkip(path) && ENEX_EXT.test(path)
  );

  if (entries.length === 0) {
    const hasHtml = Object.keys(zip.files).some((p) => /\.html?$/i.test(p));
    throw new Error(
      hasHtml
        ? 'This zip holds Evernote\'s web page export, which cannot carry attachments properly. Re-export from Evernote and pick "ENEX format (.enex)".'
        : 'No .enex files found in this zip. Export from Evernote and pick "ENEX format (.enex)".'
    );
  }

  const out: EnexFile[] = [];
  for (const [path, entry] of entries) {
    out.push({ notebook: notebookName(path), xml: await zipEntryText(entry) });
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* Public importer                                                    */
/* ------------------------------------------------------------------ */

export async function parseEvernote(
  file: File,
  onProgress?: (msg: string) => void
): Promise<ParsedImport> {
  const files = await readInput(file, onProgress);

  const flags = emptyFlags();
  const blobs = new Map<string, { data: Uint8Array; mime: string; name: string }>();
  const notes: ImportedNote[] = [];
  const plural = (n: number) => (n === 1 ? '' : 's');

  // Several .enex files means several notebooks, and Evernote names each
  // export after its notebook. One file is one notebook too, so it gets a
  // folder either way - the name is information the user chose to keep.
  const { folders, dirToFolderId } = buildFolderTree(
    files.map((f) => f.notebook).filter(Boolean)
  );

  let blobBytes = 0;
  let imageCount = 0;
  let attachmentCount = 0;
  let malformed = 0;
  let blobIndex = 0;
  let seen = 0;

  for (const enex of files) {
    const chunks = splitNotes(enex.xml);
    if (chunks.length === 0 && enex.xml.trim()) malformed++;

    for (const chunk of chunks) {
      seen++;
      const parsed = parseNoteChunk(chunk);
      if (!parsed) {
        malformed++;
        continue;
      }

      // Attachments first: the body conversion resolves en-media through
      // the hash map this fills.
      const hashToToken = new Map<string, string>();
      for (const res of parsed.resources) {
        const token = blobToken(blobIndex++);
        hashToToken.set(md5hex(res.data), token);
        blobs.set(token, res);
      }

      const ctx: ConvCtx = { hashToToken, blobs, flags };
      const doc = new DOMParser().parseFromString(
        normalizeEnml(parsed.enml),
        'text/html'
      );
      let body = enmlToMarkdown(doc.body, ctx);

      // A note-level reminder is the closest thing Evernote has to a task
      // we can actually import, so it leads the note as one.
      if (parsed.reminderTime || parsed.reminderOrder) {
        const done = Boolean(parsed.reminderDone);
        const due = parsed.reminderTime
          ? ` (due ${dueLabel(parsed.reminderTime)})`
          : '';
        const label = parsed.title.trim() || 'Reminder';
        flags.reminders++;
        body = `- [${done ? 'x' : ' '}] ${label}${due}\n\n${body}`;
      }

      if (parsed.sourceUrl) {
        flags.sourceUrls++;
        body = `${body}\n\nSource: ${parsed.sourceUrl}`;
      }

      body = linkifyMarkdown(body.trim());

      const fallback = new Date().toISOString();
      const createdAt = parsed.createdAt ?? parsed.updatedAt ?? fallback;
      const note: ImportedNote = {
        title: parsed.title,
        body,
        tags: parsed.tags,
        createdAt,
        updatedAt: parsed.updatedAt ?? createdAt,
      };

      if (enex.notebook) {
        note.folderId = dirToFolderId.get(enex.notebook) ?? null;
        note.folderPath = [enex.notebook];
      }
      notes.push(note);

      if (seen % 25 === 0) onProgress?.(`Parsed ${seen} notes...`);
    }
  }

  if (notes.length === 0) {
    throw new Error(
      'No notes found in this export. Make sure you exported from Evernote as "ENEX format (.enex)".'
    );
  }

  // Only ship blobs the notes actually reference. An en-media whose
  // resource never resolved leaves an orphan that would burn quota with
  // no way to reach it.
  const referenced = new Map<string, { data: Uint8Array; mime: string; name: string }>();
  for (const [token, blob] of blobs) {
    if (!notes.some((n) => n.body.includes(token))) continue;
    referenced.set(token, blob);
    blobBytes += blob.data.length;
    if (blob.mime.startsWith('image/')) imageCount++;
    else attachmentCount++;
  }

  /* ---------------- warnings & transforms ---------------- */

  const warnings: string[] = [];
  if (flags.taskBlocks > 0) {
    warnings.push(
      `${flags.taskBlocks} task block${plural(flags.taskBlocks)} could not be imported. Evernote's .enex export replaces tasks with a "Content not supported" placeholder - the titles, due dates, and completion states are not in the file. Checklists are unaffected and came across as task lists.`
    );
  }
  if (flags.encrypted > 0) {
    warnings.push(
      `${flags.encrypted} encrypted text block${plural(flags.encrypted)} stayed encrypted. Decrypt them in Evernote and export again to bring the text across.`
    );
  }
  if (malformed > 0) {
    warnings.push(
      `${malformed} note${plural(malformed)} could not be read and ${malformed === 1 ? 'was' : 'were'} skipped. The file may be truncated.`
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
  if (flags.reminders > 0) {
    transforms.push(
      `Turned ${flags.reminders} note reminder${plural(flags.reminders)} into a task at the top of the note.`
    );
  }
  if (flags.tables > 0) {
    transforms.push(
      `Preserved ${flags.tables} table${plural(flags.tables)}, using the first row as the header.`
    );
  }
  if (flags.codeBlocks > 0) {
    transforms.push(`Preserved ${flags.codeBlocks} code block${plural(flags.codeBlocks)}.`);
  }
  if (flags.formulas > 0) {
    transforms.push(
      `Converted ${flags.formulas} formula block${plural(flags.formulas)} into math.`
    );
  }
  if (flags.highlights > 0) {
    transforms.push('Preserved highlighted text.');
  }
  if (flags.colors > 0) {
    transforms.push(
      `Kept the text color on ${flags.colors} run${plural(flags.colors)} of text.`
    );
  }
  if (flags.underline > 0) {
    transforms.push('Preserved underline formatting.');
  }
  if (flags.transcripts > 0) {
    transforms.push(
      `Kept the transcript on ${flags.transcripts} voice note${plural(flags.transcripts)}.`
    );
  }
  if (flags.sourceUrls > 0) {
    transforms.push(
      `Kept the source URL on ${flags.sourceUrls} web clip${plural(flags.sourceUrls)}.`
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
  if (flags.droppedStyling > 0) {
    transforms.push(
      'Dropped custom fonts, text colors, and alignment, keeping the text.'
    );
  }
  transforms.push('Made bare URLs clickable.');

  const uniqueTags = new Set(notes.flatMap((n) => n.tags));

  return {
    notes,
    warnings,
    transforms,
    stats: {
      totalNotes: notes.length,
      emptyNotes: notes.filter((n) => !n.title.trim() && !n.body.trim()).length,
      untaggedNotes: notes.filter((n) => n.tags.length === 0).length,
      uniqueTags: uniqueTags.size,
    },
    source: 'evernote',
    blobBytes,
    blobs: referenced.size > 0 ? referenced : undefined,
    folders,
  };
}
