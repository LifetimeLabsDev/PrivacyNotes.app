import { noteLinkTarget } from '../noteLinks';
import type { ImportBlob } from './types';

/**
 * Standard Notes "Super" note -> the markdown our editor stores.
 *
 * A Super note's `content.text` is a serialized Lexical editor state:
 * `{"root":{"type":"root","children":[...]}}`. The node types below are the
 * set Standard Notes registers (`SuperEditor/Lexical/Nodes/AllNodes.ts` in
 * their app repository), and every field read here is one its `exportJSON`
 * writes. Spec: ops/docs/plans/standard-notes-super.md
 *
 * Mapping:
 *   paragraph / heading / quote          -> markdown; an aligned block is
 *                                           written as HTML, as our editor does
 *   text format bits                     -> ** * ~~ ` == <u> <sub> <sup>
 *   text style color / font-size / font-family -> <span style>
 *   text style background-color          -> <mark style> (a colored highlight)
 *   list bullet / number / check         -> - / 1. / - [ ] (nesting kept)
 *   code                                 -> fenced block with its language
 *   table                                -> pipe table, first row as header
 *   collapsible-container                -> a callout, folded when closed
 *   link / autolink                      -> [text](url)
 *   hashtag                              -> text kept, and a tag on the note
 *   snbubble (a link to another item)    -> [[Note title]]
 *   inline-file (a data: URI)            -> an imported image or attachment
 *   unencrypted-image                    -> ![alt](url)
 *   youtube / tweet                      -> a link to the video or post
 *   snfile (an uploaded file)            -> a marker line; a backup holds the
 *                                           file's key, never its bytes
 */

type LexNode = {
  type?: string;
  children?: LexNode[];
  text?: string;
  format?: number | string;
  style?: string;
  tag?: string;
  listType?: string;
  start?: number;
  checked?: boolean;
  language?: string | null;
  url?: string;
  open?: boolean;
  headerState?: number;
  src?: string;
  alt?: string;
  mimeType?: string;
  fileName?: string;
  fileUuid?: string;
  itemUuid?: string;
  videoID?: string;
  id?: string;
};

/** Another item in the same backup, as a Super note can point at it. */
export type SnLinkedItem =
  | { kind: 'note'; title: string }
  | { kind: 'tag'; title: string }
  | { kind: 'file'; name: string };

export interface SuperContext {
  items: Map<string, SnLinkedItem>;
  /** Shared across the whole import, so every blob key is unique. */
  blobs: Map<string, ImportBlob>;
}

export interface SuperResult {
  markdown: string;
  hashtags: string[];
  /** Uploaded files the note embedded, which the backup cannot carry. */
  missingFiles: number;
}

// Lexical's text format bitmask.
const BOLD = 1;
const ITALIC = 2;
const STRIKE = 4;
const UNDERLINE = 8;
const CODE = 16;
const SUBSCRIPT = 32;
const SUPERSCRIPT = 64;
const HIGHLIGHT = 128;

const ALIGNED = new Set(['center', 'right', 'justify']);

function parseState(text: string): LexNode | null {
  const trimmed = text.trim();
  if (!trimmed.startsWith('{')) return null;
  try {
    const root = (JSON.parse(trimmed) as { root?: LexNode })?.root;
    return root?.type === 'root' && Array.isArray(root.children) ? root : null;
  } catch {
    return null;
  }
}

/** Returns null when the text is not a Super state; the caller keeps it verbatim. */
export function superToMarkdown(text: string, ctx: SuperContext): SuperResult | null {
  const root = parseState(text);
  if (!root) return null;

  const hashtags: string[] = [];
  let missingFiles = 0;

  function kids(node: LexNode): LexNode[] {
    return Array.isArray(node.children) ? node.children : [];
  }

  function addBlob(src: string, mimeType: string | undefined, fileName: string | undefined): string | null {
    const m = /^data:([^;,]*)((?:;[^;,]*)*),(.*)$/s.exec(src);
    if (!m) return null;
    let data: Uint8Array;
    try {
      if (m[2]!.includes(';base64')) {
        const bin = atob(m[3]!.replace(/\s/g, ''));
        data = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) data[i] = bin.charCodeAt(i);
      } else {
        data = new TextEncoder().encode(decodeURIComponent(m[3]!));
      }
    } catch {
      return null;
    }
    const key = `snatt:${String(ctx.blobs.size + 1).padStart(6, '0')}`;
    const mime = mimeType || m[1] || 'application/octet-stream';
    ctx.blobs.set(key, { data, mime, name: fileName || 'attachment' });
    return key;
  }

  /* ---------------- inline ---------------- */

  function escapeMd(s: string): string {
    return s
      .replace(/[\\`*[\]<~$|]/g, '\\$&')
      .replace(/==/g, '=\\=')
      .replace(/&(?=#?\w+;)/g, '&amp;')
      // An underscore inside a word never starts emphasis; one at a word edge can.
      .replace(/(^|[^\p{L}\p{N}])_|_(?=$|[^\p{L}\p{N}])/gu, (hit) => hit.replace('_', '\\_'));
  }

  function escapeHtml(s: string): string {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  /** The inline CSS our editor keeps, split into its text-style and highlight halves. */
  function styleParts(style: string | undefined): { span: string; mark: string } {
    const span: string[] = [];
    let mark = '';
    for (const decl of (style ?? '').split(';')) {
      const i = decl.indexOf(':');
      if (i < 0) continue;
      const prop = decl.slice(0, i).trim().toLowerCase();
      const value = decl.slice(i + 1).trim().replace(/"/g, '&quot;');
      if (!value) continue;
      if (prop === 'color' || prop === 'font-size' || prop === 'font-family') span.push(`${prop}: ${value}`);
      else if (prop === 'background-color') mark = value;
    }
    return { span: span.join('; '), mark };
  }

  function linkTarget(url: string): string {
    return url.trim().replace(/ /g, '%20').replace(/\(/g, '%28').replace(/\)/g, '%29');
  }

  function bubble(uuid: string | undefined): string {
    const item = uuid ? ctx.items.get(uuid) : undefined;
    if (!item) return '';
    if (item.kind === 'tag') return `#${item.title.replace(/\s+/g, '-')}`;
    if (item.kind === 'file') return escapeMd(item.name);
    const target = noteLinkTarget(item.title);
    return target ? `[[${target}]]` : '';
  }

  function textMd(node: LexNode): string {
    const raw = node.text ?? '';
    if (!raw) return '';
    const format = typeof node.format === 'number' ? node.format : 0;
    if (format & CODE) {
      const run = Math.max(0, ...(raw.match(/`+/g) ?? []).map((r) => r.length));
      const fence = '`'.repeat(run + 1);
      const pad = raw.startsWith('`') || raw.endsWith('`') ? ' ' : '';
      return `${fence}${pad}${raw}${pad}${fence}`;
    }
    // Emphasis cannot open or close on whitespace, so it stays outside the markers.
    const [, lead, core, trail] = /^(\s*)([\s\S]*?)(\s*)$/.exec(raw)!;
    if (!core) return raw;
    let out = escapeMd(core!);
    if (format & SUBSCRIPT) out = `<sub>${out}</sub>`;
    if (format & SUPERSCRIPT) out = `<sup>${out}</sup>`;
    if (format & UNDERLINE) out = `<u>${out}</u>`;
    const { span, mark } = styleParts(node.style);
    if (mark) out = `<mark style="background-color: ${mark}">${out}</mark>`;
    else if (format & HIGHLIGHT) out = `==${out}==`;
    if (format & STRIKE) out = `~~${out}~~`;
    if (format & ITALIC) out = `*${out}*`;
    if (format & BOLD) out = `**${out}**`;
    if (span) out = `<span style="${span}">${out}</span>`;
    return lead + out + trail;
  }

  function textHtml(node: LexNode): string {
    const format = typeof node.format === 'number' ? node.format : 0;
    let out = escapeHtml(node.text ?? '');
    if (!out) return '';
    if (format & CODE) out = `<code>${out}</code>`;
    if (format & SUBSCRIPT) out = `<sub>${out}</sub>`;
    if (format & SUPERSCRIPT) out = `<sup>${out}</sup>`;
    if (format & UNDERLINE) out = `<u>${out}</u>`;
    const { span, mark } = styleParts(node.style);
    if (mark) out = `<mark style="background-color: ${mark}">${out}</mark>`;
    else if (format & HIGHLIGHT) out = `<mark>${out}</mark>`;
    if (format & STRIKE) out = `<s>${out}</s>`;
    if (format & ITALIC) out = `<em>${out}</em>`;
    if (format & BOLD) out = `<strong>${out}</strong>`;
    if (span) out = `<span style="${span}">${out}</span>`;
    return out;
  }

  /**
   * `html` renders for an aligned block, which our editor stores as HTML.
   * `cell` renders for a table cell, where a line break has to be `<br>`.
   */
  function inline(nodes: LexNode[], mode: 'md' | 'html' | 'cell'): string {
    let out = '';
    for (const n of nodes) {
      switch (n.type) {
        case 'text':
        case 'code-highlight':
          out += mode === 'html' ? textHtml(n) : textMd(n);
          break;
        case 'hashtag': {
          const t = n.text ?? '';
          const tag = t.replace(/^#/, '');
          if (tag) hashtags.push(tag);
          out += mode === 'html' ? escapeHtml(t) : t;
          break;
        }
        case 'linebreak':
          out += mode === 'md' ? '\\\n' : '<br>';
          break;
        case 'tab':
          out += ' ';
          break;
        case 'link':
        case 'autolink': {
          const url = n.url ?? '';
          const label = inline(kids(n), mode);
          if (!url) out += label;
          else if (mode === 'html') out += `<a href="${escapeHtml(url)}">${label}</a>`;
          else if (label === escapeMd(url) && !/[\s<>]/.test(url)) out += `<${url}>`;
          else out += `[${label || escapeMd(url)}](${linkTarget(url)})`;
          break;
        }
        case 'snbubble':
          out += bubble(n.itemUuid);
          break;
        case 'unencrypted-image':
        case 'inline-file':
        case 'snfile':
        case 'youtube':
        case 'tweet':
          out += embed(n);
          break;
        default:
          out += inline(kids(n), mode);
      }
    }
    return out;
  }

  /* ---------------- blocks ---------------- */

  /** Keep a paragraph that merely LOOKS like markdown syntax from becoming it. */
  function guardLineStart(s: string): string {
    if (/^\d+[.)](\s|$)/.test(s)) return s.replace(/[.)]/, '\\$&');
    if (/^(#{1,6}(\s|$)|>|[-+](\s|$))/.test(s)) return `\\${s}`;
    return s;
  }

  function aligned(node: LexNode): string | null {
    return typeof node.format === 'string' && ALIGNED.has(node.format) ? node.format : null;
  }

  function embed(n: LexNode): string {
    switch (n.type) {
      case 'unencrypted-image':
        return n.src ? `![${(n.alt ?? '').replace(/[[\]]/g, '')}](${linkTarget(n.src)})` : '';
      case 'inline-file': {
        const name = (n.fileName ?? '').replace(/[[\]]/g, '');
        const key = n.src ? addBlob(n.src, n.mimeType, n.fileName) : null;
        if (!key) return escapeMd(name);
        return (n.mimeType ?? '').startsWith('image/') ? `![${name}](${key})` : `[${name || 'attachment'}](${key})`;
      }
      case 'snfile': {
        missingFiles++;
        const item = n.fileUuid ? ctx.items.get(n.fileUuid) : undefined;
        const name = item?.kind === 'file' ? item.name : 'file';
        return `\`[attachment: ${name.replace(/`/g, "'")} - not in the Standard Notes backup]\``;
      }
      case 'youtube':
        return n.videoID ? `[YouTube video](https://www.youtube.com/watch?v=${encodeURIComponent(n.videoID)})` : '';
      case 'tweet':
        return n.id ? `[Post on X](https://x.com/i/status/${encodeURIComponent(n.id)})` : '';
      default:
        return '';
    }
  }

  function list(node: LexNode, indent: string): string[] {
    const lines: string[] = [];
    const type = node.listType ?? 'bullet';
    let number = typeof node.start === 'number' ? node.start : 1;
    let childIndent = indent + '  ';
    for (const item of kids(node)) {
      const own = kids(item).filter((c) => c.type !== 'list');
      const nested = kids(item).filter((c) => c.type === 'list');
      if (own.length > 0 || nested.length === 0) {
        const marker =
          type === 'number' ? `${number++}. ` : type === 'check' ? `- [${item.checked ? 'x' : ' '}] ` : '- ';
        childIndent = indent + ' '.repeat(type === 'number' ? marker.length : 2);
        const text = inline(own, 'md').replace(/\n/g, `\n${childIndent}`);
        lines.push(`${indent}${marker}${text}`.trimEnd());
      }
      for (const sub of nested) lines.push(...list(sub, childIndent));
    }
    return lines;
  }

  function table(node: LexNode): string {
    const rows = kids(node).map((row) =>
      kids(row).map((cell) =>
        kids(cell)
          .map((c) => (c.type === 'paragraph' || c.type === 'heading' ? inline(kids(c), 'cell') : blocks([c]).replace(/\n+/g, '<br>')))
          .filter(Boolean)
          .join('<br>')
          .replace(/\n/g, '<br>')
          .trim(),
      ),
    );
    if (rows.length === 0) return '';
    const width = Math.max(1, ...rows.map((r) => r.length));
    const line = (cells: string[]) =>
      `| ${Array.from({ length: width }, (_, i) => cells[i] ?? '').join(' | ')} |`;
    return [line(rows[0]!), `|${' --- |'.repeat(width)}`, ...rows.slice(1).map(line)].join('\n');
  }

  function code(node: LexNode): string {
    const body = kids(node)
      .map((c) => (c.type === 'linebreak' ? '\n' : c.type === 'tab' ? '\t' : c.text ?? ''))
      .join('');
    const run = Math.max(2, ...(body.match(/`{3,}/g) ?? []).map((r) => r.length));
    const fence = '`'.repeat(run + 1);
    return `${fence}${node.language ?? ''}\n${body}\n${fence}`;
  }

  function block(node: LexNode): string {
    switch (node.type) {
      case 'paragraph': {
        const align = aligned(node);
        if (align) {
          const html = inline(kids(node), 'html');
          return html ? `<p style="text-align: ${align}">${html}</p>` : '&nbsp;';
        }
        const text = inline(kids(node), 'md');
        return text.trim() ? guardLineStart(text) : '&nbsp;';
      }
      case 'heading': {
        const level = Math.min(6, Math.max(1, Number((node.tag ?? 'h1').slice(1)) || 1));
        const align = aligned(node);
        if (align) return `<h${level} style="text-align: ${align}">${inline(kids(node), 'html')}</h${level}>`;
        return `${'#'.repeat(level)} ${inline(kids(node), 'md')}`;
      }
      case 'quote':
        return inline(kids(node), 'md')
          .split('\n')
          .map((l) => `> ${l}`.trimEnd())
          .join('\n');
      case 'list':
        return list(node, '').join('\n');
      case 'code':
        return code(node);
      case 'horizontalrule':
        return '---';
      case 'table':
        return table(node);
      case 'collapsible-container': {
        const title = kids(node).find((c) => c.type === 'collapsible-title');
        const content = kids(node).find((c) => c.type === 'collapsible-content');
        const titleText = title ? inline(kids(title), 'md').replace(/\s*\\\n\s*/g, ' ') : '';
        const body = content ? blocks(kids(content)) : '';
        const lines = [`> [!note]${node.open === false ? '-' : '+'} ${titleText}`.trimEnd()];
        if (body) lines.push(...body.split('\n').map((l) => (l ? `> ${l}` : '>')));
        return lines.join('\n');
      }
      case 'unencrypted-image':
      case 'inline-file':
      case 'snfile':
      case 'youtube':
      case 'tweet':
        return embed(node);
      default: {
        // A node type this converter does not know: keep whatever text it holds.
        const children = kids(node);
        if (children.length === 0) return node.text ? escapeMd(node.text) : '';
        const blockish = children.some((c) => Array.isArray(c.children) && c.type !== 'link' && c.type !== 'autolink');
        return blockish ? blocks(children) : inline(children, 'md');
      }
    }
  }

  function blocks(nodes: LexNode[]): string {
    const out = nodes.map(block).filter((b) => b !== '');
    while (out.length > 0 && out[out.length - 1] === '&nbsp;') out.pop();
    while (out.length > 0 && out[0] === '&nbsp;') out.shift();
    return out.join('\n\n');
  }

  return { markdown: blocks(kids(root)), hashtags, missingFiles };
}
