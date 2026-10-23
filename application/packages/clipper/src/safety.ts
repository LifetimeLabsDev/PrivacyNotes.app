/**
 * The last fence before a clip becomes a note: parse the Markdown the way
 * the note editor does (markdown-it with raw HTML on) and accept it only
 * when it holds no HTML, no picture but a stored one or a picture token, and
 * no link to a scheme other than http, https or mailto. A page that slips
 * something past the conversion rules gets its text only, every Markdown
 * character escaped, so nothing in it can be read as markup.
 * Spec: ops/docs/archive/web-clipper-stage1.md (section 7, traps)
 */
import MarkdownIt from 'markdown-it';
import type Token from 'markdown-it/lib/token.mjs';

let parser: MarkdownIt | null = null;

function md(): MarkdownIt {
  parser ??= new MarkdownIt({ html: true, breaks: true, linkify: false });
  return parser;
}

const PICTURE = /^(?:pn-clip:\d+|pn:img\/[0-9a-f-]{36})$/;
const LINK = /^(?:https?:|mailto:)/i;

/** Whether `markdown` reads, in the editor, as nothing but text, stored or
 *  token pictures and web links. */
export function isSafeMarkdown(markdown: string): boolean {
  const walk = (tokens: Token[]): boolean => {
    for (const t of tokens) {
      if (t.type === 'html_block' || t.type === 'html_inline') return false;
      if (t.type === 'image' && !PICTURE.test(t.attrGet('src') ?? '')) return false;
      if (t.type === 'link_open' && !LINK.test(t.attrGet('href') ?? '')) return false;
      if (t.children && !walk(t.children)) return false;
    }
    return true;
  };
  try {
    return walk(md().parse(markdown, {}));
  } catch {
    return false;
  }
}

/** `text` as Markdown that is only text: every ASCII punctuation character
 *  escaped, paragraphs kept. */
export function plainMarkdown(text: string): string {
  return text
    .split(/\n\s*\n/)
    .map((block) => block.replace(/\s+/g, ' ').trim())
    .filter(Boolean)
    .map((block) => block.replace(/[!-/:-@[-`{-~]/g, (c) => `\\${c}`))
    .join('\n\n');
}
