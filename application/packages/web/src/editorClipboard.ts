import { Fragment, type Node as ProseMirrorNode } from '@tiptap/pm/model';

/**
 * The note's markdown, rewritten for the clipboard.
 *
 * The plain-text flavour of a copy is the lossy one. The HTML flavour beside
 * it carries the exact document, so this is what a reader sees when they paste
 * into something that is not a markdown editor at all, and its job is to look
 * like the screen they copied from. Three things stand between the file and
 * that, and each is a spelling the file needs and the screen does not.
 *
 * A hard break is written `\` in the file and two trailing spaces here. Both
 * are the same CommonMark break. The file keeps the backslash because a
 * trailing space is the one character every "trim whitespace on save" tool
 * eats, and a note in a Markdown folder is opened by other editors; the
 * clipboard takes the invisible spelling because most paste targets simply
 * print the backslash at the end of every line.
 *
 * An empty paragraph is written `&nbsp;`, the only way a file can record one,
 * and it arrives in a plain editor as those six literal characters. Here it
 * becomes a blank line, and a run of blank lines is capped at two so the gap
 * stays about the size it looked.
 *
 * A paragraph break is written as a blank line, and with the gap set to
 * nothing the screen has no blank line to show. So `tightParagraphs` joins two
 * adjacent paragraphs with a break instead, and the pasted text then has the
 * same line count as the note. Every other pair of blocks keeps the blank
 * line, which is why this walks the blocks rather than the string: a blank
 * line before a list, a heading or a code fence means something else.
 *
 * The accepted cost: what this writes says "lines" where the note says
 * "paragraphs", so a markdown reader lays out a tight copy as one paragraph
 * and a spacer paragraph is gone. Nothing a person sees moves, the stored note
 * is untouched, and a target that understands a document reads the HTML
 * flavour instead.
 */
export function markdownForClipboard(
  content: Fragment,
  serializeFile: (fragment: Fragment) => string,
  tightParagraphs: boolean,
  format: 'markdown' | 'plain' = 'markdown',
  render?: (markdown: string) => string,
): string {
  // A selection with no formatting has no markdown to carry, and every escape
  // the file needs would only change the text: a command, a key or a path
  // copies as it shows.
  if (format === 'plain') return plainTextForClipboard(content, tightParagraphs);
  if (unformatted(content)) return linesForClipboard(content, tightParagraphs);
  const serialize = render
    ? (fragment: Fragment) => dropNeedlessEscapes(serializeFile(fragment), render)
    : serializeFile;

  // A copy keeps every parent of the selection, so a command copied out of a
  // list item arrives as a list and pastes with a `- ` in front of it. A
  // selection inside one line of text copies that text and its inline marks,
  // never the block syntax around it, which the screen does not show either.
  // The line goes to the serializer as a paragraph, which writes its marks;
  // handed bare inline nodes it writes their text alone.
  const line = singleTextblock(content);
  if (line) {
    const paragraph = line.type.schema.nodes.paragraph!.create(null, line.content);
    const md = serialize(Fragment.from(paragraph));
    return tidyClipboardLines(md === EMPTY_PARAGRAPH_MARKDOWN ? '' : md);
  }

  const blocks: { node: ProseMirrorNode; md: string }[] = [];
  let at = 0;
  content.forEach((node) => {
    let md = serialize(content.cut(at, at + node.nodeSize));
    // A task list is stored loose, a blank line between tasks, because
    // tiptap-markdown's tight-list attribute covers bullets and numbers only.
    // The screen shows no gap, so the copy closes it where every task is one
    // line. The stored note keeps its form.
    if (node.type.name === 'taskList' && everyItemIsOneLine(node)) {
      md = md.replace(/\n\n(?=[ \t]*[-*+] \[[ xX]\] )/g, '\n');
    }
    // An empty paragraph is a blank line here, never its file spelling.
    blocks.push({ node, md: md === EMPTY_PARAGRAPH_MARKDOWN ? '' : md });
    at += node.nodeSize;
  });

  let joined = '';
  for (let i = 0; i < blocks.length; i++) {
    const cur = blocks[i]!;
    if (i > 0) {
      const prev = blocks[i - 1]!.node;
      const tight =
        tightParagraphs && prev.type.name === 'paragraph' && cur.node.type.name === 'paragraph';
      joined += tight ? '  \n' : '\n\n';
    }
    joined += cur.md;
  }
  return tidyClipboardLines(joined);
}

const UNESCAPED: Record<string, string> = { '&lt;': '<', '&gt;': '>', '&amp;': '&' };

/**
 * The file escapes every character that could read as syntax, wherever it
 * stands: a typed `2>1 _ ~` is saved as `2&gt;1 \_ \~`, and a paste target
 * that is not a markdown editor prints exactly that (GitHub #512). Here each
 * escape goes when the block reads back the same without it, judged by the
 * editor's own markdown parser (`render`), so the copy still loads as the
 * note it came from; one the text needs, such as the `\*` around a literal
 * `*word*`, stays. A `\~` stays wherever the block holds a second tilde and
 * one of its tildes follows text, because GitHub reads `~word~` as a strike
 * and this parser does not.
 */
function dropNeedlessEscapes(markdown: string, render: (markdown: string) => string): string {
  const expected = render(markdown);
  // A strike needs a tilde that can close it, and a closer stands right after
  // text. Two `~/` home paths after a space cannot strike anything, so their
  // escapes go (a pasted shell command broke on `\~`).
  const plain = markdown.replace(/\\~/g, '~');
  const tildes = /\S~/.test(plain) ? (plain.match(/~/g) ?? []).length : 0;
  let out = markdown;
  // Right to left, so a removal never moves a spot still to be tried.
  const spots = [...markdown.matchAll(/\\[!-/:-@[-`{-~]|&(?:lt|gt|amp);/g)].reverse();
  for (const spot of spots) {
    const escape = spot[0];
    if (escape === '\\~' && tildes > 1) continue;
    const at = spot.index;
    // A backslash at the end of a line is a hard break to the step after
    // this one (`tidyClipboardLines`), so an escaped one there stays escaped.
    if (escape === '\\\\' && /^\\*(?:\n|$)/.test(out.slice(at + 2))) continue;
    const tryOut = out.slice(0, at) + (UNESCAPED[escape] ?? escape[1]!) + out.slice(at + escape.length);
    if (render(tryOut) === expected) out = tryOut;
  }
  return out;
}

/**
 * The renderer `dropNeedlessEscapes` judges by: tiptap-markdown's own
 * markdown-it, which holds the editor's syntax (note-links, math, footnotes)
 * only once a parse has run its setup hooks. A note opened from the document
 * cache never parsed, so the first copy runs one. Rendering through
 * `parse()` every time is not an option: each call adds the hooks' rules
 * again.
 */
const primedParsers = new WeakSet<object>();
export function clipboardRenderer(parser: {
  parse(markdown: string): unknown;
  md: { render(markdown: string): string };
}): (markdown: string) => string {
  if (!primedParsers.has(parser)) {
    parser.parse('');
    primedParsers.add(parser);
  }
  return (markdown) => parser.md.render(markdown);
}

function everyItemIsOneLine(list: ProseMirrorNode): boolean {
  let ok = true;
  list.forEach((item) => {
    if (item.childCount !== 1 || !item.firstChild!.isTextblock) ok = false;
  });
  return ok;
}

/**
 * The plain-text part of a copy with the "Copied text: Plain text" setting:
 * the words of each block, one block per line, and no formatting character
 * at all. No heading, quote, bullet or task marker and no emphasis, which a
 * form field or a work tool prints as it is. A numbered list keeps its
 * numbers, because they carry the order. Blank lines follow the Markdown
 * copy: a gap between blocks, none between Compact paragraphs.
 * Spec: ops/docs/plans/paste-pictures.md (section 3.6)
 */
function plainTextForClipboard(content: Fragment, tightParagraphs: boolean): string {
  const line = singleTextblock(content);
  if (line) return plainInline(line);

  let out = '';
  let prev: ProseMirrorNode | null = null;
  content.forEach((node) => {
    const text = plainBlock(node, '');
    if (text === null) return;
    if (prev) {
      const tight = tightParagraphs && prev.type.name === 'paragraph' && node.type.name === 'paragraph';
      out += tight ? '\n' : '\n\n';
    }
    out += text;
    prev = node;
  });
  return out.replace(/\n{3,}/g, '\n\n').replace(/\s+$/, '');
}

/** The words of an inline run: a note-link writes its label, a formula its
 *  source, a hard break a new line. Text marks have no characters here. */
function plainInline(block: ProseMirrorNode): string {
  return block.textBetween(0, block.content.size, '\n', (leaf) => {
    if (leaf.type.name === 'hardBreak') return '\n';
    const attrs = leaf.attrs as { label?: string | null; target?: string; latex?: string };
    return attrs.label || attrs.target || attrs.latex || '';
  }).replace(/\u00a0/g, ' ');
}

/** One block as plain lines, or null for a block that has no words (a picture,
 *  a file, a rule). `indent` nests list items. */
function plainBlock(node: ProseMirrorNode, indent: string): string | null {
  const name = node.type.name;
  if (name === 'codeBlock') return node.textContent;
  if (name === 'blockMath') return (node.attrs as { latex?: string }).latex ?? '';
  if (node.isTextblock) return indent + plainInline(node);
  if (name === 'bulletList' || name === 'taskList' || name === 'orderedList') {
    const start = Number((node.attrs as { start?: number }).start ?? 1);
    const items: string[] = [];
    node.forEach((item, _offset, i) => {
      const prefix = name === 'orderedList' ? `${start + i}. ` : '';
      const parts: string[] = [];
      item.forEach((child, _o, j) => {
        const text = plainBlock(child, j === 0 ? indent : `${indent}  `);
        if (text !== null) parts.push(j === 0 ? text.replace(indent, indent + prefix) : text);
      });
      items.push(parts.join('\n'));
    });
    return items.join('\n');
  }
  if (name === 'table') {
    const rows: string[] = [];
    node.forEach((row) => {
      const cells: string[] = [];
      row.forEach((cell) => cells.push(cell.textContent.replace(/\s+/g, ' ').trim()));
      rows.push(indent + cells.join('\t'));
    });
    return rows.join('\n');
  }
  if (node.isLeaf || node.isAtom) return null;
  const parts: string[] = [];
  node.forEach((child) => {
    const text = plainBlock(child, indent);
    if (text !== null) parts.push(text);
  });
  return parts.join('\n');
}

/** The one textblock a fragment reduces to when every level above it holds a
 *  single child, or null when the fragment spans more than one block. */
/** The text of unformatted lines as the screen shows it: a hard break and a
 *  tight paragraph gap are one newline, a normal gap a blank line, and every
 *  empty paragraph keeps its line. */
function linesForClipboard(content: Fragment, tightParagraphs: boolean): string {
  const line = singleTextblock(content);
  if (line) return plainInline(line);
  const lines: string[] = [];
  content.forEach((node) => lines.push(plainInline(node)));
  return lines.join(tightParagraphs ? '\n' : '\n\n');
}

/** Plain paragraphs, or one line of any block, holding only unmarked text and
 *  line breaks. */
function unformatted(content: Fragment): boolean {
  const bare = (block: ProseMirrorNode) => {
    let plain = true;
    block.forEach((child) => {
      if (child.type.name === 'hardBreak') return;
      if (!child.isText || child.marks.length > 0) plain = false;
    });
    return plain;
  };
  const line = singleTextblock(content);
  if (line) return line.type.name !== 'codeBlock' && bare(line);
  let plain = content.childCount > 0;
  content.forEach((node) => {
    if (node.type.name !== 'paragraph' || !bare(node)) plain = false;
  });
  return plain;
}

function singleTextblock(content: Fragment): ProseMirrorNode | null {
  let node = content.childCount === 1 ? content.firstChild : null;
  while (node && !node.isTextblock) {
    node = node.childCount === 1 ? node.firstChild : null;
  }
  return node;
}

/** How ParagraphWithMarkdown writes a paragraph with nothing in it. */
const EMPTY_PARAGRAPH_MARKDOWN = '&nbsp;';

/**
 * The per-line half of the rewrite above: backslash breaks, stray `&nbsp;`
 * from a paragraph nested inside a list item or a callout, and blank runs.
 *
 * Fenced code is left alone throughout, because a shell line continuation
 * ends in exactly the same two characters as a hard break and is the author's
 * own text. Outside a fence, the parity of a trailing backslash run is what
 * separates a break from an escape, since the serializer writes `\\` for a
 * backslash the reader typed. A backslash on the final line ends no line and
 * is therefore not a break either.
 */
function tidyClipboardLines(markdown: string): string {
  const lines = markdown.split('\n');
  const out: string[] = [];
  let fence = '';
  let blanks = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const mark = /^ {0,3}(`{3,}|~{3,})/.exec(line)?.[1];
    if (mark) {
      if (!fence) fence = mark;
      else if (mark[0] === fence[0] && mark.length >= fence.length) fence = '';
      out.push(line);
      blanks = 0;
      continue;
    }
    if (fence) {
      out.push(line);
      continue;
    }
    const raw = line === EMPTY_PARAGRAPH_MARKDOWN ? '' : line;
    if (raw === '') {
      blanks += 1;
      if (blanks <= 2) out.push('');
      continue;
    }
    blanks = 0;
    // A paragraph indent is written as `&nbsp;` runs; a paste target wants spaces.
    const text = raw.replace(/^(?:&nbsp;)+/, (run) => ' '.repeat(run.length / 6));
    const trail = i === lines.length - 1 ? undefined : /\\+$/.exec(text)?.[0];
    out.push(trail && trail.length % 2 === 1 ? `${text.slice(0, -1)}  ` : text);
  }
  // Select all ends on the empty paragraph the editor keeps below the last
  // block. A paste target prints it as blank lines under the text, and its
  // tight join leaves two spaces on the last line, a break before nothing.
  if (!fence) {
    while (out.length > 0 && !/\S/.test(out[out.length - 1]!)) out.pop();
    if (out.length > 0) out[out.length - 1] = out[out.length - 1]!.replace(/ +$/, '');
  }
  return out.join('\n');
}
