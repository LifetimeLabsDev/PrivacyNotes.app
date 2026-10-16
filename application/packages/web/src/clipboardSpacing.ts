/**
 * Blank lines across the clipboard, in both directions.
 *
 * A paste should look like the text it came from, and a copy should look like
 * the note it came from. Both depend on the Line spacing setting, because on
 * Compact and Tight a paragraph carries no gap: every visible line is a paragraph or a
 * hard break, and every visible blank line is an empty paragraph, exactly as
 * typing produces them. So there a paragraph gap in the source has to
 * arrive as an empty paragraph, or two paragraphs that stood apart in the
 * source land on adjacent lines, while "Show markdown" still shows the blank
 * line between them.
 *
 * Three spellings of a blank line reach the paste, and each is treated alike
 * on either setting because each is a line the source drew on purpose:
 * `<div><br></div>` (Gmail, Apple Notes, any contenteditable), a `<br>` that
 * sits between two blocks (Google Docs, VS Code), and a paragraph of nothing
 * but a non-breaking space (Word). All three become `<p><br></p>`, the one
 * form ProseMirror reads as an empty paragraph. Left alone, the first was
 * dropped and the second became a paragraph holding only a hard break, which
 * drew as two lines and saved as none.
 *
 * What ProseMirror copied itself (`data-pm-slice`) is never touched: it is the
 * exact document, and a copy inside the app must paste back unchanged.
 *
 * Spec: ops/docs/design-decisions.md (editor paragraph rhythm)
 */
import { Extension } from '@tiptap/core';
import { DOMSerializer, Fragment, Slice, type Node as ProseMirrorNode, type ResolvedPos, type Schema } from '@tiptap/pm/model';
import { Plugin, PluginKey } from '@tiptap/pm/state';
import type { EditorView } from '@tiptap/pm/view';
import { paragraphGapCss, readLineSpacing, readPasteFormat } from './theme';
import { END_BREAK_ATTR, LINES_ATTR, LINE_BREAK_ATTR, joinParagraphLines } from './paragraphLines';
import { keepPaletteStyles } from './pasteStyles';

/** Elements that only group their children, so a paragraph inside one still
 *  sits in the main flow of the text. */
const WRAPPERS = new Set([
  'DIV', 'SECTION', 'ARTICLE', 'MAIN', 'HEADER', 'FOOTER', 'BLOCKQUOTE',
  'SPAN', 'B', 'I', 'EM', 'STRONG', 'FONT', 'CENTER',
]);

const BLOCKS = new Set([
  'P', 'DIV', 'H1', 'H2', 'H3', 'H4', 'H5', 'H6', 'UL', 'OL', 'BLOCKQUOTE', 'PRE',
  'TABLE', 'HR', 'SECTION', 'ARTICLE', 'HEADER', 'FOOTER', 'FIGURE',
]);

/** Content that is not text but still fills a line. */
const EMBEDS = 'img, video, audio, iframe, object, embed, svg, canvas, input, hr, table';

/** Parents a paste must not split with empty paragraphs: a list item and a
 *  table cell keep their own gaps, and code takes the text as it is. */
const NO_GAP_PARENTS = new Set(['listItem', 'taskItem', 'tableCell', 'tableHeader', 'codeBlock']);

function isWhitespaceText(node: Node): boolean {
  return (node.nodeType === Node.TEXT_NODE && !/\S/.test(node.textContent ?? '')) || node.nodeType === Node.COMMENT_NODE;
}

function siblingOf(node: Node, dir: 'previousSibling' | 'nextSibling'): Node | null {
  let at = node[dir];
  while (at && isWhitespaceText(at)) at = at[dir];
  return at;
}

function isBlock(node: Node | null): node is HTMLElement {
  return !!node && node.nodeType === Node.ELEMENT_NODE && BLOCKS.has(node.nodeName);
}

function blankLine(doc: Document): HTMLParagraphElement {
  const p = doc.createElement('p');
  p.appendChild(doc.createElement('br'));
  return p;
}

/**
 * How many lines a `<p>` or `<div>` with no text in it draws, or 0 when it is
 * not blank. A trailing `<br>` in a block draws no line of its own, but a
 * block made of nothing else still draws one, so N breaks draw N lines. An
 * element with a block inside it is a wrapper, not a line.
 */
function blankLines(el: Element): number {
  if (el.querySelector(EMBEDS) || Array.from(el.querySelectorAll('*')).some((c) => BLOCKS.has(c.nodeName))) return 0;
  const text = el.textContent ?? '';
  if (text.replace(/[\s ]/g, '') !== '') return 0;
  const breaks = el.querySelectorAll('br').length;
  if (breaks > 0) return breaks;
  return text.includes(' ') ? 1 : 0;
}

/** The lines an element shows, a `<br>` starting a new one. */
function linesOf(el: Element): string[] {
  const clone = el.cloneNode(true) as Element;
  clone.querySelectorAll('br').forEach((br) => br.replaceWith('\n'));
  return (clone.textContent ?? '').split('\n').map((l) => l.trim()).filter(Boolean);
}

/**
 * Whether the plain text of the same copy puts a blank line between the last
 * line of `a` and the first line of `b`, reading forward from `from`; null
 * when either line cannot be found there.
 */
function blankLineInText(text: string, a: Element, b: Element, from: { at: number }): boolean | null {
  const last = linesOf(a).pop();
  const first = linesOf(b)[0];
  if (!last || !first) return null;
  const end = text.indexOf(last, from.at);
  if (end < 0) return null;
  const start = text.indexOf(first, end + last.length);
  if (start < 0) return null;
  from.at = end + last.length;
  return /\n[ \t\u00A0]*\n/.test(text.slice(end + last.length, start));
}

/**
 * Whether the source drew a gap between two adjacent paragraphs. A margin
 * set inline says so either way (Chrome writes every page's margins inline,
 * Google Docs writes zero). With none, the paragraph is either a web page's,
 * where the browser's default margin is a gap, or an editor's own copy, whose
 * gap lives in a stylesheet the paste never sees: Standard Notes writes every
 * line as a `<p>` with none. The plain text of the same copy tells the two
 * apart, a blank line between the two lines or not; with no plain text, the
 * browser default decides.
 */
function gapBetween(a: HTMLElement, b: HTMLElement, text: string | undefined, from: { at: number }): boolean {
  const set = (value: string) => value !== '';
  if (set(a.style.marginBottom) || set(b.style.marginTop)) {
    const drawn = (value: string) => set(value) && parseFloat(value) !== 0;
    return drawn(a.style.marginBottom) || drawn(b.style.marginTop);
  }
  return (text ? blankLineInText(text, a, b, from) : null) ?? true;
}

function inMainFlow(el: Element): boolean {
  for (let at = el.parentElement; at && at !== el.ownerDocument.body; at = at.parentElement) {
    if (!WRAPPERS.has(at.nodeName)) return false;
  }
  return true;
}

/**
 * Pasted HTML with every blank line the source drew spelled `<p><br></p>`.
 *
 * `gapsAsBlankLines` is the Compact and Tight case: two adjacent paragraphs in the main
 * flow that the source drew apart get a blank line between them, so the gap
 * survives a setting that draws none. `text` is the plain text of the same
 * copy, which `gapBetween` reads when the HTML does not say.
 */
export function blankLinesInPastedHtml(html: string, gapsAsBlankLines: boolean, text?: string): string {
  if (html.includes('data-pm-slice')) return html;
  const doc = new DOMParser().parseFromString(html, 'text/html');
  let changed = false;

  // A blank `<p>` or `<div>`: one empty paragraph per line it draws.
  for (const el of Array.from(doc.body.querySelectorAll('p, div'))) {
    if (!el.isConnected) continue;
    const lines = blankLines(el);
    if (lines === 0) continue;
    if (el.nodeName === 'P' && lines === 1 && el.childNodes.length === 1 && el.firstChild?.nodeName === 'BR') continue;
    el.replaceWith(...Array.from({ length: lines }, () => blankLine(doc)));
    changed = true;
  }

  // A run of `<br>` between two blocks: one empty paragraph per break.
  for (const br of Array.from(doc.body.querySelectorAll('br'))) {
    if (!br.isConnected || !isBlock(siblingOf(br, 'previousSibling'))) continue;
    const run: Node[] = [br];
    let next = siblingOf(br, 'nextSibling');
    while (next && next.nodeName === 'BR') {
      run.push(next);
      next = siblingOf(next, 'nextSibling');
    }
    if (!isBlock(next)) continue;
    for (const node of run) node.parentNode!.replaceChild(blankLine(doc), node);
    changed = true;
  }

  if (gapsAsBlankLines) {
    const from = { at: 0 };
    for (const p of Array.from(doc.body.querySelectorAll('p'))) {
      const next = siblingOf(p, 'nextSibling');
      if (!(next instanceof HTMLElement) || next.nodeName !== 'P') continue;
      if (blankLines(p) > 0 || blankLines(next) > 0 || !isContent(p) || !isContent(next)) continue;
      if (!inMainFlow(p) || !gapBetween(p as HTMLElement, next, text, from)) continue;
      p.after(blankLine(doc));
      changed = true;
    }
  }

  return changed ? doc.body.innerHTML : html;
}

/** A paragraph a reader sees something in: text or an embed. */
function isContent(p: Element): boolean {
  return (p.textContent ?? '').replace(/[\s ]/g, '') !== '' || !!p.querySelector(EMBEDS);
}

function isEmptyParagraph(node: ProseMirrorNode): boolean {
  return node.type.name === 'paragraph' && node.content.size === 0;
}

/**
 * A paragraph holding nothing but hard breaks, as the empty paragraphs it
 * stands for: N breaks, N blank lines. The markdown file cannot record the
 * paragraph as it is, so it drew as lines and saved as nothing.
 */
function breaksAsBlankLines(content: Fragment): Fragment {
  const out: ProseMirrorNode[] = [];
  let changed = false;
  content.forEach((node) => {
    let breaks = 0;
    let other = false;
    if (node.type.name === 'paragraph' && node.content.size > 0) {
      node.content.forEach((child) => {
        if (child.type.name === 'hardBreak') breaks++;
        else other = true;
      });
    }
    if (breaks > 0 && !other) {
      for (let i = 0; i < breaks; i++) out.push(node.type.create(node.attrs));
      changed = true;
    } else {
      out.push(node);
    }
  });
  return changed ? Fragment.from(out) : content;
}

/**
 * A paragraph of nothing but non-breaking spaces, as an empty one. That is
 * the markdown file's spelling of an empty paragraph (`&nbsp;`), which a
 * pasted note, a pasted `.md` export and the blank-line runs above all bring
 * in; the file loader clears it the same way (NbspParagraphCleaner).
 */
function nbspAsEmpty(content: Fragment): Fragment {
  const out: ProseMirrorNode[] = [];
  let changed = false;
  content.forEach((node) => {
    let onlyNbsp = node.type.name === 'paragraph' && node.content.size > 0;
    node.forEach((child) => {
      if (!child.isText || child.text!.replace(/\u00a0/g, '') !== '') onlyNbsp = false;
    });
    out.push(onlyNbsp ? node.type.create(node.attrs) : node);
    changed ||= onlyNbsp;
  });
  return changed ? Fragment.from(out) : content;
}

/** An empty paragraph between every two adjacent paragraphs with content. */
function gapsAsBlankLines(content: Fragment, schema: Schema): Fragment {
  const out: ProseMirrorNode[] = [];
  let changed = false;
  content.forEach((node, _offset, index) => {
    const prev = index > 0 ? content.child(index - 1) : null;
    if (prev && prev.type.name === 'paragraph' && node.type.name === 'paragraph' && !isEmptyParagraph(prev) && !isEmptyParagraph(node)) {
      out.push(schema.nodes['paragraph']!.create());
      changed = true;
    }
    out.push(node);
  });
  return changed ? Fragment.from(out) : content;
}

/**
 * Apple's text system writes a line break as U+2028 and a paragraph break as
 * U+2029, and Apple Notes puts only that plain text (and RTF) on the
 * clipboard, no HTML. Every parser here splits on newlines, so without this
 * the lines of a note copied from Apple Notes ran together into one.
 */
function appleSeparatorsAsNewlines(text: string): string {
  return text.replace(/\u2029/g, '\n\n').replace(/\u2028/g, '\n');
}

/** In the main flow of the text, where a line is a paragraph. */
function inFlow($pos: ResolvedPos): boolean {
  for (let d = $pos.depth; d > 0; d--) {
    if (NO_GAP_PARENTS.has($pos.node(d).type.name)) return false;
  }
  return true;
}

function gapsWanted($pos: ResolvedPos): boolean {
  return readLineSpacing() !== 'normal' && inFlow($pos);
}

/**
 * Compact and Tight: a paragraph cut at every line break. There a paragraph is
 * a line, exactly as Enter types it, so a pasted line break (Google Docs, a
 * note copied out of this app through another one, the export page, a burn
 * link, plain text lines) lands as the lines it shows rather than as one
 * paragraph with breaks that a later switch to Normal would draw with no gap.
 * A trailing break draws no line, so it adds none.
 *
 * The markdown text path hands over a one-paragraph paste as its bare inline
 * content, so that form is cut too, into paragraphs open at both ends: the
 * first joins the paragraph at the cursor and the last takes the rest of it.
 */
function breaksAsParagraphs(slice: Slice, schema: Schema): Slice {
  const cut = (node: ProseMirrorNode): ProseMirrorNode[] => {
    const lines: ProseMirrorNode[][] = [[]];
    node.forEach((child) => {
      if (child.type.name === 'hardBreak') lines.push([]);
      else lines[lines.length - 1]!.push(child);
    });
    if (lines.length > 1 && lines[lines.length - 1]!.length === 0) lines.pop();
    return lines.map((line) => node.type.create(node.attrs, line));
  };
  const hasBreak = (node: ProseMirrorNode) => {
    let found = false;
    node.forEach((child) => {
      found ||= child.type.name === 'hardBreak';
    });
    return found;
  };
  const first = slice.content.firstChild;
  if (first?.isInline) {
    const paragraph = schema.nodes['paragraph']!.create(null, slice.content);
    return hasBreak(paragraph) ? new Slice(Fragment.from(cut(paragraph)), 1, 1) : slice;
  }
  const out: ProseMirrorNode[] = [];
  let changed = false;
  slice.content.forEach((node) => {
    if (node.type.name === 'paragraph' && hasBreak(node)) {
      out.push(...cut(node));
      changed = true;
    } else {
      out.push(node);
    }
  });
  return changed ? new Slice(Fragment.from(out), slice.openStart, slice.openEnd) : slice;
}

/**
 * How many empty paragraphs a run of blank lines in pasted plain text stands
 * for. On Compact and Tight a blank line is an empty paragraph, so the count
 * is kept. On Normal one blank line is the paragraph gap Normal draws, and a
 * longer run is one empty paragraph: that is about the height it showed, and
 * a browser copies a page with two newlines per paragraph, so a longer count
 * says more about the source than about the text.
 */
function emptiesFor(blanks: number, normal: boolean): number {
  if (normal) return blanks >= 2 ? 1 : 0;
  return blanks;
}

/**
 * The markdown path reads any run of blank lines as one paragraph break, so a
 * run of two or more is written out as `&nbsp;` paragraphs, the file's own
 * spelling of an empty one. A single blank line is left to the paragraph
 * break (and on Compact to `gapsAsBlankLines`). Fenced code keeps its text
 * exactly.
 */
function blankRunsAsEmptyParagraphs(text: string, normal: boolean): string {
  const out: string[] = [];
  let fence = '';
  let blanks = 0;
  for (const line of text.split(/\r\n?|\n/)) {
    const mark = /^ {0,3}(`{3,}|~{3,})/.exec(line)?.[1];
    if (!fence && !/\S/.test(line)) {
      blanks++;
      continue;
    }
    if (blanks > 0 && out.length > 0) {
      out.push('');
      if (blanks >= 2) for (let i = 0; i < emptiesFor(blanks, normal); i++) out.push('&nbsp;', '');
    }
    blanks = 0;
    out.push(line);
    if (mark) {
      if (!fence) fence = mark;
      else if (mark[0] === fence[0] && mark.length >= fence.length) fence = '';
    }
  }
  return out.join('\n');
}

/**
 * Plain text as the lines it shows. On Compact and Tight a line is a
 * paragraph and a blank line an empty one. On Normal a line inside a block of
 * text is a line break and a run of blank lines follows `emptiesFor`, which
 * is what the markdown path gives the same text. Blank lines at either end are how the
 * text was picked up rather than content, so they go.
 */
function linesAsParagraphs(text: string, schema: Schema, $context: ResolvedPos, normal: boolean): Slice {
  const marks = $context.marks();
  const paragraph = schema.nodes['paragraph']!;
  const hardBreak = schema.nodes['hardBreak']!;
  const out: ProseMirrorNode[] = [];
  let lines: ProseMirrorNode[] = [];
  const close = () => {
    if (lines.length > 0) out.push(paragraph.create(null, lines));
    lines = [];
  };
  let blanks = 0;
  for (const line of text.split(/\r\n?|\n/)) {
    if (!/\S/.test(line)) {
      if (out.length > 0 || lines.length > 0) blanks++;
      continue;
    }
    if (blanks > 0 || !normal) close();
    for (let i = 0; i < emptiesFor(blanks, normal); i++) out.push(paragraph.create());
    blanks = 0;
    if (lines.length > 0) lines.push(hardBreak.create());
    lines.push(schema.text(line, marks));
  }
  close();
  return new Slice(Fragment.from(out), 0, 0);
}

/**
 * The paste half of `joinParagraphLines`: a copy from this app pastes back as
 * the paragraphs it came from. A break the author typed carries no marker,
 * so it stays a break.
 */
function splitCopiedLines(html: string): string {
  if (!html.includes(LINES_ATTR)) return html;
  const doc = new DOMParser().parseFromString(html, 'text/html');
  for (const joined of Array.from(doc.body.querySelectorAll(`p[${LINES_ATTR}]`))) {
    joined.querySelectorAll(`br[${END_BREAK_ATTR}]`).forEach((br) => br.remove());
    const lines: HTMLParagraphElement[] = [];
    const startLine = () => {
      const p = joined.cloneNode(false) as HTMLParagraphElement;
      p.removeAttribute(LINES_ATTR);
      if (lines.length > 0) p.removeAttribute('data-pm-slice');
      lines.push(p);
      return p;
    };
    let line = startLine();
    for (const child of Array.from(joined.childNodes)) {
      if (child.nodeName === 'BR' && (child as Element).hasAttribute(LINE_BREAK_ATTR)) line = startLine();
      else line.appendChild(child);
    }
    joined.replaceWith(...lines);
  }
  return doc.body.innerHTML;
}

/**
 * The HTML flavour of a copy, drawn the way the note is: each paragraph
 * carries the gap the reader has set, and an empty paragraph carries a break
 * so it keeps its line. Without them the target applies its own paragraph
 * margins, and an empty `<p></p>` either vanishes or adds a gap of its own.
 * Paragraphs in a list item or a table cell keep the target's rhythm.
 */
function styleCopiedParagraphs(root: HTMLElement | DocumentFragment, gap: string): void {
  for (const p of Array.from(root.querySelectorAll('p'))) {
    if (!p.closest('li, td, th')) {
      p.style.marginTop = gap;
      p.style.marginBottom = gap;
    }
    if (!p.hasChildNodes()) p.appendChild(p.ownerDocument.createElement('br'));
    else if (p.querySelector('br') && /\S/.test(p.textContent ?? '') && !p.closest('li, td, th')) breaksInDiv(p);
  }
}

/**
 * Marks a paragraph that leaves the app as a `<div>`. Google Keep on Android
 * drops every `<br>` inside a `<p>`, so a paragraph of lines pasted there as
 * one run-on line; inside a `<div>` it keeps them, and every other target
 * draws the two the same. The paste half turns it back (`copiedParagraphsBack`).
 */
function breaksInDiv(p: HTMLParagraphElement): void {
  const div = p.ownerDocument.createElement('div');
  for (const at of Array.from(p.attributes)) div.setAttribute(at.name, at.value);
  div.setAttribute(PARAGRAPH_ATTR, '');
  div.append(...Array.from(p.childNodes));
  p.replaceWith(div);
}

const PARAGRAPH_ATTR = 'data-pn-p';

function copiedParagraphsBack(html: string): string {
  if (!html.includes(PARAGRAPH_ATTR)) return html;
  const doc = new DOMParser().parseFromString(html, 'text/html');
  for (const div of Array.from(doc.body.querySelectorAll(`div[${PARAGRAPH_ATTR}]`))) {
    const p = doc.createElement('p');
    for (const at of Array.from(div.attributes)) if (at.name !== PARAGRAPH_ATTR) p.setAttribute(at.name, at.value);
    p.append(...Array.from(div.childNodes));
    div.replaceWith(p);
  }
  return doc.body.innerHTML;
}

/**
 * The last copy that left as plain text alone, so a paste of it back into
 * the app is the exact slice again. Plain text cannot say which `*` was
 * typed and which is emphasis, or how many blank lines a capped run held.
 */
let lastPlainCopy: { text: string; slice: ReturnType<Slice['toJSON']> } | null = null;

/** Whether `text` is the plain text of the app's last copy. */
function ownPlainCopy(text: string): boolean {
  return !!lastPlainCopy && lastPlainCopy.text === text;
}

/** Only lines of unformatted text: what a plain-text copy carries in full. */
function isPlainLines(slice: Slice): boolean {
  let plain = slice.content.childCount > 0;
  slice.content.forEach((node) => {
    if (node.type.name !== 'paragraph' || Object.values(node.attrs).some((v) => v != null)) plain = false;
    node.forEach((child) => {
      if (!(child.isText && child.marks.length === 0) && child.type.name !== 'hardBreak') plain = false;
    });
  });
  return plain;
}

/**
 * On Android a copy of plain lines carries the plain text alone. An HTML
 * flavour beside it is read by whatever sits between the copy and the paste
 * (Keep's own converter, a vendor's clipboard), and some of them turn every
 * line break into a paragraph break, so one blank line arrived as three
 * (GitHub #345). Plain text has nothing to convert, and it holds the whole
 * of a copy that is only lines of text on Compact and Tight. Normal keeps
 * the HTML, because its plain text marks a paragraph gap with a blank line,
 * and a paste back into the app reads a run of them as one gap. Desktop keeps the HTML too: a word
 * processor gives every pasted plain-text line its own paragraph spacing.
 */
function copyPlainLinesAsText(view: EditorView, event: ClipboardEvent, cut: boolean): boolean {
  // ProseMirror's own cut refuses a read-only note, and this one runs first.
  if (cut && !view.editable) return false;
  if (!/android/i.test(navigator.userAgent) || !event.clipboardData || view.state.selection.empty) return false;
  if (readLineSpacing() === 'normal') return false;
  const slice = view.state.selection.content();
  if (!isPlainLines(slice)) return false;
  const text = view.someProp('clipboardTextSerializer', (f) => f(slice, view));
  if (!text) return false;
  event.preventDefault();
  event.clipboardData.clearData();
  event.clipboardData.setData('text/plain', text);
  lastPlainCopy = { text, slice: slice.toJSON() };
  if (cut) view.dispatch(view.state.tr.deleteSelection().scrollIntoView().setMeta('uiEvent', 'cut'));
  return true;
}

/**
 * Marks the HTML of a copy from this app, so Pasted text: Plain text can tell
 * it from another ProseMirror editor's, which carries `data-pm-slice` too.
 */
const COPY_ATTR = 'data-pn-copy';

/**
 * The views in which Pasted text: Plain text is handing its text to
 * ProseMirror, so the paste is placed by `placePlainPaste` and TipTap's paste
 * rules never read it.
 */
const plainPasteRunning = new WeakMap<EditorView, boolean>();

/**
 * Settings > Editor > Pasted text: Plain text. Every paste from another app
 * takes the path of a paste with Shift held: lines of text, no marks, no
 * Markdown read. A copy from a note keeps its formatting. A file goes to the
 * attachment handler and a picture to the picture handler, unless the clip
 * also holds the text the picture shows (a spreadsheet's cells), which the
 * picture handler leaves to the formatted paste. No event is passed on, so
 * those handlers never see the clipboard of a paste that became text.
 * Spec: ops/issues/0508.md (Spec)
 */
function pasteAsPlainText(view: EditorView, event: ClipboardEvent): boolean {
  if (readPasteFormat() !== 'plain') return false;
  const data = event.clipboardData;
  const text = data?.getData('text/plain');
  if (!data || !text || ownPlainCopy(text)) return false;
  const html = data.getData('text/html');
  const body = html ? new DOMParser().parseFromString(html, 'text/html').body : null;
  if (body?.querySelector(`[${COPY_ATTR}]`)) return false;
  const files = Array.from(data.files);
  if (files.length > 0 && (files.some((f) => !f.type.startsWith('image/')) || !body?.textContent.trim())) return false;
  event.preventDefault();
  const outer = plainPasteRunning.get(view) ?? false;
  plainPasteRunning.set(view, true);
  try {
    return view.pasteText(text);
  } finally {
    plainPasteRunning.set(view, outer);
  }
}

/**
 * Places the slice of a Plain text paste the way ProseMirror places a paste,
 * but without its `uiEvent: 'paste'` mark: TipTap's paste rules read that mark
 * and would turn a pasted `**word**` into bold, which plain text never asks for.
 * It is the last `handlePaste` (`PlainPastePlacement`), so the table paste
 * over selected cells and a link pasted over a selection still take theirs.
 */
function placePlainPaste(view: EditorView, slice: Slice): boolean {
  if (!plainPasteRunning.get(view)) return false;
  const single = slice.openStart === 0 && slice.openEnd === 0 && slice.content.childCount === 1 ? slice.content.firstChild : null;
  const tr = single ? view.state.tr.replaceSelectionWith(single, true) : view.state.tr.replaceSelection(slice);
  view.dispatch(tr.scrollIntoView().setMeta('paste', true));
  return true;
}

/**
 * The copy half: ProseMirror's own serializer, with the paragraphs drawn the
 * way the note draws them. The `data-pm-slice` marker goes on afterwards, so
 * a copy inside the app still pastes back as the exact document.
 */
function spacedClipboardSerializer(schema: Schema): DOMSerializer {
  const base = DOMSerializer.fromSchema(schema);
  const serializer = new DOMSerializer(base.nodes, base.marks);
  serializer.serializeFragment = (fragment, options, target) => {
    const out = base.serializeFragment(fragment, options, target);
    if (readLineSpacing() !== 'normal') joinParagraphLines(out as HTMLElement | DocumentFragment, true);
    styleCopiedParagraphs(out as HTMLElement | DocumentFragment, paragraphGapCss());
    for (const el of Array.from((out as HTMLElement | DocumentFragment).children)) el.setAttribute(COPY_ATTR, '');
    return out;
  };
  return serializer;
}

const PlainPastePlacement = Extension.create({
  name: 'plainPastePlacement',
  priority: 1,
  addProseMirrorPlugins() {
    return [
      new Plugin({
        key: new PluginKey('plainPastePlacement'),
        props: { handlePaste: (view, _event, slice) => placePlainPaste(view, slice) },
      }),
    ];
  },
});

/**
 * Wires both halves into the editor. The paste half runs after the image sanitizer,
 * which is an editor prop and so comes first, and its text parser outranks
 * tiptap-markdown's by priority, which matters only for "paste as plain
 * text": that path otherwise joins every run of newlines into one break.
 */
export const ClipboardSpacing = Extension.create({
  name: 'clipboardSpacing',
  priority: 1000,
  addExtensions() {
    return [PlainPastePlacement];
  },
  addProseMirrorPlugins() {
    // Which text path the paste in progress took. ProseMirror names it in
    // transformPastedText and forgets it by transformPasted.
    let textPath: 'markdown' | 'lines' | null = null;
    // Whether the paste is ProseMirror's own copy, which is the exact document
    // and keeps every break its author typed.
    let fromEditor = false;
    // The plain text beside the HTML of the paste in progress, which the HTML
    // hook is not handed.
    let pastedText: string | undefined;
    return [
      new Plugin({
        key: new PluginKey('clipboardSpacing'),
        props: {
          clipboardSerializer: spacedClipboardSerializer(this.editor.schema),
          handleDOMEvents: {
            copy: (view, event) => copyPlainLinesAsText(view, event, false),
            cut: (view, event) => copyPlainLinesAsText(view, event, true),
            paste(view, event) {
              // ProseMirror refuses a paste into a read-only note only in its
              // own handler, which runs after this one.
              if (!view.editable) return false;
              const data = event.clipboardData;
              const inCode = !!view.state.selection.$from.parent.type.spec.code;
              if (data && !inCode && !data.getData('text/html') && ownPlainCopy(data.getData('text/plain')) && lastPlainCopy) {
                // Each editor builds its own schema, so the slice is rebuilt
                // in this one's; a node of another schema fits nowhere. No
                // paste mark on the step: the paste rules would read a typed
                // `*word*` as emphasis, which an exact copy never does. Code
                // takes ProseMirror's own paste, which keeps the text as code.
                const own = Slice.fromJSON(view.state.schema, lastPlainCopy.slice);
                event.preventDefault();
                view.dispatch(view.state.tr.replaceSelection(own).scrollIntoView());
                return true;
              }
              if (pasteAsPlainText(view, event)) return true;
              pastedText = appleSeparatorsAsNewlines(data?.getData('text/plain') ?? '') || undefined;
              return false;
            },
          },
          transformPastedHTML(html, view) {
            textPath = null;
            fromEditor = html.includes('data-pm-slice');
            // Another app's colours, fonts and sizes go unless they are ours.
            if (!fromEditor) html = keepPaletteStyles(html);
            const breaks = html.replace(/\u2029/g, '<br><br>').replace(/\u2028/g, '<br>');
            const text = pastedText;
            pastedText = undefined;
            return blankLinesInPastedHtml(splitCopiedLines(copiedParagraphsBack(breaks)), gapsWanted(view.state.selection.$from), text);
          },
          transformPastedText(raw, plain, view) {
            textPath = plain ? null : 'markdown';
            fromEditor = false;
            const text = appleSeparatorsAsNewlines(raw);
            if (plain) return text;
            // Blank lines at either end are how the text was picked up, and
            // on this path a leading one parses as a line break before the
            // first word. Code keeps its text exactly (`plain` is set there).
            const trimmed = text.replace(/^(?:[ \t]*\r?\n)+/, '').replace(/(?:\r?\n[ \t]*)+$/, '');
            const $from = view.state.selection.$from;
            return inFlow($from) ? blankRunsAsEmptyParagraphs(trimmed, readLineSpacing() === 'normal') : trimmed;
          },
          clipboardTextParser(text, $context, plain, view) {
            if (!plain || !inFlow($context)) return null as unknown as Slice;
            textPath = 'lines';
            return linesAsParagraphs(text, view.state.schema, $context, readLineSpacing() === 'normal');
          },
          transformPasted(slice, view, asText) {
            const path = asText ? textPath : null;
            // A drag inside the editor moves the exact document too.
            const own = fromEditor || !!view.dragging;
            textPath = null;
            fromEditor = false;
            pastedText = undefined;
            let content = asText ? slice.content : breaksAsBlankLines(slice.content);
            if (!own) content = nbspAsEmpty(content);
            if (path === 'markdown' && gapsWanted(view.state.selection.$from)) {
              content = gapsAsBlankLines(content, view.state.schema);
            }
            const out = content === slice.content ? slice : new Slice(content, slice.openStart, slice.openEnd);
            return !own && gapsWanted(view.state.selection.$from) ? breaksAsParagraphs(out, view.state.schema) : out;
          },
        },
      }),
    ];
  },
});
