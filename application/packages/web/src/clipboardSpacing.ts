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
import { paragraphGapCss, readLineSpacing } from './theme';

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

/** Whether the source drew a gap between two adjacent paragraphs. A margin
 *  set to zero inline is the one sign it did not; a margin that is not set
 *  at all is the browser's default, which is a gap. */
function gapBetween(a: HTMLElement, b: HTMLElement): boolean {
  const drawn = (value: string) => value === '' || parseFloat(value) !== 0;
  return drawn(a.style.marginBottom) || drawn(b.style.marginTop);
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
 * survives a setting that draws none.
 */
export function blankLinesInPastedHtml(html: string, gapsAsBlankLines: boolean): string {
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
    for (const p of Array.from(doc.body.querySelectorAll('p'))) {
      const next = siblingOf(p, 'nextSibling');
      if (!(next instanceof HTMLElement) || next.nodeName !== 'P') continue;
      if (blankLines(p) > 0 || blankLines(next) > 0 || !isContent(p) || !isContent(next)) continue;
      if (!inMainFlow(p) || !gapBetween(p as HTMLElement, next)) continue;
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

function gapsWanted($pos: ResolvedPos): boolean {
  if (readLineSpacing() === 'normal') return false;
  for (let d = $pos.depth; d > 0; d--) {
    if (NO_GAP_PARENTS.has($pos.node(d).type.name)) return false;
  }
  return true;
}

/**
 * Plain text as the lines it shows: a line is a paragraph and a run of blank
 * lines is one empty paragraph. Blank lines at either end are how the text
 * was picked up rather than content, so they go.
 */
function linesAsParagraphs(text: string, schema: Schema, $context: ResolvedPos): Slice {
  const marks = $context.marks();
  const paragraph = schema.nodes['paragraph']!;
  const out: ProseMirrorNode[] = [];
  let blank = false;
  for (const line of text.split(/\r\n?|\n/)) {
    if (!/\S/.test(line)) {
      blank = out.length > 0;
      continue;
    }
    if (blank) out.push(paragraph.create());
    blank = false;
    out.push(paragraph.create(null, schema.text(line, marks)));
  }
  return new Slice(Fragment.from(out), 0, 0);
}

/**
 * The HTML flavour of a copy, drawn the way the note is: each paragraph
 * carries the gap the reader has set, and an empty paragraph carries a break
 * so it keeps its line. Without them the target applies its own paragraph
 * margins, and an empty `<p></p>` either vanishes or adds a gap of its own,
 * which is how one blank line arrived as three (GitHub #345). Paragraphs in a
 * list item or a table cell keep the target's rhythm.
 */
function styleCopiedParagraphs(root: HTMLElement | DocumentFragment, gap: string): void {
  for (const p of Array.from(root.querySelectorAll('p'))) {
    if (!p.closest('li, td, th')) {
      p.style.marginTop = gap;
      p.style.marginBottom = gap;
    }
    if (!p.hasChildNodes()) p.appendChild(p.ownerDocument.createElement('br'));
  }
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
    styleCopiedParagraphs(out as HTMLElement | DocumentFragment, paragraphGapCss());
    return out;
  };
  return serializer;
}

/**
 * Wires both halves into the editor. The paste half runs after the image sanitizer,
 * which is an editor prop and so comes first, and its text parser outranks
 * tiptap-markdown's by priority, which matters only for "paste as plain
 * text": that path otherwise joins every run of newlines into one break.
 */
export const ClipboardSpacing = Extension.create({
  name: 'clipboardSpacing',
  priority: 1000,
  addProseMirrorPlugins() {
    // Which text path the paste in progress took. ProseMirror names it in
    // transformPastedText and forgets it by transformPasted.
    let textPath: 'markdown' | 'lines' | null = null;
    return [
      new Plugin({
        key: new PluginKey('clipboardSpacing'),
        props: {
          clipboardSerializer: spacedClipboardSerializer(this.editor.schema),
          transformPastedHTML(html, view) {
            textPath = null;
            return blankLinesInPastedHtml(html, gapsWanted(view.state.selection.$from));
          },
          transformPastedText(text, plain) {
            textPath = plain ? null : 'markdown';
            // Blank lines at either end are how the text was picked up, and
            // on this path a leading one parses as a line break before the
            // first word. Code keeps its text exactly (`plain` is set there).
            return plain ? text : text.replace(/^(?:[ \t]*\r?\n)+/, '').replace(/(?:\r?\n[ \t]*)+$/, '');
          },
          clipboardTextParser(text, $context, plain, view) {
            if (!plain || !gapsWanted($context)) return null as unknown as Slice;
            textPath = 'lines';
            return linesAsParagraphs(text, view.state.schema, $context);
          },
          transformPasted(slice, view, asText) {
            const path = asText ? textPath : null;
            textPath = null;
            let content = asText ? slice.content : breaksAsBlankLines(slice.content);
            if (path === 'markdown' && gapsWanted(view.state.selection.$from)) {
              content = gapsAsBlankLines(content, view.state.schema);
            }
            return content === slice.content ? slice : new Slice(content, slice.openStart, slice.openEnd);
          },
        },
      }),
    ];
  },
});
