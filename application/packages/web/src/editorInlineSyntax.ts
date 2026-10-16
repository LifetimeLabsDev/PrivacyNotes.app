import Highlight from '@tiptap/extension-highlight';
import { InlineMath, BlockMath } from '@tiptap/extension-mathematics';
import { InputRule } from '@tiptap/core';
import { mathNodeView } from './editorMath';

/** Minimal typing for the markdown-it inline state the math rule touches. */
interface MathParseState {
  src: string;
  pos: number;
  posMax: number;
  push: (type: string, tag: string, nesting: number) => { content: string };
  /** The markdown-it instance, for bounded recursive inline parsing. */
  md: { inline: { tokenize: (state: MathParseState) => void } };
}

/** Minimal typing for the markdown-it BLOCK state the block math rule touches. */
interface MathBlockState {
  src: string;
  bMarks: number[];
  eMarks: number[];
  tShift: number[];
  line: number;
  push: (type: string, tag: string, nesting: number) => { content: string; map?: [number, number]; block?: boolean };
}

/** Escape a latex run for embedding in a data-latex attribute. */
function escapeLatexAttr(latex: string): string {
  return latex
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/**
 * markdown-it inline rule for `$inline$` math. Emits the
 * span[data-type="inline-math"] HTML that InlineMath's parseHTML rebuilds, so
 * math stored as plain `$...$` markdown renders on load - the extension itself
 * only converts while TYPING (input rules).
 *
 * Currency guards follow markdown-it-katex: the opening $ must be followed by
 * non-space, the closing $ preceded by non-space and not followed by a digit,
 * so "$5 and $10" stays plain text. A literal `\$` never reaches this rule
 * (markdown-it's escape rule runs first).
 *
 * `$$` is explicitly NOT handled here - it is block math now, owned by
 * blockMathRule below. Before the move to @tiptap/extension-mathematics both
 * delimiters produced one inline node distinguished by a `display` attribute;
 * the official extension models them as two node types, which is the more
 * honest schema (a display equation is a block, not a very tall word).
 */
function inlineMathRule(state: MathParseState, silent: boolean): boolean {
  const { src, pos } = state;
  if (src[pos] !== '$') return false;
  if (src[pos + 1] === '$') return false;
  const start = pos + 1;
  if (/\s/.test(src[start] ?? '')) return false;
  let search = start;
  let end = -1;
  while (search < state.posMax) {
    const idx = src.indexOf('$', search);
    if (idx < 0) break;
    if (src[idx - 1] === '\\') {
      search = idx + 1;
      continue;
    }
    end = idx;
    break;
  }
  if (end <= start) return false;
  const latex = src.slice(start, end);
  if (/\s/.test(src[end - 1] ?? '')) return false;
  if (/\d/.test(src[end + 1] ?? '')) return false;
  if (latex.includes('\n')) return false;
  if (!silent) {
    const token = state.push('html_inline', '', 0);
    token.content = `<span data-type="inline-math" data-latex="${escapeLatexAttr(latex)}"></span>`;
  }
  state.pos = end + 1;
  return true;
}

/**
 * markdown-it block rule for `$$block$$` math. Handles both the one-line form
 * our serializer writes (`$$x^2$$`) and the multi-line form Obsidian and
 * pandoc write (`$$` / latex / `$$`), so imported vaults render on load.
 *
 * Emits div[data-type="block-math"], which BlockMath's parseHTML rebuilds.
 */
function blockMathRule(
  state: MathBlockState,
  startLine: number,
  endLine: number,
  silent: boolean,
): boolean {
  const start = state.bMarks[startLine]! + state.tShift[startLine]!;
  const max = state.eMarks[startLine]!;
  if (start + 2 > max) return false;
  if (state.src.slice(start, start + 2) !== '$$') return false;

  const firstLine = state.src.slice(start + 2, max).trimEnd();
  let latex: string;
  let lastLine = startLine;

  if (firstLine.endsWith('$$') && firstLine.length > 2) {
    // One-line form: $$latex$$
    latex = firstLine.slice(0, -2);
  } else {
    // Multi-line form: scan forward for the closing $$.
    const lines: string[] = firstLine ? [firstLine] : [];
    let found = false;
    for (let line = startLine + 1; line <= endLine; line++) {
      const lStart = state.bMarks[line]! + state.tShift[line]!;
      const lMax = state.eMarks[line]!;
      const text = state.src.slice(lStart, lMax).trimEnd();
      if (text.endsWith('$$')) {
        const head = text.slice(0, -2);
        if (head) lines.push(head);
        lastLine = line;
        found = true;
        break;
      }
      lines.push(text);
    }
    if (!found) return false;
    latex = lines.join('\n');
  }

  latex = latex.trim();
  if (!latex) return false;
  if (silent) return true;

  const token = state.push('html_block', '', 0);
  token.content = `<div data-type="block-math" data-latex="${escapeLatexAttr(latex)}"></div>\n`;
  token.map = [startLine, lastLine + 1];
  token.block = true;
  state.line = lastLine + 1;
  return true;
}

/**
 * InlineMathNode with a markdown spec: serialize back to `$latex$` /
 * `$$latex$$` so the stored body stays plain markdown (an unknown node
 * would otherwise fall back to tiptap-markdown's HTML serializer), and
 * register the markdown-it rule above so stored math renders on load.
 * The this.parent spread keeps the node's own storage (the evaluation
 * variables machinery), matching the TextStyleMarkdown pattern.
 */
/** Minimal typing for the markdown-it instance the math parse rules register on. */
interface MathMarkdownIt {
  inline: {
    ruler: {
      push: (name: string, fn: (state: MathParseState, silent: boolean) => boolean) => void;
    };
  };
  block: {
    ruler: {
      before: (
        beforeName: string,
        name: string,
        fn: (state: MathBlockState, startLine: number, endLine: number, silent: boolean) => boolean,
        opts?: { alt: string[] },
      ) => void;
    };
  };
}

export const InlineMathWithMarkdown = InlineMath.extend({
  addStorage() {
    return {
      ...(this.parent?.() ?? {}),
      markdown: {
        serialize(
          state: { write: (s: string) => void },
          node: { attrs: { latex?: string } },
        ) {
          state.write('$' + (node.attrs.latex ?? '') + '$');
        },
        parse: {
          setup(md: MathMarkdownIt) {
            md.inline.ruler.push('inlineMath', inlineMathRule);
          },
        },
      },
    };
  },

  /** Source editing in place - see mathNodeView. */
  addNodeView() {
    return mathNodeView({ block: false, katexOptions: this.options.katexOptions });
  },

  /**
   * Single-dollar input rule, replacing the extension's own `$$x$$`.
   *
   * Upstream ships an inverted convention - `$$x$$` for INLINE and `$$$x$$$`
   * for block - which contradicts both our stored markdown format and the
   * near-universal LaTeX/Obsidian/pandoc convention users arrive with. Left
   * alone, typing `$x$` would produce nothing and only become math after a
   * save/reload round-trip through our markdown-it rule. The handler body is
   * upstream's, unchanged; only the delimiter differs.
   */
  addInputRules() {
    return [
      // The guards are inlineMathRule's, so typing makes math exactly where a
      // reload would: no space inside either dollar, and no digit right after
      // the closing one. Without them `costs $5 and $6` would turn `5 and `
      // into a formula as it is typed. The digit check needs the character after
      // the closing dollar, so content that opens with a digit (a price, or
      // `$2^n$`) becomes math one keystroke later, when that character is
      // typed and is not a digit. Anything else becomes math at once.
      new InputRule({
        find: /(?<![$\\])\$(?![\s\d])([^$\n]*?[^\s$\\])\$$/,
        handler: ({ state, range, match }) => {
          state.tr.replaceWith(range.from, range.to, this.type.create({ latex: match[1] }));
        },
      }),
      new InputRule({
        find: /(?<![$\\])\$(?=\d)([^$\n]*?[^\s$\\])\$([^\d$])$/,
        handler: ({ state, range, match }) => {
          const math = this.type.create({ latex: match[1] });
          state.tr.replaceWith(range.from, range.to, [math, state.schema.text(match[2]!)]);
        },
      }),
    ];
  },
});

/**
 * BlockMath with the matching `$$latex$$` markdown spec. Serializes onto its
 * own line so blockMathRule reads it back as a block on the next load.
 */
export const BlockMathWithMarkdown = BlockMath.extend({
  addStorage() {
    return {
      ...(this.parent?.() ?? {}),
      markdown: {
        serialize(
          state: { text: (s: string, escape: boolean) => void; closeBlock: (n: unknown) => void },
          node: { attrs: { latex?: string } },
        ) {
          // `text` rather than `write`: a formula of several lines needs the
          // quote or list prefix on each of them.
          state.text('$$' + (node.attrs.latex ?? '') + '$$', false);
          state.closeBlock(node);
        },
        parse: {
          setup(md: MathMarkdownIt) {
            md.block.ruler.before('fence', 'blockMath', blockMathRule, {
              alt: ['paragraph', 'reference', 'blockquote', 'list'],
            });
          },
        },
      },
    };
  },

  /** Source editing in place - see mathNodeView. */
  addNodeView() {
    return mathNodeView({ block: true, katexOptions: this.options.katexOptions });
  },

  /** Double-dollar input rule, replacing upstream's `$$$x$$$`. See the note on
   *  InlineMathWithMarkdown - same reasoning, same upstream handler body. */
  addInputRules() {
    return [
      new InputRule({
        find: /^\$\$([^$]+)\$\$$/,
        handler: ({ state, range, match }) => {
          const latex = match[1];
          const { tr } = state;
          const $from = state.doc.resolve(range.from);
          const node = this.type.create({ latex });
          const consumesHostTextblock =
            $from.depth > 0 && $from.parent.isTextblock && range.from === $from.start() && range.to === $from.end();
          const canReplaceHostTextblock =
            consumesHostTextblock &&
            $from.node(-1).canReplaceWith($from.index(-1), $from.indexAfter(-1), this.type);
          const replacementRange = canReplaceHostTextblock
            ? { from: $from.before(), to: $from.after() }
            : range;
          tr.replaceWith(replacementRange.from, replacementRange.to, node);
        },
      }),
    ];
  },
});

/**
 * markdown-it inline rule for ==highlight== (Obsidian's syntax). Guards
 * mirror the math rule: the run must hug its delimiters (no space just
 * inside), stay on one line, and be non-empty - so "a == b" comparisons
 * survive as text. Nested marks inside the run are not re-parsed on
 * load (single escaped token); the typing path (Highlight's own input
 * rule) supports nesting normally.
 */
function highlightRule(state: MathParseState, silent: boolean): boolean {
  const { src, pos } = state;
  if (src[pos] !== '=' || src[pos + 1] !== '=') return false;
  const start = pos + 2;
  if (/[\s=]/.test(src[start] ?? '') || start >= state.posMax) return false;
  const end = src.indexOf('==', start);
  if (end < 0 || end === start) return false;
  const content = src.slice(start, end);
  if (content.includes('\n')) return false;
  if (/\s/.test(src[end - 1] ?? '')) return false;
  if (silent) {
    state.pos = end + 2;
    return true;
  }
  // Emit <mark> as two html_inline tokens and RECURSE over the run between
  // them, instead of escaping the run into one token. The old single-token
  // form meant `==text with **bold** inside==` stored the asterisks literally
  // on load, even though typing the same thing nested correctly - so a note
  // changed appearance just by being reopened. Narrowing posMax to the closing
  // delimiter is markdown-it's own idiom for a bounded inline sub-parse; it is
  // restored immediately after.
  const openToken = state.push('html_inline', '', 0);
  openToken.content = '<mark>';

  const oldMax = state.posMax;
  state.pos = start;
  state.posMax = end;
  state.md.inline.tokenize(state);
  state.pos = end + 2;
  state.posMax = oldMax;

  const closeToken = state.push('html_inline', '', 0);
  closeToken.content = '</mark>';
  return true;
}

/**
 * Highlight with Obsidian-style markdown storage: serialize the mark as
 * ==text== (instead of falling back to inline <mark> HTML) and parse
 * ==text== back on load via the rule above. Keeps stored bodies plain
 * and portable to/from Obsidian.
 *
 * With multicolor on (Editor.tsx), the mark can also carry a `color`
 * attribute, which `==` cannot express. Those runs - and ONLY those -
 * serialize as an inline `<mark style="background-color: ...">` instead,
 * the same escape hatch textStyleCss (editorTextStyle.ts) uses for color/size/family. A
 * plain highlight still writes `==text==`, so every note that predates
 * the palette round-trips byte-identical and stays portable to Obsidian;
 * only a deliberately colored run pays the HTML tax.
 *
 * Reading back is automatic: Markdown({ html: true }) hands the raw tag
 * to ProseMirror's DOMParser, which matches Highlight's own parseHTML
 * (multicolor reads `style.backgroundColor`) and rebuilds the attribute.
 * Store the browser's normalized `rgba(r, g, b, a)` spelling in the
 * palette, because that is what `style.backgroundColor` reads back as -
 * any other spelling round-trips to a DIFFERENT string on the next save
 * and marks the note dirty on every open.
 *
 * An older client that predates multicolor parses the tag as a plain
 * highlight and re-serializes it as `==text==` on its next edit: the
 * emphasis survives, its color does not. That is the deliberate tradeoff
 * for keeping the common case portable rather than versioning the syntax.
 */
export const HighlightWithMarkdown = Highlight.extend({
  addStorage() {
    return {
      markdown: {
        serialize: {
          open(_state: unknown, mark: { attrs: { color?: string | null } }) {
            const color = mark.attrs.color;
            if (!color) return '==';
            return `<mark style="background-color: ${color.replace(/"/g, '&quot;')}">`;
          },
          close(_state: unknown, mark: { attrs: { color?: string | null } }) {
            // Must mirror open() exactly - see TextStyleMarkdown.
            return mark.attrs.color ? '</mark>' : '==';
          },
          mixable: true,
          expelEnclosingWhitespace: true,
        },
        parse: {
          setup(md: {
            inline: {
              ruler: {
                push: (
                  name: string,
                  fn: (state: MathParseState, silent: boolean) => boolean,
                ) => void;
              };
            };
          }) {
            md.inline.ruler.push('pnHighlight', highlightRule);
          },
        },
      },
    };
  },
});
