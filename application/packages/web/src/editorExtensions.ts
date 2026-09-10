import i18n from './i18n';
import { type Editor as TipTapEditor } from '@tiptap/react';
import TaskItem from '@tiptap/extension-task-item';
import TaskList from '@tiptap/extension-task-list';
import { Table } from '@tiptap/extension-table';
import { Paragraph } from '@tiptap/extension-paragraph';
import { Heading } from '@tiptap/extension-heading';
import { CodeBlockLowlight } from '@tiptap/extension-code-block-lowlight';
import { createLowlight, common } from 'lowlight';
import Highlight from '@tiptap/extension-highlight';
import { InlineMath, BlockMath } from '@tiptap/extension-mathematics';
import { TextAlign } from '@tiptap/extension-text-align';
import { TextStyle } from '@tiptap/extension-text-style';
import { Extension, InputRule, getHTMLFromFragment, type NodeViewRendererProps } from '@tiptap/core';
import { Fragment, type Node as ProseMirrorNode } from '@tiptap/pm/model';
import { Plugin, PluginKey, TextSelection, Selection } from '@tiptap/pm/state';
import { selectionCell } from '@tiptap/pm/tables';
import { isSoftKeyboardDevice, suppressSoftKeyboard } from './softKeyboard';
import { mathNodeView } from './editorMath';

/**
 * Text color support.
 *
 * The Color extension stores the chosen color as the `color` attribute on
 * the TextStyle mark. tiptap-markdown ships no serializer for that mark,
 * so without this getMarkdown() would either drop the color silently or
 * throw ("no serializer for mark type textStyle"). We add one here.
 *
 * Color has no native markdown syntax, so we serialize it as an inline
 * HTML <span style="color:..."> - valid CommonMark and the only portable
 * representation. The span is emitted ONLY when a color is actually set,
 * so notes without color round-trip to byte-identical clean markdown.
 *
 * Re-import / paste round-trips automatically: Markdown({ html: true })
 * feeds the raw span to ProseMirror's DOMParser, which matches the
 * TextStyle/Color parseHTML rules and rebuilds the mark.
 *
 * The HTML export and burn-after-reading viewer render this span via
 * markdownRender.ts, which independently allowlists the `color` value
 * (sanitizeColor) so an untrusted note can't smuggle other styles.
 */
/** Attributes FontSize, FontFamily and Color all hang off the one textStyle mark. */
type TextStyleAttrs = {
  color?: string | null;
  fontSize?: string | null;
  fontFamily?: string | null;
};

/**
 * Build the inline `style` value for a textStyle mark.
 *
 * ALL THREE attributes have to be listed here. They share a single mark, and
 * this serializer is the only thing that puts any of them into stored markdown
 * - an attribute missing from this function round-trips as nothing and is
 * silently dropped on the next save, which is exactly how font size and family
 * would have behaved had they been registered without touching this.
 *
 * Returns '' when the mark carries nothing, which is the signal for open/close
 * to emit no span at all. Double quotes are escaped because the value lands
 * inside a double-quoted HTML attribute (font stacks are the realistic source
 * of one, e.g. a family containing "Times New Roman").
 */
function textStyleCss(attrs: TextStyleAttrs): string {
  const parts: string[] = [];
  if (attrs.color) parts.push(`color: ${attrs.color}`);
  if (attrs.fontSize) parts.push(`font-size: ${attrs.fontSize}`);
  if (attrs.fontFamily) parts.push(`font-family: ${attrs.fontFamily}`);
  return parts.join('; ').replace(/"/g, '&quot;');
}

export const TextStyleMarkdown = TextStyle.extend({
  addStorage() {
    return {
      markdown: {
        serialize: {
          open(_state: unknown, mark: { attrs: TextStyleAttrs }) {
            const css = textStyleCss(mark.attrs);
            return css ? `<span style="${css}">` : '';
          },
          close(_state: unknown, mark: { attrs: TextStyleAttrs }) {
            // Must mirror open() exactly: emitting a closing tag for a span
            // that was never opened corrupts the document.
            return textStyleCss(mark.attrs) ? '</span>' : '';
          },
          mixable: true,
          expelEnclosingWhitespace: true,
        },
        parse: {
          // Handled by markdown-it (html: true) -> ProseMirror DOMParser.
        },
      },
    };
  },
});

/**
 * Markdown autoformatting for task lists. StarterKit ships input rules for
 * bold/italic/strike/code/headings/lists/quote/codeBlock, but TaskItem has
 * none - so typing "[] " or "[ ] " at the start of a line converts the
 * current block into a task list, matching the rest of the markdown
 * shortcuts. "[x] " starts a checked item.
 */
export const TaskListInputRule = Extension.create({
  name: 'taskListInputRule',
  addInputRules() {
    return [
      new InputRule({
        find: /^\[([ xX]?)\]\s$/,
        handler: ({ chain, range, match }) => {
          const checked = match[1] === 'x' || match[1] === 'X';
          chain().deleteRange(range).toggleTaskList().run();
          if (checked) {
            this.editor.commands.updateAttributes('taskItem', { checked: true });
          }
        },
      }),
    ];
  },
});

/**
 * TaskItem whose checkbox doesn't open the on-screen keyboard on mobile.
 *
 * Takes TWO things, and the first alone is not enough - v0.223.5 shipped it
 * on its own and the bug came straight back for anyone with a caret in the
 * note:
 *
 * 1. Stock @tiptap/extension-task-item focuses the editor inside the checkbox
 *    `change` handler (`.focus(...)`). On touch devices that focus lands on
 *    the contenteditable and the keyboard slides up on every (un)check. We
 *    replicate the stock node view but skip the focus on touch-first devices
 *    - setNodeMarkup needs no focus to run. Desktop keeps it so caret /
 *    selection behaviour is unchanged.
 * 2. That only covers an UNFOCUSED editor. Once the editor already holds
 *    focus - caret blinking, keyboard dismissed with the Back button - the
 *    tap itself re-raises the IME and no handler of ours is consulted. The
 *    touchstart below parks `inputmode="none"` for the gesture, which is the
 *    only thing that suppresses it without blurring (and blurring would cost
 *    the caret). See softKeyboard.ts.
 *
 * Fix: GitHub #153 (keyboard opens on checklist toggle, web on Android)
 */
export const TaskItemMobileSafe = TaskItem.extend({
  addNodeView() {
    return ({ node, HTMLAttributes, getPos, editor }: NodeViewRendererProps) => {
      const listItem = document.createElement('li');
      const checkboxWrapper = document.createElement('label');
      const checkboxStyler = document.createElement('span');
      const checkbox = document.createElement('input');
      const content = document.createElement('div');

      const updateA11Y = () => {
        checkbox.setAttribute(
          'aria-label',
          `Task item checkbox for ${node.textContent || 'empty task item'}`,
        );
      };
      updateA11Y();

      checkboxWrapper.contentEditable = 'false';
      // The styler span hosts the draw-in check SVG (checkbox variant B).
      // A CSS ::before clip-path cannot animate a stroke, so the check is
      // a real path whose dashoffset transitions when li[data-checked]
      // flips - see the taskList rules in index.css.
      checkboxStyler.className = 'pn-check';
      checkboxStyler.setAttribute('aria-hidden', 'true');
      checkboxStyler.innerHTML =
        '<svg viewBox="0 0 12 12"><path d="M2 6.5 5 9 10 3"/></svg>';
      checkbox.type = 'checkbox';
      checkbox.addEventListener('mousedown', (event) => event.preventDefault());
      // Skipping `.focus()` below is not enough once the editor already holds
      // focus: the tap itself is what re-raises the IME. Arm the suppression
      // as the touch starts, while there is still time for it to count.
      checkbox.addEventListener(
        'touchstart',
        () => suppressSoftKeyboard(editor.view.dom as HTMLElement),
        { passive: true },
      );
      checkbox.addEventListener('change', (event) => {
        // Undo the change when the editor isn't editable and nothing handles
        // read-only checks - identical to the stock node view.
        if (!editor.isEditable && !this.options.onReadOnlyChecked) {
          checkbox.checked = !checkbox.checked;
          return;
        }
        const { checked } = event.target as HTMLInputElement;
        if (editor.isEditable && typeof getPos === 'function') {
          const chain = editor.chain();
          // Skip the focus on touch devices so toggling a checkbox doesn't
          // pop the soft keyboard (#153). The setNodeMarkup command below
          // needs no focus to run; desktop keeps focus for caret parity.
          if (!isSoftKeyboardDevice()) {
            chain.focus(undefined, { scrollIntoView: false });
          }
          chain
            .command(({ tr }) => {
              const position = getPos();
              if (typeof position !== 'number') {
                return false;
              }
              const currentNode = tr.doc.nodeAt(position);
              tr.setNodeMarkup(position, undefined, {
                ...currentNode?.attrs,
                checked,
              });
              return true;
            })
            .run();
        }
        if (!editor.isEditable && this.options.onReadOnlyChecked) {
          if (!this.options.onReadOnlyChecked(node, checked)) {
            checkbox.checked = !checkbox.checked;
          }
        }
      });

      Object.entries(this.options.HTMLAttributes).forEach(([key, value]) => {
        listItem.setAttribute(key, value as string);
      });
      listItem.dataset.checked = String(node.attrs.checked);
      checkbox.checked = node.attrs.checked;
      checkboxWrapper.append(checkbox, checkboxStyler);
      listItem.append(checkboxWrapper, content);
      Object.entries(HTMLAttributes).forEach(([key, value]) => {
        listItem.setAttribute(key, value as string);
      });

      return {
        dom: listItem,
        contentDOM: content,
        update: (updatedNode: typeof node) => {
          if (updatedNode.type !== this.type) {
            return false;
          }
          listItem.dataset.checked = String(updatedNode.attrs.checked);
          checkbox.checked = updatedNode.attrs.checked;
          updateA11Y();
          return true;
        },
      };
    };
  },
});

/**
 * Fix empty task items that don't survive markdown round-trip.
 *
 * tiptap-markdown serializes empty task items as `- [ ] ` (no text after
 * the checkbox marker). On re-parse, markdown-it-task-lists fails to
 * recognize them because tight-list mode omits the paragraph_open token
 * that isTodoItem() requires. The item renders as a plain <li> with
 * literal `[ ]` text instead of a checkbox.
 *
 * Adding a zero-width space gives the parser the text content it needs.
 * cleanEmptyTaskItems() strips it on save so stored markdown stays clean.
 *
 * Fix: GitHub #88
 */
const ZWS = '​';

export function fixEmptyTaskItems(md: string): string {
  return md.replace(/^(\s*[-*+]\s+\[[ xX]\])[^\S\n]*$/gm, `$1 ${ZWS}`);
}

/** Strip zero-width spaces added by fixEmptyTaskItems before persisting. */
export function cleanEmptyTaskItems(md: string): string {
  return md.replace(
    new RegExp(`^(\\s*[-*+]\\s+\\[[ xX]\\] )${ZWS}`, 'gm'),
    '$1',
  );
}


/**
 * Collapse runs of 3+ newlines between consecutive media lines (images
 * and attachments) down to exactly 2 (one blank line). Prevents empty-
 * paragraph accumulation across save/load cycles.
 *
 * The root cause: markdown-it wraps `![alt](src)` in <p> tags, and
 * TipTap extracts our block-level image node, leaving the now-empty
 * paragraph behind. Each round-trip adds more empty paragraphs that
 * serialize as extra blank lines.
 *
 * Fix: GitHub #68 (empty spaces between attachments after navigating back)
 */
export function collapseMediaGaps(md: string): string {
  // Media line patterns:
  //   Image:      ![...](pn:img/...){width=N align=X} (optional attr suffix)
  //   Attachment:  [...|...|...](pn:file/...)
  const mediaLine =
    '(?:!\\[.*?\\]\\(pn:img\\/[^)]+\\)(?:\\{[^}\\n]*\\})?|\\[.*?\\|.*?\\|.*?\\]\\(pn:file\\/[^)]+\\))';
  return md.replace(
    new RegExp(`(${mediaLine})\\n{3,}(?=${mediaLine})`, 'g'),
    '$1\n\n',
  );
}

/**
 * When the user copies text whose selection sits entirely inside a single
 * code block, write the raw text to the clipboard instead of letting
 * tiptap-markdown serialize it as markdown. Prevents `[user@host](mailto:...)`
 * and friends leaking into pasted CLI snippets. Normal prose selections fall
 * through to the default markdown serializer.
 *
 * Spec: ops/docs/design-decisions.md (code-block plain-text copy)
 */
export const CodeBlockPlainCopy = Extension.create({
  name: 'codeBlockPlainCopy',
  addProseMirrorPlugins() {
    return [
      new Plugin({
        key: new PluginKey('codeBlockPlainCopy'),
        props: {
          handleDOMEvents: {
            copy(view, event) {
              const { from, to, $from, $to, empty } = view.state.selection;
              if (empty) return false;
              if (
                $from.parent.type.name !== 'codeBlock' ||
                $to.parent.type.name !== 'codeBlock' ||
                $from.parent !== $to.parent
              ) {
                return false;
              }
              const text = view.state.doc.textBetween(from, to, '\n');
              event.clipboardData?.setData('text/plain', text);
              event.clipboardData?.setData('text/html', text);
              event.preventDefault();
              return true;
            },
          },
        },
      }),
    ];
  },
});

/**
 * Code block with a hover-revealed "Copy" button in the top-right. On
 * touch devices (`@media (hover: none)`) the button is always visible
 * since there is no hover state to reveal it. Click writes the block's
 * raw text to the clipboard via `navigator.clipboard.writeText`. We mark
 * the button `contenteditable="false"` and stop pointer events so
 * ProseMirror doesn't try to manage it as content or steal the click.
 *
 * Spec: ops/docs/design-decisions.md (code-block copy button)
 *
 * Base is CodeBlockLowlight (same node name `codeBlock`, so markdown
 * round-trip and toggleCodeBlockSmart are unchanged): its ProseMirror
 * plugin decorates the content with hljs token spans, which our custom
 * node view's contentDOM receives like any other decoration. Token
 * colors live in index.css (one bright-on-dark palette - the code panel
 * is dark in both themes). `common` registers the ~37 stock hljs
 * grammars; the fence's language string picks one, anything unknown
 * falls back to plain text.
 */
export const lowlight = createLowlight(common);

export const CodeBlockWithCopy = CodeBlockLowlight.extend({
  addNodeView() {
    return ({ node }: NodeViewRendererProps) => {
      const pre = document.createElement('pre');
      pre.className = 'pn-codeblock group relative';
      const code = document.createElement('code');
      pre.appendChild(code);

      const btn = document.createElement('button');
      btn.type = 'button';
      btn.contentEditable = 'false';
      // Module-level node view - no useTranslation hook here, so the
      // i18n instance is called directly (the non-component pattern
      // from i18n.ts). Snapshot at node-view creation; a language
      // switch re-labels on the next note open.
      btn.textContent = i18n.t('editor:codeBlock.copy');
      btn.className =
        'pn-codeblock-copy absolute top-2 end-2 px-2 py-0.5 text-xs rounded ' +
        'bg-neutral-700/80 text-neutral-100 hover:bg-neutral-700 ' +
        'opacity-0 group-hover:opacity-100 transition ' +
        '[@media(hover:none)]:opacity-100';
      btn.addEventListener('mousedown', (e) => e.preventDefault());
      btn.addEventListener('click', async (e) => {
        e.preventDefault();
        e.stopPropagation();
        try {
          await navigator.clipboard.writeText(node.textContent);
          btn.textContent = i18n.t('editor:codeBlock.copied');
        } catch {
          btn.textContent = i18n.t('editor:codeBlock.copyFailed');
        }
        window.setTimeout(() => { btn.textContent = i18n.t('editor:codeBlock.copy'); }, 1500);
      });
      pre.appendChild(btn);

      return { dom: pre, contentDOM: code };
    };
  },
});

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
      new InputRule({
        find: /(?<!\$)\$([^$\n]+?)\$$/,
        handler: ({ state, range, match }) => {
          const latex = match[1];
          state.tr.replaceWith(range.from, range.to, this.type.create({ latex }));
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
          state: { write: (s: string) => void; closeBlock: (n: unknown) => void },
          node: { attrs: { latex?: string } },
        ) {
          state.write('$$' + (node.attrs.latex ?? '') + '$$');
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
 * the same escape hatch textStyleCss above uses for color/size/family. A
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

/**
 * Smart code-block toggle for the toolbar button.
 *
 * TipTap's stock `toggleCodeBlock` runs `setBlockType` per textblock, so a
 * multi-line selection becomes one code block PER LINE instead of a single
 * block (bug #142). This helper merges the selected textblocks into one code
 * block whose lines are joined by `\n` - matching how a pasted script looks.
 * It is symmetric: toggling off a multi-line code block splits it back into
 * one paragraph per line.
 *
 * Falls back to the default command when there is nothing to merge (single
 * block / partial selection) or when the selection contains a non-textblock
 * node (image, table, blockquote, list), so those cases are unchanged.
 *
 * Spec: ops/docs/design-decisions.md (code-block multi-line merge, #142)
 */
export function toggleCodeBlockSmart(editor: TipTapEditor) {
  const { state } = editor;
  const { schema, selection, doc } = state;
  const { $from, $to } = selection;
  const codeBlockType = schema.nodes['codeBlock']!;
  const paragraphType = schema.nodes['paragraph']!;
  const headingType = schema.nodes['heading'];

  const isTextBlock = (type: typeof paragraphType) =>
    type === paragraphType || type === headingType;

  // Toggle OFF: selection sits inside a single code block. Split it back into
  // one paragraph per line so the line breaks survive the round trip (the
  // default command would collapse them into a single paragraph).
  if ($from.parent.type === codeBlockType && $from.parent === $to.parent) {
    const from = $from.before();
    const to = $from.after();
    const lines = $from.parent.textContent.split('\n');
    const paragraphs = lines.map((line) =>
      paragraphType.create(null, line ? schema.text(line) : undefined),
    );
    const tr = state.tr.replaceWith(from, to, paragraphs);
    editor.view.dispatch(tr.scrollIntoView());
    editor.view.focus();
    return;
  }

  // Toggle ON: gather the top-level textblocks the selection touches.
  let mergeFrom = -1;
  let mergeTo = -1;
  const lines: string[] = [];
  let bail = false;
  doc.forEach((node, offset) => {
    if (bail) return;
    const intersects = offset < selection.to && offset + node.nodeSize > selection.from;
    if (!intersects) return;
    if (isTextBlock(node.type)) {
      if (mergeFrom === -1) mergeFrom = offset;
      mergeTo = offset + node.nodeSize;
      lines.push(node.textContent);
    } else {
      bail = true;
    }
  });

  // Nothing to merge (single block, partial selection) or a non-text node is
  // in range: defer to the stock command so behaviour is unchanged.
  if (bail || lines.length < 2) {
    editor.chain().focus().toggleCodeBlock().run();
    return;
  }

  const text = lines.join('\n');
  const codeNode = codeBlockType.create(null, text ? schema.text(text) : undefined);
  const tr = state.tr.replaceRangeWith(mergeFrom, mergeTo, codeNode);
  tr.setSelection(
    TextSelection.create(tr.doc, mergeFrom + 1, mergeFrom + 1 + text.length),
  );
  editor.view.dispatch(tr.scrollIntoView());
  editor.view.focus();
}

/**
 * Ensures the document always ends with an empty paragraph so the user
 * can click/tap below block nodes (images, code blocks, tables) to
 * continue typing. Without this, a terminal image swallows the full
 * width and there's no insertion point after it.
 */
export const TrailingParagraph = Extension.create({
  name: 'trailingParagraph',
  addProseMirrorPlugins() {
    return [
      new Plugin({
        key: new PluginKey('trailingParagraph'),
        appendTransaction(_transactions, _oldState, newState) {
          const { doc, schema } = newState;
          const lastNode = doc.lastChild;
          if (lastNode && lastNode.type.name !== 'paragraph') {
            return newState.tr.insert(
              doc.content.size,
              schema.nodes['paragraph']!.create(),
            );
          }
          return null;
        },
      }),
    ];
  },
});

/*
 * There is deliberately no leading-edge mirror of TrailingParagraph.
 *
 * One existed (`LeadingParagraph`): it forced an empty paragraph in front of a
 * note whose first block was an image, table or quote, because none of those
 * leaves a line to click above. The cost was that it EDITED the note to fix a
 * UI problem - an empty paragraph serializes as `&nbsp;` (see
 * ParagraphWithMarkdown), so the first line of the user's markdown became a
 * blank one they never typed, which is also why callouts were excluded from it
 * (it would have broken the 1:1 Obsidian round-trip on every `> [!type]` note).
 *
 * Editor.tsx now renders a click row above the body on EVERY note instead, so
 * the insertion point exists whatever the first block is, and the document is
 * only touched when the user actually asks for a line.
 */

/**
 * Removes the empty space markdown parsing leaves around media block nodes
 * (images and attachments) on initial document load.
 *
 * Root cause: markdown-it wraps `![alt](src)` in <p> tags. When
 * TipTap extracts the block-level image node, the now-empty <p>
 * wrapper remains as an empty paragraph. Each save/load cycle
 * accumulates more of these ghost paragraphs.
 *
 * This plugin fires once per editor instance (on the first
 * transaction after initial content parse) and strips empty
 * paragraphs that are sandwiched between media block nodes.
 * It preserves empty paragraphs at the start/end of the doc and
 * between non-media nodes so users can still type between content.
 *
 * It also heals notes written before media blocks closed their markdown block
 * properly (see the closeBlock call in EncryptedAttachment.tsx): those hold a
 * <br> after every media node, either alone in its own two-line-tall paragraph
 * or glued to the front of the text that followed. Only a break directly after
 * media is touched, so a break the user typed anywhere else survives.
 *
 * Fix: GitHub #68 (empty spaces between attachments after navigating back)
 */
const MEDIA_NODE_NAMES = new Set(['image', 'attachment']);

/**
 * A paragraph that carries no visible content: truly empty, or nothing but
 * hard breaks.
 *
 * The hard-break case is the residue of the serializer bug fixed in
 * EncryptedAttachment/EncryptedImage (a media block wrote a bare "\n" instead
 * of closing its block, so markdown-it's breaks:true turned the next line's
 * softbreak into a <br> and ProseMirror left it behind in its own paragraph).
 * Notes saved before that fix still hold one between every pair of media
 * blocks, two lines tall; without this they would keep it until something else
 * edited the note.
 */
function isBlankParagraph(node: ProseMirrorNode): boolean {
  if (node.type.name !== 'paragraph') return false;
  if (node.content.size === 0) return true;
  let blank = true;
  node.content.forEach((child) => {
    if (child.type.name !== 'hardBreak') blank = false;
  });
  return blank;
}

export const MediaGapCleaner = Extension.create({
  name: 'mediaGapCleaner',
  addProseMirrorPlugins() {
    let cleaned = false;
    return [
      new Plugin({
        key: new PluginKey('mediaGapCleaner'),
        appendTransaction(_transactions, _oldState, newState) {
          if (cleaned) return null;
          cleaned = true;

          const { doc, tr } = newState;
          const childCount = doc.childCount;
          if (childCount < 2) return null; // need at least media + something

          // Nearest sibling in either direction that isn't a blank paragraph.
          const mediaBefore = (i: number) => {
            for (let p = i - 1; p >= 0; p--) {
              const prev = doc.child(p);
              if (isBlankParagraph(prev)) continue;
              return MEDIA_NODE_NAMES.has(prev.type.name);
            }
            return false;
          };
          const mediaAfter = (i: number) => {
            for (let n = i + 1; n < childCount; n++) {
              const next = doc.child(n);
              if (isBlankParagraph(next)) continue;
              return MEDIA_NODE_NAMES.has(next.type.name);
            }
            return false;
          };

          // Collect positions of empty paragraphs between media blocks.
          // Walk children, identify runs of [media, empty_p+, media].
          const toDelete: { from: number; to: number }[] = [];
          let offset = 0;
          for (let i = 0; i < childCount; i++) {
            const node = doc.child(i);
            const leadingBreak = node.firstChild?.type.name === 'hardBreak';
            if (isBlankParagraph(node)) {
              if (mediaBefore(i) && mediaAfter(i)) {
                toDelete.push({ from: offset, to: offset + node.nodeSize });
              } else if (leadingBreak && mediaBefore(i)) {
                // A blank paragraph that only media precedes: keep the
                // paragraph (it's the one the user types into after the last
                // chip), drop the break that made it two lines tall.
                toDelete.push({ from: offset + 1, to: offset + 1 + node.firstChild!.nodeSize });
              }
            } else if (
              leadingBreak &&
              node.type.name === 'paragraph' &&
              mediaBefore(i)
            ) {
              // Same pre-fix residue, one block further on: text that followed
              // a media block was glued onto its line, so it came back with a
              // leading <br> instead of a paragraph split. Drop just the
              // break - the text is the user's.
              toDelete.push({ from: offset + 1, to: offset + 1 + node.firstChild!.nodeSize });
            }
            offset += node.nodeSize;
          }

          if (toDelete.length === 0) return null;

          // Delete in reverse order to keep earlier positions valid.
          for (let i = toDelete.length - 1; i >= 0; i--) {
            tr.delete(toDelete[i]!.from, toDelete[i]!.to);
          }
          return tr;
        },
      }),
    ];
  },
});

/**
 * Alignments the toolbar offers, in display order.
 *
 * 'left' is pickable but never STORED: choosing it unsets the attribute rather
 * than setting it, and serializeAlignedBlock ignores it if one arrives from
 * imported HTML anyway. Left is what unstyled text already does, so writing
 * `<p style="text-align: left">` would swap a clean paragraph for an HTML blob
 * in the markdown source and change nothing on screen. The accepted trade is
 * that explicit-left is not a state the toolbar can show as active.
 */
export const ALIGNMENT_VALUES = ['left', 'center', 'right', 'justify'] as const;

/**
 * TextAlign with its Mod-Shift-L binding REMOVED.
 *
 * The extension ships four silent shortcuts (Mod-Shift-L/E/R/J) and the L one
 * collides head-on with our own ⌘⇧L, which toggles light/dark mode and has
 * been documented in the hotkeys modal far longer than this extension has
 * existed. The collision is not a race that one side wins: our theme handler
 * is a `window` keydown listener with no editing guard, and ProseMirror's
 * keymap calls preventDefault WITHOUT stopPropagation, so the event ran both -
 * one keypress flipped the theme AND changed the block's alignment.
 *
 * Upstream's binding also set an explicit `left`, which our serializer drops
 * anyway (see ALIGNMENT_VALUES), so the shortcut was writing a state that
 * could not survive a save. Dropping it costs nothing: the popover still
 * offers left, and left means "unset" there.
 *
 * E / R / J are kept exactly as upstream defines them - they collide with
 * nothing of ours, and the browser-level conflicts (hard reload, devtools)
 * were reviewed and accepted, since they only bind while the editor has focus.
 */
/**
 * Selection span (in ProseMirror positions, roughly characters) past which
 * setTextAlign switches to the single-step path below. The stock command
 * dispatches one attr-update step per block; on a select-all over a huge
 * note that bookkeeping dominated - measured 5.5 s for 4,201 blocks where
 * one ReplaceStep over the same blocks dispatches in ~0.95 s (#150).
 */
const BIG_ALIGN_SELECTION_SPAN = 50_000;

export const TextAlignOurLeft = TextAlign.extend({
  addKeyboardShortcuts() {
    // Toggle, never set (upstream only sets): pressing the active
    // alignment's combo again returns the block to the left default, so
    // keyboard-only users can un-align. Mod-Shift-l stays removed - it
    // collides with the app's theme toggle. Decided 2026-08-21 with the
    // hotkey audit; "align left" is these three keys pressed twice.
    return {
      'Mod-Shift-e': () => this.editor.commands.toggleTextAlign('center'),
      'Mod-Shift-r': () => this.editor.commands.toggleTextAlign('right'),
      'Mod-Shift-j': () => this.editor.commands.toggleTextAlign('justify'),
    };
  },
  addCommands() {
    return {
      ...this.parent?.(),
      setTextAlign: (alignment: string) => ({ state, dispatch, commands }: any) => {
        if (!this.options.alignments.includes(alignment)) return false;
        const { from, to } = state.selection;
        // Ordinary selections: one updateAttributes per aligned type, which
        // is upstream's own body - map over the types, reduce with `some`.
        //
        // Copy it EXACTLY when touching this. v0.305.3 added this override
        // for the big-selection path below and wrote `every` here while its
        // comment claimed the small path was stock behavior bit-for-bit. It
        // was not: updateAttributes reports whether it FOUND a node of that
        // type, so with types ['heading', 'paragraph'] any selection without
        // a heading in it - a task item, a bullet, an ordinary paragraph -
        // short-circuited at `heading` and never reached the paragraph.
        // Aligning anything but a heading silently did nothing for three
        // versions. `some` also reports the honest answer: did anything move.
        if (to - from < BIG_ALIGN_SELECTION_SPAN) {
          return this.options.types
            .map((type: string) => commands.updateAttributes(type, { textAlign: alignment }))
            .some(Boolean);
        }
        // Huge selections: rebuild the covered blocks in ONE pass and
        // dispatch a single ReplaceStep. Untouched nodes are returned by
        // identity, so ProseMirror's view diff reuses their DOM instead of
        // redrawing them; overlap semantics mirror nodesBetween (any node
        // intersecting [from, to] of an aligned type gets the attr).
        if (dispatch) {
          const types = new Set<string>(this.options.types);
          const rebuild = (node: ProseMirrorNode, pos: number): ProseMirrorNode => {
            if (node.isText) return node;
            const overlaps = pos + node.nodeSize > from && pos < to;
            if (!overlaps) return node;
            let changed = false;
            const children: ProseMirrorNode[] = [];
            let childPos = pos + 1;
            node.content.forEach((child) => {
              const next = rebuild(child, childPos);
              if (next !== child) changed = true;
              children.push(next);
              childPos += child.nodeSize;
            });
            const aligns = types.has(node.type.name) && node.attrs['textAlign'] !== alignment;
            if (!aligns && !changed) return node;
            const attrs = aligns ? { ...node.attrs, textAlign: alignment } : node.attrs;
            return node.type.create(attrs, changed ? Fragment.from(children) : node.content, node.marks);
          };
          const replacement: ProseMirrorNode[] = [];
          state.doc.forEach((node: ProseMirrorNode, offset: number) => {
            replacement.push(rebuild(node, offset));
          });
          const tr = state.tr.replaceWith(0, state.doc.content.size, replacement);
          // Attr-only changes keep every size, so the original offsets are
          // still valid in the new doc.
          tr.setSelection(TextSelection.create(tr.doc, from, to));
          dispatch(tr);
        }
        return true;
      },
    };
  },
});

/**
 * Serialize a text-aligned block as raw HTML, returning true when it did.
 *
 * Alignment has no markdown representation, and the trick our colored text
 * uses does not transfer: a `<span style>` is INLINE html, which markdown-it
 * passes through while still parsing the markdown around it, but a `<p style>`
 * is a BLOCK html token, and markdown-it stops parsing markdown inside one. So
 * emitting `<p style="text-align: center">**bold**</p>` would round-trip the
 * alignment and lose the bold.
 *
 * Rendering the whole node to HTML instead keeps both: marks come back as
 * `<strong>`/`<a>` tags that the DOM parser reads on load, and TextAlign's own
 * parseHTML picks the alignment back off `element.style.textAlign`. This is
 * the same escape hatch serializeTableToMarkdown already takes for tables that
 * cannot be expressed as a pipe table - the cost is that an aligned block
 * shows as HTML in the markdown source view, which is honest about what it is.
 */
function serializeAlignedBlock(state: any, node: any): boolean {
  const align = node.attrs?.textAlign;
  if (!align || align === 'left') return false;
  state.write(getHTMLFromFragment(Fragment.from(node), node.type.schema));
  state.closeBlock(node);
  return true;
}

/** An alignment that has to be written out. Left is what plain text already does. */
function isStoredAlignment(align: unknown): boolean {
  return typeof align === 'string' && align !== '' && align !== 'left';
}

/**
 * Task list that serializes as raw HTML once one of its items is aligned.
 *
 * serializeAlignedBlock above works because markdown-it reads `<p style>` as
 * an HTML BLOCK, which it only does when the tag starts a line. The first
 * paragraph of a task item never does: it shares the `- [ ] ` marker line, so
 * the tag lands in INLINE context, and a `<p>` inside the item's own paragraph
 * is auto-closed by the HTML parser on the way back in. The item came back as
 * three paragraphs - an empty one, the aligned text, another empty one - so
 * centering a checklist quietly rewrote it into blank lines on the next open.
 *
 * Bullet and ordered items are not affected and stay plain markdown: their
 * content does start the line, so the same `<p style>` is a clean HTML block.
 *
 * Writing the whole list as HTML is the escape hatch tables already take when
 * they cannot be expressed as a pipe table. It costs the list its markdown
 * shape - in the source view and in other apps - which is why it happens only
 * when an item is actually aligned, and never for an ordinary checklist.
 */
export const TaskListWithMarkdown = TaskList.extend({
  addStorage() {
    return {
      markdown: {
        // Deliberately no `parse` key: tiptap-markdown merges its own spec
        // underneath this one, and its parse half is what registers
        // markdown-it-task-lists. Declaring even an empty `parse` here would
        // replace it and turn every checklist back into literal "[ ]" text.
        serialize(this: { editor: TipTapEditor }, state: any, node: ProseMirrorNode) {
          let aligned = false;
          node.forEach((item) => {
            if (isStoredAlignment(item.firstChild?.attrs?.['textAlign'])) aligned = true;
          });
          if (aligned) {
            state.write(getHTMLFromFragment(Fragment.from(node), node.type.schema));
            state.closeBlock(node);
            return;
          }
          // tiptap-markdown's own task-list serializer, verbatim - it borrows
          // the bullet-list one, and overriding `serialize` replaces it.
          const marker = this.editor.storage['markdown'].options.bulletListMarker || '-';
          state.renderList(node, '  ', () => `${marker} `);
        },
      },
    };
  },
});

/**
 * Paragraph with the markdown spec declared the TipTap 3 way, so empty
 * paragraphs survive the markdown round-trip.
 *
 * The default prosemirror-markdown paragraph serializer outputs
 * nothing for empty paragraphs - closeBlock just adds the standard
 * "\n\n" separator, which is indistinguishable from a normal
 * paragraph break. On re-parse, the empty paragraph vanishes.
 *
 * Fix: serialize empty paragraphs as `&nbsp;` so markdown-it
 * creates a paragraph node with NBSP content. The NbspParagraphCleaner
 * plugin strips the NBSP back to a truly empty paragraph on load.
 *
 * HISTORY: before TipTap 3 this spec was monkey-patched into StarterKit's
 * paragraph extension from an onCreate hook. TipTap 3's Extension exposes
 * `storage` as a getter that spreads addStorage() into a FRESH object on
 * every access, so writes to it became silent no-ops and the patch died
 * without a trace (caught 2026-07-16 when empty paragraphs stopped
 * round-tripping in the v3 verification note). Owning the extension and
 * declaring the spec in addStorage is the supported mechanism on both
 * majors; StarterKit registers `paragraph: false` so this is the only
 * paragraph in the schema.
 *
 * Fix: GitHub #101 (empty line spacing removed after reopening notes)
 */
export const ParagraphWithMarkdown = Paragraph.extend({
  addStorage() {
    return {
      markdown: {
        serialize(state: any, node: any) {
          if (serializeAlignedBlock(state, node)) return;
          if (node.content.size === 0) {
            state.write('&nbsp;');
          } else {
            state.renderInline(node);
          }
          state.closeBlock(node);
        },
        parse: {
          // Keep default markdown-it paragraph parsing.
        },
      },
    };
  },
});

/**
 * Heading with the same alignment-aware markdown spec as the paragraph above.
 *
 * Registered standalone (StarterKit gets `heading: false`) purely so it can
 * carry that spec. Without it, `setTextAlign` on a heading would appear to
 * work and then be silently dropped on the next save - alignment that only
 * survives until reload is worse than no alignment at all, because nothing
 * tells the user it was lost.
 */
export const HeadingWithMarkdown = Heading.extend({
  addStorage() {
    return {
      markdown: {
        serialize(state: any, node: any) {
          if (serializeAlignedBlock(state, node)) return;
          state.write(state.repeat('#', node.attrs.level) + ' ');
          state.renderInline(node);
          state.closeBlock(node);
        },
        parse: {
          // Keep default markdown-it heading parsing.
        },
      },
    };
  },
});

/**
 * Override the table markdown serializer so the contents of a table cell
 * survive the markdown round-trip.
 *
 * tiptap-markdown's default table serializer renders each cell with
 * `state.renderInline(cell.firstChild)` but guards it behind
 * `cell.firstChild.textContent.trim()`. An image is an atom block node
 * with no textContent, so an image-only cell serializes as blank - the
 * `pn:img/<uuid>` reference is dropped at save time and the image never
 * appears in HTML / PDF / print export (or after reopening the note).
 *
 * Fix: detect an image cell and emit its `![alt](src){width=N}` markdown
 * directly, and ask `cellHasContent` rather than `textContent` for every
 * other cell. Everything else (text cells, the pipe-vs-HTML structural
 * decision) matches tiptap-markdown's default behavior exactly, so
 * unaffected tables serialize identically to before.
 *
 * Spec: GitHub #105 (image added to table not visible in print/pdf/html export)
 */
function cellHasSpan(cell: any): boolean {
  return cell.attrs.colspan > 1 || cell.attrs.rowspan > 1;
}

function cellsOf(row: any): any[] {
  const cells: any[] = [];
  row.forEach((cell: any) => cells.push(cell));
  return cells;
}

/**
 * Whether a cell holds anything worth writing.
 *
 * `textContent` alone is the wrong question, and it is what tiptap-markdown
 * asks. An inline ATOM carries its content in attributes and reports an empty
 * string, so a cell holding nothing but a note-link or an inline formula
 * measured as empty and was written out as blank: the column emptied itself
 * the first time the note round-tripped through markdown. Same defect as the
 * image case above, one node type further in.
 */
function cellHasContent(cell: any): boolean {
  if (cell.textContent.trim()) return true;
  let found = false;
  cell.descendants((child: any) => {
    if (found) return false;
    if (!child.isText) found = true;
    return !found;
  });
  return found;
}

/**
 * Escape every `|` the cell just wrote, from `from` to the end of the output.
 *
 * An unescaped pipe ENDS the cell, so anything carrying one split the row
 * into an extra column on the way back in: a note-link with a display label
 * (`[[target|label]]`) and a plain text pipe alike. Nothing upstream can do
 * this - prosemirror-markdown's `esc()` does not know it is inside a table,
 * and the node's own serializer does not know either. markdown-it un-escapes
 * `\|` inside a cell before any inline rule runs, so the round trip is stable.
 */
function escapeCellPipes(state: any, from: number): void {
  const written: string = state.out.slice(from);
  if (!written.includes('|')) return;
  state.out = state.out.slice(0, from) + written.replace(/\|/g, '\\|');
}

/** Mirrors tiptap-markdown's isMarkdownSerializable so the pipe-vs-HTML choice is unchanged. */
function tableIsPipeSerializable(node: any): boolean {
  const rows: any[] = [];
  node.forEach((row: any) => rows.push(row));
  const firstRow = rows[0];
  if (!firstRow) return false;
  if (cellsOf(firstRow).some((cell) => cell.type.name !== 'tableHeader' || cellHasSpan(cell) || cell.childCount > 1)) {
    return false;
  }
  if (rows.slice(1).some((row) => cellsOf(row).some((cell) => cell.type.name === 'tableHeader' || cellHasSpan(cell) || cell.childCount > 1))) {
    return false;
  }
  return true;
}

function serializeTableToMarkdown(this: any, state: any, node: any, _parent: any): void {
  // Tables with spans or multi-block cells aren't representable as a GFM
  // pipe table - fall back to HTML, identical to tiptap-markdown's default.
  if (!tableIsPipeSerializable(node)) {
    if (this?.editor?.storage?.markdown?.options?.html ?? true) {
      state.write(getHTMLFromFragment(Fragment.from(node), node.type.schema));
    }
    if (node.isBlock) state.closeBlock(node);
    return;
  }

  state.inTable = true;
  node.forEach((row: any, _p: number, i: number) => {
    state.write('| ');
    row.forEach((col: any, _p2: number, j: number) => {
      if (j) state.write(' | ');
      const cell = col.firstChild;
      const cellStart: number = state.out.length;
      if (cell?.type.name === 'image') {
        const alt = state.esc(cell.attrs.alt || '');
        const widthSuffix =
          cell.attrs.width && cell.attrs.width !== 100 ? `{width=${cell.attrs.width}}` : '';
        state.write(`![${alt}](${cell.attrs.src || ''})${widthSuffix}`);
      } else if (cell && cellHasContent(cell)) {
        state.renderInline(cell);
      }
      escapeCellPipes(state, cellStart);
    });
    state.write(' |');
    state.ensureNewLine();
    if (!i) {
      // Column alignment lives on the header cells' own `align` attr (the
      // tiptap table cell parses it off `text-align` in the style markdown-it
      // writes for `:---:`), and the delimiter row is the only place a pipe
      // table can say it - a bare `---` here silently un-aligned every
      // column on the first edit after an import.
      const delimiterRow = cellsOf(row)
        .map((col) => {
          const align = col.attrs?.['align'];
          return align === 'center' ? ':---:' : align === 'right' ? '---:' : '---';
        })
        .join(' | ');
      state.write(`| ${delimiterRow} |`);
      state.ensureNewLine();
    }
  });
  state.closeBlock(node);
  state.inTable = false;
}

/**
 * Table with our serializer declared in addStorage, replacing the pre-TipTap-3
 * onCreate monkey-patch that died silently when v3 made extension.storage a
 * per-access rebuild (see ParagraphWithMarkdown's HISTORY note; this one was
 * caught the same day when tables started saving as raw HTML instead of pipe
 * tables). Providing only `serialize` is deliberate: tiptap-markdown's
 * getMarkdownSpec merges this over its default table spec, so `parse` is
 * preserved.
 */
export const TableWithMarkdown = Table.extend({
  addStorage() {
    return {
      markdown: {
        serialize: serializeTableToMarkdown,
      },
    };
  },
});

/**
 * Move the selection to the next/previous table cell on Tab/Shift+Tab.
 *
 * Replaces prosemirror-tables' `goToNextCell`, which is broken for cells
 * whose only content is an atom block (an image or attachment). Its landing
 * step uses `TextSelection.between`, which does a text-ONLY search for a
 * caret position; an image-only cell has none, so the search snaps back to
 * the previous text cell and the caret never advances. The command still
 * reports success, so Tab silently appears dead.
 *
 * Here we compute the adjacent cell ourselves (the same map-walk
 * prosemirror-tables uses internally) and land with `Selection.near`, which
 * resolves to a NodeSelection on the atom when the cell holds no text. This
 * makes Tab step onto, and off of, image cells like any other cell.
 *
 * Returns false when there is no adjacent cell (first/last cell of the
 * table), leaving the selection untouched.
 *
 * Spec: GitHub #145 (Tab does not move to next cell when a cell holds an image)
 */
function findAdjacentCellPos($cell: any, dir: number): number | null {
  if (dir < 0) {
    const before = $cell.nodeBefore;
    if (before) return $cell.pos - before.nodeSize;
    for (let row = $cell.index(-1) - 1, rowEnd = $cell.before(); row >= 0; row--) {
      const rowNode = $cell.node(-1).child(row);
      const lastChild = rowNode.lastChild;
      if (lastChild) return rowEnd - 1 - lastChild.nodeSize;
      rowEnd -= rowNode.nodeSize;
    }
    return null;
  }
  if ($cell.index() < $cell.parent.childCount - 1) {
    return $cell.pos + $cell.nodeAfter.nodeSize;
  }
  const table = $cell.node(-1);
  for (let row = $cell.indexAfter(-1), rowStart = $cell.after(); row < table.childCount; row++) {
    const rowNode = table.child(row);
    if (rowNode.childCount) return rowStart + 1;
    rowStart += rowNode.nodeSize;
  }
  return null;
}

export function goToAdjacentCell(editor: TipTapEditor, dir: number): boolean {
  const { state, dispatch } = editor.view;
  let $cell: any;
  try {
    $cell = selectionCell(state);
  } catch {
    return false; // not inside a table cell
  }
  const cellPos = findAdjacentCellPos($cell, dir);
  if (cellPos == null) return false;
  // +1 steps inside the cell; Selection.near lands on the first child -
  // a caret in a paragraph, or a NodeSelection on an atom (image).
  const sel = Selection.near(state.doc.resolve(cellPos + 1), 1);
  dispatch(state.tr.setSelection(sel).scrollIntoView());
  editor.view.focus();
  return true;
}

/**
 * Indent (dir 1) or outdent (dir -1) the list item the cursor sits in,
 * whatever kind of list it is.
 *
 * `sinkListItem` and `liftListItem` take the item's node TYPE, and the Tab
 * handler in Editor.tsx passed a hard-coded 'listItem' - the bullet and
 * numbered item type. Inside a CHECKLIST both commands therefore failed and
 * Tab was a swallowed no-op. Nothing else was missing: TaskItem is
 * configured `nested: true`, TaskListWithMarkdown's serializer already
 * writes the two-space child indent, markdown-it parses it back, and the
 * taskList CSS already renders the levels. There was just no key that
 * reached it, so nested checklists could only be made in the markdown pane.
 *
 * The type is read from the innermost list-item ancestor rather than from
 * `editor.isActive`, because both types can be active at once - a bullet
 * list nested inside a checklist item, or the reverse - and `isActive`
 * cannot say which one the cursor is actually in. Walking out from the
 * cursor always finds the item Tab should move.
 */
export function indentListItem(editor: TipTapEditor, dir: number): boolean {
  const { $from } = editor.state.selection;
  for (let depth = $from.depth; depth > 0; depth--) {
    const name = $from.node(depth).type.name;
    if (name !== 'listItem' && name !== 'taskItem') continue;
    return dir < 0
      ? editor.chain().focus().liftListItem(name).run()
      : editor.chain().focus().sinkListItem(name).run();
  }
  return false;
}

/**
 * Strip non-breaking spaces from paragraphs that contain only NBSP.
 * These markers are added by EmptyParagraphSerializer on save to
 * survive the markdown round-trip. On load, we clean them so the
 * user gets truly empty paragraphs (no invisible characters that
 * interfere with typing).
 *
 * Fires once per editor instance on initial content parse. The
 * mountedRef guard in onUpdate suppresses the resulting onChange,
 * so this cleanup doesn't trigger a re-save.
 *
 * Fix: GitHub #101 (empty line spacing removed after reopening notes)
 */
export const NbspParagraphCleaner = Extension.create({
  name: 'nbspParagraphCleaner',
  addProseMirrorPlugins() {
    let cleaned = false;
    return [
      new Plugin({
        key: new PluginKey('nbspParagraphCleaner'),
        appendTransaction(_transactions, _oldState, newState) {
          if (cleaned) return null;
          cleaned = true;

          const { doc, tr } = newState;
          const toClean: { from: number; to: number }[] = [];
          let offset = 0;
          for (let i = 0; i < doc.childCount; i++) {
            const node = doc.child(i);
            // Only strip paragraphs whose entire content is NBSP text.
            // An inline atom (e.g. a wiki-link) has content.size > 0 but
            // empty textContent, so the old textContent-only check matched
            // a link-only paragraph and deleted the link. Require every
            // child to be a text node made up solely of NBSP.
            if (node.type.name === 'paragraph' && node.content.size > 0) {
              let onlyNbsp = true;
              node.content.forEach((child) => {
                if (!child.isText || child.text!.replace(/\u00a0/g, '').length !== 0) {
                  onlyNbsp = false;
                }
              });
              if (onlyNbsp) {
                toClean.push({ from: offset + 1, to: offset + 1 + node.content.size });
              }
            }
            offset += node.nodeSize;
          }

          if (toClean.length === 0) return null;

          // Delete in reverse order to keep earlier positions valid.
          for (let i = toClean.length - 1; i >= 0; i--) {
            tr.delete(toClean[i]!.from, toClean[i]!.to);
          }
          return tr;
        },
      }),
    ];
  },
});

/**
 * Split mixed bullet/task lists in the parsed markdown DOM before ProseMirror
 * sees them.
 *
 * CommonMark treats list items separated by blank lines as ONE loose list, so
 * markdown like "- plain item / blank line / - [ ] task item" reaches
 * markdown-it as a single <ul>. markdown-it-task-lists then marks the whole
 * list contains-task-list, tiptap-markdown maps it to a taskList node, and the
 * plain <li>s are invalid taskList children (content spec is taskItem+).
 * ProseMirror recovers by pushing them out into a bulletList and fills the
 * now-childless taskList's required content with one empty taskItem: a phantom
 * unchecked checkbox appears above the list, and a later save would persist it
 * as a bare "- [ ] " line. Reachable through imports and hand-written markdown;
 * found via a deliberately pathological note during the markdown-it 14.3.0
 * verification (v0.251.4).
 *
 * The fix runs in tiptap-markdown's parse.updateDOM hook, the same mechanism
 * the library itself uses to tag task lists: partition each mixed <ul> into
 * runs of consecutive same-kind items and emit one homogeneous <ul> per run.
 * Task runs inherit the original list's attributes (class and data-type, so
 * ordering relative to the taskList extension's own hook does not matter);
 * plain runs get a bare <ul> that parses as a bulletList. Homogeneous lists,
 * i.e. every normal task list, are left untouched. Serialization writes the
 * split lists adjacently, CommonMark merges them again on the next load, and
 * this hook re-splits them, so the round trip is stable and no phantom is
 * ever created. Detection keys off the markdown-it-task-lists classes rather
 * than data-type attributes for the same ordering reason.
 */
export const MixedListSplitter = Extension.create({
  name: 'mixedListSplitter',
  addStorage() {
    return {
      markdown: {
        parse: {
          updateDOM(element: HTMLElement) {
            element.querySelectorAll('ul.contains-task-list').forEach((list) => {
              const items = Array.from(list.children);
              const isTask = (li: Element) => li.classList.contains('task-list-item');
              if (items.every(isTask)) return;

              const runs: { task: boolean; items: Element[] }[] = [];
              for (const li of items) {
                const task = isTask(li);
                const last = runs[runs.length - 1];
                if (last && last.task === task) last.items.push(li);
                else runs.push({ task, items: [li] });
              }

              const lists = runs.map((run) => {
                const ul = list.ownerDocument.createElement('ul');
                if (run.task) {
                  for (const attr of Array.from(list.attributes)) {
                    ul.setAttribute(attr.name, attr.value);
                  }
                }
                for (const li of run.items) ul.appendChild(li);
                return ul;
              });
              list.replaceWith(...lists);
            });
          },
        },
      },
    };
  },
});
