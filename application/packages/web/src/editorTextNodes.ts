import { Paragraph } from '@tiptap/extension-paragraph';
import { Heading } from '@tiptap/extension-heading';
import { HardBreak } from '@tiptap/extension-hard-break';
import { Text } from '@tiptap/extension-text';
import { getHTMLFromFragment } from '@tiptap/core';
import { Fragment, type Node as ProseMirrorNode } from '@tiptap/pm/model';
import { KEY_OS } from './shortcutMatch';
import { serializeAlignedBlock } from './editorAlignment';

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
function breaksOnly(node: ProseMirrorNode): boolean {
  let only = node.childCount > 0;
  node.forEach((child) => {
    if (child.type.name !== 'hardBreak') only = false;
  });
  return only;
}

/**
 * Markdown has no indent for a paragraph: markdown-it trims the spaces at the
 * start of a paragraph and after a line break, so a typed indent was lost on
 * the next load (GitHub #273). The run at the start of the paragraph is
 * written as `&nbsp;`, because markdown-it's trim also removes a literal
 * non-breaking space there. After a line break a literal one is enough, since
 * the break rule trims only plain spaces and tabs. Both load back as
 * non-breaking spaces, which this also matches, so the indent survives every
 * later save.
 *
 * A run of spaces inside a line is collapsed to one by the HTML step of the
 * load (GitHub #402). It is written as one plain space, which keeps a wrap
 * point, and literal non-breaking spaces for the rest, which HTML keeps.
 * Inline code is left alone: its text is copied out exactly as written.
 */
const LEADING_INDENT = /^[ \u00a0]+/;
const INNER_RUN = /[ \u00a0]{2,}/g;

function keepInnerRuns(child: ProseMirrorNode, text: string): ProseMirrorNode {
  if (child.marks.some((m) => m.type.spec.code)) return child.type.schema.text(text, child.marks);
  const kept = text.replace(INNER_RUN, (run) => ' ' + '\u00a0'.repeat(run.length - 1));
  return child.type.schema.text(kept, child.marks);
}

function renderIndentedInline(state: any, node: ProseMirrorNode): void {
  let lead = 0;
  let lineStart = true;
  const children: ProseMirrorNode[] = [];
  node.forEach((child, _offset, index) => {
    if (child.isText) {
      const run = lineStart ? LEADING_INDENT.exec(child.text!)?.[0].length ?? 0 : 0;
      if (run > 0) {
        if (index === 0) lead = run;
        else children.push(child.type.schema.text('\u00a0'.repeat(run), child.marks));
      }
      const rest = child.text!.slice(run);
      if (rest) children.push(keepInnerRuns(child, rest));
      lineStart = false;
      return;
    }
    lineStart = child.type.name === 'hardBreak';
    children.push(child);
  });
  // The write runs even when it adds nothing, so the pending block separator
  // and any quote prefix are out before the first mark opens. tiptap-markdown
  // records where a bold, italic, strike or highlight run starts before that
  // flush, and its whitespace trim would otherwise eat the `> ` prefix and
  // save a callout's first body line outside the callout.
  state.write('&nbsp;'.repeat(lead));
  state.renderInline(node.copy(Fragment.fromArray(children)));
}

export const ParagraphWithMarkdown = Paragraph.extend({
  addStorage() {
    return {
      markdown: {
        serialize(state: any, node: any, parent: any, index: number) {
          if (serializeAlignedBlock(state, node)) return;
          // The empty line kept in front of the footnote section is the
          // editor's, not the note's: it writes nothing.
          // `parent` is a Fragment when a copy serializes a selection.
          const next = parent && index + 1 < parent.childCount ? parent.child(index + 1) : null;
          if (node.content.size === 0 && next?.type.name === 'footnotes') return;
          if (node.content.size === 0) {
            state.write('&nbsp;');
          } else if (breaksOnly(node)) {
            // A hard break writes nothing unless text follows it, so a
            // paragraph of breaks alone saved as nothing and drew as N + 1
            // lines. It is written as that many empty paragraphs instead.
            for (let i = 0; i <= node.childCount; i++) {
              if (i > 0) state.closeBlock(node);
              state.write('&nbsp;');
            }
          } else {
            renderIndentedInline(state, node);
          }
          state.closeBlock(node);
        },
        parse: {
          // A tight list item's paragraph is written without its <p>, so its
          // text keeps markdown-it's newline when a nested list or other
          // block follows it. A load collapses that newline; a paste keeps
          // whitespace and would turn it into a line break at the end of the item.
          updateDOM(element: HTMLElement) {
            element.querySelectorAll('li').forEach((item) => {
              item.childNodes.forEach((child) => {
                const next = child.nextSibling;
                if (child.nodeType === Node.TEXT_NODE && next instanceof HTMLElement && NESTED_BLOCK_TAGS.has(next.tagName)) {
                  child.textContent = child.textContent!.replace(/\n$/, '');
                }
              });
            });
          },
        },
      },
    };
  },
});

const NESTED_BLOCK_TAGS = new Set(['UL', 'OL', 'P', 'PRE', 'BLOCKQUOTE', 'DIV', 'TABLE', 'H1', 'H2', 'H3', 'H4', 'H5', 'H6', 'HR']);

/**
 * Hard break with tiptap-markdown's own spec, plus one write after the break:
 * it puts the next line's quote prefix out before that line's first mark
 * opens, for the same reason renderIndentedInline writes before rendering.
 * Without it, a Shift+Enter line inside a callout that opens with bold would
 * save outside the callout. A trailing break still writes nothing, and a break in a
 * table cell stays inline HTML, both as the library does it.
 */
const ONE_LINE_PARENTS = new Set(['heading', 'calloutTitle']);

export const HardBreakWithMarkdown = HardBreak.extend({
  addStorage() {
    return {
      markdown: {
        serialize(state: any, node: any, parent: any, index: number) {
          for (let i = index + 1; i < parent.childCount; i++) {
            if (parent.child(i).type !== node.type) {
              // A table row, a heading and a callout title each live on one
              // markdown line, so a break inside them stays inline HTML.
              if (state.inTable || ONE_LINE_PARENTS.has(parent.type.name)) {
                state.write(getHTMLFromFragment(Fragment.from(node), node.type.schema));
              } else {
                state.write('\\\n');
                state.write('');
              }
              return;
            }
          }
        },
        parse: {
          // Keep default markdown-it break parsing.
        },
      },
    };
  },
});

/**
 * prosemirror-markdown's `esc`, byte for byte, except where its output read
 * back as something else:
 * - An underscore run stays raw only between two letters or digits. The
 *   library judged each underscore by its neighbours and counted `_` as a word
 *   character, so `__init__` saved as `\__init_\_` and reloaded as an italic.
 * - `1) ` opens an ordered list just as `1. ` does, so it is escaped at a line
 *   start too. So does a line that is only `+`, `1.` or `1)`: an empty item.
 * - A literal entity such as `&amp;` keeps its ampersand, which markdown would
 *   otherwise decode.
 */
const ENTITY = /&(?=#\d+;|#x[0-9a-f]+;|[a-z][a-z0-9]*;)/gi;
const ALNUM = /[A-Za-z0-9]/;

function escapeMarkdownText(str: string, startOfLine: boolean): string {
  str = str.replace(ENTITY, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  str = str.replace(/[`*\\~[\]]/g, '\\$&');
  str = str.replace(/_+/g, (run, i: number) =>
    ALNUM.test(str[i - 1] ?? '') && ALNUM.test(str[i + run.length] ?? '') ? run : run.replace(/_/g, '\\_'),
  );
  if (startOfLine) {
    str = str
      .replace(/^(\+(?=[ ]|$)|[-*>])/, '\\$&')
      .replace(/^(\s*)(#{1,6})(\s|$)/, '$1\\$2$3')
      .replace(/^(\s*\d+)([.)])\s/, '$1\\$2 ')
      .replace(/^(\s*\d+)([.)])$/, '$1\\$2');
  }
  return str;
}

export const TextWithMarkdown = Text.extend({
  addStorage() {
    return {
      markdown: {
        // MarkdownSerializerState.text with the escape above in place of `esc`.
        serialize(state: any, node: ProseMirrorNode) {
          const lines = node.text!.split('\n');
          for (let i = 0; i < lines.length; i++) {
            state.write();
            state.out += escapeMarkdownText(lines[i]!, state.atBlockStart);
            if (i !== lines.length - 1) state.out += '\n';
          }
        },
        parse: {
          // Handled by markdown-it.
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
  // TipTap's own Mod-Alt-1 to 6 stays; off Apple, Ctrl+Shift+1 to 6 is the
  // key that works where AltGr+digit types a character.
  // Spec: ops/docs/archive/keyboard-shortcuts.md (decision D11)
  addKeyboardShortcuts() {
    const keys = { ...this.parent?.() };
    if (KEY_OS === 'pc') {
      for (const level of this.options.levels) {
        keys[`Mod-Shift-${level}`] = () => this.editor.commands.toggleHeading({ level });
      }
    }
    return keys;
  },
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
