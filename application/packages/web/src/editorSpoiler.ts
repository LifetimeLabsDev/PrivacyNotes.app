/**
 * Spoiler text: a mark stored as `||text||` (Discord's syntax, also the one
 * the Obsidian spoiler plugins write) and drawn blurred until it is shown.
 *
 * The blur guards against a glance, not against a reader: the text stays in
 * the document, the clipboard and the accessibility tree, and the app lock
 * is what keeps a note from someone holding the device.
 *
 * A spoiler shows while the selection touches it, so a click that places
 * the caret inside also reveals the text being edited. In a note that
 * cannot be edited, a click toggles it instead. Neither state is stored.
 * Marking a selection is the one exception: the caret goes to the end of
 * the new run and the run stays hidden until the next edit or caret move,
 * so the person sees at once what the mark does.
 *
 * Spec: ops/docs/plans/spoiler-and-copy.md
 */

import { Mark, getMarkRange, markInputRule, markPasteRule, mergeAttributes } from '@tiptap/core';
import { Plugin, PluginKey, TextSelection } from '@tiptap/pm/state';
import type { EditorState } from '@tiptap/pm/state';
import { Decoration, DecorationSet } from '@tiptap/pm/view';

declare module '@tiptap/core' {
  interface Commands<ReturnType> {
    spoiler: {
      toggleSpoiler: () => ReturnType;
    };
  }
}

/** The slice of markdown-it's inline state the two rules below read. */
interface InlineState {
  src: string;
  pos: number;
  posMax: number;
  pending: string;
  push: (type: string, tag: string, nesting: number) => { content: string };
  md: { inline: { tokenize: (state: InlineState) => void } };
}

type InlineRule = (state: InlineState, silent: boolean) => boolean;

interface InlineRuler {
  at: (name: string, fn: InlineRule) => void;
  before: (beforeName: string, name: string, fn: InlineRule) => void;
}

/** A character the opening delimiter may not follow: a pipe or a
 *  backslash, so `|||x|||` and an escaped `\\||` stay text. Letters may
 *  touch it: a spoiler on part of a word saves as `un||sp||ed`, and the
 *  editor must read back every mark it writes. */
const OUTSIDE = /[|\\]/;

/**
 * markdown-it's inline `text` rule consumes every character up to the next
 * one on its terminator list, and `|` is not on it, so a rule keyed on `|`
 * would never run in the middle of a line. This is the same rule with the
 * pipe added; the list is markdown-it's own.
 */
const TERMINATORS = new Set(Array.from('\n!#$%&*+-:<=>@[\\]^_`{}~|', (c) => c.charCodeAt(0)));

function textStopsAtPipe(state: InlineState, silent: boolean): boolean {
  let pos = state.pos;
  while (pos < state.posMax && !TERMINATORS.has(state.src.charCodeAt(pos))) pos++;
  if (pos === state.pos) return false;
  if (!silent) state.pending += state.src.slice(state.pos, pos);
  state.pos = pos;
  return true;
}

/**
 * `||text||` on one line, hugging its delimiters, with no pipe or backslash
 * just outside them. `a || b` stays text because the run may not open on a
 * space. The run between the delimiters is parsed again, so a
 * bold word or a link inside a spoiler survives a reload.
 */
function spoilerRule(state: InlineState, silent: boolean): boolean {
  const { src, pos } = state;
  if (src[pos] !== '|' || src[pos + 1] !== '|') return false;
  if (pos > 0 && OUTSIDE.test(src[pos - 1] ?? '')) return false;
  const start = pos + 2;
  if (start >= state.posMax || /[\s|]/.test(src[start] ?? '')) return false;
  const end = src.indexOf('||', start);
  if (end < 0 || end + 2 > state.posMax) return false;
  if (src.slice(start, end).includes('\n')) return false;
  // A space just inside, or a backslash that escapes the first closing pipe.
  if (/[\s\\]/.test(src[end - 1] ?? '')) return false;
  // After the closing pipes only another pipe counts: a backslash there
  // starts the next token, such as the hard break a spoiler run closes before.
  if (src[end + 2] === '|') return false;
  if (silent) {
    state.pos = end + 2;
    return true;
  }
  state.push('html_inline', '', 0).content = '<span data-spoiler="">';
  const oldMax = state.posMax;
  state.pos = start;
  state.posMax = end;
  state.md.inline.tokenize(state);
  state.pos = end + 2;
  state.posMax = oldMax;
  state.push('html_inline', '', 0).content = '</span>';
  return true;
}

const revealKey = new PluginKey<DecorationSet>('spoilerReveal');
/** True from the moment a selection is marked until the next edit or caret
 *  move, so the new run shows hidden although the caret touches it. */
const hideKey = new PluginKey<boolean>('spoilerHide');

/** The spoiler run around `pos`, or null outside one. */
function spoilerRangeAt(state: EditorState, pos: number): { from: number; to: number } | null {
  const type = state.schema.marks.spoiler;
  if (!type) return null;
  const $pos = state.doc.resolve(pos);
  return getMarkRange($pos, type) ?? (pos > 0 ? getMarkRange(state.doc.resolve(pos - 1), type) ?? null : null);
}

export const Spoiler = Mark.create({
  name: 'spoiler',

  parseHTML() {
    return [
      { tag: 'span[data-spoiler]' },
      // Reddit's rendered spoiler, so a paste from a thread keeps it.
      { tag: 'span.md-spoiler-text' },
    ];
  },

  renderHTML({ HTMLAttributes }) {
    // Two spans: the outer one draws the box, which stays sharp, and the
    // inner one carries the blur, so the box does not smear into a haze.
    return [
      'span',
      mergeAttributes(HTMLAttributes, { 'data-spoiler': '', class: 'pn-spoiler' }),
      ['span', { class: 'pn-spoiler-text' }, 0],
    ];
  },

  addCommands() {
    return {
      toggleSpoiler: () => ({ state, tr, commands }) => {
        const { empty, to } = state.selection;
        const marking = !empty && !state.doc.rangeHasMark(state.selection.from, to, this.type);
        if (!commands.toggleMark(this.name)) return false;
        if (marking) tr.setSelection(TextSelection.create(tr.doc, tr.mapping.map(to))).setMeta(hideKey, true);
        return true;
      },
    };
  },

  addInputRules() {
    return [
      markInputRule({
        // No character before the delimiter in the pattern: TipTap deletes
        // whatever the match holds before its capture group, which only a
        // space survives, and no lookbehind either, which older WebKit
        // cannot parse.
        find: /\|\|([^\s|](?:[^|\n]*[^\s|])?)\|\|$/,
        type: this.type,
      }),
    ];
  },

  // A paste as plain text skips the markdown parse; this turns its ||text||
  // into the mark, as highlight's own paste rule does for ==text==.
  addPasteRules() {
    return [
      markPasteRule({
        find: /\|\|([^\s|](?:[^|\n]*[^\s|])?)\|\|/g,
        type: this.type,
      }),
    ];
  },

  addStorage() {
    return {
      markdown: {
        serialize: {
          open: '||',
          close: '||',
          mixable: true,
          expelEnclosingWhitespace: true,
        },
        parse: {
          setup(md: { inline: { ruler: InlineRuler } }) {
            md.inline.ruler.at('text', textStopsAtPipe);
            md.inline.ruler.before('text', 'pnSpoiler', spoilerRule);
          },
        },
      },
    };
  },

  addProseMirrorPlugins() {
    const editor = this.editor;
    return [
      new Plugin<boolean>({
        key: hideKey,
        state: {
          init: () => false,
          apply: (tr, hidden) => (tr.getMeta(hideKey) ? true : hidden && !tr.docChanged && !tr.selectionSet),
        },
      }),
      new Plugin<DecorationSet>({
        key: revealKey,
        // The runs a click has shown in a note that cannot be edited.
        state: {
          init: () => DecorationSet.empty,
          apply(tr, set) {
            const toggle = tr.getMeta(revealKey) as { from: number; to: number } | undefined;
            let next = set.map(tr.mapping, tr.doc);
            if (toggle) {
              const found = next.find(toggle.from, toggle.to);
              next = found.length
                ? next.remove(found)
                : next.add(tr.doc, [Decoration.inline(toggle.from, toggle.to, { class: 'pn-spoiler-on' })]);
            }
            return next;
          },
        },
        props: {
          decorations(state) {
            const shown = revealKey.getState(state) ?? DecorationSet.empty;
            // A click in a read-only note also moves the selection, so the
            // selection reveals only while the note can be edited; there the
            // click toggle below is the only door.
            if (!editor.isEditable || hideKey.getState(state)) return shown;
            const { from, to } = state.selection;
            const touched = spoilerRangeAt(state, from);
            const extra: Decoration[] = [];
            if (touched) extra.push(Decoration.inline(touched.from, touched.to, { class: 'pn-spoiler-on' }));
            if (to !== from) {
              const type = state.schema.marks.spoiler;
              state.doc.nodesBetween(from, to, (node, pos) => {
                if (type && node.isText && type.isInSet(node.marks)) {
                  const run = spoilerRangeAt(state, pos + 1);
                  if (run) extra.push(Decoration.inline(run.from, run.to, { class: 'pn-spoiler-on' }));
                }
              });
            }
            return extra.length ? shown.add(state.doc, extra) : shown;
          },
          handleClick(view, pos, event) {
            if (view.editable || event.button !== 0) return false;
            const run = spoilerRangeAt(view.state, pos);
            if (!run) return false;
            view.dispatch(view.state.tr.setMeta(revealKey, run));
            return true;
          },
        },
      }),
    ];
  },
});
