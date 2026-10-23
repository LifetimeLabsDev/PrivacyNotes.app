/**
 * Inline code copies on the same click that opens a link: Cmd (Ctrl off a
 * Mac) with the click while editing, a plain click or tap when the note
 * cannot be edited. A plain click while editing keeps placing the caret,
 * because code is text a person edits far more often than a link.
 *
 * The whole run is copied, not the word under the pointer: a path or a
 * command is the unit a reader wants out of the note.
 *
 * Spec: ops/docs/archive/spoiler-and-copy.md
 */

import { Extension, getMarkRange } from '@tiptap/core';
import { Plugin, PluginKey } from '@tiptap/pm/state';
import type { EditorState } from '@tiptap/pm/state';
import i18n from './i18n';
import { isMac, isOpenLinkModifier } from './editorLinks';

/** The text of the inline code run around `pos`, or null outside one. */
export function inlineCodeTextAt(state: EditorState, pos: number): string | null {
  const type = state.schema.marks.code;
  if (!type) return null;
  const range = getMarkRange(state.doc.resolve(pos), type);
  return range ? state.doc.textBetween(range.from, range.to) : null;
}

/** The hover hint on inline code. It names the modifier click, which copies
 *  in every note; a plain click copies only where the note cannot be edited. */
export function inlineCodeHint(): string {
  return i18n.t('editor:inlineCode.copyHint', { key: isMac() ? 'Cmd' : 'Ctrl' });
}

/** A short "Copied" label at the pointer, gone after a moment. */
function flashCopied(x: number, y: number): void {
  const bubble = document.createElement('div');
  bubble.className = 'pn-copy-bubble';
  bubble.textContent = i18n.t('editor:inlineCode.copied');
  bubble.style.left = `${x}px`;
  bubble.style.top = `${y}px`;
  document.body.appendChild(bubble);
  window.setTimeout(() => bubble.remove(), 1200);
}

export const InlineCodeCopy = Extension.create({
  name: 'inlineCodeCopy',

  addProseMirrorPlugins() {
    return [
      new Plugin({
        key: new PluginKey('inlineCodeCopy'),
        props: {
          handleClick(view, pos, event) {
            if (event.button !== 0) return false;
            if (view.editable && !isOpenLinkModifier(event)) return false;
            const text = inlineCodeTextAt(view.state, pos);
            if (text === null) return false;
            void navigator.clipboard.writeText(text).then(
              () => flashCopied(event.clientX, event.clientY),
              () => {},
            );
            return true;
          },
        },
      }),
    ];
  },
});
