/**
 * "Add a line" in the gap between two top-level blocks unless both are lines
 * of text: a callout under a paragraph, two code blocks, a table above an
 * image, and so on. A click there puts the caret inside the next block, or
 * a gap cursor nobody sees coming, so the pointer has no other way to start a
 * paragraph between them. A divider's line is 1px high, so a click aimed
 * near it would land in the next block too.
 *
 * Hovering such a gap shows the same hint as the "Add a line at the top" zone
 * in Editor.tsx; a click or a tap adds an empty paragraph there with the caret
 * in it. A touch screen has no hover, so the gap is a tap target only. A click
 * within a few px of a divider's line selects the divider, so Delete removes it.
 *
 * Only top-level blocks are read: the body of a callout or a list item is
 * left to the browser.
 */

import { Extension } from '@tiptap/core';
import type { Node as PMNode } from '@tiptap/pm/model';
import { NodeSelection, Plugin, PluginKey, TextSelection, type EditorState, type Transaction } from '@tiptap/pm/state';
import type { EditorView } from '@tiptap/pm/view';
import i18n from './i18n';

/** A gap thinner than this is widened around its middle, so a list or an
 *  image gap (9px) is still a target a finger can hit. */
const MIN_BAND_PX = 16;

const PLUS_ICON =
  '<svg width="14" height="14" viewBox="0 0 256 256" fill="currentColor" aria-hidden="true"><path d="M224,128a8,8,0,0,1-8,8H136v80a8,8,0,0,1-16,0V136H40a8,8,0,0,1,0-16h80V40a8,8,0,0,1,16,0v80h80A8,8,0,0,1,224,128Z"/></svg>';

function isLine(node: PMNode): boolean {
  return node.type.name === 'paragraph' || node.type.name === 'heading';
}

/** Whether the gap between two touching top-level blocks gets the helper:
 *  every gap except one between two lines, where a click already lands at
 *  the end or the start of a line. The footnotes section at the foot of a
 *  note is managed by the editor, so no line goes next to it. */
export function gapTakesLine(above: PMNode, below: PMNode): boolean {
  if (above.type.name === 'footnotes' || below.type.name === 'footnotes') return false;
  return !(isLine(above) && isLine(below));
}

/** Insert an empty paragraph at `pos` (a top-level boundary) with the caret in it. */
export function addLineAt(state: EditorState, pos: number): Transaction | null {
  const paragraph = state.schema.nodes['paragraph']?.create();
  if (!paragraph) return null;
  const tr = state.tr.insert(pos, paragraph);
  return tr.setSelection(TextSelection.create(tr.doc, pos + 1)).scrollIntoView();
}

interface Gap {
  pos: number;
  top: number;
  bottom: number;
}

/** What a pointer at a viewport point would act on: a divider's line (with
 *  a few px of slack, since the line itself is 1px), a helper gap, or neither. */
type Target = { divider: number } | { gap: Gap } | null;

const DIVIDER_SLACK_PX = 4;

function targetAt(view: EditorView, x: number, y: number): Target {
  const box = view.dom.getBoundingClientRect();
  if (x < box.left || x > box.right) return null;
  const hit = view.posAtCoords({ left: x, top: y });
  if (!hit) return null;
  const { doc } = view.state;
  // Only the blocks next to the hit can border the gap under the pointer.
  const index = doc.resolve(hit.pos).index(0);
  const first = Math.max(1, index - 1);
  const last = Math.min(doc.childCount - 1, index + 1);
  let start = 0;
  for (let i = 0; i < first - 1; i++) start += doc.child(i).nodeSize;
  for (let i = first - 1; i <= last; i++) {
    const node = doc.child(i);
    const dom = view.nodeDOM(start);
    if (node.type.name === 'horizontalRule' && dom instanceof HTMLElement) {
      const r = dom.getBoundingClientRect();
      if (y >= r.top - DIVIDER_SLACK_PX && y <= r.bottom + DIVIDER_SLACK_PX) return { divider: start };
    }
    start += node.nodeSize;
  }
  const gap = gapAt(view, first, last, y);
  return gap ? { gap } : null;
}

/** The helper gap at height `y` among the boundaries before children
 *  `first` to `last`, or null. */
function gapAt(view: EditorView, first: number, last: number, y: number): Gap | null {
  const { doc } = view.state;
  let pos = 0;
  for (let i = 0; i < first; i++) pos += doc.child(i).nodeSize;
  for (let i = first; i <= last; i++) {
    const above = doc.child(i - 1);
    const below = doc.child(i);
    if (gapTakesLine(above, below)) {
      const a = view.nodeDOM(pos - above.nodeSize);
      const b = view.nodeDOM(pos);
      if (a instanceof HTMLElement && b instanceof HTMLElement) {
        let top = a.getBoundingClientRect().bottom;
        let bottom = b.getBoundingClientRect().top;
        if (bottom - top < MIN_BAND_PX) {
          const mid = (top + bottom) / 2;
          top = mid - MIN_BAND_PX / 2;
          bottom = mid + MIN_BAND_PX / 2;
        }
        if (y >= top && y <= bottom) return { pos, top, bottom };
      }
    }
    pos += below.nodeSize;
  }
  return null;
}

function buildHint(): HTMLElement {
  const hint = document.createElement('div');
  hint.className = 'pn-add-line-hint pointer-events-none fixed z-[5] flex -translate-y-1/2 items-center gap-1.5';
  hint.setAttribute('aria-hidden', 'true');
  const text = document.createElement('span');
  text.className = 'flex items-center gap-1 text-xs leading-none text-accent';
  text.innerHTML = PLUS_ICON;
  text.append(i18n.t('editor:addLine.add'));
  const line = document.createElement('span');
  line.className = 'h-px flex-1 bg-accent/40';
  hint.append(text, line);
  hint.style.display = 'none';
  return hint;
}

export const AddLineBetweenBlocks = Extension.create({
  name: 'addLineBetweenBlocks',

  addProseMirrorPlugins() {
    let hint: HTMLElement | null = null;
    const hide = () => {
      if (hint) hint.style.display = 'none';
    };

    return [
      new Plugin({
        key: new PluginKey('addLineBetweenBlocks'),
        view() {
          hint = buildHint();
          document.body.appendChild(hint);
          window.addEventListener('scroll', hide, true);
          return {
            update: hide,
            destroy() {
              window.removeEventListener('scroll', hide, true);
              hint?.remove();
              hint = null;
            },
          };
        },
        props: {
          handleDOMEvents: {
            mousemove(view, event) {
              if (!hint) return false;
              const target = view.editable ? targetAt(view, event.clientX, event.clientY) : null;
              if (!target || !('gap' in target)) {
                hide();
                return false;
              }
              const { gap } = target;
              const box = view.dom.getBoundingClientRect();
              hint.style.display = 'flex';
              hint.style.left = `${box.left}px`;
              hint.style.width = `${box.width}px`;
              hint.style.top = `${(gap.top + gap.bottom) / 2}px`;
              return false;
            },
            mouseleave() {
              hide();
              return false;
            },
            mousedown(view, event) {
              if (event.button !== 0 || !view.editable) return false;
              const target = targetAt(view, event.clientX, event.clientY);
              if (!target) return false;
              const tr = 'gap' in target
                ? addLineAt(view.state, target.gap.pos)
                : view.state.tr.setSelection(NodeSelection.create(view.state.doc, target.divider));
              if (!tr) return false;
              event.preventDefault();
              view.dispatch(tr);
              view.focus();
              return true;
            },
          },
        },
      }),
    ];
  },
});
