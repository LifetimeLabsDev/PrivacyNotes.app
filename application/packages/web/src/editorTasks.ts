import { TASK_CHECK_PATH } from './ui/TaskCheckbox';
import type { Editor as TipTapEditor } from '@tiptap/react';
import TaskItem, { type TaskItemOptions } from '@tiptap/extension-task-item';
import TaskList from '@tiptap/extension-task-list';
import { Extension, InputRule, getHTMLFromFragment, type NodeViewRendererProps } from '@tiptap/core';
import { Fragment, type Node as ProseMirrorNode } from '@tiptap/pm/model';
import { Plugin, PluginKey, NodeSelection, type Transaction } from '@tiptap/pm/state';
import { Decoration, DecorationSet } from '@tiptap/pm/view';
import { isSoftKeyboardDevice, suppressSoftKeyboard } from './softKeyboard';
import { isStoredAlignment } from './editorAlignment';
import { dragCard, kanbanCardOf, markCardGrip, openCardMenu } from './kanbanDrag';

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
          // One chain: a separate command after it ran against the document
          // before the task list existed, so "[x] " made an unticked task.
          const checked = match[1] === 'x' || match[1] === 'X';
          chain().deleteRange(range).toggleTaskList().updateAttributes('taskItem', { checked }).run();
        },
      }),
    ];
  },
});

/**
 * Moves the task item at `pos` to sit right after the last open task among
 * its siblings, or to the top of the list when no other task is open. A
 * checked task lands at the top of the done group and an unchecked one at
 * the end of the open group. The move is in the document, not only on
 * screen, so the caret, a selection, the markdown and an export all see the
 * order the reader sees. Returns the item's new position, or null when it is
 * already in place.
 */
function moveTaskToGroupEdge(tr: Transaction, pos: number): number | null {
  const $pos = tr.doc.resolve(pos);
  const list = $pos.parent;
  const self = $pos.index();
  const item = list.child(self);
  let target = $pos.start();
  let offset = $pos.start();
  list.forEach((child, _, index) => {
    offset += child.nodeSize;
    if (index !== self && !child.attrs.checked) target = offset;
  });
  if (target === pos || target === pos + item.nodeSize) return null;
  tr.delete(pos, pos + item.nodeSize);
  const insertAt = tr.mapping.map(target);
  tr.insert(insertAt, item);
  return insertAt;
}

/**
 * Slides a moved task from where it was to where it is, so the reader sees
 * where the task went instead of a different task under the pointer.
 */
function slideIn(dom: Node | null, topBefore: number) {
  if (!(dom instanceof HTMLElement) || typeof dom.animate !== 'function') return;
  if (window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) return;
  const dy = topBefore - dom.getBoundingClientRect().top;
  if (!dy) return;
  dom.animate(
    [{ transform: `translateY(${dy}px)` }, { transform: 'none' }],
    { duration: 180, easing: 'ease-out' },
  );
}

/**
 * Plays the tick's draw on the task that moved. ProseMirror keeps the
 * clicked item's DOM where it was and hands it to the task that slides into
 * that place, so the CSS draw runs there, on a task that was already ticked,
 * and the moved task arrives drawn. Finish the stray draw and run the same
 * one, the `.pn-task-checkbox:checked` transition, on the moved task.
 * Spec: ops/docs/design-decisions.md (Checkbox feedback)
 */
function drawMovedTick(clicked: HTMLInputElement, moved: Node | null) {
  if (!(moved instanceof HTMLElement)) return;
  const box = moved.querySelector<HTMLInputElement>(':scope > label > .pn-task-checkbox');
  if (!box || box === clicked || !box.checked) return;
  const stray = clicked.parentElement?.querySelector('.pn-check path');
  if (stray && typeof stray.getAnimations === 'function') stray.getAnimations().forEach((a) => a.finish());
  const path = box.parentElement?.querySelector('.pn-check path');
  if (!path || typeof path.animate !== 'function') return;
  path.animate(
    [{ strokeDashoffset: 14 }, { strokeDashoffset: 0 }],
    { duration: 750, delay: 60, easing: 'ease-out', fill: 'backwards' },
  );
}

/**
 * Moves the task item at `pos` so it sits before its sibling at `toIndex`,
 * counted among the siblings without the item itself; `toIndex` equal to that
 * count puts it last.
 */
function moveTaskWithinList(tr: Transaction, pos: number, toIndex: number): Transaction {
  const $pos = tr.doc.resolve(pos);
  const list = $pos.parent;
  const self = $pos.index();
  const item = list.child(self);
  const before = toIndex < self ? toIndex : toIndex + 1;
  let target = $pos.start();
  for (let k = 0; k < before && k < list.childCount; k++) target += list.child(k).nodeSize;
  tr.delete(pos, pos + item.nodeSize);
  tr.insert(tr.mapping.map(target), item);
  return tr;
}

/** The nearest ancestor that scrolls vertically, for the drag's edge scroll. */
function scrollParentOf(el: HTMLElement): HTMLElement {
  for (let p = el.parentElement; p; p = p.parentElement) {
    const { overflowY } = getComputedStyle(p);
    if ((overflowY === 'auto' || overflowY === 'scroll') && p.scrollHeight > p.clientHeight) return p;
  }
  return (document.scrollingElement as HTMLElement | null) ?? document.documentElement;
}

/** Distance from a scroll edge, in px, inside which a drag scrolls the note. */
const DRAG_EDGE = 48;

/**
 * Drags a task by its grip to another place in its own list. Pointer events,
 * so a mouse, a pen and a finger take the same path. The item moves in one
 * transaction on release, so undo takes it back, and its sub-tasks travel with
 * it because they live inside it. A task never leaves its list: the grip of a
 * sub-task reorders the sub-tasks.
 */
function dragTask(event: PointerEvent, item: HTMLElement, getPos: () => number | undefined, editor: TipTapEditor) {
  const list = item.parentElement;
  if (!editor.isEditable || event.button !== 0 || !list) return;
  const siblings = [...list.children].filter((el): el is HTMLElement => el instanceof HTMLElement && el !== item);
  const home = [...list.children].indexOf(item);
  if (siblings.length === 0) return;
  event.preventDefault();
  // Capture keeps a touch drag from turning into a scroll. The listeners sit on
  // the window, so the drag also survives a capture the browser refuses.
  try {
    (event.currentTarget as HTMLElement).setPointerCapture(event.pointerId);
  } catch {
    /* the window listeners below still follow the pointer */
  }
  const pointerId = event.pointerId;

  const scroller = scrollParentOf(item);
  const startY = event.clientY;
  const startScroll = scroller.scrollTop;
  const marker = document.createElement('div');
  marker.className = 'pn-task-drop';
  document.body.append(marker);
  item.classList.add('pn-task-dragging');
  document.documentElement.classList.add('pn-task-drag-active');
  let lastY = startY;
  let target = home;
  let frame = 0;

  const place = () => {
    item.style.transform = `translateY(${lastY - startY + scroller.scrollTop - startScroll}px)`;
    target = siblings.findIndex((el) => {
      const r = el.getBoundingClientRect();
      return r.top + r.height / 2 > lastY;
    });
    if (target < 0) target = siblings.length;
    if (target === home) {
      marker.style.display = 'none';
      return;
    }
    const listBox = list.getBoundingClientRect();
    const edge = target < siblings.length
      ? siblings[target]!.getBoundingClientRect().top
      : siblings[siblings.length - 1]!.getBoundingClientRect().bottom;
    marker.style.display = 'block';
    marker.style.top = `${edge - 1}px`;
    marker.style.left = `${listBox.left}px`;
    marker.style.width = `${listBox.width}px`;
  };

  const tick = () => {
    const box = scroller === document.scrollingElement
      ? { top: 0, bottom: window.innerHeight }
      : scroller.getBoundingClientRect();
    const step = lastY < box.top + DRAG_EDGE ? -8 : lastY > box.bottom - DRAG_EDGE ? 8 : 0;
    if (step) {
      scroller.scrollTop += step;
      place();
    }
    frame = requestAnimationFrame(tick);
  };
  frame = requestAnimationFrame(tick);

  const onMove = (e: PointerEvent) => {
    if (e.pointerId !== pointerId) return;
    lastY = e.clientY;
    place();
  };
  const finish = (drop: boolean) => {
    cancelAnimationFrame(frame);
    window.removeEventListener('pointermove', onMove);
    window.removeEventListener('pointerup', onUp);
    window.removeEventListener('pointercancel', onCancel);
    window.removeEventListener('keydown', onKey, true);
    marker.remove();
    item.classList.remove('pn-task-dragging');
    item.style.transform = '';
    document.documentElement.classList.remove('pn-task-drag-active');
    const pos = getPos();
    if (drop && target !== home && typeof pos === 'number') {
      editor.view.dispatch(moveTaskWithinList(editor.state.tr, pos, target));
    }
  };
  const onUp = (e: PointerEvent) => { if (e.pointerId === pointerId) finish(true); };
  const onCancel = (e: PointerEvent) => { if (e.pointerId === pointerId) finish(false); };
  const onKey = (e: KeyboardEvent) => {
    if (e.key !== 'Escape') return;
    e.preventDefault();
    e.stopPropagation();
    finish(false);
  };
  window.addEventListener('pointermove', onMove);
  window.addEventListener('pointerup', onUp);
  window.addEventListener('pointercancel', onCancel);
  window.addEventListener('keydown', onKey, true);
}

const GRIP_SVG =
  '<svg viewBox="0 0 10 16"><circle cx="2.5" cy="3" r="1.4"/><circle cx="7.5" cy="3" r="1.4"/><circle cx="2.5" cy="8" r="1.4"/><circle cx="7.5" cy="8" r="1.4"/><circle cx="2.5" cy="13" r="1.4"/><circle cx="7.5" cy="13" r="1.4"/></svg>';
const CHECK_SVG = `<svg viewBox="0 0 12 12"><path d="${TASK_CHECK_PATH}"/></svg>`;

/** Each icon is parsed once and cloned for every task: a note with thousands
 *  of tasks otherwise parses the same markup thousands of times on open. */
const parsedSvgs = new Map<string, Node>();
function svgCopy(markup: string): Node {
  let svg = parsedSvgs.get(markup);
  if (!svg) {
    const host = document.createElement('span');
    host.innerHTML = markup;
    svg = host.firstChild!;
    parsedSvgs.set(markup, svg);
  }
  return svg.cloneNode(true);
}

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
export const TaskItemMobileSafe = TaskItem.extend<TaskItemOptions & {
  /** Whether a ticked task moves below the open ones. Read at each tick, so
   *  the setting applies to an editor that is already open. */
  sinkChecked: () => boolean;
}>({
  addOptions() {
    return {
      ...(this.parent?.() as TaskItemOptions),
      sinkChecked: () => true,
    };
  },

  addStorage() {
    return {
      markdown: {
        parse: {
          // tiptap-markdown's own updateDOM, plus one trim. markdown-it leaves
          // the space after `[ ]` at the front of the task's text. A load
          // collapses it, but a paste keeps whitespace, so a pasted task
          // would begin with a space that the next save writes as `&nbsp;`.
          updateDOM(element: HTMLElement) {
            element.querySelectorAll('.task-list-item').forEach((item) => {
              const input = item.querySelector('input');
              item.setAttribute('data-type', 'taskItem');
              if (input) {
                item.setAttribute('data-checked', String(input.checked));
                input.remove();
              }
              const first = document.createTreeWalker(item, NodeFilter.SHOW_TEXT).nextNode();
              if (first?.textContent) first.textContent = first.textContent.replace(/^[ \t]+/, '');
            });
          },
        },
      },
    };
  },

  // The content sits in the div after the checkbox label only in the editor's
  // own HTML. Markdown parses a task to `<li><p>…</p>…</li>`, and the library
  // rule takes the FIRST div anywhere in the item as its content, so a task
  // holding a callout or a maths block (both drawn as divs) would reload as
  // that block's inside alone, and the task's own text would be lost.
  parseHTML() {
    return [
      {
        tag: `li[data-type="${this.name}"]`,
        priority: 51,
        contentElement: (element: HTMLElement) => element.querySelector(':scope > label + div') ?? element,
      },
    ];
  },

  addProseMirrorPlugins() {
    const name = this.name;
    return [
      ...(this.parent?.() ?? []),
      new Plugin({
        key: new PluginKey('taskCaretDrawn'),
        props: {
          // A task item skips layout until the browser decides at its next
          // frame that it is on screen (content-visibility in index.css). A
          // key that arrives before that frame, right after Enter made the
          // task, was typed into the next block the browser had drawn: the
          // words fell below the list or into the task after, and an empty
          // task stayed behind. The class keeps every task around the caret
          // drawn from the moment the caret enters it. It is a decoration,
          // never a classList change on the item: ProseMirror redraws an item
          // whose attributes change under it, and the redraw re-ran the
          // change without end, freezing the tab.
          decorations: (state) => {
            const { $head } = state.selection;
            const decorations: Decoration[] = [];
            for (let depth = $head.depth; depth > 0; depth--) {
              const node = $head.node(depth);
              if (node.type.name !== name) continue;
              const from = $head.before(depth);
              decorations.push(Decoration.node(from, from + node.nodeSize, { class: 'pn-task-caret' }));
            }
            // Null when the caret is in no task, so the view skips this plugin.
            return decorations.length ? DecorationSet.create(state.doc, decorations) : null;
          },
        },
      }),
      new Plugin({
        key: new PluginKey('taskTextDrag'),
        props: {
          handleDOMEvents: {
            // A drag of a task's whole text is a drag of the task. The browser
            // would carry only the words, leave an empty checkbox behind and
            // drop them into a new unchecked task. Turning the selection into
            // the item before ProseMirror reads it makes the drag move the
            // item, with its checked state and its sub-tasks.
            dragstart: (view) => {
              const { $from, $to, empty } = view.state.selection;
              if (empty || $from.parent !== $to.parent || !$from.parent.isTextblock || $from.depth < 2) return false;
              if ($from.node(-1).type.name !== name || $from.index(-1) !== 0) return false;
              if ($from.parentOffset !== 0 || $to.parentOffset !== $from.parent.content.size) return false;
              view.dispatch(view.state.tr.setSelection(NodeSelection.create(view.state.doc, $from.before(-1))));
              return false;
            },
          },
        },
      }),
    ];
  },

  addNodeView() {
    return ({ node, HTMLAttributes, getPos, editor }: NodeViewRendererProps) => {
      const listItem = document.createElement('li');
      // The drag grip ends the row (see the pn-task-grip rules in index.css).
      // It is never part of the document.
      const grip = document.createElement('span');
      grip.className = 'pn-task-grip';
      grip.contentEditable = 'false';
      grip.setAttribute('aria-hidden', 'true');
      grip.append(svgCopy(GRIP_SVG));
      grip.addEventListener('mousedown', (event) => event.preventDefault());
      grip.addEventListener('pointerdown', (event) => {
        if (typeof getPos !== 'function') return;
        // A Kanban card can also move to another column, and a tap on its
        // grip opens Move to.
        if (kanbanCardOf(listItem)) dragCard(event, listItem, getPos, editor as TipTapEditor);
        else dragTask(event, listItem, getPos, editor as TipTapEditor);
      });
      // Once the item is in the document, a card's grip becomes a button.
      requestAnimationFrame(() => markCardGrip(grip, listItem));
      // VoiceOver and other assistive tech activate with a click and no
      // pointer press (detail 0); on a card that opens Move to.
      grip.addEventListener('click', (event) => {
        if (event.detail !== 0 || typeof getPos !== 'function' || !kanbanCardOf(listItem)) return;
        openCardMenu(grip, getPos, editor as TipTapEditor);
      });
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
      // The shared task checkbox styles follow the native checked state.
      checkboxStyler.className = 'pn-check';
      checkboxStyler.setAttribute('aria-hidden', 'true');
      checkboxStyler.append(svgCopy(CHECK_SVG));
      checkbox.type = 'checkbox';
      checkbox.className = 'pn-task-checkbox';
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
          const topBefore = listItem.getBoundingClientRect().top;
          let movedTo: number | null = null;
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
              movedTo = this.options.sinkChecked() ? moveTaskToGroupEdge(tr, position) : null;
              return true;
            })
            .run();
          if (movedTo !== null) {
            const moved = editor.view.nodeDOM(movedTo);
            slideIn(moved, topBefore);
            if (checked) drawMovedTick(checkbox, moved);
          }
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
      listItem.append(checkboxWrapper, content, grip);
      Object.entries(HTMLAttributes).forEach(([key, value]) => {
        listItem.setAttribute(key, value as string);
      });

      return {
        dom: listItem,
        contentDOM: content,
        // A drag restyles the item and its grip; that is not an edit.
        ignoreMutation: (mutation) =>
          mutation.type === 'attributes' && (mutation.target === listItem || mutation.target === grip),
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
 * Task list that serializes as raw HTML once one of its items is aligned.
 *
 * serializeAlignedBlock (editorAlignment.ts) works because markdown-it reads `<p style>` as
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
