import i18n from './i18n';
import { type Editor as TipTapEditor } from '@tiptap/react';
import TaskItem, { type TaskItemOptions } from '@tiptap/extension-task-item';
import TaskList from '@tiptap/extension-task-list';
import { Table } from '@tiptap/extension-table';
import { Paragraph } from '@tiptap/extension-paragraph';
import { Heading } from '@tiptap/extension-heading';
import { HardBreak } from '@tiptap/extension-hard-break';
import { Text } from '@tiptap/extension-text';
import { CodeBlockLowlight } from '@tiptap/extension-code-block-lowlight';
import { createLowlight, common } from 'lowlight';
import Highlight from '@tiptap/extension-highlight';
import { InlineMath, BlockMath } from '@tiptap/extension-mathematics';
import { TextAlign } from '@tiptap/extension-text-align';
import { TextStyle } from '@tiptap/extension-text-style';
import { Extension, InputRule, getHTMLFromFragment, type NodeViewRendererProps } from '@tiptap/core';
import { Fragment, type Node as ProseMirrorNode } from '@tiptap/pm/model';
import { Plugin, PluginKey, TextSelection, NodeSelection, Selection, type Transaction } from '@tiptap/pm/state';
import { selectionCell } from '@tiptap/pm/tables';
import { isSoftKeyboardDevice, suppressSoftKeyboard } from './softKeyboard';
import { mathNodeView } from './editorMath';
import { getCodeWrap, setCodeWrap, subscribeCodeWrap } from './codeWrap';
import { codeLanguageLabel, openCodeLanguageMenu } from './codeLanguages';
import { TIP_PILL, positionClasses } from './HoverLabel';
import { TABLE_MIN_WIDTH, delimiterRow } from './tableColumnWidths';
import { tableWidthMarker } from './tableDelimiterRow';
import { ColumnWidthTableView, columnResizePlugin, registerTableWidthsMarkdown, renderTableHTML, tableWidthOf, tableWidths } from './tableColumnResize';
import { markPlainEscape } from './plainEscape';

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
      grip.innerHTML =
        '<svg viewBox="0 0 10 16"><circle cx="2.5" cy="3" r="1.4"/><circle cx="7.5" cy="3" r="1.4"/><circle cx="2.5" cy="8" r="1.4"/><circle cx="7.5" cy="8" r="1.4"/><circle cx="2.5" cy="13" r="1.4"/><circle cx="7.5" cy="13" r="1.4"/></svg>';
      grip.addEventListener('mousedown', (event) => event.preventDefault());
      grip.addEventListener('pointerdown', (event) => {
        if (typeof getPos === 'function') dragTask(event, listItem, getPos, editor as TipTapEditor);
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
          if (movedTo !== null) slideIn(editor.view.nodeDOM(movedTo), topBefore);
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
  //   Image:      ![...](pn:img/...){width=N align=X} (optional attr suffix),
  //               or pn:file/... for a picture placed from Files
  //   Attachment:  [...|...|...](pn:file/...)
  const mediaLine =
    '(?:!\\[.*?\\]\\(pn:(?:img|file)\\/[^)]+\\)(?:\\{[^}\\n]*\\})?|\\[.*?\\|.*?\\|.*?\\]\\(pn:file\\/[^)]+\\))';
  return md.replace(
    new RegExp(`(${mediaLine})\\n{3,}(?=${mediaLine})`, 'g'),
    '$1\n\n',
  );
}

/**
 * Put a rewritten body into the open editor as one step of its history,
 * through the transforms the editor's own load applies, so Undo brings the
 * old body back. False when there is no editor or it takes no edits; the
 * caller then writes the row and remounts the editor itself.
 */
export function replaceBodyUndoably(editor: TipTapEditor | null | undefined, md: string): boolean {
  if (!editor || editor.isDestroyed || !editor.isEditable) return false;
  return editor.commands.setContent(collapseMediaGaps(fixEmptyTaskItems(md)));
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
 * Code block with a Copy button and a wrap toggle in its top corner.
 *
 * The pre is the visible box and keeps every typography rule (margins,
 * colours, radius, the spacing after a heading). A span inside it is the
 * element that scrolls sideways, and the tools hang off the pre, not the
 * span: a control inside the scroller travels with the text, and a long
 * line scrolled it out of the block (GitHub #340).
 *
 * The scroller reserves a band above the first line, so nothing covers
 * code: the language label sits in it on the left, always visible, and the
 * tools on the right, on hover where there is one and always on touch. Copy
 * writes the node's raw text; the wrap toggle flips one device-wide setting
 * (codeWrap.ts), so every block follows; the label opens the language menu
 * (codeLanguages.ts).
 *
 * Spec: ops/docs/design-decisions.md (code blocks wrap by default)
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

/**
 * The fence language of a copy box: a code block drawn as a light box in
 * the note's own font, with the code block's wrap and copy buttons in a
 * light look and no language label. Stored as ```copy, so another Markdown app shows a plain
 * code block. Registered as plain text, or lowlight would guess a language
 * and colour it. Spec: ops/docs/plans/spoiler-and-copy.md
 */
export const COPY_BOX_LANGUAGE = 'copy';
lowlight.registerAlias({ plaintext: [COPY_BOX_LANGUAGE] });

/** Phosphor's ArrowElbowDownLeft, bold: the return glyph editors use for
 *  wrap. A node view is plain DOM, so the icon is markup, not a component. */
const WRAP_ICON =
  '<svg viewBox="0 0 256 256" width="14" height="14" fill="currentColor" aria-hidden="true">' +
  '<path d="M204,32V176a12,12,0,0,1-12,12H77l27.52,27.51a12,12,0,0,1-17,17l-48-48a12,12,0,0,1,0-17l48-48a12,12,0,1,1,17,17L77,164H180V32a12,12,0,0,1,24,0Z"/></svg>';

/** Phosphor's Copy and Check, bold: the copy button and its done state,
 *  the same pair the vault's copy actions use. */
const COPY_ICON =
  '<svg viewBox="0 0 256 256" width="14" height="14" fill="currentColor" aria-hidden="true">' +
  '<path d="M216,28H88A12,12,0,0,0,76,40V76H40A12,12,0,0,0,28,88V216a12,12,0,0,0,12,12H168a12,12,0,0,0,12-12V180h36a12,12,0,0,0,12-12V40A12,12,0,0,0,216,28ZM156,204H52V100H156Zm48-48H180V88a12,12,0,0,0-12-12H100V52H204Z"/></svg>';
const CHECK_ICON =
  '<svg viewBox="0 0 256 256" width="14" height="14" fill="currentColor" aria-hidden="true">' +
  '<path d="M232.49,80.49l-128,128a12,12,0,0,1-17,0l-56-56a12,12,0,1,1,17-17L96,183,215.51,63.51a12,12,0,0,1,17,17Z"/></svg>';

/** Phosphor's CaretDown, bold, for the language label. */
const CARET_ICON =
  '<svg viewBox="0 0 256 256" width="10" height="10" fill="currentColor" aria-hidden="true">' +
  '<path d="M216.49,104.49l-80,80a12,12,0,0,1-17,0l-80-80a12,12,0,0,1,17-17L128,159l71.51-71.52a12,12,0,0,1,17,17Z"/></svg>';

const CODE_TOOL_BTN =
  'inline-flex items-center justify-center h-5 rounded text-xs transition ' +
  '[@media(hover:none)]:h-7';

/**
 * A block longer than FOLD_MIN_LINES opens folded to its first
 * FOLD_SHOWN_LINES, with a button under it (GitHub #427). The gap between the
 * two numbers is deliberate: a fold that hides three lines costs more than it
 * saves. The fold is a view state and is never saved, because a fence stores
 * a language and nothing else (the same limit codeWrap.ts records), so every
 * open starts folded. A cursor or a find match that lands in the hidden part
 * opens the block, so nothing is typed or found out of sight.
 * Spec: ops/docs/design-decisions.md (long code blocks fold)
 */
const FOLD_MIN_LINES = 30;
const FOLD_SHOWN_LINES = 20;

/** Each folded node view's "open it" hook, keyed by its pre. */
const unfolders = new WeakMap<Node, () => void>();

export const CodeBlockWithCopy = CodeBlockLowlight.extend({
  addKeyboardShortcuts() {
    return {
      ...this.parent?.(),
      // Select all selects the code first and the note on a second press, as
      // code editors do: one press and Delete must not clear the text around
      // the block (GitHub #426). An empty block or a selection that already
      // covers the code falls through to the stock select-all.
      'Mod-a': ({ editor }) => {
        const { $from, $to, from, to } = editor.state.selection;
        if ($from.parent.type !== this.type || !$from.sameParent($to)) return false;
        const start = $from.start();
        const end = $from.end();
        if (start === end || (from === start && to === end)) return false;
        return editor.commands.setTextSelection({ from: start, to: end });
      },
    };
  },

  addProseMirrorPlugins() {
    const type = this.type;
    let lastHit = -1;
    // Opens a folded block when `bottom()` (a viewport y) falls below its
    // last clearly readable line, the fade included. A cursor in the visible
    // lines leaves the fold alone, so a click to copy line 3 does not unroll
    // 500. Layout is read only for a block that is folded.
    const revealIfHidden = (block: Node | null | undefined, bottom: () => number) => {
      if (!(block instanceof HTMLElement) || !block.classList.contains('pn-codeblock-folded')) return;
      const scroller = block.querySelector('.pn-codeblock-scroll');
      if (!scroller) return;
      const fade = 2 * (parseFloat(getComputedStyle(scroller).lineHeight) || 24);
      if (bottom() > scroller.getBoundingClientRect().bottom - fade) unfolders.get(block)?.();
    };
    return [
      ...(this.parent?.() ?? []),
      new Plugin({
        key: new PluginKey('codeBlockUnfold'),
        view: () => ({
          update: (view, prev) => {
            const { selection } = view.state;
            if (!selection.eq(prev.selection) && selection.$head.parent.type === type) {
              revealIfHidden(view.nodeDOM(selection.$head.before()), () => view.coordsAtPos(selection.head).bottom);
            }
            // The find bar marks its current match with a decoration and
            // scrolls to it without moving the selection.
            const hit = view.dom.querySelector('.pn-search-hit-current');
            const hitPos = hit ? view.posAtDOM(hit, 0) : -1;
            if (hit && hitPos !== lastHit) {
              revealIfHidden(hit.closest('.pn-codeblock'), () => hit.getBoundingClientRect().bottom);
            }
            lastHit = hitPos;
          },
        }),
      }),
    ];
  },

  addStorage() {
    return {
      markdown: {
        // tiptap-markdown's serializer with three changes. The fence is one
        // backtick longer than any fence line inside the code, so a block
        // holding markdown keeps its ``` lines. A trailing newline gets a line
        // of its own, which the parse strips back to one. The language is
        // written only with the characters an info string can carry. No `parse` key: the
        // library's parse half is merged underneath and must stay.
        serialize(state: any, node: ProseMirrorNode) {
          const text = node.textContent;
          const runs = text.match(/^ {0,3}`{3,}/gm) ?? [];
          const longest = Math.max(2, ...runs.map((r) => r.trim().length));
          const fence = '`'.repeat(longest + 1);
          // The parse takes any class after `language-`, so a pasted block can
          // carry a language with a backtick, which no backtick fence's info
          // string may hold, or a space, which ends it. Neither is written.
          const language = String(node.attrs['language'] || '').replace(/[`\s]/g, '');
          state.write(fence + language + '\n');
          state.text(text, false);
          if (text.endsWith('\n')) state.out += '\n';
          state.ensureNewLine();
          state.write(fence);
          state.closeBlock(node);
        },
      },
    };
  },

  addNodeView() {
    return ({ node, getPos, editor }: NodeViewRendererProps) => {
      // ProseMirror keeps this view while the text inside changes, so Copy
      // reads the node `update` last handed over, never the one the view
      // was built with.
      let current = node;

      const pre = document.createElement('pre');
      pre.className = 'pn-codeblock';
      const scroller = document.createElement('span');
      scroller.className = 'pn-codeblock-scroll';
      const code = document.createElement('code');
      scroller.appendChild(code);
      pre.appendChild(scroller);

      const tools = document.createElement('span');
      tools.className = 'pn-codeblock-tools';
      tools.contentEditable = 'false';

      const wrapBtn = document.createElement('button');
      wrapBtn.type = 'button';
      wrapBtn.innerHTML = WRAP_ICON;
      // Module-level node view - no useTranslation hook here, so the
      // i18n instance is called directly (the non-component pattern
      // from i18n.ts).
      const wrapLabel = i18n.t('editor:codeBlock.wrap');
      wrapBtn.setAttribute('aria-label', wrapLabel);
      // HoverLabel's `start` tip built as DOM, from HoverLabel's own
      // classes. It opens to the left: the pre is an LTR island, and its
      // overflow: hidden would cut a tip above a button 8px from its top.
      const wrapTip = document.createElement('span');
      wrapTip.className = 'pn-codeblock-wrap relative group/tip inline-flex';
      const tip = document.createElement('span');
      tip.className = `${TIP_PILL} ${positionClasses.start} flex items-center gap-2 whitespace-nowrap`;
      tip.textContent = wrapLabel;
      wrapTip.append(wrapBtn, tip);
      // A copy box has the code block's tools in its own light look; the
      // wrap state is the one device setting both read.
      let box = false;
      const paintWrap = () => {
        const on = getCodeWrap();
        wrapBtn.setAttribute('aria-pressed', String(on));
        wrapBtn.className = `${CODE_TOOL_BTN} w-6 [@media(hover:none)]:w-8 ${
          box
            ? `pn-copybox-btn${on ? ' pn-copybox-on' : ''}`
            : on
              ? 'bg-accent-fill text-white hover:bg-accent-fill/90'
              // theme-ok: the code block toolbar is dark in every theme
              : 'bg-neutral-700/80 text-neutral-300 hover:bg-neutral-700 hover:text-neutral-100'
        }`;
      };
      paintWrap();
      const unsubscribe = subscribeCodeWrap(paintWrap);
      wrapBtn.addEventListener('mousedown', (e) => e.preventDefault());
      wrapBtn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        setCodeWrap(!getCodeWrap());
      });

      // An icon, not a word: a word grows in other languages and the tools
      // sit on the code's first line. The tip names it; a copy turns the
      // icon into a check and the tip into "Copied" for a moment.
      const copyLabel = i18n.t('editor:codeBlock.copy');
      const copyBtn = document.createElement('button');
      copyBtn.type = 'button';
      copyBtn.innerHTML = COPY_ICON;
      copyBtn.setAttribute('aria-label', copyLabel);
      const copyTip = document.createElement('span');
      copyTip.className = 'pn-codeblock-copy relative group/tip inline-flex';
      const copyTipText = document.createElement('span');
      copyTipText.className = `${TIP_PILL} ${positionClasses.start} whitespace-nowrap`;
      copyTipText.setAttribute('aria-live', 'polite');
      copyTipText.textContent = copyLabel;
      copyTip.append(copyBtn, copyTipText);
      let copyReset = 0;
      copyBtn.addEventListener('mousedown', (e) => e.preventDefault());
      copyBtn.addEventListener('click', async (e) => {
        e.preventDefault();
        e.stopPropagation();
        let done = true;
        try {
          await navigator.clipboard.writeText(current.textContent);
        } catch {
          done = false;
        }
        window.clearTimeout(copyReset);
        copyBtn.innerHTML = done ? CHECK_ICON : COPY_ICON;
        copyBtn.classList.toggle('pn-copied', done);
        copyTipText.textContent = i18n.t(done ? 'editor:codeBlock.copied' : 'editor:codeBlock.copyFailed');
        copyTip.classList.add('pn-tip-shown');
        copyReset = window.setTimeout(() => {
          copyBtn.innerHTML = COPY_ICON;
          copyBtn.classList.remove('pn-copied');
          copyTipText.textContent = copyLabel;
          copyTip.classList.remove('pn-tip-shown');
        }, 1500);
      });

      tools.append(wrapTip, copyTip);
      pre.appendChild(tools);

      // The language, always on show in the band above the first line, so a
      // plain block says why it has no colours and offers the fix in place.
      const lang = document.createElement('span');
      lang.className = 'pn-codeblock-lang';
      lang.contentEditable = 'false';
      const langBtn = document.createElement('button');
      langBtn.type = 'button';
      langBtn.className =
        `${CODE_TOOL_BTN} gap-1 px-2 [@media(hover:none)]:px-2.5 ` +
        // theme-ok: the code block toolbar is dark in every theme
        'text-neutral-400 hover:bg-neutral-700/80 hover:text-neutral-100';
      const langName = document.createElement('span');
      langBtn.append(langName);
      langBtn.insertAdjacentHTML('beforeend', CARET_ICON);
      lang.appendChild(langBtn);
      pre.appendChild(lang);
      let langShown: string | null | undefined;
      const paintCopyBtn = () => {
        const copied = copyBtn.classList.contains('pn-copied');
        copyBtn.className = box
          ? `${CODE_TOOL_BTN} w-6 [@media(hover:none)]:w-8 pn-copybox-btn`
          : `${CODE_TOOL_BTN} w-6 [@media(hover:none)]:w-8 ` +
            // theme-ok: the code block toolbar is dark in every theme
            'bg-neutral-700/80 text-neutral-100 hover:bg-neutral-700';
        copyBtn.classList.toggle('pn-copied', copied);
      };
      const paintLang = () => {
        const language = current.attrs['language'] as string | null;
        if (language === langShown) return;
        box = language === COPY_BOX_LANGUAGE;
        pre.classList.toggle('pn-copybox', box);
        paintCopyBtn();
        paintWrap();
        langShown = language;
        const name = codeLanguageLabel(language) ?? i18n.t('editor:codeBlock.plainText');
        langName.textContent = name;
        langBtn.setAttribute('aria-label', i18n.t('editor:codeBlock.language', { name }));
      };
      paintLang();
      langBtn.addEventListener('mousedown', (e) => e.preventDefault());
      langBtn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (!editor.isEditable) return;
        openCodeLanguageMenu(langBtn, current.attrs['language'] as string | null, (language) => {
          const pos = typeof getPos === 'function' ? getPos() : undefined;
          if (typeof pos !== 'number') return;
          // setNodeMarkup, not setNodeAttribute: the lowlight plugin only
          // re-highlights a block a step's from/to range covers, and an
          // attribute step has none, so the old colours stayed.
          editor.view.dispatch(editor.state.tr.setNodeMarkup(pos, undefined, { ...current.attrs, language }));
          editor.view.focus();
        });
      });

      const fold = document.createElement('span');
      fold.className = 'pn-codeblock-fold';
      fold.contentEditable = 'false';
      const foldBtn = document.createElement('button');
      foldBtn.type = 'button';
      foldBtn.className =
        `${CODE_TOOL_BTN} px-2.5 [@media(hover:none)]:px-3 ` +
        // theme-ok: the code block toolbar is dark in every theme
        'bg-neutral-700/80 text-neutral-100 hover:bg-neutral-700';
      fold.appendChild(foldBtn);
      pre.appendChild(fold);
      pre.style.setProperty('--pn-fold-lines', String(FOLD_SHOWN_LINES));

      let expanded = false;
      let foldLabel = '';
      const paintFold = () => {
        const lines = current.textContent.split('\n').length;
        const long = lines > FOLD_MIN_LINES;
        pre.classList.toggle('pn-codeblock-folded', long && !expanded);
        fold.hidden = !long;
        const label = !long ? '' : expanded
          ? i18n.t('editor:codeBlock.showLess')
          : i18n.t('editor:codeBlock.showAll', { count: lines });
        if (label !== foldLabel) foldBtn.textContent = foldLabel = label;
      };
      paintFold();
      unfolders.set(pre, () => {
        if (expanded || !pre.classList.contains('pn-codeblock-folded')) return;
        expanded = true;
        paintFold();
      });
      foldBtn.addEventListener('mousedown', (e) => e.preventDefault());
      foldBtn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        expanded = !expanded;
        paintFold();
        // Folding from the foot of a long block pulls the button up past the
        // top of the screen; bring it back to where the reader is.
        const r = fold.getBoundingClientRect();
        if (r.top < 0 || r.bottom > window.innerHeight) fold.scrollIntoView({ block: 'center' });
      });

      return {
        dom: pre,
        contentDOM: code,
        update: (next: ProseMirrorNode) => {
          if (next.type !== current.type) return false;
          current = next;
          paintFold();
          paintLang();
          return true;
        },
        // The tools, the language label and the fold button are not document
        // content: their clicks, label changes and class flips are not edits
        // for ProseMirror to read back, and neither is the fold class on the
        // pre.
        stopEvent: (e: Event) => [tools, lang, fold].some((el) => el.contains(e.target as Node)),
        ignoreMutation: (m: { type: string; target: Node }) =>
          [tools, lang, fold].some((el) => el.contains(m.target)) || (m.type === 'attributes' && m.target === pre),
        destroy: unsubscribe,
      };
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
 * Lists, task lists, quotes and code blocks merge too, their markers kept as
 * text. Falls back to the default command for a caret or a selection inside
 * one textblock, and when the selection holds a block with no text form
 * (an image, a table, a callout).
 *
 * Spec: ops/docs/design-decisions.md (code-block multi-line merge, #142)
 */
export function toggleCodeBlockSmart(editor: TipTapEditor, language: string | null = null) {
  const { state } = editor;
  const { schema, selection, doc } = state;
  const { $from, $to } = selection;
  const codeBlockType = schema.nodes['codeBlock']!;
  const paragraphType = schema.nodes['paragraph']!;

  // Toggle OFF: selection sits inside a single code block. Split it back into
  // one paragraph per line so the line breaks survive the round trip (the
  // default command would collapse them into a single paragraph).
  if ($from.parent.type === codeBlockType && $from.parent === $to.parent) {
    // A code block asked to be the other kind (a copy box, or back) changes
    // its language and keeps its text.
    const current = ($from.parent.attrs['language'] as string | null) === COPY_BOX_LANGUAGE ? COPY_BOX_LANGUAGE : null;
    if (current !== language) {
      const pos = $from.before();
      editor.view.dispatch(state.tr.setNodeMarkup(pos, undefined, { ...$from.parent.attrs, language }));
      editor.view.focus();
      return;
    }
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

  // Toggle ON. A caret or a selection inside one textblock keeps the stock
  // command, which also makes a code block inside a list item.
  if ($from.sameParent($to)) {
    editor.chain().focus().toggleCodeBlock(language ? { language } : undefined).run();
    return;
  }

  // A selection inside one list takes only the items it touches: the list
  // splits around the new block, and the part after it keeps its numbers.
  const top = doc.resolve(selection.from).node(1);
  const topTo = doc.resolve(selection.to).node(1);
  if (top && top === topTo && /^(bulletList|orderedList|taskList)$/.test(top.type.name)) {
    const listPos = doc.resolve(selection.from).before(1);
    const picked: ProseMirrorNode[] = [];
    const before: ProseMirrorNode[] = [];
    const after: ProseMirrorNode[] = [];
    top.forEach((item, offset) => {
      const from = listPos + 1 + offset;
      const to = from + item.nodeSize;
      if (to <= selection.from) before.push(item);
      else if (from >= selection.to) after.push(item);
      else picked.push(item);
    });
    const start = Number(top.attrs['start'] ?? 1) || 1;
    const asList = (items: ProseMirrorNode[], first: number) =>
      top.type.create(top.type.name === 'orderedList' ? { ...top.attrs, start: first } : top.attrs, items);
    const lines = codeLinesOf(asList(picked, start + before.length), '');
    if (lines) {
      const text = lines.join('\n');
      const parts: ProseMirrorNode[] = [];
      if (before.length) parts.push(asList(before, start));
      const codeAt = listPos + parts.reduce((n, part) => n + part.nodeSize, 0);
      parts.push(codeBlockType.create(language ? { language } : null, text ? schema.text(text) : undefined));
      if (after.length) parts.push(asList(after, start + before.length + picked.length));
      const tr = state.tr.replaceWith(listPos, listPos + top.nodeSize, parts);
      tr.setSelection(TextSelection.create(tr.doc, codeAt + 1, codeAt + 1 + text.length));
      editor.view.dispatch(tr.scrollIntoView());
      editor.view.focus();
      return;
    }
  }

  // A selection across blocks: every top-level block it touches becomes ONE
  // code block, a line per textblock. A list keeps its markers as text, so a
  // numbered list stays numbered in the block. A block that has no text form
  // (a table, an image, a callout) leaves the stock command in charge.
  let mergeFrom = -1;
  let mergeTo = -1;
  const lines: string[] = [];
  let bail = false;
  doc.forEach((node, offset) => {
    if (bail) return;
    const intersects = offset < selection.to && offset + node.nodeSize > selection.from;
    if (!intersects) return;
    const blockLines = codeLinesOf(node, '');
    if (!blockLines) {
      bail = true;
      return;
    }
    if (mergeFrom === -1) mergeFrom = offset;
    mergeTo = offset + node.nodeSize;
    lines.push(...blockLines);
  });

  if (bail || mergeFrom === -1) {
    editor.chain().focus().toggleCodeBlock(language ? { language } : undefined).run();
    return;
  }

  const text = lines.join('\n');
  const codeNode = codeBlockType.create(language ? { language } : null, text ? schema.text(text) : undefined);
  const tr = state.tr.replaceRangeWith(mergeFrom, mergeTo, codeNode);
  tr.setSelection(
    TextSelection.create(tr.doc, mergeFrom + 1, mergeFrom + 1 + text.length),
  );
  editor.view.dispatch(tr.scrollIntoView());
  editor.view.focus();
}

/**
 * The text lines a block gives inside a code block, each led by `pad`, or
 * null for a block with no text form. List items carry their marker (`1. `,
 * `- `, `- [x] `) and their nested blocks are indented under it.
 */
function codeLinesOf(node: ProseMirrorNode, pad: string): string[] | null {
  const name = node.type.name;
  if (name === 'codeBlock') return node.textContent.split('\n').map((l) => pad + l);
  if (node.isTextblock) return [pad + node.textContent];
  if (name === 'blockquote') return childLines(node, pad + '> ');
  if (name === 'bulletList' || name === 'orderedList' || name === 'taskList') {
    const out: string[] = [];
    let n = Number(node.attrs['start'] ?? 1) || 1;
    let ok = true;
    node.forEach((item) => {
      if (!ok) return;
      const marker =
        name === 'orderedList' ? `${n++}. `
        : name === 'taskList' ? `- [${item.attrs['checked'] ? 'x' : ' '}] `
        : '- ';
      let first = true;
      item.forEach((child) => {
        if (!ok) return;
        const childPad = first ? pad + marker : pad + ' '.repeat(marker.length);
        const got = first && child.isTextblock ? [childPad + child.textContent] : codeLinesOf(child, childPad);
        if (!got) ok = false;
        else out.push(...got);
        first = false;
      });
    });
    return ok ? out : null;
  }
  return null;
}

function childLines(node: ProseMirrorNode, pad: string): string[] | null {
  const out: string[] = [];
  let ok = true;
  node.forEach((child) => {
    const got = ok ? codeLinesOf(child, pad) : null;
    if (!got) ok = false;
    else out.push(...got);
  });
  return ok ? out : null;
}

/**
 * Ensures the document always ends with an empty paragraph so the user
 * can click/tap below block nodes (images, code blocks, tables) to
 * continue typing. Without this, a terminal image swallows the full
 * width and there's no insertion point after it.
 */
/**
 * Marks an Escape that reached the end of the editor's key handlers unused, so
 * the app's Escape cascade can close the note (plainEscape.ts). The lowest
 * priority puts it after every plugin that may use Escape, the note-link menu
 * among them, and it never consumes the key.
 */
export const PlainEscape = Extension.create({
  name: 'plainEscape',
  priority: 1,
  addProseMirrorPlugins() {
    return [
      new Plugin({
        key: new PluginKey('plainEscape'),
        props: {
          handleKeyDown(_view, event) {
            if (event.key === 'Escape' && !event.isComposing) markPlainEscape(event);
            return false;
          },
        },
      }),
    ];
  },
});

export const TrailingParagraph = Extension.create({
  name: 'trailingParagraph',
  addProseMirrorPlugins() {
    return [
      new Plugin({
        key: new PluginKey('trailingParagraph'),
        appendTransaction(_transactions, _oldState, newState) {
          const { doc, schema } = newState;
          const lastNode = doc.lastChild;
          // The footnote section is always last, so the line goes in front of it.
          if (lastNode?.type.name === 'footnotes') {
            const before = doc.child(doc.childCount - 2);
            if (before.type.name === 'paragraph') return null;
            return newState.tr.insert(doc.content.size - lastNode.nodeSize, schema.nodes['paragraph']!.create());
          }
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
 * Editor.tsx instead draws an "Add a line at the top" zone above any note
 * whose first block leaves no line to click, and the document is only touched
 * when the user actually asks for a line.
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
 *   start too.
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
      .replace(/^(\+[ ]|[-*>])/, '\\$&')
      .replace(/^(\s*)(#{1,6})(\s|$)/, '$1\\$2$3')
      .replace(/^(\s*\d+)([.)])\s/, '$1\\$2 ');
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
  // tiptap-markdown remembers where each mark opened and closed, as offsets
  // into `out`, and trims the run after the next node renders. Each inserted
  // backslash moves the text after it, so the offsets move with it and a
  // delimiter written in this cell is the escaped one. Left stale, the trim
  // read a one-letter spoiler as an empty mark and deleted the letter.
  const shift = (pos: number) =>
    pos < from ? pos : pos + (written.slice(0, pos - from).match(/\|/g)?.length ?? 0);
  for (const inline of (state.inlines ?? []) as { start?: number; end?: number; delimiter?: unknown }[]) {
    if (typeof inline.start === 'number' && inline.start >= from && typeof inline.delimiter === 'string') {
      inline.delimiter = inline.delimiter.replace(/\|/g, '\\|');
    }
    if (typeof inline.start === 'number') inline.start = shift(inline.start);
    if (typeof inline.end === 'number') inline.end = shift(inline.end);
  }
}

/**
 * A pipe row holds one line of inline content per cell. A cell of more than
 * one block, or of one block that is not a paragraph or an image (a list, a
 * heading, a code block, a quote), cannot be written there: it broke the row
 * and spilled out under the table on reload. Nor can a paragraph aligned on
 * its own, since a pipe table aligns whole columns only.
 */
const PIPE_CELL_BLOCKS = new Set(['paragraph', 'image']);

function cellIsPipeSafe(cell: any): boolean {
  const first = cell.firstChild;
  if (cellHasSpan(cell) || cell.childCount > 1) return false;
  if (!first) return true;
  return PIPE_CELL_BLOCKS.has(first.type.name) && !(first.type.name === 'paragraph' && isStoredAlignment(first.attrs.textAlign));
}

/** tiptap-markdown's isMarkdownSerializable, plus the cell rule above. */
function tableIsPipeSerializable(node: any): boolean {
  const rows: any[] = [];
  node.forEach((row: any) => rows.push(row));
  const firstRow = rows[0];
  if (!firstRow) return false;
  if (cellsOf(firstRow).some((cell) => cell.type.name !== 'tableHeader' || !cellIsPipeSafe(cell))) {
    return false;
  }
  if (rows.slice(1).some((row) => cellsOf(row).some((cell) => cell.type.name === 'tableHeader' || !cellIsPipeSafe(cell)))) {
    return false;
  }
  return true;
}

function serializeTableToMarkdown(this: any, state: any, node: any, _parent: any): void {
  // Tables with spans or multi-block cells aren't representable as a GFM
  // pipe table - fall back to HTML, identical to tiptap-markdown's default.
  if (!tableIsPipeSerializable(node)) {
    if (this?.editor?.storage?.markdown?.options?.html ?? true) {
      // `text` rather than `write`: a code block in a cell carries newlines,
      // and each line needs the quote or list prefix the table sits under.
      state.text(getHTMLFromFragment(Fragment.from(node), node.type.schema), false);
    }
    if (node.isBlock) state.closeBlock(node);
    return;
  }

  state.inTable = true;
  const widths = tableWidths(node);
  node.forEach((row: any, _p: number, i: number) => {
    const rowStart: number = state.out.length;
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
    const written: string = state.out.slice(rowStart);
    state.ensureNewLine();
    if (!i) {
      // The delimiter row is the only place a pipe table can say how its
      // columns align (the cell's `align` attr, which the tiptap table cell
      // parses off the `text-align` markdown-it writes for `:---:`) and how
      // wide they are (dash counts, see tableColumnWidths.ts). A bare `---`
      // here would drop both on the first edit after an import.
      const aligns = cellsOf(row).map((col) => col.attrs?.['align']);
      state.write(delimiterRow(written.slice(written.indexOf('|')), widths, aligns));
      state.ensureNewLine();
    }
  });
  const tableWidth = tableWidthOf(node);
  if (tableWidth) {
    state.write(tableWidthMarker(tableWidth));
    state.ensureNewLine();
  }
  state.closeBlock(node);
  state.inTable = false;
}

/**
 * Table with our serializer declared in addStorage, replacing the pre-TipTap-3
 * onCreate monkey-patch that died silently when v3 made extension.storage a
 * per-access rebuild (see ParagraphWithMarkdown's HISTORY note; this one was
 * caught the same day when tables started saving as raw HTML instead of pipe
 * tables). tiptap-markdown's getMarkdownSpec merges this over its default
 * table spec, whose `parse` is empty; ours reads the column widths.
 *
 * Column widths: `colwidth` holds a relative weight, so the node view and
 * `renderHTML` are replaced (TipTap's read it as pixels), and a plugin drags
 * a border. `resizable` stays false, which keeps prosemirror-tables' own
 * pixel resizer out. Spec: ops/docs/plans/table-column-widths.md
 */
export const TableWithMarkdown = Table.extend({
  addOptions() {
    return { ...this.parent!(), View: ColumnWidthTableView };
  },
  addAttributes() {
    return {
      ...this.parent?.(),
      // The table's width in percent of the note, null for full width.
      // Written as a marker line under a pipe table, as data-table-width on
      // the HTML one; renderTableHTML draws it.
      tableWidth: {
        default: null,
        parseHTML: (element: HTMLElement) => {
          const width = Number(element.getAttribute('data-table-width'));
          return width >= TABLE_MIN_WIDTH && width < 100 ? width : null;
        },
        renderHTML: () => ({}),
      },
    };
  },
  renderHTML({ node, HTMLAttributes }) {
    return renderTableHTML(node, { ...this.options.HTMLAttributes, ...HTMLAttributes });
  },
  addProseMirrorPlugins() {
    return [...(this.parent?.() ?? []), columnResizePlugin()];
  },
  addStorage() {
    return {
      markdown: {
        serialize: serializeTableToMarkdown,
        parse: {
          setup: registerTableWidthsMarkdown,
        },
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

function goToAdjacentCell(editor: TipTapEditor, dir: number): boolean {
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
 * What Tab (dir 1) and Shift+Tab (dir -1) do inside a table: step to the
 * adjacent cell, and from the last cell add a row and step into it. Shift+Tab
 * in the first cell stays put.
 */
export function stepTableCell(editor: TipTapEditor, dir: number): void {
  if (goToAdjacentCell(editor, dir) || dir !== 1 || !editor.can().addRowAfter()) return;
  editor.chain().addRowAfter().run();
  goToAdjacentCell(editor, 1);
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

/** What one Tab press adds outside a list or a table. */
const TAB_INDENT = '    ';

/**
 * Tab in a paragraph or a code block adds TAB_INDENT at the caret, and
 * Shift+Tab removes up to that many spaces before it. Markdown keeps no
 * leading spaces in a heading, so a heading is left alone, and so is a list,
 * where Tab moves the item instead. A range selection is left alone too, so
 * a stray Tab never replaces selected text.
 */
export function indentText(editor: TipTapEditor, dir: number): boolean {
  const { selection } = editor.state;
  if (!selection.empty) return false;
  const { $from } = selection;
  const parent = $from.parent.type.name;
  if (parent !== 'paragraph' && parent !== 'codeBlock') return false;
  for (let depth = $from.depth; depth > 0; depth--) {
    const name = $from.node(depth).type.name;
    if (name === 'listItem' || name === 'taskItem') return false;
  }
  if (dir > 0) {
    return editor.chain().focus().command(({ tr }) => {
      tr.insertText(TAB_INDENT);
      return true;
    }).run();
  }
  const before = $from.parent.textBetween(0, $from.parentOffset, undefined, '\ufffc');
  const run = /[ \u00a0]{1,4}$/.exec(before)?.[0].length ?? 0;
  if (run === 0) return false;
  return editor.chain().focus().deleteRange({ from: $from.pos - run, to: $from.pos }).run();
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
  serialize: (fragment: Fragment) => string,
  tightParagraphs: boolean,
  format: 'markdown' | 'plain' = 'markdown',
): string {
  if (format === 'plain') return plainTextForClipboard(content, tightParagraphs);

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
