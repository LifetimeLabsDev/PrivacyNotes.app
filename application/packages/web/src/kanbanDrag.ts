import type { Editor as TipTapEditor } from '@tiptap/react';
import i18n from './i18n';
import { CARD_MENU_EVENT, cardPlace, moveCard, type CardMenuDetail } from './kanban';

/**
 * The grip of a Kanban card. A drag moves the card to another place in its
 * column or into another column of the same board; a tap (no movement) opens
 * the board's Move to menu, which is the path on a phone, where a long press
 * selects text, and from the keyboard. One transaction on release, so undo
 * takes the move back.
 * Spec: ops/issues/0270.md (Spec, move a card)
 */

/** The board and column of a top-level card, or null for any other task. */
export function kanbanCardOf(item: HTMLElement): { board: HTMLElement; column: HTMLElement } | null {
  const list = item.parentElement;
  const column = list?.closest('.pn-callout');
  if (!list || !(column instanceof HTMLElement) || column.dataset.type !== 'column') return null;
  // A sub-task sits in a list inside another task: not a card.
  if (list.parentElement?.closest('li, .pn-callout') !== column) return null;
  const board = column.parentElement?.closest('.pn-callout');
  if (!(board instanceof HTMLElement) || board.dataset.type !== 'kanban') return null;
  return { board, column };
}

function columnsOf(board: HTMLElement): HTMLElement[] {
  return [...board.querySelectorAll<HTMLElement>('.pn-callout[data-type="column"]')].filter(
    (c) => c.parentElement?.closest('.pn-callout') === board,
  );
}

/** The first top-level task list of a column: the one its cards live in. */
function cardListOf(column: HTMLElement): HTMLElement | null {
  for (const list of column.querySelectorAll<HTMLElement>('ul[data-type="taskList"]')) {
    if (list.parentElement?.closest('li, .pn-callout') === column) return list;
  }
  return null;
}

/**
 * The grip of a card is a Move to button for VoiceOver; a plain task's grip
 * stays hidden from it, because a drag is its only use. Run once, when the
 * task's view is made: a card that moves gets a new view.
 */
export function markCardGrip(grip: HTMLElement, item: HTMLElement) {
  if (!kanbanCardOf(item)) return;
  grip.removeAttribute('aria-hidden');
  grip.setAttribute('role', 'button');
  grip.setAttribute('aria-label', i18n.t('editor:kanban.moveTo'));
}

/** Asks the card's board for its Move to menu, at the grip. A tap, and an
 *  activation by VoiceOver or a switch device, both land here. */
export function openCardMenu(grip: HTMLElement, getPos: () => number | undefined, editor: TipTapEditor) {
  const pos = getPos();
  if (typeof pos !== 'number' || !editor.isEditable) return;
  const place = cardPlace(editor.state.doc, pos);
  if (!place) return;
  const r = grip.getBoundingClientRect();
  const detail: CardMenuDetail = { pos, column: place.column, x: r.left, y: r.bottom + 4 };
  grip.dispatchEvent(new CustomEvent(CARD_MENU_EVENT, { bubbles: true, detail }));
}

/** Distance in px a pointer moves before a press becomes a drag. */
const DRAG_START = 5;

export function dragCard(event: PointerEvent, item: HTMLElement, getPos: () => number | undefined, editor: TipTapEditor) {
  const card = kanbanCardOf(item);
  if (!card || !editor.isEditable || event.button !== 0) return;
  event.preventDefault();
  const grip = event.currentTarget as HTMLElement;
  try {
    grip.setPointerCapture(event.pointerId);
  } catch {
    /* the window listeners below still follow the pointer */
  }
  const pointerId = event.pointerId;
  const startX = event.clientX;
  const startY = event.clientY;
  const columns = columnsOf(card.board);
  let dragging = false;
  let target: { column: number; index: number | undefined } | null = null;
  const marker = document.createElement('div');
  marker.className = 'pn-task-drop';

  const place = (x: number, y: number) => {
    item.style.transform = `translate(${x - startX}px, ${y - startY}px)`;
    // The column under the pointer, or the nearest one.
    let best = -1;
    let bestDist = Infinity;
    columns.forEach((col, i) => {
      const r = col.getBoundingClientRect();
      const dx = x < r.left ? r.left - x : x > r.right ? x - r.right : 0;
      const dy = y < r.top ? r.top - y : y > r.bottom ? y - r.bottom : 0;
      const d = dx * dx + dy * dy;
      if (d < bestDist) {
        bestDist = d;
        best = i;
      }
    });
    if (best < 0) return;
    const col = columns[best]!;
    columns.forEach((c) => c.classList.toggle('pn-kanban-drop-target', c === col));
    const list = cardListOf(col);
    const siblings = list ? [...list.children].filter((el): el is HTMLElement => el instanceof HTMLElement && el !== item) : [];
    let index = siblings.findIndex((el) => {
      const r = el.getBoundingClientRect();
      return r.top + r.height / 2 > y;
    });
    if (index < 0) index = siblings.length;
    target = { column: best, index: list ? index : undefined };
    const box = (list ?? col).getBoundingClientRect();
    const edge = siblings.length === 0
      ? (list ? box.top : box.bottom - 6)
      : index < siblings.length
        ? siblings[index]!.getBoundingClientRect().top
        : siblings[siblings.length - 1]!.getBoundingClientRect().bottom;
    marker.style.display = 'block';
    marker.style.top = `${edge - 1}px`;
    marker.style.left = `${box.left}px`;
    marker.style.width = `${box.width}px`;
  };

  const onMove = (e: PointerEvent) => {
    if (e.pointerId !== pointerId) return;
    if (!dragging) {
      if (Math.hypot(e.clientX - startX, e.clientY - startY) < DRAG_START) return;
      dragging = true;
      document.body.append(marker);
      item.classList.add('pn-task-dragging');
      document.documentElement.classList.add('pn-task-drag-active');
    }
    place(e.clientX, e.clientY);
  };
  const finish = (drop: boolean) => {
    window.removeEventListener('pointermove', onMove);
    window.removeEventListener('pointerup', onUp);
    window.removeEventListener('pointercancel', onCancel);
    window.removeEventListener('keydown', onKey, true);
    marker.remove();
    columns.forEach((c) => c.classList.remove('pn-kanban-drop-target'));
    item.classList.remove('pn-task-dragging');
    item.style.transform = '';
    document.documentElement.classList.remove('pn-task-drag-active');
    const pos = getPos();
    if (typeof pos !== 'number') return;
    if (!dragging) {
      // A tap: the board opens Move to at the grip.
      if (drop) openCardMenu(grip, getPos, editor);
      return;
    }
    if (drop && target && editor.isEditable) {
      const tr = editor.state.tr;
      if (moveCard(tr, pos, target.column, target.index)) editor.view.dispatch(tr);
    }
  };
  const onUp = (e: PointerEvent) => { if (e.pointerId === pointerId) finish(true); };
  const onCancel = (e: PointerEvent) => { if (e.pointerId === pointerId) finish(false); };
  const onKey = (e: KeyboardEvent) => {
    if (e.key !== 'Escape') return;
    e.preventDefault();
    e.stopPropagation();
    dragging = true;
    target = null;
    finish(false);
  };
  window.addEventListener('pointermove', onMove);
  window.addEventListener('pointerup', onUp);
  window.addEventListener('pointercancel', onCancel);
  window.addEventListener('keydown', onKey, true);
}
