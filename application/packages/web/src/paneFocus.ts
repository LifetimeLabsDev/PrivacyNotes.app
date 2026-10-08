/**
 * F6 and Shift+F6: move the focus to the next or previous pane (the
 * sidebar, the list, the editor), the Windows convention for an app made of
 * panes. A pane is an element with `data-pane`, in document order, and only
 * a pane on screen counts. Focus lands on the pane's own place: the note
 * text in the editor, the open row in the list, a tag or folder row in the
 * sidebar; else on the pane's first control.
 *
 * Spec: ops/docs/plans/keyboard-shortcuts.md (section 6)
 */

/** The places of each pane, best first. */
const PLACE: Record<string, string[]> = {
  editor: ['.ProseMirror[contenteditable="true"]', 'textarea', 'input'],
  list: ['[data-item-id][aria-current]', '[data-item-id]', 'input'],
  sidebar: ['[data-row-name]'],
};
const FOCUSABLE = 'button:not([disabled]), [href], input:not([disabled]), textarea, [tabindex]:not([tabindex="-1"]), [contenteditable="true"]';

const shown = (el: Element) => el.getClientRects().length > 0;

function focusIn(pane: HTMLElement): boolean {
  const candidates = [...(PLACE[pane.dataset.pane ?? ''] ?? []), FOCUSABLE].flatMap((selector) => [
    ...pane.querySelectorAll<HTMLElement>(selector),
  ]);
  for (const el of candidates) {
    if (!shown(el)) continue;
    // A row is not a control: it takes the focus only from the keyboard.
    if (el.matches('[data-item-id]')) el.tabIndex = -1;
    el.focus();
    if (document.activeElement === el) return true;
  }
  return false;
}

export function focusPane(direction: 1 | -1): void {
  const panes = Array.from(document.querySelectorAll<HTMLElement>('[data-pane]')).filter(shown);
  if (panes.length === 0) return;
  const current = panes.findIndex((p) => p.contains(document.activeElement));
  let at = current < 0 ? (direction === 1 ? -1 : 0) : current;
  // A pane with nothing to focus is passed over.
  for (let tries = 0; tries < panes.length; tries++) {
    at = (at + direction + panes.length) % panes.length;
    if (focusIn(panes[at]!)) return;
  }
}
