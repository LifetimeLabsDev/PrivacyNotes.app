import type { KeyboardEvent as ReactKeyboardEvent } from 'react';
import { isEditableTarget } from './ContextMenu';
import { isImeComposing } from './imeComposing';
import { foldText } from './textFold';

/**
 * Keys inside the tag list and the folder tree, where each row's main button
 * carries `data-row-name` (GitHub #260 and the #395 thread). Up and Down move
 * between the rows, and a letter jumps to the next row whose name starts
 * with it; the same letter again moves on. In the folder tree Left closes the
 * row's folder (or goes to its parent) and Right opens it (or goes to its
 * first child), the WAI-ARIA tree pattern, mirrored in a right-to-left
 * language. A key used here is cancelled, so the app's own J and K wait.
 *
 * Spec: ops/docs/archive/keyboard-shortcuts.md (section 6)
 */
export function onRowListKeyDown(e: ReactKeyboardEvent<HTMLElement>): void {
  if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey || isImeComposing(e)) return;
  // A rename field sits inside its row: its keys are typing.
  if (isEditableTarget(e.target)) return;
  const current = (e.target as HTMLElement).closest<HTMLElement>('[data-row-name]');
  if (!current) return;
  const rows = Array.from(e.currentTarget.querySelectorAll<HTMLElement>('[data-row-name]'));
  const at = rows.indexOf(current);
  const go = (row: HTMLElement | undefined) => {
    if (!row) return;
    e.preventDefault();
    row.focus();
    row.scrollIntoView({ block: 'nearest' });
  };

  if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
    go(rows[at + (e.key === 'ArrowDown' ? 1 : -1)]);
    return;
  }

  const item = current.closest<HTMLElement>('[role="treeitem"]');
  if (item && (e.key === 'ArrowLeft' || e.key === 'ArrowRight')) {
    const rtl = getComputedStyle(current).direction === 'rtl';
    const open = (e.key === 'ArrowRight') !== rtl;
    const expanded = item.getAttribute('aria-expanded');
    const caret = item.querySelector<HTMLElement>(':scope > button[data-no-drag]');
    if (open && expanded === 'false') {
      e.preventDefault();
      caret?.click();
    } else if (open && expanded === 'true') {
      go(item.parentElement?.querySelector<HTMLElement>(':scope > [role="group"] [data-row-name]') ?? undefined);
    } else if (!open && expanded === 'true') {
      e.preventDefault();
      caret?.click();
    } else if (!open) {
      const parent = item.parentElement?.closest('[role="group"]')?.parentElement;
      go(parent?.querySelector<HTMLElement>(':scope > [role="treeitem"] [data-row-name]') ?? undefined);
    }
    return;
  }

  if (e.key.length !== 1 || e.key === ' ') return;
  const letter = foldText(e.key);
  const name = (row: HTMLElement) => foldText(row.dataset.rowName ?? '');
  const after = [...rows.slice(at + 1), ...rows.slice(0, at + 1)];
  e.preventDefault();
  go(after.find((row) => name(row).startsWith(letter)));
}

/** Left and Right on a two-button switch move to the other button and press it. */
export function onSwitchKeyDown(e: ReactKeyboardEvent<HTMLElement>): void {
  if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
  if (e.metaKey || e.ctrlKey || e.altKey || e.shiftKey) return;
  const other = Array.from(e.currentTarget.querySelectorAll<HTMLElement>('button')).find(
    (b) => b !== e.target && b.getAttribute('aria-pressed') === 'false',
  );
  if (!other) return;
  e.preventDefault();
  other.focus();
  other.click();
}
