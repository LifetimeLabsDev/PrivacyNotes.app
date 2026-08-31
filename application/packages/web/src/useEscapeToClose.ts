import { useEffect, useRef } from 'react';

/**
 * Global Escape-to-close hook for modals.
 *
 * Attaches a capture-phase keydown listener so modals close before any
 * other Escape handler (search clear, selection-mode exit, etc.) can
 * claim the event. Capture phase also means the hook works even when
 * focus is inside an input/textarea within the modal.
 *
 * Nested modals: handlers are tracked in a LIFO stack and only the
 * most-recently-opened (topmost) one acts on Escape. So a sub-dialog
 * opened on top of a modal closes by itself first, without the modal
 * behind it also closing. (Registration order alone can't do this -
 * the outer modal registers first and would otherwise win.)
 *
 * Pass `enabled={false}` to disable the hook temporarily without
 * unmounting it.
 */
type EscEntry = { id: symbol; close: () => void };

const escStack: EscEntry[] = [];

/**
 * Close the topmost open overlay (modal, popover, sheet, drawer, ...)
 * exactly as Escape would. Returns true when one was open. Lets the
 * Android back button walk the same LIFO stack without synthesizing
 * keyboard events. See androidBack.ts.
 */
export function closeTopOverlay(): boolean {
  const top = escStack[escStack.length - 1];
  if (!top) return false;
  top.close();
  return true;
}

/** True while any Escape-dismissible overlay is open. */
export function hasOpenOverlay(): boolean {
  return escStack.length > 0;
}

export function useEscapeToClose(onClose: () => void, enabled = true) {
  // Keep the latest callback in a ref so the effect only re-runs (and
  // re-orders the stack) when `enabled` flips, not on every render.
  const cbRef = useRef(onClose);
  cbRef.current = onClose;

  useEffect(() => {
    if (!enabled) return;
    const id = Symbol('esc');
    escStack.push({ id, close: () => cbRef.current() });
    function handler(e: KeyboardEvent) {
      if (e.key !== 'Escape') return;
      if (e.defaultPrevented) return;
      // Only the topmost open handler responds.
      if (escStack[escStack.length - 1]?.id !== id) return;
      e.stopPropagation();
      e.preventDefault();
      cbRef.current();
    }
    window.addEventListener('keydown', handler, true);
    return () => {
      window.removeEventListener('keydown', handler, true);
      const i = escStack.findIndex((entry) => entry.id === id);
      if (i !== -1) escStack.splice(i, 1);
    };
  }, [enabled]);
}
