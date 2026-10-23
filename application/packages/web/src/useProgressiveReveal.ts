/**
 * Render a generous first slice of a long list, and extend it as the end
 * comes into view.
 *
 * Bounds the initial work independently of item windowing. Large note lists
 * use WindowedNoteItem to unmount distant contents after they are revealed;
 * other lists keep their revealed rows mounted.
 *
 * It is NOT a cap: every row stays reachable, it just arrives as you scroll,
 * and no count is affected - the list's own `length` still drives empty states,
 * selection counters and sidebar totals.
 *
 * Spec: ops/docs/design-decisions.md (list progressive reveal)
 */
import { useCallback, useState } from 'react';

const INITIAL = 100;
const STEP = 100;
/** Distance from the end, in px, that pulls in the next slice. Roughly two
 *  screens, so rows commit before the user can scroll past where they end. */
const MARGIN_PX = 1200;

export interface ProgressiveReveal {
  /** How many rows to render. Slice the list with this. */
  visible: number;
  /** Attach to the scroll container's `onScroll`. */
  onScroll: (el: HTMLElement, total: number) => void;
  /** Call when the list becomes a DIFFERENT list - a new view, search or
   *  filter. Not on content changes: that array is rebuilt on every edit, and
   *  resetting there would yank a user scrolled deep back to the first slice
   *  because they typed a character. An optional saved count restores that
   *  slice exactly, without the extra buffer used by ensure. */
  reset: (count?: number) => void;
  /** Grow to cover a row that must be on screen, e.g. an already-selected one.
   *  Only ever grows, so it cannot undo a reset. */
  ensure: (index: number) => void;
}

export function useProgressiveReveal(initialCount?: () => number | undefined): ProgressiveReveal {
  const [visible, setVisible] = useState(() => Math.max(INITIAL, initialCount?.() ?? INITIAL));

  const onScroll = useCallback((el: HTMLElement, total: number) => {
    if (el.scrollHeight - el.scrollTop - el.clientHeight >= MARGIN_PX) return;
    // The functional updater returns the same value once everything is
    // committed, so React bails out without re-rendering.
    setVisible((c) => (c < total ? c + STEP : c));
  }, []);

  const reset = useCallback((count = INITIAL) => setVisible(Math.max(INITIAL, count)), []);
  const ensure = useCallback((index: number) => {
    setVisible((c) => (index >= c ? index + STEP : c));
  }, []);

  return { visible, onScroll, reset, ensure };
}
