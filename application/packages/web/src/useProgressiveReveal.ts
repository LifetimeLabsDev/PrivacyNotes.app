/**
 * Render a generous first slice of a long list, and extend it as the end
 * comes into view.
 *
 * Measured on a 2198-item imported vault before this existed: 614ms to switch
 * into the Vault view and 20,415 DOM nodes, because every row was built up
 * front. Committing 200 and growing on scroll brought that to 99.9ms and 2,318
 * nodes, with every row still reachable.
 *
 * Deliberately NOT true windowing (render only what fits, recycle on scroll).
 * That needs row heights in JS, and grid column count is decided by the
 * `pn-list` container queries in index.css rather than by React - windowing the
 * grid would mean moving that decision out of CSS and into measurement, and
 * rows are variable height anyway once tags wrap. This needs no height maths
 * and leaves both layouts untouched.
 *
 * It is NOT a cap: every row stays reachable, it just arrives as you scroll,
 * and no count is affected - the list's own `length` still drives empty states,
 * selection counters and sidebar totals.
 *
 * Spec: ops/docs/design-decisions.md (list progressive reveal)
 */
import { useCallback, useState } from 'react';

const INITIAL = 200;
const STEP = 200;
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
   *  because they typed a character. */
  reset: () => void;
  /** Grow to cover a row that must be on screen, e.g. an already-selected one.
   *  Only ever grows, so it cannot undo a reset. */
  ensure: (index: number) => void;
}

export function useProgressiveReveal(): ProgressiveReveal {
  const [visible, setVisible] = useState(INITIAL);

  const onScroll = useCallback((el: HTMLElement, total: number) => {
    if (el.scrollHeight - el.scrollTop - el.clientHeight >= MARGIN_PX) return;
    // The functional updater returns the same value once everything is
    // committed, so React bails out without re-rendering.
    setVisible((c) => (c < total ? c + STEP : c));
  }, []);

  const reset = useCallback(() => setVisible(INITIAL), []);
  const ensure = useCallback((index: number) => {
    setVisible((c) => (index >= c ? index + STEP : c));
  }, []);

  return { visible, onScroll, reset, ensure };
}
