import { useCallback, useEffect, useRef, useState, type RefObject } from 'react';

// Spec: ops/docs/archive/ui-patterns.md section 137
/** Travel that counts as a scroll in one direction; less is a jitter. */
const STEP_PX = 8;
/** Near the top of a note the bar is always on screen. */
const TOP_PX = 8;
/** A scroll the arrow started ends on `scrollend`; this only covers a browser
 *  that never sends it. A smooth scroll down a long note runs for seconds. */
const HOLD_MS = 5000;
/** The desktop jump pill fades out this long after the last scroll. */
const SHOWN_MS = 2000;

type BarState = { away: boolean; lastY: number };

/**
 * One scroll position in, the phone bar's next state out. Down sends the bar
 * away, up brings it back, and so do the top and the end of the note.
 *
 * Hiding the bar makes the note column taller by the bar's height, which
 * lowers the furthest scroll position by the same amount. The bar therefore
 * only leaves while more than its own height of text remains below: closer to
 * the end, the browser would pull the text down to the new end, the reader
 * would see it jump, and the jump would read as a scroll up.
 */
export function stepBarAway(s: BarState, y: number, maxY: number, barH: number): BarState {
  if (y <= TOP_PX) return { away: false, lastY: y };
  if (s.away && maxY - y <= 2) return { away: false, lastY: y };
  const dy = y - s.lastY;
  if (Math.abs(dy) < STEP_PX) return s;
  if (dy < 0) return { away: false, lastY: y };
  return { away: s.away || maxY - y > barH + STEP_PX, lastY: y };
}

/** The one jump arrow on offer: none ('short'), Go to end ('reading') or
 *  Go to top ('end'). */
export type NoteSpot = 'short' | 'reading' | 'end';

type SpotState = { spot: NoteSpot; lastY: number };

/**
 * One scroll position in, the arrow's next state out. A note taller than one
 * and a half screens offers an arrow; a shorter one has little to jump over.
 * The screen is the window (`screenH`), as a reader counts it, not the
 * editor's scroll area, which the header and the bars make smaller. `viewH`
 * is that scroll area, and it sizes the half-screen zones at the two ends.
 * The arrow points the way the reader is heading: up offers the top, down
 * offers the end. The two ends decide on their own: the last half screen
 * always offers the top and the first half screen the end, where the other
 * jump would go nowhere. A move under the step keeps the arrow, so a jitter
 * never flips it.
 */
export function stepNoteSpot(s: SpotState, y: number, maxY: number, viewH: number, screenH: number): SpotState {
  if (maxY + viewH <= screenH * 1.5) return { spot: 'short', lastY: y };
  if (maxY - y <= viewH / 2) return { spot: 'end', lastY: y };
  if (y <= viewH / 2) return { spot: 'reading', lastY: y };
  const dy = y - s.lastY;
  if (Math.abs(dy) < STEP_PX) return { spot: s.spot === 'short' ? 'reading' : s.spot, lastY: s.lastY };
  return { spot: dy < 0 ? 'end' : 'reading', lastY: y };
}

/**
 * The open note's scroll, read for the chrome around it:
 * - `away`: the phone bar has stepped aside while the note is read (only
 *   with `hideBar`). `bar` is the bar's box, measured as it would leave.
 * - `spot`: which jump arrow the note offers, if any.
 * - `scrolling`: the note moved in the last two seconds, or `keepShown`
 *   holds the desktop pill on screen (the pointer is on it).
 * - `scrollTo`: the arrow's jump. It keeps the bar on screen while it runs: a
 *   scroll asked for from the bar is not a sign that the bar should go.
 * `resetKey` starts over for the next note.
 */
export function useNoteScroll(
  scroller: HTMLElement | null,
  hideBar: boolean,
  resetKey: unknown,
  bar: RefObject<HTMLElement | null>,
): {
  away: boolean;
  spot: NoteSpot;
  scrolling: boolean;
  keepShown: (on: boolean) => void;
  scrollTo: (where: 'top' | 'end') => void;
} {
  const [away, setAway] = useState(false);
  const [spot, setSpot] = useState<NoteSpot>('short');
  const holdUntil = useRef(0);
  const [scrolling, setScrolling] = useState(false);
  const idle = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const pinned = useRef(false);
  const settle = useCallback(() => {
    clearTimeout(idle.current);
    idle.current = setTimeout(() => { if (!pinned.current) setScrolling(false); }, SHOWN_MS);
  }, []);
  const keepShown = useCallback((on: boolean) => {
    pinned.current = on;
    if (on) { clearTimeout(idle.current); setScrolling(true); } else settle();
  }, [settle]);
  useEffect(() => () => clearTimeout(idle.current), []);
  useEffect(() => {
    setAway(false);
    setScrolling(false);
    pinned.current = false;
    if (!scroller) { setSpot('short'); return; }
    let s: BarState = { away: false, lastY: scroller.scrollTop };
    let j: SpotState = { spot: 'short', lastY: scroller.scrollTop };
    const measure = () => {
      j = stepNoteSpot(j, scroller.scrollTop, scroller.scrollHeight - scroller.clientHeight, scroller.clientHeight, window.innerHeight);
      setSpot(j.spot);
    };
    const onScroll = () => {
      measure();
      setScrolling(true);
      settle();
      if (!hideBar) return;
      if (Date.now() < holdUntil.current) { s = { away: false, lastY: scroller.scrollTop }; return; }
      const next = stepBarAway(s, scroller.scrollTop, scroller.scrollHeight - scroller.clientHeight, bar.current?.offsetHeight ?? 0);
      if (next.away !== s.away) setAway(next.away);
      s = next;
    };
    const onScrollEnd = () => { holdUntil.current = 0; };
    // Typing makes a note long without a scroll, and a pane resize changes how
    // long it is, so both boxes are watched too.
    const ro = new ResizeObserver(measure);
    ro.observe(scroller);
    if (scroller.firstElementChild) ro.observe(scroller.firstElementChild);
    measure();
    scroller.addEventListener('scroll', onScroll, { passive: true });
    scroller.addEventListener('scrollend', onScrollEnd);
    return () => {
      ro.disconnect();
      scroller.removeEventListener('scroll', onScroll);
      scroller.removeEventListener('scrollend', onScrollEnd);
    };
  }, [scroller, hideBar, resetKey, bar, settle]);
  const scrollTo = useCallback((where: 'top' | 'end') => {
    if (!scroller) return;
    holdUntil.current = Date.now() + HOLD_MS;
    scroller.scrollTo({ top: where === 'top' ? 0 : scroller.scrollHeight, behavior: 'smooth' });
  }, [scroller]);
  return { away: hideBar && away, spot: scroller ? spot : 'short', scrolling, keepShown, scrollTo };
}
