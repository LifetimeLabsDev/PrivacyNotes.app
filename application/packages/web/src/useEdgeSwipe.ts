import { useEffect, useRef } from 'react';

// Spec: ops/docs/ui-patterns.md (section 38 - mobile drawer gestures)
/** Default eligibility: touches starting within this many px of the left viewport edge. */
export const EDGE_START_PX = 24;
/** Rightward travel that commits the gesture. */
const OPEN_DISTANCE_PX = 60;
/** Vertical travel beyond this cancels the gesture (it is a scroll). */
const VERTICAL_SLOP_PX = 30;

/**
 * Rightward swipe-to-open gesture (fling, not drag-follow). Fires
 * `onSwipe` once when an eligible touch travels far enough rightward
 * while staying dominantly horizontal. Eligibility defaults to "starts
 * within EDGE_START_PX of the left viewport edge"; pass `eligibleStart`
 * to widen it (e.g. anywhere inside the notes list pane), since on
 * gesture-nav Android and iOS Safari the OS reserves the literal edge
 * for its own back gesture and edge touches never reach us - which is
 * the intended degradation there (Back must keep meaning Back).
 *
 * Listeners are passive and touch-only, so desktop mice never trigger
 * it and scrolling never janks.
 */
export function useEdgeSwipe(
  onSwipe: () => void,
  enabled: boolean,
  eligibleStart?: (t: Touch) => boolean
) {
  // Latest-callback refs so the effect only rebinds when `enabled` flips.
  const cbRef = useRef(onSwipe);
  cbRef.current = onSwipe;
  const eligibleRef = useRef(eligibleStart);
  eligibleRef.current = eligibleStart;

  useEffect(() => {
    if (!enabled) return;
    let start: { x: number; y: number; id: number } | null = null;

    function onTouchStart(e: TouchEvent) {
      // Single-finger gestures only; a second finger cancels tracking.
      if (e.touches.length !== 1) {
        start = null;
        return;
      }
      const t = e.touches[0];
      if (!t) return;
      const eligible = eligibleRef.current
        ? eligibleRef.current(t)
        : t.clientX <= EDGE_START_PX;
      if (!eligible) return;
      start = { x: t.clientX, y: t.clientY, id: t.identifier };
    }

    function onTouchMove(e: TouchEvent) {
      const s = start;
      if (!s) return;
      let t: Touch | undefined;
      for (let i = 0; i < e.changedTouches.length; i++) {
        const c = e.changedTouches[i];
        if (c && c.identifier === s.id) {
          t = c;
          break;
        }
      }
      if (!t) return;
      const dx = t.clientX - s.x;
      const dy = Math.abs(t.clientY - s.y);
      if (dy > VERTICAL_SLOP_PX && dy > dx) {
        // Dominantly vertical - it is a scroll, not a swipe.
        start = null;
        return;
      }
      if (dx >= OPEN_DISTANCE_PX && dx > dy * 1.5) {
        start = null;
        cbRef.current();
      }
    }

    function onTouchEnd() {
      start = null;
    }

    window.addEventListener('touchstart', onTouchStart, { passive: true });
    window.addEventListener('touchmove', onTouchMove, { passive: true });
    window.addEventListener('touchend', onTouchEnd, { passive: true });
    window.addEventListener('touchcancel', onTouchEnd, { passive: true });
    return () => {
      window.removeEventListener('touchstart', onTouchStart);
      window.removeEventListener('touchmove', onTouchMove);
      window.removeEventListener('touchend', onTouchEnd);
      window.removeEventListener('touchcancel', onTouchEnd);
    };
  }, [enabled]);
}
