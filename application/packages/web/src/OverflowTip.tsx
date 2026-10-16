import { useEffect, useRef, useState, type ReactNode } from 'react';
import { usePointMenuPosition } from './usePopoverPosition';
import { TIP_SKIN } from './HoverLabel';

/**
 * Truncation-gated tooltip: reveals the full `text` only when the wrapped
 * content's `.truncate` element actually overflows - names that fit never
 * get tooltip noise. Shows after a 500ms mouse hover, or instantly on
 * keyboard focus. The tip is fixed-positioned and viewport-clamped (via
 * usePointMenuPosition) so overflow-hidden scroll containers like the
 * sidebar can't clip it; like the row menus, it dismisses on scroll and
 * resize instead of floating detached. Touch taps never trigger it (they
 * select the row).
 *
 * Wrap the smallest element that CONTAINS the truncating node, e.g. a
 * tree row's name button. Complements HoverLabel (section 18), which is
 * CSS-only and unconditional.
 */

const HOVER_DELAY_MS = 500;

export function OverflowTip({
  text,
  always = false,
  className,
  children,
}: {
  text: string;
  /** Show it every time, for content with no visible text, such as an
   *  icon-only tab inside a strip whose scroll would cut a CSS tip. It then
   *  shows with no delay, like a HoverLabel. */
  always?: boolean;
  className?: string;
  children: ReactNode;
}) {
  const wrapRef = useRef<HTMLSpanElement>(null);
  const tipRef = useRef<HTMLSpanElement>(null);
  const timer = useRef<number | null>(null);
  const [point, setPoint] = useState<{ x: number; y: number } | null>(null);
  const pos = usePointMenuPosition(point, tipRef);

  const show = () => {
    const el = always ? wrapRef.current : wrapRef.current?.querySelector('.truncate');
    if (!el || (!always && el.scrollWidth <= el.clientWidth)) return;
    const r = el.getBoundingClientRect();
    setPoint({ x: r.left, y: r.bottom + 4 });
  };

  const cancel = () => {
    if (timer.current !== null) {
      window.clearTimeout(timer.current);
      timer.current = null;
    }
    setPoint(null);
  };

  useEffect(() => cancel, []);

  // Fixed-positioned, so scrolling would leave the tip floating detached -
  // dismiss instead (same rule as the folder/tag row menus).
  useEffect(() => {
    if (!point) return;
    const close = () => setPoint(null);
    window.addEventListener('resize', close);
    window.addEventListener('scroll', close, true);
    return () => {
      window.removeEventListener('resize', close);
      window.removeEventListener('scroll', close, true);
    };
  }, [point]);

  return (
    <span
      ref={wrapRef}
      className={className}
      onPointerEnter={(e) => {
        if (e.pointerType !== 'mouse') return;
        if (timer.current !== null) window.clearTimeout(timer.current);
        if (always) { show(); return; }
        timer.current = window.setTimeout(show, HOVER_DELAY_MS);
      }}
      onPointerLeave={cancel}
      onFocusCapture={show}
      onBlurCapture={cancel}
    >
      {children}
      {point && (
        <span
          ref={tipRef}
          role="tooltip"
          // w-max: its own width, up to the cap. A fixed box near the right
          // edge otherwise shrinks to the room left there and wraps against
          // the edge before the clamp can move it.
          style={{
            top: pos?.top ?? point.y,
            left: pos?.left ?? point.x,
            visibility: pos ? 'visible' : 'hidden',
          }}
          className={`fixed z-[60] pointer-events-none ${TIP_SKIN} w-max max-w-[280px] whitespace-normal break-words`}
        >
          {text}
        </span>
      )}
    </span>
  );
}
