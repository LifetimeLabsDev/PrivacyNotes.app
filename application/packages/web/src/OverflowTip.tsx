import { useEffect, useRef, useState, type ReactNode } from 'react';
import { usePointMenuPosition } from './usePopoverPosition';

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
  className,
  children,
}: {
  text: string;
  className?: string;
  children: ReactNode;
}) {
  const wrapRef = useRef<HTMLSpanElement>(null);
  const tipRef = useRef<HTMLSpanElement>(null);
  const timer = useRef<number | null>(null);
  const [point, setPoint] = useState<{ x: number; y: number } | null>(null);
  const pos = usePointMenuPosition(point, tipRef);

  const show = () => {
    const el = wrapRef.current?.querySelector('.truncate');
    if (!el || el.scrollWidth <= el.clientWidth) return;
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
          style={{
            top: pos?.top ?? point.y,
            left: pos?.left ?? point.x,
            visibility: pos ? 'visible' : 'hidden',
          }}
          className="fixed z-[60] pointer-events-none px-2.5 py-1.5 rounded-md bg-neutral-900 dark:bg-neutral-800 border border-neutral-700 text-[12px] text-neutral-100 max-w-[280px] whitespace-normal break-words leading-snug"
        >
          {text}
        </span>
      )}
    </span>
  );
}
