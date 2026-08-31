import { useCallback, useLayoutEffect, useState } from 'react';
import type { RefObject } from 'react';

export interface PopoverPos {
  top: number;
  left: number;
}

interface PopoverPositionOptions {
  /** Gap between the trigger and the popover, in px. */
  gap?: number;
  /** Minimum distance the popover keeps from every viewport edge, in px. */
  margin?: number;
  /**
   * Horizontal alignment to the trigger: 'start' aligns their left edges
   * (default), 'end' aligns their right edges. Either way the popover then
   * shifts inward so it never spills off a viewport edge.
   */
  align?: 'start' | 'end';
}

/**
 * Position a portal-rendered popover anchored under a trigger button so it can
 * never be clipped by the viewport, no matter where the trigger sits.
 *
 * It measures the *rendered* popover (so there are no hardcoded widths to keep
 * in sync), shifts horizontally to stay on-screen, and flips above the trigger
 * when there is no room below. Recomputes on scroll/resize while open.
 *
 * Returns null until the first measurement. Render the popover while `open` is
 * true and give it `visibility: pos ? 'visible' : 'hidden'` so it never flashes
 * at a stale position before it is placed. Spec: ops/docs/ui-patterns.md
 * (scroll listener uses capture phase to catch scrollable ancestors, not just window)
 */
export function usePopoverPosition<A extends HTMLElement, P extends HTMLElement>(
  open: boolean,
  anchorRef: RefObject<A | null>,
  popoverRef: RefObject<P | null>,
  { gap = 4, margin = 8, align = 'start' }: PopoverPositionOptions = {},
): PopoverPos | null {
  const [pos, setPos] = useState<PopoverPos | null>(null);

  const compute = useCallback(() => {
    const anchor = anchorRef.current;
    const pop = popoverRef.current;
    if (!anchor || !pop) return;
    const a = anchor.getBoundingClientRect();
    const p = pop.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;

    // Horizontal: align to the trigger's chosen edge, then slide inward to fit.
    let left = align === 'end' ? a.right - p.width : a.left;
    if (left + p.width > vw - margin) left = vw - p.width - margin;
    left = Math.max(margin, left);

    // Vertical: open below the trigger; flip above when the bottom would clip;
    // if neither side fits (very short viewport), shift up to the last spot.
    let top = a.bottom + gap;
    if (top + p.height > vh - margin) {
      const above = a.top - p.height - gap;
      top = above >= margin ? above : Math.max(margin, vh - p.height - margin);
    }

    setPos({ top, left });
  }, [anchorRef, popoverRef, gap, margin, align]);

  useLayoutEffect(() => {
    if (!open) {
      setPos(null);
      return;
    }
    compute();
    const onScroll = () => compute();
    window.addEventListener('resize', compute);
    window.addEventListener('scroll', onScroll, true);
    // Re-place when the popover's own size changes (e.g. a menu whose items
    // toggle while open) so it stays anchored and on-screen without callers
    // wiring content into the dep array.
    let ro: ResizeObserver | undefined;
    if (typeof ResizeObserver !== 'undefined' && popoverRef.current) {
      ro = new ResizeObserver(() => compute());
      ro.observe(popoverRef.current);
    }
    return () => {
      window.removeEventListener('resize', compute);
      window.removeEventListener('scroll', onScroll, true);
      ro?.disconnect();
    };
  }, [open, compute, popoverRef]);

  return pos;
}

/**
 * Position a fixed menu anchored to a *point* (a right-click location or a
 * computed corner) so it can never be clipped: it measures the rendered menu
 * and shifts it inward on both axes to stay within the viewport. Use this for
 * cursor/coordinate-anchored context menus - where there is no trigger element
 * to hand to usePopoverPosition. Mirrors the clamp in `ContextMenu.tsx`.
 *
 * `point` is the desired top-left corner in viewport coordinates (pass null
 * when the menu is closed). Returns null until measured; render the menu and
 * set `visibility: pos ? 'visible' : 'hidden'` to avoid a flash at the raw,
 * pre-clamp point. Spec: ops/docs/ui-patterns.md section 15 (measure the real
 * menu rather than a hardcoded height/width guess)
 */
export function usePointMenuPosition<P extends HTMLElement>(
  point: { x: number; y: number } | null,
  menuRef: RefObject<P | null>,
  { margin = 8 }: { margin?: number } = {},
): PopoverPos | null {
  const px = point?.x ?? null;
  const py = point?.y ?? null;
  const [pos, setPos] = useState<PopoverPos | null>(null);

  const compute = useCallback(() => {
    const menu = menuRef.current;
    if (px == null || py == null || !menu) return;
    const m = menu.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    let left = px;
    let top = py;
    if (left + m.width > vw - margin) left = Math.max(margin, vw - m.width - margin);
    if (top + m.height > vh - margin) top = Math.max(margin, vh - m.height - margin);
    setPos({ top, left });
  }, [px, py, menuRef, margin]);

  useLayoutEffect(() => {
    if (px == null || py == null) {
      setPos(null);
      return;
    }
    compute();
    window.addEventListener('resize', compute);
    return () => window.removeEventListener('resize', compute);
  }, [px, py, compute]);

  return pos;
}
