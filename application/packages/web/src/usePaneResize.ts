/**
 * Drag-to-resize for the sidebar and notes-list panes (GitHub #211).
 *
 * The EXPANDED collapse strips double as drag handles: pointer down and
 * release with movement under the threshold is a click (collapse, exactly
 * the behaviour the strips always had), movement past it is a resize that
 * clamps to [min, max] - dragging below the minimum just pins at min.
 * Arrow keys resize in 16px steps when the strip is focused, Enter/Space
 * collapses, Escape cancels an in-flight drag (width snaps back). A drag
 * that carries the pointer well past the limit on the collapsing side is
 * magnetic: the badge names the collapse, and a RELEASE there collapses the
 * pane. The width never jumps during the drag, it stays at the limit, so
 * the snap only happens once and on release; the sidebar divider between
 * Content and the tags works the same way (useSidebarSplit.ts). The COLLAPSED expand
 * strips stay plain click-to-expand buttons with no resize affordance: a
 * drag there would act on an unmounted pane with no visual feedback, so
 * advertising it would mislead (design call, #211).
 *
 * A drag ALWAYS terminates. The strip's own pointerup is only one of four
 * finishers: window-level capture-phase pointerup/pointercancel listeners
 * (attached for the drag's duration) catch a release the strip never
 * receives, lostpointercapture catches the capture dying for any reason
 * (e.g. the strip unmounting mid-drag - Cmd+Shift+F zen during a drag),
 * and Escape cancels. Without this, one missed pointerup left the global
 * col-resize cursor stuck until the next strip click (first-round bug).
 * The four are not equal, though: only a RELEASE can collapse. A pointer
 * the platform cancels or a capture that dies ends the drag and leaves
 * the pane alone, because neither is a click - a touch device cancels
 * the finger resting on the strip every time it rotates, and a collapse
 * there is both unasked for and persisted.
 *
 * Perf contract: during a drag the width is written imperatively as a CSS
 * variable on NotesView's root div (one style write per move) plus the
 * fixed-position badge next to the pointer. React state commits ONCE on
 * release, so NotesView never re-renders mid-drag. The rendered width is
 * `min(var(--pn-*-w), <max>px, <vw cap>)` in the pane's className, so
 * viewport shrink clamps declaratively with no resize listeners (the
 * stored width survives and comes back when the window grows).
 *
 * Collapse stays a separate axis: this hook never persists a collapse
 * boolean and the collapse code never rewrites a width. sidebarCollapsed
 * keeps its session-only xl reseed; the stored width simply applies
 * whenever the pane is expanded.
 *
 * Spec: ops/docs/design-decisions.md (pane resize), ops/docs/ui-patterns.md section 56
 */
import { useEffect, useRef, type RefObject } from 'react';
import { hasOpenOverlay, closeTopOverlay } from './useEscapeToClose';

// Clamps. Sidebar min equals the current w-60: the TagsRail footer-pill
// width math is tuned to exactly 240px (ui-patterns section 46), so the
// sidebar only grows. The vw caps guarantee the editor keeps a usable
// column at every window size; they are duplicated in the pane className
// strings in NotesView (min(var(...), 420px, 30vw) / min(var(...), 620px, 40vw)).
// Spec: ops/docs/design-decisions.md (pane resize clamps)
export const SIDEBAR_WIDTH_DEFAULT = 240;
export const SIDEBAR_WIDTH_MIN = 240;
export const SIDEBAR_WIDTH_MAX = 420;
export const SIDEBAR_VIEWPORT_CAP = 0.3;
export const LIST_WIDTH_DEFAULT = 288;
// The list floor is the SelectionToolbar's intrinsic width, not a taste
// call: px-4 padding (32) + the exit X (32) + gap-3 (12) + five 36px
// action buttons with four 6px gaps (204) = 280. Both toolbar clusters
// are shrink-0, so anything narrower clipped the last action - the
// delete button - straight off the pane edge.
export const LIST_WIDTH_MIN = 280;
export const LIST_WIDTH_MAX = 620;
export const LIST_VIEWPORT_CAP = 0.4;
// Docked grid mode (>=1400px with a note open) inverts the flex roles:
// the editor is the fixed pane and the GRID takes the remainder, so the
// grid needs its own floor and the divider drag sizes the editor column.
// The DEFAULT stays 830 (the TipTap toolbar fully visible, ui-patterns
// section 32) but the MINIMUM is 480: the toolbar's overflow menu and the
// compact header (<560px) degrade a narrow editor gracefully, and list
// mode already ships ~456px editors at the md breakpoint - the old 830
// floor made the divider barely draggable. GRID_DOCK_MIN is 320 so two
// tiles sit side by side (the pn-list container query flips to 2 columns
// at 320); 240 + 24 + 320 + 480 = 1064 < 1400, so the full floor holds at
// every docked window (the min() formula in --pn-grid-min stays as a
// guard for future constant changes). The system is closed: the sidebar's
// docked cap subtracts the editor MINIMUM and the full grid floor, while
// the editor's cap subtracts the grid floor and the sidebar's ACTUAL
// rendered width - so the grid remainder can never fall below the floor
// no matter which caps bind. The formulas live in the --pn-* render vars
// on NotesView's root div (reserves derived in NotesView.tsx).
// Spec: ops/docs/design-decisions.md (pane resize clamps)
export const EDITOR_DOCK_DEFAULT = 830;
export const EDITOR_DOCK_MIN = 480;
export const EDITOR_DOCK_STORE_MAX = 1600;
export const GRID_DOCK_MIN = 320;
// The rendered width of one divider strip, expanded or collapsed - it must
// match the `w-3` on all six strip buttons in NotesView (Tailwind only sees
// literal class strings, so the number cannot be interpolated there). The
// docked-grid clamp system reserves TWO of them, hence STRIPS_W.
// Spec: ops/docs/design-decisions.md (pane resize clamps)
const STRIP_W = 12;
export const STRIPS_W = STRIP_W * 2;
const DRAG_THRESHOLD_PX = 4;
const KEY_STEP_PX = 16;
// How far past the limit the pointer travels before a release collapses.
// Spec: ops/docs/ui-patterns.md section 56
const SNAP_PX = 56;

type DragState = {
  pointerId: number;
  startX: number;
  startWidth: number;
  moved: boolean;
  lastWidth: number | null;
  /** The pointer is past the limit: a release collapses. */
  snap: boolean;
  /** The strip element captured at pointerdown - cleanup must not depend
      on a later event delivering the same currentTarget. */
  el: HTMLElement;
  removeWindowListeners: () => void;
};

export type PaneResizeStripProps = {
  onPointerDown: (e: React.PointerEvent<HTMLElement>) => void;
  onPointerMove: (e: React.PointerEvent<HTMLElement>) => void;
  onPointerUp: (e: React.PointerEvent<HTMLElement>) => void;
  onPointerCancel: (e: React.PointerEvent<HTMLElement>) => void;
  onLostPointerCapture: (e: React.PointerEvent<HTMLElement>) => void;
  onKeyDown: (e: React.KeyboardEvent<HTMLElement>) => void;
};

export function usePaneResize(cfg: {
  /** NotesView's root div - carries the CSS variable and the drag cursor class. */
  rootRef: RefObject<HTMLDivElement | null>;
  /** The fixed-position live-width badge (shared by both panes). */
  badgeRef: RefObject<HTMLDivElement | null>;
  cssVar: '--pn-sidebar-w' | '--pn-list-w' | '--pn-editor-w';
  min: number;
  /** Live drag ceiling - re-evaluated per clamp so it can depend on the
      viewport and sibling panes (the editor dock cap does). */
  getMax: () => number;
  /** The editor-dock divider sits LEFT of its pane, so dragging right
      SHRINKS it - set invert to flip the axis (pointer and arrows). */
  invert?: boolean;
  /** Committed width from state (the strip only renders while expanded). */
  width: number;
  onCommitWidth: (w: number) => void;
  onCollapse: () => void;
  /** The badge text while a release would collapse the pane. */
  snapLabel: string;
  /** Which end collapses: 'min' for a pane that shrinks away (sidebar,
      list), 'max' when growing this pane squeezes out its neighbour (the
      docked editor, whose growth collapses the grid). */
  snapAt: 'min' | 'max';
}): { stripProps: PaneResizeStripProps } {
  const dragRef = useRef<DragState | null>(null);

  const clampWidth = (raw: number) =>
    Math.round(Math.max(cfg.min, Math.min(cfg.getMax(), raw)));
  const setVar = (px: number) =>
    cfg.rootRef.current?.style.setProperty(cfg.cssVar, `${px}px`);

  const badge = (e: React.PointerEvent<HTMLElement>, text: string) => {
    const el = cfg.badgeRef.current;
    if (!el) return;
    el.dataset.on = '1';
    el.textContent = text;
    el.style.left = `${e.clientX + 14}px`;
    el.style.top = `${e.clientY - 30}px`;
  };

  /** Tear down ALL drag state and visuals; idempotent. Returns the drag
      that was active so callers can decide what to commit. */
  const teardown = (): DragState | null => {
    const drag = dragRef.current;
    if (!drag) return null;
    dragRef.current = null;
    drag.removeWindowListeners();
    delete drag.el.dataset.dragging;
    delete drag.el.dataset.snap;
    cfg.rootRef.current?.classList.remove('pn-col-dragging');
    const b = cfg.badgeRef.current;
    if (b) delete b.dataset.on;
    try {
      drag.el.releasePointerCapture(drag.pointerId);
    } catch {
      /* capture already gone */
    }
    return drag;
  };

  /** Normal end: commit the width (or treat as click if never moved).
      A press that never moved collapses only when the pointer was
      RELEASED. A pointer the platform cancels is not a click, and on
      touch the platform cancels the finger resting on the strip every
      time the device rotates, where a collapse is both unasked for and
      persisted. Termination is unconditional either way; only the
      collapse waits for a real release. */
  const finishDrag = (released: boolean) => {
    const drag = teardown();
    if (!drag) return;
    if (!drag.moved) {
      // Clean click: the strip's historical collapse toggle.
      if (released) cfg.onCollapse();
      return;
    }
    if (drag.snap) {
      if (released) cfg.onCollapse();
      return;
    }
    if (drag.lastWidth !== null) cfg.onCommitWidth(drag.lastWidth);
  };

  /** Escape: abandon the drag, restore the committed width. */
  const cancelDrag = () => {
    const drag = teardown();
    if (!drag) return;
    if (drag.moved) setVar(cfg.width);
  };

  // A drag must never outlive the strip: if this hook instance unmounts
  // mid-drag (view switch, zen), end it gracefully.
  const finishRef = useRef(finishDrag);
  finishRef.current = finishDrag;
  useEffect(() => () => finishRef.current(false), []);

  const onPointerDown = (e: React.PointerEvent<HTMLElement>) => {
    if (e.button !== 0 || dragRef.current) return;
    const el = e.currentTarget;
    const pointerId = e.pointerId;
    // Window-level finishers: a release the strip never hears about
    // (focus steal, release outside the window, DOM churn) must still
    // end the drag, or the col-resize cursor stays stuck globally.
    const onWinEnd = (ev: PointerEvent) => {
      if (dragRef.current?.pointerId === ev.pointerId) finishDrag(ev.type === 'pointerup');
    };
    const onWinKey = (ev: KeyboardEvent) => {
      if (ev.key === 'Escape') {
        ev.stopPropagation();
        cancelDrag();
      }
    };
    window.addEventListener('pointerup', onWinEnd, true);
    window.addEventListener('pointercancel', onWinEnd, true);
    window.addEventListener('keydown', onWinKey, true);
    dragRef.current = {
      pointerId,
      startX: e.clientX,
      startWidth: cfg.width,
      moved: false,
      lastWidth: null,
      snap: false,
      el,
      removeWindowListeners: () => {
        window.removeEventListener('pointerup', onWinEnd, true);
        window.removeEventListener('pointercancel', onWinEnd, true);
        window.removeEventListener('keydown', onWinKey, true);
      },
    };
    try {
      el.setPointerCapture(pointerId);
    } catch {
      /* synthetic or already-released pointer - the window listeners
         still terminate the drag */
    }
  };

  const onPointerMove = (e: React.PointerEvent<HTMLElement>) => {
    const drag = dragRef.current;
    if (!drag || drag.pointerId !== e.pointerId) return;
    const rawDx = e.clientX - drag.startX;
    const dx = cfg.invert ? -rawDx : rawDx;
    if (!drag.moved) {
      if (Math.abs(dx) <= DRAG_THRESHOLD_PX) return;
      drag.moved = true;
      // Anchored popovers only reposition on window resize, which a pane
      // drag never fires - close them instead of letting them float.
      if (hasOpenOverlay()) closeTopOverlay();
      cfg.rootRef.current?.classList.add('pn-col-dragging');
      drag.el.dataset.dragging = '1';
    }
    const raw = drag.startWidth + dx;
    const w = clampWidth(raw);
    drag.snap = cfg.snapAt === 'min' ? raw < cfg.min - SNAP_PX : raw > cfg.getMax() + SNAP_PX;
    if (drag.snap) drag.el.dataset.snap = '1';
    else delete drag.el.dataset.snap;
    drag.lastWidth = w;
    setVar(w);
    badge(e, drag.snap ? cfg.snapLabel : `${w}px`);
  };

  const onRelease = () => finishDrag(true);
  const onAbandon = () => finishDrag(false);

  const onKeyDown = (e: React.KeyboardEvent<HTMLElement>) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      cfg.onCollapse();
      return;
    }
    if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
    e.preventDefault();
    const dir = (e.key === 'ArrowRight' ? 1 : -1) * (cfg.invert ? -1 : 1);
    cfg.onCommitWidth(clampWidth(cfg.width + dir * KEY_STEP_PX));
  };

  return {
    stripProps: {
      onPointerDown,
      onPointerMove,
      onPointerUp: onRelease,
      onPointerCancel: onAbandon,
      onLostPointerCapture: onAbandon,
      onKeyDown,
    },
  };
}

/**
 * A collapsed pane's strip: a click expands it, and so does a drag outward
 * past the snap distance, released. The pane is not mounted, so there is no
 * width to show during the drag; the strip's accent line says "let go and it
 * opens", and the pane opens at its stored width.
 * Spec: ops/docs/ui-patterns.md section 56
 */
export function useExpandDrag(onExpand: () => void, direction: 1 | -1) {
  const drag = useRef<{ pointerId: number; startX: number; el: HTMLElement; ready: boolean } | null>(null);
  const dragged = useRef(false);
  const end = (release: boolean) => {
    const d = drag.current;
    if (!d) return;
    drag.current = null;
    delete d.el.dataset.dragging;
    try {
      d.el.releasePointerCapture(d.pointerId);
    } catch {
      /* capture already gone */
    }
    if (release && d.ready) {
      dragged.current = true;
      onExpand();
    }
  };
  return {
    onPointerDown: (e: React.PointerEvent<HTMLElement>) => {
      if (e.button !== 0) return;
      dragged.current = false;
      drag.current = { pointerId: e.pointerId, startX: e.clientX, el: e.currentTarget, ready: false };
      try {
        e.currentTarget.setPointerCapture(e.pointerId);
      } catch {
        /* the release still ends the drag */
      }
    },
    onPointerMove: (e: React.PointerEvent<HTMLElement>) => {
      const d = drag.current;
      if (!d || d.pointerId !== e.pointerId) return;
      d.ready = (e.clientX - d.startX) * direction > SNAP_PX / 2;
      if (d.ready) d.el.dataset.dragging = '1';
      else delete d.el.dataset.dragging;
    },
    onPointerUp: () => end(true),
    onPointerCancel: () => end(false),
    onLostPointerCapture: () => end(false),
    onClick: () => {
      // The release of a drag already expanded; its click must not act twice.
      if (dragged.current) {
        dragged.current = false;
        return;
      }
      onExpand();
    },
  };
}
