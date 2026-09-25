/**
 * The divider between the Content list and the tags or folders in the
 * sidebar. Dragging it sets the height of the Content part; dragging it to
 * the bottom folds the tags or folders away, so only their switch stays, and
 * a click on either tab opens them again. A click on the divider folds or
 * opens them, like a click on a pane strip; a double-click puts the layout
 * back. Both values are this device's only, like the pane widths.
 *
 * During a drag the height is written to the element and React state commits
 * once, on release, the contract of `usePaneResize.ts`.
 * Spec: ops/docs/ui-patterns.md (sidebar split)
 */
import { useEffect, useRef, useState, type RefObject } from 'react';

const HEIGHT_KEY = 'privacynotes.ui.sidebarSplit';
const FOLDED_KEY = 'privacynotes.ui.sidebarTagsFolded';
// The Content caption and one row; below that the part has no use.
const MIN_CONTENT_PX = 48;
// A tag or folder list shorter than this shows less than one row, so the
// drag folds it instead.
const SNAP_PX = 56;
const DRAG_THRESHOLD_PX = 4;
const KEY_STEP_PX = 16;

function readHeight(): number | null {
  try {
    const n = Number(localStorage.getItem(HEIGHT_KEY));
    return Number.isFinite(n) && n > 0 ? n : null;
  } catch {
    return null;
  }
}

function readFolded(): boolean {
  try {
    return localStorage.getItem(FOLDED_KEY) === '1';
  } catch {
    return false;
  }
}

type Drag = {
  pointerId: number;
  startY: number;
  startH: number;
  total: number;
  moved: boolean;
  last: number;
  fold: boolean;
  el: HTMLElement;
};

export function useSidebarSplit(
  contentRef: RefObject<HTMLElement | null>,
  listRef: RefObject<HTMLElement | null>,
) {
  const [height, setHeight] = useState<number | null>(readHeight);
  const [folded, setFolded] = useState(readFolded);
  const drag = useRef<Drag | null>(null);

  useEffect(() => {
    try {
      if (height === null) localStorage.removeItem(HEIGHT_KEY);
      else localStorage.setItem(HEIGHT_KEY, String(Math.round(height)));
      localStorage.setItem(FOLDED_KEY, folded ? '1' : '0');
    } catch {
      /* storage blocked: the layout still works for this session */
    }
  }, [height, folded]);

  // What the two parts can share: the Content part plus the list below it.
  const measure = () => {
    const content = contentRef.current?.getBoundingClientRect().height ?? 0;
    const list = listRef.current?.getBoundingClientRect().height ?? 0;
    return { content, total: content + list };
  };

  const paint = (h: number, fold: boolean) => {
    const el = contentRef.current;
    if (el) {
      el.style.flex = `0 1 ${h}px`;
      el.style.height = '';
    }
    if (listRef.current) listRef.current.style.opacity = fold ? '0.35' : '';
  };

  const clear = () => {
    if (contentRef.current) contentRef.current.style.flex = '';
    if (listRef.current) listRef.current.style.opacity = '';
  };

  // A press that never moved is a click: it folds or opens the list, as a
  // click on a pane strip collapses the pane. Only a real release counts.
  const end = (commit: boolean, released = false) => {
    const d = drag.current;
    if (!d) return;
    drag.current = null;
    clear();
    delete d.el.dataset.dragging;
    document.documentElement.classList.remove('pn-row-dragging');
    if (!d.moved) {
      if (released) setFolded((f) => !f);
      return;
    }
    if (!commit) return;
    if (d.fold) {
      setFolded(true);
    } else {
      setFolded(false);
      setHeight(d.last);
    }
  };

  const reset = () => {
    setHeight(null);
    setFolded(false);
  };

  const separatorProps = {
    role: 'separator' as const,
    'aria-orientation': 'horizontal' as const,
    tabIndex: 0,
    onPointerDown: (e: React.PointerEvent<HTMLElement>) => {
      if (e.button !== 0 || drag.current) return;
      const { content, total } = measure();
      drag.current = {
        pointerId: e.pointerId,
        startY: e.clientY,
        startH: content,
        total,
        moved: false,
        last: content,
        fold: folded,
        el: e.currentTarget,
      };
      try {
        e.currentTarget.setPointerCapture(e.pointerId);
      } catch {
        /* the release still ends the drag */
      }
    },
    onPointerMove: (e: React.PointerEvent<HTMLElement>) => {
      const d = drag.current;
      if (!d || d.pointerId !== e.pointerId) return;
      const raw = d.startH + (e.clientY - d.startY);
      if (!d.moved && Math.abs(raw - d.startH) <= DRAG_THRESHOLD_PX) return;
      if (!d.moved) {
        d.el.dataset.dragging = '1';
        document.documentElement.classList.add('pn-row-dragging');
      }
      d.moved = true;
      d.fold = raw > d.total - SNAP_PX;
      d.last = Math.round(Math.max(MIN_CONTENT_PX, Math.min(d.total - SNAP_PX, raw)));
      paint(d.fold ? d.total : d.last, d.fold);
    },
    onPointerUp: () => end(true, true),
    onPointerCancel: () => end(false),
    onLostPointerCapture: () => end(true),
    onDoubleClick: reset,
    onKeyDown: (e: React.KeyboardEvent<HTMLElement>) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        setFolded((f) => !f);
        return;
      }
      if (e.key !== 'ArrowUp' && e.key !== 'ArrowDown') return;
      e.preventDefault();
      const { content, total } = measure();
      const next = content + (e.key === 'ArrowDown' ? KEY_STEP_PX : -KEY_STEP_PX);
      if (next > total - SNAP_PX) {
        setFolded(true);
      } else {
        setFolded(false);
        setHeight(Math.max(MIN_CONTENT_PX, next));
      }
    },
  };

  return { height, folded, unfold: () => setFolded(false), separatorProps };
}
