/**
 * The list a pane draws its items into, shared by every list pane: the one
 * grid class, the progressive reveal, the scroll position across a hide and
 * show of the pane (#186), the right-click highlight and its release, and the
 * one routing of a click on an item. A behavior belongs to the list, not to a
 * pane: each of these lived in one or two panes, and the others lacked it.
 * `pnpm check:house` refuses the `pn-notes-grid` class anywhere else.
 * Spec: ops/docs/plans/list-grid-parity.md (section 5, LG2)
 */
import { useCallback, useEffect, useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import { useProgressiveReveal, type ProgressiveReveal } from './useProgressiveReveal';
import { listTop, rememberListTop } from './notesView/listPlace';

/** The grid of tiles. `pn-notes-grid` scopes the container-query column count
 *  and every mini-tile rule in index.css; `content-start` keeps a short grid
 *  at the top of the pane. */
const GRID_CLASS = 'grid content-start gap-3 p-4 pn-notes-grid';

export function itemGridClass(grid: boolean): string {
  return grid ? GRID_CLASS : '';
}

/**
 * The item a right-click targets, highlighted while its menu is open so the
 * person can see they hit the right one. Any click releases it: the one that
 * picks a menu row and the one that dismisses the menu alike.
 */
export function useContextTarget(): [string | null, (id: string | null) => void] {
  const [id, setId] = useState<string | null>(null);
  useEffect(() => {
    if (!id) return;
    const clear = () => setId(null);
    window.addEventListener('click', clear, true);
    return () => window.removeEventListener('click', clear, true);
  }, [id]);
  return [id, setId];
}

/**
 * The scroll position across a hide and show of the pane (#186). On a phone,
 * opening an item puts the list pane at `display: none`. That destroys the
 * `.pn-list-panel` query container, so every `@container pn-list` rule stops
 * matching at once: the grid drops to its one-column fallback and the tiles
 * lose their compact layout. The content is then far taller than what the
 * person was looking at, and the offset the browser restores on the way back
 * is measured against that wrong layout. The offset is remembered while the
 * pane is on screen and applied again on the render where the pane gets its
 * box back; reading clientHeight first forces the layout that resolves the
 * container queries. A different list (`resetKey`) starts at the top.
 */
export function useScrollRestore(resetKey: readonly unknown[]) {
  const ref = useRef<HTMLElement | null>(null);
  const top = useRef(0);
  const hidden = useRef(false);
  useLayoutEffect(() => {
    top.current = 0;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, resetKey);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (el.clientHeight === 0) {
      hidden.current = true;
      return;
    }
    if (hidden.current) {
      hidden.current = false;
      el.scrollTop = top.current;
    }
  });
  // Skipped on the frame the pane reappears: that scroll event carries the
  // browser's own restore, which is the value being corrected.
  const onScroll = useCallback((el: HTMLElement) => {
    if (!hidden.current) top.current = el.scrollTop;
  }, []);
  return { ref, onScroll };
}

export interface ItemListState {
  ref: React.RefObject<HTMLElement | null>;
  reveal: ProgressiveReveal;
  onScroll: (el: HTMLElement) => void;
}

/**
 * The reveal and the scroll restore of one list, reset together when it
 * becomes a different list (`resetKey`: a new view, search or filter, never
 * an edit). `total` is what the reveal counts.
 */
export function useItemList(resetKey: readonly unknown[], total: number, place: string | null = null): ItemListState {
  // `place` names the view and space the pane draws, null under a search. A
  // list that was open earlier this session comes back at its offset, with
  // its rows drawn down to it first. Spec: ops/docs/archive/keep-my-place.md
  const key = place === null ? null : `${place}|${JSON.stringify(resetKey)}`;
  const reveal = useProgressiveReveal(() => key === null ? undefined : listTop(key)?.revealed);
  const scroll = useScrollRestore(resetKey);
  const keyRef = useRef(key);
  keyRef.current = key;
  const back = useRef<{ top: number; revealed: number; tries: number } | null>(null);
  useLayoutEffect(() => {
    const saved = key === null ? null : listTop(key);
    reveal.reset(saved?.revealed);
    back.current = saved && { ...saved, tries: 0 };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...resetKey, key]);
  // The rows of the new list, and the cards above them, can grow for a few
  // frames after the key: the offset is set again each frame until it holds,
  // and a scroll by the person ends the wait.
  useLayoutEffect(() => {
    const want = back.current;
    const el = scroll.ref.current;
    if (!want || !el || el.clientHeight === 0) return;
    if (reveal.visible < Math.min(want.revealed, total)) return;
    back.current = null;
    let frame = 0;
    const stop = () => {
      cancelAnimationFrame(frame);
      el.removeEventListener('wheel', stop);
      el.removeEventListener('touchstart', stop);
    };
    const place = () => {
      el.scrollTop = want.top;
      if (Math.abs(el.scrollTop - want.top) > 2 && ++want.tries < 10) frame = requestAnimationFrame(place);
      else stop();
    };
    el.addEventListener('wheel', stop, { passive: true });
    el.addEventListener('touchstart', stop, { passive: true });
    place();
  });
  const totalRef = useRef(total);
  totalRef.current = total;
  const visibleRef = useRef(reveal.visible);
  visibleRef.current = reveal.visible;
  const fillViewport = useCallback(() => {
    const el = scroll.ref.current;
    // A wide compact grid can fit a whole slice without a scrollbar.
    if (el && el.clientHeight > 0 && el.scrollHeight <= el.clientHeight) reveal.onScroll(el, total);
  }, [scroll.ref, reveal.onScroll, total]);
  useLayoutEffect(fillViewport);
  useEffect(() => {
    const el = scroll.ref.current;
    if (!el || typeof ResizeObserver === 'undefined') return;
    const observer = new ResizeObserver(fillViewport);
    observer.observe(el);
    return () => observer.disconnect();
  }, [scroll.ref, fillViewport]);
  const onScroll = useCallback(
    (el: HTMLElement) => {
      scroll.onScroll(el);
      reveal.onScroll(el, totalRef.current);
      if (keyRef.current !== null && el.clientHeight > 0) {
        rememberListTop(keyRef.current, el.scrollTop, visibleRef.current);
      }
    },
    [scroll, reveal],
  );
  return { ref: scroll.ref, reveal, onScroll };
}

/**
 * The list element: a `ul` of `li` items, or a `div` for the Files pane,
 * whose items are buttons. It scrolls, and in grid mode it is the grid.
 */
export function ItemList({ list, grid, as: Root = 'ul', className = '', onMouseDown, children }: {
  list: ItemListState;
  grid: boolean;
  as?: 'ul' | 'div';
  className?: string;
  onMouseDown?: (e: React.MouseEvent) => void;
  children: ReactNode;
}) {
  return (
    <Root
      ref={list.ref as React.RefObject<HTMLUListElement & HTMLDivElement>}
      onScroll={(e) => list.onScroll(e.currentTarget)}
      onMouseDown={onMouseDown}
      className={`flex-1 overflow-y-auto list-none m-0 ${grid ? GRID_CLASS : 'p-0'} ${className}`.trim()}
    >
      {children}
    </Root>
  );
}

/**
 * Where a click on an item goes. Shift extends a live selection, Cmd or Ctrl
 * toggles one item and is the mouse's way into selection mode, a plain click
 * toggles while a selection is live, and otherwise it opens the item.
 */
export function routeItemClick(
  e: React.MouseEvent,
  selecting: boolean,
  to: { range: () => void; toggle: () => void; open: () => void },
): void {
  if (e.shiftKey && selecting) {
    e.preventDefault();
    to.range();
    return;
  }
  if (e.metaKey || e.ctrlKey || selecting) {
    e.preventDefault();
    to.toggle();
    return;
  }
  to.open();
}
