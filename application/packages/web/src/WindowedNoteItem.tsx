import { memo, useCallback, useLayoutEffect, useRef, useState } from 'react';
import { flushSync } from 'react-dom';
import NoteRow, { noteRootProps, type NoteRowProps } from './NoteRow';
import NoteCard from './NoteCard';
import { windowItemSizes } from './notesView/listPlace';
import { useCompactRows } from './viewMode';

type WindowObserver = {
  observer: IntersectionObserver;
  watchers: Map<Element, (entry: IntersectionObserverEntry) => void>;
};
const windows = new WeakMap<Element, WindowObserver>();

function watch(el: Element, update: (entry: IntersectionObserverEntry) => void) {
  const root = el.closest('.overflow-y-auto') ?? el.parentElement!;
  let window = windows.get(root);
  if (!window) {
    const watchers: WindowObserver['watchers'] = new Map();
    const observer = new IntersectionObserver((entries) => {
      for (const entry of entries) watchers.get(entry.target)?.(entry);
    }, { root, rootMargin: '800px' });
    windows.set(root, window = { observer, watchers });
  }
  const { observer, watchers } = window;
  watchers.set(el, update);
  observer.observe(el);
  return () => {
    watchers.delete(el);
    observer.unobserve(el);
    if (!watchers.size) { observer.disconnect(); windows.delete(root); }
  };
}

/** Keep the row's space and keyboard destination while its contents unmount.
 * Grid placement remains CSS-owned, including mixed-width calendar cards.
 * Spec: ops/docs/archive/keep-my-place.md (windowed items)
 */
function WindowedNoteItem({ grid, ...props }: NoteRowProps & { grid: boolean }) {
  const compact = useCompactRows();
  const key = `${grid}:${compact}:${JSON.stringify(props.listPrefs)}:${props.isNoteLocked}:${!!props.selectionMode}`;
  const [near, setNear] = useState(() => typeof IntersectionObserver === 'undefined');
  const root = useRef<HTMLElement | null>(null);
  const focused = useRef(false);
  const dragging = useRef(false);
  const mounted = near || !!props.isContextTarget;
  const size = windowItemSizes(props.note.id).get(key);
  const remember = useCallback(() => {
    const el = root.current;
    if (!el || !mounted) return;
    const rect = el.getBoundingClientRect();
    if (rect.height <= 0 || rect.width <= 0) return;
    windowItemSizes(props.note.id).set(key, { width: rect.width, height: rect.height });
  }, [props.note.id, key, mounted]);
  const attach = useCallback((el: HTMLElement | null) => { root.current = el; }, []);
  useLayoutEffect(() => {
    const el = root.current;
    if (!el) return;
    if (mounted) {
      remember();
      if (focused.current) { focused.current = false; el.tabIndex = -1; el.focus({ preventScroll: true }); }
    }
    if (typeof IntersectionObserver === 'undefined') return;
    const dragStart = () => { dragging.current = true; };
    const dragEnd = () => { dragging.current = false; };
    el.addEventListener('dragstart', dragStart);
    el.addEventListener('dragend', dragEnd);
    const unwatch = watch(el, (entry) => {
      if (!entry.isIntersecting && (dragging.current || el.contains(document.activeElement))) return;
      remember();
      setNear(entry.isIntersecting);
    });
    return () => {
      unwatch();
      el.removeEventListener('dragstart', dragStart);
      el.removeEventListener('dragend', dragEnd);
    };
  }, [mounted, remember]);
  if (mounted) {
    const Item = grid ? NoteCard : NoteRow;
    return <Item {...props} rootRef={attach} />;
  }
  return (
    <li
      {...noteRootProps(props)}
      ref={attach}
      data-item-id={props.note.id}
      data-window-placeholder=""
      aria-label={props.note.title || undefined}
      style={{ height: size?.height ?? (grid ? 180 : compact ? 40 : 112), listStyle: 'none' }}
      onFocus={() => {
        focused.current = true;
        flushSync(() => setNear(true));
      }}
    />
  );
}

type WindowedProps = NoteRowProps & { windowed?: boolean };
export const WindowedNoteRow = memo(({ windowed = true, ...props }: WindowedProps) => windowed
  ? <WindowedNoteItem {...props} grid={false} /> : <NoteRow {...props} />);
export const WindowedNoteCard = memo(({ windowed = true, ...props }: WindowedProps) => windowed
  ? <WindowedNoteItem {...props} grid /> : <NoteCard {...props} />);
