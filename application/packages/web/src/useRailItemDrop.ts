import { useEffect, useRef, useState } from 'react';
import type React from 'react';
import { isItemDrag, readItemDrag } from './itemDrag';
import { useFolderExpansion } from './folderTreeState';
import { UNFILED_ID, type FolderDef } from './folders';

/**
 * List items dropped on the sidebar's folder, Unfiled and tag rows.
 *
 * ONE set of handlers on the scrolling list finds the row under the pointer
 * with `closest()`, the way the folder tree keeps its own drag handlers on
 * its root. Per-row enter and leave pairs flicker as the pointer crosses a
 * row's children, and the browser sends the new row's `dragenter` before the
 * old row's `dragleave`. A row takes part through its attribute:
 * `data-drop-folder` (a folder id, or UNFILED_ID) or `data-drop-tag`.
 *
 * A drop is accepted in `dragenter` as well as `dragover`. After a quick
 * move Chromium can release with no `dragover` on the row at all, and a row
 * that waited for one loses the drop. Every row takes it as a copy, the
 * effect the drag allows, so the cursor shows the same plus everywhere.
 *
 * Spring-loading: a closed folder (`data-drop-closed`) opens after a rest,
 * and so does the hidden half of the Tags | Folders switch. Both last for the
 * drag only: the stored choice does not change, and every folder the drag
 * opened closes again, so the reader's own collapse wins.
 * Spec: ops/docs/archive/drag-to-folder-and-tag.md (sections 5.4 and 7)
 */

/** How long a drag rests on a closed folder, or on the hidden half of the
 *  switch, before it opens. Spec: ops/docs/archive/drag-to-folder-and-tag.md (section 5.4) */
const SPRING_MS = 600;

type BrowseMode = 'tags' | 'folders';

/** The row a drop would land on. */
interface RailDropTarget {
  kind: 'folder' | 'tag';
  key: string;
}

export function useRailItemDrop({
  folders,
  browseMode,
  onDropOnFolder,
  onDropOnTag,
}: {
  folders: FolderDef[];
  /** The stored Tags | Folders choice. */
  browseMode: BrowseMode;
  onDropOnFolder: (ids: string[], folderId: string | null) => void;
  onDropOnTag: (ids: string[], tag: string) => void;
}) {
  const expansion = useFolderExpansion();
  const [over, setOver] = useState<RailDropTarget | null>(null);
  const [dragBrowse, setDragBrowse] = useState<BrowseMode | null>(null);
  const [dragging, setDragging] = useState(false);
  const overRef = useRef<RailDropTarget | null>(null);
  const spring = useRef<{ key: string; timer: number } | null>(null);
  const opened = useRef(new Set<string>());
  const latest = useRef({ folders, expansion, onDropOnFolder, onDropOnTag });
  latest.current = { folders, expansion, onDropOnFolder, onDropOnTag };
  const shownMode = dragBrowse ?? browseMode;

  // The end of a drag that touched the rail: on `dragend` or `drop`
  // anywhere, or at the first pointer move with no button down, which also
  // ends a drag whose source row left the page (the browser sends no pointer
  // moves while a drag runs).
  useEffect(() => {
    if (!dragging) return;
    const end = (e: Event) => {
      if (e.type === 'pointermove' && (e as PointerEvent).buttons !== 0) return;
      if (spring.current) window.clearTimeout(spring.current.timer);
      spring.current = null;
      overRef.current = null;
      setOver(null);
      setDragBrowse(null);
      const { folders: list, expansion: exp } = latest.current;
      for (const id of opened.current) {
        const folder = list.find((f) => f.id === id);
        if (folder && exp.isExpanded(folder)) exp.toggle(id);
      }
      opened.current.clear();
      setDragging(false);
    };
    window.addEventListener('dragend', end);
    window.addEventListener('drop', end);
    window.addEventListener('pointermove', end);
    return () => {
      window.removeEventListener('dragend', end);
      window.removeEventListener('drop', end);
      window.removeEventListener('pointermove', end);
    };
  }, [dragging]);

  useEffect(
    () => () => {
      if (spring.current) window.clearTimeout(spring.current.timer);
    },
    [],
  );

  function aim(next: RailDropTarget | null) {
    const prev = overRef.current;
    if (prev?.kind === next?.kind && prev?.key === next?.key) return;
    overRef.current = next;
    setOver(next);
  }

  /** Stops the pending spring when its key starts with `scope`. */
  function stopSpring(scope: string) {
    if (!spring.current?.key.startsWith(scope)) return;
    window.clearTimeout(spring.current.timer);
    spring.current = null;
  }

  function startSpring(key: string, fire: () => void) {
    if (spring.current?.key === key) return;
    stopSpring('');
    spring.current = {
      key,
      timer: window.setTimeout(() => {
        spring.current = null;
        fire();
      }, SPRING_MS),
    };
  }

  function rowAt(e: React.DragEvent<HTMLElement>): { el: HTMLElement; target: RailDropTarget } | null {
    const node = e.target as Node;
    const start = node instanceof Element ? node : node.parentElement;
    const el = start?.closest<HTMLElement>('[data-drop-folder], [data-drop-tag]');
    if (!el || !e.currentTarget.contains(el)) return null;
    const folder = el.dataset.dropFolder;
    if (folder !== undefined) return { el, target: { kind: 'folder', key: folder } };
    const tag = el.dataset.dropTag;
    return tag !== undefined ? { el, target: { kind: 'tag', key: tag } } : null;
  }

  /** The pointer is inside the element's box. On `dragleave` this, not
   *  `relatedTarget`, tells a move onto a child from a move out. */
  function inside(e: React.DragEvent<HTMLElement>): boolean {
    const box = e.currentTarget.getBoundingClientRect();
    return e.clientX > box.left && e.clientX < box.right && e.clientY > box.top && e.clientY < box.bottom;
  }

  function onListEnterOrOver(e: React.DragEvent<HTMLElement>) {
    if (!isItemDrag(e.dataTransfer)) return;
    if (!dragging) setDragging(true);
    const hit = rowAt(e);
    if (!hit) {
      aim(null);
      stopSpring('folder:');
      return;
    }
    e.preventDefault();
    e.dataTransfer.dropEffect = 'copy';
    aim(hit.target);
    if (hit.target.kind === 'folder' && hit.el.dataset.dropClosed !== undefined) {
      const id = hit.target.key;
      startSpring(`folder:${id}`, () => {
        const { folders: list, expansion: exp } = latest.current;
        const folder = list.find((f) => f.id === id);
        if (!folder || exp.isExpanded(folder)) return;
        exp.expand(list, id);
        opened.current.add(id);
      });
    } else {
      stopSpring('folder:');
    }
  }

  function onListLeave(e: React.DragEvent<HTMLElement>) {
    if (!isItemDrag(e.dataTransfer) || inside(e)) return;
    aim(null);
    stopSpring('folder:');
  }

  function onListDrop(e: React.DragEvent<HTMLElement>) {
    if (!isItemDrag(e.dataTransfer)) return;
    const hit = rowAt(e);
    aim(null);
    stopSpring('folder:');
    if (!hit) return;
    e.preventDefault();
    const ids = readItemDrag(e.dataTransfer);
    if (ids.length === 0) return;
    const { onDropOnFolder: toFolder, onDropOnTag: toTag } = latest.current;
    if (hit.target.kind === 'folder') toFolder(ids, hit.target.key === UNFILED_ID ? null : hit.target.key);
    else toTag(ids, hit.target.key);
  }

  /** The halves of the switch take no drop, so the cursor says "not
   *  allowed" there; a rest on the hidden half shows its list. */
  function switchProps(mode: BrowseMode) {
    const rest = (e: React.DragEvent<HTMLElement>) => {
      if (!isItemDrag(e.dataTransfer)) return;
      if (!dragging) setDragging(true);
      if (shownMode === mode) stopSpring(`mode:${mode}`);
      else startSpring(`mode:${mode}`, () => setDragBrowse(mode));
    };
    return {
      onDragEnter: rest,
      onDragOver: rest,
      onDragLeave: (e: React.DragEvent<HTMLElement>) => {
        if (isItemDrag(e.dataTransfer) && !inside(e)) stopSpring(`mode:${mode}`);
      },
    };
  }

  return {
    /** The row the pointer is over, for its look. */
    over,
    /** The list the rail shows: the stored choice, or the one a drag asked for. */
    shownMode,
    listProps: { onDragEnter: onListEnterOrOver, onDragOver: onListEnterOrOver, onDragLeave: onListLeave, onDrop: onListDrop },
    switchProps,
  };
}
