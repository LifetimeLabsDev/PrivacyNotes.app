import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { OverflowTip } from './OverflowTip';
import { folderIndentPx, INDENT_PX, MAX_INDENT_LEVEL, useFolderExpansion } from './folderTreeState';
import { ancestorIds, canMoveFolder, childrenOf, subtreeIds, type FolderDef } from './folders';
import { CaretDown, DotsSixVertical } from './icons';
import { FolderGlyph } from './looks/LookGlyph';

/**
 * The folder tree itself - carets, guide lines, indent, the tinted expanded
 * branch, and the drag that reorders and re-files folders. Rendered by BOTH
 * the sidebar (`FolderTree`) and the Move dialog (`FolderPicker`), which is
 * the point: the two drew their own trees and drifted, so the dialog had no
 * carets, no guide lines and no memory of what the sidebar had open.
 *
 * What stays with the caller: what a click does (filter a list, or pick a
 * destination), the search box, the Pro gate, the counts, the row menu, the
 * Unfiled row and the inline create input. Those genuinely differ. Folding
 * them in here would mean a prop per difference, which is harder to
 * maintain, not easier.
 *
 * Spec: ops/docs/ui-patterns.md (section 86)
 */

/** How far from a scroll edge a drag starts pulling the list, and how fast. */
const AUTOSCROLL_EDGE_PX = 36;
const AUTOSCROLL_STEP_PX = 8;
/**
 * Pointer travel before a press becomes a drag rather than a stray tap.
 * Generous on purpose: the row is a click target too, so a shaky click that
 * crossed a tight threshold would arm a drag and then be swallowed as one -
 * a folder that "sometimes does not open" and never on demand.
 */
const DRAG_THRESHOLD_PX = 8;
/**
 * Share of a row's height at each end that means "between the rows" rather
 * than "into this folder". A quarter each way leaves the middle half as the
 * drop-inside target, which is the ratio every file manager settled on: any
 * smaller and re-parenting is a pixel hunt, any larger and reordering is.
 */
const EDGE_BAND = 0.25;

interface FolderReorder {
  /**
   * Land a dragged folder. `parentId` is where it goes (null = top level)
   * and `orderedIds` is that parent's children as they will read on screen,
   * the dragged folder included. Built from the RENDERED rows, so a drop
   * under a name or entries sort writes what the user actually saw.
   */
  onReorder: (id: string, parentId: string | null, orderedIds: string[]) => void;
}

export interface FolderTreeViewProps {
  folders: FolderDef[];
  /** 'rail' is the sidebar's tighter scale, 'dialog' the modal's. */
  density: 'rail' | 'dialog';
  /** Sibling sort. Omit for the stored order, which is what Custom means. */
  sortSiblings?: (list: FolderDef[]) => FolderDef[];
  isActive?: (folder: FolderDef) => boolean;
  isDisabled?: (folder: FolderDef) => boolean;
  onSelect: (folder: FolderDef) => void;
  onContextMenu?: (e: React.MouseEvent, folder: FolderDef) => void;
  /** Replaces the folder name, for the inline rename input. */
  renderName?: (folder: FolderDef) => ReactNode;
  /**
   * True while `renderName` returns an EDITOR rather than a label. The row
   * then drops its select button entirely: a text field and its save and
   * cancel buttons cannot live inside a `<button>` - invalid HTML, and the
   * nested controls do not reliably take their own clicks.
   */
  isEditing?: (folder: FolderDef) => boolean;
  /** After the name: the count and "..." in the rail, a check in the dialog. */
  renderTrailing?: (folder: FolderDef) => ReactNode;
  /** Under the row, indented one level: the inline "new subfolder" input. */
  renderAfter?: (folder: FolderDef, level: number) => ReactNode;
  /** Omit to leave the tree read-only. */
  reorder?: FolderReorder;
  ariaLabel: string;
  mobileTabIndex?: number;
}

/** Where the pointer currently says the folder should land. */
interface DropTarget {
  /** The row the indicator is drawn against. */
  overId: string;
  place: 'before' | 'inside' | 'after';
  /** Depth of the DESTINATION, so the line sits where the folder will land
   *  rather than where the pointer happens to be. */
  level: number;
  /** Resolved destination, precomputed so the drop is a single call. */
  parentId: string | null;
  orderedIds: string[];
}

interface DragState {
  id: string;
  /** Every row the drag may not land on: itself and its own descendants. */
  refused: Set<string>;
  target: DropTarget | null;
  pointerY: number;
  active: boolean;
}

export function FolderTreeView({
  folders,
  density,
  sortSiblings,
  isActive,
  isDisabled,
  onSelect,
  onContextMenu,
  renderName,
  isEditing,
  renderTrailing,
  renderAfter,
  reorder,
  ariaLabel,
  mobileTabIndex,
}: FolderTreeViewProps) {
  const { t } = useTranslation('shell');
  const { isExpanded, toggle, expand } = useFolderExpansion();
  const rowEls = useRef(new Map<string, HTMLElement>());
  const scroller = useRef<HTMLElement | null>(null);
  const dragStartY = useRef(0);
  /** Set while a drag is live, so the click it ends on does not also select. */
  const dragged = useRef(false);
  /**
   * The live drag, mirrored in a ref because the handlers must READ it and
   * ACT on it. Doing that inside a `setState` updater would put the commit
   * (and the expand beside it) inside a function React is free to call
   * twice, which in development it does.
   */
  const dragRef = useRef<DragState | null>(null);
  /** The row the press started on, and its pointer, for the late capture. */
  const dragEl = useRef<HTMLElement | null>(null);
  const dragPointer = useRef(0);
  const [drag, setDrag] = useState<DragState | null>(null);
  const dragActive = !!drag?.active;
  const rail = density === 'rail';

  /** The rendered children of one parent, in on-screen order. */
  const renderedChildren = useCallback(
    (parentId: string | null): FolderDef[] => {
      const list = childrenOf(folders, parentId);
      return sortSiblings ? sortSiblings(list) : list;
    },
    [folders, sortSiblings],
  );

  /**
   * Which row the pointer is over, and what dropping there would mean.
   *
   * A row is three bands: the top and bottom quarters put the folder BEFORE
   * or AFTER that row among its siblings, and the middle half puts it INSIDE
   * that row as a child. One gesture then covers both reordering and
   * re-filing, and neither needs a second drop target somewhere else.
   */
  const resolveTarget = useCallback(
    (id: string, refused: Set<string>, y: number): DropTarget | null => {
      /** Depth of a destination parent: 0 is the top level. */
      const depthOf = (parentId: string | null) =>
        parentId === null ? 0 : ancestorIds(folders, parentId).length + 1;

      /** Build the destination's sibling sequence, or null if it is refused. */
      const land = (
        overId: string,
        place: 'before' | 'inside' | 'after',
        parentId: string | null,
        anchorId: string | null,
      ): DropTarget | null => {
        if (!canMoveFolder(folders, id, parentId)) return null;
        const siblings = renderedChildren(parentId)
          .map((f) => f.id)
          .filter((each) => each !== id);
        let orderedIds: string[];
        if (anchorId === null) {
          // Append: a folder dropped INTO another, or past the end of the
          // whole tree, lands last - the same place `createFolder` and
          // `moveFolder` put one.
          orderedIds = [...siblings, id];
        } else {
          const at = siblings.indexOf(anchorId);
          if (at === -1) return null;
          orderedIds = [...siblings];
          orderedIds.splice(place === 'before' ? at : at + 1, 0, id);
        }
        const current = renderedChildren(parentId).map((f) => f.id);
        const unchanged =
          orderedIds.length === current.length && orderedIds.every((each, i) => current[i] === each);
        if (unchanged) return null;
        return { overId, place, level: depthOf(parentId), parentId, orderedIds };
      };

      let hit: { folder: FolderDef; place: 'before' | 'inside' | 'after' } | null = null;
      let lastEl: { id: string; bottom: number } | null = null;
      let firstEl: { id: string; top: number } | null = null;
      for (const [rowId, el] of rowEls.current) {
        const folder = folders.find((f) => f.id === rowId);
        if (!folder) continue;
        const box = el.getBoundingClientRect();
        if (!lastEl || box.bottom > lastEl.bottom) lastEl = { id: rowId, bottom: box.bottom };
        if (!firstEl || box.top < firstEl.top) firstEl = { id: rowId, top: box.top };
        if (y < box.top || y > box.bottom) continue;
        const offset = (y - box.top) / box.height;
        hit = {
          folder,
          place: offset < EDGE_BAND ? 'before' : offset > 1 - EDGE_BAND ? 'after' : 'inside',
        };
      }

      // Past the last row, or above the first, the pointer is over no row at
      // all - and that empty space is the ONLY way to reach the top level
      // when the tree holds a single expanded root. Every downward slot below
      // it belongs to its own children, so without this a subfolder could
      // only be lifted out by dragging it ABOVE its parent, and dragging it
      // to the end of the list did nothing (reported 2026-08-27).
      if (!hit) {
        const roots = renderedChildren(null).map((f) => f.id);
        if (lastEl && y > lastEl.bottom) {
          const last = roots.filter((each) => each !== id).at(-1) ?? null;
          return land(lastEl.id, 'after', null, last);
        }
        if (firstEl && y < firstEl.top) {
          const first = roots.filter((each) => each !== id)[0] ?? null;
          return land(firstEl.id, 'before', null, first);
        }
        return null;
      }

      // Dropping onto the dragged folder or into its own subtree is a cycle,
      // and the rows are already greyed out to say so.
      if (refused.has(hit.folder.id)) return null;

      return hit.place === 'inside'
        ? land(hit.folder.id, 'inside', hit.folder.id, null)
        : land(hit.folder.id, hit.place, hit.folder.parentId, hit.folder.id);
    },
    [folders, renderedChildren],
  );

  // Auto-scroll while a drag sits near either edge of the scrolling rail.
  // Without it a tree taller than the pane can only be reordered as far as
  // the visible window, which on a phone is three or four rows. The target
  // is recomputed on every frame, not only on pointer movement, because
  // during an auto-scroll the rows move under a pointer that is holding
  // still.
  useEffect(() => {
    if (!dragActive) return;
    let frame = 0;
    const step = () => {
      const live = dragRef.current;
      const el = scroller.current;
      if (live?.active && el) {
        const box = el.getBoundingClientRect();
        const before = el.scrollTop;
        if (live.pointerY < box.top + AUTOSCROLL_EDGE_PX) el.scrollTop -= AUTOSCROLL_STEP_PX;
        else if (live.pointerY > box.bottom - AUTOSCROLL_EDGE_PX) el.scrollTop += AUTOSCROLL_STEP_PX;
        if (el.scrollTop !== before) {
          updateDrag({ ...live, target: resolveTarget(live.id, live.refused, live.pointerY) });
        }
      }
      frame = requestAnimationFrame(step);
    };
    frame = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frame);
    // The pointer position is read from the ref inside the loop, so this
    // starts ONCE per drag instead of restarting on every pointermove.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dragActive, resolveTarget]);

  function updateDrag(next: DragState | null) {
    dragRef.current = next;
    setDrag(next);
  }

  function beginDrag(e: React.PointerEvent, folder: FolderDef, captureNow = false) {
    // Left button only. A right-click used to arm a drag AND open the row
    // menu, and the drag then hung until the next click.
    if (!reorder || (e.pointerType === 'mouse' && e.button !== 0)) return;
    const el = e.currentTarget as HTMLElement;
    // NOTE: no `setPointerCapture` here. Capturing at pointerdown retargets
    // the CLICK that follows to the capturing element, so every press on a
    // control inside the row - the caret, the "..." menu - was delivered to
    // the row instead and silently did nothing (reported 2026-08-27). The
    // capture is taken at the moment the drag actually activates, by which
    // point no click is coming.
    dragStartY.current = e.clientY;
    dragPointer.current = e.pointerId;
    dragEl.current = el;
    // The GRIP is the exception: it owns no click, so capturing there
    // immediately costs nothing and buys the touch path its reliability -
    // `touch-action: none` covers the grip alone, and a fast flick that
    // leaves it before the threshold would otherwise hand the movement back
    // to the rail as a scroll.
    if (captureNow) {
      try {
        el.setPointerCapture(e.pointerId);
      } catch {
        // Not fatal - the tree's own handlers still see the drag.
      }
    }
    dragged.current = false;
    scroller.current = findScroller(el);
    updateDrag({
      id: folder.id,
      refused: subtreeIds(folders, folder.id),
      target: null,
      pointerY: e.clientY,
      active: false,
    });
  }

  function moveDrag(e: React.PointerEvent) {
    const state = dragRef.current;
    if (!state) return;
    const active = state.active || Math.abs(e.clientY - dragStartY.current) > DRAG_THRESHOLD_PX;
    if (!active) {
      updateDrag({ ...state, pointerY: e.clientY });
      return;
    }
    if (!state.active) {
      // Capture from here on, so the drag survives the pointer leaving the
      // row - and only from here, because before this a click is still
      // possible and capture would steal its target.
      try {
        dragEl.current?.setPointerCapture(dragPointer.current);
      } catch {
        // Not fatal: the tree's own move handler still sees everything that
        // happens inside it, which is where a folder can be dropped anyway.
      }
    }
    dragged.current = true;
    updateDrag({
      ...state,
      active,
      pointerY: e.clientY,
      target: resolveTarget(state.id, state.refused, e.clientY),
    });
  }

  function endDrag() {
    const state = dragRef.current;
    updateDrag(null);
    if (state?.active && state.target) {
      const { parentId, orderedIds } = state.target;
      reorder?.onReorder(state.id, parentId, orderedIds);
      // A folder dropped into a closed one would otherwise vanish behind
      // its caret with nothing to say where it went.
      if (parentId) expand(folders, parentId);
    }
    // The click that follows this pointerup must not also select, but a drag
    // released over empty space produces NO click at all - and a flag left
    // standing then eats the next real one, which reads as a folder that
    // stopped responding to clicks. Timers run after the click, so clearing
    // on one covers both endings.
    setTimeout(() => {
      dragged.current = false;
    }, 0);
  }

  const renderRow = (folder: FolderDef, level: number): React.JSX.Element => {
    const kids = renderedChildren(folder.id);
    const hasKids = kids.length > 0;
    const expanded = isExpanded(folder);
    const active = isActive?.(folder) ?? false;
    const disabled = isDisabled?.(folder) ?? false;
    const dragging = drag?.active && drag.id === folder.id;
    const refusedHere = drag?.active && drag.refused.has(folder.id) && drag.id !== folder.id;
    const target = drag?.active && drag.target?.overId === folder.id ? drag.target : null;
    const editing = isEditing?.(folder) ?? false;

    const row = (
      <div key={folder.id} role="none">
        <div
          role="treeitem"
          aria-level={level + 1}
          aria-selected={active}
          {...(hasKids ? { 'aria-expanded': expanded } : {})}
          ref={(el) => {
            if (el) rowEls.current.set(folder.id, el);
            else rowEls.current.delete(folder.id);
          }}
          onContextMenu={onContextMenu ? (e) => onContextMenu(e, folder) : undefined}
          // Mouse and pen drag from anywhere on the row; touch drags from the
          // grip only, because a row that swallowed a vertical swipe would
          // stop the rail scrolling. Controls that own their own click are
          // marked `data-no-drag` and never arm one - the caret and whatever
          // the caller puts in the trailing slot.
          onPointerDown={
            reorder && !editing
              ? (e) => {
                  if (e.pointerType === 'touch') return;
                  if ((e.target as HTMLElement).closest('[data-no-drag]')) return;
                  beginDrag(e, folder);
                }
              : undefined
          }
          className={rowClass({
            rail,
            active,
            disabled: disabled || !!refusedHere,
            dragging: !!dragging,
            inside: target?.place === 'inside',
          })}
        >
          {target?.place === 'before' && <DropLine edge="top" level={target.level} />}
          {target?.place === 'after' && <DropLine edge="bottom" level={target.level} />}
          {reorder && !editing && (
            <span
              role="button"
              aria-label={t('folders.reorder', { folder: folder.name })}
              onPointerDown={(e) => beginDrag(e, folder, true)}
              style={{ touchAction: 'none' }}
              className="pn-ftree-grip shrink-0 inline-flex items-center justify-center w-4 h-6 -ms-0.5 cursor-grab active:cursor-grabbing text-neutral-400 dark:text-neutral-600 hover:text-accent transition"
            >
              <DotsSixVertical size={12} aria-hidden="true" />
            </span>
          )}
          {hasKids ? (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                toggle(folder.id);
              }}
              tabIndex={mobileTabIndex}
              data-no-drag
              aria-label={expanded ? t('folders.collapse') : t('folders.expand')}
              className={`shrink-0 inline-flex items-center justify-center ${
                rail ? 'w-5 h-8 ms-0.5' : 'w-4 h-7'
              } text-neutral-400 dark:text-neutral-600 hover:text-accent transition`}
            >
              <CaretDown
                size={10}
                className={`transition-transform ${expanded ? '' : '-rotate-90'}`}
                aria-hidden="true"
              />
            </button>
          ) : (
            <span className={`shrink-0 ${rail ? 'w-5 ms-0.5' : 'w-4'}`} aria-hidden="true" />
          )}
          {editing ? (
            <div
              className={`flex-1 min-w-0 flex items-center ${
                rail ? 'gap-2 py-2 pe-1' : 'gap-2 py-2 pe-1'
              }`}
            >
              <span className="inline-flex shrink-0 text-amber-600/80 dark:text-amber-500/80">
                <FolderGlyph folderId={folder.id} size={rail ? 16 : 15} />
              </span>
              {renderName?.(folder)}
            </div>
          ) : (
            <OverflowTip text={folder.name} className="flex-1 min-w-0 flex">
              <button
                type="button"
                disabled={disabled}
                tabIndex={mobileTabIndex}
                onClick={() => {
                  // The click that ends a drag is not a selection.
                  if (dragged.current) {
                    dragged.current = false;
                    return;
                  }
                  onSelect(folder);
                }}
                className={`flex-1 min-w-0 flex items-center text-start ${
                  rail ? 'gap-2 py-2 pe-1' : 'gap-2 py-2 pe-1'
                } ${disabled ? 'cursor-not-allowed' : ''}`}
              >
                <span
                  className={`inline-flex shrink-0 ${
                    disabled ? '' : active ? 'text-accent' : 'text-amber-600/80 dark:text-amber-500/80'
                  }`}
                >
                  <FolderGlyph folderId={folder.id} size={rail ? 16 : 15} />
                </span>
                {renderName ? renderName(folder) : <span className="truncate">{folder.name}</span>}
              </button>
            </OverflowTip>
          )}
          {renderTrailing && (
            <span
              data-no-drag
              // Full row height on touch, so the row menu button inside can
              // fill it (SIDEBAR_ROW_MENU_BUTTON in sidebarUI.ts).
              className="shrink-0 inline-flex items-center [@media(hover:none)]:self-stretch"
            >
              {renderTrailing(folder)}
            </span>
          )}
        </div>
        {hasKids && expanded && (
          <div
            role="group"
            className="pn-ftree-group"
            // `level` is 0-based and this is the CHILD group's indent, so the
            // cap compares the children's depth, not the parent's.
            style={{ marginInlineStart: level + 1 < MAX_INDENT_LEVEL ? INDENT_PX : 0 }}
          >
            {kids.map((k) => renderRow(k, level + 1))}
          </div>
        )}
        {renderAfter?.(folder, level)}
      </div>
    );

    // The tint marks where one top-level branch ends and the next begins,
    // which a guide line alone never did once two branches were open at
    // once. Top level only: nested tints stack into mud.
    return level === 0 && hasKids && expanded ? (
      <div key={folder.id} className="pn-ftree-branch">
        {row}
      </div>
    ) : (
      row
    );
  };

  return (
    // The move and release handlers live HERE, not on each row: before the
    // drag activates there is no pointer capture, so a fast press-and-yank
    // would leave the starting row before it ever crossed the threshold and
    // the drag would die on the spot. Every row's events bubble through
    // this one element.
    <div
      role="tree"
      aria-label={ariaLabel}
      onPointerMove={reorder ? moveDrag : undefined}
      onPointerUp={reorder ? endDrag : undefined}
      onPointerCancel={reorder ? endDrag : undefined}
    >
      {renderedChildren(null).map((folder) => renderRow(folder, 0))}
    </div>
  );
}

function rowClass({
  rail,
  active,
  disabled,
  dragging,
  inside,
}: {
  rail: boolean;
  active: boolean;
  disabled: boolean;
  dragging: boolean;
  inside: boolean;
}): string {
  const base = `pn-ftree-row relative w-full flex items-center group transition ${
    rail ? 'rounded text-[15px] font-medium' : 'rounded-md text-[14px] px-1'
  }`;
  // "Drop inside" outlines the whole row, because the thing being said is
  // "into this folder", not "between two rows". The line says the other one.
  if (inside) return `${base} bg-accent/10 ring-1 ring-accent dark:bg-accent/15`;
  if (dragging) return `${base} opacity-40`;
  if (disabled) return `${base} text-neutral-400 dark:text-neutral-600 cursor-not-allowed`;
  if (active) {
    return rail
      ? `${base} bg-accent/15 text-accent dark:bg-accent/20`
      : `${base} bg-accent/15 text-accent dark:bg-accent/20 hover:bg-accent/20 dark:hover:bg-accent/25`;
  }
  return `${base} text-neutral-900 hover:bg-neutral-200/60 dark:text-white dark:hover:bg-neutral-900/60`;
}

/**
 * The landing slot. Absolutely positioned ON the row rather than inserted
 * between rows: in the flow it added its own height mid-drag, which moved
 * every row below it, which moved the midpoints the drop is measured
 * against - so the indicator flickered between two slots while the pointer
 * held still.
 */
function DropLine({ edge, level }: { edge: 'top' | 'bottom'; level: number }) {
  return (
    <span
      aria-hidden="true"
      className={`pointer-events-none absolute z-10 h-0.5 rounded-full bg-accent ${
        edge === 'top' ? 'top-0 -mt-px' : 'bottom-0 -mb-px'
      }`}
      style={{ insetInlineStart: folderIndentPx(level) + 8, insetInlineEnd: 4 }}
    />
  );
}

/**
 * Nearest scrollable ancestor, so a drag can pull a long tree past its pane.
 * The walk stops at a dialog boundary: a tree that is too short to scroll
 * would otherwise hand the auto-scroll whatever container sits OUTSIDE the
 * modal, and a drag near the screen edge would scroll the app behind it.
 */
function findScroller(el: HTMLElement): HTMLElement | null {
  let node: HTMLElement | null = el.parentElement;
  while (node) {
    const overflow = getComputedStyle(node).overflowY;
    if ((overflow === 'auto' || overflow === 'scroll') && node.scrollHeight > node.clientHeight) {
      return node;
    }
    if (node.getAttribute('role') === 'dialog') return null;
    node = node.parentElement;
  }
  return null;
}
