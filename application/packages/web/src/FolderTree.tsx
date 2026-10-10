import { useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { usePointMenuPosition } from './usePopoverPosition';
import { SIDEBAR_ACTIVE, SIDEBAR_DROP_INSIDE, SIDEBAR_ROW_MENU_BUTTON } from './sidebarUI';
import { FolderTreeView, type FolderTreeViewProps } from './FolderTreeView';
import { INDENT_PX, MAX_INDENT_LEVEL, useFolderExpansion } from './folderTreeState';
import { FolderNameInput } from './FolderNameInput';
import { ProMark } from './UpgradeModal';
import {
  canCreateChild,
  canDeleteFolder,
  folderSiblingSorter,
  folderTotals,
  type FolderSortDir,
  type FolderSortField,
  UNFILED_ID,
  type FolderDef,
} from './folders';
import {
  ArrowElbowDownRight,
  ArrowsInLineVertical,
  ArrowsOutLineVertical,
  DotsThree,
  Folder,
  FolderPlus,
  Palette,
  PencilSimple,
  Prohibit,
  Trash,
  type Icon,
} from './icons';

/**
 * Nested folder tree for the sidebar's Folders browse mode (Pro).
 *
 * The tree itself - carets, guide lines, indent, the tinted expanded
 * branch, drag to reorder - lives in `FolderTreeView`, which the Move
 * dialog renders too. This file owns what only the sidebar has: the
 * direct-member count, the "..." row menu, the inline create and rename
 * inputs, the Pro lock, the Unfiled row and the New folder button.
 */

interface OpenFolderMenu {
  id: string;
  /** Desired top-left corner in viewport coords; clamped on-screen at render. */
  x: number;
  y: number;
}

export interface FolderTreeProps {
  folders: FolderDef[];
  /** Direct-member note counts per folder id. */
  counts: Map<string, number>;
  /** Mute a folder whose whole branch counts zero: the counts speak for one
   *  section, and the folder holds nothing of it. */
  dimEmpty?: boolean;
  /** Notes with no folder - drives the muted Unfiled row (hides at zero). */
  unfiledCount: number;
  selectedFolder: string | null;
  /**
   * Folder of the open note: an id, null for a note with no folder, or
   * undefined when no note is open. Its row name is bold, which is not the
   * highlight, because the highlight is the filter.
   */
  openNoteFolder?: string | null;
  /** Clicking the active folder toggles the filter off (null). */
  onSelectFolder: (id: string | null) => void;
  onCreateFolder: (name: string, parentId: string | null) => void;
  onRenameFolder: (id: string, name: string) => void;
  /** Open the shared FolderPicker to re-parent this folder. */
  onRequestMove: (id: string) => void;
  /** Open the delete confirm (contents move up to the parent). */
  onRequestDelete: (id: string) => void;
  /** Land a dragged folder: its new parent, and that parent's children in
   *  the sequence the drop leaves them in. */
  onReorderFolders: (id: string, parentId: string | null, orderedIds: string[]) => void;
  /** Free account: the tree is browsable but every folder action is
   *  Pro - affordances fire onLockedAction (the upgrade modal)
   *  instead of their real handler. Deleting a starter folder is the one
   *  action that still works, so the tree it was given is not a tree it
   *  is stuck with (canDeleteFolder in folders.ts carries the reason). */
  locked?: boolean;
  onLockedAction?: () => void;
  /** Opens the look picker (icon and color) at the point the menu stood. */
  onEditLook?: (id: string) => void;
  /** A click on a folder's icon opens its look picker. Omit to let the icon
   *  select like the rest of the row. */
  onGlyphClick?: (id: string) => void;
  /** The Pro mark on the "Icon and color" row: a free account, and the demo. */
  looksProMark?: boolean;
  /** A dragged list item files into a folder, or out of one on Unfiled.
   *  The rail's list runs the drop and names the row the pointer is over. */
  itemDrop?: FolderTreeViewProps['itemDrop'];
  /** The root folder menu's "Move to Work" or "Move to Personal" item, and
   *  the empty tree's text, while spaces are on. Spec: ops/docs/plans/spaces.md */
  spaceMove?: { label: string; icon: Icon; run: (id: string) => void };
  emptyText?: string;
  /** Sibling sort (persisted per-device in NotesView, like tag sort). */
  sortField: FolderSortField;
  sortDir: FolderSortDir;
  mobileTabIndex: number | undefined;
}

export function FolderTree({
  folders,
  counts,
  dimEmpty = false,
  unfiledCount,
  selectedFolder,
  openNoteFolder,
  onSelectFolder,
  onCreateFolder,
  onRenameFolder,
  onRequestMove,
  onRequestDelete,
  onReorderFolders,
  locked = false,
  onLockedAction,
  onEditLook,
  onGlyphClick,
  looksProMark = false,
  itemDrop,
  spaceMove,
  emptyText,
  sortField,
  sortDir,
  mobileTabIndex,
}: FolderTreeProps) {
  const { t } = useTranslation('shell');
  const { isExpanded, expand, expandAncestors, collapseAll, expandAll } = useFolderExpansion();
  /** Parent id the inline "new folder" input is nested under; undefined = closed. */
  const [creatingUnder, setCreatingUnder] = useState<string | null | undefined>(undefined);
  const [createDraft, setCreateDraft] = useState('');
  const [renamingId, setRenamingId] = useState<string | null>(null);
  const [renameBuffer, setRenameBuffer] = useState('');
  const [menu, setMenu] = useState<OpenFolderMenu | null>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const menuPos = usePointMenuPosition(menu ? { x: menu.x, y: menu.y } : null, menuRef);

  // The active folder's ancestor path auto-expands (other branches keep
  // their manual state).
  useEffect(() => {
    if (selectedFolder) expandAncestors(folders, selectedFolder);
  }, [selectedFolder, folders, expandAncestors]);

  // Dismiss the row menu on scroll/resize - it's fixed-positioned, so
  // staying open would leave it floating detached (same rule as the
  // tag menu in NotesView).
  useEffect(() => {
    if (!menu) return;
    const close = () => setMenu(null);
    window.addEventListener('resize', close);
    window.addEventListener('scroll', close, true);
    return () => {
      window.removeEventListener('resize', close);
      window.removeEventListener('scroll', close, true);
    };
  }, [menu]);

  // A closed row counts its whole subtree, an open row its own items. The
  // Entries sort reads the totals, so opening a folder never reorders it.
  const totals = useMemo(() => folderTotals(folders, counts), [folders, counts]);

  const sortSiblings = useMemo(
    () => folderSiblingSorter(sortField, sortDir, totals),
    [sortField, sortDir, totals],
  );

  // The bold row: the open note's folder, or the collapsed ancestor that
  // hides it, so one row on screen always says where the note is. The tree
  // never expands to show it, because that would undo the reader's collapse.
  const markedFolder = useMemo(() => {
    if (!openNoteFolder) return null;
    const byId = new Map(folders.map((f) => [f.id, f]));
    const path: FolderDef[] = [];
    for (let f = byId.get(openNoteFolder); f; f = f.parentId ? byId.get(f.parentId) : undefined) {
      path.unshift(f);
    }
    return path.find((f, i) => i === path.length - 1 || !isExpanded(f))?.id ?? null;
  }, [openNoteFolder, folders, isExpanded]);

  const menuFolder = menu ? folders.find((f) => f.id === menu.id) : undefined;
  const menuCanNest = menu ? canCreateChild(folders, menu.id) : false;

  function openMenuAt(id: string, x: number, y: number) {
    // Locked accounts browse the tree but every action upsells - the
    // menu's items are all actions, so the menu itself is the gate. A
    // starter folder is the exception: its menu opens carrying Delete
    // alone, which is the only item that would work.
    if (!canDeleteFolder(id, !locked)) {
      onLockedAction?.();
      return;
    }
    // Store the raw anchor point; usePointMenuPosition measures the rendered
    // menu and clamps it on-screen (both axes) so it can't clip near an edge.
    setMenu({ id, x, y });
  }

  function cancelCreate() {
    setCreatingUnder(undefined);
    setCreateDraft('');
  }

  function commitCreate() {
    const name = createDraft.trim();
    if (name && creatingUnder !== undefined) {
      onCreateFolder(name, creatingUnder);
      if (creatingUnder) expand(folders, creatingUnder);
    }
    setCreatingUnder(undefined);
    setCreateDraft('');
  }

  function commitRename(id: string) {
    const name = renameBuffer.trim();
    if (name) onRenameFolder(id, name);
    setRenamingId(null);
  }

  return (
    <>
      {folders.length === 0 && creatingUnder === undefined && (
        <div className="text-[13px] text-pn-muted px-2 py-1">
          {emptyText ?? t('folders.noFoldersYet')}
        </div>
      )}

      <FolderTreeView
        folders={folders}
        density="rail"
        ariaLabel={t('browseToggle.folders')}
        sortSiblings={sortSiblings}
        mobileTabIndex={mobileTabIndex}
        isActive={(f) => selectedFolder === f.id}
        isDimmed={dimEmpty ? (f) => !totals.get(f.id) : undefined}
        onSelect={(f) => {
          if (renamingId === f.id) return;
          // Second click on the active folder clears the filter - with
          // folder + view composing, nothing else would.
          onSelectFolder(selectedFolder === f.id ? null : f.id);
        }}
        onContextMenu={(e, f) => {
          e.preventDefault();
          e.stopPropagation();
          openMenuAt(f.id, e.clientX, e.clientY);
        }}
        onGlyphClick={onGlyphClick ? (f) => onGlyphClick(f.id) : undefined}
        // A drag while the tree is sorted by name or entries would vanish
        // under the sort that overrules it, so the drop switches this device
        // to Custom and keeps what the user just did. Locked accounts get
        // the upsell instead, like every other folder action.
        reorder={locked ? undefined : { onReorder: onReorderFolders }}
        itemDrop={itemDrop}
        isEditing={(f) => renamingId === f.id}
        renderName={(f) =>
          renamingId === f.id ? (
            <FolderNameInput
              value={renameBuffer}
              onChange={setRenameBuffer}
              onCommit={() => commitRename(f.id)}
              onCancel={() => setRenamingId(null)}
              scale="rail"
              tabIndex={mobileTabIndex}
            />
          ) : (
            <span className={`truncate${markedFolder === f.id ? ' font-bold' : ''}`}>{f.name}</span>
          )
        }
        renderTrailing={(f) =>
          renamingId === f.id ? null : (
            <>
              <button
                type="button"
                tabIndex={mobileTabIndex}
                onClick={(e) => {
                  e.stopPropagation();
                  if (menu?.id === f.id) {
                    setMenu(null);
                  } else {
                    const rect = e.currentTarget.getBoundingClientRect();
                    openMenuAt(f.id, rect.left, rect.bottom + 4);
                  }
                }}
                aria-label={t('folders.actionsForFolder', { folder: f.name })}
                className={SIDEBAR_ROW_MENU_BUTTON}
              >
                <DotsThree />
              </button>
              <span className="text-xs text-pn-muted tabular-nums ms-1 me-2 shrink-0">
                {(isExpanded(f) ? counts : totals).get(f.id) ?? 0}
              </span>
            </>
          )
        }
        renderAfter={(f, level) =>
          creatingUnder === f.id ? (
            <div
              className="border-s border-divider"
              style={{ marginInlineStart: level + 1 < MAX_INDENT_LEVEL ? INDENT_PX : 0 }}
            >
              <div className="w-full rounded text-[15px] font-medium flex items-center text-pn">
                <span className="shrink-0 w-5 ms-0.5" aria-hidden="true" />
                <div className="flex-1 min-w-0 flex items-center gap-2 py-2 pe-2">
                  <span className="inline-flex shrink-0 text-label">
                    <Folder size={16} />
                  </span>
                  <FolderNameInput
                    value={createDraft}
                    onChange={setCreateDraft}
                    onCommit={commitCreate}
                    onCancel={cancelCreate}
                    scale="rail"
                    tabIndex={mobileTabIndex}
                  />
                </div>
              </div>
            </div>
          ) : null
        }
      />

      {/* New root folder - inline input, same pattern as tag creation. */}
      {/* Unfiled - notes with no folder, the folder sibling of the tag
          rail's Untagged row (GitHub #235). Same muted styling, folder-view
          font sizes. Above New folder, as Untagged sits above New tag.
          Hides at zero (NotesView bounces the filter). Selecting
          it is browsing, not a folder action, so it skips the Pro lock. */}
      {unfiledCount > 0 && (
        <button
          type="button"
          tabIndex={mobileTabIndex}
          onClick={() => onSelectFolder(selectedFolder === UNFILED_ID ? null : UNFILED_ID)}
          data-drop-folder={itemDrop ? UNFILED_ID : undefined}
          className={`w-full text-start px-2 py-2 rounded text-[15px] font-medium transition flex justify-between items-center ${
            itemDrop?.overId === UNFILED_ID
              ? `${SIDEBAR_DROP_INSIDE} text-pn`
              : selectedFolder === UNFILED_ID
              ? SIDEBAR_ACTIVE
              : 'text-pn-muted hover:bg-pn/5 hover:text-pn-soft'
          }`}
        >
          <span className="flex items-center gap-2 min-w-0">
            <span className="inline-flex shrink-0">
              <Prohibit size={16} />
            </span>
            <span className={`truncate${openNoteFolder === null ? ' font-bold' : ''}`}>
              {t('folders.unfiled')}
            </span>
          </span>
          <span className="text-xs tabular-nums">
            {unfiledCount}
          </span>
        </button>
      )}

      {creatingUnder === null ? (
        <div className="w-full rounded text-[15px] font-medium flex items-center text-pn">
          <div className="flex-1 min-w-0 flex items-center gap-2 px-2 py-2">
            <span className="inline-flex shrink-0 text-accent">
              <Folder size={16} />
            </span>
            <FolderNameInput
              value={createDraft}
              onChange={setCreateDraft}
              onCommit={commitCreate}
              onCancel={cancelCreate}
              scale="rail"
              tabIndex={mobileTabIndex}
            />
          </div>
        </div>
      ) : (
        <button
          type="button"
          tabIndex={mobileTabIndex}
          onClick={() => {
            if (locked) {
              onLockedAction?.();
              return;
            }
            setCreateDraft('');
            setCreatingUnder(null);
          }}
          /* A dashed button, not another tree row: the rows above are
             places you go, this is a thing you make, and the old plain row
             read as one more folder. Same FolderPlus mark and amber tint as
             the folder picker's own "New folder" button, so the two say the
             same thing in the two places they appear.
             Spec: ops/docs/ui-patterns.md (section 76) */
          className="w-full mt-2 rounded-md border border-dashed border-divider hover:border-accent/50 text-[15px] font-medium transition flex items-center justify-start gap-2 ps-[7px] pe-2 py-2 text-pn-muted hover:text-accent"
        >
          <FolderPlus size={16} className="shrink-0 text-label" />
          <span className="truncate">{t('folders.new')}</span>
        </button>
      )}

      {/* Folder actions menu - fixed-position, same z tiers as the tag menu. */}
      {menu && menuFolder && (
        <>
          <div className="fixed inset-0 z-[55]" onClick={() => setMenu(null)} />
          <div
            ref={menuRef}
            style={{
              top: menuPos?.top ?? menu.y,
              left: menuPos?.left ?? menu.x,
              visibility: menuPos ? 'visible' : 'hidden',
            }}
            className="fixed z-[60] min-w-[200px] rounded-md border border-divider bg-surface-2 shadow-lg py-1"
          >
            {/* When locked, this menu opens only on a starter folder and
                carries Delete alone. The other three are Pro, and a menu
                whose every item opens the paywall is worse than one that
                does the single thing it offers. */}
            {!locked && (
              <>
                {menuCanNest && (
                  <button
                    onClick={() => {
                      setMenu(null);
                      setCreateDraft('');
                      setCreatingUnder(menuFolder.id);
                      expand(folders, menuFolder.id);
                    }}
                    className="w-full text-start px-3 py-1.5 text-[13px] text-pn-soft hover:bg-surface-1 flex items-center gap-2"
                  >
                    <FolderPlus className="text-accent" />
                    {t('folders.newSubfolder')}
                  </button>
                )}
                <button
                  onClick={() => {
                    setMenu(null);
                    onRequestMove(menuFolder.id);
                  }}
                  className="w-full text-start px-3 py-1.5 text-[13px] text-pn-soft hover:bg-surface-1 flex items-center gap-2"
                >
                  <ArrowElbowDownRight className="text-accent" />
                  {t('folders.move')}
                </button>
                {spaceMove && menuFolder.parentId === null && (
                  <button
                    onClick={() => {
                      setMenu(null);
                      spaceMove.run(menuFolder.id);
                    }}
                    className="w-full text-start px-3 py-1.5 text-[13px] text-pn-soft hover:bg-surface-1 flex items-center gap-2"
                  >
                    <spaceMove.icon className="text-accent" />
                    {spaceMove.label}
                  </button>
                )}
                <button
                  onClick={() => {
                    setMenu(null);
                    setRenameBuffer(menuFolder.name);
                    setRenamingId(menuFolder.id);
                  }}
                  className="w-full text-start px-3 py-1.5 text-[13px] text-pn-soft hover:bg-surface-1 flex items-center gap-2"
                >
                  <PencilSimple className="text-accent" />
                  {t('folders.rename')}
                </button>
                {onEditLook && (
                  <button
                    onClick={() => {
                      setMenu(null);
                      onEditLook(menuFolder.id);
                    }}
                    className="w-full text-start px-3 py-1.5 text-[13px] text-pn-soft hover:bg-surface-1 flex items-center gap-2"
                  >
                    <Palette className="text-accent" />
                    <span className="flex-1">{t('looks.menu')}</span>
                    {looksProMark && <ProMark />}
                  </button>
                )}
                <div className="my-1 border-t border-divider" />
                <button
                  onClick={() => {
                    setMenu(null);
                    expandAll(folders);
                  }}
                  className="w-full text-start px-3 py-1.5 text-[13px] text-pn-soft hover:bg-surface-1 flex items-center gap-2"
                >
                  <ArrowsOutLineVertical className="text-accent" />
                  {t('folders.expandAll')}
                </button>
                <button
                  onClick={() => {
                    setMenu(null);
                    collapseAll(folders);
                  }}
                  className="w-full text-start px-3 py-1.5 text-[13px] text-pn-soft hover:bg-surface-1 flex items-center gap-2"
                >
                  <ArrowsInLineVertical className="text-accent" />
                  {t('folders.collapseAll')}
                </button>
                <div className="my-1 border-t border-divider" />
              </>
            )}
            <button
              onClick={() => {
                setMenu(null);
                onRequestDelete(menuFolder.id);
              }}
              className="w-full text-start px-3 py-1.5 text-[13px] text-danger hover:bg-red-50 dark:hover:bg-red-950/30 flex items-center gap-2"
            >
              <Trash />
              {t('folders.delete')}
            </button>
          </div>
        </>
      )}
    </>
  );
}
