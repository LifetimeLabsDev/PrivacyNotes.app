import { useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { usePointMenuPosition } from './usePopoverPosition';
import { SIDEBAR_ACTIVE, SIDEBAR_ROW_MENU_BUTTON } from './sidebarUI';
import { FolderTreeView } from './FolderTreeView';
import { INDENT_PX, MAX_INDENT_LEVEL, useFolderExpansion } from './folderTreeState';
import { FolderNameInput } from './FolderNameInput';
import { ProMark } from './UpgradeModal';
import {
  canCreateChild,
  canDeleteFolder,
  folderSiblingSorter,
  type FolderSortDir,
  type FolderSortField,
  UNFILED_ID,
  type FolderDef,
} from './folders';
import {
  ArrowElbowDownRight,
  DotsThree,
  Folder,
  FolderPlus,
  Palette,
  PencilSimple,
  Prohibit,
  Trash,
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
  /** Notes with no folder - drives the muted Unfiled row (hides at zero). */
  unfiledCount: number;
  selectedFolder: string | null;
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
  /** The Pro mark on the "Icon and color" row: a free account, and the demo. */
  looksProMark?: boolean;
  /** Sibling sort (persisted per-device in NotesView, like tag sort). */
  sortField: FolderSortField;
  sortDir: FolderSortDir;
  mobileTabIndex: number | undefined;
}

export function FolderTree({
  folders,
  counts,
  unfiledCount,
  selectedFolder,
  onSelectFolder,
  onCreateFolder,
  onRenameFolder,
  onRequestMove,
  onRequestDelete,
  onReorderFolders,
  locked = false,
  onLockedAction,
  onEditLook,
  looksProMark = false,
  sortField,
  sortDir,
  mobileTabIndex,
}: FolderTreeProps) {
  const { t } = useTranslation('shell');
  const { expand, expandAncestors } = useFolderExpansion();
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

  const sortSiblings = useMemo(
    () => folderSiblingSorter(sortField, sortDir, counts),
    [sortField, sortDir, counts],
  );

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
        <div className="text-[13px] text-neutral-400 dark:text-neutral-700 px-2 py-1">
          {t('folders.noFoldersYet')}
        </div>
      )}

      <FolderTreeView
        folders={folders}
        density="rail"
        ariaLabel={t('browseToggle.folders')}
        sortSiblings={sortSiblings}
        mobileTabIndex={mobileTabIndex}
        isActive={(f) => selectedFolder === f.id}
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
        // A drag while the tree is sorted by name or entries would vanish
        // under the sort that overrules it, so the drop switches this device
        // to Custom and keeps what the user just did. Locked accounts get
        // the upsell instead, like every other folder action.
        reorder={locked ? undefined : { onReorder: onReorderFolders }}
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
            <span className="truncate">{f.name}</span>
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
              <span className="text-xs lg:text-[11px] text-neutral-400 dark:text-neutral-600 tabular-nums ms-1 me-2 lg:me-1.5 shrink-0">
                {counts.get(f.id) ?? 0}
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
              <div className="w-full rounded text-[15px] lg:text-[13px] font-medium flex items-center text-neutral-900 dark:text-white">
                <span className="shrink-0 w-5 lg:w-4 ms-0.5" aria-hidden="true" />
                <div className="flex-1 min-w-0 flex items-center gap-2 lg:gap-1.5 py-2 lg:py-1 pe-2">
                  <span className="inline-flex shrink-0 text-amber-600/80 dark:text-amber-500/80">
                    <Folder size={16} className="lg:w-3.5 lg:h-3.5" />
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
      {creatingUnder === null ? (
        <div className="w-full rounded text-[15px] lg:text-[13px] font-medium flex items-center text-neutral-900 dark:text-white">
          <div className="flex-1 min-w-0 flex items-center gap-2 lg:gap-1.5 px-2 py-2 lg:py-1">
            <span className="inline-flex shrink-0 text-accent">
              <Folder size={16} className="lg:w-3.5 lg:h-3.5" />
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
          className="w-full mt-2 rounded-md border border-dashed border-divider hover:border-accent/50 text-[15px] lg:text-[13px] font-medium transition flex items-center justify-center gap-2 lg:gap-1.5 px-2 py-2 lg:py-1.5 text-pn-muted hover:text-accent"
        >
          <FolderPlus size={16} className="shrink-0 lg:w-3.5 lg:h-3.5 text-amber-600/80 dark:text-amber-500/80" />
          <span className="truncate">{t('folders.new')}</span>
        </button>
      )}

      {/* Unfiled - notes with no folder, the folder sibling of the tag
          rail's Untagged row (GitHub #235). Same muted styling, folder-view
          font sizes. Hides at zero (NotesView bounces the filter). Selecting
          it is browsing, not a folder action, so it skips the Pro lock. */}
      {unfiledCount > 0 && (
        <button
          type="button"
          tabIndex={mobileTabIndex}
          onClick={() => onSelectFolder(selectedFolder === UNFILED_ID ? null : UNFILED_ID)}
          className={`w-full text-start px-2 py-2 lg:py-1.5 rounded text-[15px] lg:text-[13px] font-medium transition flex justify-between items-center ${
            selectedFolder === UNFILED_ID
              ? SIDEBAR_ACTIVE
              : 'text-neutral-400 hover:bg-neutral-200/60 hover:text-neutral-600 dark:text-neutral-600 dark:hover:bg-neutral-900/60 dark:hover:text-neutral-400'
          }`}
        >
          <span className="flex items-center gap-2 lg:gap-1.5 min-w-0">
            <span className="inline-flex shrink-0">
              <Prohibit size={16} className="lg:w-3.5 lg:h-3.5" />
            </span>
            <span className="truncate">{t('folders.unfiled')}</span>
          </span>
          <span className="text-xs lg:text-[11px] tabular-nums">
            {unfiledCount}
          </span>
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
                    className="w-full text-start px-3 py-1.5 text-[13px] text-neutral-700 dark:text-neutral-200 hover:bg-surface-1 flex items-center gap-2"
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
                  className="w-full text-start px-3 py-1.5 text-[13px] text-neutral-700 dark:text-neutral-200 hover:bg-surface-1 flex items-center gap-2"
                >
                  <ArrowElbowDownRight className="text-accent" />
                  {t('folders.move')}
                </button>
                <button
                  onClick={() => {
                    setMenu(null);
                    setRenameBuffer(menuFolder.name);
                    setRenamingId(menuFolder.id);
                  }}
                  className="w-full text-start px-3 py-1.5 text-[13px] text-neutral-700 dark:text-neutral-200 hover:bg-surface-1 flex items-center gap-2"
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
                    className="w-full text-start px-3 py-1.5 text-[13px] text-neutral-700 dark:text-neutral-200 hover:bg-surface-1 flex items-center gap-2"
                  >
                    <Palette className="text-accent" />
                    <span className="flex-1">{t('looks.menu')}</span>
                    {looksProMark && <ProMark />}
                  </button>
                )}
                <div className="my-1 border-t border-divider" />
              </>
            )}
            <button
              onClick={() => {
                setMenu(null);
                onRequestDelete(menuFolder.id);
              }}
              className="w-full text-start px-3 py-1.5 text-[13px] text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/30 flex items-center gap-2"
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
