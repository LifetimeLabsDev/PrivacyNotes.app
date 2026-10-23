import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useEscapeToClose } from './useEscapeToClose';
import { ContextMenu, useContextMenu, type ContextMenuItem } from './ContextMenu';
import { FolderTreeView } from './FolderTreeView';
import { FolderNameInput } from './FolderNameInput';
import { SIDEBAR_ROW_MENU_BUTTON } from './sidebarUI';
import { textMatcher } from './textMatch';
import { FolderGlyph } from './looks/LookGlyph';
import { CloseButton } from './ui';
import {
  flattenFolderRows,
  INDENT_PX,
  MAX_INDENT_LEVEL,
  useFolderExpansion,
} from './folderTreeState';
import {
  canCreateChild,
  canMoveFolder,
  folderSiblingSorter,
  folderTotals,
  subtreeIds,
  type FolderDef,
  type FolderSortDir,
  type FolderSortField,
} from './folders';
import { Check, DotsThree, Folder, FolderPlus, MagnifyingGlass, PencilSimple, Prohibit, type Icon } from './icons';

/**
 * The shared folder picker (Pro folders feature) - the single "choose a
 * folder" surface. Every filing entry point opens this: the note "..."
 * menu, the note context menu, the folder menu's Move action, and the
 * bulk toolbar.
 *
 * A compact centered modal: search input, the folder tree, an Unfiled row
 * (note mode), and an inline New folder affordance. Returns the chosen
 * folderId - or null for Unfiled / root - via onPick.
 *
 * The tree is `FolderTreeView`, the same component the sidebar renders, so
 * carets, guide lines, indent, the tinted expanded branch, the open/closed
 * state and the sibling sort are one implementation rather than two. Until
 * 2026-08-27 this file drew its own flat, caret-less tree, and the two
 * surfaces disagreed about the same folders.
 *
 * The two MODES used to differ far more than they do now: re-parenting a
 * folder got no New folder button, no row menu and no check on its current
 * parent, for no reason anyone could name. What still differs is only what
 * carries meaning - which rows are refused, and what the "no folder" row
 * says.
 *
 * Right-clicking a row opens the folder's own menu (new subfolder,
 * rename), the picker's answer to the sidebar tree's row menu. The dialog
 * carries `data-no-app-menu` so the global "New note / Sign out" chrome
 * menu - which meant nothing on top of a picker - never appears here
 * again. Spec: issue #208.
 */

export interface FolderPickerProps {
  folders: FolderDef[];
  /**
   * 'note': filing note(s) - every folder is a valid target, plus
   * Unfiled. 'folder': re-parenting a folder - the moved folder's
   * subtree is disabled, and null means "move to root level".
   */
  mode: 'note' | 'folder';
  /**
   * Note mode: the current folderId, rendered with a check. null means
   * Unfiled; undefined means "no single current folder" (a multi-select
   * spanning several folders), which checks nothing.
   */
  currentFolderId?: string | null;
  /** Folder mode: the folder being moved. */
  movingFolderId?: string;
  /** Direct-member note counts, the same map the sidebar tree reads. */
  counts: Map<string, number>;
  /**
   * The sidebar's own sibling sort, so both trees read the same way. The
   * dialog has no sort control of its own on purpose: it draws the folders
   * you just looked at in the rail, and a second, separately-set order for
   * the same tree is a place to get lost, not a setting.
   */
  sortField: FolderSortField;
  sortDir: FolderSortDir;
  onPick: (folderId: string | null) => void;
  /** Land a dragged folder, exactly as the sidebar tree does. */
  onReorderFolders: (id: string, parentId: string | null, orderedIds: string[]) => void;
  /**
   * Create a folder under `parentId` (null = root level) and return its
   * id (null when creation failed).
   */
  onCreateFolder?: (name: string, parentId: string | null) => string | null;
  /** Rename a folder in place, from the row menu. */
  onRenameFolder?: (id: string, name: string) => void;
  /** Note mode while spaces are on: the tree in one section per space, each
   *  under its name; Unfiled sits in the section flagged for it. Spec: ops/docs/plans/spaces.md */
  sections?: { key: string; label: string; icon: Icon; folders: FolderDef[]; unfiled?: boolean }[];
  /** The dialog's title; "Move to folder" when absent. */
  title?: string;
  onClose: () => void;
}

export function FolderPicker({
  folders,
  mode,
  currentFolderId,
  movingFolderId,
  counts,
  sortField,
  sortDir,
  onPick,
  onReorderFolders,
  onCreateFolder,
  onRenameFolder,
  sections,
  title,
  onClose,
}: FolderPickerProps) {
  const { t } = useTranslation('shell');
  const { expand, isExpanded } = useFolderExpansion();
  useEscapeToClose(onClose);
  const [query, setQuery] = useState('');
  /** Parent id the inline "new folder" input is nested under; undefined = closed.
   *  null is the footer's own root-level create. Mirrors FolderTree. */
  const [creatingUnder, setCreatingUnder] = useState<string | null | undefined>(undefined);
  const [createDraft, setCreateDraft] = useState('');
  const [renamingId, setRenamingId] = useState<string | null>(null);
  const [renameDraft, setRenameDraft] = useState('');
  const rowMenu = useContextMenu();

  const byId = useMemo(() => new Map(folders.map((f) => [f.id, f])), [folders]);

  const totals = useMemo(() => folderTotals(folders, counts), [folders, counts]);

  const sortSiblings = useMemo(
    () => folderSiblingSorter(sortField, sortDir, totals),
    [sortField, sortDir, totals],
  );

  /** Folder mode: the moved folder's own subtree can never be its parent. */
  const refused = useMemo(() => {
    if (mode !== 'folder' || !movingFolderId) return new Set<string>();
    return subtreeIds(folders, movingFolderId);
  }, [folders, mode, movingFolderId]);

  function isDisabled(folder: FolderDef): boolean {
    if (mode !== 'folder' || !movingFolderId) return false;
    return refused.has(folder.id) || !canMoveFolder(folders, movingFolderId, folder.id);
  }

  /**
   * The row that already holds the thing being moved, checked so the
   * dialog says where it is now. In folder mode that is its parent - the
   * folder itself is refused, so a check on it would be a check on a row
   * you cannot pick.
   */
  const checkedId =
    mode === 'note' ? currentFolderId : folders.find((f) => f.id === movingFolderId)?.parentId ?? null;

  /** Search: flat matches, ancestor path shown as a muted prefix. With
   *  sections, only the folders the sections offer can match, so a search in
   *  "Move to Work" never offers a Personal folder. */
  const searching = query.trim().length > 0;
  const matches = useMemo(() => {
    const q = query.trim();
    if (!q) return [];
    const match = textMatcher(q);
    const offered = sections ? new Set(sections.flatMap((sec) => sec.folders.map((f) => f.id))) : null;
    return flattenFolderRows(folders, { isExpanded: () => true, respectCollapse: false, sortSiblings })
      .map((row) => row.folder)
      .filter((folder) => (!offered || offered.has(folder.id)) && match(folder.name));
  }, [folders, sections, query, sortSiblings]);

  function pathLabel(folder: FolderDef): string {
    const parts: string[] = [];
    let current = folder.parentId ? byId.get(folder.parentId) : undefined;
    while (current) {
      parts.unshift(current.name);
      current = current.parentId ? byId.get(current.parentId) : undefined;
    }
    return parts.join(' / ');
  }

  function cancelCreate() {
    setCreatingUnder(undefined);
    setCreateDraft('');
  }

  /**
   * Creating a folder here used to FILE the note into it and close the
   * dialog in the same keystroke, on the reasoning that you only make a
   * folder here because you want this note in it. In use that read as the
   * save step going missing: the dialog vanished, and the move had already
   * happened before anyone confirmed it (reported 2026-08-27). It now just
   * creates the folder and leaves it on screen, selected by a second tap
   * like any other row.
   */
  function commitCreate() {
    const name = createDraft.trim();
    const parentId = creatingUnder;
    cancelCreate();
    if (!name || !onCreateFolder || parentId === undefined) return;
    const id = onCreateFolder(name, parentId);
    // A subfolder made inside a closed parent would land behind its caret.
    if (id && parentId) expand(folders, parentId);
  }

  function commitRename(id: string) {
    const name = renameDraft.trim();
    setRenamingId(null);
    setRenameDraft('');
    if (name) onRenameFolder?.(id, name);
  }

  function buildRowMenu(folder: FolderDef): ContextMenuItem[] {
    const items: ContextMenuItem[] = [];
    if (onCreateFolder && canCreateChild(folders, folder.id)) {
      items.push({
        label: t('folders.newSubfolder'),
        icon: <FolderPlus size={14} />,
        onSelect: () => {
          setRenamingId(null);
          setCreateDraft('');
          setCreatingUnder(folder.id);
        },
      });
    }
    if (onRenameFolder) {
      items.push({
        label: t('folders.rename'),
        icon: <PencilSimple size={14} />,
        onSelect: () => {
          cancelCreate();
          setRenameDraft(folder.name);
          setRenamingId(folder.id);
        },
      });
    }
    return items;
  }

  /**
   * The "no folder" row is an ACTION - take this note out of its folder,
   * move this folder up to the root - not a destination, so it renders
   * only when picking it would change something. An already-unfiled note
   * used to get a checked "Unfiled" row that did nothing when clicked: a
   * state readout wearing a button's clothes, and the one entry here that
   * isn't a folder. It stays the only way to un-file, which is why it
   * can't simply be dropped. undefined (a multi-select spanning several
   * folders) counts as "would change something" - some of them are filed.
   */
  const clearWouldChange =
    mode === 'note'
      ? currentFolderId !== null
      : folders.find((f) => f.id === movingFolderId)?.parentId != null;

  /** A search hit shows no subfolders below it, so it counts them in. */
  const trailingFor = (folder: FolderDef, withMenu = false, open = false) => (
    <>
      {/* The same "..." the sidebar row wears, from the same class token.
          Right-click alone is undiscoverable on a desktop, a two-hand job on
          a trackpad and absent on a phone. Not drawn on a search result:
          those rows are a flat list of destinations, not the tree. */}
      {withMenu && !isDisabled(folder) && (
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            rowMenu.open(e, buildRowMenu(folder));
          }}
          aria-label={t('folders.actionsForFolder', { folder: folder.name })}
          className={SIDEBAR_ROW_MENU_BUTTON}
        >
          <DotsThree />
        </button>
      )}
      <span className="text-[11px] text-pn-muted tabular-nums ms-1 shrink-0">
        {(open ? counts : totals).get(folder.id) ?? 0}
      </span>
      {checkedId === folder.id ? (
        <Check size={14} className="ms-1.5 me-1 shrink-0 text-accent" />
      ) : (
        <span className="ms-1.5 me-1 w-3.5 shrink-0" aria-hidden="true" />
      )}
    </>
  );

  const renderTree = (list: FolderDef[]) => (
    <FolderTreeView
      folders={list}
      density="dialog"
      sortSiblings={sortSiblings}
      ariaLabel={t('folders.moveTo')}
      isActive={(f) => checkedId === f.id}
      isDisabled={isDisabled}
      onSelect={(f) => onPick(f.id)}
      // The dialog reorders and re-files folders too. It was read-only
      // at first, on the reasoning that here a press is a pick - but
      // the drag starts on its own handle, and a tree you can only
      // rearrange from one of the two places that draw it is the same
      // split this whole component was written to end.
      reorder={{ onReorder: onReorderFolders }}
      onContextMenu={(e, f) => {
        if (isDisabled(f)) return;
        rowMenu.open(e, buildRowMenu(f));
      }}
      isEditing={(f) => renamingId === f.id}
      renderName={(f) =>
        renamingId === f.id ? (
          <FolderNameInput
            value={renameDraft}
            onChange={setRenameDraft}
            onCommit={() => commitRename(f.id)}
            onCancel={() => setRenamingId(null)}
            scale="dialog"
          />
        ) : (
          <span className="truncate">{f.name}</span>
        )
      }
      renderTrailing={(f) => (renamingId === f.id ? null : trailingFor(f, true, isExpanded(f)))}
      renderAfter={(f, level) =>
        creatingUnder === f.id ? (
          <div
            className="border-s border-divider"
            style={{ marginInlineStart: level + 1 < MAX_INDENT_LEVEL ? INDENT_PX : 0 }}
          >
            <div className="flex items-center gap-2 px-1 py-2">
              <span className="w-4 shrink-0" aria-hidden="true" />
              <span className="inline-flex shrink-0 text-label">
                <Folder size={15} />
              </span>
              <FolderNameInput
          value={createDraft}
          onChange={setCreateDraft}
          onCommit={commitCreate}
          onCancel={cancelCreate}
          scale="dialog"
        />
            </div>
          </div>
        ) : null
      }
    />
  );
  const unfiledRow = !searching && clearWouldChange && (
    <button
      type="button"
      onClick={() => onPick(null)}
      className="w-full flex items-center gap-2 px-3 py-2 rounded-md text-[14px] text-start transition text-pn-muted hover:bg-pn/5 hover:text-pn-soft"
    >
      <span className="inline-flex shrink-0">
        <Prohibit size={15} />
      </span>
      <span className="flex-1 min-w-0 truncate">
        {mode === 'folder' ? t('folders.rootLevel') : t('folders.unfiled')}
      </span>
    </button>
  );

  return (
    <div
      className="fixed inset-0 bg-black/40 dark:bg-black/40 flex items-center justify-center p-4 sm:p-6 z-50"
      onClick={onClose}
    >
      <div
        role="dialog"
        aria-label={t('folders.moveTo')}
        // The global chrome menu means nothing on top of a picker, and it
        // used to be the only menu a right-click here produced. Spec: #208.
        data-no-app-menu
        className="bg-surface-2/95 backdrop-blur-xl border border-divider/80 text-pn rounded-lg max-w-sm w-full max-h-[70vh] flex flex-col overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between gap-2 px-4 pt-4 pb-2">
          {/* One title for both modes. "Move folder" said the same thing in
              a second dialog that was quietly missing half this one's
              features, and a folder moves INTO a folder like anything else. */}
          <h2 className="text-[15px] font-semibold m-0">{title ?? t('folders.moveTo')}</h2>
          <CloseButton onClick={onClose} />
        </div>
        <div className="px-4 pb-2 shrink-0">
          <div className="flex items-center gap-2 rounded-md bg-surface-1 border border-divider px-2.5">
            <MagnifyingGlass size={14} className="shrink-0 text-pn-muted" aria-hidden="true" />
            <input
              autoFocus
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={t('folders.searchPlaceholder')}
              className="flex-1 min-w-0 h-9 bg-transparent text-[14px] focus:outline-none placeholder:text-pn-muted"
            />
          </div>
        </div>
        <div className="flex-1 overflow-y-auto px-2 pb-2 min-h-0">
          {/* Search flattens the tree on purpose: a match three levels down
              is easier to read as one row with its path than as a branch
              the reader has to trace. Carets and indent come back the
              moment the box is empty. */}
          {searching ? (
            matches.map((folder) => {
              const disabled = isDisabled(folder);
              const path = pathLabel(folder);
              return (
                <button
                  key={folder.id}
                  type="button"
                  disabled={disabled}
                  onClick={() => onPick(folder.id)}
                  className={`w-full flex items-center gap-2 px-3 py-2 rounded-md text-[14px] text-start transition ${
                    disabled
                      ? 'text-pn-muted/75 cursor-not-allowed'
                      : checkedId === folder.id
                        ? 'pn-on-tint bg-accent/15 text-accent-strong dark:bg-accent/20 hover:bg-accent/20 dark:hover:bg-accent/25'
                        : 'text-pn hover:bg-pn/5'
                  }`}
                >
                  <span className={`inline-flex shrink-0 ${disabled ? '' : 'text-label'}`}>
                    <FolderGlyph folderId={folder.id} size={15} />
                  </span>
                  <span className="flex-1 min-w-0 truncate">
                    {path && <span className="text-pn-muted">{path} / </span>}
                    {folder.name}
                  </span>
                  {trailingFor(folder)}
                </button>
              );
            })
          ) : (
            sections ? (
              sections.map((sec, i) => (
                <div key={sec.key} className={i > 0 ? 'mt-2 pt-2 border-t border-divider' : undefined}>
                  <div className="flex items-center gap-1.5 px-3 pt-1 pb-1 text-[12px] font-semibold text-pn-muted">
                    <sec.icon size={13} aria-hidden="true" />
                    {sec.label}
                  </div>
                  {renderTree(sec.folders)}
                  {sec.unfiled && unfiledRow}
                </div>
              ))
            ) : (
              renderTree(folders)
            )
          )}
          {/* Unfiled (note mode) / root level (folder mode) - see
              clearWouldChange above. No check mark: it is never the
              "current" row, only ever an action.

              Under the tree, not over it, because that is where the sidebar
              puts its own Unfiled row and the two are the same idea. It sat
              on top while it was thought of as the dialog's primary action;
              it is the LAST resort, and it now reads that way in both
              places. Muted for the same reason the rail's is. */}
          {!sections && unfiledRow}
          {searching && matches.length === 0 && (
            <div className="px-3 py-2 text-[13px] text-pn-muted">
              {t('folders.noMatches')}
            </div>
          )}
        </div>
        {onCreateFolder && (
          <div className="shrink-0 border-t border-divider px-2 py-2 flex">
            {creatingUnder === null ? (
              <div className="flex items-center gap-2 px-3 py-1 flex-1">
                <span className="inline-flex shrink-0 text-label">
                  <Folder size={15} />
                </span>
                <FolderNameInput
                  value={createDraft}
                  onChange={setCreateDraft}
                  onCommit={commitCreate}
                  onCancel={cancelCreate}
                  scale="dialog"
                />
              </div>
            ) : (
              <button
                type="button"
                onClick={() => {
                  setRenamingId(null);
                  setCreateDraft('');
                  setCreatingUnder(null);
                }}
                /* Dashed, like the sidebar's: the rows above are places you
                   go, this is a thing you make. Two buttons that do the same
                   job in the two places that draw the same tree should not
                   look like different controls.
                   Spec: ops/docs/archive/ui-patterns.md (section 76) */
                className="flex-1 inline-flex items-center justify-center gap-2 rounded-md border border-dashed border-divider px-3 py-2 text-[13px] text-pn-muted transition hover:border-accent/50 hover:text-accent"
              >
                <FolderPlus size={15} className="shrink-0 text-label" />
                {t('folders.new')}
              </button>
            )}
          </div>
        )}
        {/* Inside the dialog on purpose. It portals to document.body, so the
            dialog's `overflow-hidden` (and its backdrop-filter, which makes
            the dialog the containing block for fixed children) cannot clip
            it - but a portal still bubbles its clicks up the REACT tree, and
            only in here does the dialog's stopPropagation keep a menu click
            off the backdrop's close handler. */}
        <ContextMenu state={rowMenu.state} onClose={rowMenu.close} />
      </div>
    </div>
  );
}
