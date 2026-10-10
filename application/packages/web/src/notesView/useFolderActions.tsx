import { useCallback, useMemo, useRef, useState } from 'react';
import type { Dispatch, SetStateAction } from 'react';
import { useTranslation } from 'react-i18next';
import { CaretDown, Folder } from '../icons';
import { FolderGlyph } from '../looks/LookGlyph';
import { IconUpgrade } from '../UpgradeModal';
import type { LocalNote } from '../db';
import {
  applyFolderPlacement,
  canDeleteFolder,
  createFolder,
  deleteFolder,
  folderCounts as computeFolderCounts,
  moveFolder,
  reconcileImportedFolders,
  renameFolder,
  validateFolders,
  type FolderDef,
} from '../folders';
import { dropFolderLooks } from '../itemStyles';
import { carrySpaces, setRootSpace, type Space } from '../spaces';
import { liveItemIds } from '../itemDrag';
import { bulkMoveToFolder } from '../notesRepo';
import type { UserSettings } from '../userSettings';
import type { View } from '../views';

export function useFolderActions({
  userSettings,
  mutateSettings,
  notes,
  activeNotes,
  listedNotes,
  selectedIds,
  refresh,
  runSync,
  foldersUnlocked,
  isPro,
  setShowUpgrade,
  discardIfEmpty,
  selectedId,
  setSelectedId,
  setDrawerOpen,
  selectedFolder,
  setSelectedFolder,
  view,
  setView,
  activeSpace,
}: {
  userSettings: UserSettings;
  mutateSettings: (updater: (prev: UserSettings) => UserSettings) => void;
  /** The space a new root folder lands in ('personal' while spaces are off). */
  activeSpace: Space;
  notes: LocalNote[];
  activeNotes: LocalNote[];
  /** What the folder counts show: the items the All list holds. */
  listedNotes: LocalNote[];
  selectedIds: Set<string>;
  refresh: () => Promise<LocalNote[]>;
  runSync: () => Promise<void>;
  foldersUnlocked: boolean;
  /** Drives the gold rocket on the folder chip. Keyed off isPro, NOT
   *  foldersUnlocked, so the demo keeps the Pro label on a feature it
   *  unlocks as a teaser. */
  isPro: boolean;
  setShowUpgrade: (next: { trigger: 'folders' }) => void;
  discardIfEmpty: (id: string | null) => Promise<boolean>;
  selectedId: string | null;
  setSelectedId: Dispatch<SetStateAction<string | null>>;
  setDrawerOpen: Dispatch<SetStateAction<boolean>>;
  selectedFolder: string | null;
  setSelectedFolder: Dispatch<SetStateAction<string | null>>;
  view: View;
  setView: Dispatch<SetStateAction<View>>;
}) {
  // Every folder edit goes through here, so a folder that becomes a root
  // keeps its space and a new root lands in the active one.
  // Spec: ops/docs/plans/spaces.md (section 3)
  const spaceRef = useRef(activeSpace);
  spaceRef.current = activeSpace;
  const mutateFolders = useCallback(
    (updater: (prev: UserSettings) => UserSettings) => mutateSettings((prev) => {
      const next = updater(prev);
      if (next === prev || next.folders === prev.folders) return next;
      const itemStyles = carrySpaces(prev.folders, next.folders, next.itemStyles, spaceRef.current, prev.itemStyles);
      return itemStyles === next.itemStyles ? next : { ...next, itemStyles };
    }),
    [mutateSettings],
  );

  const { t } = useTranslation('notes');

  /** Folder picker modal - filing note(s) or re-parenting a folder. */
  const [folderPicker, setFolderPicker] = useState<
    // currentFolderId is undefined for a mixed multi-select: the picker then
    // marks nothing as current, rather than falsely claiming "Unfiled".
    // `space`: "Move to Work" or "Move to Personal", which shows only that
    // space's folders.
    | { mode: 'note'; noteIds: string[]; currentFolderId: string | null | undefined; space?: Space }
    | { mode: 'folder'; folderId: string }
    | null
  >(null);
  /** Folder delete confirmation (contents move up to the parent). */
  const [folderDeleteConfirm, setFolderDeleteConfirm] = useState<{ id: string; name: string } | null>(null);

  // Merge folders rebuilt by an importer (Obsidian) into the settings tree.
  // Reuses any existing folder whose path already matches (so re-importing
  // the same vault does not duplicate the tree), or, for our own backup, the
  // folder still live under the id the backup saved for it, and returns
  // imported-id -> final-id so the caller can remap each note's folderId.
  // Free accounts can browse the imported folders (folder actions stay
  // Pro-gated); an upgrade unlocks editing them with no re-import.
  const mergeImportedFolders = useCallback(
    (incoming: FolderDef[], originalIds?: ReadonlyMap<string, string>): Map<string, string> => {
      if (incoming.length === 0) return new Map();
      // Reconciled against the tree the updater is handed, never against a
      // copy from render: that copy can predate the first pull, and a tree
      // rebuilt from it would replace every folder it did not know about.
      // mutateSettings runs the updater before it returns, so the map is
      // filled by the time the caller reads it.
      let idMap = new Map<string, string>();
      mutateFolders((prev) => {
        const merged = reconcileImportedFolders(prev.folders, incoming, originalIds);
        idMap = merged.idMap;
        return { ...prev, folders: validateFolders(merged.folders) };
      });
      return idMap;
    },
    [mutateFolders]
  );

  // ── Folders (Pro) ───────────────────────────────────────────────
  // A folder is a filter: selecting one mirrors handleSelectTag. The
  // definitions live in userSettings.folders; every mutation goes
  // through mutateSettings so the settings generation guard applies.

  async function handleSelectFolder(id: string | null) {
    const previousId = selectedId;
    setSelectedFolder(id);
    // The current view and any active tag are kept: folder + tag + view
    // compose as one combined filter (the folder narrows whatever pillar
    // and tag are active). Trash is the exception - it holds deleted
    // notes, so it cannot narrow to a folder without contradicting the
    // folder's own count - and picking a folder there returns to All
    // items, the same landing handleSelectTag uses. handleSelectView
    // clears both filters in the other direction.
    if (view === 'trash') setView('home');
    setSelectedId(null);
    setDrawerOpen(false);
    const discarded = await discardIfEmpty(previousId);
    if (discarded) {
      await refresh();
      void runSync();
    }
  }

  /** Effective browse mode. The Folders view itself is visible to every
   *  account - free users can switch to it and look around; every
   *  folder ACTION (create, rename, move, delete, file a note) is what
   *  carries the Pro gate. */
  const effectiveBrowseMode: 'tags' | 'folders' = userSettings.sidebarBrowse;

  function handleBrowseChange(mode: 'tags' | 'folders') {
    mutateSettings((prev) => ({ ...prev, sidebarBrowse: mode }));
  }

  /** One shared upsell for every locked folder action. */
  function openFoldersUpsell() {
    setShowUpgrade({ trigger: 'folders' });
  }

  /** Create a folder and return its id (used by tree + picker). */
  function handleCreateFolder(name: string, parentId: string | null): string | null {
    if (!foldersUnlocked) {
      openFoldersUpsell();
      return null;
    }
    // Built inside the updater, against the tree the cache holds. Sibling
    // order and the depth check both read the existing tree, and a copy
    // taken from React can be older than the cache on a device whose first
    // sync has just landed.
    let created: FolderDef | null = null;
    mutateFolders((prev) => {
      const result = createFolder(prev.folders, name, parentId);
      if (!result) return prev;
      created = result.created;
      return { ...prev, folders: result.folders };
    });
    if (!created) return null;
    scheduleFolderSync();
    return (created as FolderDef).id;
  }

  /** Push the settings blob promptly after a folder mutation instead of
   *  waiting for the 30s poller, so the tree lands on other devices right
   *  away. `mutateSettings` has already written the cache by the time this
   *  runs, and the sync pass reads that cache, so there is nothing to wait
   *  for. */
  function scheduleFolderSync() {
    void runSync();
  }

  function handleRenameFolder(id: string, name: string) {
    if (!foldersUnlocked) {
      openFoldersUpsell();
      return;
    }
    mutateFolders((prev) => ({ ...prev, folders: renameFolder(prev.folders, id, name) }));
    scheduleFolderSync();
  }

  /** Put a root folder, its subfolders and their items in a space. */
  function handleMoveFolderToSpace(id: string, space: Space) {
    if (!foldersUnlocked) {
      openFoldersUpsell();
      return;
    }
    mutateSettings((prev) => ({ ...prev, itemStyles: setRootSpace(prev.itemStyles, id, space) }));
    scheduleFolderSync();
  }

  function handleMoveFolder(id: string, newParentId: string | null) {
    if (!foldersUnlocked) {
      openFoldersUpsell();
      return;
    }
    mutateFolders((prev) => ({ ...prev, folders: moveFolder(prev.folders, id, newParentId) }));
    scheduleFolderSync();
  }

  /**
   * Commit a drag in the folder tree. A drop either reorders siblings or
   * re-parents the folder, and this is the one path for both: `parentId` is
   * where it lands and `orderedIds` is that parent's children as they read
   * ON SCREEN afterwards, not a rearrangement of stored order. While the
   * tree is sorted by name or entries the two are different lists, and
   * writing the stored one moves a folder somewhere nobody dropped it.
   *
   * The caller switches that device to Custom sort in the same gesture -
   * without it the sort that was in force would immediately overrule the
   * drop, and the whole drag would look like it did nothing.
   */
  function handleReorderFolders(id: string, parentId: string | null, orderedIds: string[]) {
    if (!foldersUnlocked) {
      openFoldersUpsell();
      return;
    }
    mutateFolders((prev) => ({
      ...prev,
      folders: applyFolderPlacement(prev.folders, id, parentId, orderedIds),
    }));
    scheduleFolderSync();
  }

  /** Delete a folder: subfolders and notes move up to its parent. */
  async function handleDeleteFolder(id: string) {
    if (!canDeleteFolder(id, foldersUnlocked)) {
      openFoldersUpsell();
      return;
    }
    const memberIds = activeNotes.filter((n) => n.folderId === id).map((n) => n.id);
    // One call, against the tree the updater is handed, so the tombstone and
    // the parent the notes move to describe the same delete. mutateSettings
    // runs the updater before it returns, so reparentTo is set by the line
    // after it.
    let reparentTo: string | null = null;
    mutateFolders((prev) => {
      const next = deleteFolder({ folders: prev.folders, deleted: prev.foldersDeleted }, id);
      reparentTo = next.reparentTo;
      return {
        ...prev,
        folders: next.folders,
        foldersDeleted: next.deleted,
        itemStyles: dropFolderLooks(prev.itemStyles, [id]),
      };
    });
    if (memberIds.length > 0) {
      await bulkMoveToFolder(memberIds, reparentTo);
      await refresh();
    }
    if (selectedFolder === id) setSelectedFolder(reparentTo);
    void runSync();
  }

  /** File note(s) into a folder via the shared picker. */
  async function handleMoveNotesToFolder(noteIds: string[], folderId: string | null) {
    if (!foldersUnlocked) {
      openFoldersUpsell();
      return;
    }
    await bulkMoveToFolder(noteIds, folderId);
    await refresh();
    void runSync();
  }

  /**
   * A list item dropped on a sidebar folder (an id) or on Unfiled (null).
   * Only live notes move, and only into a folder that still exists: a sync
   * can delete one during the drag. The move then takes the Move dialog's
   * path, so a free account gets the same upgrade window.
   * Spec: ops/docs/plans/drag-to-folder-and-tag.md (section 6)
   */
  function handleDropOnFolder(ids: string[], folderId: string | null) {
    const live = liveItemIds(ids, activeNotes);
    if (live.length === 0) return;
    if (folderId !== null && !userSettings.folders.some((f) => f.id === folderId)) return;
    void handleMoveNotesToFolder(live, folderId);
  }

  const folderCounts = useMemo(() => computeFolderCounts(listedNotes), [listedNotes]);

  /** Folder chip for the editor tag bar (filing method E) - shows where
   *  the note lives, click opens the shared picker. Used by both the
   *  markdown/task tag row and the vault item tag row. A free account
   *  gets no chip: it cannot file a note, so the chip was an empty slot
   *  that only opened the upsell. The sidebar keeps its Folders entry. */
  const folderChipFor = (note: LocalNote) => {
    if (!foldersUnlocked) return null;
    const noteFolder = note.folderId
      ? userSettings.folders.find((f) => f.id === note.folderId)
      : undefined;
    return (
      <button
        type="button"
        onClick={() =>
          setFolderPicker({ mode: 'note', noteIds: [note.id], currentFolderId: note.folderId ?? null })
        }
        aria-label={t('shell:folders.moveTo')}
        /* Square corners and a border, against the round accent pills the
           tags use: the folder is the ONE place a note lives, the tags are
           however many labels it carries, and the shape carries that split.
           The chip itself stays ACCENT like everything else in the row - only
           the folder GLYPH is amber, which is the app's mark for a folder in
           the tree and the picker too. Both states draw a border, so filing a
           note no longer changes the chip's height. Unfiled keeps a DASHED
           border for "no folder yet" but in accent rather than grey - a grey
           dashed ghost read as a disabled control.
           Spec: ops/docs/ui-patterns.md (editor tag row) */
        className={`shrink-0 inline-flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded-md border transition ${
          noteFolder
            ? 'border-accent/40 bg-accent/15 text-accent-strong hover:bg-accent/25'
            : 'border-dashed border-accent/40 bg-accent/8 text-accent-strong hover:bg-accent/15 hover:border-accent/60'
        }`}
      >
        {/* The sidebar's folder mark, unchanged: same amber, same default
            weight. One folder looks like a folder everywhere, and the chip
            is not the place to fork that. */}
        {noteFolder ? (
          <FolderGlyph
            folderId={noteFolder.id}
            size={12}
            className="shrink-0 text-label"
          />
        ) : (
          <Folder size={12} className="shrink-0 text-label" />
        )}
        <span className="truncate max-w-[120px]">
          {noteFolder ? noteFolder.name : t('shell:folders.chipUnfiled')}
        </span>
        <CaretDown size={9} className="shrink-0 opacity-70" />
        {/* Same trailing gold rocket the Folders segment carries in the
            sidebar rail. Only the demo reaches it: the demo unlocks folders
            as a teaser and still labels them Pro. */}
        {!isPro && <span className="shrink-0 inline-flex"><IconUpgrade size={11} /></span>}
      </button>
    );
  };

  /** Bulk "Move to folder" from the selection toolbar. Opens the shared
   *  picker for every selected note; currentFolderId is only pre-selected
   *  when the whole selection already shares one folder, so a mixed
   *  selection never claims a folder it isn't all in. */
  function handleBulkMoveToFolder() {
    if (!foldersUnlocked) {
      openFoldersUpsell();
      return;
    }
    const ids = [...selectedIds];
    if (ids.length === 0) return;
    const folderIds = new Set(
      ids.map((id) => notes.find((n) => n.id === id)?.folderId ?? null),
    );
    setFolderPicker({
      mode: 'note',
      noteIds: ids,
      currentFolderId: folderIds.size === 1 ? [...folderIds][0] ?? null : undefined,
    });
  }

  return {
    mergeImportedFolders,
    folderPicker,
    setFolderPicker,
    folderDeleteConfirm,
    setFolderDeleteConfirm,
    handleSelectFolder,
    effectiveBrowseMode,
    handleBrowseChange,
    openFoldersUpsell,
    handleCreateFolder,
    handleRenameFolder,
    handleMoveFolder,
    handleMoveFolderToSpace,
    handleReorderFolders,
    handleDeleteFolder,
    handleMoveNotesToFolder,
    handleDropOnFolder,
    folderCounts,
    folderChipFor,
    handleBulkMoveToFolder,
  };
}
