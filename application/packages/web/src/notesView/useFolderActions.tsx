import { useCallback, useMemo, useState } from 'react';
import type { Dispatch, SetStateAction } from 'react';
import { useTranslation } from 'react-i18next';
import { CaretDown, Folder } from '../icons';
import { IconUpgrade } from '../UpgradeModal';
import type { LocalNote } from '../db';
import {
  applyFolderPlacement,
  createFolder,
  deleteFolder,
  folderCounts as computeFolderCounts,
  moveFolder,
  reconcileImportedFolders,
  renameFolder,
  validateFolders,
  type FolderDef,
} from '../folders';
import { bulkMoveToFolder } from '../notesRepo';
import type { UserSettings } from '../userSettings';
import type { View } from '../views';

export function useFolderActions({
  userSettings,
  mutateSettings,
  notes,
  activeNotes,
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
}: {
  userSettings: UserSettings;
  mutateSettings: (updater: (prev: UserSettings) => UserSettings) => void;
  notes: LocalNote[];
  activeNotes: LocalNote[];
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
  const { t } = useTranslation('notes');

  /** Folder picker modal - filing note(s) or re-parenting a folder. */
  const [folderPicker, setFolderPicker] = useState<
    // currentFolderId is undefined for a mixed multi-select: the picker then
    // marks nothing as current, rather than falsely claiming "Unfiled".
    | { mode: 'note'; noteIds: string[]; currentFolderId: string | null | undefined }
    | { mode: 'folder'; folderId: string }
    | null
  >(null);
  /** Folder delete confirmation (contents move up to the parent). */
  const [folderDeleteConfirm, setFolderDeleteConfirm] = useState<{ id: string; name: string } | null>(null);

  // Merge folders rebuilt by an importer (Obsidian) into the settings tree.
  // Reuses any existing folder whose path already matches (so re-importing
  // the same vault does not duplicate the tree) and returns imported-id ->
  // final-id so the caller can remap each note's folderId. Free accounts can
  // browse the imported folders (folder actions stay Pro-gated); an upgrade
  // unlocks editing them with no re-import.
  const mergeImportedFolders = useCallback(
    (incoming: FolderDef[]): Map<string, string> => {
      if (incoming.length === 0) return new Map();
      const { folders, idMap } = reconcileImportedFolders(
        userSettings.folders,
        incoming
      );
      mutateSettings((prev) => ({
        ...prev,
        folders: validateFolders(folders),
      }));
      return idMap;
    },
    [userSettings.folders, mutateSettings]
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
    const result = createFolder(userSettings.folders, name, parentId);
    if (!result) return null;
    mutateSettings((prev) => ({ ...prev, folders: [...prev.folders, result.created] }));
    scheduleFolderSync();
    return result.created.id;
  }

  /** Push the settings blob promptly after a folder mutation instead of
   *  waiting for the 30s poller, so the tree lands on other devices
   *  right away. Delayed one tick: mutateSettings persists inside the
   *  React state updater, which runs on the next render pass - a
   *  synchronous runSync would race it and see a clean (undirty) blob. */
  function scheduleFolderSync() {
    window.setTimeout(() => void runSync(), 250);
  }

  function handleRenameFolder(id: string, name: string) {
    if (!foldersUnlocked) {
      openFoldersUpsell();
      return;
    }
    mutateSettings((prev) => ({ ...prev, folders: renameFolder(prev.folders, id, name) }));
    scheduleFolderSync();
  }

  function handleMoveFolder(id: string, newParentId: string | null) {
    if (!foldersUnlocked) {
      openFoldersUpsell();
      return;
    }
    mutateSettings((prev) => ({ ...prev, folders: moveFolder(prev.folders, id, newParentId) }));
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
    mutateSettings((prev) => ({
      ...prev,
      folders: applyFolderPlacement(prev.folders, id, parentId, orderedIds),
    }));
    scheduleFolderSync();
  }

  /** Delete a folder: subfolders and notes move up to its parent. */
  async function handleDeleteFolder(id: string) {
    if (!foldersUnlocked) {
      openFoldersUpsell();
      return;
    }
    const { reparentTo } = deleteFolder(userSettings.folders, id);
    const memberIds = activeNotes.filter((n) => n.folderId === id).map((n) => n.id);
    mutateSettings((prev) => ({ ...prev, folders: deleteFolder(prev.folders, id).folders }));
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

  const folderCounts = useMemo(() => computeFolderCounts(activeNotes), [activeNotes]);

  /** Folder chip for the editor tag bar (filing method E) - shows where
   *  the note lives, click opens the shared picker. Used by both the
   *  markdown/task tag row and the vault item tag row. */
  const folderChipFor = (note: LocalNote) => {
    const noteFolder = note.folderId
      ? userSettings.folders.find((f) => f.id === note.folderId)
      : undefined;
    return (
      <button
        type="button"
        onClick={() => {
          if (!foldersUnlocked) {
            openFoldersUpsell();
            return;
          }
          setFolderPicker({ mode: 'note', noteIds: [note.id], currentFolderId: note.folderId ?? null });
        }}
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
            ? 'border-accent/40 bg-accent/15 text-accent hover:bg-accent/25'
            : 'border-dashed border-accent/40 bg-accent/8 text-accent hover:bg-accent/15 hover:border-accent/60'
        }`}
      >
        {/* The sidebar's folder mark, unchanged: same amber, same default
            weight. One folder looks like a folder everywhere, and the chip
            is not the place to fork that. */}
        <Folder size={12} className="shrink-0 text-amber-600/80 dark:text-amber-500/80" />
        <span className="truncate max-w-[120px]">
          {noteFolder ? noteFolder.name : t('shell:folders.chipUnfiled')}
        </span>
        <CaretDown size={9} className="shrink-0 opacity-70" />
        {/* Same trailing gold rocket the Folders segment carries in the
            sidebar rail: filing a note is a Pro action, and this chip is
            the one control that does it from the editor. */}
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
    handleReorderFolders,
    handleDeleteFolder,
    handleMoveNotesToFolder,
    folderCounts,
    folderChipFor,
    handleBulkMoveToFolder,
  };
}
