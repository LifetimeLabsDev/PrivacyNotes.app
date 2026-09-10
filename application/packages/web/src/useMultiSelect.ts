import { useState, useRef, useCallback, useEffect } from 'react';
import type { LocalNote } from './db';
import type { View } from './views';
import type { ImageStore } from './imageStore';
import type { AttachmentStore } from './attachmentStore';
import {
  bulkTrash,
  bulkRestore,
  bulkPermanentlyDelete,
  bulkSetStarred,
  bulkAddTag,
} from './notesRepo';
import { gcOnNotesDelete } from './imageGC';

interface UseMultiSelectArgs {
  notes: LocalNote[];
  selectedId: string | null;
  setSelectedId: (id: string | null) => void;
  view: View;
  selectedTag: string | null;
  imageStoreRef: React.RefObject<ImageStore | null>;
  attachmentStoreRef: React.RefObject<AttachmentStore | null>;
  refresh: () => Promise<LocalNote[]>;
  runSync: () => Promise<void>;
  /** Re-read the storage counters after a bulk destroy. Same chain the
   *  single-note and empty-trash paths run; without it the Trash bar keeps
   *  rendering the pre-delete total until the view is left and re-entered. */
  refreshStorage: () => void;
  handleSelectNote: (id: string) => Promise<void>;
  exportAllMarkdownZip: (notes: LocalNote[]) => Promise<void>;
  /** Returns true if the note is currently PIN-locked. */
  isNoteLocked: (n: LocalNote) => boolean;
  /** Show PIN modal; resolves when user verifies or rejects. */
  requestPinGate: (action: () => Promise<void>) => void;
}

interface UseMultiSelectReturn {
  selectionMode: boolean;
  selectedIds: Set<string>;
  selectionAllStarred: boolean;
  displayNotesRef: React.MutableRefObject<LocalNote[]>;
  clearSelection: () => void;
  deselectAll: () => void;
  toggleSelected: (id: string) => void;
  rangeSelect: (id: string) => void;
  selectAllVisible: () => void;
  handleRowClick: (e: React.MouseEvent, id: string) => void;
  beginLongPress: (id: string) => void;
  cancelLongPress: () => void;
  bulkTrashPending: string[] | null;
  requestBulkTrash: () => void;
  requestTrash: (ids: string[]) => void;
  executeBulkTrash: () => Promise<void>;
  dismissBulkTrash: () => void;
  handleBulkRestore: () => Promise<void>;
  bulkDeletePending: string[] | null;
  requestBulkDelete: () => void;
  executeBulkDelete: () => Promise<void>;
  dismissBulkDelete: () => void;
  handleBulkFavorite: () => Promise<void>;
  handleBulkExport: () => Promise<void>;
  handleBulkAddTag: (tag: string) => Promise<number>;
}

/** Shift-click is the range-select gesture, so the browser must not also
 *  drag a text selection across the rows it spans. MOUSEDOWN is the only
 *  place to stop it: the selection is painted as the default action of that
 *  event, long before the click handler's `preventDefault()` runs. Attach to
 *  a list's scroll container so every row is covered by one handler - it
 *  fires only while shift is held, so ordinary text selection is untouched.
 *  Spec: ops/docs/ui-patterns.md section 53. */
export function suppressShiftTextSelection(e: React.MouseEvent) {
  if (e.shiftKey) e.preventDefault();
}

export function useMultiSelect({
  notes,
  selectedId,
  setSelectedId,
  view,
  selectedTag,
  imageStoreRef,
  attachmentStoreRef,
  refresh,
  runSync,
  refreshStorage,
  handleSelectNote,
  exportAllMarkdownZip,
  isNoteLocked,
  requestPinGate,
}: UseMultiSelectArgs): UseMultiSelectReturn {
  const [selectionMode, setSelectionMode] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(() => new Set());
  const [lastSelectedId, setLastSelectedId] = useState<string | null>(null);

  /** Drop every selected note + turn selection mode off. */
  const clearSelection = useCallback(() => {
    setSelectionMode(false);
    setSelectedIds(new Set());
    setLastSelectedId(null);
  }, []);

  /** Clear all selected IDs but stay in selection mode. */
  const deselectAll = useCallback(() => {
    setSelectedIds(new Set());
    setLastSelectedId(null);
  }, []);

  /** Toggle one id. Turns selection mode on implicitly when the set
   *  becomes non-empty, off when it drains back to zero. */
  const toggleSelected = useCallback((id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      setSelectionMode(next.size > 0);
      return next;
    });
    setLastSelectedId(id);
  }, []);

  // `displayNotes` is defined below (depends on state declared later).
  // We read it via a ref so the memoized callbacks below always see the
  // current filtered list without refiring their effect deps.
  const displayNotesRef = useRef<LocalNote[]>([]);

  // Keep a stable ref to handleSelectNote so handleRowClick's useCallback
  // doesn't go stale when selectedId changes. Without this, clicking
  // the previously-selected note after Cancel/deselect would hit the
  // early `id === selectedId` return in the stale closure and silently
  // do nothing.
  const handleSelectNoteRef = useRef(handleSelectNote);
  handleSelectNoteRef.current = handleSelectNote;

  /** Shift-click: select every row from the last-toggled id up to `id`,
   *  inclusive, additive. No-op (falls back to toggle) if there's no
   *  anchor yet. */
  const rangeSelect = useCallback(
    (id: string) => {
      if (!lastSelectedId || lastSelectedId === id) {
        toggleSelected(id);
        return;
      }
      const ids = displayNotesRef.current.map((n) => n.id);
      const a = ids.indexOf(lastSelectedId);
      const b = ids.indexOf(id);
      if (a < 0 || b < 0) {
        toggleSelected(id);
        return;
      }
      const [from, to] = a < b ? [a, b] : [b, a];
      setSelectedIds((prev) => {
        const next = new Set(prev);
        for (let i = from; i <= to; i++) {
          const nid = ids[i];
          if (nid) next.add(nid);
        }
        setSelectionMode(next.size > 0);
        return next;
      });
      setLastSelectedId(id);
    },
    [lastSelectedId, toggleSelected]
  );

  const selectAllVisible = useCallback(() => {
    const ids = displayNotesRef.current.map((n) => n.id);
    if (ids.length === 0) return;
    setSelectedIds(new Set(ids));
    setSelectionMode(true);
    setLastSelectedId(ids[ids.length - 1] ?? null);
  }, []);

  /** The one place row clicks route through. Decides whether the click
   *  is a navigation (open the note) or a selection gesture based on
   *  modifiers + current selectionMode. */
  const handleRowClick = useCallback(
    (e: React.MouseEvent, id: string) => {
      const mod = e.metaKey || e.ctrlKey;
      if (e.shiftKey && selectionMode) {
        e.preventDefault();
        rangeSelect(id);
        return;
      }
      if (mod || selectionMode) {
        e.preventDefault();
        toggleSelected(id);
        return;
      }
      void handleSelectNoteRef.current(id);
    },
    [selectionMode, rangeSelect, toggleSelected]
  );

  /** Touch long-press - enters selection mode on mobile. 500ms is the
   *  iOS standard; shorter feels twitchy, longer feels broken. */
  const longPressTimer = useRef<number | null>(null);
  const cancelLongPress = useCallback(() => {
    if (longPressTimer.current != null) {
      window.clearTimeout(longPressTimer.current);
      longPressTimer.current = null;
    }
  }, []);
  const beginLongPress = useCallback(
    (id: string) => {
      cancelLongPress();
      longPressTimer.current = window.setTimeout(() => {
        toggleSelected(id);
        longPressTimer.current = null;
      }, 500);
    },
    [cancelLongPress, toggleSelected]
  );

  // ── Bulk actions wired to the SelectionToolbar ───────────────────

  // Bulk trash uses the same two-step pattern as bulk delete:
  // requestBulkTrash stores pending IDs, the caller renders a
  // ConfirmModal, and executeBulkTrash runs the actual trash on confirm.
  const [bulkTrashPending, setBulkTrashPending] = useState<string[] | null>(null);

  function requestBulkTrash() {
    const ids = Array.from(selectedIds);
    if (ids.length === 0) return;
    setBulkTrashPending(ids);
  }

  /**
   * Ask about named notes rather than the current selection, so a single
   * note trashed from a menu gets the same question, the same wording and
   * the same PIN gate as a whole selection. One item reads "1 item"
   * through the plural form the modal already carries.
   */
  function requestTrash(ids: string[]) {
    if (ids.length === 0) return;
    setBulkTrashPending(ids);
  }

  async function executeBulkTrash() {
    const ids = bulkTrashPending;
    setBulkTrashPending(null);
    if (!ids || ids.length === 0) return;
    // If any selected notes are protected and currently locked, require PIN first.
    const hasLockedProtected = notes.some((n) => ids.includes(n.id) && n.pinProtected === 1 && isNoteLocked(n));
    if (hasLockedProtected) {
      requestPinGate(async () => {
        await bulkTrash(ids);
        if (selectedId && ids.includes(selectedId)) setSelectedId(null);
        clearSelection();
        await refresh();
        void runSync();
      });
      return;
    }
    await bulkTrash(ids);
    if (selectedId && ids.includes(selectedId)) setSelectedId(null);
    clearSelection();
    await refresh();
    void runSync();
  }

  function dismissBulkTrash() {
    setBulkTrashPending(null);
  }

  async function handleBulkRestore() {
    const ids = Array.from(selectedIds);
    if (ids.length === 0) return;
    await bulkRestore(ids);
    clearSelection();
    await refresh();
    void runSync();
  }

  // Bulk delete uses a two-step pattern: requestBulkDelete stores
  // the pending IDs, the caller renders a ConfirmModal, and
  // executeBulkDelete runs the actual destruction on confirm.
  const [bulkDeletePending, setBulkDeletePending] = useState<string[] | null>(null);

  function requestBulkDelete() {
    const ids = Array.from(selectedIds);
    if (ids.length === 0) return;
    setBulkDeletePending(ids);
  }

  async function executeBulkDelete() {
    const ids = bulkDeletePending;
    setBulkDeletePending(null);
    if (!ids || ids.length === 0) return;
    // GC blobs before deleting the notes - one batch call, so a blob
    // shared by two selected notes cannot hide behind its batch-mate in
    // the reference check.
    if (imageStoreRef.current) {
      const batch = ids
        .map((id) => notes.find((n) => n.id === id))
        .filter((n): n is NonNullable<typeof n> => n != null)
        .map((n) => ({ id: n.id, body: n.body }));
      void gcOnNotesDelete(imageStoreRef.current, batch, attachmentStoreRef.current);
    }
    await bulkPermanentlyDelete(ids);
    if (selectedId && ids.includes(selectedId)) setSelectedId(null);
    clearSelection();
    await refresh();
    // Storage counters only settle once the tombstones have reached the
    // server, so this chains off the sync rather than racing it - same
    // ordering as handlePermanentlyDelete and confirmEmptyTrash.
    void runSync().then(refreshStorage);
  }

  async function handleBulkFavorite() {
    const ids = Array.from(selectedIds);
    if (ids.length === 0) return;
    // If every selected note is already starred → unstar all. Otherwise
    // star all. Mixed sets become "star all" so one click always gives
    // a consistent outcome.
    const picked = notes.filter((n) => selectedIds.has(n.id));
    const allStarred = picked.length > 0 && picked.every((n) => n.starred === 1);
    await bulkSetStarred(ids, !allStarred);
    await refresh();
    void runSync();
  }

  async function handleBulkExport() {
    const ids = Array.from(selectedIds);
    if (ids.length === 0) return;
    const picked = notes.filter((n) => selectedIds.has(n.id));
    if (picked.length === 0) return;
    await exportAllMarkdownZip(picked);
  }

  async function handleBulkAddTag(tag: string): Promise<number> {
    const ids = Array.from(selectedIds);
    if (ids.length === 0) return 0;
    const count = await bulkAddTag(ids, tag);
    await refresh();
    void runSync();
    return count;
  }

  // When the active view changes (trash↔all↔starred↔tag) drop the
  // selection - acting on notes you can no longer see would be
  // confusing. Runs imperatively (not state-derived) so the reset only
  // fires on actual filter changes, not every render.
  useEffect(() => {
    if (selectionMode) clearSelection();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [view, selectedTag]);

  // Drop selected IDs whose note left the current list - trashed from a
  // normal view, restored out of the trash, permanently deleted, or
  // removed by a sync from another device. The per-note context menu
  // acts on one note but leaves the selection untouched, so without
  // this the set keeps dead IDs and the "N of M selected" strip
  // over-counts (#184: "5 of 4 selected", and a phantom "1 selected"
  // that survives deselecting every visible row).
  //
  // Keyed on note existence + trashed state only, NOT on the search /
  // tag / folder filters: a note being hidden is not the same as it
  // being removed, so a filter change must not silently drop the
  // user's selection.
  useEffect(() => {
    if (selectedIds.size === 0) return;
    const wantTrashed = view === 'trash' ? 1 : 0;
    const alive = new Set(
      notes.filter((n) => n.trashed === wantTrashed).map((n) => n.id)
    );
    const kept = Array.from(selectedIds).filter((id) => alive.has(id));
    if (kept.length === selectedIds.size) return;
    setSelectedIds(new Set(kept));
    setSelectionMode(kept.length > 0);
    setLastSelectedId((prev) => (prev && alive.has(prev) ? prev : null));
  }, [notes, view, selectedIds]);

  // Favorite-button state for the selection toolbar: "all starred"
  // iff every note in the selection has starred === 1. Drives the
  // toggle label ("Favorite" vs "Unfavorite") and icon fill.
  const selectionAllStarred =
    selectionMode &&
    selectedIds.size > 0 &&
    notes
      .filter((n) => selectedIds.has(n.id))
      .every((n) => n.starred === 1);

  return {
    selectionMode,
    selectedIds,
    selectionAllStarred,
    displayNotesRef,
    clearSelection,
    deselectAll,
    toggleSelected,
    rangeSelect,
    selectAllVisible,
    handleRowClick,
    beginLongPress,
    cancelLongPress,
    bulkTrashPending,
    requestBulkTrash,
    requestTrash,
    executeBulkTrash,
    dismissBulkTrash,
    handleBulkRestore,
    bulkDeletePending,
    requestBulkDelete,
    executeBulkDelete,
    dismissBulkDelete: () => setBulkDeletePending(null),
    handleBulkFavorite,
    handleBulkExport,
    handleBulkAddTag,
  };
}
