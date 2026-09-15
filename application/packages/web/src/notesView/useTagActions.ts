import { useCallback, useEffect, useState } from 'react';
import type { Dispatch, MutableRefObject, SetStateAction } from 'react';
import type { LocalNote } from '../db';
import {
  createNote,
  deleteTagEverywhere,
  normalizeTag,
  renameTagEverywhere,
  trashNotesWithTag,
} from '../notesRepo';
import type { UserSettings } from '../userSettings';
import type { View } from '../views';

export function useTagActions({
  activeNotes,
  selectedId,
  setSelectedId,
  selectedTag,
  setSelectedTag,
  setSelectedFolder,
  setView,
  setDrawerOpen,
  setCreatingTag,
  setNewTagDraft,
  pendingFocus,
  discardIfEmpty,
  mutateSettings,
  refresh,
  runSync,
}: {
  activeNotes: LocalNote[];
  selectedId: string | null;
  setSelectedId: Dispatch<SetStateAction<string | null>>;
  selectedTag: string | null;
  setSelectedTag: Dispatch<SetStateAction<string | null>>;
  setSelectedFolder: Dispatch<SetStateAction<string | null>>;
  setView: (next: View) => void;
  setDrawerOpen: Dispatch<SetStateAction<boolean>>;
  setCreatingTag: Dispatch<SetStateAction<boolean>>;
  setNewTagDraft: Dispatch<SetStateAction<string>>;
  pendingFocus: MutableRefObject<'title' | 'body' | null>;
  discardIfEmpty: (id: string | null) => Promise<boolean>;
  mutateSettings: (updater: (prev: UserSettings) => UserSettings) => void;
  refresh: () => Promise<LocalNote[]>;
  runSync: () => Promise<void>;
}) {
  // Flip a single tag between favorited / not-favorited. Idempotent.
  const toggleFavoriteTag = useCallback(
    (tag: string) => {
      mutateSettings((prev) => {
        const set = new Set(prev.favoriteTags);
        if (set.has(tag)) set.delete(tag);
        else set.add(tag);
        return { ...prev, favoriteTags: [...set] };
      });
    },
    [mutateSettings]
  );

  // Tag row action menu - "which tag's ⋯ menu is open right now".
  // At most one menu is open at a time; null means none.
  // Tag hover menu state. We store the viewport coordinates at which
  // the popup should render because the menu is positioned `fixed` -
  // `absolute` broke inside the scrolling tag rail (overflow clips
  // descendants) and let a higher-stacked bottom-of-sidebar menu cover
  // it when clicking tags near the bottom. Fixed + computed coords +
  // z-[60] dodges both problems and lets us flip upward when there's
  // not enough room below.
  const [openTagMenu, setOpenTagMenu] = useState<
    | {
        tag: string;
        x: number;
        y: number;
      }
    | null
  >(null);

  const openTagActionMenu = (tag: string, buttonEl: HTMLElement) => {
    const rect = buttonEl.getBoundingClientRect();
    // Right-align the menu under the ⋯ button so it mirrors the icon
    // (min-width 180). usePointMenuPosition measures the rendered menu and
    // clamps it on-screen - shifting it up when there's no room below - using
    // the real height, so no MENU_HEIGHT guess is needed.
    setOpenTagMenu({ tag, x: Math.max(8, rect.right - 180), y: rect.bottom + 4 });
  };
  // Inline rename: when non-null, the matching tag row renders an
  // input instead of the tag name. Enter commits, Escape or blur
  // (without committing) cancels.
  const [renamingTag, setRenamingTag] = useState<string | null>(null);
  const [renameBuffer, setRenameBuffer] = useState('');

  // Close the tag action menu on scroll / resize - fixed-positioned
  // popups can't follow their anchor, so the safest behavior is to
  // dismiss. Users can always reopen after scrolling.
  useEffect(() => {
    if (!openTagMenu) return;
    const close = () => setOpenTagMenu(null);
    window.addEventListener('resize', close);
    window.addEventListener('scroll', close, true); // capture: catch inner scrollers
    return () => {
      window.removeEventListener('resize', close);
      window.removeEventListener('scroll', close, true);
    };
  }, [openTagMenu]);

  const commitRenameTag = useCallback(
    async (oldTag: string, rawNew: string) => {
      const normalized = normalizeTag(rawNew);
      setRenamingTag(null);
      // Empty / invalid / same as before → no-op cancel.
      if (!normalized || normalized === oldTag) return;

      // If the target already exists on other notes, make it explicit:
      // we are MERGING the tag, not renaming. Use case-insensitive
      // comparison but allow pure case-change renames (e.g. "work" → "Work").
      const existingTags = new Set<string>();
      for (const n of activeNotes) for (const t of n.tags) existingTags.add(t);
      const isCaseChangeOnly = oldTag.toLowerCase() === normalized.toLowerCase();
      const conflictsWithExisting = !isCaseChangeOnly
        && [...existingTags].some((t) => t.toLowerCase() === normalized.toLowerCase());
      const doRename = async () => {
        await renameTagEverywhere(oldTag, normalized);
        // Migrate favorite flag too: if the old slug was starred, the
        // new slug inherits it (unless the new slug was already a
        // favorite, in which case nothing changes).
        mutateSettings((prev) => {
          if (!prev.favoriteTags.includes(oldTag)) return prev;
          const next = prev.favoriteTags.filter((t) => t !== oldTag);
          if (!next.includes(normalized)) next.push(normalized);
          return { ...prev, favoriteTags: next };
        });
        // If the currently selected tag filter was the old slug, point
        // it at the new one so the user keeps seeing the same notes.
        if (selectedTag === oldTag) setSelectedTag(normalized);
        await refresh();
        void runSync();
      };

      if (conflictsWithExisting) {
        const count = activeNotes.filter((n) => n.tags.includes(oldTag)).length;
        setTagConfirm({
          type: 'merge',
          tag: oldTag,
          targetTag: normalized,
          count,
          onConfirm: () => void doRename(),
        });
        return;
      }

      await doRename();
    },
    [activeNotes, mutateSettings, refresh, runSync, selectedTag]
  );

  const handleDeleteTag = useCallback(
    (tag: string) => {
      const count = activeNotes.filter((n) => n.tags.includes(tag)).length;
      setTagConfirm({
        type: 'delete',
        tag,
        count,
        onConfirm: () => {
          void (async () => {
            await deleteTagEverywhere(tag);
            mutateSettings((prev) => {
              if (!prev.favoriteTags.includes(tag)) return prev;
              return { ...prev, favoriteTags: prev.favoriteTags.filter((t) => t !== tag) };
            });
            if (selectedTag === tag) {
              setSelectedTag(null);
              setView('all');
            }
            await refresh();
            void runSync();
          })();
        },
      });
    },
    [activeNotes, mutateSettings, refresh, runSync, selectedTag]
  );

  /** Trash every note that carries a given tag, plus drop the tag from
      favorites. Notes end up in Trash (not permanently deleted) so the
      action is recoverable via the Trash view. */
  const handleDeleteTagAndNotes = useCallback(
    (tag: string) => {
      // Read-only notes keep their tag and stay put, so they are counted
      // apart: the modal asks about the rest and names how many stayed.
      const tagged = activeNotes.filter((n) => n.tags.includes(tag));
      const movable = tagged.filter((n) => n.locked !== 1);
      setTagConfirm({
        type: 'delete-with-notes',
        tag,
        count: movable.length,
        skipped: tagged.length - movable.length,
        onConfirm: () => {
          void (async () => {
            await trashNotesWithTag(tag);
            mutateSettings((prev) => {
              if (!prev.favoriteTags.includes(tag)) return prev;
              return { ...prev, favoriteTags: prev.favoriteTags.filter((t) => t !== tag) };
            });
            if (selectedTag === tag) {
              setSelectedTag(null);
              setView('all');
            }
            await refresh();
            void runSync();
          })();
        },
      });
    },
    [activeNotes, mutateSettings, refresh, runSync, selectedTag]
  );

  /**
   * Create a new note pre-tagged with `rawTag`, then select it and
   * focus the title. Tags in PrivacyNotes are just strings on notes -
   * there's no separate "tag entity" - so "create a tag" means
   * "create a note that carries this tag" and the sidebar picks it up
   * automatically via tagCounts on next refresh. Normalizes the input
   * the same way TagInput does (strip leading #, trim, lowercase).
   * No-op on empty input. View switches to 'home' + selects the new
   * tag so the user lands in the right filter.
   */
  async function handleCreateTag(rawTag: string) {
    // Use the shared normalizer so the sidebar honors the same rules as
    // TagInput in the note editor: lowercase, strip leading #, drop
    // invalid chars, cap at TAG_MAX_LENGTH. Without this, the sidebar
    // input would happily create 200-char tag strings that blow out
    // the layout.
    const tag = normalizeTag(rawTag);
    setCreatingTag(false);
    setNewTagDraft('');
    if (!tag) return;
    const previousId = selectedId;
    const note = await createNote('', '', [tag]);
    const discarded = await discardIfEmpty(previousId);
    if (discarded) await refresh();
    else await refresh();
    setView('home');
    setSelectedTag(tag);
    setSelectedFolder(null);
    pendingFocus.current = 'body';
    setSelectedId(note.id);
    setDrawerOpen(false);
  }

  /** Tag action confirmation (merge / delete / delete-with-notes). */
  const [tagConfirm, setTagConfirm] = useState<{
    type: 'merge' | 'delete' | 'delete-with-notes';
    tag: string;
    targetTag?: string;
    count: number;
    /** Read-only notes held back from a delete-with-notes action. */
    skipped?: number;
    onConfirm: () => void;
  } | null>(null);

  return {
    toggleFavoriteTag,
    openTagMenu,
    setOpenTagMenu,
    openTagActionMenu,
    renamingTag,
    setRenamingTag,
    renameBuffer,
    setRenameBuffer,
    commitRenameTag,
    handleDeleteTag,
    handleDeleteTagAndNotes,
    handleCreateTag,
    tagConfirm,
    setTagConfirm,
  };
}
