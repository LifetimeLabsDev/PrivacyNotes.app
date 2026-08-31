/**
 * Context-menu builders for the NotesView root, the editable surfaces
 * (title input, tag input, TipTap editor body) and the per-note menus
 * shown when right-clicking a row in the notes/files list.
 *
 * They live here rather than inline in NotesView's `AuthenticatedView`
 * so the orchestrator stays focused on state + layout, and so a reader
 * auditing the menus doesn't have to wade through unrelated code first.
 *
 * The builders re-derive on every call (no memoisation). That matches
 * the inline-function behaviour they replaced - switching to memoised
 * variants would risk holding stale closures over `view`, `theme` etc.
 */

import type { Dispatch, MutableRefObject, SetStateAction } from 'react';
import i18n from '../i18n';
import type { ContextMenuItem } from '../ContextMenu';
import type { LocalNote } from '../db';
import {
  iconBookmark, iconCheckbox, iconCopy, iconDownload, iconEditPencil,
  iconExternal, iconFlame, iconFolder,
  iconNewJournal, iconNewLogin, iconNewTask,
  iconNote, iconPin, iconReadOnly, iconRestore, iconSettings,
  iconShield, iconSidebar,
  iconSignOut, iconTrash, iconUpload, iconZen,
} from '../icons';
import { noteActionGuards } from '../noteActionGuards';
import type { ImageStore } from '../imageStore';
import type { View } from '../views';

/** Single config object - every builder reads from the same shape. */
export type ContextMenuDeps = {
  // Identity / navigation
  view: View;
  handleSelectView: (next: View) => Promise<void> | void;

  // Pro gate
  isPro: boolean;
  // Zen is Pro-gated but unlocked in the public demo; isPro still drives the
  // teaser badge, zenUnlocked drives whether the action fires.
  zenUnlocked: boolean;
  // Folders follows the same demo-teaser pattern as zen.
  foldersUnlocked: boolean;
  onOpenUpgrade: (trigger: string) => void;

  // Toggles + visible state (used by the Global menu)
  zenMode: boolean;
  setZenMode: Dispatch<SetStateAction<boolean>>;
  sidebarCollapsed: boolean;
  setSidebarCollapsed: Dispatch<SetStateAction<boolean>>;
  notesListCollapsed: boolean;
  setNotesListCollapsed: Dispatch<SetStateAction<boolean>>;
  /** Restore both pane widths to their defaults (GitHub #211). */
  onResetPaneWidths: () => void;

  // Creation + app shell
  handleNew: (vaultType?: 'login' | 'card' | 'ssh-key', overrideView?: View) => Promise<void> | void;
  /** Switch to Files and open the OS file picker (upload flow). */
  onNewFile: () => void;
  /** Bookmarks create through the pillar's quick-add bar, not handleNew -
   *  this navigates there and focuses the bar. */
  onNewBookmark: () => void;
  // Bookmark row actions (type 'link')
  onOpenBookmark: (n: LocalNote) => void;
  onCopyBookmarkUrl: (n: LocalNote) => void;
  onEditBookmark: (n: LocalNote) => void;
  setShowSettings: Dispatch<SetStateAction<boolean>>;
  handleSignOutClick: () => void;

  // Multi-select (used by buildNoteMenu for Select / Deselect)
  selectedIds: Set<string>;
  onToggleSelected: (id: string) => void;

  // Per-note actions (used by buildNoteMenu)
  handleRestore: (id: string) => Promise<void> | void;
  handlePermanentlyDelete: (id: string) => Promise<void> | void;
  requestDeleteConfirm: (id: string, title: string) => void;
  handleToggleStar: (id: string, starred: boolean) => Promise<void> | void;
  /** Pro: the read-only and PIN-protect toggles, gated by noteActionGuards. */
  handleSetLocked: (id: string, locked: boolean) => Promise<void> | void;
  handleSetPinProtected: (id: string, pinProtected: boolean) => Promise<void> | void;
  /** Turning protection off opens the note's gate in its remove state. */
  requestRemoveProtection: (id: string) => void;
  /** Open Security > PIN, for a protect attempt with no PIN set. */
  onSetPin: () => void;
  handleDuplicate: (id: string) => Promise<void> | void;
  handleTrash: (id: string) => Promise<void> | void;
  /** Pro: open the folder picker for this note. */
  onMoveToFolder: (id: string) => void;
  handleBurnShare: (n: LocalNote) => Promise<void> | void;
  exportSingleMarkdown: (n: LocalNote) => Promise<void> | void;
  exportSingleHtml: (n: LocalNote) => Promise<void> | void;
  printNote: (n: LocalNote) => Promise<void> | void;
  imageStoreRef: MutableRefObject<ImageStore | null>;
};

/**
 * Build the two menus for the current render. Returns plain arrays of
 * `ContextMenuItem`; the caller hands them to `ctxMenu.open`. The text
 * editor menu was retired in v0.158.0 - under strategy B (partial
 * suppression) the browser's native menu wins on editable surfaces.
 * Spec: ops/docs/backlog.md #74.
 */
export function createContextMenuBuilders(deps: ContextMenuDeps): {
  buildGlobalMenu: () => ContextMenuItem[];
  buildNoteMenu: (n: LocalNote) => ContextMenuItem[];
} {
  // Each "New X" switches to the matching pillar and then creates the
  // item. handleNew accepts an overrideView so it creates the correct
  // type even though the React re-render from handleSelectView hasn't
  // committed yet (closure's `view` would still be stale).
  // Fix: ops/docs/backlog.md #94.
  const createInPillar = (target: View) => () => {
    void deps.handleSelectView(target);
    void deps.handleNew(undefined, target);
  };

  // Order MUST match the sidebar pillar nav (TagsRail.tsx) and the "New" dropdown
  // (NotesList.tsx allNewOptions): Note, Task, Login, File, Journal, Bookmark.
  // Spec: ops/docs/ui-patterns.md section 45 (New-menu order invariant)
  const buildGlobalMenu = (): ContextMenuItem[] => [
    {
      label: i18n.t('shell:contextMenu.newNote'),
      icon: iconNote(),
      onSelect: createInPillar('all'),
    },
    {
      label: i18n.t('shell:contextMenu.newTask'),
      icon: iconNewTask(),
      onSelect: createInPillar('tasks'),
    },
    {
      label: i18n.t('shell:contextMenu.newLogin'),
      icon: iconNewLogin(),
      onSelect: createInPillar('vault'),
    },
    {
      label: i18n.t('shell:contextMenu.newFile'),
      icon: iconUpload(),
      onSelect: () => deps.onNewFile(),
    },
    {
      label: i18n.t('shell:contextMenu.newJournal'),
      icon: iconNewJournal(),
      onSelect: createInPillar('journal'),
    },
    {
      label: i18n.t('shell:contextMenu.newBookmark'),
      icon: iconBookmark(),
      onSelect: () => deps.onNewBookmark(),
    },
    { type: 'separator' },
    {
      label: deps.zenMode ? i18n.t('shell:contextMenu.exitZenMode') : i18n.t('shell:contextMenu.zenMode'),
      icon: iconZen(),
      pro: !deps.isPro,
      onSelect: () => {
        if (!deps.zenUnlocked) { deps.onOpenUpgrade('zen'); return; }
        deps.setZenMode((z) => !z);
      },
    },
    {
      label: deps.sidebarCollapsed ? i18n.t('shell:contextMenu.showSidebar') : i18n.t('shell:contextMenu.hideSidebar'),
      icon: iconSidebar(),
      onSelect: () => deps.setSidebarCollapsed((v: boolean) => !v),
    },
    {
      label: deps.notesListCollapsed ? i18n.t('shell:contextMenu.showNotesList') : i18n.t('shell:contextMenu.hideNotesList'),
      icon: iconSidebar(),
      onSelect: () => deps.setNotesListCollapsed((v) => !v),
    },
    {
      label: i18n.t('shell:contextMenu.resetPaneWidths'),
      icon: iconSidebar(),
      onSelect: () => deps.onResetPaneWidths(),
    },
    { type: 'separator' },
    {
      label: i18n.t('shell:contextMenu.settings'),
      icon: iconSettings(),
      onSelect: () => deps.setShowSettings(true),
    },
    {
      label: i18n.t('shell:contextMenu.signOut'),
      icon: iconSignOut(),
      destructive: true,
      onSelect: () => deps.handleSignOutClick(),
    },
  ];

  /**
   * Per-note menu. Different items when viewing the trash: restore +
   * "Delete Forever" (permanent delete, skips trash).
   */
  const buildNoteMenu = (n: LocalNote): ContextMenuItem[] => {
    const isSelected = deps.selectedIds.has(n.id);
    if (deps.view === 'trash') {
      return [
        {
          label: isSelected ? i18n.t('shell:contextMenu.deselect') : i18n.t('shell:contextMenu.select'),
          icon: iconCheckbox(),
          onSelect: () => deps.onToggleSelected(n.id),
        },
        { type: 'separator' },
        {
          label: i18n.t('shell:contextMenu.restore'),
          icon: iconRestore(),
          success: true,
          onSelect: () => void deps.handleRestore(n.id),
        },
        { type: 'separator' },
        {
          label: i18n.t('shell:contextMenu.deleteForever'),
          icon: iconTrash(),
          destructive: true,
          onSelect: () => deps.requestDeleteConfirm(n.id, n.title || ''),
        },
      ];
    }
    const starred = n.starred === 1;
    // The same gates the "..." options menu runs, so the two surfaces cannot
    // drift on who may lock a note and what a protect toggle asks for first.
    const guards = noteActionGuards({
      note: n,
      isPro: deps.isPro,
      onClose: () => { /* the context menu closes itself after onSelect */ },
      onSetLocked: (locked) => void deps.handleSetLocked(n.id, locked),
      onSetPinProtected: (p) => void deps.handleSetPinProtected(n.id, p),
      onRequestRemoveProtection: () => deps.requestRemoveProtection(n.id),
      onOpenUpgrade: (trigger) => deps.onOpenUpgrade(trigger ?? ''),
      onSetPin: deps.onSetPin,
    });
    // Bookmark rows lead with their own verbs; the standard entries follow.
    const linkItems: ContextMenuItem[] = n.type === 'link'
      ? [
          {
            label: i18n.t('shell:contextMenu.openBookmark'),
            icon: iconExternal(),
            onSelect: () => deps.onOpenBookmark(n),
          },
          {
            label: i18n.t('shell:contextMenu.copyBookmarkUrl'),
            icon: iconCopy(),
            onSelect: () => deps.onCopyBookmarkUrl(n),
          },
          {
            label: i18n.t('shell:contextMenu.editBookmark'),
            icon: iconEditPencil(),
            onSelect: () => deps.onEditBookmark(n),
          },
          { type: 'separator' },
        ]
      : [];
    return [
      ...linkItems,
      {
        label: isSelected ? i18n.t('shell:contextMenu.deselect') : i18n.t('shell:contextMenu.select'),
        icon: iconCheckbox(),
        onSelect: () => deps.onToggleSelected(n.id),
      },
      { type: 'separator' },
      {
        label: starred ? i18n.t('shell:contextMenu.unpin') : i18n.t('shell:contextMenu.pin'),
        icon: iconPin(starred),
        onSelect: () => void deps.handleToggleStar(n.id, !starred),
      },
      // Both labels come from the "..." options menu, because they name the
      // same two switches and one wording for a thing is enough. A trailing
      // check says which way a switch is set, the way a native menu does.
      {
        label: i18n.t('shell:noteOptionsMenu.readOnly'),
        icon: iconReadOnly(),
        pro: !deps.isPro,
        checked: n.locked === 1,
        onSelect: () => guards.toggleLock(),
      },
      {
        label: i18n.t('shell:noteOptionsMenu.protect'),
        icon: iconShield(),
        pro: !deps.isPro,
        checked: n.pinProtected === 1,
        onSelect: () => guards.toggleProtect(),
      },
      { type: 'separator' },
      {
        label: i18n.t('shell:contextMenu.duplicate'),
        icon: iconCopy(),
        onSelect: () => void deps.handleDuplicate(n.id),
      },
      {
        label: i18n.t('shell:contextMenu.moveToFolder'),
        icon: iconFolder(),
        pro: !deps.isPro,
        onSelect: () => {
          if (!deps.foldersUnlocked) { deps.onOpenUpgrade('folders'); return; }
          deps.onMoveToFolder(n.id);
        },
      },
      { type: 'separator' },
      {
        label: i18n.t('shell:contextMenu.exportAsMarkdown'),
        icon: iconDownload(),
        onSelect: () => void deps.exportSingleMarkdown(n),
      },
      {
        label: i18n.t('shell:contextMenu.exportAsHtml'),
        icon: iconDownload(),
        onSelect: () => void deps.exportSingleHtml(n),
      },
      {
        label: i18n.t('shell:contextMenu.printSaveAsPdf'),
        icon: iconDownload(),
        onSelect: () => void deps.printNote(n),
      },
      {
        label: i18n.t('shell:contextMenu.shareBurnAfterReading'),
        icon: <span className="text-orange-500">{iconFlame()}</span>,
        onSelect: () => void deps.handleBurnShare(n),
      },
      { type: 'separator' },
      {
        label: i18n.t('shell:contextMenu.moveToTrash'),
        icon: iconTrash(),
        destructive: true,
        onSelect: () => void deps.handleTrash(n.id),
      },
    ];
  };

  return { buildGlobalMenu, buildNoteMenu };
}
