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

import type { Dispatch, MutableRefObject, ReactNode, SetStateAction } from 'react';
import i18n from '../i18n';
import type { ContextMenuItem } from '../ContextMenu';
import type { LocalNote } from '../db';
import {
  iconBookmark, iconCheckbox, iconCopy, iconDownload, iconEditPencil,
  iconExternal, iconFlame, iconFolder,
  iconNewJournal, iconNewLogin, iconNewTask,
  iconNote, iconPin, iconReadOnly, iconRestore, iconSettings, iconTag,
  iconShield, iconSidebar,
  iconSignOut, iconTrash, iconUpload, iconZen, NEW_GLYPHS, EXPORT_GLYPHS,
} from '../icons';
import { bulkActionGuards, noteActionGuards } from '../noteActionGuards';
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
  onNewContact: () => void;
  // Bookmark row actions (type 'link')
  onOpenBookmark: (n: LocalNote) => void;
  onCopyBookmarkUrl: (n: LocalNote) => void;
  onEditBookmark: (n: LocalNote) => void;
  setShowSettings: Dispatch<SetStateAction<boolean>>;
  handleSignOutClick: () => void;

  // Multi-select (used by buildNoteMenu for Select / Deselect)
  selectedIds: Set<string>;
  onToggleSelected: (id: string) => void;
  /** What a row does to a whole selection. Each is the handler the
   *  selection toolbar already calls, and each reads the current selection
   *  itself, so none of them takes a list of ids. */
  selectionAllStarred: boolean;
  selectionAllLocked: boolean;
  selectionAllProtected: boolean;
  onClearSelection: () => void;
  onBulkFavorite: () => void;
  onBulkMoveToFolder: () => void;
  onBulkDuplicate: () => void;
  onBulkExportMarkdown: () => void;
  onBulkExportHtml: () => void;
  onBulkSetLocked: (locked: boolean) => void;
  onBulkSetPinProtected: (pinProtected: boolean) => void;
  onRequestBulkUnprotect: () => void;
  onBulkRestore: () => void;
  onBulkDelete: () => void;
  /** Opens the tag picker for these ids at the point that was clicked. */
  onTagPicker: (ids: string[]) => void;

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
  /** Trash one note through the shared confirm modal, the same question a
   *  whole selection gets. */
  requestTrash: (ids: string[]) => void;
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
      label: i18n.t('shell:contextMenu.newContact'),
      icon: <NEW_GLYPHS.contact size={14} />,
      onSelect: () => deps.onNewContact(),
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
   * The menu for a right-click on a row that is one of several selected
   * ones. Every verb here acts on the whole selection, which is the only
   * reading of a menu opened over rows that all look picked. It offers
   * the selection toolbar's actions and takes their labels, so the two
   * surfaces cannot name the same action differently. (GitHub #188)
   */
  /**
   * Which items a menu is being built for. Every row reads this instead of
   * closing over one note, which is what lets one list serve both cases.
   */
  type Scope =
    | { kind: 'one'; note: LocalNote; isSelected: boolean }
    | { kind: 'many'; ids: string[] };

  /**
   * A row's answer when it has no meaning for a selection. The reason is
   * the documentation: a reader of the list sees why the row is absent
   * without hunting for the code that drops it.
   */
  type OneItemOnly = { readonly oneItemOnly: string };
  const oneItemOnly = (reason: string): OneItemOnly => ({ oneItemOnly: reason });
  const isOneItemOnly = (v: RowSpec['many']): v is OneItemOnly =>
    typeof v === 'object' && v !== null && 'oneItemOnly' in v;

  /**
   * One row of a note menu.
   *
   * `many` is required and has no default. That is the whole anti-drift
   * mechanism: a row cannot be added without saying what it means for a
   * selection, and "nothing" is a value that carries its reason rather
   * than an omission nobody notices. The two menus drifted apart once
   * because they were two lists; there is one list now.
   */
  type RowSpec = {
    label: (s: Scope) => string;
    icon: (s: Scope) => ReactNode;
    checked?: (s: Scope) => boolean;
    pro?: boolean;
    destructive?: boolean;
    success?: boolean;
    /** Rows that belong to certain items only, such as the bookmark verbs. */
    when?: (s: Scope) => boolean;
    one: (n: LocalNote) => void;
    many: ((ids: string[]) => void) | OneItemOnly;
  };

  /**
   * Turn groups of rows into a menu for one scope. Separators come from the
   * grouping rather than from hand-placed entries, so a filtered-out row can
   * never leave a doubled or leading rule behind.
   */
  function renderRows(groups: RowSpec[][], s: Scope): ContextMenuItem[] {
    const out: ContextMenuItem[] = [];
    for (const group of groups) {
      const rows = group.filter((r) => {
        if (r.when && !r.when(s)) return false;
        return !(s.kind === 'many' && isOneItemOnly(r.many));
      });
      if (rows.length === 0) continue;
      if (out.length > 0) out.push({ type: 'separator' });
      for (const r of rows) {
        out.push({
          label: r.label(s),
          icon: r.icon(s),
          ...(r.checked ? { checked: r.checked(s) } : {}),
          ...(r.pro ? { pro: true } : {}),
          ...(r.destructive ? { destructive: true } : {}),
          ...(r.success ? { success: true } : {}),
          onSelect: () => {
            if (s.kind === 'one') { r.one(s.note); return; }
            if (isOneItemOnly(r.many)) return;
            r.many(s.ids);
          },
        });
      }
    }
    return out;
  }

  /** The Pro and PIN gates for a selection, the twin of the per-note ones. */
  const bulkGuards = () => bulkActionGuards({
    isPro: deps.isPro,
    allLocked: deps.selectionAllLocked,
    allProtected: deps.selectionAllProtected,
    onSetLocked: (locked) => deps.onBulkSetLocked(locked),
    onSetPinProtected: (p) => deps.onBulkSetPinProtected(p),
    onRequestRemoveProtection: () => deps.onRequestBulkUnprotect(),
    onOpenUpgrade: (trigger) => deps.onOpenUpgrade(trigger ?? ''),
    onSetPin: deps.onSetPin,
    onClose: () => { /* the context menu closes itself after onSelect */ },
  });

  /** The same gates for one note, so the two surfaces cannot drift on who
   *  may lock a note and what a protect toggle asks for first. */
  const noteGuards = (n: LocalNote) => noteActionGuards({
    note: n,
    isPro: deps.isPro,
    onClose: () => { /* the context menu closes itself after onSelect */ },
    onSetLocked: (locked) => void deps.handleSetLocked(n.id, locked),
    onSetPinProtected: (p) => void deps.handleSetPinProtected(n.id, p),
    onRequestRemoveProtection: () => deps.requestRemoveProtection(n.id),
    onOpenUpgrade: (trigger) => deps.onOpenUpgrade(trigger ?? ''),
    onSetPin: deps.onSetPin,
  });

  const isLink = (s: Scope) => s.kind === 'one' && s.note.type === 'link';

  /** The selection row: it names the gesture, so it reads differently in
   *  each scope while staying the same row in the same place. */
  const selectRow: RowSpec = {
    label: (s) => s.kind === 'many'
      ? i18n.t('notes:selection.deselectAll')
      : s.isSelected ? i18n.t('shell:contextMenu.deselect') : i18n.t('shell:contextMenu.select'),
    icon: () => iconCheckbox(),
    one: (n) => deps.onToggleSelected(n.id),
    many: () => deps.onClearSelection(),
  };

  /** The rows a note menu offers outside the trash, in groups. */
  const NOTE_GROUPS: RowSpec[][] = [
    [
      {
        label: () => i18n.t('shell:contextMenu.openBookmark'),
        icon: () => iconExternal(),
        when: isLink,
        one: (n) => deps.onOpenBookmark(n),
        many: oneItemOnly('a bookmark opens one tab'),
      },
      {
        label: () => i18n.t('shell:contextMenu.copyBookmarkUrl'),
        icon: () => iconCopy(),
        when: isLink,
        one: (n) => deps.onCopyBookmarkUrl(n),
        many: oneItemOnly('the clipboard holds one address'),
      },
      {
        label: () => i18n.t('shell:contextMenu.editBookmark'),
        icon: () => iconEditPencil(),
        when: isLink,
        one: (n) => deps.onEditBookmark(n),
        many: oneItemOnly('the bookmark editor takes one bookmark'),
      },
    ],
    [selectRow],
    [
      {
        label: (s) => (s.kind === 'many' ? deps.selectionAllStarred : s.note.starred === 1)
          ? i18n.t('shell:contextMenu.unpin')
          : i18n.t('shell:contextMenu.pin'),
        icon: (s) => iconPin(s.kind === 'many' ? deps.selectionAllStarred : s.note.starred === 1),
        one: (n) => void deps.handleToggleStar(n.id, n.starred !== 1),
        many: () => deps.onBulkFavorite(),
      },
      {
        label: () => i18n.t('shell:selectionToolbar.tag'),
        icon: () => iconTag(),
        one: (n) => deps.onTagPicker([n.id]),
        many: (ids) => deps.onTagPicker(ids),
      },
      // Both labels come from the "..." options menu, because they name the
      // same two switches and one wording for a thing is enough. A trailing
      // check says which way a switch is set, the way a native menu does.
      {
        label: () => i18n.t('shell:noteOptionsMenu.readOnly'),
        icon: () => iconReadOnly(),
        pro: !deps.isPro,
        checked: (s) => s.kind === 'many' ? deps.selectionAllLocked : s.note.locked === 1,
        one: (n) => noteGuards(n).toggleLock(),
        many: () => bulkGuards().toggleLock(),
      },
      {
        label: () => i18n.t('shell:noteOptionsMenu.protect'),
        icon: () => iconShield(),
        pro: !deps.isPro,
        checked: (s) => s.kind === 'many' ? deps.selectionAllProtected : s.note.pinProtected === 1,
        one: (n) => noteGuards(n).toggleProtect(),
        many: () => bulkGuards().toggleProtect(),
      },
    ],
    [
      {
        label: () => i18n.t('shell:contextMenu.duplicate'),
        icon: () => iconCopy(),
        one: (n) => void deps.handleDuplicate(n.id),
        many: () => deps.onBulkDuplicate(),
      },
      {
        label: () => i18n.t('shell:contextMenu.moveToFolder'),
        icon: () => iconFolder(),
        pro: !deps.isPro,
        one: (n) => {
          if (!deps.foldersUnlocked) { deps.onOpenUpgrade('folders'); return; }
          deps.onMoveToFolder(n.id);
        },
        many: () => deps.onBulkMoveToFolder(),
      },
    ],
    [
      {
        label: () => i18n.t('shell:contextMenu.exportAsMarkdown'),
        icon: () => <EXPORT_GLYPHS.markdown size={14} aria-hidden="true" />,
        one: (n) => void deps.exportSingleMarkdown(n),
        many: () => deps.onBulkExportMarkdown(),
      },
      {
        label: () => i18n.t('shell:contextMenu.exportAsHtml'),
        icon: () => <EXPORT_GLYPHS.html size={14} aria-hidden="true" />,
        one: (n) => void deps.exportSingleHtml(n),
        many: () => deps.onBulkExportHtml(),
      },
      {
        label: () => i18n.t('shell:contextMenu.printSaveAsPdf'),
        icon: () => <EXPORT_GLYPHS.print size={14} aria-hidden="true" />,
        one: (n) => void deps.printNote(n),
        many: oneItemOnly('one sheet of paper cannot mean five notes'),
      },
      {
        label: () => i18n.t('shell:contextMenu.shareBurnAfterReading'),
        icon: () => <span className="text-orange-500"><EXPORT_GLYPHS.burn size={14} aria-hidden="true" /></span>,
        one: (n) => void deps.handleBurnShare(n),
        many: oneItemOnly('a burn link points at one note'),
      },
    ],
    [
      {
        label: () => i18n.t('shell:contextMenu.moveToTrash'),
        icon: () => iconTrash(),
        destructive: true,
        one: (n) => deps.requestTrash([n.id]),
        many: (ids) => deps.requestTrash(ids),
      },
    ],
  ];

  /** The trash view is a different menu, built the same way so its own two
   *  versions cannot drift either. */
  const TRASH_GROUPS: RowSpec[][] = [
    [selectRow],
    [
      {
        label: () => i18n.t('shell:contextMenu.restore'),
        icon: () => iconRestore(),
        success: true,
        one: (n) => void deps.handleRestore(n.id),
        many: () => deps.onBulkRestore(),
      },
    ],
    [
      {
        label: () => i18n.t('shell:contextMenu.deleteForever'),
        icon: () => iconTrash(),
        destructive: true,
        one: (n) => deps.requestDeleteConfirm(n.id, n.title || ''),
        many: () => deps.onBulkDelete(),
      },
    ],
  ];

  /**
   * Per-note menu. A right-click on one of several selected rows asks about
   * all of them: a per-note menu there applies a verb to a single row while
   * the rest sit highlighted beside it, which reads as a bug and is one
   * where the verb is destructive. (GitHub #188)
   */
  const buildNoteMenu = (n: LocalNote): ContextMenuItem[] => {
    const groups = deps.view === 'trash' ? TRASH_GROUPS : NOTE_GROUPS;
    const isSelected = deps.selectedIds.has(n.id);
    if (isSelected && deps.selectedIds.size > 1) {
      const ids = Array.from(deps.selectedIds);
      return [
        { type: 'header', label: i18n.t('shell:contextMenu.selectedCount', { count: ids.length }) },
        ...renderRows(groups, { kind: 'many', ids }),
      ];
    }
    return renderRows(groups, { kind: 'one', note: n, isSelected });
  };

  return { buildGlobalMenu, buildNoteMenu };
}
