import React, { useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type { LocalNote } from './db';
import type { ListPrefs, ListPrefsStore } from './listPrefs';
import type { ContextMenuItem } from './ContextMenu';
import { SelectionToolbar } from './SelectionToolbar';
import { SelectionCountStrip } from './SelectionCountStrip';
import { suppressShiftTextSelection } from './useMultiSelect';
import { ListPrefsPopover } from './ListPrefsPopover';
import NoteRow, { itemDragSelection } from './NoteRow';
import NoteCard from './NoteCard';
import { StorageBar } from './StorageBar';
import { HoverLabel } from './HoverLabel';
import { JournalCalendarCard, JournalCalendarPopover, useJournalCalendarShown, type CalendarCardExtras } from './JournalCalendar';
import { Key, CreditCard, Lock, NotePencil, Trash, SquaresFour, Book, Shield, ShieldPlus, PushPin, FileText, FunnelSimple, Note, CheckSquare, Upload, BookmarkSimple, Plus, Notebook, CalendarPlus, PILLAR_GLYPHS, NEW_GLYPHS } from './icons';
import { ActiveFilterEntry, ActiveSearchEntry, FilteredEmpty, ListFilterChips } from './ListFilterChips';
import { ListEntryCard } from './ListEntryCard';
import { BookmarkRowActions } from './BookmarkRowActions';
import { ListSearchInput } from './ListSearchInput';
import { Switch } from './Switch';
import { exemptOpts } from './i18nExempt';
import { NewButton, NewButtonDock } from './NewButton';
import { keyText } from './shortcutMatch';
import type { View } from './views';
import { ListNav } from './notesView/ListNav';
import { ItemList, useContextTarget, useItemList } from './itemList';
import { ImportPromptEntry, importPromptFor, type ImportOffer, type ImportPromptKind } from './ImportPrompt';
import { useListKeys } from './listKeys';
import { useListGroups, type ListEntry } from './ListGroupHeader';
import type { DayIndex } from './notesViewUtils';
import type { Space } from './spaces';
import { toLocalIso } from './intlFormat';

type VaultFilter = 'all' | 'login' | 'card' | 'ssh-key';


export interface NotesListProps {
  view: string;
  displayNotes: LocalNote[];
  selectedId: string | null;
  selectedTag: string | null;
  /** Pro folders: active folder filter, rendered as a dismissable chip
   *  under the title row so users can't miss why the list is scoped.
   *  `selectedTag` gets a chip of its own beside it. */
  activeFolderName: string | null;
  onClearFolder: () => void;
  onClearTag: () => void;
  /** Bookmark row actions, for the link rows this list shows in All and
   *  Pinned. The Bookmarks pillar draws the same pair. */
  onEditBookmark: (note: LocalNote) => void;
  onTrashBookmark: (note: LocalNote) => void;
  listHeaderLabel: string;
  /** Pillar switcher + drawer button, folded into this pane's title row. */
  onSelectView: (next: View) => void;
  /** Passed straight to ListNav; see userSettings.hiddenViews. */
  hiddenViews?: import('./views').View[] | undefined;
  /** The synced import-offer dismissal; see ImportPrompt.tsx. */
  importOffer: ImportOffer;
  /**
   * In All, the open Markdown folder's files whose path matches the search.
   * Those files live on disk, outside All, so the list offers them as one
   * entry that opens the Markdown section with the same filter.
   */
  markdownBridge?: { count: number; onOpen: () => void };
  onOpenDrawer: () => void;
  search: string;
  setSearch: (v: string) => void;
  searchInputRef: React.RefObject<HTMLInputElement | null>;
  mobileTabIndex: number | undefined;

  // List prefs
  listPrefs: ListPrefs;
  /** Global layout: narrow rows ('list') or full-width tiles ('grid'). */
  viewMode: 'list' | 'grid';
  listPrefsStore: ListPrefsStore;
  onListPrefsChange: (next: ListPrefsStore) => void;

  // Selection
  selectionMode: boolean;
  selectedIds: Set<string>;
  selectionAllStarred: boolean;
  selectionAllArchived: boolean;
  onClearSelection: () => void;
  onDeselectAll: () => void;
  onSelectAllVisible: () => void;
  onToggleSelected: (id: string) => void;
  onRangeSelect: (id: string) => void;

  // Bulk actions
  onBulkFavorite: () => void;
  onBulkArchive: () => void;
  onBulkTag: (tag: string) => void;
  onBulkMoveToFolder: () => void;
  foldersUnlocked: boolean;
  onBulkExport: () => void;
  onBulkTrash: () => void;
  onBulkRestore: () => void;
  onBulkDeleteForever: () => void;
  /** All existing tags with note counts, for the bulk tag picker. */
  allTags?: [string, number][];

  // Row handlers
  onRowClick: (e: React.MouseEvent, id: string) => void;
  onContextMenu: (e: React.MouseEvent, items: ContextMenuItem[]) => void;
  /** Opens a menu from a tap on a row's own button. The context-menu path
   *  above swallows touch on purpose, because a long press selects. */
  onOpenMenu: (e: React.MouseEvent, items: ContextMenuItem[]) => void;
  buildNoteMenu: (n: LocalNote) => ContextMenuItem[];
  onLongPressStart: (id: string) => void;
  onLongPressEnd: () => void;
  isNoteLocked: (n: LocalNote) => boolean;

  // Actions
  onNew: (vaultType?: 'login' | 'card' | 'ssh-key', overrideView?: View) => void;
  /** Switch to Files and open the OS file picker - the All-view "New"
   *  type picker's File option. */
  onNewFile: () => void;
  onNewBookmark: () => void;
  onNewContact: () => void;
  /** The quick add: the switcher in create mode. */
  onQuickAdd: () => void;
  /** Open the import modal on the tab this pillar imports from - the
   *  standing import entry at the end of the list. */
  onOpenImport: (tab: 'import' | 'vault') => void;
  onBackfillDate: (isoDate: string) => void;
  /** Every dated item by day: the one index every calendar reads. */
  calendarDays: DayIndex;
  /** Whether Notes and All hold a dated item, so their card shows. */
  datedLists: { notes: boolean; all: boolean };
  /** With Spaces on, the space that is not open, for the calendar switch. */
  otherSpace: Space | null;
  /** Opens an item a calendar names; a repeating one names its occurrence. */
  onOpenCalendarItem: (id: string, occurrence?: string) => void;
  /** The cards' expand button and the drop of a row on a day. */
  calendarExtras: CalendarCardExtras;
  /** The Calendar pillar's agenda, drawn in place of the item list. */
  calendarBody?: ReactNode;
  /** Creates a note or a task list on a day picked in a calendar. */
  onCreateDated: (type: 'note' | 'task', isoDate: string) => void;
  onEmptyTrash: () => void;
  trashedNotesLength: number;
  onRefreshStorage: () => Promise<void> | void;
  hotkeyLabel: string;

  // Vault
  vaultFilter: VaultFilter;
  onVaultFilterChange: (f: VaultFilter) => void;

  // Storage quota (shown in trash view)
  quotaUsedBytes?: number;
  quotaMaxBytes?: number;

  // Auto-delete trash
  autoDeleteTrashDays: number;
  onAutoDeleteTrashDaysChange: (days: number) => void;
}

/** One entry in a "New" dropdown menu. */
type NewMenuOption = {
  key: string;
  label: string;
  icon: React.ReactNode;
  onSelect: () => void;
  /** The key that runs it, drawn at the row's end. */
  keys?: string;
};

/* ── Shared "New" dropdown ──────────────────────────────────────────
 * One menu, reused by the Vault view (login / card / ssh-key) and the All
 * view (note / task / journal / login / file) so the two can't drift in
 * style or behaviour. Callers pass fully-built, already-translated options;
 * the button label ("New") is the only string this component owns. */
function NewDropdown({ options, label }: { options: NewMenuOption[]; label: string }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const { docked, slot } = useContext(NewButtonDock);
  // The bar's slot comes and goes with an open item; a menu left open would
  // greet the person on the way back.
  useEffect(() => setOpen(false), [slot]);

  useEffect(() => {
    if (!open) return;
    const handler = (e: PointerEvent | MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    // Use pointerdown for reliable mobile touch support; fall back to
    // mousedown for environments where PointerEvent isn't available.
    const evt = typeof PointerEvent !== 'undefined' ? 'pointerdown' : 'mousedown';
    document.addEventListener(evt, handler as EventListener);
    return () => document.removeEventListener(evt, handler as EventListener);
  }, [open]);

  return (
    // Spec: ops/docs/ui-patterns.md section 45 (z-index tier system - the
    // NewButton wrapper must not create a z-20 stacking context, or it traps the
    // MobileHeader's z-50 pillar dropdown beneath it in the Vault view).
    <NewButton
      wrapRef={ref}
      onClick={() => setOpen(!open)}
      label={label}
      popup="menu"
      expanded={open}
    >
      {/*
        `w-max` on the menu below is load-bearing, not decoration. The menu is
        absolutely positioned inside a `relative` wrapper that is only as wide as
        the "New" button, and an auto-width absolute box with `end-0` and no
        `start` shrink-to-fits against its CONTAINING BLOCK, not the viewport. So
        the menu was capped at the button's ~110px and every label longer than
        that wrapped onto two lines. English never showed it ("Credit Card", 11
        chars, fits); es "Tarjeta de credito" (18), pt "Cartao de Credito" (17),
        ca (17), it (16), pl (15), fr (14) and cs (18) all wrapped, and had done
        since each locale shipped. `w-max` opts out of the containing-block cap;
        `max-w` keeps a pathological string from running off a narrow viewport;
        `whitespace-nowrap` on the rows stops a two-word label breaking anyway.
        Spec: ops/docs/ui-patterns.md section 45.
      */}
      {open && (
        <div role="menu" className={`absolute end-0 ${docked ? 'bottom-full mb-2' : 'top-full mt-1'} z-50 w-max max-w-[calc(100vw-1.5rem)] bg-surface-2 border border-divider rounded-lg shadow-lg py-1`}>
          {options.map(({ key, label, icon, onSelect, keys }) => (
            <button
              key={key}
              type="button"
              role="menuitem"
              onClick={() => { onSelect(); setOpen(false); }}
              className="w-full flex items-center gap-2.5 px-3 py-2 text-sm text-start whitespace-nowrap text-pn-soft hover:bg-pn/5 transition cursor-pointer"
            >
              {/* Accent, like every other menu that lists things to go to or
                  make: the rail rows, the sidebar option menus and the view
                  picker. Grey here made this the one menu whose glyphs read as
                  decoration. The colour lives on the row rather than in
                  NEW_GLYPHS, because the same glyphs are also drawn inside the
                  New button itself, where they sit on an accent-tinted pill. */}
              <span className="text-accent">{icon}</span>
              {label}
              {keys && <kbd className="ms-auto ps-4 font-sans text-[11px] text-pn-muted">{keys}</kbd>}
            </button>
          ))}
        </div>
      )}
    </NewButton>
  );
}

type RowHandlers = {
  onClick: (e: React.MouseEvent) => void;
  onContextMenu: (e: React.MouseEvent) => void;
  onTouchStart: () => void;
  onToggleSelect: (e: React.MouseEvent) => void;
};

export function NotesList({
  view,
  displayNotes,
  selectedId,
  selectedTag,
  activeFolderName,
  onClearFolder,
  onClearTag,
  onEditBookmark,
  onTrashBookmark,
  listHeaderLabel,
  onSelectView,
  hiddenViews,
  importOffer,
  markdownBridge,
  onOpenDrawer,
  search,
  setSearch,
  searchInputRef,
  mobileTabIndex,
  listPrefs,
  viewMode,
  listPrefsStore,
  onListPrefsChange,
  selectionMode,
  selectedIds,
  selectionAllStarred,
  selectionAllArchived,
  onClearSelection,
  onDeselectAll,
  onSelectAllVisible,
  onToggleSelected,
  onRangeSelect,
  onBulkFavorite,
  onBulkArchive,
  onBulkTag,
  onBulkMoveToFolder,
  foldersUnlocked,
  onBulkExport,
  onBulkTrash,
  onBulkRestore,
  onBulkDeleteForever,
  allTags,
  onRowClick,
  onContextMenu,
  onOpenMenu,
  buildNoteMenu,
  onLongPressStart,
  onLongPressEnd,
  isNoteLocked,
  onNew,
  onNewFile,
  onNewBookmark,
  onNewContact,
  onQuickAdd,
  onOpenImport,
  onBackfillDate,
  calendarDays,
  datedLists,
  otherSpace,
  onOpenCalendarItem,
  calendarExtras,
  calendarBody,
  onCreateDated,
  onEmptyTrash,
  trashedNotesLength,
  onRefreshStorage,
  hotkeyLabel,
  vaultFilter,
  onVaultFilterChange,
  quotaUsedBytes,
  quotaMaxBytes,
  autoDeleteTrashDays,
  onAutoDeleteTrashDaysChange,
}: NotesListProps) {
  const { t } = useTranslation('notes');
  const [showListPrefs, setShowListPrefs] = useState(false);
  const listPrefsButtonRef = useRef<HTMLButtonElement | null>(null);
  const [showBackfill, setShowBackfill] = useState(false);
  const backfillButtonRef = useRef<HTMLButtonElement | null>(null);
  const newSlot = useContext(NewButtonDock).slot;
  useEffect(() => setShowBackfill(false), [newSlot]);

  const [contextTargetId, setContextTargetId] = useContextTarget();

  // One set of handlers per note id, the same functions on every render.
  // The rows are memoized, and a fresh closure per row per render made every
  // revealed row render again whenever this list did: after a pause in
  // typing, that is every row the user ever scrolled past. The handlers read
  // the latest props when they run, so none of them can act on a stale one.
  const latest = useRef({ displayNotes, onRowClick, onContextMenu, buildNoteMenu, onLongPressStart, onLongPressEnd, onToggleSelected, onRangeSelect });
  latest.current = { displayNotes, onRowClick, onContextMenu, buildNoteMenu, onLongPressStart, onLongPressEnd, onToggleSelected, onRangeSelect };
  const rowHandlers = useRef(new Map<string, RowHandlers>()).current;
  const endLongPress = useRef(() => latest.current.onLongPressEnd()).current;
  const handlersFor = (id: string): RowHandlers => {
    let h = rowHandlers.get(id);
    if (!h) {
      h = {
        onClick: (e) => latest.current.onRowClick(e, id),
        onContextMenu: (e) => {
          const note = latest.current.displayNotes.find((x) => x.id === id);
          if (!note) return;
          setContextTargetId(id);
          latest.current.onContextMenu(e, latest.current.buildNoteMenu(note));
        },
        onTouchStart: () => latest.current.onLongPressStart(id),
        onToggleSelect: (e) => {
          if (e.shiftKey) latest.current.onRangeSelect(id);
          else latest.current.onToggleSelected(id);
        },
      };
      rowHandlers.set(id, h);
    }
    return h;
  };


  /* Group headers (#448): one switch, and the sort decides the groups.
   * Spec: ops/docs/plans/list-groups.md */
  const grouping = useListGroups({
    notes: displayNotes,
    listPrefs,
    search,
    scope: view,
    entryDays: view === 'journal',
    selectionMode,
    selectedId,
    isNoteLocked,
    onContextMenu,
  });
  const entries = grouping.entries;
  /** What the progressive reveal counts: headers and shown items together. */
  const revealTotal = entries ? entries.length : displayNotes.length;
  // The items arrive in slices of 200, and a different list - a new view,
  // filter or search - starts at its top. Not reset when `displayNotes`
  // changes identity: that array is rebuilt on every edit, and a reset there
  // would yank a person scrolled deep into a long list back to the first
  // slice because they typed. (#186 and the reveal live in itemList.tsx.)
  const list = useItemList([view, selectedTag, activeFolderName, search, vaultFilter], revealTotal);
  const reveal = list.reveal;
  useListKeys(searchInputRef, list.ref, () => !selectionMode);

  /* The standing import entry, shared with every other pillar that has an
     importer (ImportPrompt.tsx owns the rules). Pinned and Trash are left
     out on purpose: both are views OF items that already exist, so an offer
     to bring more in answers nothing there. */
  // 'all' is the Notes pillar and 'home' is the All list, which read
  // backwards from their labels - see VIEW_NOTE_TYPES in views.ts.
  const importKind: ImportPromptKind | null =
    view === 'journal'
      ? 'journal'
      : view === 'vault'
        ? 'vault'
        : view === 'home' || view === 'all'
          ? 'notes'
          : null;
  const importPrompt = importPromptFor(importKind ?? 'notes', {
    count: displayNotes.length,
    offer: importOffer,
    suppressed:
      importKind === null ||
      selectionMode ||
      search.trim().length > 0 ||
      activeFolderName !== null ||
      selectedTag !== null,
  });
  /* The standing "a filter is on" entry, in the same slot and shared with
     every other scoped pillar (ListFilterChips.tsx owns it). The chips above
     say the same thing, but a person looking at three rows is looking at the
     rows, not at the band above them - a short list reads as the whole
     collection. The EMPTY case belongs to FilteredEmpty below, which carries
     its own button, so this one waits for the pane to have something to show.
     Trash composes with neither filter, and selection mode leaves it out for
     the reason the import offer does: it is not a selectable item. Held back
     until the revealed slice covers the whole list, so a long filtered list
     never draws it mid-scroll and then pushes it down again. */
  /* "Clear search" is the same entry for the other thing that narrows a list,
     and it appears ONLY when the search found nothing: a search explains
     itself, because the text sits in the box the person just typed into, so
     an entry beside results would be noise. An empty pane has nothing else in
     it to explain the silence. */
  const showSearchEntry = search.trim().length > 0 && displayNotes.length === 0 && !selectionMode;
  const showFilterEntry =
    view !== 'trash' &&
    !selectionMode &&
    /* The filter entry rides along in that empty case, so both possible
       causes are named - clearing the search alone can still show nothing. */
    (showSearchEntry || (displayNotes.length > 0 && reveal.visible >= revealTotal));
  // Grow the slice to cover an already-selected note, so returning to a view
  // with note #900 open still shows its row rather than only the first 200.
  //
  // A separate effect on purpose. Folding this into the reset above reads
  // `displayNotes` on the render the KEY changed, but the rebuilt list arrives a
  // render later (search is debounced upstream), so the lookup ran against the
  // previous, still-filtered array and never found the note. Measured against
  // the 2198-item vault: selecting row 2193 and then clearing a search left the
  // slice at 200 with the open row missing.
  //
  // Only ever grows, never shrinks, so it cannot undo the reset or drag a deep
  // scroll position back on an ordinary edit.
  useEffect(() => {
    if (!selectedId) return;
    reveal.ensure(
      entries
        ? entries.findIndex((e) => e.kind === 'note' && e.note.id === selectedId)
        : displayNotes.findIndex((n) => n.id === selectedId),
    );
  }, [displayNotes, entries, selectedId, reveal]);

  /** What a drag of the selection carries: the selected items this list
   *  shows, in list order. One function for every render, like the row
   *  handlers, so rows stay memoized. */
  const selection = useRef({ displayNotes, selectedIds, isNoteLocked });
  selection.current = { displayNotes, selectedIds, isNoteLocked };
  const dragSelection = useRef(() => {
    const { displayNotes: all, selectedIds: ids, isNoteLocked: gated } = selection.current;
    return itemDragSelection(all.filter((n) => ids.has(n.id)), gated);
  }).current;

  const ItemComponent = viewMode === 'grid' ? NoteCard : NoteRow;
  const calendarShown = useJournalCalendarShown();

  // Vault view "New" menu - structured secret types.
  const vaultNewOptions: NewMenuOption[] = [
    { key: 'login', label: t('vaultNew.login'), icon: <Lock />, onSelect: () => onNew('login') },
    { key: 'card', label: t('vaultNew.card'), icon: <CreditCard />, onSelect: () => onNew('card') },
    { key: 'ssh-key', label: t('vaultNew.sshKey', exemptOpts('notes:vaultNew.sshKey')), icon: <Key />, onSelect: () => onNew('ssh-key') },
  ];

  // All + Pinned "New" type picker (#190) - same items as the global
  // right-click menu, so any type can be started without switching pillars
  // first. Each creates in place (both views show every type); File is the
  // lone exception - it switches to Files and opens the OS picker. ONE array
  // feeds both views (single source of truth); NotesView decides whether the
  // created item is starred, from the active view. Bare-noun labels live in
  // notes:newMenu.* so the button's "New" isn't repeated in every row.
  // Order MUST match the sidebar pillar nav (TagsRail.tsx) and the right-click
  // menu (contextMenus.tsx buildGlobalMenu): Note, Task, Login, File, Journal, Event, Contact, Bookmark.
  // A tag or folder filter narrows the list, never the menu: every type
  // inherits both filters on creation, so all seven stay reachable and land
  // where the user is looking (GitHub #324).
  // Spec: ops/docs/ui-patterns.md section 45 (New-menu order invariant)
  const allNewOptions: NewMenuOption[] = [
    // Quick add heads the menu: one line that reads a day and a time.
    { key: 'quickAdd', label: t('newMenu.quickAdd'), icon: <CalendarPlus />, onSelect: () => onQuickAdd(), keys: keyText('quickAdd') },
    { key: 'note', label: t('newMenu.note'), icon: <NEW_GLYPHS.note />, onSelect: () => onNew() },
    { key: 'task', label: t('newMenu.task'), icon: <NEW_GLYPHS.task />, onSelect: () => onNew(undefined, 'tasks') },
    { key: 'login', label: t('newMenu.login'), icon: <NEW_GLYPHS.login />, onSelect: () => onNew('login', 'vault') },
    { key: 'file', label: t('newMenu.file'), icon: <NEW_GLYPHS.file />, onSelect: () => onNewFile() },
    { key: 'journal', label: t('newMenu.journal'), icon: <NEW_GLYPHS.journal />, onSelect: () => onNew(undefined, 'journal') },
    // An event is made in the quick add, which shows what it can read.
    { key: 'event', label: t('newMenu.event'), icon: <NEW_GLYPHS.event />, onSelect: () => onQuickAdd() },
    { key: 'contact', label: t('newMenu.contact'), icon: <NEW_GLYPHS.contact />, onSelect: () => onNewContact() },
    { key: 'bookmark', label: t('newMenu.bookmark'), icon: <NEW_GLYPHS.bookmark />, onSelect: () => onNewBookmark() },
  ];

  return (
    <>
      {/* Title row - fixed h-14 so the bottom border aligns pixel-perfect
          with the sidebar brand row (same h-14, same border). Contains
          the view label (with an icon) and the big "+ New Note" button,
          sized to match the PrivacyNotes logo on the left. Search was
          moved below this border - users process "where am I" and
          "make a new note" as one cluster, then "find something" second.
          When multi-select is active the header is replaced with a
          SelectionToolbar - same h-14, same border, no layout jump. */}
      {selectionMode && selectedIds.size > 0 ? (
        <SelectionToolbar
          mode={view === 'trash' ? 'trash' : 'normal'}
          allStarred={selectionAllStarred}
          allArchived={selectionAllArchived}
          onClear={onClearSelection}
          onFavorite={onBulkFavorite}
          onArchive={onBulkArchive}
          onTag={onBulkTag}
          onMoveToFolder={onBulkMoveToFolder}
          foldersUnlocked={foldersUnlocked}
          onExport={onBulkExport}
          onDelete={onBulkTrash}
          onRestore={onBulkRestore}
          onDeleteForever={onBulkDeleteForever}
          allTags={allTags}
        />
      ) : (
      <div className="shrink-0 h-11 md:h-14 px-4 border-b border-divider flex items-center justify-between gap-3">
        <ListNav
          hiddenViews={hiddenViews}
          view={view as Parameters<typeof ListNav>[0]['view']}
          onSelectView={onSelectView}
          onOpenDrawer={onOpenDrawer}
          title={view === 'trash' ? t('header.trash') : listHeaderLabel}
          icon={
            view === 'trash' ? (
              <PILLAR_GLYPHS.trash size={26} className="text-danger shrink-0" aria-label={t('header.trash')} />
            ) : view === 'home' ? (
              <PILLAR_GLYPHS.all size={26} className="text-accent shrink-0" aria-hidden="true" />
            ) : view === 'journal' ? (
              <PILLAR_GLYPHS.journals size={26} className="text-accent shrink-0" aria-hidden="true" />
            ) : view === 'vault' ? (
              <PILLAR_GLYPHS.vault size={26} className="text-accent shrink-0" aria-hidden="true" />
            ) : view === 'starred' ? (
              <PILLAR_GLYPHS.pinned size={26} className="text-accent shrink-0" aria-hidden="true" />
            ) : view === 'archive' ? (
              <PILLAR_GLYPHS.archive size={26} className="text-accent shrink-0" aria-hidden="true" />
            ) : view === 'calendar' ? (
              <PILLAR_GLYPHS.calendar size={26} className="text-accent shrink-0" aria-hidden="true" />
            ) : (
              <PILLAR_GLYPHS.notes size={26} className="text-accent shrink-0" aria-hidden="true" />
            )
          }
        />
        {view === 'trash' && trashedNotesLength > 0 ? (
          <HoverLabel label={t('trash.emptyHover')} position="above">
          <button
            onClick={onEmptyTrash}
            aria-label={t('trash.emptyHover')}
            className="shrink-0 inline-flex items-center rounded-md bg-red-500/10 hover:bg-red-500/20 text-danger font-semibold px-3 py-1.5 text-lg tracking-tight transition"
          >
            {t('trash.empty')}
          </button>
          </HoverLabel>
        ) : view !== 'trash' && view !== 'archive' ? (
          /* No New in Archive, as in Trash: nothing is born archived. Empty
             on a phone, where the button draws in the bottom bar through a
             portal, and hidden then, or the row would keep a gap for it. */
          <div className="shrink-0 flex items-center gap-1.5 empty:hidden">
            {view === 'vault' ? (
              <NewDropdown label={t('vaultNew.ariaLabel')} options={vaultNewOptions} />
            ) : view === 'home' || view === 'starred' ? (
              <NewDropdown label={t('header.new')} options={allNewOptions} />
            ) : view === 'journal' ? (
              /* The date picker hangs off the New button rather than a calendar
                 button beside it. This pillar is the only one that wanted three
                 controls in one h-14 row, and at a narrow list width the third
                 one truncated the title to "Jou...". Nothing is buried: today is
                 the picker's first row and the hotkey still creates it in one
                 stroke. */
              <NewButton
                buttonRef={backfillButtonRef}
                onClick={() => setShowBackfill((v) => !v)}
                label={t('journal.newEntry')}
                hover={t('journal.newEntryHover', { hotkey: hotkeyLabel })}
                popup="dialog"
                expanded={showBackfill}
              >
                {showBackfill && (
                  <JournalCalendarPopover
                    entries={calendarDays}
                    onOpen={onOpenCalendarItem}
                    onToday={() => onNew()}
                    onPick={onBackfillDate}
                    onClose={() => setShowBackfill(false)}
                    anchorRef={backfillButtonRef}
                  />
                )}
              </NewButton>
            ) : view === 'calendar' ? (
              <NewButton
                onClick={() => onQuickAdd()}
                label={t('header.newEvent')}
                hover={t('header.newEventHover', { hotkey: keyText('quickAdd') })}
              />
            ) : (
              <NewButton
                onClick={() => onNew()}
                label={t('header.newNote')}
                hover={t('header.newNoteHover', { hotkey: hotkeyLabel })}
              />
            )}
          </div>
        ) : null}
      </div>
      )}
      {/* Active filter chips - shared with the Tasks, Files and Bookmarks
          pillars via ListFilterChips. Hidden in trash (neither filter
          reaches it); the row no-ops when nothing is active. */}
      {view !== 'trash' && (
        <ListFilterChips
          folderName={activeFolderName}
          tag={selectedTag}
          onClearFolder={onClearFolder}
          onClearTag={onClearTag}
        />
      )}
      {/* Storage bar - shown in trash view to encourage emptying. */}
      {view === 'trash' && quotaMaxBytes != null && quotaMaxBytes > 0 && quotaUsedBytes != null && (
        <StorageBar
          label={t('trash.storage')}
          usedBytes={quotaUsedBytes}
          maxBytes={quotaMaxBytes}
          onRefresh={onRefreshStorage}
        />
      )}
      {/* Auto-delete toggle - shown in trash view. */}
      {view === 'trash' && (
        <Switch
          label={t('trash.autoDelete')}
          checked={autoDeleteTrashDays > 0}
          onChange={(on) => onAutoDeleteTrashDaysChange(on ? 30 : 0)}
          className="shrink-0 px-4 py-2 gap-2 select-none"
          labelClassName="text-xs text-pn-muted"
        />
      )}
      {/* Vault sub-filter pills - narrow by item type.
          `overflow-x-auto` + per-pill `shrink-0 whitespace-nowrap` because four
          pills of translated text do not fit the list column: es "Inicios de
          sesion"/"Tarjetas de credito" (17/19 chars), ca and pt (16/18), fr and
          it (12/16), pl (6/15), cs (10/14). Without it the pills shrank and their
          labels wrapped to two lines, which every locale but English and Dutch
          has been doing since it shipped. Scrolling a chip row is the normal
          affordance; wrapping inside a pill is not.
          Spec: ops/docs/ui-patterns.md section 45. */}
      {view === 'vault' && (
        <div className="shrink-0 px-3 pt-2 pb-1 flex gap-1.5 overflow-x-auto pn-scrollbar-none">
          {([
            ['all', t('vaultFilter.all')],
            ['login', t('vaultFilter.logins')],
            ['card', t('vaultFilter.cards')],
            ['ssh-key', t('vaultFilter.keys', exemptOpts('notes:vaultFilter.keys'))],
          ] as const).map(([key, label]) => (
            <button
              key={key}
              type="button"
              onClick={() => onVaultFilterChange(key as VaultFilter)}
              className={`shrink-0 whitespace-nowrap text-xs px-2.5 py-1 rounded-full transition font-medium ${
                vaultFilter === key
                  ? 'bg-accent-fill text-white'
                  : 'bg-surface-1 text-pn-muted hover:bg-pn/10'
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      )}
      {/* Search row - separate block so its own bottom border sits below
          the HR coming from the title row above. The sort / list-prefs
          button sits beside the input at the same height so it reads
          as part of the same row. */}
      <div className="shrink-0 px-3 py-2 md:p-3 border-b border-divider relative">
        <div className="flex items-stretch gap-2">
          {view !== 'calendar' && (
          <HoverLabel label={t('search.sortOptions')} position="above-start">
          <button
            ref={listPrefsButtonRef}
            type="button"
            onClick={() => setShowListPrefs((v) => !v)}
            aria-label={t('search.sortOptions')}
            aria-expanded={showListPrefs}
            className={`shrink-0 inline-flex items-center justify-center w-10 h-10 rounded-md border transition ${
              showListPrefs
                ? 'bg-accent/10 border-accent text-accent-strong'
                : 'bg-surface-2 border-divider text-pn-muted hover:border-accent hover:text-accent'
            }`}
          >
            {/* Sort / filter icon - three lines of descending length,
                matches SN + most filemanagers. */}
            <FunnelSimple size={18} />
          </button>
          </HoverLabel>
          )}
          <ListSearchInput
            inputRef={searchInputRef}
            tabIndex={mobileTabIndex}
            value={search}
            onChange={setSearch}
            placeholder={view === 'vault' ? t('search.placeholderVault') : t('search.placeholderNotes')}
          />
        </div>
        {showListPrefs && (
          <ListPrefsPopover
            store={listPrefsStore}
            onChange={onListPrefsChange}
            onClose={() => setShowListPrefs(false)}
            anchorRef={listPrefsButtonRef}
            className="absolute start-3 top-full mt-1"
            calendarRows={view === 'journal' || view === 'all' || view === 'home'}
            otherSpace={otherSpace}
            /* Journal and Vault own their view. Everything else this list
               draws - Notes, All, Pinned, Trash, a folder or tag filter
               inside any of them - shares Global: giving Notes a copy of its
               own would island the very pane the shared lists inherit from. */
            pillar={view === 'journal' ? 'journal' : view === 'vault' ? 'vault' : 'global'}
            showGroupsToggle
            {...(view === 'journal' ? { createdLabel: t('noteRow.entryDate') } : {})}
          />
        )}
      </div>
      {/* Selection count strip - sits below the search bar so the
          toolbar's h-14 row stays narrow-sidebar friendly. Only
          rendered while multi-select is active. */}
      {selectionMode && selectedIds.size > 0 && (
        <SelectionCountStrip
          selectedCount={selectedIds.size}
          totalCount={displayNotes.length}
          onSelectAll={onSelectAllVisible}
          onDeselectAll={onDeselectAll}
        />
      )}
      {view === 'calendar' ? calendarBody : (
      <ItemList list={list} grid={viewMode === 'grid'} onMouseDown={suppressShiftTextSelection}>
        {view === 'journal' && calendarShown && !search.trim() && !selectionMode && (
          <JournalCalendarCard grid={viewMode === 'grid'} entries={calendarDays} onOpen={onOpenCalendarItem} onPick={onBackfillDate} onToday={() => onNew()} {...calendarExtras} />
        )}
        {/* Notes and All draw the same card once they hold a dated item; an
            empty day there makes a note. Spec: ops/docs/plans/note-date.md (section 4) */}
        {((view === 'all' && datedLists.notes) || (view === 'home' && datedLists.all)) && calendarShown && !search.trim() && !selectionMode && (
          <JournalCalendarCard
            grid={viewMode === 'grid'}
            entries={calendarDays}
            onOpen={onOpenCalendarItem}
            onPick={(day) => onCreateDated('note', day)}
            onToday={() => onCreateDated('note', toLocalIso(new Date()))}
            {...calendarExtras}
          />
        )}
        {displayNotes.length === 0 && (
          <li className={viewMode === 'grid' ? 'col-span-full' : ''}>
            {/* A filtered list that came back empty says so, and says nothing
                was deleted - "No notes yet." on a filtered pane reads as data
                loss. A search that found nothing already names its own cause,
                so it keeps the plain line. */}
            {!search.trim() && (activeFolderName !== null || selectedTag !== null) ? (
              <FilteredEmpty
                folderName={activeFolderName}
                tag={selectedTag}
                onClearFolder={onClearFolder}
                onClearTag={onClearTag}
              />
            ) : (
              <p className="p-4 text-[13px] text-pn-muted text-center">
                {search.trim() ? t('empty.noMatches') : view === 'vault' ? t('empty.vault') : view === 'archive' ? t('empty.archive') : t('empty.notes')}
              </p>
            )}
          </li>
        )}
        {(entries ?? displayNotes.map((note): ListEntry => ({ kind: 'note', note }))).slice(0, reveal.visible).map((entry) => {
          if (entry.kind === 'header') return grouping.header(entry, viewMode === 'grid');
          const n = entry.note;
          return (
          <ItemComponent
            key={n.id}
            {...handlersFor(n.id)}
            note={n}
            isOpen={selectedId === n.id && !selectionMode}
            listPrefs={listPrefs}
            isNoteLocked={isNoteLocked(n)}
            isContextTarget={contextTargetId === n.id}
            onTouchEnd={endLongPress}
            onTouchMove={endLongPress}
            onTouchCancel={endLongPress}
            selectionMode={selectionMode}
            itemDrag
            dragSelection={dragSelection}
            isMultiSelected={selectedIds.has(n.id)}
            showTypeIcons
            sortAwareDate
            entryDays={view === 'journal'}
            trashTint={view === 'trash'}
            showArchived={view !== 'archive'}
            /* A bookmark is a bookmark in every pillar: the same hover pair
               the Bookmarks pane draws, because a link row here opens its URL
               on click and would otherwise offer no way to edit or delete it.
               Trash is exempt - a trashed row restores and deletes for good,
               which the row menu owns. */
            trailing={n.type === 'link' && view !== 'trash' && !selectionMode ? (
              <BookmarkRowActions
                note={n}
                onEdit={onEditBookmark}
                onTrash={onTrashBookmark}
                onMenu={(note, e) => onOpenMenu(e, buildNoteMenu(note))}
                tipPos={viewMode === 'grid' ? 'above-start' : 'start'}
              />
            ) : undefined}
          />
          );
        })}
        {showSearchEntry && (
          <ActiveSearchEntry
            search={search}
            onClearSearch={() => setSearch('')}
            variant={viewMode === 'grid' ? 'tile' : 'row'}
          />
        )}
        {markdownBridge && markdownBridge.count > 0 && search.trim() && !selectionMode && (
          <ListEntryCard
            variant={viewMode === 'grid' ? 'tile' : 'row'}
            icon={PILLAR_GLYPHS.markdown}
            label={t('shell:markdown.bridge', { count: markdownBridge.count })}
            onClick={markdownBridge.onOpen}
          />
        )}
        {showFilterEntry && (
          <ActiveFilterEntry
            folderName={activeFolderName}
            tag={selectedTag}
            onClearFolder={onClearFolder}
            onClearTag={onClearTag}
            variant={viewMode === 'grid' ? 'tile' : 'row'}
          />
        )}
        {importPrompt.show && importKind && (
          <ImportPromptEntry
            kind={importKind}
            variant={viewMode === 'grid' ? 'tile' : 'row'}
            onOpen={() => onOpenImport(importKind === 'vault' ? 'vault' : 'import')}
            onDismiss={importPrompt.dismiss}
          />
        )}
      </ItemList>
      )}
    </>
  );
}
