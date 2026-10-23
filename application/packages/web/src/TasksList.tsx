import { TaskCheckbox } from './ui';
import { memo, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { itemGridClass, useContextTarget, useItemList } from './itemList';
import type { LocalNote } from './db';
import { setPillarPrefs, type ListPrefs, type ListPrefsStore } from './listPrefs';
import type { UserSettings } from './userSettings';
import { selectTaskNotes, type TaskItem } from './tasks';
import { itemDragSelection } from './NoteRow';
import { WindowedNoteRow as NoteRow, WindowedNoteCard as NoteCard } from './WindowedNoteItem';
import { compareNotes, stripToPlainText, type DayIndex } from './notesViewUtils';
import type { ContextMenuItem } from './ContextMenu';
import { HoverLabel } from './HoverLabel';
import { SelectionToolbar } from './SelectionToolbar';
import { suppressShiftTextSelection } from './useMultiSelect';
import { ListSearchInput } from './ListSearchInput';
import { JournalCalendarCard, useJournalCalendarShown, type CalendarCardExtras } from './JournalCalendar';
import type { Space } from './spaces';
import { toLocalIso } from './intlFormat';
import { ActiveFilterEntry, ActiveSearchEntry, FilteredEmpty, ListFilterChips } from './ListFilterChips';
import { ListPrefsPopover } from './ListPrefsPopover';
import { CheckSquare, CheckFat, NotePencil, Eye, EyeSlash, Plus, PushPin, FunnelSimple, PILLAR_GLYPHS, NEW_GLYPHS } from './icons';
import { NewDropdown } from './NewButton';
import { keyText } from './shortcutMatch';
import type { View } from './views';
import { ListNav } from './notesView/ListNav';
import { ImportPromptEntry, importPromptFor, type ImportOffer } from './ImportPrompt';
import { textMatcher } from './textMatch';
import { isImeComposing } from './imeComposing';
import { Switch } from './Switch';
import { useListGroups } from './ListGroupHeader';

export interface TasksListProps {
  /** The view and space this list draws, so a return lands where it was;
   *  null under a search. Spec: ops/docs/archive/keep-my-place.md */
  place?: string | null;
  /** The calendar card, while a task list in the open space has a day.
   *  Spec: ops/docs/archive/note-date.md (section 4) */
  calendar?: ({ entries: DayIndex; onOpen: (id: string, occurrence?: string) => void; onCreate: (isoDate: string) => void; onEvent: (isoDate: string) => void } & CalendarCardExtras) | null;
  /** With Spaces on, the space that is not open, for the calendar switch. */
  otherSpace?: Space | null;
  allTasks: TaskItem[];
  activeNotes: LocalNote[];
  selectedId: string | null;
  /** Pro folders: active folder filter, rendered as a dismissable chip
   *  under the title row. Null when no folder is selected. */
  activeFolderName: string | null;
  /** Active tag filter - the chip beside the folder one. */
  activeTag: string | null;
  /** Pillar switcher + drawer button, folded into this pane's title row. */
  onSelectView: (next: View) => void;
  /** Passed straight to ListNav; see userSettings.hiddenViews. */
  hiddenViews?: import('./views').View[] | undefined;
  /** The synced import-offer dismissal; see ImportPrompt.tsx. */
  importOffer: ImportOffer;
  onOpenDrawer: () => void;
  onClearFolder: () => void;
  onClearTag: () => void;
  listPrefs: ListPrefs;
  /** Full prefs store + writer, for the sort/view popover. */
  listPrefsStore: ListPrefsStore;
  onListPrefsChange: (next: ListPrefsStore) => void;
  /** Global layout: narrow rows ('list') or full-width tiles ('grid'). */
  viewMode: 'list' | 'grid';
  showDoneTasks: boolean;
  search: string;
  setSearch: (v: string) => void;
  taskDraft: string;
  taskInputRef: React.RefObject<HTMLInputElement | null>;
  searchInputRef?: React.RefObject<HTMLInputElement | null>;
  mobileTabIndex: number | undefined;
  isNoteLocked: (n: LocalNote) => boolean;
  onSetShowDoneTasks: (updater: boolean | ((v: boolean) => boolean)) => void;
  onSetTaskDraft: (v: string) => void;
  onToggleTask: (task: TaskItem, checked: boolean) => void;
  onOpenTaskSource: (task: TaskItem) => void;
  onAddQuickTask: (text: string) => void;
  onNew: () => void;
  /** A new task that starts as a Kanban board. */
  onNewKanban: () => void;
  /** Open the import modal - the standing import entry at the end of the list. */
  onOpenImport: () => void;
  onSelectNote: (id: string) => void;
  onContextMenu: (e: React.MouseEvent, items: ContextMenuItem[]) => void;
  buildNoteMenu: (n: LocalNote) => ContextMenuItem[];

  // Multi-select
  selectionMode: boolean;
  selectedIds: Set<string>;
  selectionAllStarred: boolean;
  selectionAllArchived: boolean;
  onRowClick: (e: React.MouseEvent, id: string) => void;
  onToggleSelected: (id: string) => void;
  onRangeSelect: (id: string) => void;
  onLongPressStart: (id: string) => void;
  onLongPressEnd: () => void;
  onClearSelection: () => void;
  onSelectAllVisible: () => void;
  onBulkFavorite: () => void;
  onBulkArchive: () => void;
  onBulkTag: (tag: string) => void;
  onBulkMoveToFolder: () => void;
  foldersUnlocked: boolean;
  onBulkExport: () => void;
  onBulkTrash: () => void;
  allTags?: [string, number][];
}

export default function TasksList({
  place = null,
  allTasks,
  activeNotes,
  selectedId,
  activeFolderName,
  onSelectView,
  hiddenViews,
  importOffer,
  onOpenDrawer,
  onClearFolder,
  onClearTag,
  activeTag,
  listPrefs,
  listPrefsStore,
  onListPrefsChange,
  viewMode,
  showDoneTasks,
  search,
  setSearch,
  taskDraft,
  taskInputRef,
  searchInputRef,
  mobileTabIndex,
  isNoteLocked,
  onSetShowDoneTasks,
  onSetTaskDraft,
  onToggleTask,
  onOpenTaskSource,
  onAddQuickTask,
  onNew,
  onNewKanban,
  onOpenImport,
  onSelectNote,
  onContextMenu,
  buildNoteMenu,
  selectionMode,
  selectedIds,
  selectionAllStarred,
  selectionAllArchived,
  onRowClick,
  onToggleSelected,
  onRangeSelect,
  onLongPressStart,
  onLongPressEnd,
  onClearSelection,
  onSelectAllVisible,
  onBulkFavorite,
  onBulkArchive,
  onBulkTag,
  onBulkMoveToFolder,
  foldersUnlocked,
  onBulkExport,
  onBulkTrash,
  allTags,
  calendar,
  otherSpace = null,
}: TasksListProps) {
  const taskActions = useRef({ onToggleTask, onOpenTaskSource });
  useLayoutEffect(() => { taskActions.current = { onToggleTask, onOpenTaskSource }; }, [onToggleTask, onOpenTaskSource]);
  const { t: tr } = useTranslation('shell');
  const { t } = useTranslation('notes');
  const [showListPrefs, setShowListPrefs] = useState(false);
  const listPrefsButtonRef = useRef<HTMLButtonElement | null>(null);

  /** ID of the note row that was right-clicked - highlighted while context menu is open. */
  const [contextTargetId, setContextTargetId] = useContextTarget();
  const calendarShown = useJournalCalendarShown();
  const calendarCard = calendar && calendarShown && !search.trim() ? (
    <JournalCalendarCard
      grid={viewMode === 'grid'}
      entries={calendar.entries}
      onOpen={calendar.onOpen}
      onPick={calendar.onCreate}
      onToday={() => calendar.onCreate(toLocalIso(new Date()))}
      creates="task"
      onEvent={calendar.onEvent}
      onExpand={calendar.onExpand}
      drop={calendar.drop}
    />
  ) : null;

  // Parent notes by id. The aggregate groups tasks by note, so it orders
  // and badges each group through the note it came from - same pinned
  // -first, then sort-pref rule every other notes surface uses.
  const notesById = useMemo(() => {
    const m = new Map<string, LocalNote>();
    for (const n of activeNotes) m.set(n.id, n);
    return m;
  }, [activeNotes]);

  // Group tasks by parent note for the Tasks view. The task lines of a note
  // the PIN guards right now are its content, so they stay out of the list
  // entirely; the note's own row, with its title and shield, is where it
  // opens the gate.
  const taskGroups = useMemo(() => {
    const q = search.trim();
    const match = q ? textMatcher(q) : null;
    const groups = new Map<
      string,
      { noteId: string; noteTitle: string; editedAt: string; tasks: TaskItem[] }
    >();
    const openTasks = allTasks.filter((t) => {
      const n = notesById.get(t.noteId);
      if (n === undefined || isNoteLocked(n)) return false;
      return listPrefs.showNoteTasks || n.type === 'task';
    });
    const doneFiltered = showDoneTasks
      ? openTasks
      : openTasks.filter((t) => !t.checked);
    const searchFiltered = match
      ? doneFiltered.filter((t) => match(t.text) || match(t.noteTitle))
      : doneFiltered;
    for (const t of searchFiltered) {
      const g = groups.get(t.noteId);
      if (g) {
        g.tasks.push(t);
        if (t.editedAt > g.editedAt) g.editedAt = t.editedAt;
      } else {
        groups.set(t.noteId, {
          noteId: t.noteId,
          noteTitle: t.noteTitle,
          editedAt: t.editedAt,
          tasks: [t],
        });
      }
    }
    return [...groups.values()].sort((a, b) => {
      const na = notesById.get(a.noteId);
      const nb = notesById.get(b.noteId);
      if (na && nb) return compareNotes(na, nb, listPrefs);
      return a.editedAt < b.editedAt ? 1 : -1;
    });
  }, [allTasks, showDoneTasks, search, notesById, listPrefs, isNoteLocked]);

  // Notes that belong in the Tasks pillar. Shared with NotesView, which
  // needs the identical list for multi-select - see selectTaskNotes.
  const taskContainingNotes = useMemo(
    () => selectTaskNotes(activeNotes, allTasks, search, listPrefs, isNoteLocked),
    [activeNotes, allTasks, search, listPrefs, isNoteLocked]
  );

  /* The pillar's two kinds of content. A note typed 'task' is a list made in
     here, with the New button or the quick-add bar; everything else is an
     ordinary note that happens to carry a checkbox. The aggregate draws them
     as two bands so a recipe never sits among the to-dos, and the switch above
     drops the second band entirely. The header appears only when both kinds
     are present, because a label that separates needs two things to separate. */
  const ownGroups = taskGroups.filter((g) => notesById.get(g.noteId)?.type === 'task');
  const fromGroups = taskGroups.filter((g) => notesById.get(g.noteId)?.type !== 'task');

  /**
   * Takes the place of every "nothing here" message below when the pane is
   * empty ONLY because a filter is on. Null the rest of the time, so each
   * branch keeps its own wording via `?? <fallback>`. A search that found
   * nothing already names its own cause and is left alone.
   */
  const filteredEmpty =
    taskContainingNotes.length === 0 && !search.trim() && (activeFolderName !== null || activeTag !== null) ? (
      <FilteredEmpty
        folderName={activeFolderName}
        tag={activeTag}
        onClearFolder={onClearFolder}
        onClearTag={onClearTag}
      />
    ) : null;

  /** The whole selection as note-links, in list order, for a drag. */
  const dragSelection = () => itemDragSelection(taskContainingNotes.filter((n) => selectedIds.has(n.id)), isNoteLocked);

  const ItemComp = viewMode === 'grid' ? NoteCard : NoteRow;

  /* The standing import entry, shared with the other pillars
     (ImportPrompt.tsx owns the rules). Tasks live inside
     notes, so the count that decides whether the offer has had its chance is
     the notes that hold them, which is exactly what this pane lists. */
  const importPrompt = importPromptFor('tasks', {
    count: taskContainingNotes.length,
    offer: importOffer,
    suppressed:
      selectionMode || search.trim().length > 0 || activeFolderName !== null || activeTag !== null,
  });

  /* The standing "a filter is on" entry, shared with the other scoped pillars
     (ListFilterChips.tsx owns it). `filteredEmpty` above answers the empty
     case; this one answers the quiet one, where the pane still has something
     to show and a short list reads as every task there is. Both counts,
     because the three list shapes draw different things: the note rows in
     list and grid, the per-note groups in aggregated, and both in hybrid. */
  /* "Clear search" is the same entry for the other thing that narrows a list,
     and it appears ONLY when the search found nothing - a search explains
     itself, an empty pane does not. Both counts again, for the same reason.
     The filter entry rides along there, so both causes are named. */
  const nothingShown = taskContainingNotes.length === 0 && taskGroups.length === 0;
  const searchEntry =
    search.trim().length > 0 && nothingShown && !selectionMode ? (
      <ActiveSearchEntry
        search={search}
        onClearSearch={() => setSearch('')}
        variant={viewMode === 'grid' ? 'tile' : 'row'}
      />
    ) : null;
  const filterEntry =
    (activeFolderName !== null || activeTag !== null) && !selectionMode && (searchEntry || !nothingShown) ? (
      <ActiveFilterEntry
        folderName={activeFolderName}
        tag={activeTag}
        onClearFolder={onClearFolder}
        onClearTag={onClearTag}
        variant={viewMode === 'grid' ? 'tile' : 'row'}
      />
    ) : null;
  const importEntry = importPrompt.show ? (
    <ImportPromptEntry
      kind="tasks"
      variant={viewMode === 'grid' ? 'tile' : 'row'}
      onOpen={onOpenImport}
      onDismiss={importPrompt.dismiss}
    />
  ) : null;

  const renderTaskNoteRow = (n: LocalNote) => (
    <ItemComp
      windowed={taskContainingNotes.length > 100}
      key={n.id}
      note={n}
      isOpen={selectedId === n.id && !selectionMode}
      listPrefs={listPrefs}
      isNoteLocked={isNoteLocked(n)}
      onClick={(e) => onRowClick(e, n.id)}
      onContextMenu={(e) => {
        setContextTargetId(n.id);
        onContextMenu(e, buildNoteMenu(n));
      }}
      isContextTarget={contextTargetId === n.id}
      onTouchStart={() => onLongPressStart(n.id)}
      onTouchEnd={onLongPressEnd}
      onTouchMove={onLongPressEnd}
      onTouchCancel={onLongPressEnd}
      selectionMode={selectionMode}
      itemDrag
      dragSelection={dragSelection}
      isMultiSelected={selectedIds.has(n.id)}
      onToggleSelect={(e) => {
        if (e.shiftKey) onRangeSelect(n.id);
        else onToggleSelected(n.id);
      }}
      showTypeIcons
      sortAwareDate
    />
  );

  /* Group headers (#448) over the notes that hold tasks, in the grid and in
     the list's first band. The "All tasks" section stays grouped by note.
     Spec: ops/docs/archive/list-groups.md */
  const grouping = useListGroups({
    notes: taskContainingNotes,
    listPrefs,
    search,
    scope: 'tasks',
    entryDays: false,
    selectionMode,
    selectedId,
    isNoteLocked,
    onContextMenu,
  });
  // Both bands arrive in slices, like every other list (useProgressiveReveal):
  // one budget counts the item rows first, then the task lines, so a vault
  // with thousands of checklist lines no longer builds all of them on open.
  // The scroll position across a hide and show of the pane (#186) rides
  // along; a new search or filter starts at the top.
  const noteItemCount = grouping.entries ? grouping.entries.length : taskContainingNotes.length;
  const taskLineCount = viewMode === 'grid' ? 0 : taskGroups.reduce((sum, g) => sum + g.tasks.length, 0);
  const revealTotal = noteItemCount + taskLineCount;
  const list = useItemList([search, activeFolderName, activeTag, viewMode], revealTotal, place);
  const reveal = list.reveal;
  const revealedAll = reveal.visible >= revealTotal;
  useEffect(() => {
    if (!selectedId) return;
    reveal.ensure(
      grouping.entries
        ? grouping.entries.findIndex((e) => e.kind === 'note' && e.note.id === selectedId)
        : taskContainingNotes.findIndex((n) => n.id === selectedId),
    );
  }, [grouping.entries, taskContainingNotes, selectedId, reveal]);

  const taskNoteItems = (grid: boolean) =>
    grouping.entries
      ? grouping.entries.slice(0, reveal.visible).map((e) => (e.kind === 'header' ? grouping.header(e, grid) : renderTaskNoteRow(e.note)))
      : taskContainingNotes.slice(0, reveal.visible).map(renderTaskNoteRow);

  // The task lines the budget still covers after the item rows, handed out
  // group by group in drawing order: the own lists, then the other items.
  let lineBudget = Math.max(0, reveal.visible - noteItemCount);
  const takeLines = (g: { tasks: TaskItem[] }) => {
    const n = Math.min(lineBudget, g.tasks.length);
    lineBudget -= n;
    return n;
  };

  const renderTaskGroup = (g: { noteId: string; noteTitle: string; editedAt: string; tasks: TaskItem[] }, shown: number) => {
        const groupActive = selectedId === g.noteId;
        return (
        <div
          key={g.noteId}
          className={`border-b border-divider/50 ${
            groupActive ? 'bg-accent/10 border-s-2 border-s-accent dark:bg-accent/15' : ''
          }`}
        >
          <HoverLabel label={tr('tasksList.openNote', { title: g.noteTitle })} position="above">
          <button
            onClick={() =>
              void onOpenTaskSource({
                noteId: g.noteId,
                noteTitle: g.noteTitle,
                lineIdx: g.tasks[0]?.lineIdx ?? 0,
                text: '',
                checked: false,
                editedAt: g.editedAt,
              })
            }
            className={`w-full flex items-center gap-1.5 text-start px-4 pt-3 pb-1 text-[11px] uppercase tracking-wide font-semibold transition ${
              groupActive
                ? 'text-accent dark:text-accent'
                : 'text-pn-muted hover:text-accent dark:hover:text-accent'
            }`}
            aria-label={tr('tasksList.openNote', { title: g.noteTitle })}
          >
            {notesById.get(g.noteId)?.starred === 1 && (
              <PushPin size={11} className="shrink-0" aria-hidden="true" />
            )}
            <span className="truncate">{g.noteTitle}</span>
          </button>
          </HoverLabel>
          <ul className="pb-2">
            {g.tasks.slice(0, shown).map((t) => (
              <TaskLine key={`${t.noteId}:${t.lineIdx}`} task={t} actions={taskActions} />
            ))}
          </ul>
        </div>
        );
  };

  /* The label between the two bands. Drawn by the list and the aggregate, so
     the hybrid shape inherits it through the aggregate it already renders. */
  const bandHeader = (
    <div className="px-4 pt-3 pb-1 text-[11px] uppercase tracking-wide font-semibold text-pn-muted border-t border-divider">
      {tr('tasksList.tasksFromOtherItems')}
    </div>
  );

  const aggregatedTasksSection = (
    <>
      {taskGroups.length === 0 && (filteredEmpty ?? (
        <div className="p-6 text-[13px] text-pn-muted text-center">
          {search.trim()
            ? tr('tasksList.noMatches')
            : !listPrefs.showNoteTasks
              ? tr('tasksList.noTaskListsYet')
              : showDoneTasks
                ? tr('tasksList.noTasksYet')
                : tr('tasksList.noOpenTasks')}
        </div>
      ))}
      {ownGroups.map((g) => {
        const shown = takeLines(g);
        return shown > 0 && renderTaskGroup(g, shown);
      })}
      {ownGroups.length > 0 && fromGroups.length > 0 && lineBudget > 0 && bandHeader}
      {fromGroups.map((g) => {
        const shown = takeLines(g);
        return shown > 0 && renderTaskGroup(g, shown);
      })}
    </>
  );

  return (
    <>
      {/* Row 1 -- title + count + New button (replaced by SelectionToolbar when selecting) */}
      {selectionMode && selectedIds.size > 0 ? (
        <SelectionToolbar
          mode="normal"
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
          onRestore={() => {}}
          onDeleteForever={() => {}}
          allTags={allTags}
        />
      ) : (
      <div className="shrink-0 h-11 md:h-14 px-4 border-b border-divider flex items-center justify-between gap-3">
        <ListNav
          hiddenViews={hiddenViews}
          view="tasks"
          onSelectView={onSelectView}
          onOpenDrawer={onOpenDrawer}
          title={tr('tasksList.title')}
          icon={<PILLAR_GLYPHS.tasks size={26} className="text-accent shrink-0" aria-hidden="true" />}
        />
        <NewDropdown
          label={tr('tasksList.newTaskNote')}
          options={[
            { key: 'task', label: t('newMenu.task'), icon: <NEW_GLYPHS.task />, onSelect: () => onNew(), keys: keyText('newNote') },
            { key: 'kanban', label: t('newMenu.kanban'), icon: <NEW_GLYPHS.kanban />, onSelect: () => onNewKanban() },
          ]}
        />
      </div>
      )}

      {/* Folder filter chip - same shared chip the notes list renders. */}
      <ListFilterChips
        folderName={activeFolderName}
        tag={activeTag}
        onClearFolder={onClearFolder}
        onClearTag={onClearTag}
      />

      {/* Row 3 -- show/hide done + sort/view prefs + search */}
      <div className="shrink-0 px-3 py-2 md:p-3 border-b border-divider relative">
        <div className="flex items-stretch gap-2">
          <HoverLabel label={showDoneTasks ? tr('tasksList.hideCompleted') : tr('tasksList.showCompleted')} position="above">
          <button
            type="button"
            onClick={() => onSetShowDoneTasks((v) => !v)}
            aria-label={showDoneTasks ? tr('tasksList.hideCompleted') : tr('tasksList.showCompleted')}
            aria-pressed={showDoneTasks}
            className={`shrink-0 inline-flex items-center justify-center w-10 h-10 rounded-md border transition ${
              showDoneTasks
                ? 'bg-accent/10 border-accent text-accent-strong'
                : 'bg-surface-2 border-divider text-pn-soft hover:border-accent hover:text-accent'
            }`}
          >
            {showDoneTasks ? <EyeSlash size={18} /> : <Eye size={18} />}
          </button>
          </HoverLabel>
          <HoverLabel label={tr('tasksList.sortOptions')} position="above-start">
          <button
            ref={listPrefsButtonRef}
            type="button"
            onClick={() => setShowListPrefs((v) => !v)}
            aria-label={tr('tasksList.sortOptions')}
            aria-expanded={showListPrefs}
            className={`shrink-0 inline-flex items-center justify-center w-10 h-10 rounded-md border transition ${
              showListPrefs
                ? 'bg-accent/10 border-accent text-accent-strong'
                : 'bg-surface-2 border-divider text-pn-soft hover:border-accent hover:text-accent'
            }`}
          >
            <FunnelSimple size={18} />
          </button>
          </HoverLabel>
          <ListSearchInput
            inputRef={searchInputRef}
            value={search}
            onChange={setSearch}
            placeholder={tr('tasksList.searchPlaceholder')}
          />
        </div>
        {showListPrefs && (
          <ListPrefsPopover
            store={listPrefsStore}
            onChange={onListPrefsChange}
            onClose={() => setShowListPrefs(false)}
            anchorRef={listPrefsButtonRef}
            className="absolute start-3 top-full mt-1"
            pillar="tasks"
            calendarRows
            otherSpace={otherSpace}
            showGroupsToggle
          />
        )}
      </div>

      {/* Tasks-from-notes toggle - the Bookmarks pillar's inline row */}
      <div className="shrink-0 px-4 py-2 border-b border-divider">
        <Switch
          label={tr('listPrefs.showNoteTasks')}
          checked={listPrefs.showNoteTasks}
          onChange={(on) => onListPrefsChange(setPillarPrefs(listPrefsStore, 'tasks', { ...listPrefs, showNoteTasks: on }))}
          className="gap-2 select-none"
          labelClassName="text-xs text-pn-muted"
        />
      </div>

      {/* Row 4 -- Quick-add */}
      <div className="shrink-0 p-3 border-b border-divider">
        <div className="flex items-center gap-2 rounded-md bg-surface-2 border border-divider px-3 py-2 focus-within:border-accent">
          <Plus size={16} className="text-pn-muted shrink-0" />
          <input
            ref={taskInputRef}
            tabIndex={mobileTabIndex}
            value={taskDraft}
            onChange={(e) => onSetTaskDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && taskDraft.trim() && !isImeComposing(e)) {
                e.preventDefault();
                const text = taskDraft;
                onSetTaskDraft('');
                void onAddQuickTask(text);
              }
            }}
            placeholder={tr('tasksList.quickAddPlaceholder')}
            enterKeyHint="done"
            className="flex-1 min-w-0 bg-transparent text-[15px] focus:outline-none placeholder:text-pn-muted"
          />
        </div>
      </div>

      {/* Content -- the tile grid, or the pane's one list shape */}
      <div
        ref={list.ref as React.RefObject<HTMLDivElement>}
        onScroll={(e) => list.onScroll(e.currentTarget)}
        className="flex-1 overflow-y-auto"
        onMouseDown={suppressShiftTextSelection}
      >
        {viewMode !== 'grid' && calendarCard && <ul>{calendarCard}</ul>}
        {viewMode === 'grid' ? (
          <>
            {taskContainingNotes.length === 0 && (filteredEmpty ?? (
              <div className="p-6 text-[13px] text-pn-muted text-center">
                {search.trim()
                  ? tr('tasksList.noMatches')
                  : !listPrefs.showNoteTasks
                    ? tr('tasksList.noTaskListsYet')
                    : tr('tasksList.noItemsWithTasks')}
              </div>
            ))}
            {(taskContainingNotes.length > 0 || importEntry || searchEntry || filterEntry) && (
              <ul className={itemGridClass(true)}>
                {calendarCard}
                {taskNoteItems(true)}
                {searchEntry}
                {revealedAll && filterEntry}
                {revealedAll && importEntry}
              </ul>
            )}
          </>
        ) : (
          <>
            {taskContainingNotes.length > 0 && (
              <div className="border-b border-divider">
                <div className="px-4 pt-3 pb-1 text-[11px] uppercase tracking-wide font-semibold text-pn-muted">
                  {tr('tasksList.itemsWithTasks')}
                </div>
                <ul>{taskNoteItems(false)}</ul>
              </div>
            )}
            {/* The heading names the groups under it, so it stays away when
                there are none and the pane's own empty line stands alone. */}
            {taskGroups.length > 0 && (
              <div className="px-4 pt-3 pb-1 text-[11px] uppercase tracking-wide font-semibold text-pn-muted">
                {tr('tasksList.allTasks')}
              </div>
            )}
            {aggregatedTasksSection}

        {/* One entry for both list shapes, at the end of whatever the
            pane just drew. The grid puts its own tile inside the grid. */}
        {/* Held back until the slice covers the whole list, so an entry is
            never drawn mid-list and then pushed down by the next slice. */}
        {(searchEntry || (revealedAll && (filterEntry || importEntry))) && (
          <ul>{searchEntry}{revealedAll && filterEntry}{revealedAll && importEntry}</ul>
        )}
          </>
        )}
      </div>
    </>
  );
}

type TaskActions = Pick<TasksListProps, 'onToggleTask' | 'onOpenTaskSource'>;

const TaskLine = memo(function TaskLine({ task: t, actions }: {
  task: TaskItem;
  actions: React.RefObject<TaskActions>;
}) {
  const { t: tr } = useTranslation('shell');
  return (
    <li
      className="pn-lazy-row group flex items-start gap-2.5 px-4 py-1.5 hover:bg-surface-1/60 transition"
    >
      <TaskCheckbox
        checked={t.checked}
        onChange={(event) => void actions.current.onToggleTask(t, event.target.checked)}
        aria-label={t.checked ? tr('tasksList.markIncomplete') : tr('tasksList.markComplete')}
        className="mt-0.5"
      />
      <ClampedTaskText
        text={t.text}
        checked={t.checked}
        onClick={() => void actions.current.onOpenTaskSource(t)}
      />
    </li>
  );
});

/* ── Clamped task text with See more / See less ──────────────── */

/** Only visible text participates in layout reads, including on resize. */
const clampMeasures = new Set<() => void>();
const clampTargets = new Map<Element, () => void>();
const runClampMeasures = () => clampMeasures.forEach((m) => m());
let clampObserver: IntersectionObserver | null = null;
function watchClamp(el: Element, measure: () => void): () => void {
  if (clampTargets.size === 0) window.addEventListener('resize', runClampMeasures);
  clampTargets.set(el, measure);
  if (typeof IntersectionObserver === 'undefined') {
    clampMeasures.add(measure);
    measure();
  } else {
    clampObserver ??= new IntersectionObserver((entries) => {
      for (const entry of entries) {
        const read = clampTargets.get(entry.target);
        if (!read) continue;
        if (entry.isIntersecting) { clampMeasures.add(read); read(); }
        else clampMeasures.delete(read);
      }
    });
    clampObserver.observe(el);
  }
  return () => {
    clampMeasures.delete(measure);
    clampTargets.delete(el);
    clampObserver?.unobserve(el);
    if (!clampTargets.size) {
      window.removeEventListener('resize', runClampMeasures);
      clampObserver?.disconnect();
      clampObserver = null;
    }
  };
}

function ClampedTaskText({ text, checked, onClick }: {
  text: string;
  checked: boolean;
  onClick: () => void;
}) {
  const { t: tr } = useTranslation('shell');
  const textRef = useRef<HTMLSpanElement>(null);
  const [clamped, setClamped] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const plainText = useMemo(() => stripToPlainText(text), [text]);

  // Detect whether the text overflows the clamp.
  const measure = useCallback(() => {
    const el = textRef.current;
    if (!el || expanded) return;
    setClamped(el.scrollHeight > el.clientHeight + 1);
  }, [expanded]);

  useEffect(() => {
    const el = textRef.current;
    if (el) return watchClamp(el, measure);
  }, [measure, text]);

  // Reset expansion when text changes (e.g. task toggled).
  useEffect(() => setExpanded(false), [text]);

  return (
    <span className="flex-1 min-w-0">
      <button
        onClick={onClick}
        className={`w-full text-start text-[15px] leading-snug ${
          checked
            ? 'text-pn-muted line-through'
            : 'text-pn'
        }`}
        aria-label={tr('tasksList.openSourceNote')}
      >
        <span
          ref={textRef}
          className={expanded ? '' : 'line-clamp-2'}
          dir="auto"
        >
          {text ? plainText : <span className="text-pn-muted italic">{tr('tasksList.empty')}</span>}
        </span>
      </button>
      {clamped && !expanded && (
        <button
          type="button"
          onClick={(e) => { e.stopPropagation(); setExpanded(true); }}
          className="text-[12px] text-accent hover:underline mt-0.5"
        >
          {tr('tasksList.seeMore')}
        </button>
      )}
      {expanded && (
        <button
          type="button"
          onClick={(e) => { e.stopPropagation(); setExpanded(false); }}
          className="text-[12px] text-accent hover:underline mt-0.5"
        >
          {tr('tasksList.seeLess')}
        </button>
      )}
    </span>
  );
}
