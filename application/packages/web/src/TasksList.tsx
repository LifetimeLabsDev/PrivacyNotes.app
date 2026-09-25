import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { LocalNote } from './db';
import type { ListPrefs, ListPrefsStore } from './listPrefs';
import type { UserSettings } from './userSettings';
import { selectTaskNotes, type TaskItem } from './tasks';
import NoteRow from './NoteRow';
import NoteCard from './NoteCard';
import { compareNotes, stripToPlainText } from './notesViewUtils';
import type { ContextMenuItem } from './ContextMenu';
import { HoverLabel } from './HoverLabel';
import { SelectionToolbar } from './SelectionToolbar';
import { suppressShiftTextSelection } from './useMultiSelect';
import { ListSearchInput } from './ListSearchInput';
import { ActiveFilterEntry, ActiveSearchEntry, FilteredEmpty, ListFilterChips } from './ListFilterChips';
import { ListPrefsPopover } from './ListPrefsPopover';
import { Check, CheckSquare, CheckFat, NotePencil, Eye, EyeSlash, Plus, PushPin, FunnelSimple, PILLAR_GLYPHS, NEW_GLYPHS } from './icons';
import { newButtonOpts } from './i18nExempt';
import type { View } from './views';
import { ListNav } from './notesView/ListNav';
import { ImportPromptEntry, useImportPrompt } from './ImportPrompt';
import { textMatcher } from './textMatch';
import { isImeComposing } from './imeComposing';

export interface TasksListProps {
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
  onOpenDrawer: () => void;
  onClearFolder: () => void;
  onClearTag: () => void;
  listPrefs: ListPrefs;
  /** Full prefs store + writer, for the sort/view popover. */
  listPrefsStore: ListPrefsStore;
  onListPrefsChange: (next: ListPrefsStore) => void;
  /** Global layout: narrow rows ('list') or full-width tiles ('grid'). */
  viewMode: 'list' | 'grid';
  tasksView: UserSettings['tasksView'];
  showDoneTasks: boolean;
  search: string;
  setSearch: (v: string) => void;
  taskDraft: string;
  taskInputRef: React.RefObject<HTMLInputElement | null>;
  searchInputRef?: React.RefObject<HTMLInputElement | null>;
  mobileTabIndex: number | undefined;
  hotkeyLabel: string;
  isNoteLocked: (n: LocalNote) => boolean;
  onTasksViewChange: (v: UserSettings['tasksView']) => void;
  onSetShowDoneTasks: (updater: boolean | ((v: boolean) => boolean)) => void;
  onSetTaskDraft: (v: string) => void;
  onToggleTask: (task: TaskItem, checked: boolean) => void;
  onOpenTaskSource: (task: TaskItem) => void;
  onAddQuickTask: (text: string) => void;
  onNew: () => void;
  /** Open the import modal - the standing import entry at the end of the list. */
  onOpenImport: () => void;
  onSelectNote: (id: string) => void;
  onContextMenu: (e: React.MouseEvent, items: ContextMenuItem[]) => void;
  buildNoteMenu: (n: LocalNote) => ContextMenuItem[];

  // Multi-select
  selectionMode: boolean;
  selectedIds: Set<string>;
  selectionAllStarred: boolean;
  onRowClick: (e: React.MouseEvent, id: string) => void;
  onToggleSelected: (id: string) => void;
  onRangeSelect: (id: string) => void;
  onLongPressStart: (id: string) => void;
  onLongPressEnd: () => void;
  onClearSelection: () => void;
  onSelectAllVisible: () => void;
  onBulkFavorite: () => void;
  onBulkTag: (tag: string) => void;
  onBulkMoveToFolder: () => void;
  foldersUnlocked: boolean;
  onBulkExport: () => void;
  onBulkTrash: () => void;
  allTags?: [string, number][];
}

const HYBRID_COLLAPSED_COUNT = 3;

export default function TasksList({
  allTasks,
  activeNotes,
  selectedId,
  activeFolderName,
  onSelectView,
  hiddenViews,
  onOpenDrawer,
  onClearFolder,
  onClearTag,
  activeTag,
  listPrefs,
  listPrefsStore,
  onListPrefsChange,
  viewMode,
  tasksView,
  showDoneTasks,
  search,
  setSearch,
  taskDraft,
  taskInputRef,
  searchInputRef,
  mobileTabIndex,
  hotkeyLabel,
  isNoteLocked,
  onTasksViewChange,
  onSetShowDoneTasks,
  onSetTaskDraft,
  onToggleTask,
  onOpenTaskSource,
  onAddQuickTask,
  onNew,
  onOpenImport,
  onSelectNote,
  onContextMenu,
  buildNoteMenu,
  selectionMode,
  selectedIds,
  selectionAllStarred,
  onRowClick,
  onToggleSelected,
  onRangeSelect,
  onLongPressStart,
  onLongPressEnd,
  onClearSelection,
  onSelectAllVisible,
  onBulkFavorite,
  onBulkTag,
  onBulkMoveToFolder,
  foldersUnlocked,
  onBulkExport,
  onBulkTrash,
  allTags,
}: TasksListProps) {
  const { t: tr } = useTranslation('shell');
  const [tasksHybridExpanded, setTasksHybridExpanded] = useState(false);
  const [showListPrefs, setShowListPrefs] = useState(false);
  const listPrefsButtonRef = useRef<HTMLButtonElement | null>(null);

  /** ID of the note row that was right-clicked - highlighted while context menu is open. */
  const [contextTargetId, setContextTargetId] = useState<string | null>(null);
  useEffect(() => {
    if (!contextTargetId) return;
    const clear = () => setContextTargetId(null);
    window.addEventListener('click', clear, true);
    return () => window.removeEventListener('click', clear, true);
  }, [contextTargetId]);

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
      { noteId: string; noteTitle: string; updatedAt: string; tasks: TaskItem[] }
    >();
    const openTasks = allTasks.filter((t) => {
      const n = notesById.get(t.noteId);
      return n !== undefined && !isNoteLocked(n);
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
        if (t.updatedAt > g.updatedAt) g.updatedAt = t.updatedAt;
      } else {
        groups.set(t.noteId, {
          noteId: t.noteId,
          noteTitle: t.noteTitle,
          updatedAt: t.updatedAt,
          tasks: [t],
        });
      }
    }
    return [...groups.values()].sort((a, b) => {
      const na = notesById.get(a.noteId);
      const nb = notesById.get(b.noteId);
      if (na && nb) return compareNotes(na, nb, listPrefs);
      return a.updatedAt < b.updatedAt ? 1 : -1;
    });
  }, [allTasks, showDoneTasks, search, notesById, listPrefs, isNoteLocked]);

  // Notes that belong in the Tasks pillar. Shared with NotesView, which
  // needs the identical list for multi-select - see selectTaskNotes.
  const taskContainingNotes = useMemo(
    () => selectTaskNotes(activeNotes, allTasks, search, listPrefs, isNoteLocked),
    [activeNotes, allTasks, search, listPrefs, isNoteLocked]
  );

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

  const ItemComp = viewMode === 'grid' ? NoteCard : NoteRow;

  /* The standing import entry, shared with the other pillars
     (ImportPrompt.tsx owns the rules and the storage keys). Tasks live inside
     notes, so the count that decides whether the offer has had its chance is
     the notes that hold them, which is exactly what this pane lists. */
  const importPrompt = useImportPrompt('tasks', {
    count: taskContainingNotes.length,
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
      isMultiSelected={selectedIds.has(n.id)}
      onToggleSelect={(e) => {
        if (e.shiftKey) onRangeSelect(n.id);
        else onToggleSelected(n.id);
      }}
      showTypeIcons
      sortAwareDate
    />
  );

  const aggregatedTasksSection = (
    <>
      {taskGroups.length === 0 && (filteredEmpty ?? (
        <div className="p-6 text-[13px] text-neutral-500 dark:text-neutral-600 text-center">
          {search.trim()
            ? tr('tasksList.noMatches')
            : showDoneTasks
              ? tr('tasksList.noTasksYet')
              : tr('tasksList.noOpenTasks')}
        </div>
      ))}
      {taskGroups.map((g) => {
        const groupActive = selectedId === g.noteId;
        return (
        <div
          key={g.noteId}
          className={`border-b border-neutral-200/50 dark:border-divider/50 ${
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
                updatedAt: g.updatedAt,
              })
            }
            className={`w-full flex items-center gap-1.5 text-start px-4 pt-3 pb-1 text-[11px] uppercase tracking-wide font-semibold transition ${
              groupActive
                ? 'text-accent dark:text-accent'
                : 'text-neutral-500 dark:text-neutral-500 hover:text-accent dark:hover:text-accent'
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
            {g.tasks.map((t) => (
              <li
                key={`${t.noteId}:${t.lineIdx}`}
                className="pn-lazy-row group flex items-start gap-2.5 px-4 py-1.5 hover:bg-surface-1/60 transition"
              >
                <button
                  onClick={() => void onToggleTask(t, !t.checked)}
                  aria-label={t.checked ? tr('tasksList.markIncomplete') : tr('tasksList.markComplete')}
                  className={`mt-0.5 shrink-0 w-[18px] h-[18px] rounded border flex items-center justify-center transition ${
                    t.checked
                      ? 'bg-accent border-accent text-white'
                      : 'border-neutral-400 dark:border-neutral-600 hover:border-accent'
                  }`}
                >
                  {t.checked && (
                    <Check size={12} />
                  )}
                </button>
                <ClampedTaskText
                  text={t.text}
                  checked={t.checked}
                  onClick={() => void onOpenTaskSource(t)}
                />
              </li>
            ))}
          </ul>
        </div>
        );
      })}
    </>
  );

  const hybridTopNotes = tasksHybridExpanded
    ? taskContainingNotes
    : taskContainingNotes.slice(0, HYBRID_COLLAPSED_COUNT);
  const hybridCanExpand =
    taskContainingNotes.length > HYBRID_COLLAPSED_COUNT;

  return (
    <>
      {/* Row 1 -- title + count + New button (replaced by SelectionToolbar when selecting) */}
      {selectionMode && selectedIds.size > 0 ? (
        <SelectionToolbar
          mode="normal"
          allStarred={selectionAllStarred}
          onClear={onClearSelection}
          onFavorite={onBulkFavorite}
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
      <div className="shrink-0 h-14 px-4 border-b border-neutral-200 dark:border-divider flex items-center justify-between gap-3">
        <ListNav
          hiddenViews={hiddenViews}
          view="tasks"
          onSelectView={onSelectView}
          onOpenDrawer={onOpenDrawer}
          title={tr('tasksList.title')}
          icon={<PILLAR_GLYPHS.tasks size={26} className="text-accent shrink-0" aria-hidden="true" />}
        />
        <HoverLabel label={tr('tasksList.newTaskNoteWithHotkey', { hotkey: hotkeyLabel })} position="above">
        <button
          onClick={() => void onNew()}
          aria-label={tr('tasksList.newTaskNote')}
          className="shrink-0 inline-flex items-center gap-1.5 rounded-md bg-accent/10 hover:bg-accent/20 text-accent font-semibold px-3 py-1.5 text-lg tracking-tight transition"
        >
          <NEW_GLYPHS.task size={18} />
          {tr('tasksList.new', newButtonOpts())}
        </button>
        </HoverLabel>
      </div>
      )}

      {/* Folder filter chip - same shared chip the notes list renders. */}
      <ListFilterChips
        folderName={activeFolderName}
        tag={activeTag}
        onClearFolder={onClearFolder}
        onClearTag={onClearTag}
      />

      {/* Row 2 -- layout pills. Hidden in grid mode - the tabs don't change the tile grid. */}
      {viewMode !== 'grid' && (
      <div className="shrink-0 px-3 pt-2 pb-1 flex gap-1.5 border-b border-neutral-200 dark:border-divider">
        {(['hybrid', 'aggregated', 'list'] as const).map((v) => {
          const active = tasksView === v;
          const label =
            v === 'hybrid' ? tr('tasksList.viewHybrid') : v === 'aggregated' ? tr('tasksList.viewAggregated') : tr('tasksList.viewList');
          return (
            <button
              key={v}
              type="button"
              onClick={() => onTasksViewChange(v)}
              aria-pressed={active}
              className={`text-xs px-2.5 py-1 rounded-full transition font-medium ${
                active
                  ? 'bg-accent text-white'
                  : 'bg-surface-1 text-neutral-600 dark:text-neutral-400 hover:bg-neutral-200 dark:hover:bg-surface-2'
              }`}
            >
              {label}
            </button>
          );
        })}
      </div>
      )}

      {/* Row 3 -- show/hide done + sort/view prefs + search */}
      <div className="shrink-0 p-3 border-b border-neutral-200 dark:border-divider relative">
        <div className="flex items-stretch gap-2">
          <HoverLabel label={showDoneTasks ? tr('tasksList.hideCompleted') : tr('tasksList.showCompleted')} position="above">
          <button
            type="button"
            onClick={() => onSetShowDoneTasks((v) => !v)}
            aria-label={showDoneTasks ? tr('tasksList.hideCompleted') : tr('tasksList.showCompleted')}
            aria-pressed={showDoneTasks}
            className={`shrink-0 inline-flex items-center justify-center w-10 h-10 rounded-md border transition ${
              showDoneTasks
                ? 'bg-accent/10 border-accent text-accent'
                : 'bg-surface-2 border-divider text-neutral-600 hover:border-accent hover:text-accent dark:text-neutral-300'
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
                ? 'bg-accent/10 border-accent text-accent'
                : 'bg-surface-2 border-divider text-neutral-600 hover:border-accent hover:text-accent dark:text-neutral-300'
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
          />
        )}
      </div>

      {/* Row 4 -- Quick-add */}
      <div className="shrink-0 p-3 border-b border-neutral-200 dark:border-divider">
        <div className="flex items-center gap-2 rounded-md bg-surface-2 border border-divider px-3 py-2 focus-within:border-accent">
          <Plus size={16} className="text-neutral-400 shrink-0" />
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
            className="flex-1 bg-transparent text-[15px] focus:outline-none placeholder:text-neutral-400 dark:placeholder:text-neutral-600"
          />
        </div>
      </div>

      {/* Content -- switches on tasksView */}
      <div className="flex-1 overflow-y-auto" onMouseDown={suppressShiftTextSelection}>
        {viewMode === 'grid' ? (
          <>
            {taskContainingNotes.length === 0 && (filteredEmpty ?? (
              <div className="p-6 text-[13px] text-neutral-500 dark:text-neutral-600 text-center">
                {search.trim() ? tr('tasksList.noMatches') : tr('tasksList.noNotesWithTasks')}
              </div>
            ))}
            {(taskContainingNotes.length > 0 || importEntry || searchEntry || filterEntry) && (
              <ul className="grid gap-3 p-4" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))' }}>
                {taskContainingNotes.map(renderTaskNoteRow)}
                {searchEntry}
                {filterEntry}
                {importEntry}
              </ul>
            )}
          </>
        ) : (
          <>
        {tasksView === 'list' && (
          <>
            {taskContainingNotes.length === 0 ? (filteredEmpty ?? (
              <div className="p-6 text-[13px] text-neutral-500 dark:text-neutral-600 text-center">
                {search.trim()
                  ? tr('tasksList.noMatches')
                  : tr('tasksList.noNotesWithTasks')}
              </div>
            )) : (
              <ul>{taskContainingNotes.map(renderTaskNoteRow)}</ul>
            )}
          </>
        )}

        {tasksView === 'hybrid' && (
          <>
            {taskContainingNotes.length > 0 && (
              <div className="border-b border-neutral-200 dark:border-divider">
                <div className="px-4 pt-3 pb-1 text-[11px] uppercase tracking-wide font-semibold text-neutral-500 dark:text-neutral-500">
                  {tr('tasksList.recentNotesWithTasks')}
                </div>
                <ul>{hybridTopNotes.map(renderTaskNoteRow)}</ul>
                {hybridCanExpand && (
                  <button
                    type="button"
                    onClick={() => setTasksHybridExpanded((v) => !v)}
                    className="w-full text-center px-4 py-2 text-[13px] font-medium text-accent hover:bg-accent/5 transition border-t border-neutral-200/50 dark:border-divider/50"
                  >
                    {tasksHybridExpanded
                      ? tr('tasksList.showLess')
                      : tr('tasksList.loadMore', { count: taskContainingNotes.length - HYBRID_COLLAPSED_COUNT })}
                  </button>
                )}
              </div>
            )}
            <div className="px-4 pt-3 pb-1 text-[11px] uppercase tracking-wide font-semibold text-neutral-500 dark:text-neutral-500">
              {tr('tasksList.tasksByNote')}
            </div>
            {aggregatedTasksSection}
          </>
        )}

        {tasksView === 'aggregated' && aggregatedTasksSection}

        {/* One entry for all three list shapes, at the end of whatever the
            pane just drew. The grid puts its own tile inside the grid. */}
        {(searchEntry || filterEntry || importEntry) && <ul>{searchEntry}{filterEntry}{importEntry}</ul>}
          </>
        )}
      </div>
    </>
  );
}

/* ── Clamped task text with See more / See less ──────────────── */

const CLAMP_LINES = 2;

function ClampedTaskText({ text, checked, onClick }: {
  text: string;
  checked: boolean;
  onClick: () => void;
}) {
  const { t: tr } = useTranslation('shell');
  const textRef = useRef<HTMLSpanElement>(null);
  const [clamped, setClamped] = useState(false);
  const [expanded, setExpanded] = useState(false);

  // Detect whether the text overflows the clamp.
  const measure = useCallback(() => {
    const el = textRef.current;
    if (!el) return;
    setClamped(el.scrollHeight > el.clientHeight + 1);
  }, []);

  useEffect(() => {
    measure();
    // Re-measure on resize (font size, container width changes).
    window.addEventListener('resize', measure);
    return () => window.removeEventListener('resize', measure);
  }, [measure, text]);

  // Reset expansion when text changes (e.g. task toggled).
  useEffect(() => setExpanded(false), [text]);

  return (
    <span className="flex-1 min-w-0">
      <button
        onClick={onClick}
        className={`w-full text-start text-[15px] leading-snug ${
          checked
            ? 'text-neutral-400 dark:text-neutral-600 line-through'
            : 'text-neutral-800 dark:text-neutral-200'
        }`}
        aria-label={tr('tasksList.openSourceNote')}
      >
        <span
          ref={textRef}
          className={expanded ? '' : 'line-clamp-2'}
          dir="auto"
        >
          {text ? stripToPlainText(text) : <span className="text-neutral-400 italic">{tr('tasksList.empty')}</span>}
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
