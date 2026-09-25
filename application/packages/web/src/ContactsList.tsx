import { useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { LocalNote } from './db';
import type { ListPrefs, ListPrefsStore } from './listPrefs';
import type { View } from './views';
import NoteRow from './NoteRow';
import NoteCard from './NoteCard';
import { ListNav } from './notesView/ListNav';
import { ListSearchInput } from './ListSearchInput';
import { ListPrefsPopover } from './ListPrefsPopover';
import { ActiveFilterEntry, ActiveSearchEntry, FilteredEmpty, ListFilterChips } from './ListFilterChips';
import { SelectionToolbar } from './SelectionToolbar';
import { SelectionCountStrip } from './SelectionCountStrip';
import { HoverLabel } from './HoverLabel';
import { ImportPromptEntry, useImportPrompt } from './ImportPrompt';
import { FunnelSimple, Download, PILLAR_GLYPHS, NEW_GLYPHS } from './icons';

/**
 * The Contacts pillar list COLUMN - the vault anatomy, one step simpler
 * than Bookmarks: a normal-width list whose selected row opens in the
 * STANDARD editor pane (the shared note header + ContactItem as the body).
 * A row click selects, the way a vault row does; there is no quick-add bar,
 * because a contact is a form rather than a line, and no derived rows.
 * Rows are the shared NoteRow, which draws the round initials chip for a
 * contact itself, so the prefs toggles and the sort rule are the same code
 * the rest of the app runs.
 * Spec: ops/docs/plans/contacts-pillar.md (section 4) + contacts-mockups.html
 */
export function ContactsList({
  contacts,
  isNoteLocked,
  listPrefs,
  listPrefsStore,
  onListPrefsChange,
  onSelectView,
  hiddenViews,
  onOpenDrawer,
  search,
  setSearch,
  searchInputRef,
  activeFolderName,
  onClearFolder,
  onClearTag,
  activeTag,
  mobileTabIndex,
  onRequestNew,
  selectedId,
  onRowContextMenu,
  onOpenImport,
  selectionMode,
  selectedIds,
  selectionAllStarred,
  onRowClick,
  onToggleSelected,
  onRangeSelect,
  onLongPressStart,
  onLongPressEnd,
  onClearSelection,
  onDeselectAll,
  onSelectAllVisible,
  onBulkFavorite,
  onBulkTag,
  onBulkMoveToFolder,
  onBulkExport,
  onBulkTrash,
  foldersUnlocked,
  allTags,
  viewMode,
}: {
  /** Active (non-trashed) contact notes, already folder/tag scoped and
   *  searched by the owner (NotesView's displayNotes). */
  contacts: LocalNote[];
  /** The view's lock predicate: a gated contact's row keeps its name and
   *  draws no photo and no number. */
  isNoteLocked: (n: LocalNote) => boolean;
  listPrefs: ListPrefs;
  listPrefsStore: ListPrefsStore;
  onListPrefsChange: (next: ListPrefsStore) => void;
  onSelectView: (v: View) => void;
  hiddenViews?: View[] | undefined;
  onOpenDrawer: () => void;
  /** The app's ONE search string, shared with every other pillar list.
   *  Never a private copy: Cmd+K and Escape act on this one. */
  search: string;
  setSearch: (v: string) => void;
  searchInputRef: React.RefObject<HTMLInputElement | null>;
  activeFolderName: string | null;
  onClearFolder: () => void;
  activeTag: string | null;
  onClearTag: () => void;
  mobileTabIndex: number | undefined;
  /** New: create an empty contact and select it into the editor, which
   *  opens in edit mode because the body is empty. */
  onRequestNew: () => void;
  selectedId: string | null;
  onRowContextMenu: (note: LocalNote, e: React.MouseEvent) => void;
  onOpenImport: () => void;
  selectionMode: boolean;
  selectedIds: Set<string>;
  selectionAllStarred: boolean;
  onRowClick: (e: React.MouseEvent, id: string) => void;
  onToggleSelected: (id: string) => void;
  onRangeSelect: (id: string) => void;
  onLongPressStart: (id: string) => void;
  onLongPressEnd: () => void;
  onClearSelection: () => void;
  onDeselectAll: () => void;
  onSelectAllVisible: () => void;
  onBulkFavorite: () => void;
  onBulkTag: (tag: string) => void;
  onBulkMoveToFolder: () => void;
  onBulkExport: () => void;
  onBulkTrash: () => void;
  foldersUnlocked: boolean;
  allTags: [string, number][];
  /** List rows or the shared NoteCard grid - the vault's exact pair. */
  viewMode: 'list' | 'grid';
}) {
  const { t } = useTranslation('shell');
  const [sortOpen, setSortOpen] = useState(false);
  const sortBtnRef = useRef<HTMLButtonElement | null>(null);
  const [contextTargetId, setContextTargetId] = useState<string | null>(null);

  const q = search.trim().toLowerCase();
  const empty = contacts.length === 0 && !q;
  const filteredAway =
    contacts.length === 0 && !q && (activeFolderName !== null || activeTag !== null);

  const importPrompt = useImportPrompt('contacts', {
    count: contacts.length,
    suppressed: selectionMode || !!q || activeFolderName !== null || activeTag !== null,
  });

  const showSearchEntry = !!q && contacts.length === 0 && !selectionMode;
  const showFilterEntry =
    !selectionMode &&
    (activeFolderName !== null || activeTag !== null) &&
    (showSearchEntry || contacts.length > 0);

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* ── Title row (SelectionToolbar swaps in, same h-14 border) ── */}
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
      <div className="shrink-0 h-14 px-4 border-b border-divider flex items-center justify-between gap-3">
        <ListNav
          hiddenViews={hiddenViews}
          view="contacts"
          onSelectView={onSelectView}
          onOpenDrawer={onOpenDrawer}
          title={t('pillars.contacts')}
          icon={<PILLAR_GLYPHS.contacts size={26} className="text-accent shrink-0" aria-hidden="true" />}
        />
        <button
          type="button"
          onClick={onRequestNew}
          tabIndex={mobileTabIndex}
          className="shrink-0 inline-flex items-center gap-1.5 rounded-md bg-accent/10 hover:bg-accent/20 text-accent font-semibold px-3 py-1.5 text-lg tracking-tight transition"
        >
          <NEW_GLYPHS.contact size={18} />
          {t('contacts.new')}
        </button>
      </div>
      )}

      <ListFilterChips
        folderName={activeFolderName}
        tag={activeTag}
        onClearFolder={onClearFolder}
        onClearTag={onClearTag}
      />

      {/* ── Search row + sort button - matches the other lists ───── */}
      <div className="shrink-0 p-3 border-b border-divider relative">
        <div className="flex items-stretch gap-2">
          <HoverLabel label={t('contacts.sortOptions')} position="above-start">
            <button
              ref={sortBtnRef}
              type="button"
              onClick={() => setSortOpen((v) => !v)}
              tabIndex={mobileTabIndex}
              aria-label={t('contacts.sortOptions')}
              aria-expanded={sortOpen}
              className={`shrink-0 inline-flex items-center justify-center w-10 h-10 rounded-md border transition ${
                sortOpen
                  ? 'bg-accent/10 border-accent text-accent'
                  : 'bg-surface-2 border-divider text-neutral-600 hover:border-accent hover:text-accent dark:text-neutral-300'
              }`}
            >
              <FunnelSimple size={18} />
            </button>
          </HoverLabel>
          <ListSearchInput
            inputRef={searchInputRef}
            tabIndex={mobileTabIndex}
            value={search}
            onChange={setSearch}
            placeholder={t('contacts.searchPlaceholder')}
          />
        </div>
        {sortOpen && (
          <ListPrefsPopover
            store={listPrefsStore}
            onChange={onListPrefsChange}
            onClose={() => setSortOpen(false)}
            anchorRef={sortBtnRef}
            className="absolute start-3 top-full mt-1"
            pillar="contacts"
          />
        )}
      </div>

      {selectionMode && selectedIds.size > 0 && (
        <SelectionCountStrip
          selectedCount={selectedIds.size}
          totalCount={contacts.length}
          onSelectAll={onSelectAllVisible}
          onDeselectAll={onDeselectAll}
        />
      )}

      {/* ── Rows - NotesList's exact list/grid pair (pn-notes-grid) ── */}
      <ul className={`flex-1 overflow-y-auto list-none m-0 p-0 ${viewMode === 'grid' ? 'grid content-start gap-3 p-4 pn-notes-grid' : ''}`}>
        {empty && !filteredAway ? (
          <li className={`flex flex-col items-center justify-center text-center px-8 py-14 ${viewMode === 'grid' ? 'col-span-full' : ''}`}>
            <PILLAR_GLYPHS.contacts size={34} className="text-neutral-400 dark:text-neutral-600" weight="duotone" aria-hidden="true" />
            <p className="text-[13px] text-neutral-500 dark:text-neutral-600 mt-3">{t('contacts.emptyNone')}</p>
            <h3 className="text-[15px] font-semibold mt-1 mb-4">{t('contacts.emptyTitle')}</h3>
            <div className="flex flex-wrap items-center justify-center gap-2">
              <button type="button" onClick={onRequestNew} className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-md bg-accent px-3.5 py-2 text-[13px] font-medium text-white transition hover:bg-accent/90">
                <NEW_GLYPHS.contact size={15} />
                {t('contacts.emptyAdd')}
              </button>
              <button type="button" onClick={onOpenImport} className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-md border border-divider bg-surface-1 px-3.5 py-2 text-[13px] transition hover:bg-neutral-200 dark:hover:bg-surface-0">
                <Download size={15} />
                {t('contacts.emptyImport')}
              </button>
            </div>
          </li>
        ) : (
          <>
            {filteredAway && (
              <li className={viewMode === 'grid' ? 'col-span-full' : ''}>
                <FilteredEmpty
                  folderName={activeFolderName}
                  tag={activeTag}
                  onClearFolder={onClearFolder}
                  onClearTag={onClearTag}
                />
              </li>
            )}
            {!filteredAway && contacts.length === 0 && (
              <li className={`p-6 text-[13px] text-neutral-500 dark:text-neutral-600 text-center ${viewMode === 'grid' ? 'col-span-full' : ''}`}>{t('contacts.noMatches')}</li>
            )}
            {contacts.map((n) => (
              viewMode === 'grid' ? (
              <NoteCard
                key={n.id}
                note={n}
                isOpen={selectedId === n.id && !selectionMode}
                listPrefs={listPrefs}
                isNoteLocked={isNoteLocked(n)}
                onClick={(e) => onRowClick(e, n.id)}
                onContextMenu={(e) => { setContextTargetId(n.id); onRowContextMenu(n, e); }}
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
              ) : (
              <NoteRow
                key={n.id}
                note={n}
                isOpen={selectedId === n.id && !selectionMode}
                listPrefs={listPrefs}
                isNoteLocked={isNoteLocked(n)}
                onClick={(e) => onRowClick(e, n.id)}
                onContextMenu={(e) => { setContextTargetId(n.id); onRowContextMenu(n, e); }}
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
              )
            ))}
            {showSearchEntry && (
              <ActiveSearchEntry
                search={search}
                onClearSearch={() => setSearch('')}
                variant={viewMode === 'grid' ? 'tile' : 'row'}
              />
            )}
            {showFilterEntry && (
              <ActiveFilterEntry
                folderName={activeFolderName}
                tag={activeTag}
                onClearFolder={onClearFolder}
                onClearTag={onClearTag}
                variant={viewMode === 'grid' ? 'tile' : 'row'}
              />
            )}
            {importPrompt.show && (
              <ImportPromptEntry
                kind="contacts"
                variant={viewMode === 'grid' ? 'tile' : 'row'}
                onOpen={onOpenImport}
                onDismiss={importPrompt.dismiss}
              />
            )}
          </>
        )}
      </ul>
    </div>
  );
}
