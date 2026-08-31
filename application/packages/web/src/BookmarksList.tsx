import { useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { LocalNote } from './db';
import { setPillarPrefs, type ListPrefs, type ListPrefsStore } from './listPrefs';
import type { View } from './views';
import NoteRow, { SiteChip, CardGlyph } from './NoteRow';
import NoteCard from './NoteCard';
import { ListNav } from './notesView/ListNav';
import { ListSearchInput } from './ListSearchInput';
import { ListPrefsPopover } from './ListPrefsPopover';
import { ActiveFilterEntry, ActiveSearchEntry, FilteredEmpty, ListFilterChips } from './ListFilterChips';
import { BookmarkRowActions } from './BookmarkRowActions';
import { SelectionToolbar } from './SelectionToolbar';
import { SelectionCountStrip } from './SelectionCountStrip';
import { HoverLabel } from './HoverLabel';
import { ImportPromptEntry, useImportPrompt } from './ImportPrompt';
import { normalizeUrl, linkDomain, linkDedupeKey, duplicateBookmarkId } from './linkBody';
import { Bookmark, Bookmarks, BookmarkSimple, FunnelSimple, Plus, Download, File, CheckSquare, Book, PILLAR_GLYPHS, NEW_GLYPHS } from './icons';

/**
 * The Bookmarks pillar list COLUMN - the vault anatomy: a normal-width
 * list whose selected row opens in the STANDARD editor pane (the shared
 * note header + BookmarkItem as the body). A plain row click opens the
 * URL; the pencil, the context menu, and the quick-add bar select into
 * the editor. Rows are the shared NoteRow, so the favicon chip, prefs
 * toggles, and sort rule are the same code the rest of the app runs.
 * Spec: ops/docs/plans/bookmarks-pillar.md + bookmarks-mockups.html
 */

export type BookmarkDraft = { url: string; name: string; tags: string[]; folderId: string | null };

/** A read-only row derived from a URL found inside a note body. */
type DerivedLink = { url: string; name: string; noteId: string; noteType: LocalNote['type'] };

/**
 * Extract http(s) URLs from a markdown body: named `[text](url)` links
 * first, then bare URLs not already captured. Trailing punctuation that
 * markdown prose glues onto a bare URL is trimmed.
 */
function extractBodyLinks(body: string): { url: string; name: string }[] {
  // Substring test before either regex. This runs over every note in the
  // account each time the pillar opens, and since the rows are ON by default
  // it runs for everyone - but a body with no `http` in it cannot hold a
  // link, and that is nearly all of them. Same guard, same reason, as the
  // `[[` test in retargetNoteLinks.
  if (!body.includes('http')) return [];
  const out: { url: string; name: string }[] = [];
  const seen = new Set<string>();
  const md = /\[([^\]]*)\]\((https?:\/\/[^\s)]+)\)/g;
  let m: RegExpExecArray | null;
  while ((m = md.exec(body)) !== null) {
    const url = m[2]!;
    if (seen.has(url)) continue;
    seen.add(url);
    out.push({ url, name: (m[1] || '').trim() });
  }
  const bare = /(?:^|[\s<])(https?:\/\/[^\s)\]}>"']+)/g;
  while ((m = bare.exec(body)) !== null) {
    const url = m[1]!.replace(/[.,;:!?]+$/, '');
    if (seen.has(url)) continue;
    seen.add(url);
    out.push({ url, name: '' });
  }
  return out;
}

export function BookmarksList({
  bookmarks,
  bookmarkKeys,
  scanNotes,
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
  onOpen,
  onOpenNote,
  onRequestAdd,
  onRequestEdit,
  editingNoteId,
  onSaveDerived,
  onTrash,
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
  focusSignal,
}: {
  /** Active (non-trashed) link notes, already folder/tag scoped by the owner. */
  bookmarks: LocalNote[];
  /** Every saved bookmark URL in the ACCOUNT (buildLinkKeyMap), not just the
   *  rows above: the quick-add guard and the derived-row dedupe both have to
   *  see the copy a search or a folder filter is hiding. */
  bookmarkKeys: Map<string, string>;
  /** Notes to scan for the derived "links from notes" rows (toggle).
   *  Folder/tag scoped by the owner, exactly like `bookmarks` above: a
   *  derived row that outlives the filter is a row from a note the user
   *  just filtered away. */
  scanNotes: LocalNote[];
  listPrefs: ListPrefs;
  listPrefsStore: ListPrefsStore;
  onListPrefsChange: (next: ListPrefsStore) => void;
  onSelectView: (v: View) => void;
  /** Passed straight to ListNav; see userSettings.hiddenViews. */
  hiddenViews?: import('./views').View[] | undefined;
  onOpenDrawer: () => void;
  /** The app's ONE search string, shared with Notes, Tasks and Files.
   *  This pane held a private one until 2026-08-22, which made the global
   *  query invisible here: it still filtered `bookmarks` upstream while this
   *  box read empty, so the sidebar counted 5 bookmarks and one row showed.
   *  It also put the pane out of reach of Cmd+K and Escape, which act on the
   *  shared string. Spec: ops/docs/plans/bookmarks-pillar.md */
  search: string;
  setSearch: (v: string) => void;
  searchInputRef: React.RefObject<HTMLInputElement | null>;
  activeFolderName: string | null;
  onClearFolder: () => void;
  /** Active tag filter - the chip beside the folder one. */
  activeTag: string | null;
  onClearTag: () => void;
  mobileTabIndex: number | undefined;
  /** Open a URL (owner routes web vs Tauri). */
  onOpen: (url: string) => void;
  /** Jump to the source note of a derived row. */
  onOpenNote: (noteId: string) => void;
  /** Enter on the bar: create the bookmark and select it into the
   *  standard editor (title focused), the vault's New Login choreography. */
  onRequestAdd: (url: string) => void;
  /** The pencil / context menu: select into the standard editor (a plain
   *  row click opens the URL instead, by design). */
  onRequestEdit: (note: LocalNote) => void;
  /** Row highlighted while it is the selected note. */
  editingNoteId: string | null;
  /** "Save as bookmark" on a derived row - saved directly, no form. */
  onSaveDerived: (draft: BookmarkDraft) => void;
  onTrash: (note: LocalNote) => void;
  onRowContextMenu: (note: LocalNote, e: React.MouseEvent) => void;
  onOpenImport: () => void;
  // Multi-select - the same machinery every list shares (useMultiSelect
  // in NotesView owns the state; SelectionToolbar swaps into the title row).
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
  /** Bump to focus the quick-add bar (the "New Bookmark" entry points). */
  focusSignal: number;
}) {
  const { t } = useTranslation('shell');
  const [sortOpen, setSortOpen] = useState(false);
  const sortBtnRef = useRef<HTMLButtonElement | null>(null);
  const [contextTargetId, setContextTargetId] = useState<string | null>(null);

  // Quick-add bar - collapsed only; the details live in the right pane.
  const quickInputRef = useRef<HTMLInputElement | null>(null);
  const [draft, setDraft] = useState('');
  const [urlError, setUrlError] = useState(false);
  const [dupWarn, setDupWarn] = useState(false);

  // Row delete: the attachment pattern - the trash icon arms into a red
  // "Delete?" pill, a second click within 3s executes.


  useEffect(() => {
    if (focusSignal > 0) quickInputRef.current?.focus();
  }, [focusSignal]);


  function submitQuickAdd() {
    const url = normalizeUrl(draft);
    if (!url) {
      setUrlError(draft.trim().length > 0);
      return;
    }
    // Duplicate guard: the same URL twice creates the trap where the user
    // later trashes "the copy" and loses the tagged, named original.
    if (duplicateBookmarkId(bookmarkKeys, url)) {
      setDupWarn(true);
      return;
    }
    setUrlError(false);
    setDraft('');
    onRequestAdd(url);
  }

  // Derived rows: URLs found inside note bodies (toggle, default off).
  // Computed locally on demand, never stored - see the spec's section 8.
  const derived = useMemo<DerivedLink[]>(() => {
    if (!listPrefs.showNoteLinks) return [];
    const rows: DerivedLink[] = [];
    const seen = new Set<string>();
    for (const n of scanNotes) {
      if (n.type === 'link' || n.type === 'file' || n.type === 'login' || n.type === 'card' || n.type === 'ssh-key') continue;
      if (n.pinProtected === 1) continue; // protected content stays out of a casual list
      for (const l of extractBodyLinks(n.body)) {
        const key = linkDedupeKey(l.url);
        if (seen.has(key) || bookmarkKeys.has(key)) continue;
        seen.add(key);
        rows.push({ url: l.url, name: l.name, noteId: n.id, noteType: n.type });
      }
    }
    return rows;
  }, [listPrefs.showNoteLinks, scanNotes, bookmarkKeys]);

  /* `bookmarks` is NotesView's `displayNotes`: already searched (the shared
     index covers the title, the address and the tags) and already sorted by
     the same `compareNotes` this pane would apply. A second pass here only
     re-sorted the hits and threw the relevance order away. The derived rows
     below are the one thing no index can hold - they are not notes - so they
     keep a local match on the query. */
  const q = search.trim().toLowerCase();

  const filteredDerived = useMemo(
    () =>
      q
        ? derived.filter(
            (d) => d.url.toLowerCase().includes(q) || d.name.toLowerCase().includes(q),
          )
        : derived,
    [derived, q],
  );

  const empty = bookmarks.length === 0 && filteredDerived.length === 0 && !q;

  /**
   * Saved bookmarks, filtered down to nothing.
   *
   * Deliberately blind to the derived "links from notes" rows: those are a
   * separate section under their own header, scanned out of note bodies, and
   * a folder full of them does not mean the folder holds a bookmark. Counting
   * them kept the hint off the pane whenever the toggle was on, which is the
   * case where the user most needs it (reported 2026-08-25).
   */
  const filteredAway =
    bookmarks.length === 0 && !q && (activeFolderName !== null || activeTag !== null);

  /* The standing import entry, shared with every other pillar that has an
     importer (ImportPrompt.tsx owns the rules and the storage key). */
  const importPrompt = useImportPrompt('bookmarks', {
    count: bookmarks.length,
    suppressed: selectionMode || !!q || activeFolderName !== null || activeTag !== null,
  });

  /* The standing "a filter is on" entry, shared with the other scoped pillars
     (ListFilterChips.tsx owns it). `filteredAway` above answers the empty
     case; this one answers the quiet one, where the pane still has rows and a
     short list reads as every bookmark there is. Rows only - with none,
     `filteredAway` or "No matches." already holds the pane. */
  /* "Clear search" is the same entry for the other thing that narrows a list,
     and it appears ONLY when the search found nothing - a search explains
     itself, an empty pane does not. The filter entry rides along there, so
     both causes are named. */
  const showSearchEntry = !!q && bookmarks.length === 0 && !selectionMode;
  const showFilterEntry =
    !selectionMode &&
    (activeFolderName !== null || activeTag !== null) &&
    (showSearchEntry || bookmarks.length > 0);

  /** The per-item pencil/delete pair - ONE builder for list rows and grid
   *  cards. Tooltip side follows the layout: list actions sit at the pane's
   *  end edge where an 'above' bubble clips against the resize strip, so
   *  they open toward the start; grid card actions sit mid-pane and open
   *  top-center. The mini grid hides every bubble via index.css. */
  /* Grid tips are START-aligned, not centred: the action row sits at the card's
     start edge, and `.pn-lazy-card`'s paint containment (content-visibility)
     clips whatever overhangs the tile - which a centred tip does by half its
     width (reported 2026-08-22, the tip read as "pen the note"). */
  const tipPos = viewMode === 'grid' ? 'above-start' as const : 'start' as const;
  const itemActions = (n: LocalNote) =>
    selectionMode ? undefined : (
      <BookmarkRowActions note={n} onEdit={onRequestEdit} onTrash={onTrash} tipPos={tipPos} />
    );

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
          view="bookmarks"
          onSelectView={onSelectView}
          onOpenDrawer={onOpenDrawer}
          title={t('pillars.bookmarks')}
          icon={<PILLAR_GLYPHS.bookmarks size={26} className="text-accent shrink-0" aria-hidden="true" />}
        />
        <button
          type="button"
          onClick={() => quickInputRef.current?.focus()}
          tabIndex={mobileTabIndex}
          className="shrink-0 inline-flex items-center gap-1.5 rounded-md bg-accent/10 hover:bg-accent/20 text-accent font-semibold px-3 py-1.5 text-lg tracking-tight transition"
        >
          <NEW_GLYPHS.bookmark size={18} />
          {t('bookmarks.new')}
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
          <HoverLabel label={t('bookmarks.sortOptions')} position="above-start">
            <button
              ref={sortBtnRef}
              type="button"
              onClick={() => setSortOpen((v) => !v)}
              tabIndex={mobileTabIndex}
              aria-label={t('bookmarks.sortOptions')}
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
            placeholder={t('bookmarks.searchPlaceholder')}
          />
        </div>
        {sortOpen && (
          <ListPrefsPopover
            store={listPrefsStore}
            onChange={onListPrefsChange}
            onClose={() => setSortOpen(false)}
            anchorRef={sortBtnRef}
            className="absolute start-3 top-full mt-1"
            pillar="bookmarks"
          />
        )}
      </div>

      {/* ── Links-from-notes toggle - the Files pillar's inline row ── */}
      <div className="shrink-0 px-4 py-2 border-b border-divider">
        <label className="flex items-center justify-between gap-2 cursor-pointer select-none">
          <span className="text-xs text-neutral-600 dark:text-neutral-400">{t('listPrefs.showNoteLinks')}</span>
          <button
            type="button"
            role="switch"
            aria-checked={listPrefs.showNoteLinks}
            onClick={() => onListPrefsChange(setPillarPrefs(listPrefsStore, 'bookmarks', { ...listPrefs, showNoteLinks: !listPrefs.showNoteLinks }))}
            className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition ${
              listPrefs.showNoteLinks ? 'bg-accent' : 'bg-neutral-300 dark:bg-neutral-700'
            }`}
          >
            <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition ${
              listPrefs.showNoteLinks ? 'translate-x-4 rtl:-translate-x-4' : 'translate-x-0.5 rtl:-translate-x-0.5'
            }`} />
          </button>
        </label>
      </div>

      {/* ── Quick-add bar (Enter opens the form pane with the URL) ── */}
      <div className="shrink-0 p-3 border-b border-divider">
        <div className={`flex items-center gap-2 rounded-md bg-surface-2 border px-3 py-2 focus-within:border-accent ${urlError || dupWarn ? (dupWarn ? 'border-amber-500' : 'border-red-500') : 'border-divider'}`}>
          <Plus size={16} className="text-neutral-400 shrink-0" />
          <input
            ref={quickInputRef}
            tabIndex={mobileTabIndex}
            value={draft}
            onChange={(e) => { setDraft(e.target.value); setUrlError(false); setDupWarn(false); }}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                submitQuickAdd();
              }
            }}
            placeholder={t('bookmarks.quickAddPlaceholder')}
            enterKeyHint="next"
            dir="ltr"
            className="flex-1 bg-transparent text-[15px] focus:outline-none placeholder:text-neutral-400 dark:placeholder:text-neutral-600"
          />
        </div>
        {urlError && (
          <div className="text-[12px] font-medium text-red-600 dark:text-red-400 mt-1 px-1">{t('bookmarks.urlInvalid')}</div>
        )}
        {dupWarn && (
          <div className="text-[12px] font-medium text-amber-600 dark:text-amber-400 mt-1 px-1">{t('bookmarks.duplicateHint')}</div>
        )}
      </div>

      {/* Selection count strip - the shared one, so this pillar and Notes
          cannot drift apart again. */}
      {selectionMode && selectedIds.size > 0 && (
        <SelectionCountStrip
          selectedCount={selectedIds.size}
          totalCount={bookmarks.length}
          onSelectAll={onSelectAllVisible}
          onDeselectAll={onDeselectAll}
        />
      )}

      {/* ── Rows - NotesList's exact list/grid pair (pn-notes-grid) ── */}
      <ul className={`flex-1 overflow-y-auto list-none m-0 p-0 ${viewMode === 'grid' ? 'grid content-start gap-3 p-4 pn-notes-grid' : ''}`}>
        {empty && !filteredAway ? (
          <li className={`flex flex-col items-center justify-center text-center px-8 py-14 ${viewMode === 'grid' ? 'col-span-full' : ''}`}>
            <BookmarkSimple size={34} className="text-neutral-400 dark:text-neutral-600" weight="duotone" aria-hidden="true" />
            {/* States the fact before it pitches, the way every other pillar
                does ("No notes yet.", "Vault is empty."). The heading under
                it is the invitation, not the status. */}
            <p className="text-[13px] text-neutral-500 dark:text-neutral-600 mt-3">{t('bookmarks.emptyNone')}</p>
            <h3 className="text-[15px] font-semibold mt-1 mb-4">{t('bookmarks.emptyTitle')}</h3>
            {/* The pane is a resizable COLUMN, so the two buttons run out of
                room long before the viewport does: they wrap onto their own
                lines instead of squeezing, and each label stays on one line
                so the wrap actually triggers. */}
            <div className="flex flex-wrap items-center justify-center gap-2">
              <button type="button" onClick={() => quickInputRef.current?.focus()} className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-md bg-accent px-3.5 py-2 text-[13px] font-medium text-white transition hover:bg-accent/90">
                <NEW_GLYPHS.bookmark size={15} />
                {t('bookmarks.emptyAdd')}
              </button>
              <button type="button" onClick={onOpenImport} className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-md border border-divider bg-surface-1 px-3.5 py-2 text-[13px] transition hover:bg-neutral-200 dark:hover:bg-surface-0">
                <Download size={15} />
                {t('bookmarks.emptyImport')}
              </button>
            </div>
          </li>
        ) : (
          <>
            {/* Sits where the bookmark rows would be, so any "links from
                notes" section keeps its place underneath. The first-run
                pitch above would tell a user who owns bookmarks to save
                their first one, which is both wrong and alarming. */}
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
            {!filteredAway && bookmarks.length === 0 && filteredDerived.length === 0 && (
              <li className={`p-6 text-[13px] text-neutral-500 dark:text-neutral-600 text-center ${viewMode === 'grid' ? 'col-span-full' : ''}`}>{t('bookmarks.noMatches')}</li>
            )}
            {bookmarks.map((n) => (
              viewMode === 'grid' ? (
              <NoteCard
                key={n.id}
                note={n}
                isOpen={editingNoteId === n.id && !selectionMode}
                listPrefs={listPrefs}
                isNoteLocked={false}
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
                trailing={itemActions(n)}
              />
              ) : (
              <NoteRow
                key={n.id}
                note={n}
                isOpen={editingNoteId === n.id && !selectionMode}
                listPrefs={listPrefs}
                isNoteLocked={false}
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
                trailing={itemActions(n)}
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
                kind="bookmarks"
                variant={viewMode === 'grid' ? 'tile' : 'row'}
                onOpen={onOpenImport}
                onDismiss={importPrompt.dismiss}
              />
            )}
            {filteredDerived.length > 0 && (
              <li className={`px-4 pt-4 pb-1 text-[10px] font-semibold tracking-wider uppercase text-neutral-500 dark:text-neutral-400 ${viewMode === 'grid' ? 'col-span-full' : ''}`}>
                {t('bookmarks.fromNotesHeading')}
              </li>
            )}
            {filteredDerived.map((d) => (
              viewMode === 'grid' ? (
              /* Derived entries wear NoteCard's exact shell in the grid so
                 the section reads as one surface; their two actions sit on
                 the card's footer row. */
              <li
                key={d.url + d.noteId}
                onClick={() => onOpen(d.url)}
                className="pn-card pn-lazy-card relative flex flex-col gap-1.5 rounded-xl border p-3 cursor-pointer transition [@media(hover:none)]:select-none border-divider bg-surface-2 hover:border-accent/50"
              >
                {/* NoteCard's exact head anatomy (icbox + glyph + titletext),
                    so the mini container query swaps chip for glyph here the
                    same way it does on real bookmark cards. */}
                <div className="pn-card-head flex items-center gap-2.5 min-w-0">
                  <span className="pn-card-icbox contents">
                    <SiteChip domain={linkDomain(d.url)} fallback="globe" />
                  </span>
                  <div className="pn-card-title min-w-0 flex-1 text-sm font-semibold truncate flex items-center gap-1.5 text-neutral-900 dark:text-white">
                    <CardGlyph type="link" domain={linkDomain(d.url)} />
                    <span className="pn-card-titletext truncate" dir="auto">{d.name || linkDomain(d.url)}</span>
                  </div>
                </div>
                <span className="pn-card-preview block text-[13px] text-neutral-500 dark:text-neutral-400 leading-snug truncate" dir="ltr">{d.url}</span>
                <span className="pn-card-actions mt-auto flex items-center gap-1 pt-1">
                  <HoverLabel label={t('bookmarks.openSourceNote')} position="above-start">
                  <button
                    type="button"
                    onClick={(e) => { e.stopPropagation(); onOpenNote(d.noteId); }}
                    aria-label={t('bookmarks.openSourceNote')}
                    className="w-7 h-7 rounded-md border border-divider bg-surface-1 inline-flex items-center justify-center transition hover:border-accent"
                  >
                    {d.noteType === 'journal' ? (
                      <Book size={14} className="text-purple-600 dark:text-purple-400" />
                    ) : d.noteType === 'task' ? (
                      <CheckSquare size={14} className="text-emerald-600 dark:text-emerald-400" />
                    ) : (
                      <File size={14} className="text-accent" />
                    )}
                  </button>
                  </HoverLabel>
                  <HoverLabel label={t('bookmarks.saveAsBookmark')} position="above-start">
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      onSaveDerived({ url: normalizeUrl(d.url) ?? d.url, name: d.name, tags: [], folderId: null });
                    }}
                    aria-label={t('bookmarks.saveAsBookmark')}
                    className="w-7 h-7 rounded-md border border-divider bg-surface-1 inline-flex items-center justify-center transition hover:border-accent"
                  >
                    {/* Filled accent, the same blue as the `.pn-ribbon` a saved
                        bookmark wears: the button says what the row will look
                        like once it is saved, and an outline glyph at 14px read
                        as one more piece of grey chrome. */}
                    <BookmarkSimple size={14} weight="fill" className="text-accent" />
                  </button>
                  </HoverLabel>
                </span>
              </li>
              ) : (
              <li key={d.url + d.noteId} className="pn-row pn-lazy-row relative flex items-center gap-2.5 px-4 py-3 border-b border-divider/50 hover:bg-neutral-200/50 dark:hover:bg-neutral-900/50 cursor-pointer" onClick={() => onOpen(d.url)}>
                <SiteChip domain={linkDomain(d.url)} tall fallback="globe" />
                <span className="min-w-0 flex-1">
                  <span className="block text-sm font-semibold truncate text-neutral-900 dark:text-white" dir="auto">{d.name || linkDomain(d.url)}</span>
                  <span className="block text-[13px] text-neutral-500 dark:text-neutral-400 truncate mt-0.5" dir="ltr">{d.url}</span>
                </span>
                <span className="pn-row-actions shrink-0 flex items-center gap-1">
                <HoverLabel label={t('bookmarks.openSourceNote')} position="start">
                  <button
                    type="button"
                    onClick={(e) => { e.stopPropagation(); onOpenNote(d.noteId); }}
                    aria-label={t('bookmarks.openSourceNote')}
                    className="shrink-0 w-7 h-7 rounded-md border border-divider bg-surface-1 inline-flex items-center justify-center transition hover:border-accent"
                  >
                    {d.noteType === 'journal' ? (
                      <Book size={14} className="text-purple-600 dark:text-purple-400" />
                    ) : d.noteType === 'task' ? (
                      <CheckSquare size={14} className="text-emerald-600 dark:text-emerald-400" />
                    ) : (
                      <File size={14} className="text-accent" />
                    )}
                  </button>
                </HoverLabel>
                <HoverLabel label={t('bookmarks.saveAsBookmark')} position="start">
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      onSaveDerived({ url: normalizeUrl(d.url) ?? d.url, name: d.name, tags: [], folderId: null });
                    }}
                    aria-label={t('bookmarks.saveAsBookmark')}
                    className="shrink-0 w-7 h-7 rounded-md border border-divider bg-surface-1 inline-flex items-center justify-center transition hover:border-accent"
                  >
                    <BookmarkSimple size={14} weight="fill" className="text-accent" />
                  </button>
                </HoverLabel>
                </span>
              </li>
              )
            ))}
          </>
        )}
      </ul>
    </div>
  );
}
