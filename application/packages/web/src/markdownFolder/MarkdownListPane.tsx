/**
 * The list column: the open folder's files, or the entry state.
 *
 * Owns its chrome rather than reusing the encrypted sidebar, which is the
 * load-bearing decision from the design session - isolation by construction,
 * not scoping by discipline. Nothing reachable from here can read or write the
 * encrypted store, so no later change can leak content across the boundary by
 * forgetting a filter.
 *
 * Spec: ops/docs/plans/markdown-folder.md (note-links never cross the boundary; a title must not leak)
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ListNav } from '../notesView/ListNav';
import { ListSearchInput } from '../ListSearchInput';
import { ListPrefsPopover } from '../ListPrefsPopover';
import NoteRow from '../NoteRow';
import NoteCard from '../NoteCard';
import { formatBytes } from '../formatBytes';
import { useProgressiveReveal } from '../useProgressiveReveal';
import { compareNotes } from '../notesViewUtils';
import { HoverLabel } from '../HoverLabel';
import { X, CheckSquare, FileMd, FileTxt, Folder, NotePencil, Question, Trash, FunnelSimple, Lock, Copy, ArrowsClockwise, NEW_GLYPHS, PILLAR_GLYPHS } from '../icons';
import type { ListPrefs, ListPrefsStore } from '../listPrefs';
import type { View } from '../views';
import type { ContextMenuItem } from '../ContextMenu';
import { markdownSupport } from './capability';
import { MarkdownDefaultAppPopover } from './MarkdownDefaultApp';
import { useMarkdownDefaultApp } from './defaultApp';
import { forgetFolder, rememberFolder } from './folderMemory';
import { adaptFile, entryToNote, isSupportedFile, isTextFile } from './adapter';
import {
  FileExistsError,
  hasRealPath,
  pickDirectory,
  pickFile,
  type DirectoryEntry,
  type OpenedFileRef,
} from './fileAccess';
import type { FileMeta } from './useTagIndex';
import { MarkdownEmptyState } from './MarkdownEmptyState';
import type { OpenedMarkdownDir, OpenedMarkdownFile } from './types';

export function MarkdownListPane({
  onSelectView,
  hiddenViews,
  onOpenDrawer,
  dir,
  onDir,
  dirFilter,
  tagFilter,
  tagsByPath,
  tagsScanned,
  listPrefs,
  listPrefsStore,
  onListPrefsChange,
  opened,
  onOpened,
  viewMode,
  onExplain,
  reopenName,
  onReopen,
  onContextMenu,
  onImportToNotes,
  onRequestDelete,
  onImportManyToNotes,
  onRequestDeleteMany,
}: {
  onSelectView: (next: View) => void;
  /** Passed straight to ListNav; see userSettings.hiddenViews. */
  hiddenViews?: import('../views').View[] | undefined;
  onOpenDrawer: () => void;
  dir: OpenedMarkdownDir | null;
  onDir: (next: OpenedMarkdownDir | null) => void;
  /** Rail selections. Both narrow the list; the rail owns the state because it
   *  renders in a different part of the shell. */
  dirFilter: string | null;
  tagFilter: string | null;
  tagsByPath: Map<string, FileMeta>;
  /** False while the background tag pass is still reading files, which is the
   *  difference between "no files have this tag" and "not read yet". */
  tagsScanned: boolean;
  /** The shell's resolved list preferences, so this list honours the same
   *  preview/date/tags toggles as every other one. */
  listPrefs: ListPrefs;
  /** The prefs store behind the sort popover - the same one every other list
   *  writes to, so sorting is a single app-wide setting rather than a
   *  per-pillar one the user has to discover twice. */
  listPrefsStore: ListPrefsStore;
  onListPrefsChange: (next: ListPrefsStore) => void;
  opened: OpenedMarkdownFile | null;
  onOpened: (file: OpenedMarkdownFile | null) => void;
  /** List or grid, from the shell's one setting - the pillar does not get its
   *  own toggle. Grid swaps `NoteRow` for `NoteCard`, which is the same swap
   *  `NotesList` makes; both take `NoteRowProps`, so nothing else changes. */
  viewMode: 'list' | 'grid';
  /** Open the reference card behind the `?`. Owned by the shell because the
   *  modal is the shell's to render. Spec: ops/docs/plans/markdown-folder.md (12) */
  onExplain: () => void;
  /** A remembered folder awaiting the click that re-grants its permission. */
  reopenName: string | null;
  onReopen: () => void;
  /** Opens the app's context menu at the pointer. */
  onContextMenu: (e: React.MouseEvent, items: ContextMenuItem[]) => void;
  /** The file's NAME and its RAW text. Deliberately not a title and a body:
   *  the conversion belongs to the importer, so a file saved from here becomes
   *  the same note as the same file dropped on the app. */
  onImportToNotes: (filename: string, raw: string) => void;
  onRequestDelete: (file: OpenedMarkdownFile) => void;
  /** Bulk verbs, taking relative paths. Both resolve their contents here rather
   *  than in the shell, which never learns what a folder entry is. */
  onImportManyToNotes: (paths: string[]) => Promise<void>;
  onRequestDeleteMany: (paths: string[]) => void;
}) {
  const { t } = useTranslation('shell');
  const support = markdownSupport();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [filter, setFilter] = useState('');
  const reveal = useProgressiveReveal();
  const gridMode = viewMode === 'grid';
  /** The same swap `NotesList` makes. Both components take `NoteRowProps`, so
   *  every handler, the selection gestures and the MD icon override carry over
   *  unchanged - there is no second row component to keep in sync. */
  const ItemComponent = gridMode ? NoteCard : NoteRow;
  const [showListPrefs, setShowListPrefs] = useState(false);
  const [showDefaultApp, setShowDefaultApp] = useState(false);
  /**
   * Read here as well as inside the popover, because the toolbar button's own
   * presence IS the state: it is green while the association is not ours and
   * absent once it is, which in grid mode with nothing open is the only thing on
   * screen that says so. One shared fetch backs both - see `defaultApp.ts`.
   */
  const defaultApp = useMarkdownDefaultApp();
  /**
   * Multi-select, mirrored rather than reused.
   *
   * `useMultiSelect` is wired to the encrypted store - notesRepo writes, sync,
   * the blob stores and the PIN gate - so calling it here would hand this pillar
   * a route into exactly the data it must not reach. The gestures are copied
   * (click to toggle, shift for a range, long-press to enter) so the list feels
   * identical; only the state is local and only paths go in it.
   */
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [selectionMode, setSelectionMode] = useState(false);
  const lastPickedRef = useRef<string | null>(null);
  const longPressRef = useRef<number | null>(null);
  const listPrefsButtonRef = useRef<HTMLButtonElement | null>(null);
  const defaultAppButtonRef = useRef<HTMLButtonElement | null>(null);

  async function openRef(ref: OpenedFileRef) {
    const raw = await ref.read();
    onOpened({ ref, raw, stamp: await ref.stamp(), adapted: adaptFile(ref.name, raw), reloadToken: 0 });
  }

  async function handleOpenFile() {
    setError(null);
    try {
      const ref = await pickFile();
      if (!ref) return; // cancelled - not an error
      // The picker's filter is a hint, not a gate: every OS picker offers an
      // "all files" escape, so check what actually came back before reading it.
      if (!isSupportedFile(ref.name)) {
        setError(t('markdown.unsupportedFile'));
        return;
      }
      await openRef(ref);
    } catch {
      setError(t('markdown.openFailed'));
    }
  }

  /**
   * Straight to the OS picker, with no explainer modal in front of it: the
   * only caller is the button UNDER `MarkdownPitch`, which the empty state
   * renders, so a modal here would answer a question by showing the reader
   * the screen they are already looking at. The plaintext facts land before
   * the picker anyway - "Outside our vault / No sync, encryption or backup"
   * sits two inches above the button - and the full card is one click away
   * on the `?`.
   * Spec: ops/docs/plans/markdown-folder.md (section 12)
   */
  async function handleOpenFolder() {
    setError(null);
    setBusy(true);
    try {
      const ref = await pickDirectory();
      if (!ref) return;
      if (ref.remember) void rememberFolder(ref.remember);
      onDir({ ref, entries: await ref.scan() });
      onOpened(null);
      setFilter('');
      reveal.reset();
    } catch {
      setError(t('markdown.openFailed'));
    } finally {
      setBusy(false);
    }
  }

  /** Create a new note in the folder, in whichever subfolder is selected. */
  async function handleNew() {
    if (!dir) return;
    setError(null);
    setBusy(true);
    const base = dirFilter ?? '';
    // `Untitled.md`, then `Untitled 2.md`, matching how the rest of the app and
    // every file manager number a duplicate.
    const freeName = (entries: DirectoryEntry[]) => {
      const taken = new Set(entries.map((e) => e.relPath));
      let name = 'Untitled.md';
      for (let i = 2; taken.has(`${base}${name}`); i++) name = `Untitled ${i}.md`;
      return `${base}${name}`;
    };
    try {
      let entries = dir.entries;
      try {
        const ref = await dir.ref.createFile(freeName(entries), '');
        onDir({ ref: dir.ref, entries: await dir.ref.scan() });
        await openRef(ref);
        return;
      } catch (err) {
        if (!(err instanceof FileExistsError)) throw err;
        // `dir.entries` is a snapshot from the last scan, so a file created in
        // Finder since then is invisible to `freeName` and `createFile` refuses
        // rather than truncating it. Rescan and take the next free name once.
        entries = await dir.ref.scan();
        onDir({ ref: dir.ref, entries });
      }
      const ref = await dir.ref.createFile(freeName(entries), '');
      onDir({ ref: dir.ref, entries: await dir.ref.scan() });
      await openRef(ref);
    } catch {
      setError(t('markdown.createFailed'));
    } finally {
      setBusy(false);
    }
  }

  /**
   * Rescan, held open for one full turn of the spinner.
   *
   * A 94-file folder scans in single-digit milliseconds, so `busy` flipped back
   * before React painted a single frame of the spin and the button read as
   * broken - nothing moved, and a scan that found no changes leaves the list
   * looking identical, so there was no second signal either. The floor is the
   * feedback: 600ms is one rotation, long enough to register as "it ran" and
   * short enough not to feel like waiting. It runs CONCURRENTLY with the scan,
   * so a genuinely slow folder is not delayed by it.
   */
  async function handleRescan() {
    if (!dir) return;
    setError(null);
    setBusy(true);
    try {
      const [entries] = await Promise.all([
        dir.ref.scan(),
        new Promise((resolve) => setTimeout(resolve, 600)),
      ]);
      onDir({ ref: dir.ref, entries });
    } catch {
      setError(t('markdown.openFailed'));
    } finally {
      setBusy(false);
    }
  }

  /**
   * Right-click menu for a file row.
   *
   * Without this the event bubbles to the shell's fallback menu, which offers
   * New Login, Zen Mode and Sign Out over a Markdown file - every entry wrong
   * for the thing under the cursor. Select leads, exactly as it does in the
   * encrypted row menu, and is the discoverable route into multi-select for
   * anyone who never guesses the Cmd/Ctrl-click. The rest is deliberately only
   * the verbs that exist and work on both platforms: path-based actions
   * (reveal in folder, copy path) cannot exist on the web at all, because the
   * File System Access API withholds the path by design, so they belong with
   * the desktop build rather than as rows that vanish depending on where you
   * are.
   */
  function rowMenu(entry: DirectoryEntry): ContextMenuItem[] {
    const path = entry.ref.location;
    const isSelected = selected.has(entry.relPath);
    // Path-based rows exist only where a path does. On the web the File System
    // Access API withholds it by design, so these are absent rather than
    // present-and-broken.
    // Copy path is the only row here, and the other two are absent by design.
    // The desktop capability file carries no opener path grant (`opener:default`
    // covers `openUrl` and nothing else), so "Reveal in folder" would be
    // ACL-denied, and "Open in default app" is self-referential once this app
    // can BE the default `.md` handler - it asks the OS to open the file, the
    // OS hands it straight back, and the user sees nothing happen. Do not add
    // either without a grant and a reason.
    const pathItems: ContextMenuItem[] = hasRealPath() ? [
      {
        label: t('markdown.copyPath'),
        icon: <Copy size={14} />,
        onSelect: () => void navigator.clipboard.writeText(path),
      },
      { type: 'separator' },
    ] : [];

    return [
      {
        label: isSelected ? t('contextMenu.deselect') : t('contextMenu.select'),
        icon: <CheckSquare size={14} />,
        onSelect: () => toggleSelected(entry.relPath),
      },
      { type: 'separator' },
      ...pathItems,
      {
        label: t('markdown.saveToNotes'),
        icon: <Lock size={14} />,
        onSelect: () => {
          void (async () => {
            const raw = await entry.ref.read();
            onImportToNotes(entry.ref.name, raw);
          })();
        },
      },
      { type: 'separator' },
      {
        label: t('markdown.delete'),
        icon: <Trash size={14} />,
        destructive: true,
        onSelect: () => {
          void (async () => {
            const raw = await entry.ref.read();
            onRequestDelete({
              ref: entry.ref,
              raw,
              stamp: await entry.ref.stamp(),
              adapted: adaptFile(entry.ref.name, raw),
              reloadToken: 0,
            });
          })();
        },
      },
    ];
  }

  function exitSelection() {
    setSelectionMode(false);
    setSelected(new Set());
    lastPickedRef.current = null;
  }

  /** Drop selected paths that no longer exist after a rescan.
   *
   *  A bulk delete finishes as a new `entries` array with those rows gone. Left
   *  alone, the selection keeps naming files that are not there, so the chip
   *  reads "3 of 82 selected" with nothing highlighted and the verbs act on
   *  paths that would fail. Emptying the set also exits selection mode, which
   *  is the same rule `toggleSelected` follows when the last row is dropped. */
  useEffect(() => {
    if (!dir) return;
    const live = new Set(dir.entries.map((e) => e.relPath));
    setSelected((prev) => {
      const next = new Set([...prev].filter((p) => live.has(p)));
      if (next.size === prev.size) return prev;
      if (next.size === 0) {
        setSelectionMode(false);
        lastPickedRef.current = null;
      }
      return next;
    });
  }, [dir]);

  /** Toggle one path. Selection mode follows the set - on the moment anything
   *  is picked, off again when the last one is dropped - so deselecting the
   *  final row leaves the list rather than stranding it in checkbox mode with
   *  nothing selected. Same rule as `useMultiSelect`. */
  function toggleSelected(relPath: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(relPath)) next.delete(relPath); else next.add(relPath);
      setSelectionMode(next.size > 0);
      return next;
    });
    lastPickedRef.current = relPath;
  }

  /** Shift-click selects everything between the last pick and this one, over
   *  the CURRENT order - which is what the user can see, and changes with the
   *  sort and the filter. */
  function rangeSelect(relPath: string) {
    const anchor = lastPickedRef.current;
    if (!anchor) { toggleSelected(relPath); return; }
    const order = matches.map((m) => m.entry.relPath);
    const from = order.indexOf(anchor);
    const to = order.indexOf(relPath);
    if (from < 0 || to < 0) { toggleSelected(relPath); return; }
    const span = order.slice(Math.min(from, to), Math.max(from, to) + 1);
    setSelectionMode(true);
    setSelected((prev) => new Set([...prev, ...span]));
    lastPickedRef.current = relPath;
  }

  function beginLongPress(relPath: string) {
    longPressRef.current = window.setTimeout(() => toggleSelected(relPath), 500);
  }
  function cancelLongPress() {
    if (longPressRef.current) { window.clearTimeout(longPressRef.current); longPressRef.current = null; }
  }

  /**
   * Escape leaves selection mode, the same way it does in the encrypted list -
   * whose Escape lives in `useKeyboardShortcuts`, alongside a cascade this
   * pillar has no entry in, so it carries its own listener instead. Bubble
   * phase on purpose: `useEscapeToClose` runs in the capture phase and stops
   * the event, so an open modal or popover keeps Escape for itself and this
   * never fires underneath one.
   */
  useEffect(() => {
    if (!selectionMode) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') exitSelection();
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [selectionMode]);

  /**
   * A different folder, or a different rail filter, drops the selection - the
   * reset `useMultiSelect` runs on a view or tag change, for its reason: bulk
   * verbs aimed at files you can no longer see are a trap. Switching pillars
   * needs no handling here, because the shell renders this pane only for the
   * markdown view and unmounts it with the state inside. Keyed on the folder's
   * location rather than the `dir` object, since a rescan hands back a new
   * object for the same folder and must not wipe a selection mid-assembly.
   */
  useEffect(() => {
    if (selectionMode) exitSelection();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dir?.ref.location, dirFilter, tagFilter]);

  /**
   * Drop paths whose file is gone. The usual case is the bulk delete that just
   * ran: the shell trashes the files, rescans, and hands back a folder without
   * them, but the set here would keep every dead path - so the strip goes on
   * counting files that no longer exist and never empties. Same guard the
   * encrypted list grew for #184. Keyed on the entries and not on the filters,
   * because a file hidden by a filter has not left the folder.
   */
  useEffect(() => {
    if (selected.size === 0) return;
    const alive = new Set((dir?.entries ?? []).map((e) => e.relPath));
    const kept = [...selected].filter((p) => alive.has(p));
    if (kept.length === selected.size) return;
    setSelected(new Set(kept));
    setSelectionMode(kept.length > 0);
    if (lastPickedRef.current !== null && !alive.has(lastPickedRef.current)) lastPickedRef.current = null;
  }, [dir, selected]);

  /** Bytes on disk, formatted, once the background pass has read the file. */
  const sizeOf = (entry: DirectoryEntry) => {
    const bytes = tagsByPath.get(entry.relPath)?.size;
    return bytes != null ? formatBytes(bytes) : null;
  };

  // Filters on path, not contents. Reading every file to search inside them is
  // a whole index and belongs with one, not with a keystroke handler.
  const matches = useMemo(() => {
    if (!dir) return [];
    const q = filter.trim().toLowerCase();
    const filtered = dir.entries.filter((e) => {
      // A folder selection includes everything beneath it, which is what
      // clicking a folder means to anyone who has used a file manager.
      if (dirFilter !== null && !e.dir.startsWith(dirFilter)) return false;
      if (tagFilter !== null && !(tagsByPath.get(e.relPath)?.tags ?? []).includes(tagFilter)) return false;
      if (q && !e.relPath.toLowerCase().includes(q)) return false;
      return true;
    });

    /* Sorted through `compareNotes`, the app's single comparator, rather than a
     * hand-rolled one. Its own doc says every list goes through it and that
     * per-pillar sorting is how the Tasks pillar silently stopped honouring
     * pins (#194) - this list was repeating that mistake.
     *
     * One override: `compareNotes` measures size as `body.length`, and our body
     * is a 300-char excerpt, so bytes come from the background read instead.
     * A file the pass has not reached yet has no size at all - not a size of
     * zero - so it sorts last in BOTH directions, outside the direction flip.
     * Folding it into the comparison as a number would park every unread file
     * at one end and then march it across the list as the index fills. */
    const rows = filtered.map((entry) => ({
      entry,
      note: entryToNote(entry.relPath, tagsByPath.get(entry.relPath)),
    }));
    const dirMul = listPrefs.sortDir === 'asc' ? 1 : -1;
    rows.sort((a, b) => {
      if (listPrefs.sortField === 'size') {
        const av = tagsByPath.get(a.entry.relPath)?.size;
        const bv = tagsByPath.get(b.entry.relPath)?.size;
        if (av == null || bv == null) {
          if (av != null) return -1;
          if (bv != null) return 1;
        } else if (av !== bv) {
          return (av - bv) * dirMul;
        }
      }
      return compareNotes(a.note, b.note, listPrefs);
    });
    return rows;
  }, [dir, filter, dirFilter, tagFilter, tagsByPath, listPrefs.sortField, listPrefs.sortDir]);

  /**
   * Open the first file when a folder is opened, matching every other pillar.
   *
   * This lives here rather than beside the shell's auto-select effect because
   * only this component knows what "first" means: the row order is the filter,
   * the rail's folder and tag scopes, and `compareNotes` applied to `matches`.
   *
   * Two of the shell effect's three guards are copied deliberately - below the
   * md breakpoint the list and pane are mutually exclusive, so punching straight
   * into an editor would hide the list the user just asked for, and in grid mode
   * the grid IS the surface (its pane is `hidden` anyway, so opening a file there
   * would change nothing on screen and everything about the state).
   *
   * The third guard is NOT copied, on purpose. The shell effect re-selects
   * whenever the selection leaves the visible list, which for this pillar would
   * mean the open file switching under the cursor as someone types in the filter
   * box - in a pane that writes to disk. So this fires once per folder, tracked
   * by path: close a file and it stays closed, switch folders and the new one
   * opens its first file.
   */
  const autoOpenedFolderRef = useRef<string | null>(null);
  useEffect(() => {
    if (!dir) {
      // Closing the folder re-arms it, so reopening the same one auto-opens again.
      autoOpenedFolderRef.current = null;
      return;
    }
    if (gridMode || opened) return;
    if (autoOpenedFolderRef.current === dir.ref.location) return;
    // `matches` is empty for one render while a background tag pass populates a
    // sort key, so an empty list is "not yet", never "nothing to open".
    const first = matches[0];
    if (!first) return;
    if (typeof window !== 'undefined' && !window.matchMedia('(min-width: 768px)').matches) return;
    autoOpenedFolderRef.current = dir.ref.location;
    void openRef(first.entry.ref).catch(() => setError(t('markdown.openFailed')));
    // `openRef` and `t` are recreated every render; the guard above is what makes
    // this run once, not the dependency list.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dir, gridMode, opened, matches]);

  return (
    <div className="flex flex-col h-full min-h-0 bg-surface-1">
      {/* Byte-for-byte the title row `NotesList` uses, so this pillar's header
          is the same control rather than a lookalike. */}
      <div className="shrink-0 h-14 px-4 border-b border-divider flex items-center justify-between gap-3">
        <ListNav
          hiddenViews={hiddenViews}
          view="markdown"
          onSelectView={onSelectView}
          onOpenDrawer={onOpenDrawer}
          icon={<PILLAR_GLYPHS.markdown size={26} className="text-accent shrink-0" aria-hidden="true" />}
          title={t('markdown.title')}
        />
        <div className="shrink-0 flex items-center gap-1.5">
          {dir && (
            <button
              type="button"
              onClick={() => void handleNew()}
              className="inline-flex items-center gap-1.5 rounded-md bg-accent/10 hover:bg-accent/20 text-accent font-semibold px-3 py-1.5 text-lg tracking-tight transition cursor-pointer"
            >
              <NEW_GLYPHS.note size={18} />
              {t('markdown.new')}
            </button>
          )}
        </div>
      </div>

      {dir && (
        <div className="shrink-0 border-b border-divider px-3 py-2">
          {/* The folder is a BUTTON, not a caption: clicking it opens the
              picker again, which is the verb people reach for right after
              reading which folder this is. Rescan and Close sit beside it
              because they act on the same object, and all three are chrome
              rather than text - the old row of accent-blue links was the only
              text-link affordance in this column and read as a footnote under
              the search box.
              `flex-wrap` is what makes it safe on a deep desktop path: the
              Unencrypted chip drops to its own line rather than squeezing the
              path down to nothing. */}
          <div className="relative flex items-center flex-wrap gap-2 mb-2">
            <HoverLabel label={t('markdown.selectFolder')} position="below" className="min-w-0">
              <button
                type="button"
                onClick={() => void handleOpenFolder()}
                className="inline-flex items-center gap-2 h-8 min-w-0 max-w-full rounded-md border border-divider bg-surface-2 px-2 hover:border-accent transition cursor-pointer"
              >
                {/* Amber, the same `text-amber-600/80 dark:text-amber-500/80` the
                    rail gives its folder glyphs - the app's "this is on your own
                    disk" colour. Accent blue here made it read as a control. */}
                <Folder size={16} className="text-amber-600/90 dark:text-amber-500/90 shrink-0" />
                {/* Full-strength text at 13px: which folder is open is the
                    load-bearing fact of this whole pillar - it is what every
                    edit writes into - and at 12px it was the smallest thing in
                    the header. A deep path still truncates from the end. */}
                <span className="font-mono text-[13px] font-medium text-pn truncate">
                  {dir.ref.location}
                </span>
                {/* Bare number: "files" is already the word above it, and the
                    count has to survive beside a path in a 320px column. The
                    spelled-out version stays for screen readers, which cannot
                    infer the noun from the layout. */}
                <span aria-hidden="true" className="shrink-0 text-[11.5px] text-pn-muted tabular-nums">
                  {matches.length}
                </span>
                <span className="sr-only">{t('markdown.fileCount', { count: matches.length })}</span>
              </button>
            </HoverLabel>
            <HoverLabel label={t('markdown.rescanFolder')} position="below">
              <button
                type="button"
                onClick={() => void handleRescan()}
                disabled={busy}
                aria-label={t('markdown.rescanFolder')}
                className="group inline-flex items-center justify-center w-8 h-8 rounded-md border border-divider bg-surface-2 text-pn-muted hover:border-accent hover:text-accent disabled:opacity-50 transition cursor-pointer"
              >
                {/* Two animations, two jobs. Half a turn on hover says the icon
                    is a live control before anything is clicked, which an inert
                    glyph in a bordered box does not. The continuous spin is the
                    progress report while the scan runs, replacing the old label
                    that swapped to "Scanning…" - see `handleRescan` for why it
                    is held to one full rotation.
                    They are exclusive on purpose: `animate-spin` drives
                    `transform` and `rotate-180` drives the `rotate` property, so
                    both at once compose into a stutter. */}
                <ArrowsClockwise
                  size={16}
                  className={busy ? 'animate-spin' : 'transition-transform duration-300 group-hover:rotate-180'}
                />
              </button>
            </HoverLabel>
            {/* Close is not just a way back to the empty state: it is the only
                thing that calls `forgetFolder`, so without it there is no way
                to stop the app reopening this folder on the next launch. */}
            <HoverLabel label={t('markdown.closeFolder')} position="below">
              <button
                type="button"
                onClick={() => { void forgetFolder(); onDir(null); onOpened(null); }}
                aria-label={t('markdown.closeFolder')}
                className="inline-flex items-center justify-center w-8 h-8 rounded-md border border-divider bg-surface-2 text-pn-muted hover:border-accent hover:text-accent transition cursor-pointer"
              >
                <X size={16} />
              </button>
            </HoverLabel>
            {/* Grows on a line that fits, so the chip sits at the end; on a
                wrapped line it is simply the last thing before the break. */}
            <span className="flex-1" />
            {/* Which app the OS opens .md files with. Present only in the desktop
                app (`defaultApp` is null everywhere else, where there is no OS
                association to read), and the ONLY home this control has in grid
                mode: the file pane that carries the big card is hidden outright
                there, so without this button grid users could never reach it.
                AFTER the spacer, beside the `?`, rather than beside Close. Two
                reasons, and they agree. Rescan and Close act on the open folder;
                this and the `?` are both about the feature, so grouping them
                matches what they do. And it is the arrangement that survives a
                narrow column: this button is what tips the row past its wrap
                threshold at around 360px, and grouped at the end the two of them
                wrap together as a pair instead of stranding this one at the start
                of the second line with the `?` alone at its end.
                Icon square rather than a labelled button, even though grid mode
                has room for a label: a control that grows a word at one width and
                loses it at another is exactly what made the old Unencrypted chip
                wrap.
                GONE once we own the association, and green until then. That is the
                inverse of the first build, and the inverse is right: green here
                means "there is something to do", so it draws the eye to an offer
                rather than decorating a finished state. Once the association is
                ours there is nothing left to do in this popover, and the fact is
                still stated in the resting pane's card and in the `?` explainer -
                so the button retires instead of sitting there permanently green.
                `below-end` and not `below`: a centred tip on the second-to-last
                control in the row collided with the `?`'s own tip beside it. Same
                position as that one, for the same reason it has it.
                Spec: ops/docs/plans/markdown-folder.md (section 11) */}
            {defaultApp && defaultApp.owner !== 'ours' && (
              <HoverLabel label={t('markdown.assocTitle')} position="below-end" className="shrink-0">
                <button
                  ref={defaultAppButtonRef}
                  type="button"
                  onClick={() => setShowDefaultApp((v) => !v)}
                  aria-label={t('markdown.assocTitle')}
                  aria-expanded={showDefaultApp}
                  className={`inline-flex items-center justify-center w-8 h-8 rounded-md border transition cursor-pointer ${
                    showDefaultApp
                      ? 'bg-accent/10 border-accent text-accent'
                      : 'bg-surface-2 border-green-600/50 dark:border-green-500/50 text-green-600 dark:text-green-500 hover:border-green-600 dark:hover:border-green-500 hover:bg-green-600/5'
                  }`}
                >
                  <FileMd size={16} />
                </button>
              </HoverLabel>
            )}
            {showDefaultApp && (
              // End-aligned to the row, which is the one choice that is right in
              // both view modes, and the reason is worth keeping: the trigger sits
              // at the END of this row. In grid mode the row is the full window
              // width, so `start-0` (what `ListPrefsPopover` uses one row below,
              // where its trigger is at the start) opened the panel hundreds of
              // pixels away from the button that opened it. In list mode the
              // popover's own `max-w-full` clamps it to the column, at which point
              // start and end alignment are the same box - so end-aligned costs
              // nothing there and fixes grid.
              <MarkdownDefaultAppPopover
                onClose={() => setShowDefaultApp(false)}
                anchorRef={defaultAppButtonRef}
                className="absolute end-0 top-full mt-1"
              />
            )}
            {/* This button is the explainer's ONLY entry point, so it cannot be
                dropped without leaving the explainer unreachable.
                Icon-only, and the same 32px square as Rescan and Close beside
                it: the amber "Unencrypted" chip it replaces was the one thing
                in this row whose width grew with the translation, so on a long
                path in a narrow column it was the piece that wrapped. A `?`
                cannot outgrow its box in any locale. The word itself is not
                lost - it is the sidebar rail's own tip (`nav.markdownTip`), and
                the explainer one click away spells it out in full.
                `below-end` and not `below`: this is the last thing on the row,
                so a centred tip would hang off the end of the column. The tip's
                end edge pins to the button's and it opens back across the row,
                which also mirrors correctly under RTL. */}
            <HoverLabel label={t('markdown.localFolder')} position="below-end" className="shrink-0">
              <button
                type="button"
                onClick={() => onExplain()}
                aria-label={t('markdown.localFolder')}
                className="inline-flex items-center justify-center w-8 h-8 rounded-md border border-divider bg-surface-2 text-accent hover:border-accent transition cursor-pointer"
              >
                <Question size={16} weight="fill" />
              </button>
            </HoverLabel>
          </div>
          {/* Same search row as `NotesList`: the sort / list-prefs button sits
              beside the input at the same height so the two read as one row.
              Copied rather than re-styled, so this list keeps the app's
              controls instead of growing its own. */}
          <div className="flex items-stretch gap-2 relative">
            <HoverLabel label={t('notes:search.sortOptions')} position="above-start">
              <button
                ref={listPrefsButtonRef}
                type="button"
                onClick={() => setShowListPrefs((v) => !v)}
                aria-label={t('notes:search.sortOptions')}
                aria-expanded={showListPrefs}
                className={`shrink-0 inline-flex items-center justify-center w-10 h-10 rounded-md border transition ${
                  showListPrefs
                    ? 'bg-accent/10 border-accent text-accent'
                    : 'bg-surface-2 border-divider text-pn-muted hover:border-accent hover:text-accent'
                }`}
              >
                <FunnelSimple size={18} />
              </button>
            </HoverLabel>
            <ListSearchInput
              value={filter}
              onChange={(v) => { setFilter(v); reveal.reset(); }}
              placeholder={t('markdown.searchFolder')}
            />
            {showListPrefs && (
              <ListPrefsPopover
                store={listPrefsStore}
                onChange={onListPrefsChange}
                onClose={() => setShowListPrefs(false)}
                anchorRef={listPrefsButtonRef}
                className="absolute start-0 top-full mt-1 z-20"
              />
            )}
          </div>
          {/* Where a failed New or Rescan surfaces. The empty state carries the
              same red line, but it is off screen once a folder is open, so
              until this existed those two actions failed in silence. Both
              clear it before they try again, so it never outlives the attempt
              it describes. */}
          {error && <p className="mt-1.5 text-[12px] text-red-600 dark:text-red-400">{error}</p>}
        </div>
      )}

      {/* Selection strip - same placement and treatment as `NotesList`'s, below
          the search row so the h-14 title row stays narrow-sidebar friendly.
          It does NOT match what `NotesList` puts in it, though: there the strip
          holds only the count and select-all, because the title row above it is
          swapped out for `SelectionToolbar` and the verbs live there. This list
          keeps its title row and carries the verbs in the strip instead, for
          two reasons. There are only two of them - the encrypted list's
          favourite, tag, folder and export have no meaning for a file on disk -
          so a whole replacement toolbar would be a large control for a small
          job. And the title row is where New and the pillar switcher are, which
          stay worth reaching mid-selection. The X is the toolbar's Clear. */}
      {selectionMode && selected.size > 0 && (
        <div className="shrink-0 px-4 py-2 border-b border-divider bg-accent/5 dark:bg-accent/10 flex items-center justify-between gap-2 text-[13px]">
          <span className="font-medium text-neutral-700 dark:text-neutral-200 tabular-nums">
            {t('markdown.selectedCount', { selected: selected.size, total: matches.length })}
          </span>
          <div className="flex items-center gap-3 shrink-0">
            <button
              type="button"
              onClick={() => setSelected(new Set(matches.map((m) => m.entry.relPath)))}
              className="font-semibold text-accent hover:underline"
            >
              {t('markdown.selectAll')}
            </button>
            <button
              type="button"
              onClick={() => { const paths = [...selected]; exitSelection(); void onImportManyToNotes(paths); }}
              className="font-semibold text-accent hover:underline"
            >
              {t('markdown.saveToNotes')}
            </button>
            <button
              type="button"
              // No `exitSelection()` here: this only OPENS a confirm modal, and
              // clearing the selection now would throw it away on cancel. The
              // prune effect drops the rows once the delete actually lands.
              onClick={() => onRequestDeleteMany([...selected])}
              className="font-semibold text-red-600 dark:text-red-400 hover:underline"
            >
              {t('markdown.delete')}
            </button>
            <button
              type="button"
              onClick={exitSelection}
              aria-label={t('markdown.exitSelection')}
              className="text-neutral-500 hover:text-accent dark:text-neutral-400"
            >
              <X size={14} />
            </button>
          </div>
        </div>
      )}
      <div
        className="flex-1 min-h-0 overflow-y-auto"
        onScroll={(e) => {
          reveal.onScroll(e.currentTarget, matches.length);
        }}
      >
        {dir ? (
          matches.length === 0 ? (
            <p className="p-4 text-[13px] text-neutral-500 dark:text-neutral-400 text-center">
              {/* A tag filter with the index still running is "not read yet",
                  not "nothing matches" - saying the latter would be wrong for
                  as long as the pass takes on a large vault. */}
              {tagFilter !== null && !tagsScanned
                ? t('markdown.scanning')
                : filter.trim() || dirFilter !== null || tagFilter !== null
                  ? t('markdown.noMatches')
                  : t('markdown.folderEmpty')}
            </p>
          ) : (
            <ul className={gridMode ? 'grid content-start gap-3 p-4 pn-notes-grid' : ''}>
              {matches.slice(0, reveal.visible).map(({ entry, note }) => (
                <ItemComponent
                  key={entry.relPath}
                  note={note}
                  isOpen={opened?.ref.location === entry.ref.location}
                  // Preview and date come from the background read, so they are
                  // suppressed until it finishes rather than rendering a blank
                  // line and an empty date for every unread file.
                  listPrefs={{ ...listPrefs, showPreview: listPrefs.showPreview && tagsScanned, showDate: listPrefs.showDate && tagsScanned }}
                  isNoteLocked={false}
                  // The routing `useMultiSelect.handleRowClick` does, mirrored:
                  // shift extends the range once a selection exists, Cmd/Ctrl
                  // toggles and is the mouse's way INTO selection mode (the
                  // long-press below is touch-only, so without this the bulk
                  // verbs were unreachable on a desktop), and a plain click
                  // opens the file.
                  onClick={(e) => {
                    if (e.shiftKey && selectionMode) {
                      e.preventDefault();
                      rangeSelect(entry.relPath);
                      return;
                    }
                    if (e.metaKey || e.ctrlKey || selectionMode) {
                      e.preventDefault();
                      toggleSelected(entry.relPath);
                      return;
                    }
                    void openRef(entry.ref);
                  }}
                  selectionMode={selectionMode}
                  isMultiSelected={selected.has(entry.relPath)}
                  onToggleSelect={(e) => {
                    if (e.shiftKey) rangeSelect(entry.relPath); else toggleSelected(entry.relPath);
                  }}
                  onTouchStart={() => beginLongPress(entry.relPath)}
                  onTouchEnd={cancelLongPress}
                  onTouchMove={cancelLongPress}
                  onTouchCancel={cancelLongPress}
                  showTypeIcons
                  sizeLabel={sizeOf(entry) ?? undefined}
                  onContextMenu={(e) => { e.stopPropagation(); onContextMenu(e, rowMenu(entry)); }}
                  iconOverride={
                    // The glyph reports the extension, because that is the one
                    // thing about a row the filename stem does not say: we strip
                    // it to make the title, so `notes.md` and `notes.txt` are two
                    // identical rows without this. Same square either way - it is
                    // the same pillar, not a second kind of file.
                    <span className="shrink-0 w-7 h-7 rounded-lg bg-accent/10 flex items-center justify-center text-accent">
                      {isTextFile(entry.ref.name) ? <FileTxt size={18} /> : <FileMd size={18} />}
                    </span>
                  }
                  // Same choice for the mini tile, which draws a bare glyph
                  // instead of the boxed icon above - see `glyphOverride`.
                  glyphOverride={isTextFile(entry.ref.name) ? FileTxt : FileMd}
                />
              ))}
            </ul>
          )
        ) : opened ? (
          <SingleFileCard opened={opened} onClose={() => onOpened(null)} onOpenFile={() => void handleOpenFile()} />
        ) : (
          <MarkdownEmptyState
            support={support}
            error={error}
            busy={busy}
            reopenName={reopenName}
            onReopen={onReopen}
            onOpenFile={() => void handleOpenFile()}
            onOpenFolder={() => void handleOpenFolder()}
          />
        )}
      </div>
    </div>
  );
}

function SingleFileCard({
  opened,
  onClose,
  onOpenFile,
}: {
  opened: OpenedMarkdownFile;
  onClose: () => void;
  onOpenFile: () => void;
}) {
  const { t } = useTranslation('shell');
  return (
    <div className="p-3">
      <div className="rounded-lg border border-divider bg-surface-2 p-3">
        <div className="flex items-center gap-2 mb-1">
          {/* Same extension rule as the folder rows above - a lone file is
              still a file, and this card is the only place its type is shown. */}
          {isTextFile(opened.ref.name)
            ? <FileTxt size={14} className="text-accent shrink-0" />
            : <FileMd size={14} className="text-accent shrink-0" />}
          <span className="text-[13px] font-medium truncate">{opened.adapted.title}</span>
        </div>
        <p className="font-mono text-[11px] text-neutral-500 dark:text-neutral-400 truncate mb-2">
          {opened.ref.location}
        </p>
        {opened.adapted.tags.length > 0 && (
          <div className="flex flex-wrap gap-1 mb-2">
            {opened.adapted.tags.map((tag) => (
              <span key={tag} className="text-[10px] px-1.5 py-0.5 rounded-full border border-divider text-neutral-500 dark:text-neutral-400">
                #{tag}
              </span>
            ))}
          </div>
        )}
        <div className="flex items-center gap-3">
          <button type="button" onClick={onOpenFile} className="text-[12px] text-accent hover:underline">
            {t('markdown.openFile')}
          </button>
          <button type="button" onClick={onClose} className="text-[12px] text-accent hover:underline">
            {t('markdown.close')}
          </button>
        </div>
      </div>
    </div>
  );
}

/** The wide pane: the opened file's text, editable, saved straight to disk. */
