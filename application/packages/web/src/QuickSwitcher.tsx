import { cloneElement, isValidElement, useEffect, useMemo, useRef, useState, type ComponentType, type ReactElement, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type { LocalNote } from './db';
import type { FileItem } from './FilesList';
import type { DirectoryEntry } from './markdownFolder/fileAccess';
import { editedAtOf } from './notesViewUtils';
import { typeGlyph } from './NoteRow';
import i18n from './i18n';
import { intlLocale } from './languages';
import { engineWords, parseQuickAdd, readWords, type QuickAdd, type QuickAddType } from './quickAdd';
import { describeSchedule } from './scheduleText';
import { useEscapeToClose } from './useEscapeToClose';
import { isImeComposing } from './imeComposing';
import { textMatcher, type TextMatch } from './textMatch';
import { formatDay, formatRelative, toLocalIso } from './intlFormat';
import { activeLocale, ensureSettingsSearchLoaded } from './i18n';
import { ArrowSquareOut, ArrowsHorizontal, BellSimple, Briefcase, CalendarBlank, Clock, Folder, Hash, ListChecks, PencilSimple, Compass, MagnifyingGlass, Plus, Repeat, Terminal, X, type Icon, type IconProps } from './icons';
import { HoverLabel } from './HoverLabel';
import { helpPath } from './localeRoutes';
import { openExternal } from './openExternal';
import { siteHref } from './siteLinks';
import { APP_KEYS, KEY_OS, matchesKey } from './shortcutMatch';
import { COMMAND_PREFIX, GROUP_ORDER, matchEntries, type PaletteEntry, type PaletteGroup } from './commandPalette';
import type { SectionId, SettingEntry } from './settingsSearch/registry';
import { railLabels, runSettingsSearch, tabOf } from './settingsSearch/SettingsSearchResults';
import { FolderGlyph, TagGlyph } from './looks/LookGlyph';
import { normalizeTag } from './notesRepo';
import { foldText } from './textFold';

/** How many items the list shows at most. */
const LIMIT = 30;
/** How many settings show under the items at most. */
const SETTINGS_LIMIT = 10;
/** How many commands show under the items when the query has no ">". */
const COMMANDS_LIMIT = 3;
/** How many tags, and how many folders, show under the items with no prefix. */
const FILTERS_LIMIT = 3;
/** Typed first, these limit the switcher to tags or to folders. */
const TAG_PREFIX = '#';
const FOLDER_PREFIX = '/';
/** The command list's entries that type a prefix instead of running. */
const PREFIX_ENTRY = { tags: 'jump:tags', folders: 'jump:folders', newTag: 'new:tag', newFolder: 'new:folder' } as const;
const PREFIX_OF: Record<string, { prefix: string; creating: boolean }> = {
  [PREFIX_ENTRY.tags]: { prefix: TAG_PREFIX, creating: false },
  [PREFIX_ENTRY.folders]: { prefix: FOLDER_PREFIX, creating: false },
  [PREFIX_ENTRY.newTag]: { prefix: TAG_PREFIX, creating: true },
  [PREFIX_ENTRY.newFolder]: { prefix: FOLDER_PREFIX, creating: true },
};

const KEYCAP = 'inline-flex min-w-6 h-6 shrink-0 items-center justify-center rounded-md border border-b-2 border-divider bg-surface-1 px-1.5 font-sans text-[13px] font-medium leading-none text-pn';

/**
 * The icon tile's color for each kind of item, so a vault entry or a
 * bookmark reads apart from a note before its title does: the type's own
 * color from `typeGlyph`, the one table of type colors, on a tint of itself.
 */
function toneOf(type: LocalNote['type']): string {
  return `${typeGlyph(type).color} bg-current/15`;
}
const ACCENT_TONE = 'bg-accent/10 text-accent';
/** A tag or a folder: the sidebar's filter color, under the item's own color if it has one. */
const FILTER_TONE = 'bg-label/15 text-label';

const optionId = (i: number) => `pn-quick-switcher-${i}`;
const GROUP_RULE = 'mt-1.5 pt-1 border-t border-divider';
const GROUP_HEADER = 'px-3.5 pt-2.5 pb-1 text-[11px] font-semibold uppercase tracking-wider text-accent';
const GROUP_ICONS: Record<PaletteGroup, Icon> = { commands: Terminal, new: Plus, goTo: Compass };

type Mark = Pick<TextMatch, 'start' | 'end'> | null | undefined;

function Glyph({ as: C }: { as: ComponentType<IconProps> }) {
  return <C size={16} />;
}

/** The part of a title the query matched, marked as the settings search marks it. */
function Highlighted({ text, mark }: { text: string; mark: Mark }) {
  if (!mark) return <>{text}</>;
  return (
    <>
      {text.slice(0, mark.start)}
      <mark className="rounded-sm bg-accent/20 text-inherit">{text.slice(mark.start, mark.end)}</mark>
      {text.slice(mark.end)}
    </>
  );
}

type Row =
  | { kind: 'item'; n: LocalNote; m: Mark }
  | { kind: 'file'; f: FileItem; m: Mark }
  | { kind: 'markdown'; e: DirectoryEntry; title: string; m: Mark }
  | { kind: 'command'; entry: PaletteEntry; m: Mark }
  | { kind: 'tag'; tag: string; count: number; favorite: boolean; m: Mark }
  | { kind: 'folder'; id: string; name: string; path: string; m: Mark }
  | { kind: 'newFilter'; scope: 'tags' | 'folders'; name: string }
  | { kind: 'setting'; hit: ReturnType<typeof runSettingsSearch>[number] }
  | { kind: 'search'; everything: boolean }
  | { kind: 'create'; type: QuickAddType; parsed: QuickAdd }
  | { kind: 'syntax'; id: SyntaxId }
  | { kind: 'example'; n: number; text: string; parsed: QuickAdd };

/** The example sentences of `quickAdd.examples`, numbered from 1. */
const EXAMPLES = 6;

/** What the quick add reads, one row a kind, under an empty input: the
 *  commands list of the quick add. Enter or a click types the first example.
 *  Spec: ops/docs/plans/calendar-pillar-spec.md (step 8) */
const SYNTAX = [
  { id: 'day', Icon: CalendarBlank },
  { id: 'time', Icon: Clock },
  { id: 'length', Icon: ArrowsHorizontal },
  { id: 'repeat', Icon: Repeat },
  { id: 'alert', Icon: BellSimple },
  { id: 'place', Icon: Hash },
  { id: 'space', Icon: Briefcase },
  { id: 'type', Icon: ListChecks },
] as const;
type SyntaxId = (typeof SYNTAX)[number]['id'];

/**
 * A run of rows under one header; the first group draws no rule above it.
 * `only` is the prefix that lists this group alone: its header offers it as a
 * button, so the prefix is learnt where the group shows.
 */
type Group = { header?: string; rows: Row[]; only?: { prefix: string; label: string } };

/**
 * Jump to any item by its title, to any setting by its name, or run any
 * command: Mod+K in every app (Mod+P and, in the desktop apps, Mod+O too),
 * and the "Jump to" button of the sidebar, the rail or a phone's list header.
 * Empty, it lists the items opened last (the back and forward history), then
 * the ones changed last. Typing filters every item that is not in the trash,
 * through the search core's matcher, and adds the best few commands and the
 * matching settings as groups under the items. Enter opens an item the way a
 * note-link does, and Option or Alt+Enter opens it in a tab. A setting opens
 * Settings at its row, which flashes.
 *
 * A ">" typed first is command mode, as in code editors: only the commands,
 * in their groups. A "#" typed first lists only the tags, and a "/" only the
 * folders, the sidebar's two lists; a pick applies that filter as a click on
 * its sidebar row does. With no prefix the best few of each show under the
 * items. Later in the query both keep their quick add meaning. Every other way into command mode (">" in the list search
 * or outside a text field, the list search's commands button, Mod+Shift+P)
 * opens the switcher with ">" typed.
 *
 * The switcher matches titles only, so its last row hands the query to the
 * list search, which reads the text of every item in the open section: the
 * search stays one Enter (or Mod+Enter from any row) away from Mod+K. The
 * switcher's own key closes it.
 *
 * A lazy chunk: NotesView mounts it only while it is open.
 *
 * Spec: ops/docs/plans/keyboard-shortcuts.md (section 8.1, the quick switcher; D14 and D15)
 */
export default function QuickSwitcher({
  initialQuery = '',
  notes,
  recentIds,
  titleOf,
  sectionOf,
  canOpenInTab,
  onOpen,
  linkOf,
  onEditLink,
  sectionIcons,
  onOpenSetting,
  listSearch,
  commands,
  files,
  filesSection,
  onOpenFile,
  markdown,
  onOpenMarkdown,
  quickAdd,
  filters,
  onClose,
}: {
  /** ">" opens it in command mode. */
  initialQuery?: string;
  notes: LocalNote[];
  /** The items opened last, newest first. */
  recentIds: string[];
  /** The title the list shows: a note behind the PIN shows no body text. */
  titleOf: (n: LocalNote) => string;
  /** The section an item lives in, as the sidebar names and draws it. */
  sectionOf: (n: LocalNote) => { label: string; icon: Icon } | undefined;
  canOpenInTab: boolean;
  onOpen: (n: LocalNote, inTab: boolean) => void;
  /**
   * A bookmark's link, or null for every other item and for a bookmark
   * behind a gate. A bookmark row then has two actions: Enter opens the
   * link and Shift+Enter edits it; the arrow keys and the mouse move
   * between the two.
   */
  linkOf?: (n: LocalNote) => string | null;
  /** Opens a bookmark for editing, as its row menu's Edit does. */
  onEditLink?: (n: LocalNote) => void;
  /** Each settings section's rail icon. */
  sectionIcons: Record<SectionId, Icon>;
  /** Opens Settings at the setting's row. */
  onOpenSetting: (entry: SettingEntry) => void;
  /**
   * The list search. `scoped` when the list is narrower than everything (a
   * section other than All, or a tag or folder filter), with the section's
   * name when it has one. `run` searches the list as it is, or everything.
   */
  listSearch?: { scoped: boolean; section?: string; sectionIcon: Icon; run: (query: string, everything: boolean) => void };
  /** The commands available right now (commandPalette.ts). */
  commands: () => PaletteEntry[];
  /**
   * The Files section's attachments, none from a note the PIN guards. An
   * attachment's name is not a title (a file attached inside a note keeps
   * its own name), so the switcher matches the names as well.
   */
  files: FileItem[];
  /** The Files section's name and icon, as the sidebar draws them. */
  filesSection: { label: string; icon: Icon } | undefined;
  /** Opens the file's note and scrolls to the file, as the Files list does. */
  onOpenFile: (f: FileItem) => void;
  /**
   * The open Markdown folder's files, shown and matched by their full file
   * name, extension included: "MAP.md" says the row opens a file from disk,
   * and finds what the Markdown list's own search finds. Names and paths
   * only: the files stay on disk until one is opened.
   */
  markdown?: { entries: DirectoryEntry[]; section: { label: string; icon: Icon } | undefined };
  /** Opens the file in the Markdown section. */
  onOpenMarkdown: (e: DirectoryEntry) => void;
  /**
   * Quick add: the Create rows under the hits, which read a day, a time, a
   * repeat, alerts, a folder and a tag out of the query. In `create` mode
   * (a calendar cell, the New menu, the phone's +) they come first, and a
   * cell's day and time fill what the words leave out.
   * Spec: ops/docs/plans/calendar-pillar-spec.md (step 8)
   */
  quickAdd?: {
    mode: 'jump' | 'create';
    defaultDay?: string;
    time?: string;
    timeEnd?: string;
    folders: readonly { id: string; name: string }[];
    /** Spaces is on, so "@work" means something. */
    spaces: boolean;
    onCreate: (q: QuickAdd, type: QuickAddType) => void;
  };
  /**
   * The sidebar's tags and folders, in its own order and scoped to the open
   * space as it is. `folders` is empty while folders are locked.
   */
  filters?: {
    tags: readonly (readonly [string, number])[];
    favoriteTags: ReadonlySet<string>;
    folders: readonly { id: string; name: string; parentId: string | null }[];
    onTag: (tag: string) => void;
    onFolder: (id: string) => void;
    /** A new note with the tag, as the sidebar's new tag field makes. */
    onCreateTag: (tag: string) => void;
    /** A new top folder, then its filter. */
    onCreateFolder: (name: string) => void;
  };
  onClose: () => void;
}) {
  const { t } = useTranslation('common');
  useEscapeToClose(onClose);
  const [query, setQuery] = useState(initialQuery);
  // Came in through New tag or New folder: the Create row leads, so Enter
  // after the name makes it. Ends with the prefix.
  const [creatingFilter, setCreatingFilter] = useState(false);
  const [active, setActive] = useState(0);
  // A row picks the pointer only when the pointer moves. The panel opens under
  // a still pointer (a click on a calendar cell), and the browser sends a move
  // at the same place when a row lands under it; that must not take the
  // highlight from the first row, or Enter runs the wrong row.
  const pointer = useRef<{ x: number; y: number } | null>(null);
  const hover = (i: number, e: { clientX: number; clientY: number }) => {
    const last = pointer.current;
    pointer.current = { x: e.clientX, y: e.clientY };
    if (last && (last.x !== e.clientX || last.y !== e.clientY)) setActive(i);
  };
  // On a bookmark row: 0 is Open link, 1 is Edit. Kept with the row it was
  // set on, so a new row starts on the link.
  const [actionAt, setActionAt] = useState<{ row: number; which: 0 | 1 }>({ row: -1, which: 0 });
  // The settings search also reads the keyword lists, which load here.
  const [settingsReady, setSettingsReady] = useState(false);
  useEffect(() => {
    void ensureSettingsSearchLoaded()
      .catch((err) => console.warn('[switcher] settings search failed to load:', err))
      .then(() => setSettingsReady(true));
  }, []);

  const commandMode = query.startsWith(COMMAND_PREFIX);
  // The quick add's own "#tag" and "/Folder" come first in a create field, so
  // the prefixes work in the jump field only.
  const scope: 'tags' | 'folders' | null =
    !filters || quickAdd?.mode === 'create' ? null
      : query.startsWith(TAG_PREFIX) ? 'tags'
        : query.startsWith(FOLDER_PREFIX) ? 'folders'
          : null;
  const q = (commandMode ? query.slice(COMMAND_PREFIX.length) : scope ? query.slice(1) : query).trim();
  // Read once per open: the list is what the app could run when it opened.
  // The switcher's own entry is left out, since it is already open.
  // Two of the switcher's own: they type a prefix and keep it open, so the
  // command list also teaches "#" and "/".
  const [entries] = useState(() => [
    ...commands().filter((e) => e.id !== 'cmd:quickSwitcher'),
    ...(filters
      ? [
          { id: PREFIX_ENTRY.tags, group: 'goTo', label: t('quickSwitcher.goToTag'), keys: TAG_PREFIX, icon: Hash, run: () => {} } satisfies PaletteEntry,
          ...(filters.folders.length
            ? [{ id: PREFIX_ENTRY.folders, group: 'goTo', label: t('quickSwitcher.goToFolder'), keys: FOLDER_PREFIX, icon: Folder, run: () => {} } satisfies PaletteEntry]
            : []),
          { id: PREFIX_ENTRY.newTag, group: 'new', label: t('quickSwitcher.newTag'), icon: Hash, run: () => {} } satisfies PaletteEntry,
          { id: PREFIX_ENTRY.newFolder, group: 'new', label: t('quickSwitcher.newFolder'), icon: Folder, run: () => {} } satisfies PaletteEntry,
        ]
      : []),
  ]);
  // The quick add shows one sentence it understands, a different one per open
  // (tests/quickAdd.test.ts parses each in every language).
  const [example] = useState(() => 1 + Math.floor(Math.random() * EXAMPLES));

  const items = useMemo(() => {
    if (commandMode || scope) return [];
    const live = notes.filter((n) => n.trashed !== 1);
    const recentRank = new Map(recentIds.map((id, i) => [id, i]));
    const byRecency = (a: LocalNote, b: LocalNote) =>
      (recentRank.get(a.id) ?? Infinity) - (recentRank.get(b.id) ?? Infinity) ||
      editedAtOf(b).localeCompare(editedAtOf(a));
    if (!q) return [...live].sort(byRecency).slice(0, LIMIT).map((n): Row => ({ kind: 'item', n, m: null }));
    const match = textMatcher(q);
    const byId = new Map(live.map((n) => [n.id, n]));
    // A Markdown file has no note behind it, so it sorts after the items of
    // the same rank.
    type Hit = { row: Row; m: TextMatch; n?: LocalNote };
    const hits: Hit[] = [];
    for (const n of live) {
      const m = match(titleOf(n));
      if (m) hits.push({ row: { kind: 'item', n, m }, m, n });
    }
    const titled = new Set(hits.map((h) => h.n!.id));
    // Attachments only: a picture's name is made from its note's title. A
    // file that is its own item and already matched by title is not repeated.
    for (const f of files) {
      const n = byId.get(f.noteId);
      if (f.kind !== 'attachment' || !n || (f.standalone && titled.has(f.noteId))) continue;
      const m = match(f.name);
      if (m) hits.push({ row: { kind: 'file', f, m }, m, n });
    }
    for (const e of markdown?.entries ?? []) {
      const title = e.relPath.slice(e.relPath.lastIndexOf('/') + 1);
      const m = match(title);
      if (m) hits.push({ row: { kind: 'markdown', e, title, m }, m });
    }
    return hits
      .sort((a, b) => b.m.rank - a.m.rank || (a.n && b.n ? byRecency(a.n, b.n) : a.n ? -1 : b.n ? 1 : 0))
      .slice(0, LIMIT)
      .map((h) => h.row);
  }, [commandMode, scope, q, notes, recentIds, titleOf, files, markdown]);

  // A folder's place in the tree, so two folders of one name read apart.
  const folderPath = useMemo(() => {
    const byId = new Map((filters?.folders ?? []).map((f) => [f.id, f]));
    return (f: { parentId: string | null }) => {
      const names: string[] = [];
      for (let p = f.parentId ? byId.get(f.parentId) : undefined; p && names.length < 8; p = p.parentId ? byId.get(p.parentId) : undefined) {
        names.unshift(p.name);
      }
      return names.join(' / ');
    };
  }, [filters?.folders]);
  const tagRows = useMemo((): Row[] => {
    if (!filters || commandMode || scope === 'folders' || (!scope && !q)) return [];
    const match = q ? textMatcher(q) : null;
    const hits: { row: Row; rank: number }[] = [];
    for (const [tag, count] of filters.tags) {
      const m = match ? match(tag) : null;
      if (match && !m) continue;
      hits.push({ row: { kind: 'tag', tag, count, favorite: filters.favoriteTags.has(tag), m }, rank: m?.rank ?? 0 });
    }
    // The sidebar's order among equal ranks: the sort is stable.
    return hits.sort((a, b) => b.rank - a.rank).slice(0, scope ? LIMIT : FILTERS_LIMIT).map((h) => h.row);
  }, [filters, commandMode, scope, q]);
  const folderRows = useMemo((): Row[] => {
    if (!filters || commandMode || scope === 'tags' || (!scope && !q)) return [];
    const match = q ? textMatcher(q) : null;
    const hits: { row: Row; rank: number }[] = [];
    for (const f of filters.folders) {
      const m = match ? match(f.name) : null;
      if (match && !m) continue;
      hits.push({ row: { kind: 'folder', id: f.id, name: f.name, path: folderPath(f), m }, rank: m?.rank ?? 0 });
    }
    return hits.sort((a, b) => b.rank - a.rank).slice(0, scope ? LIMIT : FILTERS_LIMIT).map((h) => h.row);
  }, [filters, commandMode, scope, q, folderPath]);

  // A name no tag or folder has yet, offered under the hits in "#" and "/".
  const newFilterRows = useMemo((): Row[] => {
    if (!filters || !scope || !q) return [];
    if (scope === 'tags') {
      const tag = normalizeTag(q);
      return tag && !filters.tags.some(([t]) => t === tag) ? [{ kind: 'newFilter', scope, name: tag }] : [];
    }
    const name = q.trim();
    return filters.folders.some((f) => foldText(f.name) === foldText(name)) ? [] : [{ kind: 'newFilter', scope, name }];
  }, [filters, scope, q]);

  const commandRows = useMemo(() => {
    if (scope || (!commandMode && !q)) return [];
    const match = q ? textMatcher(q) : null;
    const found = matchEntries(entries, q).map((entry): Row => ({ kind: 'command', entry, m: match?.(entry.label) }));
    return commandMode ? found : found.slice(0, COMMANDS_LIMIT);
  }, [commandMode, scope, q, entries]);

  const sectionLabels = useMemo(railLabels, []);
  const settings = useMemo(
    () =>
      settingsReady && q && !commandMode && !scope
        ? runSettingsSearch(q, sectionLabels).slice(0, SETTINGS_LIMIT).map((hit): Row => ({ kind: 'setting', hit }))
        : [],
    [settingsReady, q, commandMode, scope, sectionLabels],
  );

  const { t: tShell } = useTranslation('shell');
  const readCtx = useMemo(() => {
    if (!quickAdd) return null;
    const locale = intlLocale();
    const sample = formatDay('2026-10-06', 'numeric');
    const order: 'dmy' | 'mdy' | 'ymd' = /^2026/.test(sample) ? 'ymd' : sample.indexOf('6') < sample.indexOf('10') ? 'dmy' : 'mdy';
    const bundle = (lng: string) => (i18n.getResourceBundle(lng, 'quickAdd') as { words?: Record<string, string> } | undefined)?.words;
    return { words: readWords(bundle(activeLocale()), bundle('en') ?? {}), engine: engineWords(locale, order) };
  }, [quickAdd]);
  const createRows = useMemo((): Row[] => {
    if (!quickAdd || !readCtx || commandMode || scope || (!q && quickAdd.mode !== 'create')) return [];
    const parsed = parseQuickAdd(q, { ...readCtx, today: toLocalIso(new Date()), defaultDay: quickAdd.defaultDay, folders: quickAdd.folders });
    // A cell gave a day (and an hour): it fills what the words leave out.
    if (!parsed.day && quickAdd.defaultDay) parsed.day = quickAdd.defaultDay;
    if (!parsed.time && quickAdd.time && parsed.day === quickAdd.defaultDay) {
      parsed.time = quickAdd.time;
      if (quickAdd.timeEnd) parsed.timeEnd = quickAdd.timeEnd;
    }
    const first: QuickAddType = parsed.type ?? 'event';
    return ([first, ...(['event', 'note', 'task', 'journal'] as const).filter((x) => x !== first)])
      .map((type): Row => ({ kind: 'create', type, parsed }));
  }, [quickAdd, readCtx, commandMode, scope, q]);
  // Whole sentences, each with what it becomes: a click types it.
  const exampleRows = useMemo((): Row[] => {
    if (quickAdd?.mode !== 'create' || q || !readCtx) return [];
    return Array.from({ length: EXAMPLES }, (_, k): Row => {
      const text = tShell(`quickAdd.examples.${k + 1}`);
      const parsed = parseQuickAdd(text, { ...readCtx, today: toLocalIso(new Date()), folders: quickAdd.folders });
      return { kind: 'example', n: k + 1, text, parsed };
    });
  }, [quickAdd?.mode, quickAdd?.folders, q, readCtx, tShell]);
  const syntaxRows = useMemo(
    (): Row[] => (quickAdd?.mode === 'create' && !q
      ? SYNTAX.filter((s) => s.id !== 'space' || quickAdd.spaces).map((s): Row => ({ kind: 'syntax', id: s.id }))
      : []),
    [quickAdd?.mode, quickAdd?.spaces, q],
  );

  const groups = useMemo((): Group[] => {
    if (commandMode) {
      return GROUP_ORDER.map((g) => ({
        header: t(`palette.groups.${g}`),
        rows: commandRows.filter((r) => r.kind === 'command' && r.entry.group === g),
      })).filter((g) => g.rows.length);
    }
    const tagGroup: Group = { header: t('quickSwitcher.tags'), rows: tagRows, only: { prefix: TAG_PREFIX, label: t('quickSwitcher.showOnlyTags') } };
    const folderGroup: Group = { header: t('quickSwitcher.folders'), rows: folderRows, only: { prefix: FOLDER_PREFIX, label: t('quickSwitcher.showOnlyFolders') } };
    if (scope) {
      const found = { ...(scope === 'tags' ? tagGroup : folderGroup), only: undefined };
      const make = { header: tShell('quickAdd.group'), rows: newFilterRows };
      return (creatingFilter ? [make, found] : [found, make]).filter((g) => g.rows.length);
    }
    const create = { header: tShell('quickAdd.group'), rows: createRows };
    const creating = quickAdd?.mode === 'create';
    return [
      // Under an empty quick add: Create, then what it reads, then the recent items.
      ...(creating
        ? [create, { header: tShell('quickAdd.examplesGroup'), rows: exampleRows }, { header: tShell('quickAdd.syntax.group'), rows: syntaxRows }]
        : []),
      { header: q ? (creating ? tShell('quickAdd.items') : undefined) : t('quickSwitcher.recent'), rows: items },
      tagGroup,
      folderGroup,
      { header: t('palette.label'), rows: commandRows, only: { prefix: COMMAND_PREFIX, label: t('quickSwitcher.showOnlyCommands') } },
      { header: t('settings:shell.title'), rows: settings },
      // Explicit under the hits: Enter on a hit still opens the hit.
      ...(creating ? [] : [create]),
    ].filter((g) => g.rows.length);
  }, [commandMode, scope, creatingFilter, q, items, tagRows, folderRows, newFilterRows, commandRows, settings, t, tShell, createRows, exampleRows, syntaxRows, quickAdd?.mode]);

  const searchRow = !!listSearch && !!q && !commandMode && !scope;
  // "Search everything" is always offered; the open section's own search
  // follows it when the list is narrower than everything.
  const searchRows = useMemo(
    (): Row[] =>
      searchRow
        ? [{ kind: 'search', everything: true }, ...(listSearch!.scoped ? [{ kind: 'search', everything: false } as Row] : [])]
        : [],
    [searchRow, listSearch],
  );
  const rows = useMemo(() => [...groups.flatMap((g) => g.rows), ...searchRows], [groups, searchRows]);
  const count = rows.length;
  const at = Math.min(active, Math.max(0, count - 1));
  const searchIndex = count - searchRows.length;

  const move = (step: number) => {
    if (!count) return;
    const next = (at + step + count) % count;
    setActive(next);
    document.getElementById(optionId(next))?.scrollIntoView({ block: 'nearest' });
  };

  /** The link of a row that is a bookmark with one. */
  const linkAt = (i: number): string | null => {
    const row = rows[i];
    return row?.kind === 'item' ? (linkOf?.(row.n) ?? null) : null;
  };
  const selectedLink = linkAt(at);
  const action: 0 | 1 = actionAt.row === at ? actionAt.which : 0;
  const setAction = (which: 0 | 1) => setActionAt({ row: at, which });

  /** Open a row. A bookmark row opens its link unless `edit` asks for the
   *  bookmark itself, as a tab does. */
  const open = (i: number, inTab: boolean, edit = false) => {
    const row = rows[i];
    if (!row) return;
    // A syntax row types its example and keeps the quick add open.
    if (row.kind === 'example') {
      setQuery(row.text);
      setActive(0);
      return;
    }
    if (row.kind === 'syntax') {
      const insert = tShell(`quickAdd.syntax.${row.id}.insert`);
      setQuery(/[#/@]$/.test(insert) ? insert : `${insert} `);
      setActive(0);
      return;
    }
    const typed = row.kind === 'command' ? PREFIX_OF[row.entry.id] : undefined;
    if (typed) {
      setQuery(typed.prefix);
      setCreatingFilter(typed.creating);
      setActive(0);
      return;
    }
    const link = linkAt(i);
    onClose();
    if (link && row.kind === 'item' && !inTab) {
      if (edit && onEditLink) onEditLink(row.n);
      else openExternal(link);
    } else if (row.kind === 'item') onOpen(row.n, inTab && canOpenInTab);
    else if (row.kind === 'file') onOpenFile(row.f);
    else if (row.kind === 'markdown') onOpenMarkdown(row.e);
    else if (row.kind === 'command') row.entry.run();
    else if (row.kind === 'tag') filters!.onTag(row.tag);
    else if (row.kind === 'folder') filters!.onFolder(row.id);
    else if (row.kind === 'newFilter') (row.scope === 'tags' ? filters!.onCreateTag : filters!.onCreateFolder)(row.name);
    else if (row.kind === 'search') listSearch!.run(q, row.everything);
    else if (row.kind === 'create') quickAdd!.onCreate(row.parsed, row.type);
    // The help center is a site, not a pane, as it is in the settings rail.
    else if (row.hit.entry.section === 'help') openExternal(siteHref(helpPath(activeLocale())));
    else onOpenSetting(row.hit.entry);
  };

  /** Mod+Enter runs the list search from any row, so it never needs the arrows. */
  const searchKeys = KEY_OS === 'mac' ? '⌘↵' : 'Ctrl+↵';

  /** What a quick add makes, in words: the day, the time, the repeat, the alerts. */
  const sentenceOf = (parsed: QuickAdd, type: QuickAddType) =>
    parsed.day
      ? describeSchedule({
          day: parsed.day,
          ...(parsed.end ? { end: parsed.end } : {}),
          ...(parsed.time ? { time: parsed.time } : {}),
          ...(parsed.timeEnd ? { timeEnd: parsed.timeEnd } : {}),
          ...(parsed.repeat && type === 'event' ? { repeat: parsed.repeat } : {}),
          ...(parsed.alerts.length ? { alerts: parsed.alerts } : {}),
        }, tShell)
      : null;

  const option = (
    i: number,
    key: string,
    RowIcon: ComponentType<IconProps> | ReactNode | undefined,
    title: ReactNode,
    detail: ReactNode,
    opts: { keys?: string; accent?: boolean; tone?: string; strong?: boolean; link?: boolean } = {},
  ) => {
    const selected = i === at;
    // The "Search everything" row wears an accent title: it is the one row
    // that is not a jump but a search of the text of every item.
    // An item's title is bold, as in the list; a command or a setting is not.
    const { keys, accent, tone = ACCENT_TONE, strong } = opts;
    return (
      <div
        key={key}
        id={optionId(i)}
        role="option"
        aria-selected={selected}
        onMouseMove={(e) => hover(i, e)}
        onMouseDown={(e) => e.preventDefault()}
        onClick={(e) => open(i, e.altKey)}
        className={`relative mx-1.5 flex items-center gap-3 rounded-md px-2 py-1.5 cursor-pointer ${selected ? 'bg-accent/10 before:absolute before:inset-y-1.5 before:start-0 before:w-[3px] before:rounded-full before:bg-accent' : ''}`}
      >
        <span className={`flex w-7 h-7 shrink-0 items-center justify-center rounded-md ${tone}`} aria-hidden="true">
          {/* A component, or a ready-made glyph redrawn at the tile's size. */}
          {isValidElement(RowIcon) ? cloneElement(RowIcon as ReactElement<IconProps>, { size: 16 }) : RowIcon ? <Glyph as={RowIcon as ComponentType<IconProps>} /> : null}
        </span>
        <div className="min-w-0 flex-1">
          <div className={`truncate text-[14px] leading-5 ${accent ? 'font-medium text-accent' : 'text-pn'} ${strong ? 'font-semibold' : ''}`}>{title}</div>
          {detail && <div className="truncate text-[12px] leading-4 text-pn-muted">{detail}</div>}
        </div>
        {opts.link ? (
          // A bookmark: Edit and Open link, the one Enter runs marked. On a
          // touch screen, where no row is selected, every bookmark row shows
          // them and a tap on the row opens the link.
          <span className={`shrink-0 items-center gap-1 ${selected ? 'flex' : 'hidden [@media(hover:none)]:flex'}`}>
            {([1, 0] as const).map((which) => (
              <button
                key={which}
                type="button"
                tabIndex={-1}
                onMouseDown={(e) => e.preventDefault()}
                onMouseEnter={() => selected && setAction(which)}
                onClick={(e) => {
                  e.stopPropagation();
                  open(i, false, which === 1);
                }}
                className={`inline-flex items-center gap-1.5 rounded-md border px-1.5 py-0.5 text-[12px] transition ${
                  selected && action === which ? 'border-accent text-accent-strong bg-accent/10' : 'border-pn-muted/50 text-pn-soft hover:text-pn hover:border-pn-muted'
                }`}
              >
                {which === 1 ? <PencilSimple size={12} aria-hidden="true" /> : <ArrowSquareOut size={12} aria-hidden="true" />}
                {which === 1 ? t('actions.edit') : t('quickSwitcher.openLink')}
                <kbd aria-hidden="true" className={`${KEYCAP} [@media(hover:none)]:hidden`}>{which === 1 ? '⇧↵' : '↵'}</kbd>
              </button>
            ))}
          </span>
        ) : (keys || selected) && (
          <kbd aria-hidden="true" className={`${KEYCAP} [@media(hover:none)]:hidden`}>{selected ? '↵' : keys}</kbd>
        )}
      </div>
    );
  };

  const renderRow = (row: Row, i: number): ReactNode => {
    if (row.kind === 'item') {
      const view = sectionOf(row.n);
      return option(
        i,
        row.n.id,
        view?.icon,
        <Highlighted text={titleOf(row.n)} mark={row.m} />,
        <>
          {view?.label}
          {view?.label ? ' · ' : ''}
          {formatRelative(editedAtOf(row.n))}
        </>,
        { tone: toneOf(row.n.type), strong: true, link: !!linkOf?.(row.n) },
      );
    }
    if (row.kind === 'file') {
      const { f } = row;
      // A file inside a note names the note; a file that is its own item
      // needs only the section.
      return option(
        i,
        `file:${f.noteId}:${f.uuid}`,
        filesSection?.icon,
        <Highlighted text={f.name} mark={row.m} />,
        <>
          {[filesSection?.label, f.standalone ? '' : f.noteTitle].filter(Boolean).join(' · ')}
          {' · '}
          {formatRelative(f.editedAt)}
        </>,
        { tone: toneOf('file'), strong: true },
      );
    }
    if (row.kind === 'markdown') {
      // The folder path tells apart the files that share a name, as the
      // Markdown list's chip does.
      return option(
        i,
        `md:${row.e.relPath}`,
        markdown?.section?.icon,
        <Highlighted text={row.title} mark={row.m} />,
        [markdown?.section?.label, row.e.dir.replace(/\/$/, '')].filter(Boolean).join(' · '),
        { strong: true },
      );
    }
    if (row.kind === 'tag') {
      return option(
        i,
        `tag:${row.tag}`,
        <TagGlyph tag={row.tag} favorite={row.favorite} />,
        <Highlighted text={row.tag} mark={row.m} />,
        t('quickSwitcher.tagItems', { count: row.count }),
        { tone: FILTER_TONE },
      );
    }
    if (row.kind === 'folder') {
      return option(
        i,
        `folder:${row.id}`,
        <FolderGlyph folderId={row.id} />,
        <Highlighted text={row.name} mark={row.m} />,
        row.path || null,
        { tone: FILTER_TONE },
      );
    }
    if (row.kind === 'newFilter') {
      return option(
        i,
        `new:${row.scope}`,
        Plus,
        t(row.scope === 'tags' ? 'quickSwitcher.createTag' : 'quickSwitcher.createFolder', { name: row.name }),
        null,
        { tone: FILTER_TONE },
      );
    }
    if (row.kind === 'command') {
      const { entry } = row;
      return option(i, entry.id, entry.glyph ?? entry.icon ?? GROUP_ICONS[entry.group], <Highlighted text={entry.label} mark={row.m} />, null, {
        keys: entry.keys,
      });
    }
    if (row.kind === 'setting') {
      const { hit } = row;
      // A section's own entry names no place but Settings.
      const place = hit.entry.isSection
        ? t('settings:shell.title')
        : [sectionLabels.get(hit.entry.section), tabOf(hit)].filter(Boolean).join(' · ');
      return option(
        i,
        hit.entry.id,
        sectionIcons[hit.entry.section],
        <>
          <Highlighted text={hit.label} mark={hit.english ? null : hit.mark} />
          {hit.entry.section === 'help' && <ArrowSquareOut size={12} className="inline ms-1.5 text-accent" aria-hidden="true" />}
        </>,
        <>
          {place}
          {hit.why && (
            <>
              {' · '}
              {t(hit.english ? 'settingsSearch:matchedInEnglish' : 'settingsSearch:matched')} <bdi>{hit.why}</bdi>
            </>
          )}
        </>,
      );
    }
    if (row.kind === 'example') {
      const { parsed } = row;
      const type = parsed.type ?? 'event';
      const sentence = sentenceOf(parsed, type);
      const what = tShell('quickAdd.createNamed', { type: tShell(`quickAdd.types.${type}`), title: parsed.title });
      return option(i, `example-${row.n}`, typeGlyph(type).Icon, row.text, [what, sentence].filter(Boolean).join(' · '), { tone: toneOf(type) });
    }
    if (row.kind === 'syntax') {
      const s = SYNTAX.find((x) => x.id === row.id)!;
      return option(i, `syntax-${row.id}`, s.Icon, tShell(`quickAdd.syntax.${row.id}.label`), tShell(`quickAdd.syntax.${row.id}.examples`));
    }
    if (row.kind === 'create') {
      const { parsed, type } = row;
      const { Icon } = typeGlyph(type);
      const label = parsed.title
        ? tShell('quickAdd.createNamed', { type: tShell(`quickAdd.types.${type}`), title: parsed.title })
        : tShell(`quickAdd.types.${type}`);
      const sentence = sentenceOf(parsed, type);
      return option(
        i,
        `create-${type}`,
        <Icon size={16} />,
        label,
        <>
          {sentence}
          {/* What the words were read as. A click keeps that text in the
              title instead, by putting it in quotes. */}
          {parsed.parts.length > 0 && type === (parsed.type ?? 'event') && (
            <span className="ms-1.5 inline-flex flex-wrap gap-1 align-middle">
              {parsed.parts.map((part, k) => (
                <button
                  key={k}
                  type="button"
                  title={tShell('quickAdd.keepAsText')}
                  onMouseDown={(e) => e.preventDefault()}
                  onClick={(e) => {
                    e.stopPropagation();
                    setQuery((cur) => cur.replace(part.text, `"${part.text}"`));
                  }}
                  className="rounded bg-accent/15 px-1 text-[11px] text-accent-strong hover:bg-accent/25"
                >
                  {part.text}
                </button>
              ))}
            </span>
          )}
        </>,
        { tone: toneOf(type), strong: true },
      );
    }
    if (row.everything) {
      return option(
        i,
        'search-everything',
        MagnifyingGlass,
        t('quickSwitcher.searchAll', { query: q }),
        t('quickSwitcher.searchDetail'),
        { keys: searchKeys, accent: true },
      );
    }
    // The open section's own icon, so the row reads apart from "everything".
    return option(
      i,
      'search-here',
      listSearch!.sectionIcon,
      listSearch!.section
        ? t('quickSwitcher.searchIn', { section: listSearch!.section, query: q })
        : t('quickSwitcher.searchList', { query: q }),
      null,
    );
  };

  let index = 0;
  return (
    // Centred on the screen at its full height (the 48px field, the 50vh
    // list, the 37px footer and the borders); as a query shortens the list
    // it shrinks from the bottom, so the field never moves under the typing.
    // A touch screen keeps it high, above the on-screen keyboard.
    <div
      className="fixed inset-0 z-50 bg-black/50 dark:bg-black/70 flex justify-center items-start pt-[12vh] [@media(hover:hover)]:pt-[max(1rem,calc(25dvh-44px))] px-4"
      onClick={onClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={t('quickSwitcher.label')}
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-xl bg-surface-2 border border-divider rounded-lg shadow-xl overflow-hidden"
      >
        <div className="flex items-center gap-2.5 px-3.5 border-b border-divider">
          <input
            autoFocus
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              if (!/^[#/]/.test(e.target.value)) setCreatingFilter(false);
              setActive(0);
              setActionAt({ row: -1, which: 0 });
            }}
            onKeyDown={(e) => {
              if (isImeComposing(e)) return;
              // The window listener would open the switcher again behind the
              // close, so the key stops here.
              if (matchesKey(e.nativeEvent, APP_KEYS.quickSwitcher, true)) {
                e.preventDefault();
                e.nativeEvent.stopPropagation();
                onClose();
              } else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
                e.preventDefault();
                move(e.key === 'ArrowDown' ? 1 : -1);
              } else if (selectedLink && (e.key === 'ArrowRight' || e.key === 'ArrowLeft') && !e.shiftKey) {
                // On a bookmark row the arrows move between Edit and Open
                // link; the caret still moves while it is inside the query.
                const input = e.currentTarget;
                const atEnd = input.selectionStart === input.value.length && input.selectionEnd === input.value.length;
                const toEdit = (e.key === 'ArrowLeft') !== (document.dir === 'rtl');
                if (toEdit && action === 0 && atEnd) {
                  e.preventDefault();
                  setAction(1);
                } else if (!toEdit && action === 1) {
                  e.preventDefault();
                  setAction(0);
                }
              } else if (e.key === 'Enter') {
                e.preventDefault();
                if (searchRow && (KEY_OS === 'mac' ? e.metaKey : e.ctrlKey)) open(searchIndex, false);
                else open(at, e.altKey, e.shiftKey || action === 1);
              }
            }}
            placeholder={quickAdd?.mode === 'create'
              ? tShell('quickAdd.example', { example: tShell(`quickAdd.examples.${example}`) })
              : t('quickSwitcher.placeholder')}
            aria-label={quickAdd?.mode === 'create' ? tShell('quickAdd.placeholder') : t('quickSwitcher.placeholder')}
            role="combobox"
            aria-expanded
            aria-controls="pn-quick-switcher-list"
            aria-activedescendant={count ? optionId(at) : undefined}
            className="flex-1 min-w-0 h-12 bg-transparent text-[17px] font-medium text-pn placeholder:text-[15px] placeholder:font-normal placeholder:text-pn-muted outline-none"
          />
          {/* Always shown: it clears the query, and with no query it closes
              the switcher, so a pointer never needs Escape. */}
          <HoverLabel label={t(query ? 'actions.clearSearch' : 'actions.close')} position="below-end" className="-me-2 flex shrink-0">
            <button
              type="button"
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => {
                if (!query) return onClose();
                setQuery('');
                setCreatingFilter(false);
                setActive(0);
              }}
              aria-label={t(query ? 'actions.clearSearch' : 'actions.close')}
              className="inline-flex items-center justify-center w-8 h-8 rounded-md text-pn-muted hover:text-pn hover:bg-pn/5 transition"
            >
              <X size={14} />
            </button>
          </HoverLabel>
        </div>
        <div id="pn-quick-switcher-list" role="listbox" className="max-h-[50vh] overflow-y-auto pt-1 [&:not(:has(.sticky))]:pb-1">
          {count === 0 && (
            <div className="px-3.5 py-3 text-[13px] text-pn-muted">
              {t(commandMode ? 'palette.empty' : scope === 'tags' ? 'quickSwitcher.emptyTags' : scope === 'folders' ? 'quickSwitcher.emptyFolders' : 'quickSwitcher.empty')}
            </div>
          )}
          {groups.map((g, gi) => {
            const headerId = `pn-quick-switcher-group-${gi}`;
            return (
              <div key={gi} role="group" aria-labelledby={g.header ? headerId : undefined}>
                {g.header && (
                  <div className={`flex items-center justify-between gap-2 pe-3.5 ${gi ? GROUP_RULE : ''}`}>
                    <div id={headerId} className={GROUP_HEADER}>{g.header}</div>
                    {g.only && (
                      <button
                        type="button"
                        tabIndex={-1}
                        onMouseDown={(e) => e.preventDefault()}
                        onClick={() => {
                          setQuery(`${g.only!.prefix}${q}`);
                          setActive(0);
                        }}
                        className="mt-1.5 inline-flex items-center gap-1.5 rounded-md px-1.5 py-0.5 text-[12px] text-pn-muted hover:text-pn hover:bg-pn/5 transition"
                      >
                        <kbd aria-hidden="true" className="inline-flex min-w-5 h-5 items-center justify-center rounded border border-b-2 border-divider bg-surface-1 px-1 font-sans text-[12px] font-medium leading-none text-pn">{g.only.prefix}</kbd>
                        {g.only.label}
                      </button>
                    )}
                  </div>
                )}
                {!g.header && gi > 0 && <div className={GROUP_RULE} aria-hidden="true" />}
                {g.rows.map((row) => renderRow(row, index++))}
              </div>
            );
          })}
          {/* Pinned under the scrolling rows, so it is in view at any length. */}
          {searchRow && (
            <div className={`sticky bottom-0 py-1 bg-surface-2 ${groups.length ? 'mt-1 border-t border-divider' : '-mt-1'}`}>
              {searchRows.map((row) => renderRow(row, index++))}
            </div>
          )}
        </div>
        {/* Key hints only: a touch screen has no keys to name. */}
        <div className="flex flex-wrap gap-x-4 gap-y-1 px-3.5 py-2 border-t border-divider text-[12px] text-pn-muted [@media(hover:none)]:hidden">
          <span className="inline-flex items-center gap-1"><kbd className={KEYCAP}>↑</kbd><kbd className={KEYCAP}>↓</kbd> {t('quickSwitcher.move')}</span>
          <span className="inline-flex items-center gap-1"><kbd className={KEYCAP}>↵</kbd> {t('quickSwitcher.open')}</span>
          {selectedLink && (
            <span className="inline-flex items-center gap-1"><kbd className={KEYCAP}>⇧↵</kbd> {t('quickSwitcher.edit')}</span>
          )}
          {canOpenInTab && !commandMode && !scope && (
            <span className="inline-flex items-center gap-1"><kbd className={KEYCAP}>{KEY_OS === 'mac' ? '⌥↵' : 'Alt+↵'}</kbd> {t('quickSwitcher.openInTab')}</span>
          )}
          {/* The prefixes, named while the field is empty and they can be typed. */}
          {filters && !query && quickAdd?.mode !== 'create' && (
            <>
              <span className="inline-flex items-center gap-1"><kbd className={KEYCAP}>{TAG_PREFIX}</kbd> {t('quickSwitcher.onlyTags')}</span>
              {filters.folders.length > 0 && (
                <span className="inline-flex items-center gap-1"><kbd className={KEYCAP}>{FOLDER_PREFIX}</kbd> {t('quickSwitcher.onlyFolders')}</span>
              )}
            </>
          )}
          <span className="inline-flex items-center gap-1"><kbd className={KEYCAP}>Esc</kbd> {t('quickSwitcher.close')}</span>
        </div>
      </div>
    </div>
  );
}
