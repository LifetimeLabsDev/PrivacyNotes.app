import { cloneElement, isValidElement, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type ComponentType, type CSSProperties, type ReactElement, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type { LocalNote } from './db';
import type { FileItem } from './FilesList';
import type { DirectoryEntry } from './markdownFolder/fileAccess';
import { editedAtOf, journalOn } from './notesViewUtils';
import type { ContextMenuItem } from './ContextMenu';
import { searchIndexReady, searchNotes } from './search';
import { CREATE_PREFIX, FOLDER_PREFIX, TAG_PREFIX, appendLines, asWebAddress, dayOfQuery, emptyMessage, readSwitcherQuery, splitAppend, textHit } from './switcherQuery';
import { typeGlyph } from './NoteRow';
import i18n from './i18n';
import { intlLocale } from './languages';
import { engineWords, parseQuickAdd, readWords, type QuickAdd, type QuickAddType } from './quickAdd';
import { describeSchedule } from './scheduleText';
import { useEscapeToClose } from './useEscapeToClose';
import { isImeComposing } from './imeComposing';
import { foldForMatch, textMatcher, type TextMatch } from './textMatch';
import { formatDay, formatRelative, toLocalIso } from './intlFormat';
import { activeLocale, ensureSettingsSearchLoaded } from './i18n';
import { NEW_GLYPHS, ArrowElbowDownRight, ArrowSquareOut, ArrowsHorizontal, BellSimple, Briefcase, CalendarBlank, CalendarDot, Check, Clock, DotsThreeOutlineVertical, ArrowLeft, Folder, Hash, ListChecks, PencilSimple, Compass, MagnifyingGlass, Palette, Plus, Repeat, Sparkle, Terminal, X, type Icon, type IconProps } from './icons';
import { HoverLabel } from './HoverLabel';
import { KATANA_LINE, NinjaIcon } from './NinjaIcon';
import { helpPath } from './localeRoutes';
import { openExternal } from './openExternal';
import { siteHref } from './siteLinks';
import { APP_KEYS, KEY_OS, matchesKey } from './shortcutMatch';
import { COMMAND_PREFIX, GROUP_ORDER, matchEntries, type PaletteEntry, type PaletteGroup } from './commandPalette';
import type { SectionId, SettingEntry } from './settingsSearch/registry';
import { railLabels, runSettingsSearch, tabOf } from './settingsSearch/SettingsSearchResults';
import { FolderGlyph, PathGlyph, TagGlyph, useItemLookResolver, useNoteIconPaths } from './looks/LookGlyph';
import { normalizeTag } from './notesRepo';
import { foldText } from './textFold';
import { ProMark } from './ui';
import { SECTIONS_IN_FEATURES, noteRecentCommand, readRecentCommands } from './ninjaFeatures';
import { DARK_THEMES, LIGHT_THEMES, THEME_DISPLAY_NAME, customChoice, isFreeTheme, themeSwatch, useTheme, type CustomSnapshot, type Theme, type ThemeChoice } from './theme';
import { customThemeEntries, teamThemeEntries } from './customThemeUI';
import type { CustomThemes } from './customThemes';

/** How many items the list shows at most. */
const LIMIT = 30;
/** How many settings show under the items at most. */
const SETTINGS_LIMIT = 10;
/** How many commands show under the items when the query has no ">". */
const COMMANDS_LIMIT = 3;
/** How many tags, and how many folders, show under the items with no prefix. */
const FILTERS_LIMIT = 3;
/** How many items found by their text, and not their title, show at most. */
const TEXT_LIMIT = 5;
/** How many of the search's hits are read for a visible match at most. */
const TEXT_SCAN = 60;
/** A shorter query finds too much in the text to be worth a group. */
const TEXT_MIN = 3;
/** Between the lines a ">>" row lists. */
const LINES_JOIN = ' · ';
/** How many items a ">>" offers to add to. */
const APPEND_LIMIT = 5;
/** The types whose body is Markdown: a snippet of any other would read as data. */
const SNIPPET_TYPES: ReadonlySet<LocalNote['type']> = new Set(['note', 'task', 'journal', 'event']);
/** The first line of a Kanban board's body (`kanbanLayout.ts`). */
const KANBAN_BODY = /^> \[!kanban\]/m;
/** The command list's entries that type a prefix instead of running. The
 *  quick add's own command types "+" there, as its other doors do. */
const PREFIX_ENTRY = { tags: 'jump:tags', folders: 'jump:folders', newTag: 'new:tag', newFolder: 'new:folder', quickAdd: 'cmd:quickAdd' } as const;
const PREFIX_OF: Record<string, { prefix: string; creating: boolean }> = {
  [PREFIX_ENTRY.tags]: { prefix: TAG_PREFIX, creating: false },
  [PREFIX_ENTRY.folders]: { prefix: FOLDER_PREFIX, creating: false },
  [PREFIX_ENTRY.newTag]: { prefix: TAG_PREFIX, creating: true },
  [PREFIX_ENTRY.newFolder]: { prefix: FOLDER_PREFIX, creating: true },
  [PREFIX_ENTRY.quickAdd]: { prefix: CREATE_PREFIX, creating: false },
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

/** An item's own icon when it has one, else its section's. */
function ItemIcon({ noteId, fallback: Fallback, size }: { noteId: string; fallback: Icon | undefined; size?: number }) {
  const paths = useNoteIconPaths(noteId);
  if (paths) return <PathGlyph paths={paths} size={size} />;
  return Fallback ? <Fallback size={size} /> : null;
}

/**
 * One key hint of the footer: the keys only, and the word slides out beside
 * them on hover, as the editor's slot pills (EditorSlotPill.tsx) and the
 * sidebar's Ninja button reveal theirs, so the row of hints always fits on
 * one line. A touch screen hides the whole row.
 * Spec: ops/design/patterns/145-150.md section 146
 */
function FooterHint({ keys, children }: { keys: string[]; children: string }) {
  return (
    <span className="group inline-flex shrink-0 items-center" aria-label={children}>
      {keys.map((k, i) => <kbd key={k} className={`${KEYCAP}${i ? ' ms-1' : ''}`} aria-hidden="true">{k}</kbd>)}
      <span aria-hidden="true" className={HINT_WORD}>
        <span className="ps-1.5">{children}</span>
      </span>
    </span>
  );
}
/** The word's reveal: a max-width cap, not a grid track (see EditorSlotPill). */
const HINT_WORD = 'max-w-0 overflow-hidden whitespace-nowrap [@media(hover:hover)]:group-hover:max-w-[12rem] transition-[max-width] duration-150 ease-out';

const optionId = (i: number) => `pn-quick-switcher-${i}`;
const GROUP_RULE = 'mt-1.5 pt-1 border-t border-divider';
/** Sticks to the list's lower edge (or above the pinned row) and takes no room: a negative margin as tall as itself. */
const LIST_FADE = 'pointer-events-none sticky z-10 -mt-8 h-8 bg-gradient-to-t from-surface-2 to-transparent';
const GROUP_HEADER = 'px-3.5 pt-2.5 pb-1 text-[11px] font-semibold uppercase tracking-wider text-accent';
const GROUP_ICONS: Record<PaletteGroup, Icon> = { features: Sparkle, commands: Terminal, new: Plus, goTo: Compass, themes: Palette };
/** A theme row shows once the query is this long: an empty ">" stays short;
 *  without ">" it takes one more letter, so a short title query stays on items. */
const THEMES_MIN = 2;
const THEMES_MIN_JUMP = 3;
/** How many theme rows a name shows without ">"; the word alone shows them all. */
const THEMES_LIMIT = 6;
/** "them" is enough to ask for the themes; "the" is not. */
const THEME_WORD_MIN = 4;
/** A command or a setting that is the query comes first from this length on. */
const TOP_MIN = 3;
/** How many rows the Best match group holds at most. */
const TOP_LIMIT = 3;

type Mark = Pick<TextMatch, 'start' | 'end'> | null | undefined;

function Glyph({ as: C }: { as: ComponentType<IconProps> }) {
  return <C size={16} />;
}

/** The words that ask for the themes: the reader's own, then the English ones. */
function themeWords(t: (key: string, opts?: { lng: string }) => string): string[] {
  const keys = ['palette.groups.themes', 'ninja.themes.word'];
  return [...new Set([...keys.map((k) => t(k)), ...keys.map((k) => t(k, { lng: 'en' }))])];
}

/** A theme's three stripes (sidebar, accent, text), as its Design card shows them, filling the row's tile. */
function ThemeSwatch({ colors }: { colors: readonly string[]; size?: number }) {
  return (
    <span className="flex h-full w-full">
      {colors.map((c, i) => <span key={i} className="flex-1" style={{ backgroundColor: c }} />)}
    </span>
  );
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

type Snippet = { text: string; start: number; end: number } | null;

/**
 * The New menu's kinds the quick add's parser does not read, in that menu's
 * order. Each makes one item from the text as typed: a name, a web address,
 * or nothing. The view hands over the call for each; one it leaves out is
 * not offered. Spec: ops/docs/archive/keyboard-shortcuts.md (section 8.3, item 5)
 */
const MAKERS = [
  { id: 'kanban', glyph: NEW_GLYPHS.kanban, tone: 'task', takes: 'name' },
  { id: 'login', glyph: NEW_GLYPHS.login, tone: 'login', takes: 'name' },
  { id: 'file', glyph: NEW_GLYPHS.file, tone: 'file', takes: 'none' },
  { id: 'contact', glyph: NEW_GLYPHS.contact, tone: 'contact', takes: 'name' },
  { id: 'bookmark', glyph: NEW_GLYPHS.bookmark, tone: 'link', takes: 'url' },
  { id: 'clip', glyph: NEW_GLYPHS.clip, tone: 'link', takes: 'url' },
] as const satisfies readonly { id: string; glyph: Icon; tone: LocalNote['type']; takes: 'name' | 'url' | 'none' }[];
export type MakerId = (typeof MAKERS)[number]['id'];
type Maker = (typeof MAKERS)[number];
type MenuRow = Extract<ContextMenuItem, { onSelect: () => void }>;

type Row =
  | { kind: 'item'; n: LocalNote; m: Mark }
  | { kind: 'text'; n: LocalNote; snippet: Snippet }
  | { kind: 'day'; day: string }
  | { kind: 'append'; n: LocalNote; lines: string[]; asTasks: boolean }
  | { kind: 'appendNew'; title: string; lines: string[] }
  | { kind: 'appendHint'; text: string }
  | { kind: 'appendNone' }
  | { kind: 'action'; item: MenuRow; label: string }
  | { kind: 'make'; maker: Maker; text: string }
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
 *  Spec: ops/docs/archive/calendar-pillar-spec.md (step 8) */
const SYNTAX = [
  { id: 'day', Icon: CalendarBlank },
  { id: 'time', Icon: Clock },
  { id: 'length', Icon: ArrowsHorizontal },
  { id: 'repeat', Icon: Repeat },
  { id: 'alert', Icon: BellSimple },
  { id: 'place', Icon: Hash },
  { id: 'space', Icon: Briefcase },
  { id: 'type', Icon: ListChecks },
  { id: 'append', Icon: ArrowElbowDownRight },
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
 * Spec: ops/docs/archive/keyboard-shortcuts.md (section 8.1, the quick switcher; D14 and D15; the "+" mode, D16 and section 8.3)
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
  bodyOf,
  actionsOf,
  onGoToDay,
  daySection,
  themes,
  onClose,
}: {
  /** ">" opens it in command mode, "+" in the quick add. */
  initialQuery?: string;
  notes: LocalNote[];
  /** The body an item's snippet and a ">>" may read; null behind the PIN. */
  bodyOf: (n: LocalNote) => string | null;
  /** The item's own menu, the one a right click opens: Tab shows it here. */
  actionsOf?: (n: LocalNote) => ContextMenuItem[];
  /** Opens the calendar at a day, for a query that is a date alone. */
  onGoToDay?: (day: string) => void;
  daySection?: { label: string; icon: Icon };
  /**
   * The themes ">" switches by name. A kept pick goes through `pickTheme`, as
   * a card in Settings does; a Pro theme on a free account opens the Design
   * pane, where its preview lives.
   */
  themes?: { unlocked: boolean; customThemes: CustomThemes; onLocked: () => void };
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
   * repeat, alerts, a folder and a tag out of the query. After a "+" typed
   * first (Q, a calendar cell, the New menu, the phone's +) they come first,
   * a cell's day and time fill what the words leave out, and "text >> name"
   * adds the text to an item that exists.
   * Spec: ops/docs/archive/calendar-pillar-spec.md (step 8), ops/docs/archive/quick-add-prefix.md
   */
  quickAdd?: {
    defaultDay?: string;
    time?: string;
    timeEnd?: string;
    folders: readonly { id: string; name: string }[];
    /** Spaces is on, so "@work" means something. */
    spaces: boolean;
    onCreate: (q: QuickAdd, type: QuickAddType) => void;
    /** Adds lines to an item that exists: as tasks to a task list. */
    onAppend: (n: LocalNote, lines: string[], asTasks: boolean) => void;
    /** No item has the name typed after ">>": a new task list of that name. */
    onAppendNew: (title: string, lines: string[]) => void;
    /** The other kinds of the New menu; the text is the name or the address,
     *  or '' when the text is not one. */
    makers: Partial<Record<MakerId, (text: string) => void>>;
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
  const itemLook = useItemLookResolver();
  const [query, setQuery] = useState(initialQuery);
  // Tab on an item lists its own menu in place of the rows; the query typed
  // before comes back with Escape, Shift+Tab or a Backspace on an empty field.
  const [actionsFor, setActionsFor] = useState<{ n: LocalNote; query: string; row: number } | null>(null);
  const leaveActions = () => {
    if (!actionsFor) return;
    setQuery(actionsFor.query);
    setActionsFor(null);
    setActive(actionsFor.row);
  };
  useEscapeToClose(() => (actionsFor ? leaveActions() : onClose()));
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

  // The words that open the quick add as "+" does: English everywhere, and
  // the reader's own from the quick add catalog.
  const hasQuickAdd = !!quickAdd;
  const addWords = useMemo(() => {
    if (!hasQuickAdd) return [];
    const bundle = (lng: string) => (i18n.getResourceBundle(lng, 'quickAdd') as { words?: Record<string, string> } | undefined)?.words;
    const english = bundle('en') ?? {};
    return [...new Set([...readWords(english, english).add, ...readWords(bundle(activeLocale()), english).add])];
  }, [hasQuickAdd]);
  // The first character, or an add word, picks the mode (switcherQuery.ts).
  // After it the quick add's own "#tag" and "/Folder" keep their meaning.
  const typed = readSwitcherQuery(query, !!filters, addWords);
  const read = actionsFor || (typed.mode === 'create' && !quickAdd) ? { mode: 'jump' as const, text: query.trim() } : typed;
  const mode = read.mode;
  const creating = mode === 'create';
  const commandMode = mode === 'commands';
  const scope: 'tags' | 'folders' | null = mode === 'tags' || mode === 'folders' ? mode : null;
  const q = read.text;
  // "milk, eggs >> groc": the Create rows read the text, the Add rows the name.
  // ">>" reads the same with or without the "+": a title seldom holds it.
  const append = useMemo(() => ((creating || (mode === 'jump' && !actionsFor && quickAdd)) ? splitAppend(q) : null), [creating, mode, actionsFor, quickAdd, q]);
  const createText = append ? append.text : q;
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

  // Every theme, by its name, as ">" rows. "theme frost" finds Frost too.
  const { lightTheme, darkTheme, pickTheme } = useTheme();
  const themeEntries = useMemo((): PaletteEntry[] => {
    if (!themes) return [];
    // "Themes Frost Theme Frost": "themes", "theme", "themes frost" and
    // "theme frost" all find it.
    // The reader's own words, and the English ones in every language, as the
    // quick add's "add" word works: a German reader may type "Design" or "theme".
    const words = themeWords(t);
    const out: PaletteEntry[] = [];
    for (const mode of ['light', 'dark'] as const) {
      const current = mode === 'light' ? lightTheme : darkTheme;
      const add = (id: string, name: string, colors: readonly string[], choice: ThemeChoice, pick: ThemeChoice | CustomSnapshot) => {
        const kept = themes.unlocked || isFreeTheme(choice);
        out.push({
          id: `theme:${mode}:${id}`,
          group: 'themes',
          label: name,
          detail: t(`ninja.themes.${mode}`),
          match: words.map((w) => `${w} ${name}`).join(' '),
          glyph: <ThemeSwatch colors={colors} />,
          ...(kept ? {} : { pro: true }),
          ...(current === choice ? { checked: true } : {}),
          run: () => (kept ? pickTheme(mode as Theme, pick) : themes.onLocked()),
        });
      };
      for (const ct of mode === 'light' ? LIGHT_THEMES : DARK_THEMES) add(ct, THEME_DISPLAY_NAME[ct], themeSwatch(ct, mode === 'dark'), ct, ct);
      for (const e of [...teamThemeEntries(), ...customThemeEntries(themes.customThemes)]) {
        if (e.snapshot.mode !== mode) continue;
        const c = e.snapshot.colors;
        add(e.id, e.theme.name, [c['surface-0'], c.accent, c.text].map((x) => x ?? 'transparent'), customChoice(e.id), e.snapshot);
      }
    }
    // The themes on screen first.
    return out.sort((a, b) => Number(!!b.checked) - Number(!!a.checked));
  }, [themes, t, lightTheme, darkTheme, pickTheme]);
  // The commands run last, read once per open: ">" lists them first.
  const [recentCommands] = useState(readRecentCommands);

  const { t: tShell } = useTranslation('shell');
  const readCtx = useMemo(() => {
    if (!quickAdd) return null;
    const locale = intlLocale();
    const sample = formatDay('2026-10-06', 'numeric');
    const order: 'dmy' | 'mdy' | 'ymd' = /^2026/.test(sample) ? 'ymd' : sample.indexOf('6') < sample.indexOf('10') ? 'dmy' : 'mdy';
    const bundle = (lng: string) => (i18n.getResourceBundle(lng, 'quickAdd') as { words?: Record<string, string> } | undefined)?.words;
    return { words: readWords(bundle(activeLocale()), bundle('en') ?? {}), engine: engineWords(locale, order) };
  }, [quickAdd]);
  // In the quick add, the items that hold the title the words leave: "+Dentist
  // fri 3pm" shows the Dentist that exists, so it is opened, not made twice.
  const itemText = useMemo(() => {
    if (!creating || !readCtx || !quickAdd) return q;
    return parseQuickAdd(createText, { ...readCtx, today: toLocalIso(new Date()), folders: quickAdd.folders }).title.trim();
  }, [creating, readCtx, quickAdd, q, createText]);

  const items = useMemo(() => {
    if (commandMode || scope || actionsFor || (q && !itemText)) return [];
    const live = notes.filter((n) => n.trashed !== 1);
    const recentRank = new Map(recentIds.map((id, i) => [id, i]));
    const byRecency = (a: LocalNote, b: LocalNote) =>
      (recentRank.get(a.id) ?? Infinity) - (recentRank.get(b.id) ?? Infinity) ||
      editedAtOf(b).localeCompare(editedAtOf(a));
    if (!q) return [...live].sort(byRecency).slice(0, LIMIT).map((n): Row => ({ kind: 'item', n, m: null }));
    const match = textMatcher(itemText);
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
  }, [commandMode, scope, actionsFor, q, itemText, notes, recentIds, titleOf, files, markdown]);

  // A new function each render from the view; read through a ref so the
  // index is not searched again on every hover.
  const bodyOfRef = useRef(bodyOf);
  bodyOfRef.current = bodyOf;
  // The items that hold the query in their text and not in their title, in
  // the list search's own order (the same index). The index never read a
  // body behind the PIN, and `bodyOf` keeps its snippet out too.
  const textRows = useMemo((): Row[] => {
    if (mode !== 'jump' || actionsFor || q.length < TEXT_MIN || !searchIndexReady()) return [];
    const titled = new Set(items.flatMap((r) => (r.kind === 'item' ? [r.n.id] : [])));
    const byId = new Map(notes.map((n) => [n.id, n]));
    const out: Row[] = [];
    let looked = 0;
    for (const id of searchNotes(q)) {
      // A query that is mostly markup ("[x]") hits thousands of items whose
      // match the reader cannot see; past a few dozen, stop looking.
      if (++looked > TEXT_SCAN) break;
      const n = byId.get(id);
      if (!n || n.trashed === 1 || titled.has(id)) continue;
      const body = bodyOfRef.current(n);
      if (body === null) continue;
      const hit = textHit(body, q, SNIPPET_TYPES.has(n.type));
      if (!hit) continue;
      out.push({ kind: 'text', n, snippet: hit.snippet });
      if (out.length >= TEXT_LIMIT) break;
    }
    return out;
  }, [mode, actionsFor, q, items, notes]);

  // The item's own menu, filtered by what is typed after Tab.
  const actionRows = useMemo((): Row[] => {
    if (!actionsFor || !actionsOf) return [];
    const match = q ? textMatcher(q) : null;
    return actionsOf(actionsFor.n).flatMap((item): Row[] => {
      if (item.type === 'separator' || item.type === 'header' || item.disabled) return [];
      const label = typeof item.label === 'string' ? item.label : '';
      return !match || (label && match(label)) ? [{ kind: 'action', item, label }] : [];
    });
  }, [actionsFor, actionsOf, q]);

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
    // Theme rows in ">" past two characters, so an empty ">" stays short.
    // Without ">" they have a group of their own (themeRows).
    const pool = commandMode && q.length >= THEMES_MIN ? [...entries, ...themeEntries] : entries;
    const found = matchEntries(pool, q).map((entry): Row => ({ kind: 'command', entry, m: match?.(entry.label) }));
    return commandMode ? found : found.slice(0, COMMANDS_LIMIT);
  }, [commandMode, scope, q, entries, themeEntries]);
  // Without ">": the themes that match, in a group of their own, so "theme"
  // lists themes and "frost" finds Frost; the header's button lists them all.
  const { themeRows, themesAsked } = useMemo((): { themeRows: Row[]; themesAsked: boolean } => {
    if (mode !== 'jump' || actionsFor || q.length < THEMES_MIN_JUMP) return { themeRows: [], themesAsked: false };
    const match = textMatcher(q);
    // The word "theme" counts only when the query starts with it: "the" is
    // the start of a title far more often than of a theme's name.
    const asked = themeWords(t).some((w) => foldForMatch(w).startsWith(foldForMatch(q)) || foldForMatch(q).startsWith(foldForMatch(w)));
    const pool = asked && q.length >= THEME_WORD_MIN ? themeEntries : themeEntries.map((e) => ({ ...e, match: undefined }));
    // The word alone ("theme", "themes") asks for the list: all of it.
    const wordOnly = asked && q.length >= THEME_WORD_MIN && !/\s/.test(q.trim());
    const found = matchEntries(pool, q);
    return {
      themeRows: (wordOnly ? found : found.slice(0, THEMES_LIMIT)).map((entry): Row => ({ kind: 'command', entry, m: match(entry.label) })),
      themesAsked: asked && q.length >= THEME_WORD_MIN,
    };
  }, [mode, actionsFor, q, themeEntries, t]);
  // An empty ">" lists the commands run last first, those still offered.
  const recentRows = useMemo((): Row[] => {
    if (!commandMode || q) return [];
    const byId = new Map([...entries, ...themeEntries].map((e) => [e.id, e]));
    return recentCommands.flatMap((id): Row[] => {
      const entry = byId.get(id);
      return entry ? [{ kind: 'command', entry, m: null }] : [];
    });
  }, [commandMode, q, entries, themeEntries, recentCommands]);

  const sectionLabels = useMemo(railLabels, []);
  const settings = useMemo(
    () =>
      !settingsReady || !q || scope
        ? []
        : commandMode
          // In ">", the settings sections by name ("> stats"), each once.
          ? runSettingsSearch(q, sectionLabels)
              .filter((hit) => hit.entry.isSection && !SECTIONS_IN_FEATURES.has(hit.entry.id))
              .map((hit): Row => ({ kind: 'setting', hit }))
          : runSettingsSearch(q, sectionLabels).slice(0, SETTINGS_LIMIT).map((hit): Row => ({ kind: 'setting', hit })),
    [settingsReady, q, commandMode, scope, sectionLabels],
  );

  // Without ">": a command, a theme or a setting whose name is the query
  // comes first, so "lock app" runs Lock app on Enter. One whose name only
  // starts with the query joins it while no item's title starts with it.
  const topRows = useMemo((): Row[] => {
    if (mode !== 'jump' || actionsFor || q.length < TOP_MIN) return [];
    const folded = foldForMatch(q);
    const match = textMatcher(q);
    const itemStarts = items.some((r) => r.kind === 'item' && match(titleOf(r.n))?.rank === 3);
    const hits: { row: Row; exact: boolean }[] = [];
    for (const row of [...commandRows, ...themeRows]) {
      if (row.kind !== 'command' || match(row.entry.label)?.rank !== 3) continue;
      const exact = foldForMatch(row.entry.label) === folded;
      if (exact || !itemStarts) hits.push({ row, exact });
    }
    const named = new Set(hits.map((h) => (h.row.kind === 'command' ? foldForMatch(h.row.entry.label) : '')));
    for (const row of settings) {
      if (row.kind !== 'setting' || row.hit.tier !== 3 || row.hit.rank !== 3 || named.has(foldForMatch(row.hit.label))) continue;
      if (row.hit.exact || !itemStarts) hits.push({ row, exact: row.hit.exact });
    }
    return hits.sort((a, b) => Number(b.exact) - Number(a.exact)).slice(0, TOP_LIMIT).map((h) => h.row);
  }, [mode, actionsFor, q, items, commandRows, themeRows, settings, titleOf]);

  const createRows = useMemo((): Row[] => {
    if (!quickAdd || !readCtx || commandMode || scope || actionsFor || (!q && !creating)) return [];
    // A cell's day and hour belong to the "+" it opened: Backspace over the
    // "+" leaves them behind, and a "+" typed again brings them back.
    const defaultDay = creating ? quickAdd.defaultDay : undefined;
    const parsed = parseQuickAdd(createText, { ...readCtx, today: toLocalIso(new Date()), defaultDay, folders: quickAdd.folders });
    // A cell gave a day (and an hour): it fills what the words leave out.
    if (!parsed.day && defaultDay) parsed.day = defaultDay;
    if (!parsed.time && defaultDay && quickAdd.time && parsed.day === defaultDay) {
      parsed.time = quickAdd.time;
      if (quickAdd.timeEnd) parsed.timeEnd = quickAdd.timeEnd;
    }
    const first: QuickAddType = parsed.type ?? 'event';
    return ([first, ...(['event', 'note', 'task', 'journal'] as const).filter((x) => x !== first)])
      .map((type): Row => ({ kind: 'create', type, parsed }));
  }, [quickAdd, readCtx, commandMode, scope, actionsFor, creating, q, createText]);

  // The rest of the New menu, under the four the parser reads. A web address
  // puts the bookmark and the clip first: that is what a link is typed for.
  const webAddress = creating && !append ? asWebAddress(createText) : null;
  const makeRows = useMemo((): Row[] => {
    if (!creating || append || !quickAdd) return [];
    return MAKERS.filter((m) => quickAdd.makers[m.id]).map((maker): Row => ({
      kind: 'make',
      maker,
      text: maker.takes === 'url' ? (webAddress ?? '') : maker.takes === 'name' ? createText : '',
    }));
  }, [creating, append, quickAdd, createText, webAddress]);

  // A query that is a date and nothing else ("fri", "oct 24", "12/24")
  // goes to that day: the calendar, then the day's journal entry.
  const dayRows = useMemo((): Row[] => {
    if (mode !== 'jump' || actionsFor || !q || !readCtx || !onGoToDay) return [];
    const today = toLocalIso(new Date());
    const day = dayOfQuery(parseQuickAdd(q, { ...readCtx, today, folders: [] }), today);
    if (!day) return [];
    const journal = journalOn(notes.filter((n) => n.trashed !== 1), day);
    return [{ kind: 'day', day }, ...(journal ? [{ kind: 'item', n: journal, m: null } as Row] : [])];
  }, [mode, actionsFor, q, readCtx, onGoToDay, notes]);

  // "text >> name": the items the text can go into, best match first. With no
  // name yet, the day's journal entry and the task lists opened last.
  const appendRows = useMemo((): Row[] => {
    if (!append || !quickAdd) return [];
    const lines = appendLines(append.text);
    if (!lines.length) return [];
    const recentRank = new Map(recentIds.map((id, i) => [id, i]));
    const byRecency = (a: LocalNote, b: LocalNote) =>
      (recentRank.get(a.id) ?? Infinity) - (recentRank.get(b.id) ?? Infinity) ||
      editedAtOf(b).localeCompare(editedAtOf(a));
    // A Kanban board is a task too, but its cards live in columns: a line
    // added at its end would land outside the board.
    const open = notes.filter((n) => {
      if (n.trashed === 1 || n.locked === 1 || (n.type !== 'note' && n.type !== 'task' && n.type !== 'journal')) return false;
      const body = bodyOfRef.current(n);
      return body !== null && !KANBAN_BODY.test(body);
    });
    let targets: LocalNote[];
    if (append.target) {
      const match = textMatcher(append.target);
      targets = open
        .flatMap((n) => {
          const m = match(titleOf(n));
          return m ? [{ n, rank: m.rank }] : [];
        })
        .sort((a, b) => b.rank - a.rank || byRecency(a.n, b.n))
        .map((h) => h.n);
    } else {
      const today = journalOn(open, toLocalIso(new Date()));
      targets = [...(today ? [today] : []), ...open.filter((n) => n.type === 'task').sort(byRecency)];
    }
    // A name no item has: the list it names, made with the lines in it, so
    // the ">>" never ends in nothing.
    if (!targets.length && append.target) return [{ kind: 'appendNew', title: append.target, lines }];
    // No name, and nothing that takes text: say so, and how a list is made.
    if (!targets.length) return [{ kind: 'appendNone' }];
    return targets.slice(0, APPEND_LIMIT).map((n): Row => {
      const asTasks = n.type === 'task';
      return { kind: 'append', n, lines: asTasks ? lines : [append.text], asTasks };
    });
  }, [append, quickAdd, notes, recentIds, titleOf]);
  // Whole sentences, each with what it becomes: a click types it.
  const exampleRows = useMemo((): Row[] => {
    if (!creating || !quickAdd || q || !readCtx) return [];
    return Array.from({ length: EXAMPLES }, (_, k): Row => {
      const text = tShell(`quickAdd.examples.${k + 1}`);
      const parsed = parseQuickAdd(text, { ...readCtx, today: toLocalIso(new Date()), folders: quickAdd.folders });
      return { kind: 'example', n: k + 1, text, parsed };
    });
  }, [creating, quickAdd?.folders, q, readCtx, tShell]);
  const syntaxRows = useMemo(
    (): Row[] => (creating && quickAdd && !q
      ? SYNTAX.filter((s) => s.id !== 'space' || quickAdd.spaces).map((s): Row => ({ kind: 'syntax', id: s.id }))
      : []),
    [creating, quickAdd, q],
  );

  const groups = useMemo((): Group[] => {
    if (commandMode) {
      const recent = new Set(recentRows.map((r) => (r.kind === 'command' ? r.entry.id : '')));
      return [
        { header: t('ninja.recent'), rows: recentRows },
        ...GROUP_ORDER.map((g) => ({
          header: t(`palette.groups.${g}`),
          rows: commandRows.filter((r) => r.kind === 'command' && r.entry.group === g && !recent.has(r.entry.id)),
        })),
        { header: t('settings:shell.title'), rows: settings.filter((r) => !(r.kind === 'setting' && commandRows.some((c) => c.kind === 'command' && foldForMatch(c.entry.label) === foldForMatch(r.hit.label)))) },
      ].filter((g) => g.rows.length);
    }
    const tagGroup: Group = { header: t('quickSwitcher.tags'), rows: tagRows, only: { prefix: TAG_PREFIX, label: t('quickSwitcher.showOnlyTags') } };
    const folderGroup: Group = { header: t('quickSwitcher.folders'), rows: folderRows, only: { prefix: FOLDER_PREFIX, label: t('quickSwitcher.showOnlyFolders') } };
    if (scope) {
      const found = { ...(scope === 'tags' ? tagGroup : folderGroup), only: undefined };
      const make = { header: tShell('quickAdd.group'), rows: newFilterRows };
      return (creatingFilter ? [make, found] : [found, make]).filter((g) => g.rows.length);
    }
    if (actionsFor) return [{ header: titleOf(actionsFor.n), rows: actionRows }];
    // A web address gets a group of its own above Create, which says what
    // the two rows are for; each row says what it keeps.
    // A login saves a site's address too, so it joins them, after the two
    // a link is mostly typed for: Enter still makes the bookmark.
    const linkRows = webAddress
      ? [
          ...makeRows.filter((r) => r.kind === 'make' && r.maker.takes === 'url'),
          ...makeRows.filter((r) => r.kind === 'make' && r.maker.id === 'login'),
        ]
      : [];
    // The way to ">>" where it is needed: typed text in the quick add, with
    // no ">>" yet, ends with a row that types it.
    const hint: Row[] = creating && q && !append && !webAddress ? [{ kind: 'appendHint', text: createText }] : [];
    // The doors that make something outside the items (a medication, a
    // tracker) close the Create group of "+".
    const doors: Row[] = creating && !append && !webAddress
      ? entries.filter((e) => e.inCreate).map((entry): Row => ({ kind: 'command', entry, m: null }))
      : [];
    const create = {
      header: tShell('quickAdd.group'),
      rows: [...createRows, ...makeRows.filter((r) => !linkRows.includes(r)), ...doors, ...hint],
    };
    const top = new Set(topRows);
    // Asked for by the word ("theme"), the themes come right after the best match.
    const themeGroup: Group = { header: t('palette.groups.themes'), rows: themeRows.filter((r) => !top.has(r)), only: { prefix: COMMAND_PREFIX, label: t('ninja.allThemes') } };
    // A Features row and its settings section share a name: the row shows once.
    const commandNames = new Set([...topRows, ...commandRows, ...themeRows].flatMap((r) => (r.kind === 'command' ? [foldForMatch(r.entry.label)] : [])));
    const settingRows = settings.filter((r) => !top.has(r) && !(r.kind === 'setting' && commandNames.has(foldForMatch(r.hit.label))));
    return [
      { header: t('ninja.topHit'), rows: topRows },
      ...(themesAsked ? [themeGroup] : []),
      // A date alone: the day first, before any title that holds the word.
      { header: t('quickSwitcher.goToDay'), rows: dayRows },
      // With ">>", with or without the "+": the items the text can go into.
      { header: tShell('quickAdd.addTo'), rows: appendRows },
      // Under an empty quick add: Create, then what it reads, then the recent items.
      ...(creating
        ? [{ header: tShell('quickAdd.linkGroup'), rows: linkRows }, create, { header: tShell('quickAdd.examplesGroup'), rows: exampleRows }, { header: tShell('quickAdd.syntax.group'), rows: syntaxRows }]
        : []),
      { header: q ? (creating || dayRows.length ? tShell('quickAdd.items') : undefined) : t('quickSwitcher.recent'), rows: items },
      { header: t('quickSwitcher.inText'), rows: textRows },
      tagGroup,
      folderGroup,
      { header: t('palette.label'), rows: commandRows.filter((r) => !top.has(r)), only: { prefix: COMMAND_PREFIX, label: t('quickSwitcher.showOnlyCommands') } },
      { header: t('settings:shell.title'), rows: settingRows },
      // Found by a name, the themes follow the settings ("dark" finds Mode first).
      ...(themesAsked ? [] : [themeGroup]),
      // Explicit under the hits: Enter on a hit still opens the hit.
      ...(creating ? [] : [create]),
    ].filter((g) => g.rows.length);
  }, [commandMode, scope, creatingFilter, q, items, tagRows, folderRows, newFilterRows, commandRows, themeRows, themesAsked, recentRows, topRows, entries, settings, t, tShell, createRows, exampleRows, syntaxRows, creating, actionsFor, actionRows, titleOf, dayRows, appendRows, textRows, makeRows, webAddress, append, createText]);

  const searchRow = !!listSearch && !!q && !commandMode && !scope && !actionsFor && !creating;
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
  // The fade at the list's lower edge: its offset above the pinned search
  // row while more rows sit below, null at the bottom.
  const listRef = useRef<HTMLDivElement>(null);
  const pinRef = useRef<HTMLDivElement>(null);
  const [fadeAt, setFadeAt] = useState<number | null>(null);
  const measureFade = useCallback(() => {
    const el = listRef.current;
    if (!el) return;
    const below = el.scrollHeight - el.scrollTop - el.clientHeight > 1;
    setFadeAt(below ? (pinRef.current?.offsetHeight ?? 0) : null);
  }, []);
  useLayoutEffect(measureFade, [rows, measureFade]);
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

  /** The item a row stands for, when Tab can list its menu. */
  const noteAt = (i: number): LocalNote | null => {
    const row = rows[i];
    return actionsOf && !actionsFor && (row?.kind === 'item' || row?.kind === 'text') ? row.n : null;
  };
  const enterActions = (n: LocalNote, row = at) => {
    setActionsFor({ n, query, row });
    setQuery('');
    setActive(0);
    setActionAt({ row: -1, which: 0 });
  };

  /** Open a row. A bookmark row opens its link unless `edit` asks for the
   *  bookmark itself, as a tab does. */
  const open = (i: number, inTab: boolean, edit = false) => {
    const row = rows[i];
    if (!row) return;
    // A syntax row types its example and keeps the quick add open.
    if (row.kind === 'example') {
      setQuery(`${CREATE_PREFIX}${row.text}`);
      setActive(0);
      return;
    }
    // A line that says why nothing can be added: it keeps the switcher open.
    if (row.kind === 'appendNone') return;
    if (row.kind === 'appendHint') {
      setQuery(`${query.trimEnd()} >> `);
      setActive(0);
      return;
    }
    if (row.kind === 'syntax') {
      const insert = tShell(`quickAdd.syntax.${row.id}.insert`);
      setQuery(`${CREATE_PREFIX}${/[#/@]$/.test(insert) ? insert : `${insert} `}`);
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
    if (row.kind === 'action') row.item.onSelect();
    else if (row.kind === 'day') onGoToDay!(row.day);
    else if (row.kind === 'append') quickAdd!.onAppend(row.n, row.lines, row.asTasks);
    else if (row.kind === 'appendNew') quickAdd!.onAppendNew(row.title, row.lines);
    else if (row.kind === 'make') quickAdd!.makers[row.maker.id]?.(row.text);
    else if (row.kind === 'text') onOpen(row.n, inTab && canOpenInTab);
    else if (link && row.kind === 'item' && !inTab) {
      if (edit && onEditLink) onEditLink(row.n);
      else openExternal(link);
    } else if (row.kind === 'item') onOpen(row.n, inTab && canOpenInTab);
    else if (row.kind === 'file') onOpenFile(row.f);
    else if (row.kind === 'markdown') onOpenMarkdown(row.e);
    else if (row.kind === 'command') {
      noteRecentCommand(row.entry.id);
      row.entry.run();
    }
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
    opts: { keys?: string; accent?: boolean; tone?: string; toneStyle?: CSSProperties; rowStyle?: CSSProperties; strong?: boolean; link?: boolean; more?: () => void; ownText?: 'title' | 'both' } = {},
  ) => {
    const selected = i === at;
    // The "Search everything" row wears an accent title: it is the one row
    // that is not a jump but a search of the text of every item.
    // An item's title is bold, as in the list; a command or a setting is not.
    const { keys, accent, tone = ACCENT_TONE, toneStyle, rowStyle, strong } = opts;
    return (
      <div
        key={key}
        id={optionId(i)}
        role="option"
        aria-selected={selected}
        onMouseMove={(e) => hover(i, e)}
        onMouseDown={(e) => e.preventDefault()}
        onClick={(e) => open(i, e.altKey)}
        style={rowStyle}
        className={`relative mx-1.5 flex items-center gap-3 rounded-md px-2 py-1.5 cursor-pointer ${selected ? 'bg-accent/10 before:absolute before:inset-y-1.5 before:start-0 before:w-[3px] before:rounded-full before:bg-accent' : ''}`}
      >
        <span className={`flex w-7 h-7 shrink-0 items-center justify-center rounded-md ${tone}`} style={toneStyle} aria-hidden="true">
          {/* A component, or a ready-made glyph redrawn at the tile's size. */}
          {isValidElement(RowIcon) ? cloneElement(RowIcon as ReactElement<IconProps>, { size: 16 }) : RowIcon ? <Glyph as={RowIcon as ComponentType<IconProps>} /> : null}
        </span>
        <div className="min-w-0 flex-1">
          {/* An item's own words take their own direction, as the list's title
              does: an Arabic title right-aligned under an English interface. */}
          <div dir={opts.ownText ? 'auto' : undefined} className={`truncate text-[14px] leading-5 ${accent ? 'font-medium text-accent' : 'text-pn'} ${strong ? 'font-semibold' : ''}`}>{title}</div>
          {detail && <div dir={opts.ownText === 'both' ? 'auto' : undefined} className="truncate text-[12px] leading-4 text-pn-muted">{detail}</div>}
        </div>
        {/* The item's own menu, as Tab lists it: a touch screen has no Tab,
            so every item row shows the button there; a pointer sees it on
            the selected row. */}
        {opts.more && (
          <button
            type="button"
            tabIndex={-1}
            onMouseDown={(e) => e.preventDefault()}
            onClick={(e) => {
              e.stopPropagation();
              opts.more!();
            }}
            aria-label={tShell('selectionToolbar.more')}
            className={`${selected ? 'inline-flex' : 'hidden [@media(hover:none)]:inline-flex'} w-8 h-8 shrink-0 items-center justify-center rounded-md text-pn-muted hover:text-pn hover:bg-pn/5`}
          >
            <DotsThreeOutlineVertical size={16} aria-hidden="true" />
          </button>
        )}
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

  // An item's own color (or its tag's or folder's), as the list row shows it:
  // the tile and its icon take the color, and a background look tints the
  // row under the selection.
  const lookOf = (n: LocalNote) => {
    const { row, icon } = itemLook(n);
    return { toneStyle: icon, rowStyle: row };
  };
  /** Opens row `i`'s own menu, where Tab could: the "..." of a touch screen. */
  const moreFor = (i: number) => {
    const n = noteAt(i);
    return n ? () => enterActions(n, i) : undefined;
  };
  const renderRow = (row: Row, i: number): ReactNode => {
    if (row.kind === 'item') {
      const view = sectionOf(row.n);
      return option(
        i,
        row.n.id,
        <ItemIcon noteId={row.n.id} fallback={view?.icon} />,
        <Highlighted text={titleOf(row.n)} mark={row.m} />,
        <>
          {view?.label}
          {view?.label ? ' · ' : ''}
          {formatRelative(editedAtOf(row.n))}
        </>,
        { tone: toneOf(row.n.type), ...lookOf(row.n), strong: true, link: !!linkOf?.(row.n), more: moreFor(i), ownText: 'title' },
      );
    }
    if (row.kind === 'text') {
      const view = sectionOf(row.n);
      // The line that holds the query, where the title would show the date.
      return option(
        i,
        `text:${row.n.id}`,
        <ItemIcon noteId={row.n.id} fallback={view?.icon} />,
        titleOf(row.n),
        row.snippet
          ? <Highlighted text={row.snippet.text} mark={row.snippet} />
          : <>{view?.label}{view?.label ? ' · ' : ''}{formatRelative(editedAtOf(row.n))}</>,
        { tone: toneOf(row.n.type), ...lookOf(row.n), strong: true, more: moreFor(i), ownText: row.snippet ? 'both' : 'title' },
      );
    }
    if (row.kind === 'day') {
      return option(i, `day:${row.day}`, CalendarDot, formatDay(row.day, 'weekdayDate'), daySection?.label, { tone: toneOf('event') });
    }
    if (row.kind === 'append') {
      const title = titleOf(row.n);
      const label = row.asTasks
        ? tShell('quickAdd.addTasks', { count: row.lines.length, title })
        : tShell('quickAdd.addLine', { title });
      // " · " between the tasks: a task's own comma ("socks, warm") stays readable.
      return option(i, `append:${row.n.id}`, ArrowElbowDownRight, label, row.lines.join(LINES_JOIN), { tone: toneOf(row.n.type), strong: true });
    }
    if (row.kind === 'appendHint') {
      return option(
        i,
        'append-hint',
        ArrowElbowDownRight,
        tShell('quickAdd.appendHint', { text: row.text }),
        tShell('quickAdd.appendHintDetail'),
        { keys: '>>' },
      );
    }
    if (row.kind === 'appendNone') {
      return option(i, 'append-none', ArrowElbowDownRight, tShell('quickAdd.appendNone'), tShell('quickAdd.appendNoneDetail'));
    }
    if (row.kind === 'appendNew') {
      return option(
        i,
        'append-new',
        typeGlyph('task').Icon,
        tShell('quickAdd.newListWith', { count: row.lines.length, title: row.title }),
        row.lines.join(LINES_JOIN),
        { tone: toneOf('task'), strong: true },
      );
    }
    if (row.kind === 'make') {
      const { maker, text } = row;
      const type = tShell(`quickAdd.types.${maker.id}`);
      // Under "Save this link": the address is in the field, so the row names
      // what it does with it.
      const linkRow = (maker.takes === 'url' && !!text) || (maker.id === 'login' && !!webAddress);
      return option(
        i,
        `make-${maker.id}`,
        maker.glyph,
        linkRow ? type : text ? tShell('quickAdd.createNamed', { type, title: text }) : type,
        linkRow ? tShell(`quickAdd.linkDetail.${maker.id}`) : null,
        { tone: toneOf(maker.tone), strong: true },
      );
    }
    if (row.kind === 'action') {
      const { item } = row;
      // The Pro word and the check that says which way a switch is set, as
      // the right-click menu draws them.
      return option(
        i,
        `action:${i}`,
        item.icon,
        <span className="inline-flex items-center gap-2">
          <span className={item.destructive ? 'text-danger' : undefined}>{item.label}</span>
          {item.pro && <span className="text-[11px] font-semibold text-accent">Pro</span>}
          {item.checked && <Check size={14} className="text-accent" aria-hidden="true" />}
        </span>,
        null,
        { keys: item.shortcut },
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
      // The Pro mark and the check of the right-click menu; a theme's tile is its stripes.
      return option(
        i,
        entry.id,
        entry.glyph ?? entry.icon ?? GROUP_ICONS[entry.group],
        entry.pro || entry.checked ? (
          <span className="inline-flex items-center gap-2">
            {/* One flex child: the mark splits the label into pieces, and the gap would open between them. */}
            <span><Highlighted text={entry.label} mark={row.m} /></span>
            {entry.pro && <ProMark />}
            {entry.checked && <Check size={14} className="text-accent" aria-hidden="true" />}
          </span>
        ) : <Highlighted text={entry.label} mark={row.m} />,
        entry.detail ?? null,
        { keys: entry.keys, ...(entry.group === 'themes' ? { tone: 'overflow-hidden border border-divider' } : {}) },
      );
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
        // A press on a header, a rule or the footer keeps the caret in the
        // field, so the next key still types the query.
        onMouseDown={(e) => {
          if (!(e.target as HTMLElement).closest('input, button, a')) e.preventDefault();
        }}
        className="w-full max-w-xl bg-surface-2 border border-divider rounded-lg shadow-xl overflow-hidden"
      >
        <div className="flex items-center gap-2.5 px-3.5 border-b border-divider">
          {/* The mark in its real colors, where the rows below show theirs:
              the box says its own name. Spec: ops/design/patterns/145-150.md
              section 146 */}
          {/* The mark plays the sidebar button's katana cut once each time
              the box opens: the animation runs on mount. */}
          <span className="pn-ninja-open relative flex shrink-0 overflow-hidden rounded-md" aria-hidden="true">
            <span className="pn-jump-charge" />
            <NinjaIcon size={28} tone="real" />
          </span>
          {/* Commands, dates and names, not prose: no red lines, no autocorrect. */}
          <input
            autoFocus
            spellCheck={false}
            autoCorrect="off"
            autoComplete="off"
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
              } else if (e.key === 'Tab' && !e.shiftKey && noteAt(at)) {
                // Tab lists the selected item's own menu in place of the rows.
                e.preventDefault();
                enterActions(noteAt(at)!);
              } else if (actionsFor && ((e.key === 'Tab' && e.shiftKey) || (e.key === 'Backspace' && !query))) {
                e.preventDefault();
                leaveActions();
              } else if (actionsFor && e.key === 'Tab') {
                // Already in the menu: the focus stays in the field.
                e.preventDefault();
              } else if (e.key === 'Enter') {
                e.preventDefault();
                if (searchRow && (KEY_OS === 'mac' ? e.metaKey : e.ctrlKey)) open(searchIndex, false);
                else open(at, e.altKey, e.shiftKey || action === 1);
              }
            }}
            placeholder={actionsFor ? t('quickSwitcher.actionsPlaceholder') : t('quickSwitcher.placeholder')}
            aria-label={creating ? tShell('quickAdd.placeholder') : t('quickSwitcher.placeholder')}
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
        <div id="pn-quick-switcher-list" ref={listRef} onScroll={measureFade} role="listbox" className="max-h-[max(33vh,15rem)] overflow-y-auto pt-1 [&:not(:has(.sticky))]:pb-1">
          {count === 0 && (
            <div className="px-3.5 py-3 text-[13px] text-pn-muted">
              {t(emptyMessage(mode, query, !!quickAdd))}
            </div>
          )}
          {groups.map((g, gi) => {
            const headerId = `pn-quick-switcher-group-${gi}`;
            return (
              <div key={gi} role="group" aria-labelledby={g.header ? headerId : undefined}>
                {g.header && (
                  <div className={`flex items-center justify-between gap-2 pe-3.5 ${gi ? GROUP_RULE : ''}`}>
                    {/* The menu of the item goes back to the rows by a button too:
                        Shift+Tab and Escape need a keyboard. */}
                    {actionsFor && gi === 0 ? (
                      <button
                        type="button"
                        tabIndex={-1}
                        onMouseDown={(e) => e.preventDefault()}
                        onClick={leaveActions}
                        aria-label={t('actions.back')}
                        className="ms-1.5 mt-1.5 inline-flex min-w-0 items-center gap-1 rounded-md pe-1.5 text-pn-muted hover:text-pn hover:bg-pn/5"
                      >
                        <ArrowLeft size={14} className="ms-1.5 shrink-0" aria-hidden="true" />
                        <span id={headerId} className={`${GROUP_HEADER} truncate !ps-0.5 !pt-1`}>{g.header}</span>
                      </button>
                    ) : (
                      <div id={headerId} className={GROUP_HEADER}>{g.header}</div>
                    )}
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
          {/* More rows below: the lower edge fades, above the pinned search
              row, so a group header at the edge never reads as an empty group. */}
          {fadeAt !== null && (
            <div aria-hidden="true" className={LIST_FADE} style={{ bottom: fadeAt }} />
          )}
          {/* Pinned under the scrolling rows, so it is in view at any length. */}
          {searchRow && (
            <div ref={pinRef} className={`sticky bottom-0 py-1 bg-surface-2 ${groups.length ? 'mt-1 border-t border-divider' : '-mt-1'}`}>
              {searchRows.map((row) => renderRow(row, index++))}
            </div>
          )}
        </div>
        {/* Key hints only: a touch screen has no keys to name. */}
        <div className="flex flex-nowrap gap-x-2.5 px-3.5 py-2 border-t border-divider text-[12px] text-pn-muted [@media(hover:none)]:hidden">
          <FooterHint keys={['↑', '↓']}>{t('quickSwitcher.move')}</FooterHint>
          <FooterHint keys={['↵']}>{t('quickSwitcher.open')}</FooterHint>
          {selectedLink && <FooterHint keys={['⇧↵']}>{t('quickSwitcher.edit')}</FooterHint>}
          {noteAt(at) && <FooterHint keys={['Tab']}>{t('quickSwitcher.actions')}</FooterHint>}
          {actionsFor && <FooterHint keys={['⇧Tab']}>{t('quickSwitcher.back')}</FooterHint>}
          {canOpenInTab && !commandMode && !scope && !actionsFor && !creating && (
            <FooterHint keys={[KEY_OS === 'mac' ? '⌥↵' : 'Alt+↵']}>{t('quickSwitcher.openInTab')}</FooterHint>
          )}
          {/* The prefixes, named while the field is empty and they can be typed. */}
          {quickAdd && !query && !actionsFor && <FooterHint keys={[CREATE_PREFIX]}>{t('quickSwitcher.onlyCreate')}</FooterHint>}
          {filters && !query && !actionsFor && (
            <>
              <FooterHint keys={[TAG_PREFIX]}>{t('quickSwitcher.onlyTags')}</FooterHint>
              {filters.folders.length > 0 && <FooterHint keys={[FOLDER_PREFIX]}>{t('quickSwitcher.onlyFolders')}</FooterHint>}
            </>
          )}
          <FooterHint keys={['Esc']}>{t('quickSwitcher.close')}</FooterHint>
          {/* The key's memory trick, at the free end of the row. */}
          <span className="ms-auto inline-flex min-w-0 items-center gap-1.5 self-center ps-2 text-[13px] font-semibold text-pn-soft" dir="ltr">
            <kbd className={KEYCAP}>{KEY_OS === 'mac' ? '⌘K' : 'Ctrl+K'}</kbd>
            <span className="truncate">{KATANA_LINE}</span>
          </span>
        </div>
      </div>
    </div>
  );
}
