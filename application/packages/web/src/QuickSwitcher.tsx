import { cloneElement, isValidElement, useEffect, useMemo, useState, type ComponentType, type ReactElement, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type { LocalNote } from './db';
import type { FileItem } from './FilesList';
import type { DirectoryEntry } from './markdownFolder/fileAccess';
import { editedAtOf } from './notesViewUtils';
import { useEscapeToClose } from './useEscapeToClose';
import { isImeComposing } from './imeComposing';
import { textMatcher, type TextMatch } from './textMatch';
import { formatRelative } from './intlFormat';
import { activeLocale, ensureSettingsSearchLoaded } from './i18n';
import { ArrowSquareOut, Compass, MagnifyingGlass, Plus, Terminal, X, type Icon, type IconProps } from './icons';
import { HoverLabel } from './HoverLabel';
import { helpPath } from './localeRoutes';
import { openExternal } from './openExternal';
import { siteHref } from './siteLinks';
import { APP_KEYS, KEY_OS, matchesKey } from './shortcutMatch';
import { COMMAND_PREFIX, GROUP_ORDER, matchEntries, type PaletteEntry, type PaletteGroup } from './commandPalette';
import type { SectionId, SettingEntry } from './settingsSearch/registry';
import { railLabels, runSettingsSearch, tabOf } from './settingsSearch/SettingsSearchResults';

/** How many items the list shows at most. */
const LIMIT = 30;
/** How many settings show under the items at most. */
const SETTINGS_LIMIT = 10;
/** How many commands show under the items when the query has no ">". */
const COMMANDS_LIMIT = 3;

const KEYCAP = 'inline-flex min-w-6 h-6 shrink-0 items-center justify-center rounded-md border border-b-2 border-divider bg-surface-1 px-1.5 font-sans text-[13px] font-medium leading-none text-pn';

/**
 * The icon tile's color for each kind of item, so a vault entry or a
 * bookmark reads apart from a note before its title does. A kind not listed
 * keeps the accent.
 */
const KIND_TONE = {
  vault: 'bg-warning/15 text-warning',
  link: 'bg-success/15 text-success',
  task: 'bg-violet-500/15 text-violet-600 dark:text-violet-400',
  journal: 'bg-rose-500/15 text-rose-600 dark:text-rose-400',
  file: 'bg-teal-500/15 text-teal-600 dark:text-teal-400',
  contact: 'bg-sky-500/15 text-sky-600 dark:text-sky-400',
} as const;
const ACCENT_TONE = 'bg-accent/10 text-accent';

function toneOf(type: LocalNote['type']): string {
  if (type === 'login' || type === 'card' || type === 'ssh-key') return KIND_TONE.vault;
  return type === 'note' ? ACCENT_TONE : KIND_TONE[type];
}

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
  | { kind: 'setting'; hit: ReturnType<typeof runSettingsSearch>[number] }
  | { kind: 'search'; everything: boolean };

/** A run of rows under one header; the first group draws no rule above it. */
type Group = { header?: string; rows: Row[] };

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
 * in their groups. Every other way into command mode (">" in the list search
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
  sectionIcons,
  onOpenSetting,
  listSearch,
  commands,
  files,
  filesSection,
  onOpenFile,
  markdown,
  onOpenMarkdown,
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
  onClose: () => void;
}) {
  const { t } = useTranslation('common');
  useEscapeToClose(onClose);
  const [query, setQuery] = useState(initialQuery);
  const [active, setActive] = useState(0);
  // The settings search also reads the keyword lists, which load here.
  const [settingsReady, setSettingsReady] = useState(false);
  useEffect(() => {
    void ensureSettingsSearchLoaded()
      .catch((err) => console.warn('[switcher] settings search failed to load:', err))
      .then(() => setSettingsReady(true));
  }, []);

  const commandMode = query.startsWith(COMMAND_PREFIX);
  const q = (commandMode ? query.slice(COMMAND_PREFIX.length) : query).trim();
  // Read once per open: the list is what the app could run when it opened.
  // The switcher's own entry is left out, since it is already open.
  const [entries] = useState(() => commands().filter((e) => e.id !== 'cmd:quickSwitcher'));

  const items = useMemo(() => {
    if (commandMode) return [];
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
  }, [commandMode, q, notes, recentIds, titleOf, files, markdown]);

  const commandRows = useMemo(() => {
    if (!commandMode && !q) return [];
    const match = q ? textMatcher(q) : null;
    const found = matchEntries(entries, q).map((entry): Row => ({ kind: 'command', entry, m: match?.(entry.label) }));
    return commandMode ? found : found.slice(0, COMMANDS_LIMIT);
  }, [commandMode, q, entries]);

  const sectionLabels = useMemo(railLabels, []);
  const settings = useMemo(
    () =>
      settingsReady && q && !commandMode
        ? runSettingsSearch(q, sectionLabels).slice(0, SETTINGS_LIMIT).map((hit): Row => ({ kind: 'setting', hit }))
        : [],
    [settingsReady, q, commandMode, sectionLabels],
  );

  const groups = useMemo((): Group[] => {
    if (commandMode) {
      return GROUP_ORDER.map((g) => ({
        header: t(`palette.groups.${g}`),
        rows: commandRows.filter((r) => r.kind === 'command' && r.entry.group === g),
      })).filter((g) => g.rows.length);
    }
    return [
      { header: q ? undefined : t('quickSwitcher.recent'), rows: items },
      { header: t('palette.label'), rows: commandRows },
      { header: t('settings:shell.title'), rows: settings },
    ].filter((g) => g.rows.length);
  }, [commandMode, q, items, commandRows, settings, t]);

  const searchRow = !!listSearch && !!q && !commandMode;
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

  const open = (i: number, inTab: boolean) => {
    const row = rows[i];
    if (!row) return;
    onClose();
    if (row.kind === 'item') onOpen(row.n, inTab && canOpenInTab);
    else if (row.kind === 'file') onOpenFile(row.f);
    else if (row.kind === 'markdown') onOpenMarkdown(row.e);
    else if (row.kind === 'command') row.entry.run();
    else if (row.kind === 'search') listSearch!.run(q, row.everything);
    // The help center is a site, not a pane, as it is in the settings rail.
    else if (row.hit.entry.section === 'help') openExternal(siteHref(helpPath(activeLocale())));
    else onOpenSetting(row.hit.entry);
  };

  /** Mod+Enter runs the list search from any row, so it never needs the arrows. */
  const searchKeys = KEY_OS === 'mac' ? '⌘↵' : 'Ctrl+↵';

  const option = (
    i: number,
    key: string,
    RowIcon: ComponentType<IconProps> | ReactNode | undefined,
    title: ReactNode,
    detail: ReactNode,
    opts: { keys?: string; accent?: boolean; tone?: string; strong?: boolean } = {},
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
        onMouseEnter={() => setActive(i)}
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
        {(keys || selected) && (
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
        { tone: toneOf(row.n.type), strong: true },
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
        { tone: KIND_TONE.file, strong: true },
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
              setActive(0);
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
              } else if (e.key === 'Enter') {
                e.preventDefault();
                if (searchRow && (KEY_OS === 'mac' ? e.metaKey : e.ctrlKey)) open(searchIndex, false);
                else open(at, e.altKey);
              }
            }}
            placeholder={t('quickSwitcher.placeholder')}
            aria-label={t('quickSwitcher.placeholder')}
            role="combobox"
            aria-expanded
            aria-controls="pn-quick-switcher-list"
            aria-activedescendant={count ? optionId(at) : undefined}
            className="flex-1 min-w-0 h-12 bg-transparent text-[15px] text-pn placeholder:text-pn-muted outline-none"
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
            <div className="px-3.5 py-3 text-[13px] text-pn-muted">{t(commandMode ? 'palette.empty' : 'quickSwitcher.empty')}</div>
          )}
          {groups.map((g, gi) => {
            const headerId = `pn-quick-switcher-group-${gi}`;
            return (
              <div key={gi} role="group" aria-labelledby={g.header ? headerId : undefined}>
                {g.header && (
                  <div id={headerId} className={`${GROUP_HEADER} ${gi ? GROUP_RULE : ''}`}>
                    {g.header}
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
          {canOpenInTab && !commandMode && (
            <span className="inline-flex items-center gap-1"><kbd className={KEYCAP}>{KEY_OS === 'mac' ? '⌥↵' : 'Alt+↵'}</kbd> {t('quickSwitcher.openInTab')}</span>
          )}
          <span className="inline-flex items-center gap-1"><kbd className={KEYCAP}>Esc</kbd> {t('quickSwitcher.close')}</span>
        </div>
      </div>
    </div>
  );
}
