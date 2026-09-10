import { Fragment, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { usePointMenuPosition } from './usePopoverPosition';
import { VERSION } from './version';
import { LogoIcon } from './LogoIcon';
import { Brand } from './Brand';
import { HoverLabel } from './HoverLabel';
import { SortRow } from './ListPrefsPopover';
import { useEscapeToClose } from './useEscapeToClose';
import { SidebarOptionsPopover } from './SidebarOptionsPopover';
import { allViewRows, sidebarViewRows } from './viewRows';
import { TAG_MAX_LENGTH } from './notesRepo';
import type { UserSettings } from './userSettings';
import type { FolderDef } from './folders';
import { FolderTree, type FolderTreeProps } from './FolderTree';
import type { FolderSortDir, FolderSortField } from './folders';
import { IconUpgrade } from './UpgradeModal';
import { Star, Hash, DotsThree, PencilSimple, Trash, X, CaretDown, SquaresFour, List, Sparkle, PushPin, File, NotePencil, CheckFat, Shield, Key, Folder, Book, Notebook, FunnelSimple, Eye, Download, Plus, Prohibit, Chat, Devices, Question, FileMd, Bookmarks, type Icon, PILLAR_GLYPHS } from './icons';
import { isViewShown, type View } from './views';
import { exemptOpts } from './i18nExempt';
import { SIDEBAR_ACTIVE } from './sidebarUI';
import { marketingHomeHref, siteHref } from './siteLinks';
import { useUpdateAvailable } from './updateAvailable';
import { UpdateDot } from './UpdateDot';
import { helpPath } from './localeRoutes';
import { activeLocale } from './languages';

// ── Types ──────────────────────────────────────────────────────────────

type TagSortField = 'name' | 'modified' | 'entries';
type TagSortDir = 'asc' | 'desc';

interface OpenTagMenu {
  tag: string;
  /** Desired top-left corner in viewport coords; clamped on-screen at render. */
  x: number;
  y: number;
}

export interface TagsRailProps {
  // View state
  view: View;
  selectedTag: string | null;
  handleSelectView: (next: View) => void;
  handleSelectTag: (tag: string | null) => void;

  // Drawer
  setDrawerOpen: (open: boolean) => void;

  // About modal
  setShowAbout: (v: false | { tab?: 'about' | 'changelog' | 'hotkeys' }) => void;

  // Feedback modal
  onFeedback: () => void;

  // Rate modal
  onRate: () => void;

  // Views collapse
  viewsCollapsed: boolean;
  setViewsCollapsed: React.Dispatch<React.SetStateAction<boolean>>;

  /** Item count per pillar row, looked up by view. An absent entry draws no
   *  count at all, which is not the same as a zero: the Markdown pillar scans
   *  nothing until a folder is chosen, and a "0" there would read as an empty
   *  folder rather than an unconfigured one.
   *  Spec: ops/docs/plans/start-view.md (one counts object) */
  viewCounts: Partial<Record<View, number>>;
  trashedCount: number;

  // Tag counts + tag lists
  tagCounts: { tags: [string, number][]; untagged: number };
  favoriteTagsList: [string, number][];
  nonFavoriteTagsList: [string, number][];

  // Browse mode - Tags vs Folders. Every account can SEE the folder tree
  // and browse it; the Pro gate sits on each folder ACTION (create,
  // rename, move, delete, file a note), not on the view.
  browseMode: 'tags' | 'folders';
  onBrowseChange: (mode: 'tags' | 'folders') => void;
  /** Drives the gold rocket on the Folders segment (shown while not Pro). */
  isPro: boolean;

  // Folder tree (rendered when browseMode === 'folders')
  folders: FolderDef[];
  folderCounts: Map<string, number>;
  unfiledCount: number;
  selectedFolder: string | null;
  onSelectFolder: (id: string | null) => void;
  onCreateFolder: FolderTreeProps['onCreateFolder'];
  onRenameFolder: FolderTreeProps['onRenameFolder'];
  onRequestMoveFolder: FolderTreeProps['onRequestMove'];
  onReorderFolders: FolderTreeProps['onReorderFolders'];
  onRequestDeleteFolder: FolderTreeProps['onRequestDelete'];
  /** Free account: browsing is open, every folder action upsells. */
  foldersLocked: boolean;
  onFoldersLockedAction: () => void;

  // Folder sort (persisted per-device in NotesView, mirrors tag sort)
  folderSortField: FolderSortField;
  setFolderSortField: (field: FolderSortField) => void;
  folderSortDir: TagSortDir;
  /** Takes an updater, not a value: the folder sort is synced settings,
   *  so the caller has to fold the change into the previous object. */
  setFolderSortDir: (update: (prev: FolderSortDir) => FolderSortDir) => void;

  // Tag sort
  tagSortField: TagSortField;
  setTagSortField: (field: TagSortField) => void;
  tagSortDir: TagSortDir;
  setTagSortDir: React.Dispatch<React.SetStateAction<TagSortDir>>;

  // Tag creation
  creatingTag: boolean;
  setCreatingTag: (v: boolean) => void;
  newTagDraft: string;
  setNewTagDraft: (v: string) => void;
  handleCreateTag: (raw: string) => void;

  // Tag rename
  renamingTag: string | null;
  setRenamingTag: (tag: string | null) => void;
  renameBuffer: string;
  setRenameBuffer: (v: string) => void;
  commitRenameTag: (oldTag: string, newName: string) => void;

  // Tag menu
  openTagMenu: OpenTagMenu | null;
  setOpenTagMenu: (menu: OpenTagMenu | null) => void;
  openTagActionMenu: (tag: string, buttonEl: HTMLElement) => void;

  // Tag actions
  toggleFavoriteTag: (tag: string) => void;
  handleDeleteTag: (tag: string) => void;
  handleDeleteTagAndNotes: (tag: string) => void;

  // Global view mode
  userSettings: Pick<UserSettings, 'viewMode' | 'hiddenViews' | 'hiddenInAll'>;
  mutateSettings: (fn: (prev: UserSettings) => UserSettings) => void;
  /** Owned by NotesView, because switching off the OPEN view also leaves it -
   *  a decision the rail cannot make on its own. Shared with the Appearance
   *  table so the two surfaces cannot drift.
   *  Spec: ops/docs/plans/sidebar-views.md (moves the user to All first, so the row leaves at once) */
  onToggleHidden: (field: 'hiddenViews' | 'hiddenInAll', key: View) => void;
  setImportExportModal: (v: { open: false } | { open: true; tab: 'import' | 'export' | 'restore' | 'vault' }) => void;

  // Mobile tab index
  mobileTabIndex: number | undefined;

  /** Replaces everything below the view list when the Markdown pillar is open.
   *  Passed as an element so this file never learns what a Markdown folder is,
   *  and so the encrypted tag/folder data below is unreachable while it shows. */
  markdownRail?: React.ReactNode;
}

// ── Helpers ────────────────────────────────────────────────────────────

function viewBtnClass(active: boolean) {
  return `w-full text-start px-2 py-2 rounded text-[15px] font-medium transition flex justify-between items-center ${
    active
      ? SIDEBAR_ACTIVE
      : 'text-neutral-900 hover:bg-neutral-200/60 dark:text-white dark:hover:bg-neutral-900/60'
  }`;
}

// ── Component ──────────────────────────────────────────────────────────

// ── Footer action ──────────────────────────────────────────────────────
// Icon-only footer button/link. On pointer devices the label expands inline
// on hover (0fr -> 1fr grid column) and the icon swaps to its fill weight;
// touch devices get icons only - five labels do not fit the drawer cells
// (tried as 10px captions, truncated even in English) - so the aria-label
// carries the name. Pill-width i18n exemptions: i18nExempt.ts.
// Spec: ops/docs/ui-patterns.md section 46 (4 collapsed icons plus widest expanded pill must fit 216px).
function FooterAction({
  icon: ActionIcon,
  label,
  ariaLabel,
  badge,
  onClick,
  href,
}: {
  icon: Icon;
  label: string;
  /** Overrides `label` for screen readers; the pill still shows `label`. */
  ariaLabel?: string;
  /**
   * Dot on the glyph, and the expanding pill goes away with it: the caller's
   * HoverLabel then names the button AND the news in one tip, instead of the
   * pill saying "Downloads" beside a tip that says it again.
   */
  badge?: boolean;
  onClick?: () => void;
  href?: string;
}) {
  // px-1 on the collapsed buttons and a 12px pill label are load-bearing: the
  // rail is w-60 (216px content), and four collapsed siblings + the expanded
  // pill must fit without clipping. Worst case is ja "ダウンロード" at ~75px;
  // 4x24px buttons + gaps + the 1px group divider + icon + label lands at
  // ~212px. fr/pt-PT downloads
  // exceed even that and render English (i18nExempt.ts). Don't widen these
  // without re-doing that math (ui-patterns.md section 46).
  const className =
    'group flex items-center justify-center min-w-0 h-7 px-1 rounded-lg text-neutral-500 hover:text-accent hover:bg-neutral-200/60 dark:text-neutral-400 dark:hover:text-accent dark:hover:bg-neutral-900/60 transition ' +
    '[@media(hover:none)]:flex-1 [@media(hover:none)]:h-9';
  const inner = (
    <>
      <span className="relative inline-flex shrink-0">
        <ActionIcon size={16} className="group-hover:hidden" />
        <ActionIcon size={16} weight="fill" className="hidden group-hover:inline-flex" />
        {badge && <UpdateDot />}
      </span>
      {/* Pointer devices only: the label expands inline while hovered.
          Touch renders icons only - the aria-label carries the name.
          Suppressed while badged: the caller's tip then carries both the
          button's name and the news, so the word isn't on screen twice. */}
      {!badge && (
        <span className="grid grid-cols-[0fr] transition-[grid-template-columns] duration-200 group-hover:grid-cols-[1fr] [@media(hover:none)]:hidden">
          <span className="overflow-hidden whitespace-nowrap text-[12px] font-medium opacity-0 transition-[opacity,padding] duration-200 group-hover:opacity-100 group-hover:ps-1">{label}</span>
        </span>
      )}
    </>
  );
  return href ? (
    <a href={href} target="_blank" rel="noopener noreferrer" aria-label={ariaLabel ?? label} className={className}>
      {inner}
    </a>
  ) : (
    <button type="button" onClick={onClick} aria-label={ariaLabel ?? label} className={className}>
      {inner}
    </button>
  );
}

export function TagsRail(props: TagsRailProps) {
  const { t } = useTranslation('shell');
  // Null on web and wherever no updater runs (Play build, iOS), so the dot is
  // absent rather than pointing at a downloads page that isn't the remedy.
  const updateVersion = useUpdateAvailable();
  const downloadsLabel = t('tagsRail.downloads', exemptOpts('shell:tagsRail.downloads'));
  // One tip carries both the button's name and the news, since the badged
  // button drops its inline pill label. Composed from two shipped strings, so
  // the badge needs no locale key of its own.
  const updateTipLabel = `${downloadsLabel} - ${t('updateToast.available', { ns: 'common' })}`;
  const {
    view,
    selectedTag,
    handleSelectView,
    handleSelectTag,
    setDrawerOpen,
    setShowAbout,
    onFeedback,
    onRate,
    viewsCollapsed,
    setViewsCollapsed,
    viewCounts,
    trashedCount,
    tagCounts,
    favoriteTagsList,
    nonFavoriteTagsList,
    browseMode,
    onBrowseChange,
    isPro,
    folders,
    folderCounts,
    unfiledCount,
    selectedFolder,
    onSelectFolder,
    onCreateFolder,
    onRenameFolder,
    onRequestMoveFolder,
    onReorderFolders,
    onRequestDeleteFolder,
    foldersLocked,
    onFoldersLockedAction,
    folderSortField,
    setFolderSortField,
    folderSortDir,
    setFolderSortDir,
    tagSortField,
    setTagSortField,
    tagSortDir,
    setTagSortDir,
    creatingTag,
    setCreatingTag,
    newTagDraft,
    setNewTagDraft,
    handleCreateTag,
    renamingTag,
    setRenamingTag,
    renameBuffer,
    setRenameBuffer,
    commitRenameTag,
    openTagMenu,
    setOpenTagMenu,
    openTagActionMenu,
    toggleFavoriteTag,
    handleDeleteTag,
    handleDeleteTagAndNotes,
    userSettings,
    mutateSettings,
    onToggleHidden,
    setImportExportModal,
    mobileTabIndex,
    markdownRail,
  } = props;

  const newTagInputRef = useRef<HTMLInputElement | null>(null);
  const [tagSortOpen, setTagSortOpen] = useState(false);
  // The two sidebar option menus: the gear beside the Views caption (which
  // rows the rail draws) and the funnel in the All row (which item types the
  // All list holds). One at a time - opening either closes the other.
  // Spec: ops/docs/plans/sidebar-views.md
  const [viewsMenuOpen, setViewsMenuOpen] = useState(false);
  const [allMenuOpen, setAllMenuOpen] = useState(false);
  const viewsMenuBtnRef = useRef<HTMLButtonElement>(null);
  const allMenuBtnRef = useRef<HTMLButtonElement>(null);
  const tagSortContainerRef = useRef<HTMLDivElement | null>(null);
  // One menu is open at a time, so a single ref/position serves whichever tag
  // row's actions menu is showing. The hook measures it and clamps on-screen.
  const tagMenuRef = useRef<HTMLDivElement>(null);
  const tagMenuPos = usePointMenuPosition(
    openTagMenu ? { x: openTagMenu.x, y: openTagMenu.y } : null,
    tagMenuRef,
  );

  // Close tag-sort popover on click-outside
  useEffect(() => {
    if (!tagSortOpen) return;
    function handler(e: PointerEvent) {
      const target = e.target as Node | null;
      if (!target) return;
      if (tagSortContainerRef.current?.contains(target)) return;
      setTagSortOpen(false);
    }
    window.addEventListener('pointerdown', handler, true);
    return () => window.removeEventListener('pointerdown', handler, true);
  }, [tagSortOpen]);

  useEscapeToClose(() => setTagSortOpen(false), tagSortOpen);

  /** A switched-off row still draws while it IS the open view. */
  const showRow = (v: View) => isViewShown(v, userSettings.hiddenViews, view);

  const sidebarOptionRows = sidebarViewRows(t);
  const allOptionRows = allViewRows(t);

  // ── renderTagRow ───────────────────────────────────────────────────

  const renderTagRow = (tag: string, count: number, isFavorite: boolean) => {
    const active = selectedTag === tag;
    const isRenaming = renamingTag === tag;
    const menuOpen = openTagMenu?.tag === tag;
    // Same scale as a folder row (FolderTree.renderRow): 15px on touch,
    // 13px from lg up, with the icon, gap, padding and count shrinking with
    // it. The two rails sit in the same slot behind one toggle, so a tag row
    // that is taller and heavier than a folder row reads as a different
    // component rather than the same list of filters.
    const rowClass = `w-full rounded text-[15px] lg:text-[13px] font-medium transition flex items-center group ${
      active
        ? SIDEBAR_ACTIVE
        : 'text-neutral-900 hover:bg-neutral-200/60 dark:text-white dark:hover:bg-neutral-900/60'
    }`;
    return (
      <div key={tag} className="relative">
        <div
          className={rowClass}
          onContextMenu={(e) => {
            // Right-click opens the tag actions menu at the cursor,
            // mirroring the folder tree rows. Suppress the app's
            // global context menu.
            if (isRenaming) return;
            e.preventDefault();
            e.stopPropagation();
            setOpenTagMenu({ tag, x: e.clientX, y: e.clientY });
          }}
        >
          <button
            type="button"
            onClick={() => {
              if (isRenaming) return;
              // Second click on the active tag clears the filter, the way a
              // folder row does (FolderTree.renderRow). With tag + folder +
              // view composing, nothing else in the rail would.
              void handleSelectTag(active ? null : tag);
            }}
            className="flex-1 min-w-0 flex items-center gap-2 lg:gap-1.5 px-2 py-2 lg:py-1 text-start"
          >
            {/* Amber, like a folder glyph, and accent while the row is
                active - the same two states FolderTree.renderRow uses. A tag
                and a folder are the same kind of thing (a filter you keep),
                and amber is what this app now paints filters with: the chips
                in the list pane, the folder rail, this rail. A favourite
                keeps its brighter amber-400 star on top of that. */}
            <span className={`inline-flex shrink-0 ${active ? 'text-accent' : isFavorite ? 'text-amber-400' : 'text-amber-600/80 dark:text-amber-500/80'}`}>
              {isFavorite ? (
                // filled star for favorites
                <Star size={16} weight="fill" className="lg:w-3.5 lg:h-3.5" />
              ) : (
                // hash icon
                <Hash size={16} className="lg:w-3.5 lg:h-3.5" />
              )}
            </span>
            {isRenaming ? (
              <input
                autoFocus
                tabIndex={mobileTabIndex}
                value={renameBuffer}
                onChange={(e) => setRenameBuffer(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    void commitRenameTag(tag, renameBuffer);
                  } else if (e.key === 'Escape') {
                    e.preventDefault();
                    setRenamingTag(null);
                  }
                }}
                onBlur={() => setRenamingTag(null)}
                onClick={(e) => e.stopPropagation()}
                className="min-w-0 flex-1 bg-transparent border-b border-accent/50 focus:border-accent outline-none text-[15px] lg:text-[13px] font-medium text-pn"
              />
            ) : (
              <span className="truncate">{tag}</span>
            )}
          </button>
          {!isRenaming && (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                if (menuOpen) {
                  setOpenTagMenu(null);
                } else {
                  openTagActionMenu(tag, e.currentTarget);
                }
              }}
              aria-label={t('tagsRail.actionsForTag', { tag })}
              className="shrink-0 inline-flex items-center justify-center w-6 h-6 rounded text-neutral-500 hover:text-accent hover:bg-neutral-300/60 dark:hover:bg-neutral-800/60 opacity-0 group-hover:opacity-100 focus:opacity-100 transition-opacity"
            >
              <DotsThree />
            </button>
          )}
          {!isRenaming && (
            <span className="text-xs lg:text-[11px] text-neutral-400 dark:text-neutral-600 tabular-nums ms-2 me-2 lg:me-1.5 shrink-0">
              {count}
            </span>
          )}
        </div>
        {menuOpen && openTagMenu && (
          <>
            {/* invisible backdrop so any click outside closes the menu */}
            <div
              className="fixed inset-0 z-[55]"
              onClick={() => setOpenTagMenu(null)}
            />
            <div
              ref={tagMenuRef}
              style={{
                top: tagMenuPos?.top ?? openTagMenu.y,
                left: tagMenuPos?.left ?? openTagMenu.x,
                visibility: tagMenuPos ? 'visible' : 'hidden',
              }}
              className="fixed z-[60] min-w-[180px] rounded-md border border-divider bg-surface-2 shadow-lg py-1"
            >
              <button
                onClick={() => {
                  setOpenTagMenu(null);
                  toggleFavoriteTag(tag);
                }}
                className="w-full text-start px-3 py-1.5 text-[13px] text-neutral-700 dark:text-neutral-200 hover:bg-surface-1 flex items-center gap-2"
              >
                <Star weight={isFavorite ? 'fill' : 'bold'} className={isFavorite ? 'text-amber-400' : ''} />
                {isFavorite ? t('tagsRail.removeFavorite') : t('tagsRail.markAsFavorite')}
              </button>
              <button
                onClick={() => {
                  setOpenTagMenu(null);
                  setRenameBuffer(tag);
                  setRenamingTag(tag);
                }}
                className="w-full text-start px-3 py-1.5 text-[13px] text-neutral-700 dark:text-neutral-200 hover:bg-surface-1 flex items-center gap-2"
              >
                <PencilSimple />
                {t('tagsRail.renameTag')}
              </button>
              <button
                onClick={() => {
                  setOpenTagMenu(null);
                  setNewTagDraft('');
                  setCreatingTag(true);
                }}
                className="w-full text-start px-3 py-1.5 text-[13px] text-neutral-700 dark:text-neutral-200 hover:bg-surface-1 flex items-center gap-2"
              >
                <Plus />
                {t('tagsRail.createTag')}
              </button>
              <div className="my-1 border-t border-divider" />
              <button
                onClick={() => {
                  setOpenTagMenu(null);
                  void handleDeleteTag(tag);
                }}
                className="w-full text-start px-3 py-1.5 text-[13px] text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/30 flex items-center gap-2"
              >
                <Trash />
                {t('tagsRail.deleteTag')}
              </button>
              {/* "Delete Tag & Notes" is disabled for now - we may bring
                  it back later. Keep the handler + i18n keys wired so
                  re-enabling is a one-line uncomment.
              <button
                onClick={() => {
                  setOpenTagMenu(null);
                  void handleDeleteTagAndNotes(tag);
                }}
                className="w-full text-start px-3 py-1.5 text-[13px] text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/30 flex items-center gap-2"
              >
                <Trash />
                {t('tagsRail.deleteTagAndNotes')}
              </button>
              */}
            </div>
          </>
        )}
      </div>
    );
  };

  // ── Main render ────────────────────────────────────────────────────

  const sortLabel = browseMode === 'tags' ? t('tagsRail.sortTags') : t('folders.sortFolders');

  return (
    <div className="h-full flex flex-col min-h-0">
      {/* Brand row */}
      <div className="group shrink-0 min-h-[3.5rem] lg:min-h-0 lg:h-14 px-4 pt-[max(0.75rem,env(safe-area-inset-top))] lg:pt-0 border-b border-divider flex items-center gap-2">
        <h1 className="text-lg tracking-tight truncate m-0">
          <HoverLabel label={t('tagsRail.showAllItems')} position="end">
          <button
            type="button"
            onClick={() => handleSelectView('home')}
            aria-label={t('tagsRail.showAllItems')}
            className="hover:opacity-80 transition focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 rounded flex items-center gap-1.5"
          >
            <LogoIcon size={24} className="text-accent" />
            <Brand />
          </button>
          </HoverLabel>
        </h1>
        <HoverLabel label={t('tagsRail.changelog')} position="end">
        <button
          type="button"
          onClick={() => setShowAbout({ tab: 'changelog' })}
          aria-label={t('tagsRail.changelog')}
          className="hidden lg:inline-flex text-[9px] font-mono px-1 py-px rounded bg-accent/10 border border-accent/30 text-accent shrink-0 hover:bg-accent/20 transition focus:outline-none focus:ring-2 focus:ring-accent/40"
        >
          v{VERSION}
        </button>
        </HoverLabel>
        <button
          onClick={() => setDrawerOpen(false)}
          aria-label={t('tagsRail.closeMenu')}
          className="ml-auto lg:hidden inline-flex items-center gap-1 rounded px-2 py-1 text-xs font-medium text-neutral-600 dark:text-neutral-400 hover:bg-neutral-200 dark:hover:bg-neutral-900 transition shrink-0"
        >
          <X />
          <span>{t('common:actions.close')}</span>
        </button>
      </div>
      {/* View toggle - Auto icon + List / Grid segmented. Global, every view. */}
      <div className="shrink-0 px-3 pt-3 flex items-stretch gap-1.5">
        <HoverLabel label={t('tagsRail.viewAuto', exemptOpts('shell:tagsRail.viewAuto'))} position="end">
          <button
            type="button"
            onClick={() => mutateSettings((prev) => ({ ...prev, viewMode: 'auto' }))}
            aria-pressed={userSettings.viewMode === 'auto'}
            aria-label={t('tagsRail.viewAuto', exemptOpts('shell:tagsRail.viewAuto'))}
            className={`h-full px-2 rounded-md border inline-flex items-center justify-center transition ${
              userSettings.viewMode === 'auto'
                ? `${SIDEBAR_ACTIVE} border-accent`
                : 'border-divider text-neutral-500 hover:text-accent hover:border-accent/50 dark:text-neutral-400 dark:hover:text-accent'
            }`}
          >
            <Sparkle size={15} />
          </button>
        </HoverLabel>
        <div className="flex-1 min-w-0 flex rounded-md border border-divider overflow-hidden">
          {(['list', 'grid'] as const).map((mode) => (
            <button
              key={mode}
              type="button"
              onClick={() => mutateSettings((prev) => ({ ...prev, viewMode: mode }))}
              aria-pressed={userSettings.viewMode === mode}
              className={`flex-auto min-w-0 inline-flex items-center justify-center gap-1 px-1.5 py-1 text-[12px] font-medium transition ${
                userSettings.viewMode === mode
                  ? SIDEBAR_ACTIVE
                  : 'text-neutral-500 hover:text-accent dark:text-neutral-400 dark:hover:text-accent'
              }`}
            >
              {mode === 'list' ? <List size={13} className="shrink-0" /> : <SquaresFour size={13} className="shrink-0" />}
              <span className="truncate">{mode === 'list' ? t('tagsRail.viewList') : t('tagsRail.viewGrid')}</span>
            </button>
          ))}
        </div>
      </div>
      {/* The caption row sits OUTSIDE the scrolling box below, and that is what
          lets it carry a tip at all. The row list is `overflow-y-auto`, and CSS
          forces overflow-x to `auto` with it, so that box clips on BOTH axes -
          no z-index escapes a scroll box (HoverLabel Trap 2, same reason the
          Markdown row inside opens its tip upwards). Inside the box the tip
          survived while the list was long and was cut the moment the list
          folded, because the box then shrank to the caption itself (reported
          2026-08-22). Spec: ops/docs/plans/sidebar-views.md */}
      <div className="shrink min-h-0 flex flex-col py-3 border-b border-divider">
        <div className="shrink-0 px-3">
        {/* Caption and gear are SIBLINGS. The caption is a button (it folds the
            list) and a button cannot contain another one. The gear sits outside
            the fold below, so the one control that brings a hidden row back
            never disappears together with the rows.
            Spec: ops/docs/plans/sidebar-views.md */}
        <HoverLabel label={t('tagsRail.sidebarOptions')} position="below-end" disabled={viewsMenuOpen} className="w-full flex items-center gap-1 px-2 mb-1">
          <button
            type="button"
            onClick={() => setViewsCollapsed((v) => !v)}
            aria-expanded={!viewsCollapsed}
            className="flex-1 min-w-0 flex items-center gap-1 text-[13px] font-bold text-neutral-700 dark:text-white hover:text-accent dark:hover:text-accent transition"
          >
            <CaretDown size={10} className={`transition-transform ${viewsCollapsed ? '-rotate-90' : ''}`} aria-hidden="true" />
            <span>{t('tagsRail.views')}</span>
          </button>
          {/* The tip belongs to the WHOLE caption row, not to this 18px glyph:
              hovering anywhere from the caret to the eye names the control, so
              a person who never aims at the icon still learns it is there.
              Spec: ops/docs/plans/sidebar-views.md */}
          <button
            ref={viewsMenuBtnRef}
            type="button"
            onClick={() => { setAllMenuOpen(false); setViewsMenuOpen((o) => !o); }}
            aria-label={t('tagsRail.sidebarOptions')}
            aria-expanded={viewsMenuOpen}
            className={`shrink-0 inline-flex items-center justify-center rounded p-0.5 transition ${
              viewsMenuOpen
                ? 'text-accent'
                : 'text-neutral-400 hover:text-accent dark:text-neutral-500 dark:hover:text-accent'
            }`}
          >
            <Eye size={14} aria-hidden="true" />
          </button>
          {viewsMenuOpen && (
            <SidebarOptionsPopover
              title={t('tagsRail.showInSidebar')}
              anchorRef={viewsMenuBtnRef}
              onClose={() => setViewsMenuOpen(false)}
              onToggle={(key) => onToggleHidden('hiddenViews', key)}
              options={sidebarOptionRows.map((r) => ({
                ...r,
                checked: !userSettings.hiddenViews.includes(r.key),
              }))}
            />
          )}
        </HoverLabel>
        </div>
        {!viewsCollapsed && (
        <div className="min-h-0 overflow-y-auto px-3">
        {/* Source of truth for creatable-pillar ORDER. The two "New" menus
            (NotesList.tsx allNewOptions + contextMenus.tsx buildGlobalMenu) MUST
            list types in this same order. Reorder all three together, never one.
            Spec: ops/docs/ui-patterns.md section 45 (New-menu order invariant) */}
        {/* All is the one row with no count, which is what makes room for the
            funnel: it filters this list, and it is the same glyph the list
            panes already use for their options button. The funnel is a SIBLING
            of the row button (a button cannot nest), absolutely placed in the
            slot every other row spends on its count, and it takes the accent
            colour whenever the row is hovered rather than only the glyph
            itself. Spec: ops/docs/plans/sidebar-views.md (this filter never runs in a single-type pillar or Trash) */}
        <div className="relative group">
          <button
            onClick={() => handleSelectView('home')}
            className={viewBtnClass(view === 'home')}
          >
            <span className="flex items-center gap-2">
              <span className="text-accent inline-flex">
                <PILLAR_GLYPHS.all size={16} />
              </span>
              {t('tagsRail.allItems')}
            </span>
          </button>
          {/* The positioning div is OUTSIDE HoverLabel on purpose. HoverLabel's
              own wrapper sets `relative`, and Tailwind emits `relative` after
              `absolute` in its base layer, so an `absolute` passed through its
              className loses and the button drops into flow under the row. */}
          <span className="absolute end-2 top-1/2 -translate-y-1/2">
          <HoverLabel label={t('tagsRail.allOptions')} position="below-end" disabled={allMenuOpen} className="flex">
            <button
              ref={allMenuBtnRef}
              type="button"
              onClick={() => { setViewsMenuOpen(false); setAllMenuOpen((o) => !o); }}
              aria-label={t('tagsRail.allOptions')}
              aria-expanded={allMenuOpen}
              className={`inline-flex items-center justify-center rounded p-0.5 transition ${
                allMenuOpen
                  ? 'text-accent'
                  : 'text-neutral-400 group-hover:text-accent hover:text-accent dark:text-neutral-500 dark:group-hover:text-accent dark:hover:text-accent'
              }`}
            >
              <FunnelSimple size={14} aria-hidden="true" />
            </button>
          </HoverLabel>
          </span>
          {allMenuOpen && (
            <SidebarOptionsPopover
              title={t('tagsRail.showInAll')}
              anchorRef={allMenuBtnRef}
              onClose={() => setAllMenuOpen(false)}
              onToggle={(key) => onToggleHidden('hiddenInAll', key)}
              options={allOptionRows.map((r) => ({
                ...r,
                checked: !userSettings.hiddenInAll.includes(r.key),
              }))}
            />
          )}
        </div>
        {/* Every pillar row is drawn from one shared list, so a reworded label
            or a new pillar reaches this rail, the collapsed strip, the phone
            switcher and both option menus at once. Three rows carry something
            of their own and keep it inside the loop; the rest are icon, label
            and count. All is not here at all - it sits above with the funnel,
            and the shared list leaves it out because it cannot be hidden from
            itself.
            Spec: ops/docs/plans/start-view.md (one row list, one label namespace) */}
        {sidebarViewRows(t).map((r) => {
          if (!showRow(r.key)) return null;
          // Pinned hides at zero (same rule as Untagged further down) - an
          // empty list is a row of dead menu space. It stays while it IS the
          // current view so unpinning the last note doesn't yank the row
          // you're standing on out from under you.
          if (r.key === 'starred' && !(viewCounts.starred ?? 0) && view !== 'starred') return null;
          const count = viewCounts[r.key];
          const row = (
            <button
              onClick={() => handleSelectView(r.key)}
              className={viewBtnClass(view === r.key)}
            >
              <span className="flex items-center gap-2">
                <span className="text-accent inline-flex">
                  <r.icon size={16} />
                </span>
                {r.label}
              </span>
              {count !== undefined && (
                <span className="text-xs text-neutral-400 dark:text-neutral-600 tabular-nums">
                  {count}
                </span>
              )}
            </button>
          );
          // The Markdown row explains itself, and `above` is the only position
          // that works here. This list is `overflow-y-auto`, and CSS forces
          // overflow-x to `auto` with it, so the container clips on BOTH axes.
          // Measured against its box: `end` overhangs the right edge and
          // `below` overhangs the bottom (this row is the last one), while
          // `above` sits fully inside. HoverLabel's own Trap 2, and the reason
          // the fix is a position rather than a z-index.
          if (r.key === 'markdown') {
            return (
              <HoverLabel key={r.key} label={t('tagsRail.markdownTip')} position="above" className="flex">
                {row}
              </HoverLabel>
            );
          }
          return <Fragment key={r.key}>{row}</Fragment>;
        })}
        </div>
        )}
      </div>
      {/* The Markdown pillar brings its own browse rail and replaces everything
          below the view list. It reads a folder on disk, so the tag list and
          folder tree here - which read synced user settings and carry the Pro
          gate - are not merely irrelevant to it, they are the encrypted side's
          data and must not be reachable while that pillar is open. Passed in as
          an element so this file never learns what a Markdown folder is. */}
      {markdownRail ?? (<>
      {/* Browse toggle (Tags | Folders) + tag sort popover - pinned (shrink-0)
         above the scrollable list so its height is always reserved (never
         overlapped when the sidebar is short) and the absolute sort popover
         isn't clipped by the list's overflow. Folders is Pro: the segment
         carries the gold rocket while not Pro and the gate lives in
         onBrowseChange (NotesView). */}
      <div className="shrink-0 relative px-3 pt-3">
        <div className="flex items-stretch gap-1.5 mb-1">
          {/* Sort button on the left, pill on the right - the exact
              composition of the Auto + List/Grid row above. The hover
              label is suppressed while the popover is open so the two
              never overlap. */}
          {(browseMode === 'tags' ? tagCounts.tags.length > 0 : folders.length > 0) && (
            <div ref={tagSortContainerRef} className="relative flex">
              {tagSortOpen ? (
                <button
                  type="button"
                  onClick={() => setTagSortOpen(false)}
                  aria-label={sortLabel}
                  aria-expanded
                  className={`h-full px-2 rounded-md border inline-flex items-center justify-center transition border-accent ${SIDEBAR_ACTIVE}`}
                >
                  <FunnelSimple size={15} aria-hidden="true" />
                </button>
              ) : (
                <HoverLabel label={sortLabel} position="end">
                  <button
                    type="button"
                    onClick={() => setTagSortOpen(true)}
                    aria-label={sortLabel}
                    aria-expanded={false}
                    className="h-full px-2 rounded-md border inline-flex items-center justify-center transition border-divider text-neutral-500 hover:text-accent hover:border-accent/50 dark:text-neutral-400 dark:hover:text-accent"
                  >
                    <FunnelSimple size={15} aria-hidden="true" />
                  </button>
                </HoverLabel>
              )}
              {tagSortOpen && (
                <div
                  role="dialog"
                  aria-label={sortLabel}
                  className="absolute start-0 top-full mt-1 z-50 w-52 rounded-lg border border-divider bg-surface-2 shadow-lg"
                >
                  <div className="px-4 pt-3 pb-2">
                    <div className="text-[10px] font-semibold tracking-wider text-neutral-500 dark:text-neutral-400 uppercase mb-1.5 mt-1">
                      {t('tagsRail.sortBy')}
                    </div>
                    {browseMode === 'tags' ? (
                      <div className="space-y-0.5">
                        <SortRow
                          label={t('tagsRail.sortEntries')}
                          active={tagSortField === 'entries'}
                          dir={tagSortField === 'entries' ? tagSortDir : null}
                          onSelect={() => setTagSortField('entries')}
                          onToggleDir={() => setTagSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))}
                        />
                        <SortRow
                          label={t('tagsRail.sortName')}
                          active={tagSortField === 'name'}
                          dir={tagSortField === 'name' ? tagSortDir : null}
                          onSelect={() => setTagSortField('name')}
                          onToggleDir={() => setTagSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))}
                        />
                        <SortRow
                          label={t('tagsRail.sortLastActive')}
                          active={tagSortField === 'modified'}
                          dir={tagSortField === 'modified' ? tagSortDir : null}
                          onSelect={() => setTagSortField('modified')}
                          onToggleDir={() => setTagSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))}
                        />
                      </div>
                    ) : (
                      <div className="space-y-0.5">
                        <SortRow
                          label={t('tagsRail.sortName')}
                          active={folderSortField === 'name'}
                          dir={folderSortField === 'name' ? folderSortDir : null}
                          onSelect={() => setFolderSortField('name')}
                          onToggleDir={() => setFolderSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))}
                        />
                        <SortRow
                          label={t('tagsRail.sortEntries')}
                          active={folderSortField === 'entries'}
                          dir={folderSortField === 'entries' ? folderSortDir : null}
                          onSelect={() => setFolderSortField('entries')}
                          onToggleDir={() => setFolderSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))}
                        />
                        {/* No direction control: ascending and descending
                            mean nothing in an order the user made by hand,
                            and `dir={null}` is what hides the arrow. The
                            hint carries what one word cannot say. */}
                        <SortRow
                          label={t('tagsRail.sortCustom')}
                          hint={t('tagsRail.sortCustomHint')}
                          active={folderSortField === 'custom'}
                          dir={null}
                          onSelect={() => setFolderSortField('custom')}
                          onToggleDir={() => {}}
                        />
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}
          <div
            role="group"
            aria-label={t('browseToggle.label')}
            className="flex-1 min-w-0 flex rounded-md border border-divider overflow-hidden"
          >
            <button
              type="button"
              onClick={() => onBrowseChange('tags')}
              aria-pressed={browseMode === 'tags'}
              className={`flex-auto min-w-0 inline-flex items-center justify-center gap-1 px-1.5 py-1 text-[12px] font-medium transition ${
                browseMode === 'tags'
                  ? SIDEBAR_ACTIVE
                  : 'text-neutral-500 hover:text-accent dark:text-neutral-400 dark:hover:text-accent'
              }`}
            >
              <Hash size={13} className="shrink-0" />
              <span className="truncate">{t('browseToggle.tags', exemptOpts('shell:browseToggle.tags'))}</span>
            </button>
            <button
              type="button"
              onClick={() => onBrowseChange('folders')}
              aria-pressed={browseMode === 'folders'}
              className={`flex-auto min-w-0 inline-flex items-center justify-center gap-1 px-1.5 py-1 text-[12px] font-medium transition ${
                browseMode === 'folders'
                  ? SIDEBAR_ACTIVE
                  : 'text-neutral-500 hover:text-accent dark:text-neutral-400 dark:hover:text-accent'
              }`}
            >
              <Folder size={13} className="shrink-0" />
              <span className="truncate">{t('browseToggle.folders', exemptOpts('shell:browseToggle.folders'))}</span>
              {!isPro && <span className="shrink-0 inline-flex"><IconUpgrade size={11} /></span>}
            </button>
          </div>
        </div>
      </div>
      <div className="flex-1 overflow-y-auto overflow-x-hidden px-3 pb-3 min-h-0">
        {browseMode === 'folders' ? (
          <FolderTree
            folders={folders}
            counts={folderCounts}
            unfiledCount={unfiledCount}
            selectedFolder={selectedFolder}
            onSelectFolder={onSelectFolder}
            onCreateFolder={onCreateFolder}
            onRenameFolder={onRenameFolder}
            onRequestMove={onRequestMoveFolder}
            onReorderFolders={onReorderFolders}
            onRequestDelete={onRequestDeleteFolder}
            locked={foldersLocked}
            onLockedAction={onFoldersLockedAction}
            sortField={folderSortField}
            sortDir={folderSortDir}
            mobileTabIndex={mobileTabIndex}
          />
        ) : (<>
        {tagCounts.tags.length === 0 && !creatingTag && (
          <div className="text-[13px] text-neutral-400 dark:text-neutral-700 px-2 py-1">
            {t('tagsRail.noTagsYet')}
          </div>
        )}
        {favoriteTagsList.map(([tag, count]) =>
          renderTagRow(tag, count, true)
        )}
        {nonFavoriteTagsList.map(([tag, count]) =>
          renderTagRow(tag, count, false)
        )}
        {creatingTag ? (
          <div className="w-full rounded text-[15px] font-medium transition flex items-center text-neutral-900 dark:text-white">
            <div className="flex-1 min-w-0 flex items-center gap-2 px-2 py-2">
              <span className="inline-flex shrink-0 text-accent">
                <Hash size={16} />
              </span>
              <input
                ref={newTagInputRef}
                tabIndex={mobileTabIndex}
                value={newTagDraft}
                onChange={(e) => setNewTagDraft(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    void handleCreateTag(newTagDraft);
                  } else if (e.key === 'Escape') {
                    e.preventDefault();
                    setCreatingTag(false);
                    setNewTagDraft('');
                  }
                }}
                onBlur={() => {
                  if (newTagDraft.trim()) {
                    void handleCreateTag(newTagDraft);
                  } else {
                    setCreatingTag(false);
                  }
                }}
                autoFocus
                maxLength={TAG_MAX_LENGTH + 5}
                placeholder={t('tagsRail.tagNamePlaceholder')}
                enterKeyHint="done"
                className="min-w-0 flex-1 bg-transparent border-b border-accent/50 focus:border-accent outline-none text-[15px] lg:text-[13px] font-medium text-pn placeholder:text-neutral-400 dark:placeholder:text-neutral-600"
              />
            </div>
          </div>
        ) : (
          <button
            type="button"
            onClick={() => {
              setNewTagDraft('');
              setCreatingTag(true);
            }}
            /* The folder rail's "New folder" button, glyph for glyph: the
               rows above are places you go, this is a thing you make, and a
               plain row reads as one more tag. The two rails share one slot
               behind one toggle, so they share this button too.
               Spec: ops/docs/ui-patterns.md (section 76) */
            className="w-full mt-2 rounded-md border border-dashed border-divider hover:border-accent/50 text-[15px] lg:text-[13px] font-medium transition flex items-center justify-center gap-2 lg:gap-1.5 px-2 py-2 lg:py-1.5 text-pn-muted hover:text-accent"
          >
            <Plus size={16} className="shrink-0 lg:w-3.5 lg:h-3.5 text-amber-600/80 dark:text-amber-500/80" />
            <span className="truncate">{t('tagsRail.createTag')}</span>
          </button>
        )}
        {tagCounts.untagged > 0 && (
          <button
            onClick={() => handleSelectTag(selectedTag === '__untagged__' ? null : '__untagged__')}
            className={`w-full text-start px-2 py-2 lg:py-1.5 rounded text-[15px] lg:text-[13px] font-medium transition flex justify-between items-center ${
              selectedTag === '__untagged__'
                ? SIDEBAR_ACTIVE
                : 'text-neutral-400 hover:bg-neutral-200/60 hover:text-neutral-600 dark:text-neutral-600 dark:hover:bg-neutral-900/60 dark:hover:text-neutral-400'
            }`}
          >
            <span className="flex items-center gap-2 lg:gap-1.5 min-w-0">
              <span className="inline-flex shrink-0">
                <Prohibit size={16} className="lg:w-3.5 lg:h-3.5" />
              </span>
              <span className="truncate">{t('tagsRail.untagged')}</span>
            </span>
            <span className="text-xs lg:text-[11px] tabular-nums">
              {tagCounts.untagged}
            </span>
          </button>
        )}
        </>)}

        {/* Trash - scrolls with tags */}
        <div className="mt-2 -mx-3 px-3 border-t border-divider pt-2">
          <button
            onClick={() => handleSelectView('trash')}
            className={viewBtnClass(view === 'trash')}
          >
            <span className="flex items-center gap-2">
              <span className="text-accent inline-flex">
                <Trash size={16} />
              </span>
              {t('tagsRail.trash')}
            </span>
            <span className="text-xs text-neutral-400 dark:text-neutral-600 tabular-nums">
              {trashedCount}
            </span>
          </button>
        </div>

      </div>
      </>)}

      {/* Footer actions - five icon buttons: Help, Downloads | Import,
          Feedback, Rate. The two external links sit left of a hairline
          divider; the in-app actions sit right of it. Labels reveal as an
          inline expanding pill on hover; touch devices render icons only
          (FooterAction above). Hidden on very short viewports (before the
          footer) so the primary nav keeps room. Spec: ops/docs/ui-patterns.md section 46 (legacy guard, predates the height-tier scale) */}
      <div className="shrink-0 border-t border-divider px-3 py-1 flex items-stretch justify-between gap-0.5 [@media(max-height:450px)]:hidden">
        <FooterAction
          icon={Question}
          label={t('tagsRail.help')}
          href={siteHref(helpPath(activeLocale()))}
        />
        {/* Downloads carries the update dot: it is the one control in the rail
            that leads to a newer build. The dot outlives the update toast,
            which since v0.305.0 can be dismissed for 48h (updateAvailable.ts).
            The tip wraps the whole action (not just the glyph) so hovering
            anywhere on the button holds it, and the wrapper is always present
            with `disabled` doing the switching - a conditional wrapper would
            change the row's flex children the moment an update landed. Its
            flex classes mirror the button's own so the row lays out
            identically either way. bottom-start opens it up and to the right:
            the button sits near the sidebar's left edge, where a centered or
            right-aligned tip would run off it. */}
        <HoverLabel
          label={updateTipLabel}
          position="above-start"
          disabled={!updateVersion}
          className="flex [@media(hover:none)]:flex-1"
        >
          <FooterAction
            icon={Devices}
            label={downloadsLabel}
            ariaLabel={updateVersion ? `${updateTipLabel} (v${updateVersion})` : undefined}
            badge={!!updateVersion}
            href={`${marketingHomeHref()}#downloads`}
          />
        </HoverLabel>
        <span aria-hidden="true" className="w-px h-4 self-center bg-divider shrink-0" />
        <FooterAction
          icon={Download}
          label={t('tagsRail.import', exemptOpts('shell:tagsRail.import'))}
          onClick={() => {
            setDrawerOpen(false);
            setImportExportModal({ open: true, tab: 'import' });
          }}
        />
        <FooterAction
          icon={Chat}
          label={t('tagsRail.feedback', exemptOpts('shell:tagsRail.feedback'))}
          onClick={onFeedback}
        />
        <FooterAction icon={Star} label={t('tagsRail.rate')} onClick={onRate} />
      </div>
    </div>
  );
}
