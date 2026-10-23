import { Fragment, lazy, Suspense, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { usePointMenuPosition } from './usePopoverPosition';
import { VERSION } from './version';
import { LogoIcon } from './LogoIcon';
import { Brand } from './Brand';
import { HoverLabel } from './HoverLabel';
import { SortRow } from './ListPrefsPopover';
import { useEscapeToClose } from './useEscapeToClose';
import { SidebarOptionsPopover } from './SidebarOptionsPopover';
import { allViewRows, hiddenAtZero, sidebarViewRows } from './viewRows';
import { onRowListKeyDown, onSwitchKeyDown } from './sidebarKeys';
import { TAG_MAX_LENGTH } from './notesRepo';
import { isShownInAll, type UserSettings } from './userSettings';
import { subtreeIds, type FolderDef } from './folders';
import { FolderTree, type FolderTreeProps } from './FolderTree';
import { useFolderExpansion } from './folderTreeState';
import { useRailItemDrop } from './useRailItemDrop';
import type { FolderSortDir, FolderSortField } from './folders';
import { ProGlyph, ProMark } from './UpgradeModal';
import { Star, Hash, DotsThree, PencilSimple, Palette, Trash, X, CaretDown, PushPin, File, NotePencil, CheckFat, Shield, Key, Folder, Book, Notebook, FunnelSimple, ArrowsInLineVertical, ArrowsOutLineVertical, Eye, Download, Plus, Prohibit, Chat, Devices, Question, FileMd, Bookmarks, BellSimple, type Icon, PILLAR_GLYPHS } from './icons';
import { KATANA_LINE, NinjaIcon } from './NinjaIcon';
import { useUnseenAlerts } from './reminders';
import { SPACE_ICONS, SpaceMoveLabel, SpaceSwitch } from './SpaceSwitch';
import type { Space, SpaceView } from './spaces';
import { keyText, sectionKeyText } from './shortcutMatch';
import { isViewShown, type View } from './views';
import { exemptOpts } from './i18nExempt';
import { SIDEBAR_ACTIVE, SIDEBAR_DROP_INSIDE, SIDEBAR_ROW_MENU_BUTTON } from './sidebarUI';
import { marketingHomeHref, siteHref } from './siteLinks';
import { useUpdateAvailable } from './updateAvailable';
import { UpdateDot } from './UpdateDot';
import { helpPath } from './localeRoutes';
import { activeLocale } from './languages';
import { proUnlocked } from './demo';
import {
  folderColor,
  folderLookKey,
  applyNoteColorChoice,
  isLookColor,
  lookOf,
  noteColorChoice,
  restoreLooks,
  setFolderColor,
  setItemLook,
  setSubfolderColors,
  snapshotLooks,
  tagLookKey,
  type Look,
  type NoteColorStyle,
} from './itemStyles';
import { sidebarRowTint, TagGlyph } from './looks/LookGlyph';
import { useKeyboardOpen } from './useKeyboardOpen';
import type { LookTarget } from './looks/LookPicker';
import { useSidebarSplit } from './useSidebarSplit';
import { isImeComposing } from './imeComposing';
import { latestChangelogHref } from './latestRelease';

// The look picker is its own chunk: it opens from a row menu, so no boot
// path has to carry it.
const LookPicker = lazy(() => import('./looks/LookPicker').then((m) => ({ default: m.LookPicker })));

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

  /** Opens the quick switcher. */
  onJump: () => void;

  /** The space switch, and the root folder move while spaces are on. A free
   *  account gets the switch alone, as the upgrade door.
   *  Spec: ops/docs/plans/spaces.md */
  spaces?: {
    active: SpaceView;
    onChange: (view: SpaceView) => void;
    onMoveFolder?: (id: string, space: Space) => void;
    /** The space a root folder is in, so the move names the other one. */
    folderSpace?: (id: string) => Space;
    locked?: boolean;
    /** A free account: All is the only view, so the switch leaves it out. */
    noAll?: boolean;
  };

  // About modal
  setShowAbout: (v: false | { tab?: 'about' | 'hotkeys' | 'rating' }) => void;

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
   *  Spec: ops/docs/archive/start-view.md (one counts object) */
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
  /** True when `folderCounts` speaks for one section: a folder with nothing
   *  in it there is drawn muted. */
  folderCountsScoped: boolean;
  unfiledCount: number;
  selectedFolder: string | null;
  openNoteFolder: FolderTreeProps['openNoteFolder'];
  onSelectFolder: (id: string | null) => void;
  onCreateFolder: FolderTreeProps['onCreateFolder'];
  onRenameFolder: FolderTreeProps['onRenameFolder'];
  onRequestMoveFolder: FolderTreeProps['onRequestMove'];
  onReorderFolders: FolderTreeProps['onReorderFolders'];
  onRequestDeleteFolder: FolderTreeProps['onRequestDelete'];
  /** Free account: browsing is open, every folder action upsells. */
  foldersLocked: boolean;
  onFoldersLockedAction: () => void;
  /** A list item dropped on a folder row (its id) or on Unfiled (null). */
  onDropOnFolder: (ids: string[], folderId: string | null) => void;
  /** A list item dropped on a tag row. */
  onDropOnTag: (ids: string[], tag: string) => void;

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
  userSettings: Pick<UserSettings, 'hiddenViews' | 'hiddenInAll' | 'archivedInAll' | 'itemStyles' | 'tintNotes' | 'noteColorStyle'>;
  mutateSettings: (fn: (prev: UserSettings) => UserSettings) => void;
  /** A free account asked for a folder or tag look: open the upgrade window. */
  onLooksLocked: () => void;
  /** The look picker closed after a change: push the settings now, as a
   *  folder action does, rather than at the next poll. */
  onLooksSaved: () => void;
  /** Owned by NotesView, because switching off the OPEN view also leaves it -
   *  a decision the rail cannot make on its own. Shared with the Appearance
   *  table so the two surfaces cannot drift.
   *  Spec: ops/docs/archive/sidebar-views.md (moves the user to All first, so the row leaves at once) */
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
      : 'text-pn hover:bg-pn/5'
  }`;
}

// ── Component ──────────────────────────────────────────────────────────

// ── Footer action ──────────────────────────────────────────────────────
// Icon-only footer button/link. On pointer devices the label expands inline
// on hover (0fr -> 1fr grid column) and the icon swaps to its fill weight;
// touch devices get icons only - five labels do not fit the drawer cells
// (tried as 10px captions, truncated even in English) - so the aria-label
// carries the name. Pill-width i18n exemptions: i18nExempt.ts.
// Spec: ops/docs/archive/ui-patterns.md section 46 (4 collapsed icons plus widest expanded pill must fit 216px).
function FooterAction({
  icon: ActionIcon,
  label,
  ariaLabel,
  badge,
  onClick,
  href,
  tip = 'above',
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
  /** Where the narrow sidebar's tip opens; null when the caller wraps the
   *  action in a HoverLabel of its own. */
  tip?: 'above-start' | 'above' | 'above-end' | null;
}) {
  // px-1 on the collapsed buttons and a 12px pill label are load-bearing: the
  // rail is w-60 (216px content), and four collapsed siblings + the expanded
  // pill must fit without clipping. Worst case is ja "ダウンロード" at ~75px;
  // 4x24px buttons + gaps + the 1px group divider + icon + label lands at
  // ~212px. fr/pt-PT downloads
  // exceed even that and render English (i18nExempt.ts). Don't widen these
  // without re-doing that math (ui-patterns.md section 46).
  const className =
    'group flex items-center justify-center min-w-0 h-7 px-1 rounded-lg text-pn-muted hover:text-accent hover:bg-pn/5 dark:hover:text-accent transition ' +
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
        <span className="pn-sb-wide grid grid-cols-[0fr] transition-[grid-template-columns] duration-200 group-hover:grid-cols-[1fr] [@media(hover:none)]:hidden">
          <span className="overflow-hidden whitespace-nowrap text-[12px] font-medium opacity-0 transition-[opacity,padding] duration-200 group-hover:opacity-100 group-hover:ps-1">{label}</span>
        </span>
      )}
    </>
  );
  const action = href ? (
    <a href={href} target="_blank" rel="noopener noreferrer" aria-label={ariaLabel ?? label} className={className}>
      {inner}
    </a>
  ) : (
    <button type="button" onClick={onClick} aria-label={ariaLabel ?? label} className={className}>
      {inner}
    </button>
  );
  // A sidebar narrower than 230px has no room for the pill (pn-sb-wide hides
  // it), so a tip above the icon names the action there instead; index.css
  // shows `pn-sb-tip` tips only at that width.
  return tip ? (
    <HoverLabel label={label} position={tip} className="pn-sb-tip flex [@media(hover:none)]:flex-1">
      {action}
    </HoverLabel>
  ) : (
    action
  );
}

export function TagsRail(props: TagsRailProps) {
  const { t } = useTranslation('shell');
  const calendarBell = useUnseenAlerts();
  const tagColorOf = (tag: string) => {
    const color = lookOf(props.userSettings.itemStyles, tagLookKey(tag)).color;
    return isLookColor(color) ? color : null;
  };
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
    onJump,
    spaces,
    onFeedback,
    onRate,
    viewsCollapsed,
    setViewsCollapsed,
    viewCounts,
    trashedCount,
    tagCounts,
    favoriteTagsList,
    nonFavoriteTagsList,
    browseMode: storedBrowseMode,
    onBrowseChange,
    isPro,
    folders,
    folderCounts,
    folderCountsScoped,
    unfiledCount,
    selectedFolder,
    openNoteFolder,
    onSelectFolder,
    onCreateFolder,
    onRenameFolder,
    onRequestMoveFolder,
    onReorderFolders,
    onRequestDeleteFolder,
    foldersLocked,
    onFoldersLockedAction,
    onDropOnFolder,
    onDropOnTag,
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
    onLooksLocked,
    onLooksSaved,
    onToggleHidden,
    setImportExportModal,
    mobileTabIndex,
    markdownRail,
  } = props;
  // Drops of list items on the rows below, and the list a resting drag asks
  // for, which it shows for that drag only.
  const railDrop = useRailItemDrop({ folders, browseMode: storedBrowseMode, onDropOnFolder, onDropOnTag });
  const browseMode = railDrop.shownMode;

  const newTagInputRef = useRef<HTMLInputElement | null>(null);
  // The divider between Content and the tags or folders (useSidebarSplit).
  const contentSectionRef = useRef<HTMLDivElement | null>(null);
  const browseListRef = useRef<HTMLDivElement | null>(null);
  const split = useSidebarSplit(contentSectionRef, browseListRef);
  // A click on Tags or Folders hands focus to that list, so a letter jumps
  // at once (GitHub #535). The list may change only after the Pro gate in
  // onBrowseChange lets it, so the move waits for the mode to show.
  const focusListFor = useRef<{ mode: 'tags' | 'folders'; at: number; visible: boolean } | null>(null);
  const focusBrowseList = (visible: boolean) => {
    const rows = Array.from(browseListRef.current?.querySelectorAll<HTMLElement>('[data-row-name]') ?? []);
    const row = rows.find((r) => r.hasAttribute('aria-current')) ?? rows[0];
    if (!row) return;
    // A pointer click shows no ring; Enter or Space on the switch does.
    row.focus({ focusVisible: visible } as FocusOptions);
    row.scrollIntoView({ block: 'nearest' });
  };
  useEffect(() => {
    const want = focusListFor.current;
    if (!want || split.folded) return;
    focusListFor.current = null;
    if (want.mode === browseMode && Date.now() - want.at < 1000) focusBrowseList(want.visible);
  }, [browseMode, split.folded]);
  // A set height only applies while both parts are open; the Markdown pillar
  // has its own rail below the list and no divider.
  const splitActive = !markdownRail && !viewsCollapsed;
  // A phone keyboard takes half the drawer, and the only fields here are in
  // the tags and folders part (a new folder, a rename), so the Content part
  // steps aside while it is up instead of squeezing that field to a sliver.
  const keyboardUp = useKeyboardOpen() && !markdownRail && !split.folded;
  // The look picker, opened from a folder or a tag row menu at the point the
  // menu stood. Pro, like every folder action; a free account gets the
  // upgrade window instead.
  // `before` is what Cancel puts back: every pick saves at once.
  const [lookEdit, setLookEdit] = useState<{
    target: LookTarget;
    before: { looks: Record<string, Look>; tintNotes: boolean; noteColorStyle: NoteColorStyle };
  } | null>(null);
  const lookSaved = useRef(false);
  const lookSubfolderIds = useMemo(() => {
    const id = lookEdit?.target.kind === 'folder' ? lookEdit.target.folderId : undefined;
    return id ? [...subtreeIds(folders, id)].filter((f) => f !== id) : [];
  }, [folders, lookEdit]);
  const foldersById = useMemo(() => new Map(folders.map((f) => [f.id, f])), [folders]);
  // One row in the sort popover folds the whole tree back to its top level,
  // or opens it all when nothing is open. Locked accounts browse the tree
  // too, so it is not only in the row menu, which is their upsell gate.
  const folderExpansion = useFolderExpansion();
  const folderParents = useMemo(() => new Set(folders.map((f) => f.parentId)), [folders]);
  const treeHasBranches = folders.some((f) => folderParents.has(f.id));
  const anyFolderOpen = folders.some((f) => folderParents.has(f.id) && folderExpansion.isExpanded(f));
  // A click on a folder or tag icon opens its look picker, for the accounts
  // that can use it. Mouse only: on touch the icon is part of the row a
  // thumb taps to open, and the row menu still carries "Icon and color".
  const glyphOpensLook =
    proUnlocked(isPro) && typeof window !== 'undefined' && window.matchMedia('(hover: hover)').matches;
  function openLook(target: LookTarget) {
    if (!proUnlocked(isPro)) {
      onLooksLocked();
      return;
    }
    // A folder's color can reach every folder below it (the subfolder
    // switch), so Cancel keeps their looks too.
    const keys = target.folderId
      ? [...subtreeIds(folders, target.folderId)].map(folderLookKey)
      : [target.lookKey];
    setLookEdit({
      target,
      before: {
        looks: snapshotLooks(userSettings.itemStyles, keys),
        tintNotes: userSettings.tintNotes,
        noteColorStyle: userSettings.noteColorStyle,
      },
    });
  }
  function openFolderLook(id: string) {
    openLook({
      kind: 'folder',
      lookKey: folderLookKey(id),
      folderId: id,
      name: foldersById.get(id)?.name ?? '',
    });
  }
  const [tagSortOpen, setTagSortOpen] = useState(false);
  // The two sidebar option menus: the gear beside the Views caption (which
  // rows the rail draws) and the funnel in the All row (which item types the
  // All list holds). One at a time - opening either closes the other.
  // Spec: ops/docs/archive/sidebar-views.md
  const [viewsMenuOpen, setViewsMenuOpen] = useState(false);
  const [allMenuOpen, setAllMenuOpen] = useState(false);
  const viewsMenuBtnRef = useRef<HTMLButtonElement>(null);
  // The list scrolls and its caption does not: a classic scrollbar (Firefox,
  // Windows) takes its width from the rows only, and the eye above stops
  // lining up with the funnel on the All row. The caption pads by that width.
  const viewsListRef = useRef<HTMLDivElement>(null);
  const viewsGutter = useScrollbarWidth(viewsListRef, !viewsCollapsed);
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

  // Trash scrolls with the tags and folds away with them. An empty trash has
  // no row, like Pinned and Archive, unless it is the open view.
  const trashRow = (trashedCount > 0 || view === 'trash') && (
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
        <span className="text-xs text-pn-muted tabular-nums">
          {trashedCount}
        </span>
      </button>
    </div>
  );

  // ── renderTagMenu ──────────────────────────────────────────────────

  // The tag actions menu, drawn at the rail's top level rather than in its
  // row: a tag chip elsewhere (the note's tag row, the list's filter chip)
  // opens the same menu while the rail shows folders.
  const renderTagMenu = () => {
    if (!openTagMenu) return null;
    const tag = openTagMenu.tag;
    const isFavorite = favoriteTagsList.some(([name]) => name === tag);
    return (
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
            className="w-full text-start px-3 py-1.5 text-[13px] text-pn-soft hover:bg-surface-1 flex items-center gap-2"
          >
            <Star weight={isFavorite ? 'fill' : 'bold'} className={isFavorite ? 'text-amber-400' : 'text-accent'} />
            {isFavorite ? t('tagsRail.removeFavorite') : t('tagsRail.markAsFavorite')}
          </button>
          <button
            onClick={() => {
              setOpenTagMenu(null);
              // The menu also opens from a tag chip (NotesView) while
              // the rail shows folders, and the rename field lives on
              // the tag row.
              if (browseMode !== 'tags') onBrowseChange('tags');
              setRenameBuffer(tag);
              setRenamingTag(tag);
            }}
            className="w-full text-start px-3 py-1.5 text-[13px] text-pn-soft hover:bg-surface-1 flex items-center gap-2"
          >
            <PencilSimple className="text-accent" />
            {t('tagsRail.renameTag')}
          </button>
          <button
            onClick={() => {
              setOpenTagMenu(null);
              openLook({ kind: 'tag', lookKey: tagLookKey(tag), name: tag, favorite: isFavorite });
            }}
            className="w-full text-start px-3 py-1.5 text-[13px] text-pn-soft hover:bg-surface-1 flex items-center gap-2"
          >
            <Palette className="text-accent" />
            <span className="flex-1">{t('looks.menu')}</span>
            {!isPro && <ProMark />}
          </button>
          <button
            onClick={() => {
              setOpenTagMenu(null);
              setNewTagDraft('');
              setCreatingTag(true);
            }}
            className="w-full text-start px-3 py-1.5 text-[13px] text-pn-soft hover:bg-surface-1 flex items-center gap-2"
          >
            <Plus className="text-accent" />
            {t('tagsRail.createTag')}
          </button>
          <div className="my-1 border-t border-divider" />
          <button
            onClick={() => {
              setOpenTagMenu(null);
              void handleDeleteTag(tag);
            }}
            className="w-full text-start px-3 py-1.5 text-[13px] text-danger hover:bg-red-50 dark:hover:bg-red-950/30 flex items-center gap-2"
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
            className="w-full text-start px-3 py-1.5 text-[13px] text-danger hover:bg-red-50 dark:hover:bg-red-950/30 flex items-center gap-2"
          >
            <Trash />
            {t('tagsRail.deleteTagAndNotes')}
          </button>
          */}
        </div>
      </>
    );
  };

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
    const dropHere = railDrop.over?.kind === 'tag' && railDrop.over.key === tag;
    const rowClass = `w-full rounded text-[15px] font-medium transition flex items-center group ${
      dropHere
        ? `${SIDEBAR_DROP_INSIDE} text-pn`
        : active
        ? SIDEBAR_ACTIVE
        : 'text-pn hover:bg-pn/5'
    }`;
    return (
      <div key={tag} className="relative">
        <div
          className={rowClass}
          // A dragged list item dropped here takes the tag (useRailItemDrop).
          // Not while the name is an input: the field would take the drop
          // as typed text.
          data-drop-tag={isRenaming ? undefined : tag}
          // The tag's color on its row, as on a folder row (FolderTreeView).
          style={sidebarRowTint(tagColorOf(tag), userSettings)}
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
            onClick={(e) => {
              if (isRenaming) return;
              if (glyphOpensLook && (e.target as HTMLElement).closest('[data-tag-glyph]')) {
                openLook({ kind: 'tag', lookKey: tagLookKey(tag), name: tag, favorite: isFavorite });
                return;
              }
              // Second click on the active tag clears the filter, the way a
              // folder row does (FolderTree.renderRow). With tag + folder +
              // view composing, nothing else in the rail would.
              void handleSelectTag(active ? null : tag);
            }}
            data-row-name={tag}
            aria-current={active || undefined}
            className="flex-1 min-w-0 flex items-center gap-2 px-2 py-2 text-start"
          >
            {/* Amber, like a folder glyph, and accent while the row is
                active - the same two states FolderTree.renderRow uses. A tag
                and a folder are the same kind of thing (a filter you keep),
                and amber is what this app now paints filters with: the chips
                in the list pane, the folder rail, this rail. A favourite
                keeps its brighter amber-400 on top of that, around its star
                or around the icon it wears. A tag's own color wins over
                both (TagGlyph). */}
            <span
              data-tag-glyph
              className={`inline-flex shrink-0 ${active ? 'text-accent' : isFavorite ? 'text-amber-400' : 'text-label'}${glyphOpensLook ? ' pn-look-glyph' : ''}`}
            >
              <TagGlyph tag={tag} favorite={isFavorite} size={16} />
            </span>
            {isRenaming ? (
              <input
                autoFocus
                tabIndex={mobileTabIndex}
                value={renameBuffer}
                onChange={(e) => setRenameBuffer(e.target.value)}
                onKeyDown={(e) => {
                  if (isImeComposing(e)) return;
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
                className="min-w-0 flex-1 bg-transparent border-b border-accent/50 focus:border-accent outline-none text-[15px] font-medium text-pn"
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
              className={SIDEBAR_ROW_MENU_BUTTON}
            >
              <DotsThree />
            </button>
          )}
          {!isRenaming && (
            <span className="text-xs text-pn-muted tabular-nums ms-2 me-2 shrink-0">
              {count}
            </span>
          )}
        </div>
      </div>
    );
  };

  // ── Main render ────────────────────────────────────────────────────

  const sortLabel = browseMode === 'tags' ? t('tagsRail.sortTags') : t('folders.sortFolders');

  // The rows Mod+1 to 9 count, after All (goToSection in NotesView): the
  // shown section rows, in the order drawn below.
  const sectionRows = sidebarViewRows(t)
    .filter((r) => showRow(r.key) && !hiddenAtZero(r.key, viewCounts[r.key], view))
    .map((r) => r.key);

  return (
    <div className="h-full flex flex-col min-h-0">
      {renderTagMenu()}
      {/* Brand row */}
      <div className="group shrink-0 min-h-[3.5rem] lg:min-h-0 lg:h-14 px-4 pt-[max(0.75rem,env(safe-area-inset-top))] lg:pt-0 border-b border-divider flex items-center gap-2">
        <h1 className="text-lg tracking-tight truncate m-0">
          <HoverLabel label={t('tagsRail.showAllItems')} keys={sectionKeyText(1)} position="end">
          <button
            type="button"
            onClick={() => handleSelectView('home')}
            aria-label={t('tagsRail.showAllItems')}
            className="pn-logo-host hover:opacity-80 transition focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 rounded flex items-center gap-1.5"
          >
            <LogoIcon size={24} tint />
            <Brand />
          </button>
          </HoverLabel>
        </h1>
        <HoverLabel label={t('tagsRail.changelog')} position="end">
        <a
          href={latestChangelogHref()}
          target="_blank"
          rel="noopener noreferrer"
          aria-label={t('tagsRail.changelog')}
          className="pn-sb-wide hidden lg:inline-flex text-[9px] font-mono px-1 py-px rounded bg-accent/10 border border-accent/30 text-accent-strong shrink-0 hover:bg-accent/20 transition focus:outline-none focus:ring-2 focus:ring-accent/40"
        >
          v{VERSION}
        </a>
        </HoverLabel>
        <button
          onClick={() => setDrawerOpen(false)}
          aria-label={t('tagsRail.closeMenu')}
          className="ml-auto lg:hidden inline-flex items-center gap-1 rounded px-2 py-1 text-xs font-medium text-pn-muted hover:bg-pn/10 transition shrink-0"
        >
          <X />
          <span>{t('common:actions.close')}</span>
        </button>
      </div>
      {/* Below lg the drawer has no Jump to row, so the switch takes that
          slot, full width, in the same look as the Tags and Folders switch:
          the open space names itself. */}
      {spaces && (
        <div className="lg:hidden shrink-0 px-3 pt-3 flex">
          <SpaceSwitch active={spaces.active} onChange={spaces.onChange} locked={spaces.locked} noAll={spaces.noAll} stretch />
        </div>
      )}
      {/* The quick switcher's button, from lg up. Below lg the list header
          carries it (ListNav), so the drawer does not repeat it.
          Spec: ops/docs/archive/keyboard-shortcuts.md (decision D15) */}
      <div className="pn-jump-row hidden lg:flex items-center gap-1.5 shrink-0 px-3 pt-3">
        {/* The tint of the "+ New" button, so the app's two main actions
            read as one family. The Ninja mark, not a magnifier: the list
            search, find in note and the settings search already draw one,
            and this button also runs commands. */}
        {spaces ? (
          <>
            {/* Beside the space switch, Ninja is the mark alone, the same height
                and tint as the switch, so the row reads as one bar. Its name
                and key slide in on hover, as a closed segment's name does,
                and a sidebar too narrow for them gets the tip instead. */}
            <HoverLabel label={t('common:quickSwitcher.jumpTo')} keys={`${keyText('quickSwitcher')} · ${KATANA_LINE}`} position="below" className="pn-sb-tip flex shrink-0">
              <button
                type="button"
                onClick={onJump}
                aria-label={t('common:quickSwitcher.jumpTo')}
                className="group pn-jump min-w-8 h-8 px-1 flex items-center justify-center rounded-md bg-accent/10 text-accent-strong transition focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent/40"
              >
                <span className="pn-jump-charge" aria-hidden="true" />
                <NinjaIcon size={24} className="shrink-0" />
                <span aria-hidden="true" className="pn-sb-wide grid grid-cols-[0fr] transition-[grid-template-columns] duration-200 group-hover:grid-cols-[1fr] group-focus-visible:grid-cols-[1fr] [@media(hover:none)]:hidden">
                  <span className="flex items-center gap-1.5 overflow-hidden whitespace-nowrap text-[13px] font-semibold opacity-0 transition-[opacity,padding] duration-200 group-hover:opacity-100 group-hover:ps-1.5 group-focus-visible:opacity-100 group-focus-visible:ps-1.5">
                    {t('common:quickSwitcher.jumpTo')}
                    <kbd dir="ltr" className="rounded border border-accent/30 px-1 font-sans text-[11px] font-normal leading-4">{keyText('quickSwitcher')}</kbd>
                  </span>
                </span>
              </button>
            </HoverLabel>
            <SpaceSwitch active={spaces.active} onChange={spaces.onChange} locked={spaces.locked} noAll={spaces.noAll} stretch />
          </>
        ) : (
          <button
            type="button"
            onClick={onJump}
            className="pn-jump flex-1 min-w-0 h-8 flex items-center gap-2 rounded-md bg-accent/10 ps-2.5 pe-1.5 text-[14px] font-semibold text-accent-strong transition focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
          >
            <span className="pn-jump-charge" aria-hidden="true" />
            <NinjaIcon size={24} className="shrink-0" />
            <span className="flex-1 truncate text-start">{t('common:quickSwitcher.jumpTo')}</span>
            <kbd dir="ltr" className="pn-sb-wide shrink-0 rounded border border-accent/30 px-1.5 font-sans text-[11px] font-normal leading-5">
              {keyText('quickSwitcher')}
            </kbd>
          </button>
        )}
      </div>
      {/* The caption row sits OUTSIDE the scrolling box below, and that is what
          lets it carry a tip at all. The row list is `overflow-y-auto`, and CSS
          forces overflow-x to `auto` with it, so that box clips on BOTH axes -
          no z-index escapes a scroll box (HoverLabel Trap 2, same reason the
          Markdown row inside opens its tip upwards). Inside the box the tip
          survived while the list was long and was cut the moment the list
          folded, because the box then shrank to the caption itself (reported
          2026-08-22). Spec: ops/docs/archive/sidebar-views.md */}
      <div
        ref={contentSectionRef}
        className={`min-h-0 flex flex-col py-3 ${keyboardUp ? 'hidden' : ''} ${markdownRail ? 'shrink border-b border-divider' : split.folded ? 'flex-1' : 'shrink'}`}
        style={splitActive && !split.folded && split.height !== null ? { flex: `0 1 ${split.height}px` } : undefined}
      >
        <div className="shrink-0 px-3" style={viewsGutter ? { paddingInlineEnd: `calc(0.75rem + ${viewsGutter}px)` } : undefined}>
        {/* Caption and gear are SIBLINGS. The caption is a button (it folds the
            list) and a button cannot contain another one. The gear sits outside
            the fold below, so the one control that brings a hidden row back
            never disappears together with the rows.
            Spec: ops/docs/archive/sidebar-views.md */}
        <HoverLabel label={t('tagsRail.sidebarOptions')} position="below-end" disabled={viewsMenuOpen} className="w-full flex items-center gap-1 px-2 mb-1">
          <button
            type="button"
            onClick={() => setViewsCollapsed((v) => !v)}
            aria-expanded={!viewsCollapsed}
            className="flex-1 min-w-0 flex items-center gap-1 text-[13px] font-bold text-pn-soft hover:text-accent dark:hover:text-accent transition"
          >
            <CaretDown size={10} className={`transition-transform ${viewsCollapsed ? '-rotate-90' : ''}`} aria-hidden="true" />
            <span>{t('tagsRail.views')}</span>
          </button>
          {/* The tip belongs to the WHOLE caption row, not to this 18px glyph:
              hovering anywhere from the caret to the eye names the control, so
              a person who never aims at the icon still learns it is there.
              Spec: ops/docs/archive/sidebar-views.md */}
          <button
            ref={viewsMenuBtnRef}
            type="button"
            onClick={() => { setAllMenuOpen(false); setViewsMenuOpen((o) => !o); }}
            aria-label={t('tagsRail.sidebarOptions')}
            aria-expanded={viewsMenuOpen}
            className={`shrink-0 inline-flex items-center justify-center rounded p-0.5 transition ${
              viewsMenuOpen
                ? 'text-accent'
                : 'text-pn-muted hover:text-accent dark:hover:text-accent'
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
        <div ref={viewsListRef} className="min-h-0 overflow-y-auto px-3">
        {/* Source of truth for creatable-pillar ORDER. The two "New" menus
            (NotesList.tsx allNewOptions + contextMenus.tsx buildGlobalMenu) MUST
            list types in this same order. Reorder all three together, never one.
            Spec: ops/docs/archive/ui-patterns.md section 45 (New-menu order invariant) */}
        {/* All is the one row with no count, which is what makes room for the
            funnel: it filters this list, and it is the same glyph the list
            panes already use for their options button. The funnel is a SIBLING
            of the row button (a button cannot nest), absolutely placed in the
            slot every other row spends on its count, and it takes the accent
            colour whenever the row is hovered rather than only the glyph
            itself. Spec: ops/docs/archive/sidebar-views.md (this filter never runs in a single-type pillar or Trash) */}
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
                  : 'text-pn-muted group-hover:text-accent hover:text-accent dark:group-hover:text-accent dark:hover:text-accent'
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
                checked: isShownInAll(userSettings, r.key),
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
            Spec: ops/docs/archive/start-view.md (one row list, one label namespace) */}
        {sidebarViewRows(t).map((r) => {
          if (!showRow(r.key)) return null;
          // Pinned and Archive hide at zero (same rule as Untagged further
          // down), and stay while they are the open view.
          if (hiddenAtZero(r.key, viewCounts[r.key], view)) return null;
          const count = viewCounts[r.key];
          const sectionKey = sectionKeyText(sectionRows.indexOf(r.key) + 2);
          const row = (
            <button
              onClick={() => handleSelectView(r.key)}
              className={`group/sec ${viewBtnClass(view === r.key)}`}
            >
              <span className="flex items-center gap-2">
                <span className="text-accent inline-flex">
                  <r.icon size={16} />
                </span>
                {r.label}
              </span>
              {/* rtl-ok: a key sequence never reorders. The section key shows
                  on hover only, as a menu shows a shortcut. */}
              {sectionKey && (
                <span dir="ltr" className="hidden [@media(hover:hover)]:group-hover/sec:inline ms-auto me-2 text-xs text-pn-muted">
                  {sectionKey}
                </span>
              )}
              {r.key === 'calendar' && calendarBell ? (
                // A reminder fired and its item is not opened yet: the count
                // takes the accent fill and the bell until it is.
                <span className="inline-flex items-center gap-0.5 rounded-full bg-accent-fill text-white px-1.5 text-xs font-semibold tabular-nums">
                  <BellSimple size={10} weight="fill" aria-hidden="true" />
                  {count}
                </span>
              ) : count !== undefined && (
                <span className="text-xs text-pn-muted tabular-nums">
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
      {/* The divider: drag to share the height, drag to the bottom to fold
          the tags or folders, double-click to put it back. It draws the
          line the Content part used to carry as its bottom border. */}
      <HoverLabel
        label={t(split.folded ? 'notes:paneResize.hintExpand' : 'notes:paneResize.hintCollapse')}
        position="below"
        className={`shrink-0 flex flex-col${keyboardUp ? ' hidden' : ''}`}
      >
        <div
          {...split.separatorProps}
          aria-label={t('tagsRail.resizeSplit')}
          className="pn-hstrip shrink-0 h-3 border-t border-b border-divider bg-surface-0 hover:bg-surface-1 text-pn-muted hover:text-accent transition"
        >
          <span className="pn-hstrip-dots" aria-hidden="true" />
        </div>
      </HoverLabel>
      {/* Browse toggle (Tags | Folders) + tag sort popover - pinned (shrink-0)
         above the scrollable list so its height is always reserved (never
         overlapped when the sidebar is short) and the absolute sort popover
         isn't clipped by the list's overflow. Folders is Pro: the segment
         carries the gold rocket while not Pro and the gate lives in
         onBrowseChange (NotesView). */}
      <div className="shrink-0 relative px-3 pt-3">
        <div className="flex items-center gap-1.5 mb-1">
          {/* Sort button on the left, pill on the right - the same
              composition as the layout switch (ViewModeToggle). The hover
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
                  className="w-8 h-8 rounded-md inline-flex items-center justify-center transition bg-surface-2 text-accent-strong ring-1 ring-inset ring-accent/40"
                >
                  <FunnelSimple size={16} aria-hidden="true" />
                </button>
              ) : (
                <HoverLabel label={sortLabel} position="end">
                  <button
                    type="button"
                    onClick={() => {
                      // Folded, the list has no room under the switch and the
                      // menu would be cut off; sorting is about the list anyway.
                      split.unfold();
                      setTagSortOpen(true);
                    }}
                    aria-label={sortLabel}
                    aria-expanded={false}
                    className="w-8 h-8 rounded-md inline-flex items-center justify-center transition bg-accent/10 text-accent-strong/70 hover:text-accent-strong hover:bg-accent/15 focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent/40"
                  >
                    <FunnelSimple size={16} aria-hidden="true" />
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
                    <div className="text-[10px] font-semibold tracking-wider text-pn-muted uppercase mb-1.5 mt-1">
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
                    {browseMode === 'folders' && treeHasBranches && (
                      <div className="mt-2 pt-2 border-t border-divider">
                        <button
                          type="button"
                          onClick={() => {
                            if (anyFolderOpen) folderExpansion.collapseAll(folders);
                            else folderExpansion.expandAll(folders);
                            setTagSortOpen(false);
                          }}
                          className="w-full flex items-center gap-2 px-2 py-1.5 rounded text-[13px] text-pn-soft hover:bg-surface-1 transition"
                        >
                          {anyFolderOpen ? (
                            <ArrowsInLineVertical className="text-accent" aria-hidden="true" />
                          ) : (
                            <ArrowsOutLineVertical className="text-accent" aria-hidden="true" />
                          )}
                          {anyFolderOpen ? t('folders.collapseAll') : t('folders.expandAll')}
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}
          {/* The space switch's look: a tinted track, the open segment a
              light pill with a filled icon and its name. A closed segment
              names itself on hover the way the footer actions do, and a
              sidebar too narrow for names gets tips instead (pn-browse in
              index.css). Folders carries the Pro mark on its icon while not Pro,
              and the gate lives in onBrowseChange (NotesView). */}
          <div
            role="group"
            aria-label={t('browseToggle.label')}
            onKeyDown={onSwitchKeyDown}
            className="pn-browse flex-1 min-w-0 flex gap-0.5 rounded-md bg-accent/10 p-0.5"
          >
            {(['tags', 'folders'] as const).map((mode) => {
              // Folded, neither shows as open: the list it would name is away.
              const on = browseMode === mode && !split.folded;
              const label = t(`browseToggle.${mode}`, exemptOpts(`shell:browseToggle.${mode}`));
              const pro = mode === 'folders' && !isPro;
              const ModeIcon = mode === 'tags' ? Hash : Folder;
              const filled = mode === 'tags' ? 'bold' : 'fill';
              return (
                <HoverLabel key={mode} label={label} pro={pro} position="below" className={`pn-sb-tip pn-browse-seg${on ? ' is-open' : ''}`}>
                  <button
                    type="button"
                    onClick={(e) => {
                      // Left and Right on the switch press the other segment
                      // with a script click, and focus stays on the switch.
                      if (e.isTrusted) {
                        const visible = e.detail === 0;
                        if (browseMode === mode && !split.folded) focusBrowseList(visible);
                        else focusListFor.current = { mode, at: Date.now(), visible };
                      }
                      split.unfold();
                      onBrowseChange(mode);
                    }}
                    {...railDrop.switchProps(mode)}
                    aria-pressed={on}
                    aria-label={pro ? `${label} (Pro)` : label}
                    className={`group w-full min-w-0 h-7 flex items-center justify-center px-1.5 rounded transition focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent/40 ${
                      on ? 'bg-surface-2 text-accent-strong' : 'text-accent-strong/60 hover:text-accent-strong hover:bg-surface-2/60'
                    }`}
                  >
                    <ProGlyph pro={pro}>
                      <ModeIcon size={16} weight={on ? filled : 'regular'} className={on ? '' : 'group-hover:hidden'} aria-hidden="true" />
                      {!on && <ModeIcon size={16} weight={filled} className="hidden group-hover:inline-flex" aria-hidden="true" />}
                    </ProGlyph>
                    <span aria-hidden="true" className="pn-sb-wide pn-browse-name">
                      <span className="text-[13px] font-semibold">{label}</span>
                    </span>
                  </button>
                </HoverLabel>
              );
            })}
          </div>
        </div>
      </div>
      {!split.folded && (
      // pb-1, not more: the bottom padding counts as content, so a deeper one
      // shows the scrollbar while Trash still has room under it.
      <div ref={browseListRef} onKeyDown={onRowListKeyDown} {...railDrop.listProps} className="flex-1 overflow-y-auto overflow-x-hidden px-3 pb-1 min-h-0">
        {browseMode === 'folders' ? (
          <FolderTree
            folders={folders}
            counts={folderCounts}
            dimEmpty={folderCountsScoped}
            unfiledCount={unfiledCount}
            selectedFolder={selectedFolder}
            openNoteFolder={openNoteFolder}
            onSelectFolder={onSelectFolder}
            onCreateFolder={onCreateFolder}
            onRenameFolder={onRenameFolder}
            onRequestMove={onRequestMoveFolder}
            onReorderFolders={onReorderFolders}
            onRequestDelete={onRequestDeleteFolder}
            locked={foldersLocked}
            looksProMark={!isPro}
            onLockedAction={onFoldersLockedAction}
            onEditLook={openFolderLook}
            onGlyphClick={glyphOpensLook ? openFolderLook : undefined}
            itemDrop={{ overId: railDrop.over?.kind === 'folder' ? railDrop.over.key : null }}
            spaceMove={spaces?.onMoveFolder && ((id) => {
              const to: Space = spaces.folderSpace?.(id) === 'work' ? 'personal' : 'work';
              return { label: <SpaceMoveLabel to={to} />, icon: SPACE_ICONS[to], run: () => spaces.onMoveFolder?.(id, to) };
            })}
            emptyText={spaces?.active === 'work' ? t('spaces.workEmpty') : undefined}
            sortField={folderSortField}
            sortDir={folderSortDir}
            mobileTabIndex={mobileTabIndex}
          />
        ) : (<>
        {tagCounts.tags.length === 0 && !creatingTag && (
          <div className="text-[13px] text-pn-muted px-2 py-1">
            {t('tagsRail.noTagsYet')}
          </div>
        )}
        {favoriteTagsList.map(([tag, count]) =>
          renderTagRow(tag, count, true)
        )}
        {nonFavoriteTagsList.map(([tag, count]) =>
          renderTagRow(tag, count, false)
        )}
        {tagCounts.untagged > 0 && (
          <button
            onClick={() => handleSelectTag(selectedTag === '__untagged__' ? null : '__untagged__')}
            className={`w-full text-start px-2 py-2 rounded text-[15px] font-medium transition flex justify-between items-center ${
              selectedTag === '__untagged__'
                ? SIDEBAR_ACTIVE
                : 'text-pn-muted hover:bg-pn/5 hover:text-pn-soft'
            }`}
          >
            <span className="flex items-center gap-2 min-w-0">
              <span className="inline-flex shrink-0">
                <Prohibit size={16} />
              </span>
              <span className="truncate">{t('tagsRail.untagged')}</span>
            </span>
            <span className="text-xs tabular-nums">
              {tagCounts.untagged}
            </span>
          </button>
        )}
        {creatingTag ? (
          <div className="w-full rounded text-[15px] font-medium transition flex items-center text-pn">
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
                  if (isImeComposing(e)) return;
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
                className="min-w-0 flex-1 bg-transparent border-b border-accent/50 focus:border-accent outline-none text-[15px] font-medium text-pn placeholder:text-pn-muted"
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
               Spec: ops/docs/archive/ui-patterns.md (section 76) */
            className="w-full mt-2 rounded-md border border-dashed border-divider hover:border-accent/50 text-[15px] font-medium transition flex items-center justify-start gap-2 ps-[7px] pe-2 py-2 text-pn-muted hover:text-accent"
          >
            <Plus size={16} className="shrink-0 text-label" />
            <span className="truncate">{t('tagsRail.createTag')}</span>
          </button>
        )}
        </>)}

        {trashRow}

      </div>
      )}
      </>)}

      {/* Footer actions - five icon buttons: Help, Downloads | Import,
          Feedback, Rate. The two external links sit left of a hairline
          divider; the in-app actions sit right of it. Labels reveal as an
          inline expanding pill on hover; touch devices render icons only
          (FooterAction above). Hidden on very short viewports (before the
          footer) so the primary nav keeps room. The row inset plus the
          button's own px-1 puts the first and last glyph 20px from the
          sidebar edges, the inset of the sidebar rows and of the app
          footer's Settings zone below. Spec: ops/docs/archive/ui-patterns.md section 46 (legacy guard, predates the height-tier scale) */}
      <div className="shrink-0 border-t border-divider px-4 py-1 flex items-stretch justify-between gap-0.5 [@media(max-height:450px)]:hidden">
        <FooterAction
          icon={Question}
          label={t('tagsRail.help')}
          href={siteHref(helpPath(activeLocale()))}
          tip="above-start"
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
          label={updateVersion ? updateTipLabel : downloadsLabel}
          position="above-start"
          // With no update the tip only names the action, and only in a
          // narrow sidebar, where the pill has no room (pn-sb-tip).
          className={`${updateVersion ? '' : 'pn-sb-tip '}flex [@media(hover:none)]:flex-1`}
        >
          <FooterAction
            icon={Devices}
            label={downloadsLabel}
            ariaLabel={updateVersion ? `${updateTipLabel} (v${updateVersion})` : undefined}
            badge={!!updateVersion}
            href={`${marketingHomeHref()}#downloads`}
            tip={null}
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
        <FooterAction icon={Star} label={t('tagsRail.rate')} onClick={onRate} tip="above-end" />
      </div>
      {lookEdit && (
        <Suspense fallback={null}>
          <LookPicker
            target={lookEdit.target}
            styles={userSettings.itemStyles}
            subfolderIds={lookSubfolderIds}
            noteColors={noteColorChoice(userSettings.tintNotes, userSettings.noteColorStyle)}
            onPick={(patch) => {
              lookSaved.current = true;
              mutateSettings((prev) => {
                const { kind, lookKey, folderId } = lookEdit.target;
                let itemStyles: typeof prev.itemStyles;
                if (kind === 'folder' && folderId && patch.color !== undefined) {
                  // Through the folder writer, so the copies below follow
                  // while the subfolder switch is on.
                  const { color, ...rest } = patch;
                  itemStyles = setFolderColor(prev.itemStyles, folderId, prev.folders, isLookColor(color) ? color : null);
                  itemStyles = setItemLook(itemStyles, lookKey, rest);
                } else {
                  itemStyles = setItemLook(prev.itemStyles, lookKey, patch);
                }
                return itemStyles === prev.itemStyles ? prev : { ...prev, itemStyles };
              });
            }}
            onSubfoldersFollow={(on) => {
              const id = lookEdit.target.folderId;
              if (!id) return;
              lookSaved.current = true;
              mutateSettings((prev) => {
                const color = folderColor(id, prev.itemStyles);
                if (!color) return prev;
                // Off clears only the copies, never a color a subfolder chose.
                const itemStyles = on
                  ? setSubfolderColors(prev.itemStyles, id, prev.folders, color)
                  : setSubfolderColors(prev.itemStyles, id, prev.folders, null, color);
                return itemStyles === prev.itemStyles ? prev : { ...prev, itemStyles };
              });
            }}
            onNoteColors={(next) => {
              lookSaved.current = true;
              mutateSettings((prev) => applyNoteColorChoice(prev, next));
            }}
            onCancel={() => {
              const { before } = lookEdit;
              mutateSettings((prev) => {
                const itemStyles = restoreLooks(prev.itemStyles, before.looks);
                if (
                  itemStyles === prev.itemStyles &&
                  prev.tintNotes === before.tintNotes &&
                  prev.noteColorStyle === before.noteColorStyle
                ) {
                  return prev;
                }
                return { ...prev, itemStyles, tintNotes: before.tintNotes, noteColorStyle: before.noteColorStyle };
              });
            }}
            onClose={() => {
              setLookEdit(null);
              if (lookSaved.current) {
                lookSaved.current = false;
                onLooksSaved();
              }
            }}
          />
        </Suspense>
      )}
    </div>
  );
}

/**
 * The width a classic scrollbar takes from the element's content, or 0 for an
 * overlay scrollbar (macOS Chrome and Safari) and while nothing overflows.
 * The ResizeObserver fires when the scrollbar appears or goes, because the
 * content box changes width with it.
 */
function useScrollbarWidth(ref: React.RefObject<HTMLElement | null>, active: boolean): number {
  const [width, setWidth] = useState(0);
  useEffect(() => {
    const el = ref.current;
    if (!active || !el) {
      setWidth(0);
      return;
    }
    const measure = () => setWidth(el.offsetWidth - el.clientWidth);
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, [ref, active]);
  return width;
}
