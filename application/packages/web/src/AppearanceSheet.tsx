import { Suspense, useEffect, useRef, useState, type MouseEvent, type ReactNode } from 'react';
import { lazyPart } from './chunkLoad';
import { usePopoverPosition } from './usePopoverPosition';
import { Trans, useTranslation } from 'react-i18next';
import { useEscapeToClose } from './useEscapeToClose';
import { HelpChip } from './HelpChip';
import type { FormatBarBoardProps } from './FormatBarBoard';
import {
  useTheme,
  type Theme,
  getSystemTheme,
  type ThemeMode,
  type ColorTheme,
  type ThemeChoice,
  type CustomSnapshot,
  customChoice,
  isFreeTheme,
  previewCustomTheme,
  type TextSize,
  type ContentWidth,
  THEME_MODES,
  LIGHT_THEMES,
  DARK_THEMES,
  THEME_DISPLAY_NAME,
  FREE_THEMES,
  TEXT_SIZES,
  CONTENT_WIDTHS,
  LINE_SPACINGS,
  resetStyleAxes,
  resetThemeAxes,
  peekThemeMode,
  customIdOf,
  paintedSlot,
  themeSwatch,
  type LineSpacing,
} from './theme';
import { APP_ZOOM_LEVELS, DEFAULT_APP_ZOOM, appZoomSupported, useAppZoom } from './appZoom';
import { intlLocale } from './languages';
import { IconUpgrade, ProMark, type UpgradeTrigger } from './UpgradeModal';
import { proUnlocked } from './demo';
import { ArrowCounterClockwise, Folder, X, List, ListBullets, Palette, Star, Toolbox, SquaresFour, Sparkle, DotsThreeOutlineVertical, CaretDown, CaretRight, Globe, Plus, ClipboardText, ArrowSquareOut, PencilSimple, Copy, UserSwitch, TextT, TextAlignJustify, FrameCorners, PencilLine, HouseLine, Layout, MagnifyingGlassPlus, Tabs, Paragraph, ListChecks, CheckSquare, Confetti, CircleHalf, PaintBucket, Sun, Moon, Files, PILLAR_GLYPHS, type Icon } from './icons';
import { DefaultAppSettingsRow } from './markdownFolder/MarkdownDefaultApp';
import { markdownDefaultAppSupported } from './markdownFolder/defaultApp';
import type { BUILTIN_THEME_CODES } from './builtinThemeCodes';
import type { CustomThemes } from './customThemes';
import type { ThemeGalleryCtx } from './customThemeUI';
import type { ThemeBuilderTarget } from './notesView/useThemeBuilder';
import { CardMenuButton, ProCorner, QuickCorner, QuickStarButton } from './ThemeCardMenuButton';
import { QUICK_THEMES_MAX, quickThemesFor, restoreQuickThemes, toggleQuickTheme, useQuickThemeMarks } from './quickThemes';
import { ContextMenu, useContextMenu, type ContextMenuItem } from './ContextMenu';
import { siteHref } from './siteLinks';

// The team and custom theme cards and the paste field: a lazy chunk with
// the theme code module, so none of it is on the boot path.
import type { MadeBy } from './customThemeUI';
import type { CommunitySort } from './communityShown';
const ExtraThemeCards = lazyPart(() => import('./customThemeUI').then((m) => m.ExtraThemeCards));
const ThemePasteField = lazyPart(() => import('./customThemeUI').then((m) => m.ThemePasteField));
const FormatBarBoard = lazyPart(() => import('./FormatBarBoard').then((m) => m.FormatBarBoard));
import { exemptOpts } from './i18nExempt';
import { AccentBar, EYEBROW_ICON_ROW, EyebrowGlyph, HeadlineRule, ROW_TITLE, ResetDefaultsButton, RowTitle, SectionEyebrow, SETTINGS_BTN, SETTINGS_EYEBROW, SETTINGS_HELP, SettingsTabStrip, settingsTabClass, SETTINGS_TRACK } from './settingsUI';
import { Switch } from './Switch';
import { useOpenItemsInTabs, useTabsFit } from './notesView/useOpenTabs';
import { faviconUrl } from './favicon';
import { ViewCheckBox } from './SidebarOptionsPopover';
import { allViewRows, resolveStartView, sidebarViewRows, startViewRows } from './viewRows';
import { ViewMenu } from './ViewMenu';
import type { View } from './views';
import { defaultSettings, isShownInAll } from './userSettings';
import { NOTE_COLOR_CHOICES, NOTE_COLOR_LABEL, noteColorChoice, type NoteColorChoice } from './itemStyles';
import { CloseButton } from './ui';
import { NoteColorExample } from './looks/NoteColorExample';
import { usePaneTab } from './settingsPaneTab';

type Props = {
  isPro: boolean;
  /** Opens the upgrade window; no trigger means the theme pitch. */
  onOpenUpgrade: (trigger?: UpgradeTrigger) => void;
  onClose: () => void;
  /** Render inline as a settings pane (no popover chrome, no outside-click). */
  embedded?: boolean;
  /** Global notes layout, and its setter. */
  viewMode: 'auto' | 'list' | 'grid';
  onViewModeChange: (mode: 'auto' | 'list' | 'grid') => void;
  /** Default editor mode for note bodies, and its setter. */
  editorMode: 'formatted' | 'markdown';
  onEditorModeChange: (mode: 'formatted' | 'markdown') => void;
  /** The Format bar tab's board. Without it the tab is not shown. */
  formatBar?: FormatBarBoardProps;
  /** Gap between two paragraphs in a note body, and its setter. */
  lineSpacing: LineSpacing;
  onLineSpacingChange: (next: LineSpacing) => void;
  /** Views switched off in the sidebar, and item types switched out of the
   *  All list. Both also live behind the rail's own two icons - this is the
   *  same field shown twice, like View. Spec: ops/docs/archive/sidebar-views.md */
  hiddenViews: View[];
  hiddenInAll: View[];
  archivedInAll: boolean;
  onToggleHidden: (field: 'hiddenViews' | 'hiddenInAll', key: View) => void;
  /** The view the app opens on at a cold start, and its setter.
   *  Spec: ops/docs/archive/start-view.md */
  startView: View;
  onStartViewChange: (next: View) => void;
  /** How a note shows its folder, tag or own color: a background, an accent
   *  on its icon, or off. The same control the look picker shows.
   *  Spec: ops/docs/archive/note-color-style.md (section 3) */
  noteColors: NoteColorChoice;
  onNoteColorsChange: (next: NoteColorChoice) => void;
  /** Whether a ticked task moves below the open tasks of its list, in the
   *  editor and in the Tasks view. */
  sinkCheckedTasks: boolean;
  onSinkCheckedTasksChange: (on: boolean) => void;
  taskConfetti: boolean;
  onTaskConfettiChange: (on: boolean) => void;
  /** Lists only: which of its two tabs opens. */
  initialTab?: string;
  /** Personal and Work. Spec: ops/docs/plans/spaces.md */
  spaces: boolean;
  onSpacesChange: (on: boolean) => void;
  /** Embedded only: which Settings entry this is. Design is the look,
   *  Editor is writing, Format bar is its board, Lists is finding things. */
  pane?: AppearancePane;
  /** Popover only: open Settings on one of the three panes, and on one row of
   *  it when `row` names a settings search id ("All themes" lands on the
   *  themes). */
  onOpenAll?: (pane: AppearancePane, row?: string) => void;
  /** The color themes a person made, from the settings blob.
   *  Spec: ops/docs/color-themes.md (section 6) */
  customThemes: CustomThemes;
  /** Embedded pane only: save or delete a custom theme. */
  onCustomThemesChange?: (update: (prev: CustomThemes) => CustomThemes) => void;
  /** Embedded pane only: open the theme builder, empty, on a theme, or on a
   *  copy of one. */
  onOpenThemeBuilder?: (target: ThemeBuilderTarget) => void;
};

/** Translation key per text size. Keeps the order in TEXT_SIZES. */
const TEXT_SIZE_LABEL: Record<TextSize, string> = {
  xs: 'appearance.textSizeSmallest',
  sm: 'appearance.textSizeSmall',
  md: 'appearance.textSizeDefault',
  lg: 'appearance.textSizeLarge',
  xl: 'appearance.textSizeLargest',
};

/** Translation key per line spacing. Keeps the order in LINE_SPACINGS. */
const LINE_SPACING_LABEL: Record<LineSpacing, string> = {
  tight: 'appearance.lineSpacingTight',
  compact: 'appearance.lineSpacingCompact',
  normal: 'appearance.lineSpacingNormal',
};

/** Translation key per content width. Keeps the order in CONTENT_WIDTHS. */
const CONTENT_WIDTH_LABEL: Record<ContentWidth, string> = {
  default: 'appearance.contentWidthDefault',
  wide: 'appearance.contentWidthWide',
  full: 'appearance.contentWidthFull',
};

/** Glyph size per text size. The control shows a scaled "A" per option -
    the "A" is a size preview, not copy; the translated size word stays as
    the option's aria-label and title. */
const TEXT_SIZE_GLYPH: Record<TextSize, string> = {
  xs: 'text-[9px]',
  sm: 'text-[11px]',
  md: 'text-[13px]',
  lg: 'text-[15px]',
  xl: 'text-[17px]',
};

/** A glyph welded to the word it labels, for a heading that names a column.
    Trans clones this and replaces only the children, so `icon` survives. */
function IconWord({ icon: Glyph, children }: { icon: Icon; children?: ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <Glyph size={14} className="text-accent shrink-0" aria-hidden="true" />
      {children}
    </span>
  );
}

/** Segmented-control option states, shared by both layouts. */
const SEG_ACTIVE = 'bg-surface-2 shadow-sm text-pn font-semibold';
const SEG_IDLE = 'text-pn-soft hover:text-pn font-medium';
/**
 * Option width inside a segmented track, embedded pane only: the options
 * split the track evenly while the row is stacked (narrow), and shrink back
 * to hugging their labels once the row is one line (lg and up).
 */
const SEG_FILL = 'flex-1 px-3 lg:flex-none';

export type AppearancePane = 'design' | 'editor' | 'formatBar' | 'lists';

export function AppearanceSheet({ isPro, onOpenUpgrade, onClose, embedded = false, viewMode, onViewModeChange, editorMode, onEditorModeChange, formatBar, lineSpacing, onLineSpacingChange, hiddenViews, hiddenInAll, archivedInAll, onToggleHidden, startView, onStartViewChange, noteColors, onNoteColorsChange, sinkCheckedTasks, onSinkCheckedTasksChange, taskConfetti, onTaskConfettiChange, initialTab, spaces, onSpacesChange, pane = 'design', onOpenAll, customThemes, onCustomThemesChange, onOpenThemeBuilder }: Props) {
  const { t } = useTranslation('settings');
  // The table's row labels are the sidebar's own strings, so the pane and the
  // rail can never disagree in any language.
  const { t: tShell } = useTranslation('shell');
  // Which part of the embedded pane shows: Themes is the palette pair and the
  // mode, Text and layout (id `style`) is how text and panes are set, Lists
  // is what the lists hold. The footer popover has no tab strip - it renders
  // a subset of the first two. Spec: ops/docs/archive/ui-patterns.md section 36

  const [startMenuOpen, setStartMenuOpen] = useState(false);
  // Lists has two tabs: General, and the Sidebar and All table.
  const [listsTab, setListsTab] = usePaneTab<'general' | 'sidebar'>('lists', initialTab === 'sidebar' ? 'sidebar' : 'general');
  // The example starts closed: the pane already runs a long column of rows,
  // and a sample that is always open makes one group several times the height
  // of every other for a reader who never asked to see it. The first click on
  // either control above it opens it, because that click is the moment the
  // reader is asking what the option does.
  const [spacingExampleOpen, setSpacingExampleOpen] = useState(false);
  // The Note colors example, closed until asked for, like the one above; a
  // click on an option opens it.
  const [noteExampleOpen, setNoteExampleOpen] = useState(false);
  // The popover renders no example, so nothing there should arm one: the note
  // is still on screen behind it and is the better demonstration.
  const revealExample = () => {
    if (embedded) setSpacingExampleOpen(true);
  };
  const startBtnRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  // The popover opens above the Design button that opened it. Both footers
  // carry one and CSS hides the other, so the one with a box is the one on
  // screen. At the end of the desktop footer it lines up with the button's
  // end edge; at the start of the phone bar it centres on the screen, which
  // on a phone is nearly the full width anyway. A popover opened without a
  // button (a shortcut) falls back to the footer's end corner.
  const [trigger] = useState(() => (embedded ? null
    : [...document.querySelectorAll<HTMLElement>('[data-appearance-trigger]')].find((el) => el.getClientRects().length > 0) ?? null));
  const triggerRef = useRef(trigger);
  const triggerRect = trigger?.getBoundingClientRect();
  const centred = !!triggerRect && triggerRect.left + triggerRect.width / 2 < window.innerWidth / 2;
  const popPos = usePopoverPosition(!!trigger, triggerRef, panelRef, { gap: 8, align: 'end', shrink: true });
  const { theme, themeMode, setThemeMode, colorTheme, lightTheme, darkTheme, setColorTheme, pickTheme, previewColor, textSize, setTextSize, contentWidth, setContentWidth, favicons, setFavicons, invisibles, setInvisibles, copyFormat, setCopyFormat, pasteFormat, setPasteFormat } = useTheme();
  // Its own store rather than an axis of useTheme(): a level is handed to the
  // webview under the page, not to a CSS variable on <html>, and keeping it
  // out of theme.ts keeps that module free of a native import on the boot
  // path. Spec: ops/docs/design-decisions.md (app zoom)
  const { appZoom, setAppZoom } = useAppZoom();
  const [openItemsInTabs, setOpenItemsInTabs] = useOpenItemsInTabs();
  // No strip below the pane layout, so no switch for it either.
  const tabsFit = useTabsFit();
  const exampleFavicon = faviconUrl('google.com');

  // The public demo unlocks every palette so visitors can try them for
  // real (they persist, no revert). The rocket badge on each card still
  // keys off isPro, so the themes stay labelled as Pro.
  const themesUnlocked = proUnlocked(isPro);

  // Remember the pair when the sheet opened so we can revert previews.
  const savedThemesRef = useRef<Record<Theme, ThemeChoice>>({ light: lightTheme, dark: darkTheme });

  // The live pair for the unmount cleanup below (avoids a stale closure).
  const liveThemesRef = useRef<Record<Theme, ThemeChoice>>({ light: lightTheme, dark: darkTheme });
  liveThemesRef.current = { light: lightTheme, dark: darkTheme };

  // Put back any slot that shows a Pro palette a free user only previewed.
  function revertPreviews(live: Record<Theme, ThemeChoice>) {
    if (themesUnlocked) return;
    for (const mode of ['light', 'dark'] as const) {
      if (!isFreeTheme(live[mode])) setColorTheme(mode, savedThemesRef.current[mode]);
    }
  }

  // True while handing off to the upgrade modal - the modal owns the
  // revert then (NotesView reverts on upgrade-modal close).
  const upgradeHandoffRef = useRef(false);

  // Revert un-persisted pro previews on unmount. The embedded settings
  // pane never reaches handleClose (no escape/outside-click/X), so
  // closing Settings or switching panes would otherwise leave a free
  // user on a pro theme for the rest of the session.
  useEffect(() => {
    return () => {
      peekThemeMode(null);
      if (upgradeHandoffRef.current) return;
      revertPreviews(liveThemesRef.current);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEscapeToClose(() => handleClose(), !embedded);

  // Close on click outside. A press on the footer button that opened the
  // popover is left to that button, which toggles it: closing here as well
  // would let the same click open it again.
  useEffect(() => {
    if (embedded) return;
    function onClick(e: PointerEvent) {
      const target = e.target as Element;
      if (target.closest?.('[data-appearance-trigger]')) return;
      if (panelRef.current && !panelRef.current.contains(target)) {
        handleClose();
      }
    }
    const id = setTimeout(() => document.addEventListener('pointerdown', onClick), 50);
    return () => { clearTimeout(id); document.removeEventListener('pointerdown', onClick); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function handleClose() {
    // If the user isn't pro and previewed a pro theme, revert to what
    // they had when the sheet opened (which must be a free theme).
    peekThemeMode(null);
    revertPreviews({ light: lightTheme, dark: darkTheme });
    onClose();
  }

  // A free user previewing a Pro palette in either slot.
  const previewing = !themesUnlocked && (!isFreeTheme(lightTheme) || !isFreeTheme(darkTheme));

  // The card menus and the paste field. The team and custom cards
  // themselves are ExtraThemeCards, a lazy chunk.
  const themeMenu = useContextMenu();
  // The themes marked for the quick menu, and the "..." row that marks one.
  const quickMarks = useQuickThemeMarks();
  // A fourth star pushes the oldest out; the pane says which, with Undo.
  const [droppedFav, setDroppedFav] = useState<{ mode: Theme; name: string; before: ThemeChoice[] } | null>(null);
  const starTheme = (mode: Theme, choice: ThemeChoice) => {
    const { dropped, before } = toggleQuickTheme(mode, choice);
    if (!dropped) {
      setDroppedFav(null);
      return;
    }
    // A custom theme's name is in the card chunk, loaded with the cards.
    const id = customIdOf(dropped);
    if (!id) {
      setDroppedFav({ mode, name: THEME_DISPLAY_NAME[dropped as ColorTheme], before });
      return;
    }
    void import('./customThemeUI').then((m) => setDroppedFav({ mode, name: m.themeNameOf(id, customThemes) ?? '', before }));
  };
  const [pasteOpen, setPasteOpen] = useState(false);
  // The gallery's Made by filter, the same one /themes has. Per visit.
  const [madeBy, setMadeBy] = useState<MadeBy>('all');
  // The order of the community themes under Community. Per visit.
  // Newest first: an installed app's saved vote counts can be months old.
  const [communitySort, setCommunitySort] = useState<CommunitySort>('newest');
  const [copiedName, setCopiedName] = useState<string | null>(null);
  // The built-in palettes' codes, for their card menus: off the boot path like
  // the rest of the theme code, and here long before a menu can open. Loaded
  // ahead, not on the click, because a clipboard write after a wait loses the
  // click that allowed it.
  const [builtinCodes, setBuiltinCodes] = useState<typeof BUILTIN_THEME_CODES | null>(null);
  useEffect(() => {
    void import('./builtinThemeCodes').then((m) => setBuiltinCodes(m.BUILTIN_THEME_CODES));
  }, []);

  // The mode only picks which slot is painted; the pair stays as it is.
  function handleModeClick(target: ThemeMode) {
    if (target === themeMode) return;
    setThemeMode(target);
  }

  function handleThemeClick(mode: Theme, t: ThemeChoice, snapshot?: CustomSnapshot) {
    // A click always shows the pick. A kept pick moves the screen to its
    // mode for good, Auto included (pickTheme); a free account's preview of
    // a Pro theme only peeks, so a preview never changes the stored mode.
    const keeps = themesUnlocked || isFreeTheme(t);
    if (keeps) {
      pickTheme(mode, snapshot ?? t);
      savedThemesRef.current = { ...savedThemesRef.current, [mode]: t };
      return;
    }

    // Free user clicked a pro theme: preview visually (no localStorage
    // write) so the user sees it live but it won't survive a reload.
    if (mode !== theme) peekThemeMode(mode);
    if (snapshot) previewCustomTheme(mode, snapshot);
    else previewColor(mode, t);
  }

  /** "<name> copy", shortened so that it still fits a theme name. */
  function copyName(name: string): string {
    let base = [...name];
    for (;;) {
      const out = t('appearance.custom.copyName', { name: base.join('').trimEnd() });
      if ([...out].length <= 32 || base.length <= 1) return out;
      base = base.slice(0, -1);
    }
  }

  function showCopied(name: string) {
    setCopiedName(name);
    window.setTimeout(() => setCopiedName(null), 2500);
  }

  /** A built-in palette's menu, read from its exact code. */
  function openBuiltinMenu(e: MouseEvent<HTMLButtonElement>, mode: Theme, ct: ColorTheme) {
    const code = builtinCodes?.[mode][ct];
    if (!code) return;
    const name = THEME_DISPLAY_NAME[ct];
    openCardMenu(e, [
      {
        label: t('appearance.custom.makeCopy'),
        icon: <PencilSimple size={14} />,
        onSelect: () => onOpenThemeBuilder?.({ code, name: copyName(name) }),
      },
      {
        label: t('appearance.custom.copyCode'),
        icon: <Copy size={14} />,
        onSelect: () => void navigator.clipboard?.writeText(code).then(() => showCopied(name)),
      },
    ]);
  }

  /** A card's "..." menu opens beside its button, toward the card's start,
   *  with its top at the button's top, never under the pointer. */
  function openCardMenu(e: MouseEvent<HTMLButtonElement>, items: ContextMenuItem[]) {
    const r = e.currentTarget.getBoundingClientRect();
    const rtl = document.documentElement.dir === 'rtl';
    const at = { clientX: rtl ? r.right + 4 : r.left - 4, clientY: r.top, preventDefault: () => e.preventDefault(), stopPropagation: () => e.stopPropagation() };
    themeMenu.open(at, items, false, undefined, true);
  }

  const galleryCtx: ThemeGalleryCtx = {
    customThemes,
    isPro,
    canSave: themesUnlocked,
    lightTheme,
    darkTheme,
    painted: theme,
    pick: handleThemeClick,
    openMenu: openCardMenu,
    copyName,
    onCopied: showCopied,
    setColorTheme,
    openUpgrade: () => { upgradeHandoffRef.current = true; onOpenUpgrade(); },
    quickMarks,
    star: starTheme,
    onChange: onCustomThemesChange,
    openBuilder: onOpenThemeBuilder,
  };

  // One theme card: a three-stripe swatch (sidebar, accent, text) over the
  // name, with the Pro mark on a locked palette. The pane and the popover
  // share it; `compact` is the popover's four-in-a-row size.
  function themeCard(mode: Theme, ct: ColorTheme, active: boolean, compact: boolean) {
    // Badge only - keyed off isPro, not themesUnlocked, so the demo still
    // shows which palettes are Pro while using them.
    const locked = !isPro && !FREE_THEMES.has(ct);
    const [c1, c2, c3] = themeSwatch(ct, mode === 'dark');
    const card = (
      <button
        key={`${mode}-${ct}`}
        type="button"
        onClick={() => handleThemeClick(mode, ct)}
        aria-pressed={active}
        className={`w-full min-w-0 rounded-lg border transition flex flex-col items-center ${compact ? 'p-1.5 gap-1' : 'p-2 gap-1.5'} ${
          active ? 'border-accent ring-1 ring-accent/30' : 'border-divider hover:border-pn-muted'
        }`}
      >
        <span className={`relative w-full ${compact ? 'h-6' : 'h-9'} rounded overflow-hidden flex`}>
          <span className="flex-1" style={{ backgroundColor: c1 }} />
          <span className="flex-1" style={{ backgroundColor: c2 }} />
          <span className="flex-1" style={{ backgroundColor: c3 }} />
          {locked && <ProCorner />}
          {!compact && !onOpenThemeBuilder && quickMarks[mode].includes(ct) && <QuickCorner />}
        </span>
        <span className={`${compact ? 'text-[10px]' : 'text-[11px]'} font-medium text-pn-muted flex items-center gap-1 max-w-full`}>
          <span className="line-clamp-2 text-center break-words">{THEME_DISPLAY_NAME[ct]}</span>
        </span>
      </button>
    );
    if (compact || !onOpenThemeBuilder) return card;
    return (
      <div key={`${mode}-${ct}`} className="group/card relative min-w-0">
        {card}
        <QuickStarButton
          name={THEME_DISPLAY_NAME[ct]}
          marked={quickMarks[mode].includes(ct)}
          onToggle={() => starTheme(mode, ct)}
        />
        <CardMenuButton name={THEME_DISPLAY_NAME[ct]} onClick={(e) => openBuiltinMenu(e, mode, ct)} />
      </div>
    );
  }

  const unlockNudge = previewing && (
    <button
      type="button"
      onClick={() => { upgradeHandoffRef.current = true; onOpenUpgrade(); }}
      className="mt-3 w-full flex items-center justify-center gap-1 text-[11px] font-medium text-accent hover:underline transition"
    >
      <IconUpgrade size={12} /> {t('appearance.unlockThemes')}
    </button>
  );

  // Each pane resets exactly the rows it shows. The device axes go back
  // through their own setters; the synced ones go through the same callbacks
  // their rows use, so the defaults are read from the settings blob's own
  // and never copied.
  function resetStyle() {
    const d = defaultSettings();
    resetStyleAxes();
    onLineSpacingChange(d.lineSpacing);
    onEditorModeChange(d.editorMode);
    onSinkCheckedTasksChange(d.sinkCheckedTasks);
    onTaskConfettiChange(d.taskConfetti);
  }

  function resetThemes() {
    const d = defaultSettings();
    resetThemeAxes();
    setAppZoom(DEFAULT_APP_ZOOM);
    onNoteColorsChange(noteColorChoice(d.tintNotes, d.noteColorStyle));
    savedThemesRef.current = { light: 'default', dark: 'default' };
  }

  function resetLists() {
    const d = defaultSettings();
    setFavicons(true);
    onStartViewChange(d.startView);
    onViewModeChange(d.viewMode);
    setOpenItemsInTabs(true);
    for (const v of hiddenViews) onToggleHidden('hiddenViews', v);
    for (const v of hiddenInAll) onToggleHidden('hiddenInAll', v);
    if (archivedInAll) onToggleHidden('hiddenInAll', 'archive');
  }

  const modeButtons = THEME_MODES.map((mode) => (
    <button
      key={mode}
      onClick={() => handleModeClick(mode)}
      aria-pressed={themeMode === mode}
      className={`${embedded ? SEG_FILL : 'flex-1'} inline-flex items-center justify-center gap-1.5 text-xs py-1.5 rounded transition ${
        themeMode === mode ? SEG_ACTIVE : SEG_IDLE
      }`}
    >
      {mode === 'auto' && <Sparkle size={14} />}
      {mode === 'auto'
        ? t('appearance.modeAuto', exemptOpts('settings:appearance.modeAuto'))
        : mode === 'light'
          ? t('appearance.light')
          : t('appearance.dark')}
    </button>
  ));

  // The "A" glyph row. Words live in aria-label/title so the size
  // names stay translated without spending the row's width on them.
  const textSizeButtons = TEXT_SIZES.map((size) => (
    <button
      key={size}
      onClick={() => {
        setTextSize(size);
        revealExample();
      }}
      aria-pressed={textSize === size}
      aria-label={t(TEXT_SIZE_LABEL[size])}
      title={t(TEXT_SIZE_LABEL[size])}
      className={`${embedded ? 'flex-1 lg:flex-none lg:w-9' : 'flex-auto'} inline-flex items-center justify-center py-1.5 rounded transition ${TEXT_SIZE_GLYPH[size]} ${
        textSize === size ? SEG_ACTIVE : SEG_IDLE
      }`}
    >
      A
    </button>
  ));

  // Words, not glyphs: unlike the "A" preview above, a width has nothing
  // it can show at button size, so the option carries its own name.
  const contentWidthButtons = CONTENT_WIDTHS.map((w) => (
    <button
      key={w}
      onClick={() => setContentWidth(w)}
      aria-pressed={contentWidth === w}
      className={`${embedded ? 'flex-1 lg:flex-none lg:px-3' : 'flex-auto'} inline-flex items-center justify-center py-1.5 rounded text-xs transition ${
        contentWidth === w ? SEG_ACTIVE : SEG_IDLE
      }`}
    >
      {t(CONTENT_WIDTH_LABEL[w])}
    </button>
  ));

  // The level itself, because a percentage IS the label a browser already
  // taught everybody, and a translated word per number would say less.
  // Formatted per locale, so the sign lands where that language puts it.
  //
  // One fixed width for all of them, like the "A" row below, rather than
  // padding to content: this is the widest control on the tab, and at the
  // pane's own width a content-width row came out one pixel over the room
  // beside its label and dropped to a line of its own, which is the drift
  // the row layout above exists to prevent.
  const appZoomButtons = APP_ZOOM_LEVELS.map((level) => (
    <button
      key={level}
      onClick={() => setAppZoom(level)}
      aria-pressed={appZoom === level}
      className={`${embedded ? 'flex-1 lg:flex-none lg:w-12' : 'flex-auto'} inline-flex items-center justify-center py-1.5 rounded text-xs transition ${
        appZoom === level ? SEG_ACTIVE : SEG_IDLE
      }`}
    >
      {level.toLocaleString(intlLocale(), { style: 'percent' })}
    </button>
  ));

  // Two words rather than a preview glyph, for the content-width reason: a
  // gap has nothing it can show at button size. The example block under the
  // row is where the difference is actually visible.
  const lineSpacingButtons = LINE_SPACINGS.map((sp) => (
    <button
      key={sp}
      onClick={() => {
        onLineSpacingChange(sp);
        revealExample();
      }}
      aria-pressed={lineSpacing === sp}
      className={`${embedded ? 'flex-1 lg:flex-none lg:px-3' : 'flex-auto'} inline-flex items-center justify-center py-1.5 rounded text-xs transition ${
        lineSpacing === sp ? SEG_ACTIVE : SEG_IDLE
      }`}
    >
      {t(LINE_SPACING_LABEL[sp])}
    </button>
  ));

  const noteColorButtons = NOTE_COLOR_CHOICES.map((c) => (
    <button
      key={c}
      onClick={() => {
        onNoteColorsChange(c);
        if (embedded) setNoteExampleOpen(true);
      }}
      aria-pressed={noteColors === c}
      className={`${embedded ? 'flex-1 lg:flex-none lg:px-3' : 'flex-auto'} inline-flex items-center justify-center py-1.5 rounded text-xs transition ${
        noteColors === c ? SEG_ACTIVE : SEG_IDLE
      }`}
    >
      {t(NOTE_COLOR_LABEL[c])}
    </button>
  ));

  // ---- Embedded: compact setting rows ------------------------------------
  // One row per setting: from lg up, label + helper on the left and the
  // control right-aligned; below lg every row stacks instead. Row labels
  // replace section eyebrows here; the footer popover below keeps its own
  // stacked layout because w-80 has no room for a label column.
  // Spec: ops/docs/archive/ui-patterns.md section 36 (compact setting rows)
  if (embedded) {
    // Below lg (where the shell is the push stack) every row stacks: label
    // and helper, then the control full-width beneath. Above lg it is one
    // line with the control right-aligned. Stacking ALL of them rather than
    // letting each row wrap when it happens to run out of room is the point:
    // which rows wrapped used to change with the pane width (three of six at
    // 400px, five of six at 341px), so the list read as arbitrary.
    const rowLayout =
      'flex flex-col gap-2 lg:flex-row lg:flex-wrap lg:items-center lg:justify-between lg:gap-x-5 lg:gap-y-2';
    const row = `${rowLayout} py-3`;
    const track = SETTINGS_TRACK;
    // A helper that only EXPLAINS its control (what Auto does, what the two
    // editor modes mean) is desktop-only: the options largely carry it, and
    // at the push-stack width these were what pushed the pane into a scroll.
    // A helper that states a FACT you cannot see from the control (text size
    // and website icons are device-local, icons pass through our proxy)
    // stays at every width - mobile is where those matter most.
    const helpExplain = `${SETTINGS_HELP} mt-0.5 hidden lg:block`;
    // Offered start views, and the one chosen. A view switched off in the
    // table below is not offered, and a stored choice that points at one
    // reads back as All, so the two settings cannot contradict each other.
    const startRows = startViewRows(tShell, hiddenViews);
    const startRow = startRows.find((r) => r.key === resolveStartView(startView, hiddenViews));
    const themeRows = (
      <>
        {/* Mode - Auto / Light / Dark. Auto follows the OS and re-resolves
            live when it flips (see watchSystemTheme in theme.ts), and it
            switches between the two slots below. */}
        <div data-setting="appearance.mode" className={row}>
          <div className="min-w-0">
            <RowTitle icon={CircleHalf}>{t('appearance.modeTitle')}</RowTitle>
            <p className={helpExplain}>{t('appearance.modeDesc')}</p>
            {themeMode === 'auto' && theme !== getSystemTheme() && (
              <p className={`${SETTINGS_HELP} mt-1 text-accent-strong`}>
                {theme === 'dark' ? t('appearance.peekDark') : t('appearance.peekLight')}
              </p>
            )}
          </div>
          <div className={track}>{modeButtons}</div>
        </div>

        {/* App size - the whole window, which is what the Editor pane's text
            size deliberately is not. Desktop only: a browser already has
            this on the same keys, and the mobile webviews have no equivalent,
            so the row is absent rather than present and dead.
            Spec: ops/docs/design-decisions.md (app zoom) */}
        {appZoomSupported() && (
          <div data-setting="appearance.appZoom" className={row}>
            <div className="min-w-0">
              <RowTitle icon={MagnifyingGlassPlus}>{t('appearance.appZoomTitle')}</RowTitle>
              <p className={`${SETTINGS_HELP} mt-0.5`}>{t('appearance.appZoomDesc')}</p>
            </div>
            <div className={track}>{appZoomButtons}</div>
          </div>
        )}

        {/* The pair: one palette per mode, both always shown, so a choice for
            the other mode is made without switching to it. */}
        <div data-setting="appearance.theme" className="py-3 space-y-4">
          {/* The heading carries make and paste: above both sections, because a
              theme made or pasted here can land in either mode. */}
          <div data-setting="appearance.customThemes">
            <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
              <RowTitle icon={Palette}>{t('appearance.tabThemes')}</RowTitle>
              {onOpenThemeBuilder && (
                <div className="flex flex-wrap items-center gap-2 text-[13px]">
                  <button
                    type="button"
                    onClick={() => onOpenThemeBuilder({})}
                    className="inline-flex items-center gap-1.5 rounded-md border border-divider px-3 py-1.5 font-medium text-pn-soft hover:text-pn hover:border-pn-muted transition"
                  >
                    <Plus size={14} aria-hidden="true" /> {t('appearance.custom.newTheme')}
                    {!isPro && <IconUpgrade size={12} />}
                  </button>
                  <button
                    type="button"
                    onClick={() => setPasteOpen((open) => !open)}
                    aria-expanded={pasteOpen}
                    className={`inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 font-medium transition ${
                      pasteOpen ? 'border-accent text-pn' : 'border-divider text-pn-soft hover:text-pn hover:border-pn-muted'
                    }`}
                  >
                    <ClipboardText size={14} aria-hidden="true" /> {t('appearance.custom.pasteCode')}
                    {!isPro && <IconUpgrade size={12} />}
                  </button>
                </div>
              )}
            </div>
            {onOpenThemeBuilder && (
              <>
                {copiedName && (
                  <p className={`${SETTINGS_HELP} mt-2`} role="status">
                    {t('appearance.custom.copied', { name: copiedName })}
                  </p>
                )}
                {pasteOpen && (
                  <Suspense fallback={null}>
                    <ThemePasteField ctx={galleryCtx} onClose={() => setPasteOpen(false)} />
                  </Suspense>
                )}
                <ContextMenu state={themeMenu.state} onClose={themeMenu.close} />
              </>
            )}
          </div>
          {/* Made by, as on /themes: the built-in palettes count as the team's. */}
          <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
            {/* Wraps, so a long word in any language never clips the last chip. */}
            <div role="group" aria-label={t('appearance.madeBy.label')} className={`flex-wrap max-w-full ${SETTINGS_TRACK}`}>
              {(['all', 'community', 'team', 'yours'] as const).map((m) => (
                <button
                  key={m}
                  type="button"
                  onClick={() => setMadeBy(m)}
                  aria-pressed={madeBy === m}
                  className={`inline-flex items-center justify-center px-3 py-1 rounded text-xs transition ${madeBy === m ? SEG_ACTIVE : SEG_IDLE}`}
                >
                  {t(`appearance.madeBy.${m}`)}
                </button>
              ))}
            </div>
            {/* The order toggle applies to the community themes, so it shows
                where they do; the website link sits at the end in every tab.
                The group grows to the row's end, so on a narrow pane it takes
                a line of its own: the toggle at the start, the link at the end.
                On a phone the link wraps under the toggle and stays at the
                start, like New theme and Paste theme code above it. */}
            <div className="flex max-w-full grow flex-wrap items-center gap-2">
              {(madeBy === 'all' || madeBy === 'community') && (
                <div role="group" aria-label={t('appearance.madeBy.sortLabel')} className={`flex-wrap max-w-full ${SETTINGS_TRACK}`}>
                  {(['newest', 'votes'] as const).map((s) => (
                    <button
                      key={s}
                      type="button"
                      onClick={() => setCommunitySort(s)}
                      aria-pressed={communitySort === s}
                      className={`inline-flex items-center justify-center px-3 py-1 rounded text-xs transition ${communitySort === s ? SEG_ACTIVE : SEG_IDLE}`}
                    >
                      {t(s === 'votes' ? 'appearance.madeBy.sortVotes' : 'appearance.madeBy.sortNewest')}
                    </button>
                  ))}
                </div>
              )}
              <a
                href={siteHref('/themes')}
                target="_blank"
                rel="noopener noreferrer"
                className={`sm:ms-auto ${SETTINGS_BTN.replace('py-1.5 text-sm', 'h-8 text-[13px]')}`}
              >
                {t('appearance.madeBy.more')}
                <ArrowSquareOut size={12} aria-hidden="true" />
              </a>
            </div>
          </div>
          {(['light', 'dark'] as const).map((mode) => (
            <div key={mode}>
              <RowTitle icon={mode === 'dark' ? Moon : Sun}>
                {mode === 'dark' ? t('appearance.darkThemes') : t('appearance.lightThemes')}
              </RowTitle>
              <p className={`${SETTINGS_HELP} mt-0.5 mb-2`}>
                {mode === 'dark' ? t('appearance.darkThemesDesc') : t('appearance.lightThemesDesc')}
              </p>
              <div className="pn-theme-gallery grid grid-cols-2 sm:grid-cols-4 gap-2">
                {(madeBy === 'all' || madeBy === 'team') &&
                  (mode === 'dark' ? DARK_THEMES : LIGHT_THEMES).map((ct) =>
                    themeCard(mode, ct, (mode === 'dark' ? darkTheme : lightTheme) === ct, false),
                  )}
                <Suspense fallback={null}>
                  <ExtraThemeCards mode={mode} compact={false} ctx={galleryCtx} madeBy={madeBy} sort={communitySort} />
                </Suspense>
              </div>
              {/* Shown by CSS while the grid above has no card (index.css). */}
              <p className={`pn-theme-gallery-empty ${SETTINGS_HELP} rounded-lg border border-dashed border-divider px-3 py-4 text-center`}>
                {madeBy === 'community'
                  ? t(mode === 'dark' ? 'appearance.madeBy.noDarkCommunity' : 'appearance.madeBy.noLightCommunity')
                  : t('appearance.madeBy.none')}
              </p>
            </div>
          ))}
          {/* Reference text after the galleries, so the filters lead straight
              to the themes. */}
          <div className="space-y-1.5 border-t border-divider pt-3">
            {/* What a star does, and the star a fourth one pushed out. */}
            <div>
              <p className={`${SETTINGS_HELP} flex items-center gap-1.5`}>
                <Star size={13} weight="fill" className="shrink-0 text-pro" aria-hidden="true" />
                {t('appearance.favoritesHint')}
              </p>
              {droppedFav && (
                <p className={`${SETTINGS_HELP} mt-1 flex flex-wrap items-center gap-x-2`} role="status">
                  {t('appearance.favoriteDropped', { name: droppedFav.name })}
                  <button
                    type="button"
                    onClick={() => { restoreQuickThemes(droppedFav.mode, droppedFav.before); setDroppedFav(null); }}
                    className="font-medium text-accent hover:underline"
                  >
                    {t('notes:editor.undo')}
                  </button>
                </p>
              )}
            </div>
            {/* The app ships the themes of its build; /themes gets new ones and
                the votes every day, so it is where to send people. */}
            <p className={`${SETTINGS_HELP} flex flex-wrap items-center gap-x-2 gap-y-0.5`}>
              <a
                href={siteHref('/themes')}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 font-medium text-accent hover:underline"
              >
                <Globe size={14} aria-hidden="true" />
                {t('appearance.custom.websiteTitle')}
                <ArrowSquareOut size={12} aria-hidden="true" />
              </a>
              <span>{t('appearance.custom.websiteDesc')}</span>
            </p>
          </div>
          {unlockNudge}
        </div>

        {/* Note colors - how strongly notes and sidebar rows show their
            color. Last in the pane, just above Reset to defaults; the look
            picker shows the same control. */}
        <div data-setting="appearance.tintNotes" className={row}>
          <div className="min-w-0">
            <RowTitle icon={PaintBucket}>{t('appearance.noteColorsTitle')}</RowTitle>
            <p className={`${SETTINGS_HELP} mt-0.5`}>{t('appearance.noteColorsDesc')}</p>
          </div>
          <div className={track}>{noteColorButtons}</div>
        </div>
        {/* A note in a green folder, as each option shows it: the whole row
            tinted, only its icon, or neither. */}
        <div className="pb-3">
          <button
            type="button"
            onClick={() => setNoteExampleOpen((v) => !v)}
            aria-expanded={noteExampleOpen}
            className="inline-flex items-center gap-1 text-xs text-accent"
          >
            <CaretDown size={12} className={`shrink-0 transition-transform ${noteExampleOpen ? '' : '-rotate-90'}`} aria-hidden="true" />
            {t('appearance.lineSpacingExample')}
          </button>
          {noteExampleOpen && (
            <div className="mt-2 rounded-md bg-track p-2">
              <NoteColorExample
                choice={noteColors}
                color="green"
                title={t('appearance.noteColorsExampleTitle')}
                source={
                  <>
                    <Folder size={11} weight="fill" style={{ color: 'var(--pn-label-green-ink)' }} aria-hidden="true" />
                    {t('appearance.noteColorsExampleFolder')}
                  </>
                }
              />
            </div>
          )}
        </div>
      </>
    );

    const styleRows = (
      <>
        {/* Text size and Line spacing, one group under one example. They are
            the two knobs that change how a paragraph READS, and the sample
            below shows both at once: it is set in the editor's own body size
            and reads --pn-para-gap straight off <html>, so it reflows on the
            click that sets either one and no second copy of a value exists to
            drift. They are grouped rather than merely adjacent, which is why
            no hairline runs between them.

            Text size is device-local and line spacing syncs, which is the one
            disagreement inside the group: a size is a property of the screen
            in front of you, a paragraph gap is a property of how somebody
            writes. Each helper says so in its own words.

            The example starts closed. The pane already runs a long column of
            rows, and a sample that is always open makes this group twice the
            height of anything else for a reader who never asked to see it.
            Spec: ops/docs/design-decisions.md (editor paragraph rhythm) */}
        <div>
          <div data-setting="appearance.textSize" className={row}>
            <div className="min-w-0">
              <RowTitle icon={TextT}>{t('appearance.textSizeTitle')}</RowTitle>
              <p className={`${SETTINGS_HELP} mt-0.5`}>{t('appearance.textSizeDesc')}</p>
            </div>
            <div className={track}>{textSizeButtons}</div>
          </div>
          <div data-setting="appearance.lineSpacing" className={`${row} pt-0`}>
            <div className="min-w-0">
              <RowTitle icon={TextAlignJustify}>{t('appearance.lineSpacingTitle')}</RowTitle>
              <p className={`${SETTINGS_HELP} mt-0.5`}>{t('appearance.lineSpacingDesc')}</p>
            </div>
            <div className={track}>{lineSpacingButtons}</div>
          </div>
          <div className="pb-3">
            <button
              type="button"
              onClick={() => setSpacingExampleOpen((v) => !v)}
              aria-expanded={spacingExampleOpen}
              className="inline-flex items-center gap-1 text-xs text-accent"
            >
              <CaretDown size={12} className={`shrink-0 transition-transform ${spacingExampleOpen ? '' : '-rotate-90'}`} aria-hidden="true" />
              {t('appearance.lineSpacingExample')}
            </button>
            {spacingExampleOpen && (
              <div className="mt-2 rounded-md bg-track px-3 py-2 text-[length:var(--pn-editor-body)] leading-[var(--pn-line-height)]">
                {(['lineSpacingExample1', 'lineSpacingExample2', 'lineSpacingExample3'] as const).map((key) => (
                  <p key={key} style={{ marginBlock: 'var(--pn-para-gap)' }}>{t(`appearance.${key}`)}</p>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Editor width - the cap on the note's reading column. Device-local
            for the text-size reason: a phone never reaches the cap at all.
            The editor's own toggle only shows on a pane wider than the
            default cap, so this row is the way in at every other width. */}
        <div data-setting="appearance.contentWidth" className={row}>
          <div className="min-w-0">
            <RowTitle icon={FrameCorners}>{t('appearance.contentWidthTitle')}</RowTitle>
            <p className={`${SETTINGS_HELP} mt-0.5`}>{t('appearance.contentWidthDesc')}</p>
          </div>
          <div className={track}>{contentWidthButtons}</div>
        </div>

        {/* Editor - formatted / markdown. This is the default every note
            opens in; the per-note "Show markdown" link in the editor footer
            overrides it for one note only.
            Spec: ops/specs/editor-mode-toggle.md */}
        <div data-setting="appearance.editor" className={row}>
          <div className="min-w-0">
            <RowTitle icon={PencilLine}>{t('appearance.editorTitle')}</RowTitle>
            <p className={helpExplain}>{t('appearance.editorDesc')}</p>
          </div>
          <div className={track}>
            {(['formatted', 'markdown'] as const).map((mode) => (
              <button
                key={mode}
                onClick={() => onEditorModeChange(mode)}
                aria-pressed={editorMode === mode}
                className={`${SEG_FILL} text-xs py-1.5 rounded transition ${
                  editorMode === mode ? SEG_ACTIVE : SEG_IDLE
                }`}
              >
                {mode === 'formatted' ? t('appearance.editorFormatted') : t('appearance.editorMarkdown')}
              </button>
            ))}
          </div>
        </div>


        {/* Copied text - what the plain-text part of a copy holds. Markdown
            keeps today's copy; Plain text drops the `- [ ]` and every other
            formatting character for targets that print them as they are.
            Device-local. Spec: ops/docs/archive/paste-pictures.md (section 3.6) */}
        <div data-setting="appearance.copyFormat" className={row}>
          <div className="min-w-0">
            <RowTitle icon={Copy}>{t('appearance.copyFormatTitle')}</RowTitle>
            <p className={helpExplain}>{t('appearance.copyFormatDesc')}</p>
          </div>
          <div className={track}>
            {(['markdown', 'plain'] as const).map((format) => (
              <button
                key={format}
                onClick={() => setCopyFormat(format)}
                aria-pressed={copyFormat === format}
                className={`${SEG_FILL} text-xs py-1.5 rounded transition ${
                  copyFormat === format ? SEG_ACTIVE : SEG_IDLE
                }`}
              >
                {format === 'markdown' ? t('appearance.copyFormatMarkdown') : t('appearance.copyFormatPlain')}
              </button>
            ))}
          </div>
        </div>

        {/* Pasted text - the other half of the clipboard. Plain text pastes
            from other apps as lines of text, the way Shift+paste does, for
            phones that have no such key. Device-local.
            Spec: ops/issues/0508.md (Spec) */}
        <div data-setting="appearance.pasteFormat" className={row}>
          <div className="min-w-0">
            <RowTitle icon={ClipboardText}>{t('appearance.pasteFormatTitle')}</RowTitle>
            <p className={helpExplain}>{t('appearance.pasteFormatDesc')}</p>
          </div>
          <div className={track}>
            {(['formatted', 'plain'] as const).map((format) => (
              <button
                key={format}
                onClick={() => setPasteFormat(format)}
                aria-pressed={pasteFormat === format}
                className={`${SEG_FILL} text-xs py-1.5 rounded transition ${
                  pasteFormat === format ? SEG_ACTIVE : SEG_IDLE
                }`}
              >
                {format === 'formatted' ? t('appearance.pasteFormatFormatted') : t('appearance.pasteFormatPlain')}
              </button>
            ))}
          </div>
        </div>

        {/* Invisible characters - the pilcrow, the space dots and the line
            breaks the editor can draw. This is a taste somebody sets once
            and leaves, which is what makes a settings row the right home for
            it and a permanent button over the note text the wrong one. The
            editor keeps the quick toggle beside the word count for the
            person who wants it on for one note.
            Spec: ops/docs/design-decisions.md (the editor corner holds only controls that can hide themselves) */}
        <Switch
          setting="appearance.invisibles"
          icon={<Paragraph size={14} className="text-accent" />}
          labelClassName={ROW_TITLE}
          label={t('appearance.invisiblesTitle')}
          description={t('appearance.invisiblesDesc')}
          checked={invisibles}
          onChange={setInvisibles}
          className="gap-x-5 py-3"
        />

        {/* Checkboxes - what a tick does, in a note and in the Tasks view
            alike. Both sync. */}
        <div className="pt-4">
          <SectionEyebrow icon={CheckSquare}>{t('appearance.checkboxesTitle')}</SectionEyebrow>
          <div className="divide-y divide-divider">
            <Switch
              setting="appearance.taskConfetti"
              icon={<Confetti size={14} className="text-accent" />}
              labelClassName={ROW_TITLE}
              label={t('appearance.taskConfettiTitle')}
              description={t('appearance.taskConfettiDesc')}
              checked={taskConfetti}
              onChange={onTaskConfettiChange}
              className="gap-x-5 py-3"
            />
            <Switch
              setting="appearance.sinkChecked"
              icon={<ListChecks size={14} className="text-accent" />}
              labelClassName={ROW_TITLE}
              label={t('appearance.sinkCheckedTitle')}
              description={t('appearance.sinkCheckedDesc')}
              checked={sinkCheckedTasks}
              onChange={onSinkCheckedTasksChange}
              className="gap-x-5 py-3"
            />
          </div>
        </div>

        {/* Open with PrivacyNotes - which app the OS opens a double-clicked
            file with. Desktop app only. It stores nothing, so Reset to
            defaults leaves it alone.
            Spec: ops/docs/plans/default-app-settings.md */}
        {markdownDefaultAppSupported() && (
          <div data-setting="appearance.defaultApps" className="pt-4">
            <SectionEyebrow icon={Files}>{t('appearance.defaultAppsTitle')}</SectionEyebrow>
            <DefaultAppSettingsRow kind="text" />
            <DefaultAppSettingsRow kind="markdown" />
          </div>
        )}
      </>
    );

    const generalRows = (
      <>
        {/* Start in - which view the app opens on. First on the tab because
            it answers the question a person arrives with, and because a menu
            here has the whole pane below it to open into. The menu is the one
            the phone pillar switcher uses, so a pillar added later appears in
            both without a second list.
            Spec: ops/docs/archive/start-view.md */}
        <div data-setting="appearance.startView" className={row}>
          <div className="min-w-0">
            <RowTitle icon={HouseLine}>{t('appearance.startViewTitle')}</RowTitle>
          </div>
          <button
            ref={startBtnRef}
            type="button"
            onClick={() => setStartMenuOpen((o) => !o)}
            aria-haspopup="menu"
            aria-expanded={startMenuOpen}
            aria-label={`${t('appearance.startViewTitle')}: ${startRow?.label ?? ''}`}
            className="shrink-0 self-start lg:self-auto inline-flex items-center gap-2 rounded-md bg-track px-3 py-1.5 text-sm font-medium text-pn hover:bg-pn-muted/20 transition"
          >
            {startRow && <startRow.icon size={15} className="text-accent shrink-0" aria-hidden="true" />}
            {startRow?.label}
            <CaretDown size={12} className={`text-pn-soft transition-transform ${startMenuOpen ? 'rotate-180' : ''}`} aria-hidden="true" />
          </button>
          {startMenuOpen && (
            <ViewMenu
              rows={startRows}
              current={startView}
              onPick={onStartViewChange}
              anchorRef={startBtnRef}
              onClose={() => setStartMenuOpen(false)}
              align="end"
            />
          )}
        </div>

        {/* View - list / grid / auto layout. */}
        <div data-setting="appearance.view" className={row}>
          <div className="min-w-0">
            <RowTitle icon={Layout}>{t('appearance.viewTitle')}</RowTitle>
            <p className={helpExplain}>{t('appearance.viewDesc')}</p>
          </div>
          <div className={track}>
            {(['auto', 'list', 'grid'] as const).map((mode) => (
              <button
                key={mode}
                onClick={() => onViewModeChange(mode)}
                aria-pressed={viewMode === mode}
                className={`${SEG_FILL} inline-flex items-center justify-center gap-1.5 text-xs py-1.5 rounded transition ${
                  viewMode === mode ? SEG_ACTIVE : SEG_IDLE
                }`}
              >
                {mode === 'list' ? <List size={14} /> : mode === 'grid' ? <SquaresFour size={14} /> : <Sparkle size={14} />}
                {mode === 'list' ? t('appearance.viewList') : mode === 'grid' ? t('appearance.viewGrid') : t('appearance.viewAuto', exemptOpts('settings:appearance.viewAuto'))}
              </button>
            ))}
          </div>
        </div>

        {/* Spaces - Pro. A free account sees the row switched off, and the
            switch opens the upgrade window, as every Pro row here does.
            Spec: ops/docs/plans/spaces.md */}
        {/* One element for the switch and its help chip: the list draws a
            divider between children, and the chip belongs to this row. */}
        <div>
        <Switch
          setting="appearance.spaces"
          icon={<UserSwitch size={14} className="text-accent" />}
          labelClassName={ROW_TITLE}
          label={t('appearance.spacesTitle')}
          description={<>{t('appearance.spacesDesc')}{!isPro && <> <ProMark /></>}</>}
          checked={spaces && proUnlocked(isPro)}
          onChange={(on) => {
            if (!proUnlocked(isPro)) { upgradeHandoffRef.current = true; onOpenUpgrade('spaces'); return; }
            onSpacesChange(on);
          }}
          className="gap-x-5 py-3"
        />
        {/* The row is the whole topic of its help entry, so the chip sits
            under it rather than at the top of the pane.
            Spec: ops/docs/help-center.md (section 9) */}
        <HelpChip surface="spaces" className="-mt-1 mb-2" />
        </div>

        {/* Open items in tabs - a row click opens a tab, so it changes what a
            click in a list does. Device-local, like the tabs themselves.
            Spec: ops/docs/archive/note-tabs.md */}
        {tabsFit && (
          <Switch
            setting="appearance.openInTabs"
            icon={<Tabs size={14} className="text-accent" />}
            labelClassName={ROW_TITLE}
            label={t('appearance.openInTabsTitle')}
            description={t('appearance.openInTabsDesc')}
            checked={openItemsInTabs}
            onChange={setOpenItemsInTabs}
            className="gap-x-5 py-3"
          />
        )}

        {/* Website icons - the site logo on links and vault logins. The one
            thing they cost is a request per new domain to our proxy, so the
            off switch is device-local like text size, not synced. The full
            privacy story lives in About > Trust; the row keeps the one-line
            version.
            Spec: ops/docs/design-decisions.md (Website icons toggle) */}
        <Switch
          setting="appearance.favicons"
          icon={<Globe size={14} className="text-accent" />}
          labelClassName={ROW_TITLE}
          label={t('appearance.faviconsTitle')}
          description={
            <>
              {/* The example is live: real domain, real proxy response, and the
                  icon disappears with the toggle, so the control demonstrates
                  itself rather than describing itself. Where there is no lookup
                  (the demo) it draws the globe the rows draw instead. */}
              <span className="flex flex-wrap items-center gap-x-1.5 gap-y-0.5">
                <span>{t('appearance.faviconsDesc')}</span>
                <span className="inline-flex items-center gap-1.5">
                  {t('appearance.faviconsExample')}
                  {favicons && (exampleFavicon ? (
                    <img
                      src={exampleFavicon}
                      alt=""
                      width={14}
                      height={14}
                      className="rounded-[3px]"
                      onError={(e) => { e.currentTarget.style.visibility = 'hidden'; }}
                    />
                  ) : (
                    <Globe size={14} aria-hidden="true" />
                  ))}
                  <span className="text-accent">google.com</span>
                </span>
              </span>
              {/* The proxy line describes the lookup, so it shows only where
                  there is one. */}
              {exampleFavicon && <span className="block mt-0.5">{t('appearance.faviconsProxy')}</span>}
            </>
          }
          checked={favicons}
          onChange={setFavicons}
          className="gap-x-5 py-3"
        />
      </>
    );
    const sidebarRows = (
      <>
        {/* Sidebar - two settings in one table. "In sidebar" decides which
            rows the rail draws; "In All" decides which item types the All
            list holds. They look like one setting and are not: seeing Vault
            ticked in one column and clear in the other is the whole point,
            and two stacked lists would hide it. Both are also one click away
            in the rail itself (the eye on the Content caption, the funnel in
            the All row) - the same field shown twice, exactly as the
            List/Grid choice already is.
            Spec: ops/docs/archive/sidebar-views.md */}
        <div data-setting="appearance.sidebar" className="py-3">
          {/* The heading names the two columns using the two glyphs the column
              headers carry, so the words below are already recognisable. Each
              glyph is bound to its word by a Trans tag rather than dropped in
              at a fixed offset: word order moves between languages, and the
              pair has to move with it. */}
          <p className="text-sm font-medium flex items-center gap-1.5">
            <Trans
              i18nKey="settings:appearance.sidebarTitle"
              components={{
                sb: <IconWord icon={DotsThreeOutlineVertical} />,
                all: <IconWord icon={PILLAR_GLYPHS.all} />,
              }}
            />
          </p>
          <p className={`${SETTINGS_HELP} mt-0.5`}>{t('appearance.sidebarDesc')}</p>
          <table className="mt-2.5 w-full text-sm">
            <thead>
              {/* No fixed column widths. `w-full` on the label column means
                  "absorb whatever is left", so the two option columns take
                  exactly what their own header needs in whatever language it
                  is written - de "In der Seitenleiste" is three times the
                  English, and a px number here would be right in one
                  catalogue and wrong in half the others. From lg the headers
                  stay on one line; below it they wrap, because the pane is a
                  push stack down there and three nowrap columns would run off
                  its edge. `align-bottom` keeps a wrapped header on the same
                  baseline as a single-line one. */}
              <tr className="align-bottom text-xs font-semibold text-accent">
                <th className="text-start pb-1.5 w-full" />
                {/* Both headers carry a glyph. The All column takes the All
                    pillar's own icon, the same one on its row in the rail, so
                    the picture carries the link faster than the word. The
                    sidebar column has no pillar to borrow from, so it takes
                    the three-dot stack, which reads as a list of rows. The
                    Sidebar glyph itself was tried here and dropped: at 13px
                    its panel-and-divider detail turns to mush. One
                    bare header beside one iconed header looked like a
                    mistake. Neither icon sets its own colour: the header row
                    is accent already. */}
                <th className="pb-1.5 px-2 lg:whitespace-nowrap">
                  <span className="inline-flex items-center justify-center gap-1.5">
                    <DotsThreeOutlineVertical size={13} className="shrink-0" aria-hidden="true" />
                    {t('appearance.colInSidebar')}
                  </span>
                </th>
                <th className="pb-1.5 px-2 lg:whitespace-nowrap">
                  <span className="inline-flex items-center justify-center gap-1.5">
                    <PILLAR_GLYPHS.all size={13} className="shrink-0" aria-hidden="true" />
                    {t('appearance.colInAll')}
                  </span>
                </th>
              </tr>
            </thead>
            <tbody>
              {sidebarViewRows(tShell).map((r) => {
                const inAll = allViewRows(tShell).some((a) => a.key === r.key);
                return (
                  <tr key={r.key} className="border-t border-divider">
                    <td className="py-1.5">
                      <span className="flex items-center gap-2">
                        <r.icon size={16} className="text-accent shrink-0" aria-hidden="true" />
                        {r.label}
                      </span>
                    </td>
                    <td className="text-center py-1.5">
                      <button
                        type="button"
                        role="checkbox"
                        aria-checked={!hiddenViews.includes(r.key)}
                        aria-label={`${t('appearance.colInSidebar')}: ${r.label}`}
                        onClick={() => onToggleHidden('hiddenViews', r.key)}
                        className="inline-flex items-center justify-center p-1"
                      >
                        <ViewCheckBox checked={!hiddenViews.includes(r.key)} />
                      </button>
                    </td>
                    <td className="text-center py-1.5">
                      {inAll ? (
                        <button
                          type="button"
                          role="checkbox"
                          aria-checked={isShownInAll({ hiddenInAll, archivedInAll }, r.key)}
                          aria-label={`${t('appearance.colInAll')}: ${r.label}`}
                          onClick={() => onToggleHidden('hiddenInAll', r.key)}
                          className="inline-flex items-center justify-center p-1"
                        >
                          <ViewCheckBox checked={isShownInAll({ hiddenInAll, archivedInAll }, r.key)} />
                        </button>
                      ) : (
                        <span className={SETTINGS_HELP} aria-hidden="true">-</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </>
    );

    if (pane === 'formatBar') {
      return (
        <div className="flex-1 min-h-0 overflow-y-auto text-pn">
          {formatBar && (
            <>
              <div data-setting="appearance.formatBar" className="px-6 pt-4">
                <Suspense fallback={null}>
                  <FormatBarBoard
                    {...formatBar}
                    // Under the free bar position, so the Pro mark covers
                    // only the arranging. Keyed on the plan, not on the
                    // unlock, so the demo still labels it.
                    heading={
                      // Two columns: the heading and its note, and the
                      // reset for the arrangement it heads. A free draft
                      // shows Discard at the foot instead.
                      <div className="pt-1 flex items-start justify-between gap-4">
                        <div className="min-w-0">
                          <div className={`${SETTINGS_EYEBROW} ${EYEBROW_ICON_ROW}`}>
                            <EyebrowGlyph icon={Toolbox} />
                            {t('editor:formatBar.arrangeTitle')}
                            {!isPro && <ProMark />}
                          </div>
                          {/* The Markdown view draws a fixed bar this board
                              does not arrange (GitHub #493). */}
                          <p className={`${SETTINGS_HELP} mt-1`}>{t('editor:formatBar.markdownViewNote')}</p>
                        </div>
                        {!formatBar.previewing && (
                          <ResetDefaultsButton key="formatBar" className="shrink-0" onReset={() => formatBar.onUpdate(() => null)} />
                        )}
                      </div>
                    }
                  />
                </Suspense>
              </div>
              {/* A free account's draft: Discard takes the place of Reset, and
                  the upgrade door sits in the same row, so the tab does not
                  grow. At rest the row carries one quiet invitation.
                  Spec: ops/docs/archive/format-bar.md (section 5) */}
              <div className="px-6 pb-4">
                {formatBar.previewing ? (
                  <div className="pt-4 flex flex-wrap items-center gap-x-3 gap-y-2">
                    <button
                      type="button"
                      onClick={formatBar.onDiscard}
                      className="inline-flex items-center gap-1.5 rounded-md border border-divider px-3 py-1.5 text-sm font-medium text-pn-soft hover:text-pn transition"
                    >
                      <ArrowCounterClockwise size={15} aria-hidden="true" />
                      {t('editor:formatBar.discard')}
                    </button>
                    <button
                      type="button"
                      onClick={formatBar.onKeep}
                      // The upgrade window's own button colors, so the door and the
                      // window read as one action.
                      className="ms-auto inline-flex items-center gap-1.5 rounded-md bg-amber-700 hover:bg-amber-800 px-3 py-1.5 text-sm font-semibold text-white transition"
                    >
                      <IconUpgrade size={15} onFill />
                      {t('editor:formatBar.keepLayout')}
                    </button>
                  </div>
                ) : (
                  formatBar.locked && <p className="pt-3 text-xs text-pn-muted">{t('editor:formatBar.tryIt')}</p>
                )}
              </div>
            </>
          )}
        </div>
      );
    }
    const rows = pane === 'design' ? themeRows : pane === 'editor' ? styleRows : listsTab === 'sidebar' ? sidebarRows : generalRows;
    const listsTabs = [
      { id: 'general' as const, label: t('appearance.listsTabGeneral'), icon: <ListBullets aria-hidden="true" /> },
      { id: 'sidebar' as const, label: t('appearance.listsTabSidebar'), icon: <DotsThreeOutlineVertical aria-hidden="true" /> },
    ];
    return (
      <div className="flex-1 min-h-0 flex flex-col text-pn">
        {pane === 'lists' && (
          <SettingsTabStrip role="tablist" aria-label={t('notes:settings.listsLabel')} className="shrink-0 px-4 sm:px-6">
            {listsTabs.map((tb) => (
              <button key={tb.id} type="button" data-setting={`lists.${tb.id}`} role="tab" aria-selected={listsTab === tb.id}
                onClick={() => setListsTab(tb.id)} className={settingsTabClass(listsTab === tb.id)}>
                {tb.icon}
                <span>{tb.label}</span>
              </button>
            ))}
          </SettingsTabStrip>
        )}
        <div className="flex-1 min-h-0 overflow-y-auto">
          <div className="px-6 divide-y divide-divider">{rows}</div>
          <div className="px-6 pb-4">
            <ResetDefaultsButton key={pane} onReset={pane === 'design' ? resetThemes : pane === 'editor' ? resetStyle : resetLists} />
          </div>
        </div>
      </div>
    );
  }

  // ---- Popover: the footer quick menu -------------------------------------
  // The four settings reached for mid-session, one compact row each, and a
  // door to each of the three panes the rest live on. No help lines: the
  // note behind the popover shows every change as it is made.
  const quickRow = (glyph: Icon, title: string, buttons: ReactNode) => (
    <div className="px-4 py-2">
      <RowTitle icon={glyph}>{title}</RowTitle>
      <div className={`mt-1.5 ${SETTINGS_TRACK}`}>{buttons}</div>
    </div>
  );
  const painted: Theme = theme;
  const paintedChoice = painted === 'dark' ? darkTheme : lightTheme;
  // A custom theme's name is the second field of its code.
  const activeName = customIdOf(paintedChoice)
    ? (paintedSlot(painted).snapshot?.code.split(':')[1] ?? '')
    : THEME_DISPLAY_NAME[paintedChoice as ColorTheme];
  const builtins: readonly ThemeChoice[] = painted === 'dark' ? DARK_THEMES : LIGHT_THEMES;
  const quickThemes = quickThemesFor(painted, quickMarks, (c) => customIdOf(c) !== null || builtins.includes(c));
  const doors: { pane: AppearancePane; label: string; glyph: Icon }[] = [
    { pane: 'design', label: t('notes:settings.appearanceLabel'), glyph: Palette },
    { pane: 'editor', label: t('notes:settings.editorLabel'), glyph: PencilLine },
    { pane: 'lists', label: t('notes:settings.listsLabel'), glyph: ListBullets },
  ];
  return (
    <div
      ref={panelRef}
      className={`fixed z-50 w-80 max-w-[calc(100vw-1rem)] max-h-[calc(100dvh-4rem)] flex flex-col bg-surface-2 border border-divider rounded-lg shadow-xl text-pn ${!trigger ? 'bottom-12 end-4' : centred ? 'left-1/2 -translate-x-1/2' : ''}`}
      style={trigger ? { top: popPos?.top ?? 0, left: centred ? undefined : popPos?.left ?? 0, maxHeight: popPos?.maxHeight, visibility: popPos ? 'visible' : 'hidden' } : undefined}
    >
      <div className="shrink-0 flex items-center gap-2.5 px-4 pt-3 pb-1">
        <AccentBar />
        <h2 className="text-sm font-semibold">{t('notes:settings.appearanceLabel')}</h2>
        <HeadlineRule />
        <CloseButton onClick={handleClose} />
      </div>

      {/* The rows scroll between the pinned header and the pinned doors: the
          panel grows upward from the footer, so a short window would push its
          top off screen. */}
      <div className="flex-1 min-h-0 overflow-y-auto overscroll-contain pb-2">
        {quickRow(TextT, t('appearance.textSizeTitle'), textSizeButtons)}
        {quickRow(TextAlignJustify, t('appearance.lineSpacingTitle'), lineSpacingButtons)}
        {quickRow(FrameCorners, t('appearance.contentWidthTitle'), contentWidthButtons)}
        {/* The favorites of the mode on screen: up to three starred themes,
            an empty slot for each one missing, and the active theme on a row
            of its own when it is not one of them. */}
        <div className="px-4 py-2">
          <div className="flex items-center gap-2">
            <RowTitle icon={Star}>{t('appearance.favoriteThemes')}</RowTitle>
            {onOpenAll && (
              <button
                type="button"
                onClick={() => onOpenAll('design', 'appearance.theme')}
                className="ms-auto inline-flex items-center gap-0.5 text-xs font-medium text-accent hover:underline"
              >
                {t('appearance.allThemes')}
                <CaretRight size={11} className="rtl:-scale-x-100" aria-hidden="true" />
              </button>
            )}
          </div>
          <div className="pn-theme-grid mt-1.5 grid grid-cols-3 gap-1.5">
            {quickThemes.map((choice) => {
              const id = customIdOf(choice);
              return id ? (
                <Suspense key={choice} fallback={null}>
                  <ExtraThemeCards mode={painted} compact ctx={galleryCtx} only={id} />
                </Suspense>
              ) : (
                themeCard(painted, choice as ColorTheme, paintedChoice === choice, true)
              );
            })}
            {Array.from({ length: QUICK_THEMES_MAX - quickThemes.length }, (_, i) => (
              <button
                key={`empty-${i}`}
                type="button"
                onClick={() => onOpenAll?.('design', 'appearance.theme')}
                disabled={!onOpenAll}
                className="flex min-h-[3.25rem] flex-col items-center justify-center gap-0.5 rounded-lg border border-dashed border-divider text-[10px] font-medium text-pn-muted hover:border-pn-muted hover:text-pn-soft transition"
              >
                <Star size={13} aria-hidden="true" />
                {t('appearance.favoriteEmpty')}
              </button>
            ))}
          </div>
          {!quickThemes.includes(paintedChoice) && (
            <div className="mt-1.5 flex items-center gap-2 rounded-lg border border-accent px-2 py-1.5 text-[11px] font-medium">
              <span className="h-3.5 w-3.5 shrink-0 rounded" style={{ backgroundColor: 'rgb(var(--pn-accent))' }} aria-hidden="true" />
              <span className="min-w-0 flex-1 truncate" dir="auto">{activeName}</span>
              <button
                type="button"
                onClick={() => starTheme(painted, paintedChoice)}
                aria-label={t('appearance.favoriteAdd', { name: activeName })}
                className="inline-flex shrink-0 items-center gap-1 text-accent hover:underline"
              >
                <Star size={12} aria-hidden="true" />
                {t('appearance.favoriteAddShort')}
              </button>
            </div>
          )}
          {unlockNudge}
        </div>
        {/* Mode last: the popover opens upward, so the last row sits nearest
            the button, and Mode is the one reached for most. */}
        {quickRow(CircleHalf, t('appearance.modeTitle'), modeButtons)}
      </div>

      {/* Everything else lives on one of three panes since the split, so the
          popover opens each of them, not one "all settings" page. */}
      {onOpenAll && (
        <div className="shrink-0 grid grid-cols-3 gap-1 p-1.5 border-t border-divider">
          {doors.map(({ pane: target, label, glyph: Glyph }) => (
            <button
              key={target}
              type="button"
              onClick={() => onOpenAll(target)}
              className="flex flex-col items-center gap-1 rounded-md py-2 text-xs font-medium text-pn-soft hover:text-accent hover:bg-pn/5 transition"
            >
              <Glyph size={16} className="text-accent" aria-hidden="true" />
              {label}
            </button>
          ))}
        </div>
      )}
    </div>
  );

}
