import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useEscapeToClose } from './useEscapeToClose';
import {
  useTheme,
  getSystemTheme,
  type ThemeMode,
  type ColorTheme,
  type TextSize,
  type ContentWidth,
  THEME_MODES,
  LIGHT_THEMES,
  DARK_THEMES,
  THEME_DISPLAY_NAME,
  FREE_THEMES,
  TEXT_SIZES,
  CONTENT_WIDTHS,
} from './theme';
import { IconUpgrade } from './UpgradeModal';
import { proUnlocked } from './demo';
import { X, List, ListBullets, Palette, SquaresFour, Sparkle, DotsThreeOutlineVertical, PILLAR_GLYPHS } from './icons';
import { exemptOpts } from './i18nExempt';
import { AccentBar, HeadlineRule, SETTINGS_EYEBROW, SETTINGS_HELP } from './settingsUI';
import { faviconUrl } from './favicon';
import { allViewRows, sidebarViewRows, ViewCheckBox } from './SidebarOptionsPopover';
import type { View } from './views';

type Props = {
  isPro: boolean;
  onOpenUpgrade: () => void;
  onClose: () => void;
  /** Render inline as a settings pane (no popover chrome, no outside-click). */
  embedded?: boolean;
  /** Global notes layout, and its setter. */
  viewMode: 'auto' | 'list' | 'grid';
  onViewModeChange: (mode: 'auto' | 'list' | 'grid') => void;
  /** Default editor mode for note bodies, and its setter. */
  editorMode: 'formatted' | 'markdown';
  onEditorModeChange: (mode: 'formatted' | 'markdown') => void;
  /** Views switched off in the sidebar, and item types switched out of the
   *  All list. Both also live behind the rail's own two icons - this is the
   *  same field shown twice, like View. Spec: ops/docs/plans/sidebar-views.md */
  hiddenViews: View[];
  hiddenInAll: View[];
  onToggleHidden: (field: 'hiddenViews' | 'hiddenInAll', key: View) => void;
};

/** Translation key per text size. Keeps the order in TEXT_SIZES. */
const TEXT_SIZE_LABEL: Record<TextSize, string> = {
  sm: 'appearance.textSizeSmall',
  md: 'appearance.textSizeDefault',
  lg: 'appearance.textSizeLarge',
  xl: 'appearance.textSizeLargest',
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
  sm: 'text-[11px]',
  md: 'text-[13px]',
  lg: 'text-[15px]',
  xl: 'text-[17px]',
};

/** Swatch colors per theme - 3 vertical stripes: bg tone, accent, text. */
const SWATCH: Record<ColorTheme, [string, string, string]> = {
  'default': ['#F5F5F5', '#1E40AF', '#0A0A0A'],
  'warm-cream': ['#D8CDB4', '#1D4ED8', '#2D2416'],
  'slate': ['#DDE1E8', '#4338CA', '#121524'],
  'soft-dark': ['#22262E', '#4A90D9', '#CDD3DE'],
  'navy-depths': ['#0D1321', '#4B7BF5', '#D4DAE7'],
};

/** Segmented-control option states, shared by both layouts. */
const SEG_ACTIVE = 'bg-surface-2 shadow-sm text-pn font-semibold';
const SEG_IDLE = 'text-pn-soft hover:text-pn font-medium';
/**
 * Option width inside a segmented track, embedded pane only: the options
 * split the track evenly while the row is stacked (narrow), and shrink back
 * to hugging their labels once the row is one line (lg and up).
 */
const SEG_FILL = 'flex-1 px-3 lg:flex-none';

export function AppearanceSheet({ isPro, onOpenUpgrade, onClose, embedded = false, viewMode, onViewModeChange, editorMode, onEditorModeChange, hiddenViews, hiddenInAll, onToggleHidden }: Props) {
  const { t } = useTranslation('settings');
  // The table's row labels are the sidebar's own strings, so the pane and the
  // rail can never disagree in any language.
  const { t: tShell } = useTranslation('shell');
  // Which half of the embedded pane shows: Style is how the app is painted,
  // Lists is what its lists hold. The footer popover has no tab strip - it
  // renders a subset of Style only. Spec: ops/docs/ui-patterns.md section 36
  const [tab, setTab] = useState<'style' | 'lists'>('style');
  const panelRef = useRef<HTMLDivElement>(null);
  const { theme, themeMode, setThemeMode, colorTheme, setColorTheme, previewColor, textSize, setTextSize, contentWidth, setContentWidth, favicons, setFavicons } = useTheme();

  // The public demo unlocks every palette so visitors can try them for
  // real (they persist, no revert). The rocket badge on each card still
  // keys off isPro, so the themes stay labelled as Pro.
  const themesUnlocked = proUnlocked(isPro);

  // Remember the theme when the sheet opened so we can revert previews.
  const savedThemeRef = useRef<ColorTheme>(colorTheme);

  // Live colorTheme for the unmount cleanup below (avoids stale closure).
  const colorThemeRef = useRef(colorTheme);
  colorThemeRef.current = colorTheme;

  // True while handing off to the upgrade modal - the modal owns the
  // revert then (NotesView reverts on upgrade-modal close).
  const upgradeHandoffRef = useRef(false);

  // Revert un-persisted pro previews on unmount. The embedded settings
  // pane never reaches handleClose (no escape/outside-click/X), so
  // closing Settings or switching panes would otherwise leave a free
  // user on a pro theme for the rest of the session.
  useEffect(() => {
    return () => {
      if (upgradeHandoffRef.current) return;
      if (!themesUnlocked && !FREE_THEMES.has(colorThemeRef.current)) {
        setColorTheme(savedThemeRef.current);
      }
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEscapeToClose(() => handleClose(), !embedded);

  // Close on click outside
  useEffect(() => {
    if (embedded) return;
    function onClick(e: PointerEvent) {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) {
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
    if (!themesUnlocked && !FREE_THEMES.has(colorTheme)) {
      setColorTheme(savedThemeRef.current);
    }
    onClose();
  }

  // Derive mode directly from React state - no stale localStorage reads
  const isDark = theme === 'dark';
  const themeOptions = isDark ? DARK_THEMES : LIGHT_THEMES;

  // Under 'auto' the OS can flip the painted mode out from under a
  // stored palette (Cream is a light theme; the system goes dark at
  // sunset). The CSS then falls through to the default palette, so the
  // grid shows Default selected rather than nothing at all. The stored
  // choice is untouched and comes back when the OS flips again.
  const activeCard: ColorTheme = themeOptions.includes(colorTheme) ? colorTheme : 'default';

  function handleModeClick(target: ThemeMode) {
    if (target === themeMode) return;
    const nextTheme = target === 'auto' ? getSystemTheme() : target;
    setThemeMode(target);
    // Color themes belong to one mode, so reset to Default only when the
    // painted mode actually changes. Picking Auto on a light system when
    // Light was already selected must not throw away the palette.
    if (nextTheme !== theme) {
      setColorTheme('default');
      savedThemeRef.current = 'default';
    }
  }

  function handleThemeClick(t: ColorTheme) {
    if (themesUnlocked || FREE_THEMES.has(t)) {
      // Pro user or free theme: persist normally
      setColorTheme(t);
      savedThemeRef.current = t;
      return;
    }

    // Free user clicked a pro theme: preview visually (no localStorage
    // write) so the user sees it live but it won't survive a reload.
    previewColor(t);
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

  // The "A" glyph row. Words live in aria-label/title so the four size
  // names stay translated without spending the row's width on them.
  const textSizeButtons = TEXT_SIZES.map((size) => (
    <button
      key={size}
      onClick={() => setTextSize(size)}
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

  // ---- Embedded: compact setting rows ------------------------------------
  // One row per setting: from lg up, label + helper on the left and the
  // control right-aligned; below lg every row stacks instead. Row labels
  // replace section eyebrows here; the footer popover below keeps its own
  // stacked layout because w-80 has no room for a label column.
  // Spec: ops/docs/ui-patterns.md section 36 (compact setting rows)
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
    const track = 'flex gap-1 rounded-md p-1 bg-track';
    // A helper that only EXPLAINS its control (what Auto does, what the two
    // editor modes mean) is desktop-only: the options largely carry it, and
    // at the push-stack width these were what pushed the pane into a scroll.
    // A helper that states a FACT you cannot see from the control (text size
    // and website icons are device-local, icons pass through our proxy)
    // stays at every width - mobile is where those matter most.
    const helpExplain = `${SETTINGS_HELP} mt-0.5 hidden lg:block`;
    const styleRows = (
      <>
        {/* Mode - Auto / Light / Dark. Auto follows the OS and re-resolves
            live when it flips (see watchSystemTheme in theme.ts). */}
        <div className={row}>
          <div className="min-w-0">
            <p className="text-sm font-medium">{t('appearance.modeTitle')}</p>
            <p className={helpExplain}>{t('appearance.modeDesc')}</p>
          </div>
          <div className={track}>{modeButtons}</div>
        </div>

        {/* Theme - swatch chips; the upgrade nudge stays inside the row's
            divider segment so it reads as part of this setting. */}
        <div className="py-3">
          <div className={rowLayout}>
            <p className="text-sm font-medium">
              {isDark ? t('appearance.darkThemes') : t('appearance.lightThemes')}
            </p>
            <div className="flex gap-1.5">
              {themeOptions.map((ct) => {
                const active = activeCard === ct;
                // Badge only - keyed off isPro, not themesUnlocked, so the
                // demo still shows which palettes are Pro while using them.
                const locked = !isPro && !FREE_THEMES.has(ct);
                const [c1, c2, c3] = SWATCH[ct];
                return (
                  <button
                    key={ct}
                    onClick={() => handleThemeClick(ct)}
                    aria-pressed={active}
                    className={`flex flex-1 items-center justify-center gap-1.5 rounded-lg border p-1 pe-2 transition lg:flex-none ${
                      active
                        ? 'border-accent ring-1 ring-accent/30'
                        : 'border-divider hover:border-pn-muted'
                    }`}
                  >
                    {/* 3-stripe swatch - vertical: bg | accent | text */}
                    <span className="flex w-8 h-5 rounded overflow-hidden">
                      <span className="flex-1" style={{ backgroundColor: c1 }} />
                      <span className="flex-1" style={{ backgroundColor: c2 }} />
                      <span className="flex-1" style={{ backgroundColor: c3 }} />
                    </span>
                    <span className="text-[11px] font-medium text-pn-muted flex items-center gap-1">
                      {THEME_DISPLAY_NAME[ct]}
                      {locked && <IconUpgrade size={10} />}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Upgrade nudge for free users previewing a pro theme. Hidden in
              the demo: "Unlock themes" reads wrong when they already work. */}
          {!themesUnlocked && !FREE_THEMES.has(activeCard) && (
            <button
              type="button"
              onClick={() => { upgradeHandoffRef.current = true; onOpenUpgrade(); }}
              className="mt-2 w-full flex items-center justify-center gap-1 text-[11px] font-medium text-accent hover:underline transition"
            >
              <IconUpgrade size={12} /> {t('appearance.unlockThemes')}
            </button>
          )}
        </div>

        {/* Text size - the writing surface only. Device-local, never synced
            (theme.ts explains why). App chrome does not scale: most of it is
            pinned to literal pixel sizes. */}
        <div className={row}>
          <div className="min-w-0">
            <p className="text-sm font-medium">{t('appearance.textSizeTitle')}</p>
            <p className={`${SETTINGS_HELP} mt-0.5`}>{t('appearance.textSizeDesc')}</p>
          </div>
          <div className={track}>{textSizeButtons}</div>
        </div>

        {/* Editor width - the cap on the note's reading column. Device-local
            for the text-size reason: a phone never reaches the cap at all.
            The editor's own toggle only shows on a pane wider than the
            default cap, so this row is the way in at every other width. */}
        <div className={row}>
          <div className="min-w-0">
            <p className="text-sm font-medium">{t('appearance.contentWidthTitle')}</p>
            <p className={`${SETTINGS_HELP} mt-0.5`}>{t('appearance.contentWidthDesc')}</p>
          </div>
          <div className={track}>{contentWidthButtons}</div>
        </div>

        {/* Editor - formatted / markdown. This is the default every note
            opens in; the per-note "Show markdown" link in the editor footer
            overrides it for one note only.
            Spec: ops/specs/editor-mode-toggle.md */}
        <div className={row}>
          <div className="min-w-0">
            <p className="text-sm font-medium">{t('appearance.editorTitle')}</p>
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

        {/* Website icons - the site logo on links and vault logins. The one
            thing they cost is a request per new domain to our proxy, so the
            off switch is device-local like text size, not synced. The full
            privacy story lives in About > Trust; the row keeps the one-line
            version. Switch idiom: security/BiometricTab.tsx (Lock on open).
            Spec: ops/docs/design-decisions.md (Website icons toggle) */}
        <label className="flex items-center justify-between gap-x-5 py-3 cursor-pointer">
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium">{t('appearance.faviconsTitle')}</p>
            {/* The example is live: real domain, real proxy response, and the
                icon disappears with the toggle, so the control demonstrates
                itself rather than describing itself. */}
            <p className={`${SETTINGS_HELP} mt-0.5 flex flex-wrap items-center gap-x-1.5 gap-y-0.5`}>
              <span>{t('appearance.faviconsDesc')}</span>
              <span className="inline-flex items-center gap-1.5">
                {t('appearance.faviconsExample')}
                {favicons && (
                  <img
                    src={faviconUrl('google.com')}
                    alt=""
                    width={14}
                    height={14}
                    className="rounded-[3px]"
                    onError={(e) => { e.currentTarget.style.visibility = 'hidden'; }}
                  />
                )}
                <span className="text-accent">google.com</span>
              </span>
            </p>
            <p className={`${SETTINGS_HELP} mt-0.5`}>{t('appearance.faviconsProxy')}</p>
          </div>
          <div className="relative shrink-0">
            <input
              type="checkbox"
              checked={favicons}
              onChange={(e) => setFavicons(e.target.checked)}
              className="sr-only peer"
            />
            <div className="w-9 h-5 bg-pn-muted/35 peer-checked:bg-accent rounded-full transition-colors" />
            <div className="absolute start-0.5 top-0.5 w-4 h-4 bg-white rounded-full shadow-sm transition-transform peer-checked:translate-x-4 peer-checked:rtl:-translate-x-4" />
          </div>
        </label>
      </>
    );

    const listRows = (
      <>
        {/* View - list / grid / auto layout. */}
        <div className={row}>
          <div className="min-w-0">
            <p className="text-sm font-medium">{t('appearance.viewTitle')}</p>
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

        {/* Sidebar - two settings in one table. "In sidebar" decides which
            rows the rail draws; "In All" decides which item types the All
            list holds. They look like one setting and are not: seeing Vault
            ticked in one column and clear in the other is the whole point,
            and two stacked lists would hide it. Both are also one click away
            in the rail itself (the eye on the Content caption, the funnel in
            the All row) - the same field shown twice, exactly as the
            List/Grid choice already is.
            Spec: ops/docs/plans/sidebar-views.md */}
        <div className="py-3">
          <p className="text-sm font-medium">{t('appearance.sidebarTitle')}</p>
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
                          aria-checked={!hiddenInAll.includes(r.key)}
                          aria-label={`${t('appearance.colInAll')}: ${r.label}`}
                          onClick={() => onToggleHidden('hiddenInAll', r.key)}
                          className="inline-flex items-center justify-center p-1"
                        >
                          <ViewCheckBox checked={!hiddenInAll.includes(r.key)} />
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

    return (
      <div className="flex-1 min-h-0 flex flex-col text-pn">
        {/* Tab strip - the pane holds two subjects, so it splits rather than
            scrolls: how the app is painted, and what its lists show. It copies
            import/ImportModal's strip (the underline sits on the border, the
            options carry an icon), not StatsModal's, which is the older
            rounded-top pair. Spec: ops/docs/ui-patterns.md section 36 */}
        <div
          role="tablist"
          aria-label={t('appearance.tablistLabel')}
          className="shrink-0 flex items-stretch border-b border-divider px-6"
        >
          {([
            { id: 'style' as const, label: t('appearance.tabStyle'), icon: <Palette aria-hidden="true" /> },
            { id: 'lists' as const, label: t('appearance.tabLists'), icon: <ListBullets aria-hidden="true" /> },
          ]).map((tb) => (
            <button
              key={tb.id}
              role="tab"
              aria-selected={tab === tb.id}
              onClick={() => setTab(tb.id)}
              className={`inline-flex items-center gap-1.5 px-3 py-2.5 text-sm font-medium border-b-2 -mb-px transition ${
                tab === tb.id
                  ? 'border-accent text-accent'
                  : 'border-transparent text-pn-soft hover:text-pn'
              }`}
            >
              {tb.icon}
              {tb.label}
            </button>
          ))}
        </div>

        <div className="flex-1 min-h-0 overflow-y-auto">
          <div className="px-6 pb-4 divide-y divide-divider">
            {tab === 'style' ? styleRows : listRows}
          </div>
        </div>
      </div>
    );
  }

  // ---- Popover: the footer quick pass ------------------------------------
  // Mode, theme and text size only. View, Editor and Website icons are
  // set-once-and-forget writing defaults, not things anyone reaches for
  // mid-session, so they render only in the embedded settings pane above
  // (View already has a one-click List/Grid toggle in the sidebar).
  return (
    <div
      ref={panelRef}
      className="fixed bottom-12 end-4 z-50 w-80 bg-surface-2 border border-divider rounded-lg shadow-xl text-pn"
    >
      {/* Header */}
      <div className="flex items-center gap-2.5 px-4 py-3">
        <AccentBar />
        <h2 className="text-sm font-semibold">{t('appearance.title')}</h2>
        <HeadlineRule />
        <button
          onClick={handleClose}
          className="text-pn-muted hover:text-pn transition p-1 -m-1"
          aria-label={t('common:actions.close')}
        >
          <X />
        </button>
      </div>

      {/* Mode - Auto / Light / Dark. Auto follows the OS and re-resolves
          live when it flips (see watchSystemTheme in theme.ts). */}
      <div className="px-6 pb-4">
        <p className={`${SETTINGS_EYEBROW} mb-0.5`}>
          {t('appearance.modeTitle')}
        </p>
        <p className={`${SETTINGS_HELP} mb-2`}>
          {t('appearance.modeDesc')}
        </p>
        <div className="flex gap-1 rounded-md p-1 bg-track">{modeButtons}</div>
      </div>

      {/* Theme cards */}
      <div className="px-6 pb-4">
        <p className={`${SETTINGS_EYEBROW} mb-2`}>
          {isDark ? t('appearance.darkThemes') : t('appearance.lightThemes')}
        </p>
        <div className="grid grid-cols-3 gap-2">
          {themeOptions.map((ct) => {
            const active = activeCard === ct;
            // Badge only - keyed off isPro, not themesUnlocked, so the
            // demo still shows which palettes are Pro while using them.
            const locked = !isPro && !FREE_THEMES.has(ct);
            const [c1, c2, c3] = SWATCH[ct];
            return (
              <button
                key={ct}
                onClick={() => handleThemeClick(ct)}
                className={`rounded-lg border p-2 transition flex flex-col items-center gap-1.5 ${
                  active
                    ? 'border-accent ring-1 ring-accent/30'
                    : 'border-divider hover:border-pn-muted'
                }`}
              >
                {/* 3-stripe swatch - vertical: bg | accent | text */}
                <div className="w-full h-8 rounded overflow-hidden flex">
                  <div className="flex-1" style={{ backgroundColor: c1 }} />
                  <div className="flex-1" style={{ backgroundColor: c2 }} />
                  <div className="flex-1" style={{ backgroundColor: c3 }} />
                </div>
                <span className="text-[10px] font-medium text-pn-muted flex items-center gap-1">
                  {THEME_DISPLAY_NAME[ct]}
                  {locked && <IconUpgrade size={10} />}
                </span>
              </button>
            );
          })}
        </div>

        {/* Upgrade nudge for free users previewing a pro theme. Hidden in
            the demo: "Unlock themes" reads wrong when they already work. */}
        {!themesUnlocked && !FREE_THEMES.has(activeCard) && (
          <button
            type="button"
            onClick={() => { upgradeHandoffRef.current = true; onOpenUpgrade(); }}
            className="mt-3 w-full flex items-center justify-center gap-1 text-[11px] font-medium text-accent hover:underline transition"
          >
            <IconUpgrade size={12} /> {t('appearance.unlockThemes')}
          </button>
        )}
      </div>

      {/* Text size - the writing surface only. Device-local, never synced
          (theme.ts explains why). App chrome does not scale: most of it is
          pinned to literal pixel sizes. */}
      <div className="px-6 pb-4">
        <p className={`${SETTINGS_EYEBROW} mb-0.5`}>
          {t('appearance.textSizeTitle')}
        </p>
        <p className={`${SETTINGS_HELP} mb-2`}>
          {t('appearance.textSizeDesc')}
        </p>
        <div className="flex gap-1 rounded-md p-1 bg-track">{textSizeButtons}</div>
      </div>

      {/* Editor width - see the embedded row above for the reasoning. */}
      <div className="px-6 pb-4">
        <p className={`${SETTINGS_EYEBROW} mb-0.5`}>
          {t('appearance.contentWidthTitle')}
        </p>
        <p className={`${SETTINGS_HELP} mb-2`}>
          {t('appearance.contentWidthDesc')}
        </p>
        <div className="flex gap-1 rounded-md p-1 bg-track">{contentWidthButtons}</div>
      </div>

      {/* Spell check moved to LanguageSheet in v0.300.0 - it is a language
          setting, not a look-and-feel one, and it sat here only because it
          shares the device-local storage pattern with Text size. */}
    </div>
  );
}
