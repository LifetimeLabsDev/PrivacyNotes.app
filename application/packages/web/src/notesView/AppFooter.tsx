import type { Dispatch, ReactNode, SetStateAction } from 'react';
import { useTranslation } from 'react-i18next';
import { ArrowCircleDown, ArrowCircleUp, ArrowsOutSimple, ChartBar, Gear, SignOut, Sun } from '../icons';
import { JournalCalendarButton, type JournalCalendarHandlers } from '../JournalCalendar';
import type { LocalNote } from '../db';
import { detectPlatform } from '../devices';
import { isDemoMode } from '../demo';
import { exemptOpts } from '../i18nExempt';
import { HoverLabel } from '../HoverLabel';
import { SyncStatus } from '../SyncStatus';
import { IconUpgrade } from '../UpgradeModal';
import { hotkeyKeys, hotkeyLabel, isMacPlatform } from '../notesViewUtils';
import { DESKTOP_APP, keyText } from '../shortcutMatch';
import { intlLocale } from '../languages';

// Desktop wrapper only (not web, not iOS/Android): the mini footer's lifted
// bottom padding exists for phone home-indicator/gesture areas, which the
// desktop webview never has - a narrow desktop window keeps the normal pad.
const IS_DESKTOP_APP = detectPlatform() === 'desktop';

type FooterStats = { notes: number; words: number; label: string };

/** The one jump a long open note offers: to its end while it is read, to its
 *  top once the reader is near the end. `scrolling` and `keepShown` drive the
 *  desktop pill, which only shows while the note moves. */
export type NoteJump = {
  toTop: boolean;
  go: (where: 'top' | 'end') => void;
  scrolling: boolean;
  keepShown: (on: boolean) => void;
};

/** What the footer's journal calendar opens and creates. */
export type FooterCalendar = JournalCalendarHandlers;

export function FullFooter({
  zenMode,
  setZenMode,
  zenUnlocked,
  sidebarCollapsed,
  gridMode,
  selected,
  openSyncVerify,
  footerStats,
  calendar,
  auth,
  setShowSettings,
  setShowStats,
  setShowAbout,
  setShowAppearance,
  setShowUpgrade,
  handleSignOutClick,
}: {
  zenMode: boolean;
  setZenMode: Dispatch<SetStateAction<boolean>>;
  zenUnlocked: boolean;
  sidebarCollapsed: boolean;
  gridMode: boolean;
  selected: LocalNote | null;
  openSyncVerify: () => void;
  footerStats: FooterStats;
  calendar: FooterCalendar;
  auth: { isPro: boolean };
  setShowSettings: Dispatch<SetStateAction<boolean>>;
  setShowStats: Dispatch<SetStateAction<boolean>>;
  setShowAbout: (next: { tab: 'hotkeys' }) => void;
  setShowAppearance: Dispatch<SetStateAction<boolean>>;
  setShowUpgrade: (next: { trigger: 'zen' }) => void;
  handleSignOutClick: () => void;
}) {
  const { t } = useTranslation('notes');
  return (
      <footer className="hidden [@media(min-width:768px)_and_(min-height:501px)]:flex shrink-0 items-center border-t border-divider text-[13px] text-pn-muted">
        {/* Settings + Sync zone - matches sidebar width. It is a sidebar
            size container too (pn-sidebar in index.css), so a sidebar
            narrower than 230px drops the Settings word for a tip, the way
            the sidebar's own footer actions do, and the sync label keeps
            its room. The padding sits on the inner row: a container
            measures its content box, and padding on it would hide the
            word at 240px too. */}
        {!zenMode && (
          <div className={`pn-sidebar shrink-0 self-stretch hidden lg:flex ${sidebarCollapsed ? 'w-[52px]' : `w-[var(--pn-sidebar-render)] ${gridMode && selected ? 'min-[1400px]:w-[var(--pn-sidebar-render-dock)]' : ''}`}`}>
            <div className={`flex flex-1 min-w-0 items-center gap-2 px-5 py-1 ${sidebarCollapsed ? 'justify-center' : 'justify-between'}`}>
              <HoverLabel label={t('footer.settings', exemptOpts('notes:footer.settings'))} position="above-start" className="pn-sb-tip flex">
                <button
                  onClick={() => setShowSettings(true)}
                  aria-label={t('footer.settings', exemptOpts('notes:footer.settings'))}
                  className="inline-flex items-center gap-2 text-pn hover:text-accent transition"
                >
                  <Gear size={16} className="text-accent" />
                  {!sidebarCollapsed && <span className="pn-sb-wide text-[14px] font-medium">{t('footer.settings', exemptOpts('notes:footer.settings'))}</span>}
                </button>
              </HoverLabel>
              {!sidebarCollapsed && <SyncStatus onOpen={openSyncVerify} />}
            </div>
          </div>
        )}
        {/* Main footer content. The divider is a border-s HERE (not a
            border-e on the zone) so it occupies the same pixel column
            as the sidebar collapse-handle's border-s above it. */}
        <div className={`flex-1 self-stretch flex items-center justify-between gap-4 px-5 py-1 ${!zenMode ? 'lg:border-s border-divider' : ''}`}>
          <div className="flex items-center gap-4 min-w-0">
            {/* md band: no sidebar, so Settings + Sync live inline here.
                At lg+ the sidebar-width zone above takes over. */}
            {!zenMode && (
              <span className="flex lg:hidden items-center gap-4">
                <button
                  onClick={() => setShowSettings(true)}
                  aria-label={t('footer.settings', exemptOpts('notes:footer.settings'))}
                  className="inline-flex items-center gap-2 text-pn hover:text-accent transition"
                >
                  <Gear size={16} className="text-accent" />
                  <span className="text-[14px] font-medium">{t('footer.settings', exemptOpts('notes:footer.settings'))}</span>
                </button>
                <SyncStatus onOpen={openSyncVerify} />
              </span>
            )}
            {(zenMode || sidebarCollapsed) && (
              <span className={zenMode ? 'flex' : 'hidden lg:flex'}><SyncStatus onOpen={openSyncVerify} /></span>
            )}
            <HoverLabel label={t('footer.viewShortcuts')} position="above">
              <button
                onClick={() => setShowAbout({ tab: 'hotkeys' })}
                aria-label={t('footer.viewShortcuts')}
                className="inline-flex items-center gap-2 whitespace-nowrap text-[14px] font-medium text-pn hover:text-accent transition cursor-pointer"
              >
              <span>{t('footer.newNote')}</span>
              <span dir="ltr" className="hidden xl:inline-flex items-center gap-1"> {/* rtl-ok: modifier-key sequence never reorders */}
                {hotkeyKeys.map((k) => (
                  <kbd
                    key={k}
                    className="font-mono text-xs leading-none px-1.5 py-0.5 rounded border border-divider bg-surface-2 text-pn shadow-[0_1px_0_rgba(0,0,0,0.08)] dark:shadow-[0_1px_0_rgba(0,0,0,0.6)] min-w-[1.25rem] text-center"
                  >
                    {k}
                  </kbd>
                ))}
              </span>
              <kbd dir="ltr" className="xl:hidden font-mono text-xs leading-none px-1.5 py-0.5 rounded border border-divider bg-surface-2 text-pn shadow-[0_1px_0_rgba(0,0,0,0.08)] dark:shadow-[0_1px_0_rgba(0,0,0,0.6)] text-center"> {/* rtl-ok: modifier-key sequence never reorders */}
                {hotkeyLabel}
              </kbd>
              <span className="text-[13px] font-normal text-pn-muted hidden min-[1400px]:inline">
                ({DESKTOP_APP
                  ? t(isMacPlatform ? 'footer.newNoteHintMacDesktop' : 'footer.newNoteHintOtherDesktop')
                  : t(isMacPlatform ? 'footer.newNoteHintMac' : 'footer.newNoteHintOther')})
              </span>
              </button>
            </HoverLabel>
          </div>
          <div className="hidden lg:flex items-center gap-1.5">
          <HoverLabel label={t('footer.openStats')} position="above">
            <button
              onClick={() => setShowStats(true)}
              aria-label={t('footer.openStats')}
              className="inline-flex items-center gap-2 text-[13px] text-pn-muted hover:text-accent transition whitespace-nowrap"
            >
              <ChartBar size={13} />
              <span>
                <span className="tabular-nums font-medium">
                  {footerStats.notes.toLocaleString(intlLocale())}
                </span>
                <span className="hidden xl:inline">{' '}{footerStats.label}</span>
                {' · '}
                <span className="tabular-nums font-medium">
                  {footerStats.words.toLocaleString(intlLocale())}
                </span>
                <span className="hidden xl:inline">{' '}{t('footer.words')}</span>
              </span>
            </button>
          </HoverLabel>
          <JournalCalendarButton {...calendar} />
          </div>
          <div className="flex items-center gap-1">
            {/* Borderless text-style controls (the boxes read as a toolbar
                and fight the compact row); the rounded hover bg carries the
                affordance. Sign out keeps a destructive hover so it never
                fires by accident. Below xl the labels drop and the buttons
                are icon-only, so the HoverLabels carry the words there and
                only there - `hiddenAtXl` drops the tip at the width the
                label itself appears, where it would just repeat it. */}
            <HoverLabel hiddenAtXl label={zenMode ? t('zen.exitHover') : zenUnlocked ? t('zen.enterHover') : t('zen.proHover')} position="above-end">
              <button
                onClick={() => {
                  if (!zenUnlocked) { setShowUpgrade({ trigger: 'zen' }); return; }
                  setZenMode((z) => !z);
                }}
                aria-label={zenMode ? t('zen.exitHover') : t('zen.enterAriaShortcut', { keys: keyText('zen') })}
                aria-pressed={zenMode}
                className={`rounded-md inline-flex items-center gap-1.5 px-2 py-1 font-medium transition ${
                  zenMode
                    ? 'text-accent-strong bg-accent/10 hover:bg-accent/20'
                    : 'text-pn hover:bg-pn/5'
                }`}
              >
                <ArrowsOutSimple size={14} className={zenMode ? '' : 'text-accent'} />
                <span className="hidden xl:inline">{t('footer.zen')}</span>
                {!auth.isPro && <IconUpgrade size={10} />}
              </button>
            </HoverLabel>
            {/* Opens the Appearance sheet, nothing else. It used to flip
                light/dark on the way in, which quietly cancelled Auto for
                anyone who just wanted to look at the pane. ⌘⇧L is still
                the one-key flip. Same Sun glyph the Settings rail uses for
                this category, so the button reads as "open", not "toggle". */}
            <HoverLabel hiddenAtXl label={t('footer.appearance')} position="above-end">
              <button
                onClick={() => setShowAppearance((open) => !open)}
                data-appearance-trigger
                aria-label={t('footer.appearance')}
                className="rounded-md inline-flex items-center gap-1.5 px-2 py-1 font-medium text-pn hover:bg-pn/5 transition"
              >
                <Sun size={14} className="text-accent" />
                <span className="hidden xl:inline">{t('footer.appearance')}</span>
              </button>
            </HoverLabel>
            {!isDemoMode() && (
            <HoverLabel hiddenAtXl label={t('footer.signOut')} position="above-end">
              <button
                onClick={handleSignOutClick}
                aria-label={t('footer.signOut')}
                className="inline-flex items-center gap-1.5 rounded-md px-2 py-1 font-medium text-pn hover:text-red-600 hover:bg-red-500/10 dark:hover:text-red-400 transition"
              >
                <SignOut size={14} />
                <span className="hidden xl:inline">{t('footer.signOut')}</span>
              </button>
            </HoverLabel>
            )}
          </div>
        </div>
      </footer>
  );
}

/** One square touch target in the phone bar: 44px, the smallest either phone
 *  platform recommends, with a tip on devices that hover. */
function BarButton({
  label,
  position,
  onClick,
  pressed,
  appearanceTrigger,
  children,
}: {
  label: string;
  position: 'above' | 'above-end';
  onClick: () => void;
  pressed?: boolean;
  appearanceTrigger?: boolean;
  children: ReactNode;
}) {
  return (
    <HoverLabel label={label} position={position}>
      <button
        type="button"
        onClick={onClick}
        aria-label={label}
        aria-pressed={pressed}
        data-appearance-trigger={appearanceTrigger || undefined}
        className="relative inline-flex h-11 w-11 shrink-0 items-center justify-center rounded-lg text-accent hover:bg-pn/5 active:bg-pn/10 transition"
      >
        {children}
      </button>
    </HoverLabel>
  );
}

export function MiniFooter({
  setZenMode,
  zenUnlocked,
  selected,
  openSyncVerify,
  footerStats,
  calendar,
  auth,
  newSlotRef,
  noteJump,
  setShowSettings,
  setShowStats,
  setShowAppearance,
  setShowUpgrade,
}: {
  setZenMode: Dispatch<SetStateAction<boolean>>;
  zenUnlocked: boolean;
  selected: LocalNote | null;
  openSyncVerify: () => void;
  footerStats: FooterStats;
  calendar: FooterCalendar;
  auth: { isPro: boolean };
  /** The box a list's New button moves into on a phone (see NewButton). */
  newSlotRef: (node: HTMLDivElement | null) => void;
  /** The one jump a long open note offers: to its end while it is read, to
   *  its top once the reader is near the end. Absent for a short note. */
  noteJump?: NoteJump;
  setShowSettings: Dispatch<SetStateAction<boolean>>;
  setShowStats: Dispatch<SetStateAction<boolean>>;
  setShowAppearance: Dispatch<SetStateAction<boolean>>;
  setShowUpgrade: (next: { trigger: 'zen' }) => void;
}) {
  const { t } = useTranslation('notes');
  const settingsLabel = t('footer.settings', exemptOpts('notes:footer.settings'));
  return (
      <footer className={`[@media(min-width:768px)_and_(min-height:501px)]:hidden shrink-0 flex items-center justify-between gap-2 px-2 py-0.5 ${IS_DESKTOP_APP ? 'pb-0.5' : 'pb-[max(0.125rem,env(safe-area-inset-bottom))]'} md:pb-0.5 border-t border-divider text-[13px] text-pn-muted [@media(max-height:320px)]:hidden`}>
        {/* Settings and Design hold the start of the bar on every screen, so
            they never move under the thumb. The end holds the one action of
            the screen on show: New on a list, Zen in an open item, where New
            would act on a list nobody can see. The two end boxes are equal
            flex boxes, so the sync status sits on the true centre of the bar
            whatever they hold (GitHub #205). At md+ (a short window) the
            stats readout joins the row and justify-between spreads it. */}
        <div className="flex flex-1 md:flex-none items-center gap-1">
          <BarButton label={settingsLabel} position="above" onClick={() => setShowSettings(true)}>
            <Gear size={22} />
          </BarButton>
          {/* Opens the sheet rather than flipping light and dark: a straight
              flip silently cancels Auto. */}
          <BarButton label={t('footer.appearance')} position="above" onClick={() => setShowAppearance((open) => !open)} appearanceTrigger>
            <Sun size={22} />
          </BarButton>
        </div>
        <span className="shrink-0">
          <SyncStatus onOpen={openSyncVerify} tipPosition="above" />
        </span>
        {/* Stats readout - md+ only. Below md the phone row is too tight;
            at md-lg the same three phone controls span a tablet-width row,
            so fill the middle like the desktop footer does. */}
        <span className="hidden md:flex items-center gap-1.5">
        <button
          onClick={() => setShowStats(true)}
          aria-label={t('footer.openStats')}
          className="inline-flex items-center gap-2 text-[13px] text-pn-muted hover:text-accent transition whitespace-nowrap"
        >
          <ChartBar size={13} />
          <span>
            <span className="tabular-nums font-medium">
              {footerStats.notes.toLocaleString(intlLocale())}
            </span>{' '}
            {footerStats.label} ·{' '}
            <span className="tabular-nums font-medium">
              {footerStats.words.toLocaleString(intlLocale())}
            </span>{' '}
            {t('footer.words')}
          </span>
        </button>
        <JournalCalendarButton {...calendar} />
        </span>
        {/* No min-w-0 on either side box: when the row runs short, a box keeps
            its buttons and the sync status gives up exact centre instead of
            sliding under them. */}
        <div className="flex flex-1 md:flex-none md:shrink-0 items-center justify-end gap-1">
          {selected && noteJump && (
            noteJump.toTop ? (
              <BarButton label={t('footer.goToTop')} position="above" onClick={() => noteJump.go('top')}>
                <ArrowCircleUp size={22} />
              </BarButton>
            ) : (
              <BarButton label={t('footer.goToEnd')} position="above" onClick={() => noteJump.go('end')}>
                <ArrowCircleDown size={22} />
              </BarButton>
            )
          )}
          {selected ? (
            <BarButton
              label={t('zen.enterHover')}
              position="above-end"
              onClick={() => {
                if (!zenUnlocked) { setShowUpgrade({ trigger: 'zen' }); return; }
                setZenMode((z) => !z);
              }}
            >
              <ArrowsOutSimple size={22} />
              {/* The corner the arrow leaves empty. The glyph does not mirror,
                  so neither does the corner. */}
              {!auth.isPro && (
                <span className="absolute bottom-1.5 right-1.5 inline-flex"> {/* rtl-ok: follows the unmirrored glyph */}
                  <IconUpgrade size={10} />
                </span>
              )}
            </BarButton>
          ) : (
            <div ref={newSlotRef} className="flex md:hidden me-1" />
          )}
        </div>
      </footer>
  );
}
