import type { Dispatch, SetStateAction } from 'react';
import { useTranslation } from 'react-i18next';
import { ArrowsOutSimple, ChartBar, Gear, SignOut, Sun } from '../icons';
import type { LocalNote } from '../db';
import { detectPlatform } from '../devices';
import { isDemoMode } from '../demo';
import { exemptOpts } from '../i18nExempt';
import { HoverLabel } from '../HoverLabel';
import { SyncStatus } from '../SyncStatus';
import { IconUpgrade } from '../UpgradeModal';
import { hotkeyKeys, hotkeyLabel, isMacPlatform } from '../notesViewUtils';
import { intlLocale } from '../languages';

// Desktop wrapper only (not web, not iOS/Android): the mini footer's lifted
// bottom padding exists for phone home-indicator/gesture areas, which the
// desktop webview never has - a narrow desktop window keeps the normal pad.
const IS_DESKTOP_APP = detectPlatform() === 'desktop';

type FooterStats = { notes: number; words: number; label: string };

export function FullFooter({
  zenMode,
  setZenMode,
  zenUnlocked,
  sidebarCollapsed,
  gridMode,
  selected,
  openSyncVerify,
  footerStats,
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
        {/* Settings + Sync zone - matches sidebar width */}
        {!zenMode && (
          <div className={`shrink-0 self-stretch hidden lg:flex items-center justify-between px-5 py-1 ${sidebarCollapsed ? 'w-[52px] justify-center' : `w-[var(--pn-sidebar-render)] ${gridMode && selected ? 'min-[1400px]:w-[var(--pn-sidebar-render-dock)]' : ''}`}`}>
            <button
              onClick={() => setShowSettings(true)}
              aria-label={t('footer.settings', exemptOpts('notes:footer.settings'))}
              className="inline-flex items-center gap-2 text-pn hover:text-accent transition"
            >
              <Gear size={16} className="text-accent" />
              {!sidebarCollapsed && <span className="text-[14px] font-medium">{t('footer.settings', exemptOpts('notes:footer.settings'))}</span>}
            </button>
            {!sidebarCollapsed && <SyncStatus onOpen={openSyncVerify} />}
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
                ({t(isMacPlatform ? 'footer.newNoteHintMac' : 'footer.newNoteHintOther')})
              </span>
              </button>
            </HoverLabel>
          </div>
          <HoverLabel label={t('footer.openStats')} position="above">
            <button
              onClick={() => setShowStats(true)}
              aria-label={t('footer.openStats')}
              className="hidden lg:inline-flex items-center gap-2 text-[13px] text-pn-muted hover:text-accent transition whitespace-nowrap"
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
                aria-label={zenMode ? t('zen.exitHover') : t('zen.enterAriaShortcut')}
                aria-pressed={zenMode}
                className={`rounded-md inline-flex items-center gap-1.5 px-2 py-1 font-medium transition ${
                  zenMode
                    ? 'text-accent bg-accent/10 hover:bg-accent/20'
                    : 'text-pn hover:bg-neutral-100 dark:hover:bg-neutral-900'
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
                onClick={() => setShowAppearance(true)}
                aria-label={t('footer.appearance')}
                className="rounded-md inline-flex items-center gap-1.5 px-2 py-1 font-medium text-pn hover:bg-neutral-100 dark:hover:bg-neutral-900 transition"
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

export function MiniFooter({
  zenMode,
  setZenMode,
  zenUnlocked,
  selected,
  openSyncVerify,
  footerStats,
  auth,
  setShowSettings,
  setShowStats,
  setShowAppearance,
  setShowUpgrade,
}: {
  zenMode: boolean;
  setZenMode: Dispatch<SetStateAction<boolean>>;
  zenUnlocked: boolean;
  selected: LocalNote | null;
  openSyncVerify: () => void;
  footerStats: FooterStats;
  auth: { isPro: boolean };
  setShowSettings: Dispatch<SetStateAction<boolean>>;
  setShowStats: Dispatch<SetStateAction<boolean>>;
  setShowAppearance: Dispatch<SetStateAction<boolean>>;
  setShowUpgrade: (next: { trigger: 'zen' }) => void;
}) {
  const { t } = useTranslation('notes');
  return (
      <footer className={`[@media(min-width:768px)_and_(min-height:501px)]:hidden shrink-0 flex items-center justify-between gap-3 px-4 py-1.5 ${IS_DESKTOP_APP ? 'pb-1.5' : 'pb-[max(0.375rem,env(safe-area-inset-bottom))]'} md:pb-1.5 border-t border-divider text-[13px] text-neutral-500 dark:text-neutral-500 [@media(max-height:320px)]:hidden`}>
        {/* Below md the row is exactly three items, so the flanking two get
            equal-width flex boxes and the sync status lands on the true centre
            of the bar. justify-between alone centred it only by accident - it
            sat wherever "Settings" and "Zen" happened to leave it, and the
            Android nav line right underneath made the few px of drift obvious
            (GitHub #205). The boxes carry the width, not the buttons, so no
            dead space becomes clickable. At md+ the stats readout joins the
            row and justify-between spreads all four as before. */}
        <div className="flex flex-1 md:flex-none min-w-0">
          <button
            onClick={() => setShowSettings(true)}
            aria-label={t('footer.settings', exemptOpts('notes:footer.settings'))}
            className="inline-flex items-center gap-1.5 text-[13px] text-neutral-600 dark:text-neutral-400 hover:text-accent transition shrink-0"
          >
            <Gear className="text-accent" />
            <span>{t('footer.settings', exemptOpts('notes:footer.settings'))}</span>
          </button>
        </div>
        <span className="shrink-0">
          <SyncStatus onOpen={openSyncVerify} tipPosition="above" />
        </span>
        {/* Stats readout - md+ only. Below md the phone row is too tight;
            at md-lg the same three phone controls span a tablet-width row,
            so fill the middle like the desktop footer does. */}
        <button
          onClick={() => setShowStats(true)}
          aria-label={t('footer.openStats')}
          className="hidden md:inline-flex items-center gap-2 text-[13px] text-pn-muted hover:text-accent transition whitespace-nowrap"
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
        <div className="flex flex-1 md:flex-none md:shrink-0 items-center justify-end gap-3">
          {/* One slot, two controls (GitHub #216). The mini footer has room
              for exactly one trailing button, so it shows the one that acts
              on what is currently on screen: Zen while a note is open, and
              Appearance while it isn't. Zen with no note open only arms a
              mode the next opened note will use - nothing visibly happens,
              which reads as a dead button on a phone, where this is the only
              trailing control there is. Appearance opens the sheet rather
              than flipping light/dark inline, for the same reason the
              desktop footer does: a straight flip silently cancels Auto.
              The desktop footer is unchanged and still shows both. */}
          {selected ? (
            <button
              onClick={() => {
                if (!zenUnlocked) { setShowUpgrade({ trigger: 'zen' }); return; }
                setZenMode((z) => !z);
              }}
              aria-label={zenMode ? t('zen.exitHover') : t('zen.enterHover')}
              aria-pressed={zenMode}
              className={`inline-flex items-center gap-1 text-[13px] transition shrink-0 ${
                zenMode ? 'text-accent' : 'text-neutral-600 dark:text-neutral-400 hover:text-accent'
              }`}
            >
              <ArrowsOutSimple size={13} />
              <span>{t('footer.zen')}</span>
              {!auth.isPro && (
                <span className="inline-flex items-center text-accent">
                  <IconUpgrade size={10} />
                </span>
              )}
            </button>
          ) : (
            <button
              onClick={() => setShowAppearance(true)}
              aria-label={t('footer.appearance')}
              className="inline-flex items-center gap-1 text-[13px] text-neutral-600 dark:text-neutral-400 hover:text-accent transition shrink-0"
            >
              <Sun size={13} className="text-accent" />
              <span>{t('footer.appearance')}</span>
            </button>
          )}
        </div>
      </footer>
  );
}
