import { useState, type ReactNode } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import { VERSION } from './version';
import { useEscapeToClose } from './useEscapeToClose';
import { ArrowSquareOut, CaretRight, ClockCounterClockwise, GithubLogo, Info, Keyboard, Link, MastodonLogo, Printer, RedditLogo, Star, X, XLogo } from './icons';
import { HelpChip } from './HelpChip';
import { LinksList } from './LinksList';
import { RateOutro, useRateLinks } from './rateLinks';
import { siteHref } from './siteLinks';
import { PUBLIC_CHANGELOG, IN_APP_CHANGELOG_LIMIT, type ChangelogItemType } from './publicChangelog';
import { HOTKEY_GROUPS, renderKey } from './HotkeysModal';
import { SETTINGS_EYEBROW, SETTINGS_HELP } from './settingsUI';
import { isTouchOnly } from './touchOnly';
import { Brand } from './Brand';

type Tab = 'about' | 'changelog' | 'hotkeys' | 'rating';

type Props = {
  onClose: () => void;
  initialTab?: Tab;
  /** Render inline as a settings pane (no overlay, no own header/footer/escape). */
  embedded?: boolean;
};

const ALL_TABS: { id: Tab; setting: string; labelKey: string; icon: ReactNode }[] = [
  { id: 'about', setting: 'about.about', labelKey: 'about.tabs.about', icon: <Info size={14} aria-hidden="true" /> },
  { id: 'changelog', setting: 'about.changelog', labelKey: 'about.tabs.changelog', icon: <ClockCounterClockwise size={14} aria-hidden="true" /> },
  { id: 'hotkeys', setting: 'about.hotkeys', labelKey: 'about.tabs.hotkeys', icon: <Keyboard size={14} aria-hidden="true" /> },
  // The one tab that asks for something instead of explaining something, so
  // it sits last and carries a filled amber star rather than an outline mark.
  { id: 'rating', setting: 'about.rating', labelKey: 'about.tabs.rating', icon: <Star size={14} weight="fill" className="text-amber-400" aria-hidden="true" /> },
];

/* ------------------------------------------------------------------ */
/*  Icons                                                             */
/* ------------------------------------------------------------------ */

function LinkIcon() {
  return <Link />;
}

function ChevronRightIcon() {
  return <CaretRight size={12} />;
}

function ExternalLinkIcon() {
  return <ArrowSquareOut size={12} />;
}

/** "View this on the public site" link, shown atop (and below) web-backed tabs.
 *  Defaults to the shared "View on privacynotes.app" label, right-aligned. */
function OpenOnWebLink({ path, label, align = 'right' }: { path: string; label?: string; align?: 'left' | 'right' }) {
  const { t } = useTranslation('landing');
  return (
    <div className={align === 'left' ? 'flex justify-start' : 'flex justify-end'}>
      <a
        href={siteHref(path)}
        target="_blank"
        rel="noopener noreferrer"
        className="inline-flex items-center gap-1.5 text-xs text-accent border border-accent/30 rounded-md px-2.5 py-1 hover:bg-accent/10 transition"
      >
        {label ?? t('about.openOnWeb')}
        <ExternalLinkIcon />
      </a>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Tab content                                                       */
/* ------------------------------------------------------------------ */

function AboutTab({ onNavigateToChangelog }: { onNavigateToChangelog: () => void }) {
  const { t } = useTranslation('landing');
  return (
    <div className="space-y-6">
      <section>
        <p className="text-pn-soft leading-relaxed">
          <Trans
            i18nKey="landing:about.intro"
            components={{
              brand: <Brand />,
              nowrap: <span className="whitespace-nowrap" />,
            }}
          />
        </p>
      </section>

      <section className="grid grid-cols-2 gap-6">
        <div>
          <h3 data-setting="about.version" className={`${SETTINGS_EYEBROW} mb-2`}>
            {t('about.versionHeading')}
          </h3>
          <button
            onClick={onNavigateToChangelog}
            className="font-mono text-pn-soft hover:text-accent dark:hover:text-accent transition inline-flex items-center gap-1.5"
          >
            v{VERSION}
            <ChevronRightIcon />
          </button>
        </div>
        <div>
          {/* Reuses the retired tab's label rather than carrying a second key
              for the same word, exactly as the desktop About window does.
              /roadmap is an English-only page, so the href takes no slug. */}
          <h3 data-setting="about.roadmap" className={`${SETTINGS_EYEBROW} mb-2`}>
            {t('about.tabs.roadmap')}
          </h3>
          <a
            href={siteHref('/roadmap')}
            target="_blank"
            rel="noopener noreferrer"
            className="text-accent hover:underline transition inline-flex items-center gap-1.5"
          >
            privacynotes.app
            <ExternalLinkIcon />
          </a>
        </div>
      </section>

      <section className="border-t border-divider pt-5">
        <h3 data-setting="about.openSource" className={`${SETTINGS_EYEBROW} mb-2`}>
          {t('trust.openSourceHeading')}
        </h3>
        <a
          href="https://github.com/LifetimeLabsDev/PrivacyNotes.app"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-2 text-xs text-accent hover:underline"
        >
          <LinkIcon />
          {t('trust.openSourceLink')}
        </a>
        <p className="text-[11px] text-pn-soft mt-1 leading-relaxed">
          {t('trust.openSourceBody')}
        </p>
      </section>

      <section className="border-t border-divider pt-5">
        <h3 data-setting="about.feedback" className={`${SETTINGS_EYEBROW} mb-3`}>
          {t('about.feedbackHeading')}
        </h3>
        <p className="text-xs text-pn-soft mb-3">
          {t('about.feedbackPrompt')}
        </p>
        <div className="flex flex-wrap gap-3">
          <a
            href="https://x.com/PrivacyNotesApp"
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-accent hover:underline inline-flex items-center gap-1"
          >
            <XLogo size={12} weight="fill" className="shrink-0" />
            X.com
          </a>
          <a
            href="https://github.com/LifetimeLabsDev/PrivacyNotes.app/issues"
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-accent hover:underline inline-flex items-center gap-1"
          >
            <GithubLogo size={12} weight="fill" className="shrink-0" />
            GitHub
          </a>
          <a
            href="https://www.reddit.com/r/PrivacyNotes/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-accent hover:underline inline-flex items-center gap-1"
          >
            <RedditLogo size={12} weight="fill" className="shrink-0" />
            Reddit
          </a>
          <a
            href="https://mastodon.social/@privacynotes"
            target="_blank"
            rel="noopener noreferrer me"
            className="text-xs text-accent hover:underline inline-flex items-center gap-1"
          >
            <MastodonLogo size={12} weight="fill" className="shrink-0" />
            Mastodon
          </a>
        </div>
      </section>

      <section className="border-t border-divider pt-5">
        <h3 data-setting="about.dataStorage" className={`${SETTINGS_EYEBROW} mb-2`}>
          {t('trust.dataStorageHeading')}
        </h3>
        <p className="text-xs text-pn-soft leading-relaxed">
          {t('trust.dataStorageBody')}
        </p>
        <HelpChip surface="about" className="mt-2" />
      </section>

      <section className="border-t border-divider pt-5">
        <h3 data-setting="about.favicons" className={`${SETTINGS_EYEBROW} mb-2`}>
          {t('trust.faviconsHeading')}
        </h3>
        {/* One paragraph, not two: the split read as two separate claims when
            it is one story - where the icons come from, and what that costs. */}
        <p className="text-[11px] text-pn-soft leading-relaxed">
          {t('trust.faviconsBody1')} {t('trust.faviconsBody2')}
        </p>
      </section>

      <section className="border-t border-divider pt-5">
        <h3 data-setting="about.legal" className={`${SETTINGS_EYEBROW} mb-3`}>
          {t('about.legalHeading')}
        </h3>
        <div className="flex gap-3">
          <a
            href="https://lifetimelabs.dev/privacy/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-accent hover:underline"
          >
            {t('about.privacyPolicy')}
          </a>
          <a
            href="https://lifetimelabs.dev/terms/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-accent hover:underline"
          >
            {t('about.termsOfService')}
          </a>
          <a
            href="https://lifetimelabs.dev/terms/#refunds"
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-accent hover:underline"
          >
            {t('about.refundPolicy')}
          </a>
        </div>
        <p className={`${SETTINGS_HELP} mt-3 leading-relaxed`}>
          <a href="https://lifetimelabs.dev" target="_blank" rel="noopener noreferrer" className="text-accent hover:underline">Lifetime Labs LLC</a>
          {' - '}
          <span className="italic">{t('about.tagline')}</span>
        </p>
      </section>
    </div>
  );
}

const TYPE_LABEL_KEY: Record<ChangelogItemType, string> = {
  new: 'about.changelogType.new',
  improved: 'about.changelogType.improved',
  fixed: 'about.changelogType.fixed',
};

const TYPE_COLOR: Record<ChangelogItemType, string> = {
  new: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-400',
  improved: 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-400',
  fixed: 'bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-400',
};

function ChangelogTab() {
  const { t } = useTranslation('landing');
  const releases = PUBLIC_CHANGELOG.slice(0, IN_APP_CHANGELOG_LIMIT);

  if (releases.length === 0) {
    return (
      <div className="space-y-4">
        <p className="text-xs text-pn-muted/75 italic">
          {t('about.changelogComingSoon')}
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <OpenOnWebLink path="/changelog" label={t('about.viewFullChangelog')} />
      {releases.map((release) => (
        <section key={release.version}>
          <div className="flex items-baseline gap-2 mb-2">
            <span className="font-mono text-xs font-medium text-pn-soft">
              v{release.version}
            </span>
            <span className="text-[11px] text-pn-muted/75">
              {release.date}
            </span>
          </div>
          <p className="text-xs text-pn-soft mb-3">
            {release.title}
          </p>
          <ul className="space-y-1.5">
            {release.items.map((item, i) => (
              <li key={i} className="flex items-start gap-2 text-xs">
                <span className={`inline-block shrink-0 mt-px rounded px-1.5 py-0.5 text-[10px] font-medium leading-tight ${TYPE_COLOR[item.type]}`}>
                  {t(TYPE_LABEL_KEY[item.type])}
                </span>
                <span className="text-pn-soft leading-relaxed">
                  {item.text}
                </span>
              </li>
            ))}
          </ul>
        </section>
      ))}
      <OpenOnWebLink path="/changelog" label={t('about.viewFullChangelog')} align="left" />
    </div>
  );
}

/** The review platforms, sharing one list with the Rate modal. */
function RatingTab() {
  const { t } = useTranslation('landing');
  const links = useRateLinks();
  return (
    <div>
      <p className="text-sm text-neutral-500 mb-3">{t('rate.intro')}</p>
      <LinksList links={links} />
      <p className="mt-3 pt-3 border-t border-divider text-xs leading-relaxed text-neutral-500">
        <RateOutro />
      </p>
    </div>
  );
}

/** "Printable cheat sheet" chip: the static A4 sheet, rendered from the
 *  same hotkeysData.ts this tab reads, so the two can never drift. Shown
 *  above and below the list (OpenOnWebLink's placement pattern). The sheet
 *  is English-only by design, so the link carries no locale. */
function CheatSheetLink({ align = 'right' }: { align?: 'left' | 'right' }) {
  const { t } = useTranslation('landing');
  return (
    <div className={align === 'left' ? 'flex justify-start' : 'flex justify-end'}>
      <a
        href={siteHref('/help/keyboard-shortcuts/cheat-sheet')}
        target="_blank"
        rel="noopener noreferrer"
        className="inline-flex items-center gap-1.5 text-xs text-accent border border-accent/30 rounded-md px-2.5 py-1 hover:bg-accent/10 transition"
      >
        <Printer size={12} aria-hidden="true" />
        {t('common:hotkeys.cheatSheet')}
      </a>
    </div>
  );
}

function HotkeysTab() {
  const { t } = useTranslation('landing');
  return (
    <div className="space-y-6">
      <CheatSheetLink />
      {HOTKEY_GROUPS.map((g) => (
        <section key={g.title}>
          <h3 className={`${SETTINGS_EYEBROW} mb-2`}>
            {g.title}
          </h3>
          <div className="divide-y divide-divider">
            {g.rows.map((r, i) => (
              <div
                key={i}
                className="flex items-center justify-between py-1.5 gap-4"
              >
                <span className="text-pn-soft">
                  {r.label}
                </span>
                <kbd className="font-mono text-xs px-2 py-1 rounded border border-divider bg-track whitespace-nowrap">
                  {renderKey(r.keys)}
                </kbd>
              </div>
            ))}
          </div>
        </section>
      ))}

      <p className="text-xs text-pn-soft">
        {t('about.hotkeysFootnote')}
      </p>

      <CheatSheetLink align="left" />
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Modal shell                                                       */
/* ------------------------------------------------------------------ */

export function AboutModal({ onClose, initialTab, embedded = false }: Props) {
  const { t } = useTranslation('landing');
  useEscapeToClose(onClose, !embedded);
  const tabs = isTouchOnly() ? ALL_TABS.filter((tab) => tab.id !== 'hotkeys') : ALL_TABS;
  const safeInitial = tabs.some((tab) => tab.id === initialTab) ? initialTab! : 'about';
  const [tab, setTab] = useState<Tab>(safeInitial);

  return (
    <div
      // Same opt-out as SettingsShell (which hosts the embedded copy):
      // this screen is text people copy from. Spec: issue #208.
      data-no-app-menu
      className={embedded ? 'contents' : 'fixed inset-0 bg-black/50 dark:bg-black/70 flex items-center justify-center p-4 sm:p-6 z-50'}
      onClick={embedded ? undefined : onClose}
    >
      <div
        className={
          embedded
            ? 'flex-1 min-h-0 overflow-hidden flex flex-col text-pn'
            : 'bg-surface-2 border border-divider text-pn rounded-lg max-w-lg w-full max-h-[90vh] overflow-hidden flex flex-col'
        }
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        {!embedded && (
          <div className="flex items-center justify-between px-6 py-4 border-b border-divider">
            <h2 className="text-lg font-semibold">{t('about.modalTitle')}</h2>
            <button
              onClick={onClose}
              className="text-pn-muted hover:text-pn transition p-1 -m-1"
              aria-label={t('common:actions.close')}
            >
              <X size={18} />
            </button>
          </div>
        )}

        {/* Tab strip. `shrink-0` is load-bearing: `overflow-x-auto` makes this
            a scroll container, whose automatic minimum size is 0, so the flex
            column was free to squeeze it to a sliver whenever a tall tab
            (Hotkeys, Changelog) filled the pane - the labels were cut in half
            and the tabs themselves were barely clickable. The header and the
            footer need no such guard: they are not scroll containers, so
            `min-height: auto` already floors them at their content. */}
        <div className="shrink-0 px-6 flex border-b border-divider overflow-x-auto">
          {tabs.map((tabItem) => (
            <button
              key={tabItem.id}
              data-setting={tabItem.setting}
              onClick={() => setTab(tabItem.id)}
              aria-pressed={tab === tabItem.id}
              className={`inline-flex items-center gap-1.5 px-3 py-2.5 text-xs whitespace-nowrap transition border-b-2 ${
                tab === tabItem.id
                  ? 'border-accent text-pn font-medium'
                  : 'border-transparent text-pn-soft hover:text-pn'
              }`}
            >
              <span className="text-accent">{tabItem.icon}</span>
              {t(tabItem.labelKey)}
            </button>
          ))}
        </div>

        {/* Tab content */}
        <div className="flex-1 overflow-y-auto p-6 text-sm">
          {tab === 'about' && <AboutTab onNavigateToChangelog={() => setTab('changelog')} />}
          {tab === 'changelog' && <ChangelogTab />}
          {tab === 'hotkeys' && <HotkeysTab />}
          {tab === 'rating' && <RatingTab />}
        </div>

        {/* Footer */}
        {!embedded && (
          <div className="flex justify-end px-6 py-3 border-t border-divider">
            <button
              onClick={onClose}
              className="rounded-md border border-divider px-4 py-2 text-sm transition hover:bg-surface-1"
            >
              {t('common:actions.close')}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
