import { useState, type ReactNode } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import { VERSION } from './version';
import { ArrowSquareOut, Bug, ChatCircle, Code, Database, GithubLogo, Globe, Info, Keyboard, Link, MapTrifold, Printer, Scales, Sparkle, Star, Tag } from './icons';
import { bugReportUrl } from './bugReportUrl';
import { FOLLOW_LINKS, GITHUB_NEW_ISSUE } from './followLinks';
import { HelpChip } from './HelpChip';
import { LinksList } from './LinksList';
import { RateOutro, useRateLinks } from './rateLinks';
import { marketingHomeHref, siteHref } from './siteLinks';
import { DESKTOP_MORE_NOTE, HOTKEY_GROUPS, rowCaps, rowText } from './hotkeysData';
import { DESKTOP_APP, KEY_OS } from './shortcutMatch';
import { setSingleKeys, useSingleKeys } from './singleKeys';
import { Switch } from './Switch';
import { EYEBROW_ICON_ROW, EyebrowGlyph, ROW_TITLE, SETTINGS_EYEBROW, SETTINGS_HELP, SettingsTabStrip, settingsTabClass } from './settingsUI';
import { Modal } from './ui';
import { isTouchOnly } from './touchOnly';
import { Brand } from './Brand';
import { SwissFlag } from './SwissFlag';
import { formatDay } from './intlFormat';
import { LATEST_RELEASE, latestChangelogHref } from './latestRelease';
import { usePaneTab } from './settingsPaneTab';

type Tab = 'about' | 'hotkeys' | 'rating';

type Props = {
  onClose: () => void;
  initialTab?: Tab;
  /** Render inline as a settings pane (no overlay, no own header/footer/escape). */
  embedded?: boolean;
};

const ALL_TABS: { id: Tab; setting: string; labelKey: string; icon: ReactNode }[] = [
  { id: 'about', setting: 'about.about', labelKey: 'about.tabs.about', icon: <Info size={14} aria-hidden="true" /> },
  { id: 'hotkeys', setting: 'about.hotkeys', labelKey: 'about.tabs.hotkeys', icon: <Keyboard size={14} aria-hidden="true" /> },
  { id: 'rating', setting: 'about.rating', labelKey: 'about.tabs.rating', icon: <Star size={14} weight="fill" aria-hidden="true" /> },
];

/* ------------------------------------------------------------------ */
/*  Icons                                                             */
/* ------------------------------------------------------------------ */

function LinkIcon() {
  return <Link />;
}

function ExternalLinkIcon() {
  return <ArrowSquareOut size={12} />;
}

/* ------------------------------------------------------------------ */
/*  Tab content                                                       */
/* ------------------------------------------------------------------ */

function AboutTab() {
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

      {/* The newest release only. The /changelog page carries the full
          history with its screenshots, so the app links there instead of
          keeping a shorter copy of it. */}
      <a
        href={latestChangelogHref()}
        target="_blank"
        rel="noopener noreferrer"
        data-setting="about.changelog"
        className="group block rounded-lg border border-divider p-4 hover:border-accent/40 transition"
      >
        <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
          <span className={`${SETTINGS_EYEBROW} ${EYEBROW_ICON_ROW}`}><EyebrowGlyph icon={Sparkle} />{t('about.whatsNew')}</span>
          <span className="font-mono text-[11px] text-pn-muted">
            v{LATEST_RELEASE.version} - {formatDay(LATEST_RELEASE.date, 'date')}
          </span>
        </div>
        <p className="mt-2 text-sm font-medium text-pn">{LATEST_RELEASE.title}</p>
        <span className="mt-2 inline-flex items-center gap-1.5 text-xs text-accent group-hover:underline">
          {t('about.seeWhatsNew')}
          <ExternalLinkIcon />
        </span>
      </a>

      <section className="grid grid-cols-2 gap-6">
        <div>
          <h3 data-setting="about.version" className={`${SETTINGS_EYEBROW} ${EYEBROW_ICON_ROW} mb-2`}>
            <EyebrowGlyph icon={Tag} />
            {t('about.versionHeading')}
          </h3>
          <p className="font-mono text-pn-soft">v{VERSION}</p>
        </div>
        <div>
          {/* Reuses the retired tab's label rather than carrying a second key
              for the same word, exactly as the desktop About window does.
              /roadmap is an English-only page, so the href takes no slug. */}
          <h3 data-setting="about.roadmap" className={`${SETTINGS_EYEBROW} ${EYEBROW_ICON_ROW} mb-2`}>
            <EyebrowGlyph icon={MapTrifold} />
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
        <h3 data-setting="about.openSource" className={`${SETTINGS_EYEBROW} ${EYEBROW_ICON_ROW} mb-2`}>
            <EyebrowGlyph icon={Code} />
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

      {/* Same split as the feedback window: bugs and requests go to GitHub,
          and the channels below are for following along only. */}
      <section className="border-t border-divider pt-5">
        <h3 data-setting="about.feedback" className={`${SETTINGS_EYEBROW} ${EYEBROW_ICON_ROW} mb-2`}>
            <EyebrowGlyph icon={ChatCircle} />
          {t('about.feedbackHeading')}
        </h3>
        <p className="text-xs text-pn-soft mb-3">{t('feedback.intro')}</p>
        <div className="flex flex-wrap gap-x-4 gap-y-2">
          <a href={bugReportUrl()} target="_blank" rel="noopener noreferrer"
            className="text-xs text-accent hover:underline inline-flex items-center gap-1">
            <Bug size={12} weight="fill" className="shrink-0" />
            {t('feedback.labelReportBug')}
          </a>
          <a href={GITHUB_NEW_ISSUE} target="_blank" rel="noopener noreferrer"
            className="text-xs text-accent hover:underline inline-flex items-center gap-1">
            <GithubLogo size={12} weight="fill" className="shrink-0" />
            GitHub
          </a>
        </div>
        <h4 className="mt-4 mb-2 text-xs font-medium text-pn-muted">{t('feedback.followHeading')}</h4>
        <div className="flex flex-wrap gap-x-4 gap-y-2">
          {FOLLOW_LINKS.map((l) => (
            <a key={l.href} href={l.href} target="_blank" rel={l.rel}
              className="text-xs text-accent hover:underline inline-flex items-center gap-1">
              <l.Icon size={12} weight="fill" className="shrink-0" />
              {l.label}
            </a>
          ))}
        </div>
      </section>

      <section className="border-t border-divider pt-5">
        <h3 data-setting="about.dataStorage" className={`${SETTINGS_EYEBROW} ${EYEBROW_ICON_ROW} mb-2`}>
            <EyebrowGlyph icon={Database} />
          {t('trust.dataStorageHeading')}
        </h3>
        <p className="text-xs text-pn-soft leading-relaxed">
          <Trans i18nKey="landing:trust.dataStorageBody" components={{ flag: <SwissFlag /> }} />
        </p>
        <HelpChip surface="about" className="mt-2" />
      </section>

      <section className="border-t border-divider pt-5">
        <h3 data-setting="about.favicons" className={`${SETTINGS_EYEBROW} ${EYEBROW_ICON_ROW} mb-2`}>
            <EyebrowGlyph icon={Globe} />
          {t('trust.faviconsHeading')}
        </h3>
        {/* One paragraph, not two: the split read as two separate claims when
            it is one story - where the icons come from, and what that costs. */}
        <p className="text-[11px] text-pn-soft leading-relaxed">
          {t('trust.faviconsBody1')} {t('trust.faviconsBody2')}
        </p>
      </section>

      <section className="border-t border-divider pt-5">
        <h3 data-setting="about.legal" className={`${SETTINGS_EYEBROW} ${EYEBROW_ICON_ROW} mb-3`}>
            <EyebrowGlyph icon={Scales} />
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

/** The review platforms, sharing one list with the Rate modal. */
function RatingTab() {
  const { t } = useTranslation('landing');
  const links = useRateLinks();
  return (
    <div>
      <p className={`${SETTINGS_HELP} mb-3`}>{t('rate.intro')}</p>
      <LinksList links={links} grid />
      <p className="mt-3 pt-3 border-t border-divider text-xs leading-relaxed text-pn-muted">
        <RateOutro />
      </p>
    </div>
  );
}

/** "Printable cheat sheet" chip: the static A4 sheet, rendered from the
 *  same hotkeysData.ts this tab reads, so the two can never drift. Shown
 *  above and below the list. The sheet
 *  is English-only by design, so the link carries no locale. */
function CheatSheetLink({ align = 'right' }: { align?: 'left' | 'right' }) {
  const { t } = useTranslation('landing');
  return (
    <div className={align === 'left' ? 'flex justify-start' : 'flex justify-end'}>
      <a
        href={siteHref(`/help/keyboard-shortcuts/cheat-sheet${DESKTOP_APP ? '?app=desktop' : ''}`)}
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

/** The keys of this OS and this app: a browser shows no desktop-only row. */
function HotkeysTab() {
  const { t } = useTranslation('landing');
  const singleKeys = useSingleKeys();
  return (
    <div className="space-y-6">
      <CheatSheetLink />
      <Switch
        setting="about.singleKeys"
        label={t('about.singleKeysTitle')}
        icon={<Keyboard size={14} className="text-accent" />}
        labelClassName={ROW_TITLE}
        description={t('about.singleKeysDesc')}
        checked={singleKeys}
        onChange={setSingleKeys}
      />
      {HOTKEY_GROUPS.map((g) => {
        const rows = g.rows.filter((r) => rowCaps(r, KEY_OS, DESKTOP_APP).length > 0);
        if (rows.length === 0) return null;
        return (
          <section key={g.title}>
            <h3 className={`${SETTINGS_EYEBROW} ${EYEBROW_ICON_ROW} mb-2`}>
              <EyebrowGlyph icon={Keyboard} />
              {g.title}
            </h3>
            <div className="divide-y divide-divider">
              {rows.map((r, i) => (
                <div
                  key={i}
                  className="flex items-center justify-between py-1.5 gap-4"
                >
                  <span className="text-pn-soft">
                    {r.label}
                  </span>
                  <kbd className="font-mono text-xs px-2 py-1 rounded border border-divider bg-track whitespace-nowrap">
                    {rowText(r, KEY_OS, DESKTOP_APP)}
                  </kbd>
                </div>
              ))}
            </div>
          </section>
        );
      })}

      <p className="text-xs text-pn-soft">
        {t('about.hotkeysFootnote')}
      </p>

      {/* English, like the rows above (the list keeps one layout). */}
      {!DESKTOP_APP && (
        <p className="text-xs text-pn-soft">
          <a
            href={`${marketingHomeHref()}#downloads`}
            target="_blank"
            rel="noopener noreferrer"
            className="text-accent hover:underline"
          >
            {DESKTOP_MORE_NOTE}
          </a>
        </p>
      )}

      <CheatSheetLink align="left" />
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Modal shell                                                       */
/* ------------------------------------------------------------------ */

export function AboutModal({ onClose, initialTab, embedded = false }: Props) {
  const { t } = useTranslation('landing');
  const tabs = isTouchOnly() ? ALL_TABS.filter((tab) => tab.id !== 'hotkeys') : ALL_TABS;
  const safeInitial = tabs.some((tab) => tab.id === initialTab) ? initialTab! : 'about';
  const [tab, setTab] = usePaneTab<Tab>('about', safeInitial);

  return (
    <Modal
      // Same opt-out as SettingsShell (which hosts the embedded copy):
      // this screen is text people copy from. Spec: issue #208.
      data-no-app-menu
      embedded={embedded}
      embeddedClassName="flex-1 min-h-0 overflow-hidden flex flex-col text-pn"
      onClose={onClose}
      title={t('about.modalTitle')}
      header="bar"
      className="max-w-lg max-h-[90vh] overflow-hidden flex flex-col"
    >
        <SettingsTabStrip className="shrink-0 px-4 sm:px-6">
          {tabs.map((tabItem) => (
            <button
              key={tabItem.id}
              data-setting={tabItem.setting}
              onClick={() => setTab(tabItem.id)}
              aria-pressed={tab === tabItem.id}
              className={settingsTabClass(tab === tabItem.id)}
            >
              {tabItem.icon}
              <span>{t(tabItem.labelKey)}</span>
            </button>
          ))}
        </SettingsTabStrip>

        {/* Tab content */}
        <div className="flex-1 overflow-y-auto p-6 text-sm">
          {tab === 'about' && <AboutTab />}
          {tab === 'hotkeys' && <HotkeysTab />}
          {tab === 'rating' && <RatingTab />}
        </div>

    </Modal>
  );
}
