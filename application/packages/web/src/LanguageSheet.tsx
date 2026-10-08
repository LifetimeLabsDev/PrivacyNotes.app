import { useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { SUPPORTED_LOCALES } from './i18n';
import { LANGUAGE_META as META, Flag, currentLanguageChoice, setLanguage, sortByNative } from './languages';
import { ArrowSquareOut, Bug, Calendar, Check, Translate } from './icons';
import { HelpChip } from './HelpChip';
import { useTheme } from './theme';
import { SETTINGS_EYEBROW, SETTINGS_HELP, SettingsTabStrip, settingsTabClass } from './settingsUI';
import { formatInstantWith, type Clock, type DateOrder } from './intlFormat';

type Tab = 'dateTime' | 'language';

type Props = {
  onClose: () => void;
  /** Render inline as a settings pane (no popover chrome). */
  embedded?: boolean;
  /** The tab a search result opens on; the date settings come first. */
  initialTab?: Tab;
  /** The synced date settings and their setters. */
  dateOrder: DateOrder;
  onDateOrderChange: (order: DateOrder) => void;
  clock: Clock;
  onClockChange: (clock: Clock) => void;
};

/**
 * The "Date & Language" pane, in two tabs: "Date & time" (the synced date
 * format and clock) and "Language" (spell check and the app language, both
 * device-local). Spec: ops/docs/ui-patterns.md section 36 (settings standard)
 */
export function LanguageSheet({ embedded = false, initialTab = 'dateTime', dateOrder, onDateOrderChange, clock, onClockChange }: Props) {
  const { t } = useTranslation('settings');
  const [tab, setTab] = useState<Tab>(initialTab);
  // The pane subtitle lives in the notes catalog because the settings shell
  // owns the category list it was written for. It is rendered here, above the
  // grid it describes, rather than in the shell header - the pane holds two
  // settings now and the header line only ever covered one of them.
  const { t: tNotes } = useTranslation('notes');
  const { spellcheck, setSpellcheck } = useTheme();
  const [lang, setLang] = useState<string>(currentLanguageChoice);

  function choose(value: string) {
    setLang(value);
    setLanguage(value);
  }

  const tiles: Array<{ value: string; icon: ReactNode; title: string }> = [
    {
      value: 'system',
      icon: (
        <span className="flex items-center justify-center rounded-[3px] bg-accent/15 text-accent-strong" style={{ width: 26, height: 19, flexShrink: 0 }}>
          <Translate size={14} />
        </span>
      ),
      title: t('appearance.languageSystem'),
    },
    ...sortByNative(SUPPORTED_LOCALES).map((code) => ({
      value: code,
      icon: <Flag code={code} />,
      title: META[code]?.native ?? code,
    })),
  ];

  const languageTab = (
    <>
      {/* Spell check - on / off. Lives here rather than in Appearance because
          it is a LANGUAGE setting: the app ships no dictionary, every squiggle
          comes from the engine the app runs in, and that engine picks the
          language with no way for us to override it. The only thing we can
          offer is the off switch, and the person reaching for it is someone
          whose writing language and device language disagree - which is what
          brought them to this pane. Device-local, like the app language below.
          It LEADS the tab because it is the setting nobody comes looking for:
          under the language grid it sat below the fold on every window short
          of full height, so the only people who found it were the ones who
          already knew it was there.
          Spec: ops/docs/design-decisions.md (Spell check is the engine's,
          not ours) */}
      <div data-setting="language.spellCheck">
        <p className={`${SETTINGS_EYEBROW} mb-0.5`}>
          {t('appearance.spellCheckTitle')}
        </p>
        <p className={`${SETTINGS_HELP} mb-2`}>
          {t('appearance.spellCheckDesc')}
        </p>
        <div className="flex gap-1 rounded-md p-1 bg-track">
          {([true, false] as const).map((on) => (
            <button
              key={String(on)}
              onClick={() => setSpellcheck(on)}
              aria-pressed={spellcheck === on}
              className={`flex-1 text-xs font-medium py-1.5 rounded transition ${
                spellcheck === on
                  ? 'bg-surface-2 shadow-sm text-pn'
                  : 'text-pn-soft hover:text-pn'
              }`}
            >
              {on ? t('appearance.spellCheckOn') : t('appearance.spellCheckOff')}
            </button>
          ))}
        </div>
      </div>

      <div data-setting="language.language" className="mt-4">
        <p className={`${SETTINGS_EYEBROW} mb-0.5`}>
          {t('appearance.language')}
        </p>
        <p className={`${SETTINGS_HELP} mb-2`}>
          {tNotes('settings.languageDesc')}
        </p>
        {/* One line per tile, 8px of vertical padding. 18 tiles is a tall grid:
            the old two-line tile (endonym over its English name, p-3) ran 62px
            a row and pushed the last row - and the spell-check control under it
            - off a 640px settings modal. At 38px the whole pane fits. Keep any
            new row this flat, and see languageData.tsx before reviving the
            English gloss. */}
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5">
          {tiles.map((tile) => {
            const active = lang === tile.value;
            return (
              <button
                key={tile.value}
                type="button"
                onClick={() => choose(tile.value)}
                className={`relative flex items-center gap-2.5 rounded-lg border px-2.5 py-2 text-start transition ${
                  active
                    ? 'border-accent ring-1 ring-accent/30'
                    : 'border-divider hover:border-pn-muted'
                }`}
              >
                {tile.icon}
                <span className="min-w-0 pe-4 text-sm font-medium text-pn truncate">{tile.title}</span>
                {active && (
                  <span className="absolute top-1/2 -translate-y-1/2 end-2 inline-flex h-4 w-4 items-center justify-center rounded-full bg-accent/15 text-accent-strong">
                    <Check size={11} />
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* The pane's two outbound links: why a translation may read oddly, and
          where to say so. The report link is red and carries the same Bug mark
          as /changelog's own report link, so the two read as one action. */}
      <HelpChip surface="language" className="pt-4" />
      <a
        href="https://github.com/LifetimeLabsDev/PrivacyNotes.app/issues/new?template=translation.yml"
        target="_blank"
        rel="noopener noreferrer"
        data-setting="language.reportMistake"
        className="mt-1.5 inline-flex items-center gap-2 max-w-full text-[13px] text-red-600 hover:underline dark:text-red-400"
      >
        <span className="flex h-5 shrink-0 items-center">
          <Bug size={15} weight="fill" aria-hidden="true" />
        </span>
        <span>{t('language.reportMistake')}</span>
        <ArrowSquareOut size={12} className="shrink-0 mt-1 opacity-70" aria-hidden="true" />
      </a>
    </>
  );

  const tabs: Array<{ id: Tab; label: string; icon: ReactNode }> = [
    { id: 'dateTime', label: t('language.tabDateTime'), icon: <Calendar aria-hidden="true" /> },
    { id: 'language', label: t('language.tabLanguage'), icon: <Translate aria-hidden="true" /> },
  ];

  return (
    <div className={embedded ? 'flex-1 min-h-0 flex flex-col text-pn' : 'text-pn'}>
      <SettingsTabStrip role="tablist" aria-label={t('language.tablistLabel')} className="shrink-0 px-4 sm:px-6">
        {tabs.map((tb) => (
          <button key={tb.id} role="tab" aria-selected={tab === tb.id} onClick={() => setTab(tb.id)} className={settingsTabClass(tab === tb.id)}>
            {tb.icon}
            <span>{tb.label}</span>
          </button>
        ))}
      </SettingsTabStrip>
      <div className={embedded ? 'flex-1 min-h-0 overflow-y-auto p-6' : 'p-4'}>
        {tab === 'dateTime' ? (
          <DateTimeSection dateOrder={dateOrder} onDateOrderChange={onDateOrderChange} clock={clock} onClockChange={onClockChange} />
        ) : (
          languageTab
        )}
      </div>
    </div>
  );
}

/**
 * "Date format" and "Clock": synced, so the help line says the choice reaches
 * every device, while Automatic resolves on each one. Every row writes today
 * in its own shape, and a row that writes exactly what Automatic writes here
 * says so, which is the common case for a reader whose region already has
 * that order. Spec: ops/docs/plans/dates.md (section 3.3)
 */
function DateTimeSection({ dateOrder, onDateOrderChange, clock, onClockChange }: Omit<Props, 'onClose' | 'embedded' | 'initialTab'>) {
  const { t } = useTranslation('settings');
  const now = new Date();
  const dateExample = (order: DateOrder) => {
    const text = formatInstantWith({ order, clock }, now, 'date');
    const digits = formatInstantWith({ order, clock }, now, 'numeric');
    return text === digits ? text : `${text} · ${digits}`;
  };
  const timeExample = (c: Clock) => formatInstantWith({ order: dateOrder, clock: c }, now, 'time');
  const orders: Array<{ value: DateOrder; label: string }> = [
    { value: 'auto', label: t('language.automatic') },
    { value: 'dmy', label: t('language.dayFirst') },
    { value: 'mdy', label: t('language.monthFirst') },
    { value: 'ymd', label: t('language.yearFirst') },
  ];
  const clocks: Array<{ value: Clock; label: string }> = [
    { value: 'auto', label: t('language.automatic') },
    { value: 'h23', label: t('language.hour24') },
    { value: 'h12', label: t('language.hour12') },
  ];
  const row = (active: boolean, label: string, note: string | null, example: string, onClick: () => void, key: string) => (
    <button
      key={key}
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={`flex items-center justify-between gap-3 rounded-lg border px-3 py-2 text-start text-sm transition ${
        active ? 'border-accent ring-1 ring-accent/30 text-pn' : 'border-divider text-pn-soft hover:border-pn-muted hover:text-pn'
      }`}
    >
      <span className="min-w-0">
        <span className="block font-medium">{label}</span>
        {note && <span className="block text-xs text-pn-muted">{note}</span>}
      </span>
      <span className="shrink-0 text-end text-xs text-pn-muted tabular-nums">{example}</span>
    </button>
  );
  const noteFor = (value: string, same: boolean) =>
    value === 'auto' ? t('language.followsDevice') : same ? t('language.sameAsAutomatic') : null;

  return (
    <>
      <p className={`${SETTINGS_HELP} mb-4`}>{t('language.dateTimeHelp')}</p>
      <div data-setting="language.dateFormat">
        <p className={`${SETTINGS_EYEBROW} mb-2`}>{t('language.dateFormat')}</p>
        <div className="flex flex-col gap-1.5">
          {orders.map(({ value, label }) => {
            const example = dateExample(value);
            return row(dateOrder === value, label, noteFor(value, example === dateExample('auto')), example, () => onDateOrderChange(value), value);
          })}
        </div>
      </div>
      <div data-setting="language.clock" className="mt-4">
        <p className={`${SETTINGS_EYEBROW} mb-2`}>{t('language.clock')}</p>
        <div className="flex flex-col gap-1.5">
          {clocks.map(({ value, label }) => {
            const example = timeExample(value);
            return row(clock === value, label, noteFor(value, example === timeExample('auto')), example, () => onClockChange(value), value);
          })}
        </div>
      </div>
    </>
  );
}
