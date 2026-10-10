import { useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { SUPPORTED_LOCALES } from './i18n';
import { LANGUAGE_META as META, Flag, activeLocale, currentLanguageChoice, setLanguage, sortByNative } from './languages';
import { ArrowSquareOut, Bug, CalendarBlank, Check, Clock as ClockIcon, TextAUnderline, Translate } from './icons';
import { HelpChip } from './HelpChip';
import { useTheme } from './theme';
import { EYEBROW_ICON_ROW, EyebrowGlyph, RowTitle, SETTINGS_EYEBROW, SETTINGS_HELP, SETTINGS_ROW, SETTINGS_TRACK, settingsSegClass } from './settingsUI';
import { JournalTitles, type JournalTitlesProps } from './JournalsSheet';
import { journalTitle } from './notesViewUtils';
import { formatInstantWith, type Clock, type DateOrder } from './intlFormat';

type Props = {
  onClose: () => void;
  /** Render inline as a settings pane (no popover chrome). */
  embedded?: boolean;
};

type DateProps = {
  /** The synced date settings and their setters. */
  dateOrder: DateOrder;
  onDateOrderChange: (order: DateOrder) => void;
  clock: Clock;
  onClockChange: (clock: Clock) => void;
};

/**
 * The "Language" pane: spell check and the app language, both device-local.
 * The date settings have their own pane, `DateSheet` below.
 * Spec: ops/docs/ui-patterns.md section 36 (settings standard)
 */
export function LanguageSheet({ embedded = false }: Props) {
  const { t } = useTranslation('settings');
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
        <p className={`${SETTINGS_EYEBROW} ${EYEBROW_ICON_ROW} mb-0.5`}>
          <EyebrowGlyph icon={TextAUnderline} />
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
        <p className={`${SETTINGS_EYEBROW} ${EYEBROW_ICON_ROW} mb-0.5`}>
          <EyebrowGlyph icon={Translate} />
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

  return (
    <div className={embedded ? 'flex-1 min-h-0 flex flex-col text-pn' : 'text-pn'}>
      <div className={embedded ? 'flex-1 min-h-0 overflow-y-auto p-6' : 'p-4'}>{languageTab}</div>
    </div>
  );
}

/** The "Date" pane: one preview line, then the synced date format and clock,
 *  then the titles new journal entries get, which are written in that format.
 *  The preview is the only place a choice shows its result, so no option
 *  needs an example of its own. Spec: ops/docs/plans/dates.md (section 3.3) */
export function DateSheet({ journal, ...props }: DateProps & { journal: JournalTitlesProps }) {
  const { t } = useTranslation('settings');
  const now = new Date();
  const prefs = { order: props.dateOrder, clock: props.clock };
  const today = `${formatInstantWith(prefs, now, 'date')} \u00b7 ${formatInstantWith(prefs, now, 'time')}`;
  return (
    <div className="flex-1 min-h-0 overflow-y-auto text-pn">
      <div className="px-6 pt-4">
        <div className="rounded-md bg-accent/10 px-3 py-2 text-sm text-accent-strong">
          <p>{t('language.previewToday', { date: today })}</p>
          <p>{t('language.previewJournal', { title: journalTitle(now, journal.format, journal.suffix, activeLocale(), journal.pattern) })}</p>
        </div>
      </div>
      <div className="px-6 pb-4 divide-y divide-divider">
        <DateTimeSection {...props} />
        <JournalTitles {...journal} />
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
function DateTimeSection({ dateOrder, onDateOrderChange, clock, onClockChange }: DateProps) {
  const { t } = useTranslation('settings');
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
  return (
    <>
      <div data-setting="language.dateFormat" className={SETTINGS_ROW}>
        <div className="min-w-0">
          <RowTitle icon={CalendarBlank}>{t('language.dateFormat')}</RowTitle>
          <p className={`${SETTINGS_HELP} mt-0.5`}>{t('language.dateTimeHelp')}</p>
        </div>
        <div className={SETTINGS_TRACK}>
          {orders.map(({ value, label }) => (
            <button key={value} type="button" onClick={() => onDateOrderChange(value)} aria-pressed={dateOrder === value} className={settingsSegClass(dateOrder === value)}>
              {label}
            </button>
          ))}
        </div>
      </div>
      <div data-setting="language.clock" className={SETTINGS_ROW}>
        <RowTitle icon={ClockIcon}>{t('language.clock')}</RowTitle>
        <div className={SETTINGS_TRACK}>
          {clocks.map(({ value, label }) => (
            <button key={value} type="button" onClick={() => onClockChange(value)} aria-pressed={clock === value} className={settingsSegClass(clock === value)}>
              {label}
            </button>
          ))}
        </div>
      </div>
    </>
  );
}
