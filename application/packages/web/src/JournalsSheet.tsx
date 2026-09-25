import { useTranslation } from 'react-i18next';
import { activeLocale } from './languages';
import {
  JOURNAL_TITLE_FORMATS,
  JOURNAL_SUFFIX_MAX,
  journalTitle,
  type JournalTitleFormat,
} from './notesViewUtils';
import { SectionEyebrow, SETTINGS_HELP } from './settingsUI';

type Props = {
  /** Date shape new entries are titled with, and its setter. */
  format: JournalTitleFormat;
  onFormatChange: (format: JournalTitleFormat) => void;
  /** Optional text appended after the date, and its setter. */
  suffix: string;
  onSuffixChange: (suffix: string) => void;
};

/**
 * Journals settings pane: how new entries are titled.
 *
 * Every option renders today's date in its own shape, with the suffix
 * applied live, so the picker IS the preview and no shape needs a
 * translated label ("2026-07-29" says ISO in every language). Only new
 * entries are affected - existing titles are free text the user may
 * have edited by hand, so nothing rewrites them.
 *
 * The entry's calendar date is stored separately in
 * `trackers.journalDate`, which is what the Week in Review card matches
 * on. Nothing infers a date from the title. See notesViewUtils.ts.
 *
 * GitHub #200. Spec: ops/docs/ui-patterns.md section 36 (settings standard)
 */
export function JournalsSheet({ format, onFormatChange, suffix, onSuffixChange }: Props) {
  const { t } = useTranslation('settings');
  const locale = activeLocale();
  const today = new Date();

  return (
    <div className="flex-1 min-h-0 overflow-y-auto text-pn">
      {/* No section header on the formats: the pane's own subtitle ("How new
          entries are titled") already says it, and an eyebrow repeating it
          reads as filler. The rows speak for themselves. */}
      <div className="px-6 pt-2 pb-4">
        <div className="flex flex-col gap-1.5">
          {JOURNAL_TITLE_FORMATS.map((f) => {
            const active = format === f;
            return (
              <button
                key={f}
                onClick={() => onFormatChange(f)}
                aria-pressed={active}
                className={`rounded-lg border px-3 py-2 text-start text-sm transition ${
                  active
                    ? 'border-accent ring-1 ring-accent/30 text-pn'
                    : 'border-divider text-pn-soft hover:border-pn-muted hover:text-pn'
                }`}
              >
                {journalTitle(today, f, suffix, locale)}
              </button>
            );
          })}
        </div>
      </div>

      <div className="px-6 pb-4">
        <SectionEyebrow setting="journals.suffix" className="mb-0.5">{t('journals.suffixTitle')}</SectionEyebrow>
        <p className={`${SETTINGS_HELP} mb-2`}>{t('journals.suffixDesc')}</p>
        <input
          type="text"
          value={suffix}
          maxLength={JOURNAL_SUFFIX_MAX}
          onChange={(e) => onSuffixChange(e.target.value)}
          placeholder={t('journals.suffixPlaceholder')}
          className="w-full rounded-md bg-track border border-divider px-3 py-1.5 text-sm text-pn placeholder:text-pn-muted focus:border-accent focus:outline-none"
        />
        <p className={`${SETTINGS_HELP} mt-2`}>{t('journals.applyNote')}</p>
      </div>
    </div>
  );
}
