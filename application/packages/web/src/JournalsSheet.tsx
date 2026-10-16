import { useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { activeLocale } from './languages';
import {
  JOURNAL_TITLE_FORMATS,
  JOURNAL_SUFFIX_MAX,
  journalTitle,
  type JournalTitleFormat,
} from './notesViewUtils';
import { formatPattern, PATTERN_TOKENS, type PatternResult } from './intlFormat';
import { RowTitle, SETTINGS_HELP, SETTINGS_ROW } from './settingsUI';
import { Notebook } from './icons';

export type JournalTitlesProps = {
  /** Date shape new entries are titled with, and its setter. */
  format: JournalTitleFormat;
  onFormatChange: (format: JournalTitleFormat) => void;
  /** Optional text appended after the date, and its setter. */
  suffix: string;
  onSuffixChange: (suffix: string) => void;
  /** A custom title pattern; a non-empty one is the active choice. */
  pattern: string;
  onPatternChange: (pattern: string) => void;
};

/**
 * The "Journal entry titles" section of Settings > Date: how new entries
 * are titled. The spelled-out shapes and the digits follow the Date format
 * above it, so the section only chooses a shape, never an order.
 *
 * Every option renders today's date in its own shape, with the suffix
 * applied live, so the picker IS the preview and no shape needs a
 * translated label ("2026-07-29" says ISO in every language). Only new
 * entries are affected - existing titles are free text the user may
 * have edited by hand, so nothing rewrites them.
 *
 * The last row is a custom pattern of Day.js tokens: a non-empty pattern is
 * the active choice and takes no suffix, so the suffix field hides while one
 * is set, and picking a preset clears it. The preset rows preview without the
 * pattern, or every row would show the custom title.
 *
 * The entry's calendar date is stored separately in
 * `trackers.journalDate`, which is what the Week in Review card matches
 * on. Nothing infers a date from the title. See notesViewUtils.ts.
 *
 * GitHub #200. Spec: ops/docs/ui-patterns.md section 36 (settings standard),
 * ops/docs/plans/dates.md (section 3.5)
 */
/** The select's value for the custom pattern, which no preset uses. */
const CUSTOM = 'custom';

export function JournalTitles({ format, onFormatChange, suffix, onSuffixChange, pattern, onPatternChange }: JournalTitlesProps) {
  const { t } = useTranslation('settings');
  const locale = activeLocale();
  const today = new Date();
  const patternActive = pattern.trim() !== '';
  const [customOpen, setCustomOpen] = useState(patternActive);
  const fieldRef = useRef<HTMLInputElement>(null);
  const result: PatternResult | null = pattern.trim() ? formatPattern(today, pattern, locale) : null;


  function pickPreset(f: JournalTitleFormat) {
    onFormatChange(f);
    if (pattern) onPatternChange('');
    setCustomOpen(false);
  }

  /** Put a token at the caret, keeping the pattern inside its cap. */
  function insertToken(token: string) {
    const field = fieldRef.current;
    const start = field?.selectionStart ?? pattern.length;
    const end = field?.selectionEnd ?? pattern.length;
    const next = pattern.slice(0, start) + token + pattern.slice(end);
    if (next.length > JOURNAL_SUFFIX_MAX) return;
    onPatternChange(next);
    requestAnimationFrame(() => {
      field?.focus();
      field?.setSelectionRange(start + token.length, start + token.length);
    });
  }

  function errorText(r: PatternResult): string {
    if ('text' in r) return '';
    if (r.error === 'letter') return t('journals.customPatternErrorLetter', { letter: r.letter });
    if (r.error === 'bracket') return t('journals.customPatternErrorBracket');
    return t('journals.customPatternErrorEmpty');
  }

  return (
    <>
      <div data-setting="journals.titles" className={SETTINGS_ROW}>
        <div className="min-w-0">
          <RowTitle icon={Notebook}>{t('journals.titlesTitle')}</RowTitle>
          <p className={`${SETTINGS_HELP} mt-0.5`}>{t('journals.titlesPreview', { title: journalTitle(today, format, suffix, locale, pattern) })}</p>
          <p className={SETTINGS_HELP}>{t('journals.titlesDesc')}</p>
        </div>
        {/* Each option is today's date in that shape, so the shapes need no
            names; the line under the title adds the words after it. */}
        <div className="flex flex-wrap items-center gap-2">
        <select
          value={customOpen ? CUSTOM : format}
          onChange={(e) => (e.target.value === CUSTOM ? setCustomOpen(true) : pickPreset(e.target.value as JournalTitleFormat))}
          aria-label={t('journals.titlesTitle')}
          className="rounded-md bg-track border border-divider px-2.5 py-1.5 text-sm text-pn focus:border-accent focus:outline-none"
        >
          {JOURNAL_TITLE_FORMATS.map((f) => (
            <option key={f} value={f}>{journalTitle(today, f, '', locale)}</option>
          ))}
          <option value={CUSTOM}>{t('journals.customPattern')}</option>
        </select>
        {!patternActive && (
          <input
            data-setting="journals.suffix"
            type="text"
            value={suffix}
            maxLength={JOURNAL_SUFFIX_MAX}
            onChange={(e) => onSuffixChange(e.target.value)}
            placeholder={t('journals.suffixPlaceholder')}
            aria-label={t('journals.suffixTitle')}
            className="w-44 rounded-md bg-track border border-divider px-3 py-1.5 text-sm text-pn placeholder:text-pn-muted focus:border-accent focus:outline-none"
          />
        )}
        </div>
      </div>
      {customOpen && (
          <div className="pb-3">
            <p className={`${SETTINGS_HELP} mb-2`}>{t('journals.customPatternHelp')}</p>
            <input
              ref={fieldRef}
              type="text"
              dir="ltr"
              value={pattern}
              maxLength={JOURNAL_SUFFIX_MAX}
              onChange={(e) => onPatternChange(e.target.value)}
              placeholder={t('journals.customPatternPlaceholder')}
              aria-label={t('journals.customPattern')}
              className="w-full rounded-md bg-track border border-divider px-3 py-1.5 font-mono text-sm text-pn placeholder:text-pn-muted focus:border-accent focus:outline-none"
            />
            {result &&
              ('text' in result ? (
                <p className="mt-1.5 text-[13px] text-pn-soft">{t('journals.customPatternPreview', { title: result.text })}</p>
              ) : (
                <p role="alert" className="mt-1.5 text-[13px] text-red-600 dark:text-red-400">{errorText(result)}</p>
              ))}
            <p className={`${SETTINGS_HELP} mt-3 mb-1.5`}>{t('journals.customPatternTokens')}</p>
            <div className="flex flex-wrap gap-1.5">
              {PATTERN_TOKENS.map((token) => {
                const value = formatPattern(today, token, locale);
                return (
                  <button
                    key={token}
                    type="button"
                    onClick={() => insertToken(token)}
                    className="inline-flex items-baseline gap-1.5 rounded-md border border-divider px-2 py-1 text-xs hover:border-pn-muted"
                  >
                    <code dir="ltr" className="font-mono text-pn">{token}</code>
                    <span className="text-pn-muted">{'text' in value ? value.text : ''}</span>
                  </button>
                );
              })}
            </div>
          </div>
        )}

    </>
  );
}
