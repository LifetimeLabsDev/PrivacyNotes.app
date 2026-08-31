import { useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { SUPPORTED_LOCALES } from './i18n';
import { LANGUAGE_META as META, Flag, setLanguage, sortByNative } from './languages';
import { ArrowSquareOut, Bug, Check, Translate } from './icons';
import { HelpChip } from './HelpChip';
import { useTheme } from './theme';
import { SETTINGS_EYEBROW, SETTINGS_HELP } from './settingsUI';

type Props = {
  onClose: () => void;
  /** Render inline as a settings pane (no popover chrome). */
  embedded?: boolean;
};

export function LanguageSheet({ embedded = false }: Props) {
  const { t } = useTranslation('settings');
  // The pane subtitle lives in the notes catalog because the settings shell
  // owns the category list it was written for. It is rendered here, above the
  // grid it describes, rather than in the shell header - the pane holds two
  // settings now and the header line only ever covered one of them.
  const { t: tNotes } = useTranslation('notes');
  const { spellcheck, setSpellcheck } = useTheme();
  const [lang, setLang] = useState<string>(
    () => localStorage.getItem('privacynotes.language') || 'system',
  );

  function choose(value: string) {
    setLang(value);
    setLanguage(value);
  }

  const tiles: Array<{ value: string; icon: ReactNode; title: string }> = [
    {
      value: 'system',
      icon: (
        <span className="flex items-center justify-center rounded-[3px] bg-accent/15 text-accent" style={{ width: 26, height: 19, flexShrink: 0 }}>
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

  return (
    <div className={embedded ? 'flex-1 min-h-0 overflow-y-auto px-6 pt-2 pb-3 text-pn' : 'p-4 text-pn'}>
      {/* Spell check - on / off. Lives here rather than in Appearance because
          it is a LANGUAGE setting: the app ships no dictionary, every squiggle
          comes from the engine the app runs in, and that engine picks the
          language with no way for us to override it. The only thing we can
          offer is the off switch, and the person reaching for it is someone
          whose writing language and device language disagree - which is what
          brought them to this pane. Device-local, like the app language below.
          It LEADS the pane because it is the setting nobody comes looking for:
          under the language grid it sat below the fold on every window short
          of full height, so the only people who found it were the ones who
          already knew it was there.
          Spec: ops/docs/design-decisions.md (Spell check is the engine's,
          not ours) */}
      <div>
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

      <div className="mt-4">
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
                  <span className="absolute top-1/2 -translate-y-1/2 end-2 inline-flex h-4 w-4 items-center justify-center rounded-full bg-accent/15 text-accent">
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
        className="mt-1.5 inline-flex items-center gap-2 max-w-full text-[13px] text-red-600 hover:underline dark:text-red-400"
      >
        <span className="flex h-5 shrink-0 items-center">
          <Bug size={15} weight="fill" aria-hidden="true" />
        </span>
        <span>{t('language.reportMistake')}</span>
        <ArrowSquareOut size={12} className="shrink-0 mt-1 opacity-70" aria-hidden="true" />
      </a>
    </div>
  );
}
