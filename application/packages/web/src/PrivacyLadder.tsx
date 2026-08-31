import { useTranslation } from 'react-i18next';
import { BookOpenText, CheckFat } from './icons';
import { activeLocale } from './languages';
import { helpPath } from './localeRoutes';
import { siteHref } from './siteLinks';

/** The three rungs, in ladder order: most convenient to most private. */
const RUNGS = ['custodial', 'self', 'phrase'] as const;

/**
 * The two surfaces this renders on carry different palettes, and both are
 * correct: the sign-in card wears the washi shell (`--wl-*`), while the
 * settings pane uses the app theme tokens. Everything else - structure,
 * strings, rung order, the help link - is shared, which is the point of
 * this file. Accent, the numeral chip and the emerald check need no entry:
 * those tokens resolve identically in both places.
 */
const TONES = {
  washi: {
    panel: 'border-[var(--wl-line)] bg-[var(--wl-card)]',
    rung: 'border-[var(--wl-line)] bg-[var(--wl-bg)]',
    body: 'text-[var(--wl-ink)]',
    muted: 'text-[var(--wl-sub)]',
  },
  app: {
    panel: 'border-divider bg-surface-1',
    rung: 'border-divider bg-surface-2',
    body: 'text-pn',
    muted: 'text-pn-muted',
  },
} as const;

/**
 * The privacy ladder: provider login with the key on our server, the same
 * login with the key on the device, and phrase-only. Expanded from
 * "Compare the options" on the sign-in card, and from the same control in
 * Settings > Security > Your Phrase so the comparison survives signup.
 *
 * ONE source of truth on purpose. The settings copy started life as a
 * second set of tiles and would have drifted from the sign-in copy the
 * first time either was edited.
 *
 * ONE help link, in the footer, and deliberately not one per rung. The
 * labels would be real FAQ questions running 78, 35 and 41 characters,
 * which puts a four-line block of blue under one card and two-line blocks
 * under the others. That link is labelled rather than carrying its
 * question, which is a deliberate exemption from the show-the-question
 * rule and the only one in the app - see ops/docs/help-center.md
 * section 9 for what it costs.
 *
 * The bullets are a shortened retelling of the `threat-model-levels` FAQ
 * entry and nothing links them: if that ladder changes, change these too.
 *
 * Spec: ops/docs/design-decisions.md (Pro mark colour is unrelated; see
 * the sign-in ladder entry), ops/docs/help-center.md (section 9)
 */
export function PrivacyLadder({
  id,
  tone = 'app',
}: {
  /** Target for the trigger's `aria-controls`. */
  id: string;
  tone?: keyof typeof TONES;
}) {
  const { t } = useTranslation('auth');
  const c = TONES[tone];
  return (
    <div id={id} className={`rounded-2xl border p-4 sm:p-5 space-y-3 ${c.panel}`}>
      <p className={`text-[13px] ${c.body}`}>{t('ladder.intro')}</p>
      <div className="grid gap-3 sm:grid-cols-3">
        {RUNGS.map((key, i) => (
          <div key={key} className={`rounded-xl border p-3 flex flex-col gap-2 ${c.rung}`}>
            <div className="flex items-start gap-2">
              {/* A numeral, not a glyph. The copy calls this a ladder, so the
                  three are ordered rather than parallel and the number says so
                  outright - where an icon would have to carry a meaning it
                  cannot (there is no readable mark for "fully anonymous").
                  Western digits in every locale, Arabic included, matching
                  intlLocale's ar-u-nu-latn rule. */}
              <span className="flex h-[19px] w-[19px] shrink-0 items-center justify-center rounded-[5px] bg-accent/10 text-[11px] font-medium text-accent">
                {i + 1}
              </span>
              <div>
                <div className="text-[13px] font-medium text-accent">
                  {t(`ladder.${key}Title`)}
                </div>
                <div className={`text-[11px] ${c.muted}`}>{t(`ladder.${key}Tag`)}</div>
              </div>
            </div>
            <ul className="space-y-1">
              {(t(`ladder.${key}Points`, { returnObjects: true }) as string[]).map((point) => (
                <li key={point} className={`flex gap-1.5 text-[12px] leading-snug ${c.body}`}>
                  <span aria-hidden="true">&bull;</span>
                  <span>{point}</span>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
      <div className="border-t border-divider pt-3 flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between sm:gap-6 [&>a:only-child]:sm:ms-auto">
        {/* The reassurance mark, in the 600/500 pair the folder glyphs use.
            Not `--wl-emerald`: its light value #065F46 is 6.81:1 on cream and
            reads as near-black rather than as green. Not emerald-500 either,
            which is the light green it looks like but measures 2.25:1 on
            cream. emerald-600 is 3.34:1 there and emerald-500 is 7.28:1 on
            the dark ground, so both ends are lighter than one fixed value
            and both clear 3:1.
            sm:shrink-0 keeps the sentence whole and lets the link wrap
            instead: German and Turkish run longer than English here. */}
        {/* Washi only, and this is not a styling split. The sentence names
            Settings as the place to change your mind, which is true on the
            sign-in card and absurd in the settings pane, where the reader is
            already looking at the control it points at. The link is right on
            both surfaces, so only the sentence is gated. */}
        {tone === 'washi' && (
          <p className={`flex items-center gap-1.5 text-[13px] font-semibold sm:shrink-0 ${c.body}`}>
            <CheckFat
              size={14}
              weight="fill"
              className="shrink-0 text-emerald-600 dark:text-emerald-500"
              aria-hidden="true"
            />
            {t('ladder.footer')}
          </p>
        )}
        <a
          href={siteHref(`${helpPath(activeLocale())}/threat-model-levels`)}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-start gap-2 text-[13px] text-accent hover:underline"
        >
          <span className="flex h-5 shrink-0 items-center">
            <BookOpenText size={15} aria-hidden="true" />
          </span>
          <span>{t('ladder.moreInfo')}</span>
        </a>
      </div>
    </div>
  );
}
