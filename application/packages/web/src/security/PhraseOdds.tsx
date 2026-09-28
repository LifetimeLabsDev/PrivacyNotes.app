import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { CurrencyBtc, GlobeHemisphereWest, Hourglass, LockKey, ShieldCheck } from '../icons';
import { intlLocale } from '../languages';

// A 12-word phrase carries 128 bits of entropy (generateMnemonic(wordlist, 128)
// in packages/shared/src/crypto.ts), so this is the exact count of phrases.
const PHRASE_COUNT = 2n ** 128n;

/**
 * The answer to "can somebody guess my phrase?", shown under the phrase in
 * Settings > Security > Your Phrase. It opens with a plain "No" and every
 * claim is a comparison a reader already knows, never a large-number word.
 * The claims are the same ones the `guess-phrase` FAQ entry makes, so a
 * change to one belongs in the other.
 */
export function PhraseOdds() {
  const { t } = useTranslation('security');

  return (
    <section className="@container rounded-xl border border-accent/25 bg-accent/[0.06] p-4 space-y-3.5">
      <div className="flex items-center gap-3">
        <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-accent text-white">
          <ShieldCheck size={21} />
        </span>
        <div className="min-w-0">
          <h3 className="text-[15px] font-semibold text-pn">{t('phraseOdds.title')}</h3>
          <p className="text-[13px] text-pn-soft">
            <span className="font-semibold text-emerald-700 dark:text-emerald-400">{t('phraseOdds.answerNo')}</span>{' '}
            {t('phraseOdds.answerRest')}
          </p>
        </div>
      </div>

      <div className="rounded-lg border border-accent/20 bg-surface-2 px-4 py-3 text-center">
        <p className="text-xs text-accent mb-1.5">{t('phraseOdds.countLabel')}</p>
        <p dir="ltr" className="font-mono text-[15px] font-semibold text-accent break-all leading-relaxed"> {/* rtl-ok: a number stays LTR */}
          {PHRASE_COUNT.toLocaleString(intlLocale())}
        </p>
      </div>

      <div className="grid grid-cols-1 @xl:grid-cols-3 gap-2">
        <OddsTile
          icon={<CurrencyBtc size={17} />}
          tone="bg-orange-100 text-orange-700 dark:bg-orange-950/50 dark:text-orange-400"
          title={t('phraseOdds.bitcoinTitle')}
          body={t('phraseOdds.bitcoinBody')}
        />
        <OddsTile
          icon={<Hourglass size={17} />}
          tone="bg-violet-100 text-violet-700 dark:bg-violet-950/50 dark:text-violet-400"
          title={t('phraseOdds.universeTitle')}
          body={t('phraseOdds.universeBody')}
        />
        <OddsTile
          icon={<GlobeHemisphereWest size={17} />}
          tone="bg-emerald-100 text-emerald-700 dark:bg-emerald-950/50 dark:text-emerald-400"
          title={t('phraseOdds.twinTitle')}
          body={t('phraseOdds.twinBody')}
        />
      </div>

      <p className="flex items-start gap-2 text-[13px] text-pn-soft">
        <LockKey size={16} className="shrink-0 mt-0.5 text-accent" />
        {t('phraseOdds.keepPrivate')}
      </p>
    </section>
  );
}

function OddsTile({ icon, tone, title, body }: { icon: ReactNode; tone: string; title: string; body: string }) {
  return (
    <div className="flex items-start gap-3 @xl:flex-col @xl:gap-2.5 rounded-lg border border-accent/20 bg-surface-2 p-3">
      <span className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full ${tone}`}>
        {icon}
      </span>
      <div className="min-w-0">
        <p className="text-sm font-semibold text-pn leading-snug">{title}</p>
        <p className="mt-0.5 text-xs text-pn-soft leading-snug">{body}</p>
      </div>
    </div>
  );
}
