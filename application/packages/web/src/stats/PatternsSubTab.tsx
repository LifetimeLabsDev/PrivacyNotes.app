import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { PatternInsight, TrackerStats } from '../trackerStats';
import { insightText } from '../trackerStats';
import { SectionEyebrow, SETTINGS_EYEBROW } from '../settingsUI';
import { compareAll, qualifiesForInsight } from '../trackerCompare';
import { EffectRow } from './EffectRow';
import { compareSentence, type WellnessModel } from './wellnessModel';

const PATTERN_ICONS: Record<string, string> = { day_of_week: '#', streak: '*', trend: '^', correlation: '~', medication: '+' };

function PatternCard({ text, icon }: { text: string; icon: string }) {
  return (
    <div className="flex items-start gap-2 rounded-md bg-track border border-divider px-3 py-2">
      <span className="text-xs font-mono text-accent mt-0.5">{icon}</span>
      <span className="text-xs text-pn-soft leading-relaxed">{text}</span>
    </div>
  );
}

/** Spec: ops/docs/plans/wellness-statistics.md (section 11) */
export function PatternsSubTab({ model, stats, unlocked, isPro, onOpenUpgrade }: {
  model: WellnessModel;
  stats: TrackerStats;
  unlocked: boolean;
  isPro: boolean;
  onOpenUpgrade?: () => void;
}) {
  const { t } = useTranslation('stats');
  const [lag, setLag] = useState<0 | 1>(0);
  const mood = model.byId('mood');
  const rows = useMemo(() => (mood ? compareAll(model.entries, model.registry, mood, model.range, lag) : []), [model, mood, lag]);
  const sentences = useMemo(() => {
    if (!mood) return [] as string[];
    return rows.filter(qualifiesForInsight).map((r) => compareSentence(r, model.byId(r.trackerId)!, mood, t));
  }, [rows, mood, model, t]);
  const others: PatternInsight[] = stats.patterns;
  const insightCount = sentences.length + others.length;

  return (
    <>
      {mood && rows.length > 0 && (
        <div>
          <div className="flex items-center justify-between mb-1 gap-2">
            <div className="flex items-center gap-2">
              <span className={SETTINGS_EYEBROW}>{t('wellness.effects.heading')}</span>
              {!isPro && <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-bold bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-300">{t('wellness.patterns.proBadge')}</span>}
            </div>
            <div className="inline-flex rounded-md border border-divider overflow-hidden text-[10px]">
              {([0, 1] as const).map((l) => (
                <button key={l} type="button" onClick={() => setLag(l)} className={`px-2 py-0.5 ${lag === l ? 'bg-pn text-surface-2' : 'text-pn-soft'}`}>
                  {t(l === 0 ? 'wellness.effects.sameDay' : 'wellness.effects.nextDay')}
                </button>
              ))}
            </div>
          </div>
          {unlocked ? (
            <>
              {rows.map((r) => {
                const d = model.byId(r.trackerId);
                return d ? <EffectRow key={r.trackerId + (r.tag ?? '')} r={r} tracker={d} /> : null;
              })}
              <p className="text-[10px] text-pn-muted mt-2">{t('wellness.effects.footnote')}</p>
            </>
          ) : (
            <button type="button" onClick={onOpenUpgrade} className="w-full rounded-lg border border-dashed border-divider p-3 text-xs text-pn-muted hover:text-pn hover:border-pn-muted transition-colors text-center">
              {t('wellness.patterns.tableLocked')}
            </button>
          )}
        </div>
      )}

      {insightCount > 0 && (
        <div>
          <div className="flex items-center gap-2 mb-2">
            <SectionEyebrow>{t('wellness.patterns.insights')}</SectionEyebrow>
            {!isPro && <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-bold bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-300">{t('wellness.patterns.proBadge')}</span>}
          </div>
          {unlocked ? (
            <div className="space-y-2">
              {sentences.map((s, i) => <PatternCard key={`c${i}`} text={s} icon="~" />)}
              {others.map((p, i) => <PatternCard key={`p${i}`} text={insightText(p, t)} icon={PATTERN_ICONS[p.type] ?? '?'} />)}
            </div>
          ) : (
            <button type="button" onClick={onOpenUpgrade} className="w-full rounded-lg border border-dashed border-divider p-3 text-xs text-pn-muted hover:text-pn hover:border-pn-muted transition-colors text-center">
              {t('wellness.patterns.insightsLocked', { count: insightCount })}
            </button>
          )}
        </div>
      )}
    </>
  );
}
