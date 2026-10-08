import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import type { MedicationTemplate } from '../trackerTypes';
import type { TrackerStats } from '../trackerStats';
import { SectionEyebrow } from '../settingsUI';
import { formatDay } from '../intlFormat';
import { TrackerChart } from '../TrackerChart';
import { buildSeries, aggregate, previousWindow } from '../trackerSeries';
import { compareAll, qualifiesForInsight } from '../trackerCompare';
import { visibleInUi } from '../trackerRegistry';
import { EffectRow } from './EffectRow';
import { TrackerCard, chartSpecFor } from './TrackerCard';
import { WeekCard } from './WeekCard';
import { daysBetween, formatNumber, hasData, MOOD_COLORS, moodColor, trackerName, type WellnessModel } from './wellnessModel';

function Stat({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div>
      <div className="text-2xl font-semibold tabular-nums whitespace-nowrap">{value}</div>
      <SectionEyebrow className="mt-0.5">{label}</SectionEyebrow>
      {sub && <div className="text-[10px] text-pn-muted">{sub}</div>}
    </div>
  );
}

/** Spec: ops/docs/plans/wellness-statistics.md (section 8) */
export function AllSubTab({ model, stats, medications, unlocked, isPro, onExplore, onPatterns, weekReflection, onWeekReflectionChange, onOpenUpgrade }: {
  model: WellnessModel;
  stats: TrackerStats;
  medications: MedicationTemplate[];
  unlocked: boolean;
  isPro: boolean;
  onExplore: (id: string) => void;
  onPatterns: () => void;
  weekReflection?: string;
  onWeekReflectionChange?: (text: string) => void;
  onOpenUpgrade?: () => void;
}) {
  const { t } = useTranslation('stats');
  const weekly = model.rangeDays > 182;
  const mood = model.byId('mood');
  const moodSeries = mood ? model.seriesOf(mood) : null;
  const moodAgg = mood && moodSeries ? aggregate(moodSeries, mood) : null;
  const sleep = model.byId('sleepHours');
  const sleepAgg = sleep ? aggregate(model.seriesOf(sleep), sleep) : null;

  const moodDelta = useMemo(() => {
    if (!mood || !moodAgg || moodAgg.kind !== 'numeric' || moodAgg.avg === null) return null;
    const prev = aggregate(buildSeries(model.entries, mood, previousWindow(model.range)), mood);
    if (prev.kind !== 'numeric' || prev.avg === null || prev.n < 7) return null;
    return moodAgg.avg - prev.avg;
  }, [model, mood, moodAgg]);

  const grid = useMemo(() => {
    const rows = model.registry
      .filter((d) => d.id !== 'mood' && d.kind !== 'medication')
      .map((d) => ({ d, series: model.seriesOf(d) }))
      .filter(({ series }) => hasData(series));
    return { live: rows.filter(({ d }) => visibleInUi(d)), stopped: rows.filter(({ d }) => !visibleInUi(d)) };
  }, [model]);

  const top = useMemo(() => {
    if (!mood) return [];
    return compareAll(model.entries, model.registry, mood, model.range, 0).filter(qualifiesForInsight).slice(0, 3);
  }, [model, mood]);

  // Dose events inside the range, as marks under the mood chart.
  const doseMarks = useMemo(() => {
    const out: { date: string; label: string }[] = [];
    for (const m of medications) {
      for (const h of m.dosageHistory) {
        if (h.changedAt >= model.range.from && h.changedAt <= model.range.to) out.push({ date: h.changedAt, label: t('wellness.mood.dose', { name: m.name, dosage: h.dosage }) });
      }
    }
    return out;
  }, [medications, model.range, t]);

  const logged = model.inRange.length;
  return (
    <>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <Stat label={t('wellness.tiles.daysLogged')} value={t('wellness.tiles.daysLoggedOf', { logged, days: model.rangeDays })} />
        <Stat
          label={t('wellness.tiles.avgMood')}
          value={moodAgg?.kind === 'numeric' && moodAgg.avg !== null ? formatNumber(moodAgg.avg) : '-'}
          sub={moodDelta === null ? undefined : t('wellness.tiles.moodDelta', { delta: `${moodDelta >= 0 ? '+' : ''}${formatNumber(moodDelta)}`, days: model.rangeDays })}
        />
        <Stat label={t('wellness.tiles.avgSleep')} value={sleepAgg?.kind === 'numeric' && sleepAgg.avg !== null ? `${formatNumber(sleepAgg.avg)} h` : '-'} />
        <Stat label={t('wellness.tiles.medsTaken')} value={stats.medAdherence != null ? `${stats.medAdherence}%` : '-'} />
      </div>

      {mood && moodSeries && hasData(moodSeries) && (
        <div data-setting="stats.moodTrend">
          <div className="flex items-center justify-between mb-2 gap-2">
            <SectionEyebrow>{t('wellness.mood.heading')}</SectionEyebrow>
            <span className="text-[10px] text-pn-muted">{t('wellness.mood.legend')}</span>
          </div>
          <TrackerChart spec={chartSpecFor(mood, moodSeries, weekly)} height={96} average ariaLabel={trackerName(mood, t)} />
          <div className="relative h-4">
            {doseMarks.map((m) => (
              <span
                key={m.date + m.label}
                title={`${formatDay(m.date, 'date')}: ${m.label}`}
                className="absolute -translate-x-1/2 text-[10px] leading-none"
                style={{ left: `${((daysBetween(model.range.from, m.date) + 0.5) / model.rangeDays) * 100}%`, color: '#C2512B' }}
              >
                &#9650;
              </span>
            ))}
          </div>
          <div className="flex justify-between text-[10px] text-pn-muted">
            <span>{formatDay(model.range.from, 'dayMonth')}</span>
            <span>{formatDay(model.range.to, 'dayMonth')}</span>
          </div>
          <div className="flex flex-wrap gap-3 mt-1 text-[10px] text-pn-muted">
            {(['1', '3', '5', '7', '10'] as const).map((k, i) => (
              <span key={k} className="inline-flex items-center gap-1">
                <span className="w-2 h-2 rounded-sm" style={{ backgroundColor: MOOD_COLORS[i] }} />
                {t(`trackers:mood.anchor.${k}`)}
              </span>
            ))}
          </div>
        </div>
      )}

      {stats.weekInReview && (
        <div>
          <div className="flex items-center gap-2 mb-2">
            <SectionEyebrow>{t('wellness.week.heading')}</SectionEyebrow>
            {!isPro && <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-bold bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-300">{t('wellness.week.proBadge')}</span>}
          </div>
          {unlocked ? (
            <WeekCard week={stats.weekInReview} reflection={weekReflection} onReflectionChange={onWeekReflectionChange} />
          ) : (
            <button type="button" onClick={onOpenUpgrade} className="w-full rounded-lg border border-dashed border-divider p-4 text-sm text-pn-muted hover:text-pn hover:border-pn-muted transition-colors text-center">
              {t('wellness.week.locked')}
            </button>
          )}
        </div>
      )}

      <div>
        <div className="flex items-center justify-between mb-2">
          <SectionEyebrow>{t('wellness.trackers.heading')}</SectionEyebrow>
          <span className="text-[10px] text-pn-muted">{t('wellness.trackers.tapHint')}</span>
        </div>
        {grid.live.length === 0 && grid.stopped.length === 0 ? (
          <p className="text-xs text-pn-muted">{t('wellness.trackers.empty')}</p>
        ) : (
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
            {grid.live.map(({ d, series }) => (
              <TrackerCard key={d.id} d={d} series={series} weekly={weekly} loggedDays={logged} onOpen={onExplore} />
            ))}
          </div>
        )}
        {grid.stopped.length > 0 && (
          <details className="mt-2">
            <summary className="text-[11px] text-pn-muted cursor-pointer">{t('wellness.trackers.stoppedChip', { count: grid.stopped.length })}</summary>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 mt-2">
              {grid.stopped.map(({ d, series }) => (
                <TrackerCard key={d.id} d={d} series={series} weekly={weekly} loggedDays={logged} onOpen={onExplore} />
              ))}
            </div>
          </details>
        )}
      </div>

      {mood && top.length > 0 && (
        <div>
          <div className="flex items-center justify-between mb-1">
            <SectionEyebrow>{t('wellness.effects.heading')}</SectionEyebrow>
            <button type="button" onClick={onPatterns} className="text-[10px] text-accent hover:underline">{t('wellness.effects.allInPatterns')}</button>
          </div>
          {unlocked ? (
            top.map((r) => {
              const d = model.byId(r.trackerId);
              return d ? <EffectRow key={r.trackerId + (r.tag ?? '')} r={r} tracker={d} /> : null;
            })
          ) : (
            <button type="button" onClick={onOpenUpgrade} className="w-full rounded-lg border border-dashed border-divider p-3 text-xs text-pn-muted hover:text-pn hover:border-pn-muted transition-colors text-center">
              {t('wellness.patterns.tableLocked')}
            </button>
          )}
        </div>
      )}
    </>
  );
}
