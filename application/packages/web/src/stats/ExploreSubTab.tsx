import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { CompareResult } from '../wellnessTypes';
import { SETTINGS_SELECT, SectionEyebrow, SettingsSegmented } from '../settingsUI';
import { ProMark } from '../UpgradeModal';
import { CalendarCheck, ChartLine, Sparkle } from '../icons';
import { EffectBarRow, SureDots, WeekdayChart, changeTone, signedValue, spreadOf, weekdayAverages } from './statsParts';
import { formatDay } from '../intlFormat';
import { TrackerChart } from '../TrackerChart';
import { aggregate } from '../trackerSeries';
import { compare, outcomesFor } from '../trackerCompare';
import { cardNumbers, chartSpecFor } from './TrackerCard';
import { compareSentence, formatNumber, hasData, levelLabel, sideLabels, trackerName, type WellnessModel } from './wellnessModel';

/**
 * One tracker's page: its numbers, its chart against an outcome on one date
 * axis, and the comparison, same day or next day. The Back row above names it.
 * Spec: ops/docs/archive/wellness-statistics.md (sections 9, 22)
 */
/** The smallest difference the goes-with list shows, as a share of the outcome's spread, and how many rows it keeps. */
const GOES_WITH_MIN = 0.05;
const GOES_WITH_MAX = 5;

export function ExploreSubTab({ model, trackerId, unlocked, isPro, onOpenUpgrade, onOpenDay }: {
  model: WellnessModel;
  trackerId: string;
  unlocked: boolean;
  isPro: boolean;
  onOpenUpgrade?: () => void;
  onOpenDay?: (date: string) => void;
}) {
  const { t } = useTranslation('stats');
  const [lag, setLag] = useState<0 | 1>(0);
  const [outcomeId, setOutcomeId] = useState<string>('mood');
  const selected = model.byId(trackerId) ?? null;
  const weekly = model.rangeDays > 182;

  const outcomes = useMemo(
    () => (selected ? outcomesFor(model.registry, selected.id).filter((d) => hasData(model.seriesOf(d))) : []),
    [model, selected],
  );
  const outcome = outcomes.find((d) => d.id === outcomeId) ?? outcomes.find((d) => d.id === 'mood') ?? outcomes[0] ?? null;

  const results = useMemo(() => {
    if (!selected || !outcome) return [] as { result: CompareResult; tag?: string }[];
    if (selected.kind === 'set') {
      const agg = aggregate(model.seriesOf(selected), selected);
      if (agg.kind !== 'set') return [];
      return agg.top.slice(0, 5).map((x) => ({ result: compare(model.entries, selected, outcome, model.range, lag, x.key), tag: x.key }));
    }
    return [{ result: compare(model.entries, selected, outcome, model.range, lag) }];
  }, [model, selected, outcome, lag]);

  // Every outcome at once, same day: what this tracker goes with, biggest difference first.
  const goesWith = useMemo(() => {
    if (!selected || !unlocked || selected.kind === 'set') return [];
    // Each difference as a share of its outcome's spread, so steps and a 1 to 10 scale compare fairly.
    const rows = outcomes
      .map((o) => {
        const r = compare(model.entries, selected, o, model.range, 0);
        return { o, r, share: r.delta === null ? 0 : Math.abs(r.delta) / spreadOf(o, model.seriesOf(o)) };
      })
      .filter(({ r, share }) => r.delta !== null && share >= GOES_WITH_MIN)
      .sort((a, b) => b.share - a.share)
      .slice(0, GOES_WITH_MAX);
    const top = Math.max(...rows.map((x) => x.share), 1e-9);
    return rows.map((x) => ({ ...x, share: x.share / top }));
  }, [model, selected, outcomes, unlocked]);

  if (!selected) return <p className="text-xs text-pn-muted">{t('wellness.trackers.empty')}</p>;
  const series = model.seriesOf(selected);
  const { headline, sub } = cardNumbers(selected, series, t);
  const name = trackerName(selected, t);
  const agg = aggregate(series, selected);
  const weekdayValues = selected.kind === 'scale' || selected.kind === 'measure' ? weekdayAverages(series) : null;
  const weekdays = weekdayValues && weekdayValues.every((v) => v !== null) ? weekdayValues : null;
  const formatPoint = (v: unknown) => {
    if (typeof v === 'boolean') return v ? t('trackers:custom.yes') : t('trackers:custom.no');
    if (typeof v === 'string') return levelLabel(selected, v, t);
    if (typeof v === 'number') return formatNumber(v, 1);
    if (Array.isArray(v)) return v.map((k) => levelLabel(selected, String(k), t)).join(', ');
    return '';
  };

  return (
    <>
      <div>
        <div className="text-2xl font-semibold">{headline}</div>
        <div className="text-[11px] text-pn-muted">{sub}</div>
        {agg.kind === 'yesno' && (
          <div className="text-[11px] text-pn-muted">
            {t('wellness.explore.longestRunWithout', { count: agg.longestRunWithout })}, {t('wellness.explore.longestRunWith', { count: agg.longestRunWith })}
          </div>
        )}
      </div>

      {/* The tracker's own chart when nothing else has data to set it against. */}
      {!outcome && (
        <div>
          <TrackerChart spec={chartSpecFor(selected, series, weekly)} height={64} ariaLabel={name} formatValue={formatPoint} onPickDay={onOpenDay} />
          <div className="flex justify-between text-[11px] text-pn-muted mt-1">
            <span>{formatDay(model.range.from, 'dayMonth')}</span>
            <span>{formatDay(model.range.to, 'dayMonth')}</span>
          </div>
        </div>
      )}

      {outcome && (
        <div>
          <SectionEyebrow className="mb-2" icon={ChartLine}>{t('wellness.explore.against', { outcome: trackerName(outcome, t) })}</SectionEyebrow>
          <TrackerChart spec={chartSpecFor(outcome, model.seriesOf(outcome), weekly)} height={64} ariaLabel={trackerName(outcome, t)} onPickDay={onOpenDay} />
          <div className="mt-1">
            <TrackerChart spec={chartSpecFor(selected, series, weekly)} height={selected.kind === 'yesno' ? 24 : 48} ariaLabel={name} formatValue={formatPoint} onPickDay={onOpenDay} />
          </div>
          <div className="flex justify-between text-[11px] text-pn-muted mt-1">
            <span>{formatDay(model.range.from, 'dayMonth')}</span>
            <span>{formatDay(model.range.to, 'dayMonth')}</span>
          </div>
        </div>
      )}

      {goesWith.length > 0 && (
        <div>
          <div className="flex items-center justify-between gap-2 mb-2">
            <SectionEyebrow icon={Sparkle}>{t('home.goesWith', { name })}</SectionEyebrow>
            <span className="text-[11px] text-pn-muted">{t('home.goesWithHint', { side: sideLabels(goesWith[0]!.r, selected, t).a })}</span>
          </div>
          <div className="@container rounded-lg border border-divider bg-surface-2 px-3 divide-y divide-divider">
            {goesWith.map(({ o, r, share }) => (
              <EffectBarRow
                key={o.id}
                d={o}
                label={trackerName(o, t)}
                sub={t('home.daysSplit', { a: r.a.n, b: r.b.n })}
                delta={r.delta ?? 0}
                sure={<SureDots r={r} />}
                share={share}
                text={signedValue(o, r.delta ?? 0, t)}
                tone={changeTone(o, r.delta ?? 0)}
              />
            ))}
          </div>
        </div>
      )}

      {weekdays && (
        <div>
          <SectionEyebrow className="mb-2" icon={CalendarCheck}>{t('home.byWeekday')}</SectionEyebrow>
          <div className="rounded-lg border border-divider bg-surface-2 p-3">
            <WeekdayChart values={weekdays} color={selected.color} format={(v) => formatNumber(v, 1)} />
          </div>
        </div>
      )}

      {outcome && (
        <div>
          <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
            <div className="flex items-center gap-2">
              <SettingsSegmented
                label={`${t('wellness.effects.sameDay')} / ${t('wellness.effects.nextDay')}`}
                value={lag === 0 ? 'same' : 'next'}
                onChange={(v) => setLag(v === 'same' ? 0 : 1)}
                options={[
                  { value: 'same', label: t('wellness.effects.sameDay') },
                  { value: 'next', label: t('wellness.effects.nextDay') },
                ]}
              />
              {!isPro && <ProMark />}
            </div>
            {unlocked && outcomes.length > 1 && (
              <label className="flex items-center gap-2 text-xs text-pn-soft">
                {t('wellness.effects.compareWith')}
                <select value={outcome.id} onChange={(e) => setOutcomeId(e.target.value)} className={SETTINGS_SELECT}>
                  {outcomes.map((d) => <option key={d.id} value={d.id}>{trackerName(d, t)}</option>)}
                </select>
              </label>
            )}
          </div>
          {unlocked ? (
            <div className="space-y-3">
              {results.map(({ result, tag }) => {
                const sides = sideLabels(result, selected, t);
                // The bars share one scale: the outcome's declared range, or the larger mean.
                const scale = outcome.max ?? Math.max(result.a.mean ?? 0, result.b.mean ?? 0, 1);
                const widthA = result.a.mean === null ? 0 : (result.a.mean / scale) * 100;
                const widthB = result.b.mean === null ? 0 : (result.b.mean / scale) * 100;
                return (
                  <div key={tag ?? 'one'} className="rounded-lg border border-divider bg-track p-3">
                    {/* The finding first, in words; the bars below show it. */}
                    <p className="text-sm text-pn mb-3">
                      {result.delta === null
                        ? result.shortfall && t('wellness.effects.shortfall', { count: result.shortfall.days, side: t(result.shortfall.side === 'a' ? 'wellness.effects.sideWith' : 'wellness.effects.sideWithout') })
                        : compareSentence(result, selected, outcome, t)}
                    </p>
                    {([['a', widthA, result.a, selected.color, sides.a], ['b', widthB, result.b, undefined, sides.b]] as const).map(([side, w, g, color, label]) => (
                      <div key={side} className="grid grid-cols-[minmax(0,9rem)_1fr_2.5rem] items-center gap-3 text-xs mb-2 last:mb-0">
                        <span className="min-w-0">
                          <span className="block text-pn-soft truncate">{label}</span>
                          <span className="block text-[11px] text-pn-muted">{t('wellness.units.days', { count: g.n })}</span>
                        </span>
                        <span className="h-2.5 rounded bg-surface-0 overflow-hidden"><span className="block h-full rounded" style={{ width: `${Math.min(100, w)}%`, backgroundColor: color ?? 'var(--pn-border-stronger, #9ca3af)' }} /></span>
                        <span className="tabular-nums text-end text-sm font-semibold">{g.mean === null ? '-' : formatNumber(g.mean, 1)}</span>
                      </div>
                    ))}
                  </div>
                );
              })}
              <p className="text-[11px] text-pn-muted">{t('wellness.effects.footnote')}</p>
            </div>
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
