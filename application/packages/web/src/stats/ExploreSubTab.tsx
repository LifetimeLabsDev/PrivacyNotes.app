import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { CompareResult, DaySeries, TrackerDescriptor } from '../wellnessTypes';
import { SectionEyebrow } from '../settingsUI';
import { formatDay } from '../intlFormat';
import { TrackerChart } from '../TrackerChart';
import { aggregate } from '../trackerSeries';
import { compare, outcomesFor } from '../trackerCompare';
import { visibleInUi } from '../trackerRegistry';
import { cardNumbers, chartSpecFor } from './TrackerCard';
import { compareSentence, formatNumber, hasData, levelLabel, ruleLabel, trackerName, type WellnessModel } from './wellnessModel';

/** The calendar shows at most this many days; longer ranges show its tail. */
const CALENDAR_DAYS = 91;

function tail(series: DaySeries, days: number): DaySeries {
  if (series.points.length <= days) return series;
  const points = series.points.slice(-days);
  return { from: points[0]!.date, to: series.to, points };
}

/** Spec: ops/docs/plans/wellness-statistics.md (section 9) */
export function ExploreSubTab({ model, selectedId, onSelect, unlocked, isPro, onOpenUpgrade, onOpenDay }: {
  model: WellnessModel;
  selectedId: string | null;
  onSelect: (id: string) => void;
  unlocked: boolean;
  isPro: boolean;
  onOpenUpgrade?: () => void;
  onOpenDay?: (date: string) => void;
}) {
  const { t } = useTranslation('stats');
  const [showStopped, setShowStopped] = useState(false);
  const [lag, setLag] = useState<0 | 1>(0);
  const [outcomeId, setOutcomeId] = useState<string>('mood');

  const withData = useMemo(
    () => model.registry.filter((d) => d.kind !== 'medication' && hasData(model.seriesOf(d))),
    [model],
  );
  const live = withData.filter(visibleInUi);
  const stopped = withData.filter((d) => !visibleInUi(d));
  const chips = showStopped ? [...live, ...stopped] : live;
  // Mood is the default outcome, so the default subject is the first other tracker.
  const selected = model.byId(selectedId ?? '') ?? live.find((d) => d.id !== 'mood') ?? live[0] ?? null;
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

  if (!selected) return <p className="text-xs text-pn-muted">{t('wellness.trackers.empty')}</p>;
  const series = model.seriesOf(selected);
  const { headline, sub } = cardNumbers(selected, series, t);
  const name = trackerName(selected, t);
  const agg = aggregate(series, selected);
  const formatPoint = (v: unknown) => {
    if (typeof v === 'boolean') return v ? t('trackers:custom.yes') : t('trackers:custom.no');
    if (typeof v === 'string') return levelLabel(selected, v, t);
    if (typeof v === 'number') return formatNumber(v, 1);
    if (Array.isArray(v)) return v.map((k) => levelLabel(selected, String(k), t)).join(', ');
    return '';
  };

  return (
    <>
      <div className="flex flex-wrap gap-1.5">
        {chips.map((d) => {
          const on = d.id === selected.id;
          return (
            <button
              key={d.id}
              type="button"
              onClick={() => onSelect(d.id)}
              className={`px-2.5 py-1 rounded-full text-[11px] font-medium border transition-colors ${on ? 'text-white border-transparent' : 'border-divider text-pn-soft hover:border-pn-muted'} ${!visibleInUi(d) ? 'line-through' : ''}`}
              style={on ? { backgroundColor: d.color } : undefined}
            >
              {trackerName(d, t)}
            </button>
          );
        })}
        {stopped.length > 0 && (
          <button type="button" onClick={() => setShowStopped((v) => !v)} className="px-2.5 py-1 rounded-full text-[11px] border border-dashed border-divider text-pn-muted">
            {t('wellness.trackers.stoppedChip', { count: stopped.length })}
          </button>
        )}
      </div>

      <div>
        <div className="flex items-baseline justify-between gap-2">
          <span className="text-sm font-semibold inline-flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: selected.color }} />
            {name}
          </span>
          <span className="text-[10px] text-pn-muted">{t(`range.${model.rangeId}`)}</span>
        </div>
        <div className="text-xl font-semibold mt-1">{headline}</div>
        <div className="text-[11px] text-pn-muted">{sub}</div>
        {agg.kind === 'yesno' && (
          <div className="text-[11px] text-pn-muted">
            {t('wellness.explore.longestRunWithout', { count: agg.longestRunWithout })}, {t('wellness.explore.longestRunWith', { count: agg.longestRunWith })}
          </div>
        )}
      </div>

      <div>
        <SectionEyebrow className="mb-2">{t('wellness.explore.calendar')}</SectionEyebrow>
        <TrackerChart
          spec={{ form: 'calendar', series: tail(series, CALENDAR_DAYS), color: selected.color, levels: selected.levels }}
          height={Math.ceil(Math.min(series.points.length, CALENDAR_DAYS) / 7 + 1) * 20}
          ariaLabel={`${name}: ${t('wellness.explore.calendar')}`}
          formatValue={formatPoint}
          onPickDay={onOpenDay}
        />
      </div>

      {outcome && (
        <div>
          <SectionEyebrow className="mb-2">{t('wellness.explore.against', { outcome: trackerName(outcome, t) })}</SectionEyebrow>
          <TrackerChart spec={chartSpecFor(outcome, model.seriesOf(outcome), weekly)} height={64} ariaLabel={trackerName(outcome, t)} onPickDay={onOpenDay} />
          <div className="mt-1">
            <TrackerChart spec={chartSpecFor(selected, series, weekly)} height={selected.kind === 'yesno' ? 24 : 48} ariaLabel={name} formatValue={formatPoint} onPickDay={onOpenDay} />
          </div>
          <div className="flex justify-between text-[10px] text-pn-muted mt-1">
            <span>{formatDay(model.range.from, 'dayMonth')}</span>
            <span>{formatDay(model.range.to, 'dayMonth')}</span>
          </div>
        </div>
      )}

      {outcome && (
        <div>
          <div className="flex items-center gap-2 mb-2">
            <div className="inline-flex rounded-md border border-divider overflow-hidden text-[11px]">
              {([0, 1] as const).map((l) => (
                <button key={l} type="button" onClick={() => setLag(l)} className={`px-3 py-1 ${lag === l ? 'bg-pn text-surface-2' : 'text-pn-soft'}`}>
                  {t(l === 0 ? 'wellness.effects.sameDay' : 'wellness.effects.nextDay')}
                </button>
              ))}
            </div>
            {!isPro && <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-bold bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-300">{t('wellness.patterns.proBadge')}</span>}
          </div>
          {unlocked ? (
            <div className="space-y-3">
              {results.map(({ result, tag }) => {
                const oName = trackerName(outcome, t);
                const label = tag ? levelLabel(selected, tag, t) : name;
                // The bars share one scale: the outcome's declared range, or the larger mean.
                const scale = outcome.max ?? Math.max(result.a.mean ?? 0, result.b.mean ?? 0, 1);
                const widthA = result.a.mean === null ? 0 : (result.a.mean / scale) * 100;
                const widthB = result.b.mean === null ? 0 : (result.b.mean / scale) * 100;
                return (
                  <div key={tag ?? 'one'} className="rounded-lg border border-divider bg-track p-3">
                    <div className="text-[10px] text-pn-muted mb-2">{label}: {ruleLabel(result, selected, t)}</div>
                    {([['a', widthA, result.a, selected.color], ['b', widthB, result.b, undefined]] as const).map(([side, w, g, color]) => (
                      <div key={side} className="grid grid-cols-[88px_1fr_36px] items-center gap-2 text-xs mb-1">
                        <span className="text-pn-soft">
                          {t(side === 'a' ? 'wellness.effects.withLabel' : 'wellness.effects.withoutLabel')}
                          <span className="block text-[10px] text-pn-muted">{t('wellness.units.days', { count: g.n })}</span>
                        </span>
                        <span className="h-2.5 rounded bg-surface-0 overflow-hidden"><span className="block h-full rounded" style={{ width: `${Math.min(100, w)}%`, backgroundColor: color ?? 'var(--pn-border-stronger, #9ca3af)' }} /></span>
                        <span className="tabular-nums text-end">{g.mean === null ? '-' : formatNumber(g.mean, 1)}</span>
                      </div>
                    ))}
                    <div className="text-xs mt-2">
                      {result.delta === null
                        ? result.shortfall && t('wellness.effects.shortfall', { count: result.shortfall.days, side: t(result.shortfall.side === 'a' ? 'wellness.effects.sideWith' : 'wellness.effects.sideWithout') })
                        : t(result.delta >= 0 ? 'wellness.effects.higher' : 'wellness.effects.lower', { outcome: oName, delta: formatNumber(Math.abs(result.delta), 1) })}
                    </div>
                    {result.delta !== null && Math.abs(result.delta) >= 0.5 && (
                      <div className="text-[11px] text-pn-muted mt-1">{compareSentence(result, selected, outcome, t)}</div>
                    )}
                  </div>
                );
              })}
              <p className="text-[10px] text-pn-muted">{t('wellness.effects.footnote')}</p>
              {outcomes.length > 1 && (
                <label className="flex items-center gap-2 text-[11px] text-pn-muted">
                  {t('wellness.effects.compareWith')}
                  <select value={outcome.id} onChange={(e) => setOutcomeId(e.target.value)} className="px-2 py-1 rounded-md text-xs border border-divider bg-surface-0 text-pn">
                    {outcomes.map((d) => <option key={d.id} value={d.id}>{trackerName(d, t)}</option>)}
                  </select>
                </label>
              )}
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
