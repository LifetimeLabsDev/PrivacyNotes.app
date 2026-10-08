import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import type { DaySeries, TrackerDescriptor } from '../wellnessTypes';
import { aggregate } from '../trackerSeries';
import { TrackerChart } from '../TrackerChart';
import { formatNumber, formatValue, levelLabel, moodColor, trackerName } from './wellnessModel';

/** The chart form a tracker's kind takes on a card and in Explore. */
export function chartSpecFor(d: TrackerDescriptor, series: DaySeries, weekly: boolean) {
  switch (d.kind) {
    case 'yesno':
    case 'medication':
      return { form: 'dots' as const, series, color: d.color };
    case 'measure':
      return { form: 'line' as const, series, color: d.color, weekly };
    case 'ordinal':
      return { form: 'bars' as const, series, color: d.color, levels: d.levels, min: 0, max: (d.levels?.length ?? 1) - 1, weekly };
    case 'set': {
      // The number of tags a day, so the card shows when something was felt.
      const counted = { ...series, points: series.points.map((p) => ({ date: p.date, value: Array.isArray(p.value) && p.value.length ? p.value.length : undefined })) };
      return { form: 'bars' as const, series: counted, color: d.color, min: 0, weekly };
    }
    default:
      return {
        form: 'bars' as const,
        series,
        color: d.color,
        min: d.min,
        max: d.max,
        weekly,
        ...(d.id === 'mood' ? { ramp: moodColor } : {}),
      };
  }
}

/** The headline and the sub-line of a card, from the aggregate of its kind. */
export function cardNumbers(d: TrackerDescriptor, series: DaySeries, t: TFunction): { headline: string; sub: string } {
  const a = aggregate(series, d);
  switch (a.kind) {
    case 'yesno':
      return {
        headline: t('stats:wellness.trackers.yesNo', { yes: a.yes, no: a.no }),
        sub: t('stats:wellness.trackers.notLogged', { count: a.notLogged }),
      };
    case 'medication':
      return {
        headline: a.rate === null ? '-' : `${a.rate}%`,
        sub: t('stats:wellness.trackers.taken', { taken: a.taken, total: a.taken + a.skipped + a.missed }),
      };
    case 'ordinal': {
      const top = Object.entries(a.counts).sort((x, y) => y[1] - x[1])[0];
      return {
        headline: top && top[1] > 0 ? levelLabel(d, top[0], t) : '-',
        sub: top && top[1] > 0 ? t('stats:wellness.trackers.topLevel', { level: levelLabel(d, top[0], t), count: top[1] }) : t('stats:wellness.trackers.empty'),
      };
    }
    case 'set':
      return {
        headline: a.top.slice(0, 3).map((x) => levelLabel(d, x.key, t)).join(', ') || '-',
        sub: t('stats:wellness.trackers.avgDays', { count: a.n }),
      };
    default: {
      if (a.n === 0) return { headline: '-', sub: t('stats:wellness.trackers.empty') };
      const headline = d.aggregate === 'sum' ? formatNumber(a.sum, 1) : formatValue(d, a.avg ?? 0, t, d.kind === 'scale' ? 1 : 1);
      const sub = d.aggregate === 'sum'
        ? t('stats:wellness.trackers.sumDays', { count: a.n })
        : `${t('stats:wellness.trackers.avgDays', { count: a.n })}, ${t('stats:wellness.trackers.latestLowHigh', {
            latest: formatValue(d, a.latest ?? 0, t), low: formatNumber(a.low ?? 0), high: formatNumber(a.high ?? 0),
          })}`;
      return { headline, sub };
    }
  }
}

/** The series from its first day with a value, so a card is not two thirds empty when the range opens before the log. */
function sinceFirstValue(series: DaySeries): DaySeries {
  const i = series.points.findIndex((p) => p.value !== undefined && !(Array.isArray(p.value) && p.value.length === 0));
  if (i <= 0) return series;
  const points = series.points.slice(i);
  return { from: points[0]!.date, to: series.to, points };
}

export function TrackerCard({ d, series, weekly, loggedDays, onOpen }: {
  d: TrackerDescriptor;
  series: DaySeries;
  weekly: boolean;
  /** Days in the range with a journal entry: a yes/no card counts its unanswered days among them. */
  loggedDays: number;
  onOpen: (id: string) => void;
}) {
  const { t } = useTranslation('stats');
  const shown = sinceFirstValue(series);
  const numbers = cardNumbers(d, series, t);
  const a = d.kind === 'yesno' ? aggregate(series, d) : null;
  const headline = numbers.headline;
  const sub = a?.kind === 'yesno' ? t('stats:wellness.trackers.unanswered', { count: Math.max(0, loggedDays - a.yes - a.no) }) : numbers.sub;
  const name = trackerName(d, t);
  return (
    <button
      type="button"
      onClick={() => onOpen(d.id)}
      className="text-start rounded-lg border border-divider bg-surface-2 px-3 py-2.5 hover:border-pn-muted transition-colors min-w-0"
    >
      <div className="flex items-center gap-1.5 text-xs text-pn-soft min-w-0">
        <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: d.color }} />
        <span className="truncate">{name}</span>
        {d.stoppedAt && !d.deletedAt && <span className="ms-auto text-[10px] text-pn-muted">{t('wellness.trackers.stopped')}</span>}
        {d.deletedAt && <span className="ms-auto text-[10px] text-pn-muted">{t('wellness.trackers.deleted')}</span>}
      </div>
      <div className="text-base font-semibold mt-1 truncate">{headline}</div>
      <div className="text-[10px] text-pn-muted truncate mb-1.5">{sub}</div>
      <TrackerChart spec={chartSpecFor(d, shown, weekly)} height={36} ariaLabel={`${name}: ${headline}`} />
    </button>
  );
}
