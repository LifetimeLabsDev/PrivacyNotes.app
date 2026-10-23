import type { TFunction } from 'i18next';
import type { DaySeries, TrackerDescriptor } from '../wellnessTypes';
import { aggregate } from '../trackerSeries';
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
      // As needed: how many doses, never a share. Scheduled: doses taken of
      // the doses owed, the figure the statistics and the report give.
      if (a.doses && a.doses.expected === 0 && a.doses.asNeeded > 0) {
        return { headline: String(a.doses.asNeeded), sub: t('stats:wellness.trackers.asNeededDoses', { count: a.doses.asNeeded }) };
      }
      return {
        headline: a.rate === null ? '-' : `${a.rate}%`,
        sub: a.doses
          ? t('stats:wellness.trackers.takenDoses', { taken: a.doses.taken, count: a.doses.expected })
          : t('stats:wellness.trackers.taken', { taken: a.taken, total: a.taken + a.skipped + a.missed }),
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
        // Tags are counted, not averaged: the sub-line says how many days carry one.
        sub: t('stats:wellness.trackers.daysLogged', { count: a.n }),
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
