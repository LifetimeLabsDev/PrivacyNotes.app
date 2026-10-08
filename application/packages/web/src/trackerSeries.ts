import { toLocalIso } from './intlFormat';
import type { JournalEntry } from './trackerStats';
import type {
  DayPoint,
  DaySeries,
  RangeBounds,
  RangeId,
  TrackerDescriptor,
  TrackerKind,
} from './wellnessTypes';

/**
 * Tracker values on a calendar axis: one slot per local day, a missing day
 * kept as a gap, never closed up. Every day is stepped with a local Date,
 * so a day is the person's calendar day, never a UTC slice.
 * Spec: ops/docs/plans/wellness-statistics.md (section 5)
 */

function parseDay(iso: string): Date {
  const [y, m, d] = iso.split('-').map(Number);
  return new Date(y!, m! - 1, d!);
}

function addDays(iso: string, n: number): string {
  const d = parseDay(iso);
  d.setDate(d.getDate() + n);
  return toLocalIso(d);
}

/** Whole calendar days from `a` to `b`; date-only UTC arithmetic so a DST change cannot shift it. */
function dayDiff(a: string, b: string): number {
  const [ay, am, ad] = a.split('-').map(Number);
  const [by, bm, bd] = b.split('-').map(Number);
  return Math.round((Date.UTC(by!, bm! - 1, bd!) - Date.UTC(ay!, am! - 1, ad!)) / 86_400_000);
}

const RANGE_DAYS: Record<Exclude<RangeId, 'all'>, number> = {
  '7d': 7, '14d': 14, '30d': 30, '3mo': 91, '6mo': 182, '12mo': 365,
};

/** The days a range covers, today included. */
export function resolveRange(id: RangeId, firstDay: string | null, today = toLocalIso(new Date())): RangeBounds {
  if (id === 'all') {
    return { from: firstDay && firstDay < today ? firstDay : today, to: today };
  }
  return { from: addDays(today, -(RANGE_DAYS[id] - 1)), to: today };
}

/** The shortest preset that holds the whole journal; never 'all'. */
export function adaptiveRange(firstDay: string | null, today = toLocalIso(new Date())): RangeId {
  const age = firstDay ? dayDiff(firstDay, today) : 0;
  if (age <= 7) return '7d';
  if (age <= 14) return '14d';
  if (age <= 30) return '30d';
  if (age <= 91) return '3mo';
  if (age <= 182) return '6mo';
  return '12mo';
}

/** The window of the same length that ends the day before `range` starts. */
export function previousWindow(range: RangeBounds): RangeBounds {
  const len = dayDiff(range.from, range.to) + 1;
  const to = addDays(range.from, -1);
  return { from: addDays(to, -(len - 1)), to };
}

export function buildSeries(entries: JournalEntry[], d: TrackerDescriptor, range: RangeBounds): DaySeries {
  const byDate = new Map(entries.map((e) => [e.date, e.data]));
  const points: DayPoint[] = [];
  for (let day = range.from; day <= range.to; day = addDays(day, 1)) {
    const data = byDate.get(day);
    points.push({ date: day, value: data ? d.read(data) : undefined });
  }
  return { from: range.from, to: range.to, points };
}

function numeric(p: DayPoint): number | undefined {
  return typeof p.value === 'number' ? p.value : undefined;
}

function mean(xs: number[]): number {
  return xs.reduce((s, x) => s + x, 0) / xs.length;
}

/**
 * One mark per Monday-start week: the mean of the numbers, or for yes/no
 * the share of answered days that said yes. `weekStart` can fall before the
 * series start when the range opens mid-week. A week with nothing logged
 * carries `value: null`. Display only: no statistic reads these marks.
 */
export function weeklyMarks(series: DaySeries, kind: TrackerKind): { weekStart: string; value: number | null; n: number }[] {
  const weeks = new Map<string, number[]>();
  for (const p of series.points) {
    const dow = parseDay(p.date).getDay();
    const start = addDays(p.date, -(dow === 0 ? 6 : dow - 1));
    const bucket = weeks.get(start) ?? [];
    weeks.set(start, bucket);
    const v = kind === 'yesno'
      ? (typeof p.value === 'boolean' ? (p.value ? 1 : 0) : undefined)
      : numeric(p);
    if (v !== undefined) bucket.push(v);
  }
  return [...weeks].map(([weekStart, xs]) => ({
    weekStart,
    value: xs.length ? mean(xs) : null,
    n: xs.length,
  }));
}

/** For each day, the mean of the values in the `window` calendar days ending on it, when at least `minObs` are logged. */
export function rollingAverage(series: DaySeries, window = 7, minObs = 4): DaySeries {
  const values = series.points.map(numeric);
  const points = series.points.map((p, i) => {
    const xs = values.slice(Math.max(0, i - window + 1), i + 1).filter((v): v is number => v !== undefined);
    return { date: p.date, value: xs.length >= minObs ? mean(xs) : undefined };
  });
  return { from: series.from, to: series.to, points };
}

function aggregateYesNo(series: DaySeries) {
  let yes = 0, no = 0, notLogged = 0, runWith = 0, runWithout = 0, longestRunWith = 0, longestRunWithout = 0;
  for (const p of series.points) {
    if (p.value === true) {
      yes++; runWith++; runWithout = 0;
    } else if (p.value === false) {
      no++; runWithout++; runWith = 0;
    } else {
      notLogged++; runWith = 0; runWithout = 0;
    }
    longestRunWith = Math.max(longestRunWith, runWith);
    longestRunWithout = Math.max(longestRunWithout, runWithout);
  }
  return { kind: 'yesno' as const, yes, no, notLogged, longestRunWith, longestRunWithout };
}

function aggregateMedication(series: DaySeries) {
  let taken = 0, skipped = 0, missed = 0, unmarked = 0, started = false;
  for (const p of series.points) {
    if (p.value === 'taken') taken++;
    else if (p.value === 'skipped') skipped++;
    else if (p.value === 'missed') missed++;
    // Days before the first mark in the range are before the person began logging this dose.
    else if (started) unmarked++;
    if (p.value !== undefined) started = true;
  }
  const marked = taken + skipped + missed;
  return {
    kind: 'medication' as const, taken, skipped, missed, unmarked,
    rate: marked ? Math.round((taken / marked) * 100) : null,
  };
}

/** The card headline and sub-line numbers of one tracker over one series, from daily values. */
export function aggregate(series: DaySeries, d: TrackerDescriptor) {
  switch (d.kind) {
    case 'yesno':
      return aggregateYesNo(series);
    case 'medication':
      return aggregateMedication(series);
    case 'ordinal': {
      const counts: Record<string, number> = Object.fromEntries((d.levels ?? []).map((l) => [l, 0]));
      let n = 0;
      for (const p of series.points) {
        if (typeof p.value !== 'string') continue;
        counts[p.value] = (counts[p.value] ?? 0) + 1;
        n++;
      }
      return { kind: 'ordinal' as const, counts, n };
    }
    case 'set': {
      const counts = new Map<string, number>();
      let n = 0;
      for (const p of series.points) {
        if (!Array.isArray(p.value)) continue;
        n++;
        for (const key of p.value) counts.set(key, (counts.get(key) ?? 0) + 1);
      }
      const top = [...counts]
        .map(([key, count]) => ({ key, count }))
        .sort((a, b) => b.count - a.count || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
      return { kind: 'set' as const, top, n };
    }
    default: {
      const xs = series.points.map(numeric).filter((v): v is number => v !== undefined);
      return {
        kind: 'numeric' as const,
        avg: xs.length ? mean(xs) : null,
        sum: xs.reduce((s, x) => s + x, 0),
        n: xs.length,
        low: xs.length ? Math.min(...xs) : null,
        high: xs.length ? Math.max(...xs) : null,
        latest: xs.length ? xs[xs.length - 1]! : null,
      };
    }
  }
}
