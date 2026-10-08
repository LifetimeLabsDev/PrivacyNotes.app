import { toLocalIso } from './intlFormat';
import type { JournalEntry } from './trackerStats';
import type { CompareResult, CompareRuleKind, RangeBounds, TrackerDescriptor, TrackerKind } from './wellnessTypes';

/**
 * One tracker against one numeric outcome: the days split into two groups by
 * a rule fixed per kind, the outcome averaged on each side. A rule never
 * depends on the tracker's name, and a threshold is never picked for the size
 * of the difference it produces.
 * Spec: ops/docs/plans/wellness-statistics.md (section 7)
 */

/** Days needed on each side before a difference is shown. */
export const MIN_PER_SIDE = 7;
/** The smallest difference an insight sentence may state. */
const INSIGHT_MIN_DELTA = 0.5;

const RULE_OF_KIND: Record<TrackerKind, CompareRuleKind> = {
  yesno: 'yesno',
  scale: 'halves',
  measure: 'median',
  ordinal: 'levels',
  set: 'tag',
  medication: 'medication',
};

const isNumericKind = (d: TrackerDescriptor) => d.kind === 'scale' || d.kind === 'measure';

function inRange(date: string, range: RangeBounds): boolean {
  return date >= range.from && date <= range.to;
}

/** A local ISO date as a local midnight. */
function localDate(iso: string): Date {
  const [y = 0, m = 1, d = 1] = iso.split('-').map(Number);
  return new Date(y, m - 1, d);
}

function nextDay(iso: string): string {
  const day = localDate(iso);
  day.setDate(day.getDate() + 1);
  return toLocalIso(day);
}

function asNumber(v: unknown): number | undefined {
  return typeof v === 'number' && Number.isFinite(v) ? v : undefined;
}

function median(values: number[]): number {
  const s = [...values].sort((x, y) => x - y);
  const mid = s.length >> 1;
  return s.length % 2 ? s[mid]! : (s[mid - 1]! + s[mid]!) / 2;
}

/** The scale's split point: 5 for 0 to 10 and for 1 to 10, 2 for 0 to 5, 50 for 0 to 100. */
function scaleThreshold(t: TrackerDescriptor): number {
  return Math.floor(((t.min ?? 0) + (t.max ?? 10)) / 2);
}

/** 'a', 'b', 'out' (left out and counted), or null (not a day of this tracker). */
type Side = 'a' | 'b' | 'out' | null;

function sideOf(t: TrackerDescriptor, v: unknown, threshold: number | undefined, tag: string | undefined): Side {
  switch (t.kind) {
    case 'yesno':
      return v === true ? 'a' : v === false ? 'b' : null;
    case 'scale':
    case 'measure': {
      const n = asNumber(v);
      if (n === undefined) return null;
      return n > threshold! ? 'a' : 'b';
    }
    case 'ordinal': {
      if (typeof v !== 'string') return null;
      const levels = t.levels ?? [];
      const i = levels.indexOf(v);
      if (i < 0) return null;
      const k = Math.min(2, levels.length >> 1);
      if (i >= levels.length - k) return 'a';
      if (i < k) return 'b';
      return 'out';
    }
    case 'set': {
      if (!Array.isArray(v) || v.length === 0) return null;
      return v.includes(tag) ? 'a' : 'b';
    }
    case 'medication':
      return v === 'taken' ? 'a' : v === 'missed' ? 'b' : 'out';
  }
}

function meanOf(values: number[]): number | null {
  return values.length ? values.reduce((s, x) => s + x, 0) / values.length : null;
}

/**
 * Compares `tracker` against `outcome`, a scale or measure, over `range`.
 * Lag 1 pairs day d with the outcome of calendar day d+1, both in range. The
 * tracker and the outcome are assumed distinct (see `outcomesFor`); a set
 * tracker needs `tag`.
 */
export function compare(
  entries: JournalEntry[],
  tracker: TrackerDescriptor,
  outcome: TrackerDescriptor,
  range: RangeBounds,
  lag: 0 | 1,
  tag?: string,
): CompareResult {
  if (tracker.kind === 'set' && tag === undefined) throw new Error('compare: a set tracker needs a tag');
  const byDate = new Map<string, JournalEntry>();
  for (const e of entries) if (inRange(e.date, range)) byDate.set(e.date, e);

  let threshold: number | undefined;
  if (tracker.kind === 'scale') threshold = scaleThreshold(tracker);
  if (tracker.kind === 'measure') {
    // Taken from every observation in range, so it holds when the lag switches.
    const obs: number[] = [];
    for (const e of byDate.values()) {
      const n = asNumber(tracker.read(e.data));
      if (n !== undefined) obs.push(n);
    }
    threshold = obs.length ? median(obs) : 0;
  }

  const groups = { a: [] as number[], b: [] as number[] };
  let excluded = 0;
  for (const e of byDate.values()) {
    const side = sideOf(tracker, tracker.read(e.data), threshold, tag);
    if (side === null) continue;
    if (side === 'out') { excluded++; continue; }
    const outcomeDate = lag === 0 ? e.date : nextDay(e.date);
    const other = byDate.get(outcomeDate);
    const y = other ? asNumber(outcome.read(other.data)) : undefined;
    if (y === undefined) { excluded++; continue; }
    groups[side].push(y);
  }

  const a = { n: groups.a.length, mean: meanOf(groups.a) };
  const b = { n: groups.b.length, mean: meanOf(groups.b) };
  const short = a.n < MIN_PER_SIDE || b.n < MIN_PER_SIDE;
  const result: CompareResult = {
    trackerId: tracker.id,
    outcomeId: outcome.id,
    range,
    lag,
    rule: threshold === undefined ? { kind: RULE_OF_KIND[tracker.kind] } : { kind: RULE_OF_KIND[tracker.kind], threshold },
    a,
    b,
    delta: short ? null : a.mean! - b.mean!,
    excluded,
  };
  if (tag !== undefined) result.tag = tag;
  if (short) {
    const side = a.n <= b.n ? 'a' : 'b';
    result.shortfall = { side, days: MIN_PER_SIDE - result[side].n };
  }
  return result;
}

/** The outcomes a tracker can be compared with: every scale and measure but itself. */
export function outcomesFor(registry: TrackerDescriptor[], trackerId: string): TrackerDescriptor[] {
  return registry.filter((d) => !d.unknown && isNumericKind(d) && d.id !== trackerId);
}

/** A set tracker's tags with at least one day in range: its declared order, then the rest as met. */
function tagsInRange(entries: JournalEntry[], t: TrackerDescriptor, range: RangeBounds): string[] {
  const seen = new Set<string>();
  for (const e of entries) {
    if (!inRange(e.date, range)) continue;
    const v = t.read(e.data);
    if (Array.isArray(v)) for (const tag of v) seen.add(tag);
  }
  const declared = (t.levels ?? []).filter((tag) => seen.has(tag));
  return [...declared, ...[...seen].filter((tag) => !declared.includes(tag))];
}

/**
 * Every tracker of the registry against `outcome`, one row per set tag.
 * Rows at the minimum come first by the size of the difference, then the
 * shortfall rows by the days still missing; ties keep the registry order.
 */
export function compareAll(
  entries: JournalEntry[],
  registry: TrackerDescriptor[],
  outcome: TrackerDescriptor,
  range: RangeBounds,
  lag: 0 | 1,
): CompareResult[] {
  const rows: CompareResult[] = [];
  for (const t of registry) {
    if (t.unknown || t.id === outcome.id) continue;
    if (t.kind === 'set') {
      for (const tag of tagsInRange(entries, t, range)) rows.push(compare(entries, t, outcome, range, lag, tag));
    } else {
      rows.push(compare(entries, t, outcome, range, lag));
    }
  }
  const full = rows.filter((r) => r.delta !== null).sort((x, y) => Math.abs(y.delta!) - Math.abs(x.delta!));
  const short = rows.filter((r) => r.delta === null).sort((x, y) => x.shortfall!.days - y.shortfall!.days);
  return [...full, ...short];
}

/** An insight sentence needs both sides at the minimum and a difference of at least half a point. */
export function qualifiesForInsight(r: CompareResult): boolean {
  return r.a.n >= MIN_PER_SIDE && r.b.n >= MIN_PER_SIDE && r.delta !== null && Math.abs(r.delta) >= INSIGHT_MIN_DELTA;
}

/**
 * Consecutive calendar days with a mood, ending today, or yesterday when
 * today has no mood yet. A day tracked without a mood ends the run.
 */
export function moodStreak(entries: JournalEntry[], today: string): number {
  const moodDays = new Set(entries.filter((e) => asNumber(e.data.mood) !== undefined).map((e) => e.date));
  const day = localDate(today);
  if (!moodDays.has(toLocalIso(day))) day.setDate(day.getDate() - 1);
  let streak = 0;
  while (moodDays.has(toLocalIso(day))) {
    streak++;
    day.setDate(day.getDate() - 1);
  }
  return streak;
}
