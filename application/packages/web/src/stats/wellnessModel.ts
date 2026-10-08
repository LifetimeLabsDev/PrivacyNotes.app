import type { TFunction } from 'i18next';
import type { LocalNote } from '../db';
import type { MedicationTemplate, TrackerSettings } from '../trackerTypes';
import { extractEntries, type JournalEntry } from '../trackerStats';
import { toLocalIso } from '../notesViewUtils';
import { buildRegistry } from '../trackerRegistry';
import { buildSeries, resolveRange } from '../trackerSeries';
import type { CompareResult, DaySeries, RangeBounds, RangeId, TrackerDescriptor } from '../wellnessTypes';
import { intlLocale } from '../languages';

/**
 * The one model every Wellness screen reads: the entries behind the lock
 * predicate, the registry of every tracker, the range, and a series per
 * tracker on the calendar axis. Built once per range change and shared, so
 * the sub-tabs never disagree about a number.
 * Spec: ops/docs/plans/wellness-statistics.md (sections 4, 5)
 */
export interface WellnessModel {
  entries: JournalEntry[];
  inRange: JournalEntry[];
  registry: TrackerDescriptor[];
  range: RangeBounds;
  rangeId: RangeId;
  /** Calendar days in the range, inclusive. */
  rangeDays: number;
  firstDay: string | null;
  seriesOf: (d: TrackerDescriptor) => DaySeries;
  byId: (id: string) => TrackerDescriptor | undefined;
}

export function buildWellnessModel(
  notes: LocalNote[],
  isNoteLocked: (n: LocalNote) => boolean,
  trackerSettings: TrackerSettings,
  medications: MedicationTemplate[],
  rangeId: RangeId,
): WellnessModel {
  const entries = extractEntries(notes, isNoteLocked);
  const registry = buildRegistry(trackerSettings, medications, entries);
  const firstDay = entries[0]?.date ?? null;
  const range = resolveRange(rangeId, firstDay);
  const inRange = entries.filter((e) => e.date >= range.from && e.date <= range.to);
  const cache = new Map<string, DaySeries>();
  const seriesOf = (d: TrackerDescriptor) => {
    const hit = cache.get(d.id);
    if (hit) return hit;
    const s = buildSeries(entries, d, range);
    cache.set(d.id, s);
    return s;
  };
  return {
    entries,
    inRange,
    registry,
    range,
    rangeId,
    rangeDays: daysBetween(range.from, range.to) + 1,
    firstDay,
    seriesOf,
    byId: (id) => registry.find((d) => d.id === id),
  };
}

export function daysBetween(from: string, to: string): number {
  return Math.round((Date.parse(`${to}T12:00:00`) - Date.parse(`${from}T12:00:00`)) / 86_400_000);
}

/** A tracker has data in the range when at least one day carries a value. */
export function hasData(series: DaySeries): boolean {
  return series.points.some((p) => p.value !== undefined && !(Array.isArray(p.value) && p.value.length === 0));
}

/** The tracker's name in the language on screen; custom names are user text. */
export function trackerName(d: TrackerDescriptor, t: TFunction): string {
  if (d.unknown) return t('stats:wellness.trackers.unknown', { id: d.id.slice(0, 8) });
  if (d.name) return d.name;
  return d.labelKey ? t(d.labelKey) : d.id;
}

/** An ordinal level or a tag key as the catalog names it. */
export function levelLabel(d: TrackerDescriptor, level: string, t: TFunction): string {
  if (d.id === 'sleepQuality') return t(`trackers:sleep.quality.${level}`);
  if (d.id === 'activity') return t(`trackers:activity.level.${level}`);
  if (d.id === 'emotions') return t(`trackers:emotions.tags.${level}`, { defaultValue: level });
  return level;
}

export function formatNumber(n: number, digits = 1): string {
  return n.toLocaleString(intlLocale(), { maximumFractionDigits: digits });
}

/** A numeric value with its unit, the way the pills show it. */
export function formatValue(d: TrackerDescriptor, v: number, t: TFunction, digits = 1): string {
  // Steps and beats are counted, never fractional.
  const n = formatNumber(v, d.unit === 'steps' || d.unit === 'bpm' ? 0 : digits);
  switch (d.unit) {
    case 'h': return `${n} ${t('trackers:units.hoursSuffix')}`;
    case 'bpm': return `${n} ${t('trackers:units.bpm')}`;
    case 'kg': return `${n} ${t('trackers:units.kg')}`;
    case 'lb': return `${n} ${t('trackers:units.lb')}`;
    default: return n;
  }
}

export const MOOD_COLORS = ['#EF4444', '#F97316', '#EAB308', '#22C55E', '#1E40AF'] as const;

export function moodColor(mood: number): string {
  if (mood <= 2) return MOOD_COLORS[0];
  if (mood <= 4) return MOOD_COLORS[1];
  if (mood <= 6) return MOOD_COLORS[2];
  if (mood <= 8) return MOOD_COLORS[3];
  return MOOD_COLORS[4];
}

/** The rule of a comparison as one translated phrase. */
export function ruleLabel(r: CompareResult, tracker: TrackerDescriptor, t: TFunction): string {
  const k = r.rule.kind;
  if (k === 'levels') {
    const levels = tracker.levels ?? [];
    const half = Math.min(2, Math.floor(levels.length / 2));
    const top = levels.slice(-half).map((l) => levelLabel(tracker, l, t)).join(', ');
    const bottom = levels.slice(0, half).map((l) => levelLabel(tracker, l, t)).join(', ');
    return t('stats:wellness.effects.rule.levels', { top, bottom });
  }
  if (k === 'tag') return t('stats:wellness.effects.rule.tag', { tag: levelLabel(tracker, r.tag ?? '', t) });
  const threshold = r.rule.threshold === undefined ? '' : formatValue(tracker, r.rule.threshold, t, 1);
  return t(`stats:wellness.effects.rule.${k}`, { threshold });
}

/** The name a comparison row shows: the tracker, or the tag of a set row. */
export function rowName(r: CompareResult, tracker: TrackerDescriptor, t: TFunction): string {
  return r.tag ? levelLabel(tracker, r.tag, t) : trackerName(tracker, t);
}

/** The insight sentence of a qualifying comparison, in the language on screen. */
export function compareSentence(r: CompareResult, tracker: TrackerDescriptor, outcome: TrackerDescriptor, t: TFunction): string {
  const key = `stats:wellness.insights.${r.rule.kind}${r.lag === 1 ? 'NextDay' : ''}`;
  const levels = tracker.levels ?? [];
  const half = Math.min(2, Math.floor(levels.length / 2));
  return t(key, {
    outcome: trackerName(outcome, t).toLowerCase(),
    name: trackerName(tracker, t),
    tag: r.tag ? levelLabel(tracker, r.tag, t).toLowerCase() : '',
    a: formatNumber(r.a.mean ?? 0, 1),
    b: formatNumber(r.b.mean ?? 0, 1),
    threshold: r.rule.threshold === undefined ? '' : formatValue(tracker, r.rule.threshold, t, 1),
    top: levels.slice(-half).map((l) => levelLabel(tracker, l, t)).join(', ').toLowerCase(),
    bottom: levels.slice(0, half).map((l) => levelLabel(tracker, l, t)).join(', ').toLowerCase(),
  });
}

/** Mood days per side of a dose event, from the entries, bounded by the range and the deletion. */
const DOSE_LENS_DAYS = 14;

export interface DoseLens {
  medicationId: string;
  name: string;
  dosage: string;
  date: string;
  before: { n: number; mean: number | null };
  after: { n: number; mean: number | null };
}

/**
 * The dose lens: for the start and every dose change of a medication inside
 * the range, the mood average of the two weeks before and after, each side
 * cut at the range, at the day before the next change, and at the deletion.
 * Spec: ops/docs/plans/wellness-statistics.md (section 10)
 */
export function doseLenses(entries: JournalEntry[], medications: MedicationTemplate[], range: RangeBounds): DoseLens[] {
  const out: DoseLens[] = [];
  const shift = (date: string, days: number) => {
    const d = new Date(`${date}T12:00:00`);
    d.setDate(d.getDate() + days);
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
  };
  const moods = (from: string, to: string) => {
    const xs = entries.filter((e) => e.date >= from && e.date <= to && e.data.mood != null).map((e) => e.data.mood!);
    return { n: xs.length, mean: xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null };
  };
  for (const m of medications) {
    const events = m.dosageHistory.length ? m.dosageHistory : m.startedAt ? [{ dosage: m.dosage, changedAt: m.startedAt }] : [];
    // The local day of the delete: the UTC date can be a day off either way.
    const until = m.deletedAt ? toLocalIso(new Date(m.deletedAt)) : range.to;
    events.forEach((ev, i) => {
      if (ev.changedAt < range.from || ev.changedAt > range.to) return;
      const next = events[i + 1]?.changedAt;
      const beforeFrom = shift(ev.changedAt, -DOSE_LENS_DAYS) < range.from ? range.from : shift(ev.changedAt, -DOSE_LENS_DAYS);
      const afterToRaw = shift(ev.changedAt, DOSE_LENS_DAYS - 1);
      let afterTo = afterToRaw > until ? until : afterToRaw;
      if (next && shift(next, -1) < afterTo) afterTo = shift(next, -1);
      out.push({
        medicationId: m.id,
        name: m.name,
        dosage: ev.dosage,
        date: ev.changedAt,
        before: moods(beforeFrom, shift(ev.changedAt, -1)),
        after: moods(ev.changedAt, afterTo),
      });
    });
  }
  return out;
}


/** A signed difference, with no sign on a difference that rounds to zero. */
export function formatDelta(delta: number, digits = 1): string {
  const rounded = Math.round(Math.abs(delta) * 10 ** digits) / 10 ** digits;
  if (rounded === 0) return formatNumber(0, digits);
  return `${delta > 0 ? '+' : '-'}${formatNumber(rounded, digits)}`;
}
