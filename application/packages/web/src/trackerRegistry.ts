import { askedHabits, customHabitsNow, type HabitQuestion } from './habitList';
import { adherenceOn, asNeededOn, logsOf, medicationDayStatus } from './medicationDoses';
import {
  ACTIVITY_LEVELS,
  BUILTIN_TRACKER_COLORS,
  EMOTION_TAGS,
  SLEEP_QUALITIES,
  customTrackerColor,
  caffeineToDisplay,
  waterToDisplay,
  weightToDisplay,
  type CustomTrackerTemplate,
  type FactorDef,
  type JournalTrackerData,
  type MedicationTemplate,
  type TrackerSettings,
} from './trackerTypes';
import type { JournalEntry } from './trackerStats';
import type { TrackerDescriptor, TrackerValue } from './wellnessTypes';

/**
 * One descriptor per tracker a value can belong to: the built-ins, every
 * custom template (stopped and deleted included, so an old value always
 * resolves to a name), and every medication template. The engine never
 * filters; the UI does, through `visibleInUi`.
 * Spec: ops/docs/archive/wellness-statistics.md (section 4)
 */

type NumericField =
  | 'mood' | 'energy' | 'focus' | 'pain' | 'social' | 'sleepScore' | 'heartRate'
  | 'steps' | 'water' | 'screenTime' | 'caffeine';

function num(v: unknown): number | undefined {
  return typeof v === 'number' && Number.isFinite(v) ? v : undefined;
}

function field(key: NumericField) {
  return (d: JournalTrackerData) => num(d[key]);
}

function scale(id: NumericField, min: number, max: number, unit?: TrackerDescriptor['unit']): TrackerDescriptor {
  return {
    id, source: 'builtin', labelKey: `trackers:labels.${id}`, color: BUILTIN_TRACKER_COLORS[id],
    kind: 'scale', min, max, unit, aggregate: 'avg', read: field(id),
  };
}

function measure(id: NumericField, unit: TrackerDescriptor['unit']): TrackerDescriptor {
  return {
    id, source: 'builtin', labelKey: `trackers:labels.${id}`, color: BUILTIN_TRACKER_COLORS[id],
    kind: 'measure', unit, aggregate: 'avg', read: field(id),
  };
}

/** The Factors set: the person's own tags, deleted ones included, so a day
 *  that holds one keeps its name in the charts. */
function factorsDescriptor(factors: FactorDef[]): TrackerDescriptor {
  const known = new Set(factors.map((f) => f.id));
  return {
    id: 'factors', source: 'builtin', labelKey: 'trackers:labels.factors',
    color: BUILTIN_TRACKER_COLORS.factors, kind: 'set', aggregate: 'share',
    levels: factors.map((f) => f.id),
    levelNames: Object.fromEntries(factors.map((f) => [f.id, f.name])),
    read: (d) => {
      const ids = Array.isArray(d.factors) ? d.factors.filter((id) => known.has(id)) : [];
      return ids.length > 0 ? ids : undefined;
    },
  };
}

/** One yes or no tracker per Habits question that is on, so Patterns and
 *  Explore show the mood with and without each one. The id is prefixed, so
 *  it never meets a built-in or a custom id. */
function habitDescriptor(q: HabitQuestion): TrackerDescriptor {
  const id = q.id;
  return {
    id: `habit-${id}`, source: 'builtin',
    // A person's own habit carries its name; a built-in one its catalog key.
    ...(q.custom ? { name: q.label } : { labelKey: `trackers:habits.short.${id}` }),
    color: BUILTIN_TRACKER_COLORS.habits, kind: 'yesno', aggregate: 'share',
    read: (d) => {
      const v = d.habits?.[id];
      return typeof v === 'boolean' ? v : undefined;
    },
  };
}

function builtins(settings: TrackerSettings, factors: FactorDef[]): Record<string, TrackerDescriptor[]> {
  const unit = settings.weightUnit;
  const waterUnit = settings.waterUnit;
  const caffeineUnit = settings.caffeineUnit;
  return {
    mood: [scale('mood', 1, 10)],
    emotions: [{
      id: 'emotions', source: 'builtin', labelKey: 'trackers:labels.emotions',
      color: BUILTIN_TRACKER_COLORS.emotions, kind: 'set', aggregate: 'share',
      levels: EMOTION_TAGS.map((e) => e.key),
      read: (d) => (Array.isArray(d.emotions) && d.emotions.length > 0 ? d.emotions : undefined),
    }],
    factors: [factorsDescriptor(factors)],
    habits: askedHabits(settings.habits, customHabitsNow()).map(habitDescriptor),
    focus: [scale('focus', 0, 10)],
    pain: [scale('pain', 0, 10)],
    social: [scale('social', 0, 5)],
    sleep: [
      {
        id: 'sleepHours', source: 'builtin', labelKey: 'stats:wellness.trackers.sleepHours',
        color: BUILTIN_TRACKER_COLORS.sleep, kind: 'measure', unit: 'h', aggregate: 'avg',
        read: (d) => num(d.sleep?.hours),
      },
      {
        id: 'sleepQuality', source: 'builtin', labelKey: 'stats:wellness.trackers.sleepQuality',
        color: BUILTIN_TRACKER_COLORS.sleep, kind: 'ordinal', levels: SLEEP_QUALITIES, aggregate: 'share',
        read: (d) => d.sleep?.quality,
      },
    ],
    sleepScore: [scale('sleepScore', 0, 100)],
    heartRate: [measure('heartRate', 'bpm')],
    activity: [{
      id: 'activity', source: 'builtin', labelKey: 'trackers:labels.activity',
      color: BUILTIN_TRACKER_COLORS.activity, kind: 'ordinal', levels: ACTIVITY_LEVELS,
      aggregate: 'share', read: (d) => d.activity,
    }],
    weight: [{
      id: 'weight', source: 'builtin', labelKey: 'trackers:labels.weight',
      color: BUILTIN_TRACKER_COLORS.weight, kind: 'measure', unit, aggregate: 'avg',
      read: (d) => {
        const kg = num(d.weight);
        return kg === undefined ? undefined : weightToDisplay(kg, unit);
      },
    }],
    energy: [scale('energy', 0, 10)],
    steps: [measure('steps', 'steps')],
    water: [{
      id: 'water', source: 'builtin', labelKey: 'trackers:labels.water',
      color: BUILTIN_TRACKER_COLORS.water, kind: 'measure', unit: waterUnit, aggregate: 'avg',
      read: (d) => {
        const glasses = num(d.water);
        return glasses === undefined ? undefined : waterToDisplay(glasses, waterUnit);
      },
    }],
    caffeine: [{
      id: 'caffeine', source: 'builtin', labelKey: 'trackers:labels.caffeine',
      color: BUILTIN_TRACKER_COLORS.caffeine, kind: 'measure', unit: caffeineUnit, aggregate: 'avg',
      read: (d) => {
        const cups = num(d.caffeine);
        return cups === undefined ? undefined : caffeineToDisplay(cups, caffeineUnit);
      },
    }],
    screenTime: [measure('screenTime', 'h')],
  };
}

/** The built-in order of the tracker settings dialog; medication is listed per template, last. */
const BUILTIN_ORDER = [
  'mood', 'emotions', 'factors', 'focus', 'pain', 'social',
  'sleep', 'sleepScore', 'heartRate', 'activity', 'weight',
  'habits', 'energy', 'steps', 'water', 'caffeine', 'screenTime',
] as const;

const CUSTOM_RANGE: Partial<Record<CustomTrackerTemplate['type'], [number, number]>> = {
  scale10: [0, 10],
  scale5: [0, 5],
  slider100: [0, 100],
};

function customValue(d: JournalTrackerData, id: string): unknown {
  return d.customTrackers?.find((c) => c.trackerId === id)?.value;
}

function customDescriptor(t: CustomTrackerTemplate): TrackerDescriptor {
  const base = {
    id: t.id, source: 'custom' as const, name: t.name, color: customTrackerColor(t),
    stoppedAt: t.stoppedAt, deletedAt: t.deletedAt,
  };
  if (t.type === 'yesno') {
    return {
      ...base, kind: 'yesno', aggregate: 'share',
      read: (d) => {
        const v = customValue(d, t.id);
        return typeof v === 'boolean' ? v : undefined;
      },
    };
  }
  const range = CUSTOM_RANGE[t.type];
  return {
    ...base,
    kind: range ? 'scale' : 'measure',
    min: range?.[0],
    max: range?.[1],
    // A free number is a count the person adds up (glasses, pages, euros).
    aggregate: range ? 'avg' : 'sum',
    read: (d) => num(customValue(d, t.id)),
  };
}

function medicationDescriptor(m: MedicationTemplate): TrackerDescriptor {
  return {
    id: m.id, source: 'medication', name: m.name, color: BUILTIN_TRACKER_COLORS.medication,
    kind: 'medication', aggregate: 'share', deletedAt: m.deletedAt,
    // One status for the day over all its doses (section 6.7); the day comes
    // from the entry's own stamp, absent only on entries that predate it.
    read: (d) => medicationDayStatus(m, d.medications, typeof d.journalDate === 'string' ? d.journalDate : undefined),
    doses: (d, day) => {
      const owed = adherenceOn(m, d.medications, day);
      const asNeeded = asNeededOn(m, day) ? logsOf(d.medications, m.id).filter((l) => l.status === 'taken').length : 0;
      return { ...owed, asNeeded };
    },
  };
}

/** A value whose template is gone from the settings: listed and charted, never compared. */
function unknownDescriptor(id: string): TrackerDescriptor {
  return {
    id, source: 'custom', name: `Unknown tracker ${id.slice(0, 8)}`,
    color: BUILTIN_TRACKER_COLORS.weight, kind: 'measure', aggregate: 'avg', unknown: true,
    read: (d) => customValue(d, id) as TrackerValue | undefined,
  };
}

export function buildRegistry(
  settings: TrackerSettings,
  medications: MedicationTemplate[],
  entries?: JournalEntry[],
  factors: FactorDef[] = [],
): TrackerDescriptor[] {
  const table = builtins(settings, factors);
  const out: TrackerDescriptor[] = BUILTIN_ORDER.flatMap((id) => table[id] ?? []);
  const customs = [...settings.customTrackers].sort((a, b) =>
    a.createdAt < b.createdAt ? -1 : a.createdAt > b.createdAt ? 1 : 0,
  );
  out.push(...customs.map(customDescriptor));
  if (entries) {
    const known = new Set(settings.customTrackers.map((t) => t.id));
    for (const e of entries) {
      for (const c of e.data.customTrackers ?? []) {
        if (known.has(c.trackerId)) continue;
        known.add(c.trackerId);
        out.push(unknownDescriptor(c.trackerId));
      }
    }
  }
  out.push(...medications.map(medicationDescriptor));
  return out;
}

/** Whether a descriptor gets a card and a chip without the "Stopped" reveal. */
export function visibleInUi(d: TrackerDescriptor): boolean {
  return !d.deletedAt && !d.stoppedAt;
}
