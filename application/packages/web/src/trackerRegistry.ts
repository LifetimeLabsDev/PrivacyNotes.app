import {
  ACTIVITY_LEVELS,
  BUILTIN_TRACKER_COLORS,
  EMOTION_TAGS,
  SLEEP_QUALITIES,
  customTrackerColor,
  weightToDisplay,
  type CustomTrackerTemplate,
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
 * Spec: ops/docs/plans/wellness-statistics.md (section 4)
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

function builtins(settings: TrackerSettings): Record<string, TrackerDescriptor[]> {
  const unit = settings.weightUnit;
  return {
    mood: [scale('mood', 1, 10)],
    emotions: [{
      id: 'emotions', source: 'builtin', labelKey: 'trackers:labels.emotions',
      color: BUILTIN_TRACKER_COLORS.emotions, kind: 'set', aggregate: 'share',
      levels: EMOTION_TAGS.map((e) => e.key),
      read: (d) => (Array.isArray(d.emotions) && d.emotions.length > 0 ? d.emotions : undefined),
    }],
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
    water: [scale('water', 0, 10, 'glasses')],
    caffeine: [scale('caffeine', 0, 5, 'cups')],
    screenTime: [measure('screenTime', 'h')],
  };
}

/** The built-in order of the tracker settings dialog; medication is listed per template, last. */
const BUILTIN_ORDER = [
  'mood', 'emotions', 'focus', 'pain', 'social',
  'sleep', 'sleepScore', 'heartRate', 'activity', 'weight',
  'energy', 'steps', 'water', 'caffeine', 'screenTime',
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
    read: (d) => d.medications?.find((x) => x.medicationId === m.id)?.status,
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
): TrackerDescriptor[] {
  const table = builtins(settings);
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
