/**
 * Mood & wellness tracker types.
 *
 * All tracker data lives inside the encrypted note payload alongside
 * title/body/tags - zero new Supabase tables, zero new sync logic.
 * Medication templates and tracker configuration live in UserSettings.
 *
 * See ops/docs/mood-wellness-tracker.md for the full feature spec.
 */

// ------------------------------------------------------------------
// Emotion tags - 24 fixed tags, clinically validated (PANAS-X, PHQ-9, GAD-7)
// ------------------------------------------------------------------

type EmotionValence = 'positive' | 'neutral' | 'negative';

export interface EmotionTag {
  key: string;
  label: string;
  valence: EmotionValence;
}

export const EMOTION_TAGS: EmotionTag[] = [
  // Positive (10) - Joviality, Serenity, Self-Assurance, Attentiveness, Gratitude
  { key: 'happy', label: 'Happy', valence: 'positive' },
  { key: 'calm', label: 'Calm', valence: 'positive' },
  { key: 'relaxed', label: 'Relaxed', valence: 'positive' },
  { key: 'grateful', label: 'Grateful', valence: 'positive' },
  { key: 'loved', label: 'Loved', valence: 'positive' },
  { key: 'motivated', label: 'Motivated', valence: 'positive' },
  { key: 'confident', label: 'Confident', valence: 'positive' },
  { key: 'productive', label: 'Productive', valence: 'positive' },
  { key: 'focused', label: 'Focused', valence: 'positive' },
  { key: 'energetic', label: 'Energetic', valence: 'positive' },

  // Neutral (5) - Fatigue, Anhedonia, Overwhelm
  { key: 'tired', label: 'Tired', valence: 'neutral' },
  { key: 'restless', label: 'Restless', valence: 'neutral' },
  { key: 'distracted', label: 'Distracted', valence: 'neutral' },
  { key: 'numb', label: 'Numb', valence: 'neutral' },
  { key: 'overwhelmed', label: 'Overwhelmed', valence: 'neutral' },

  // Negative (9) - Fear/Anxiety, Hostility, Sadness, Guilt, Hopelessness
  { key: 'anxious', label: 'Anxious', valence: 'negative' },
  { key: 'stressed', label: 'Stressed', valence: 'negative' },
  { key: 'frustrated', label: 'Frustrated', valence: 'negative' },
  { key: 'irritable', label: 'Irritable', valence: 'negative' },
  { key: 'sad', label: 'Sad', valence: 'negative' },
  { key: 'lonely', label: 'Lonely', valence: 'negative' },
  { key: 'guilty', label: 'Guilty', valence: 'negative' },
  { key: 'hopeless', label: 'Hopeless', valence: 'negative' },
  { key: 'angry', label: 'Angry', valence: 'negative' },
];

// ------------------------------------------------------------------
// Activity levels
// ------------------------------------------------------------------

export const ACTIVITY_LEVELS = [
  'sedentary',
  'light',
  'moderate',
  'active',
  'intense',
] as const;

export type ActivityLevel = (typeof ACTIVITY_LEVELS)[number];

export const ACTIVITY_LABELS: Record<ActivityLevel, string> = {
  sedentary: 'Sedentary',
  light: 'Light',
  moderate: 'Moderate',
  active: 'Active',
  intense: 'Intense',
};

// ------------------------------------------------------------------
// Sleep
// ------------------------------------------------------------------

export const SLEEP_QUALITIES = [
  'terrible',
  'poor',
  'okay',
  'good',
  'great',
] as const;

export type SleepQuality = (typeof SLEEP_QUALITIES)[number];

export const SLEEP_LABELS: Record<SleepQuality, string> = {
  terrible: 'Terrible',
  poor: 'Poor',
  okay: 'Okay',
  good: 'Good',
  great: 'Great',
};

// ------------------------------------------------------------------
// Medication
// ------------------------------------------------------------------

type MedicationTiming = 'morning' | 'afternoon' | 'evening' | 'bedtime';

/** Persistent medication template - lives in UserSettings. */
export interface MedicationTemplate {
  id: string;
  name: string;
  dosage: string;
  timing: MedicationTiming;
  startedAt: string; // ISO date
  dosageHistory: Array<{ dosage: string; changedAt: string }>;
  /**
   * ISO timestamp of the last edit to THIS template. The settings blob
   * carries one timestamp for the whole object, which cannot say which
   * device holds the newer version of one medication - so an
   * active-vs-active collision used to resolve "local wins" with no
   * clock, and a dosage corrected on one device never reached the
   * others. Absent on templates written before this shipped; the merge
   * treats a stamped copy as newer than an unstamped one.
   */
  updatedAt?: string;
  /**
   * Tombstone: ISO timestamp when the user deleted this medication.
   * Undefined/absent means active. Once set, this med is hidden from
   * the UI but kept in the array so union-merge sync never resurrects it.
   */
  deletedAt?: string;
}

/** Filter out tombstoned (soft-deleted) medication templates. */
export function activeMedications(meds: MedicationTemplate[]): MedicationTemplate[] {
  return meds.filter((m) => !m.deletedAt);
}

/** Per-day medication log entry - lives in the journal note payload. */
export type MedicationStatus = 'taken' | 'skipped' | 'missed';

export interface MedicationLogEntry {
  medicationId: string;
  status: MedicationStatus;
}

// ------------------------------------------------------------------
// Custom trackers
// ------------------------------------------------------------------

export type CustomTrackerType = 'scale10' | 'scale5' | 'slider100' | 'number' | 'yesno';

export const CUSTOM_TRACKER_TYPE_LABELS: Record<CustomTrackerType, string> = {
  scale10: 'Scale (0-10)',
  scale5: 'Scale (0-5)',
  slider100: 'Slider (0-100)',
  number: 'Number',
  yesno: 'Yes / No',
};

export const TRACKER_COLORS = [
  '#7F77DD', // purple
  '#1D9E75', // teal
  '#D85A30', // coral
  '#D4537E', // pink
  '#BA7517', // amber
  '#378ADD', // blue
] as const;

export type TrackerColor = (typeof TRACKER_COLORS)[number];

/** Custom tracker template - lives in UserSettings. */
export interface CustomTrackerTemplate {
  id: string;
  name: string;
  type: CustomTrackerType;
  color: TrackerColor;
  createdAt: string; // ISO date
  /** When set, tracker is hidden from new entries but data is preserved. */
  stoppedAt?: string;
  /** Last edit to THIS template - see MedicationTemplate.updatedAt. */
  updatedAt?: string;
  /**
   * Tombstone: ISO timestamp when the user deleted this tracker. Same
   * contract as MedicationTemplate.deletedAt - the row stays in the array
   * so the union merge cannot resurrect it, and so the journal values
   * that reference this id keep resolving to a name.
   */
  deletedAt?: string;
}

/** Filter out tombstoned (deleted) custom trackers. */
export function activeCustomTrackers(
  trackers: CustomTrackerTemplate[]
): CustomTrackerTemplate[] {
  return trackers.filter((t) => !t.deletedAt);
}

/** Per-day custom tracker value - lives in the journal note payload. */
interface CustomTrackerEntry {
  trackerId: string;
  value: number | boolean | string;
}

// ------------------------------------------------------------------
// Built-in tracker IDs
// ------------------------------------------------------------------

export type BuiltinTrackerId =
  | 'mood'
  | 'emotions'
  | 'sleep'
  | 'sleepScore'
  | 'heartRate'
  | 'medication'
  | 'activity'
  | 'energy'
  | 'focus'
  | 'weight'
  | 'steps'
  | 'water'
  | 'screenTime'
  | 'caffeine'
  | 'pain'
  | 'social';

export const BUILTIN_TRACKER_COLORS: Record<BuiltinTrackerId, string> = {
  mood: '#1E40AF',
  emotions: '#1E40AF', // grouped with mood visually
  sleep: '#7F77DD',
  sleepScore: '#534AB7', // deeper purple, complements sleep
  heartRate: '#D4537E', // pink - medical/vitals feel
  medication: '#D85A30',
  activity: '#1D9E75',
  energy: '#BA7517',
  focus: '#378ADD',
  weight: '#6B7280', // neutral gray - body metrics
  steps: '#059669', // green - movement
  water: '#0EA5E9', // sky blue - hydration
  screenTime: '#8B5CF6', // violet - digital
  caffeine: '#92400E', // brown - coffee
  pain: '#DC2626', // red - alert/pain
  social: '#EC4899', // pink - social/people
};

// ------------------------------------------------------------------
// Weight units
// ------------------------------------------------------------------

export const WEIGHT_UNITS = ['kg', 'lb'] as const;

export type WeightUnit = (typeof WEIGHT_UNITS)[number];

/** The pound is defined as exactly 0.45359237 kg. */
const KG_PER_LB = 0.45359237;

/**
 * Countries whose everyday body weight is quoted in pounds. Read from the
 * browser's region rather than the app language, because the language a
 * person reads in says nothing about the scale they own.
 */
const POUND_REGIONS = new Set(['US', 'LR', 'MM']);

function defaultWeightUnit(): WeightUnit {
  if (typeof navigator === 'undefined') return 'kg';
  const region = new Intl.Locale(navigator.language || 'en').region;
  return region && POUND_REGIONS.has(region) ? 'lb' : 'kg';
}

/** The range a person can weigh, in kilograms. */
const WEIGHT_RANGE_KG = { min: 20, max: 300 } as const;

/**
 * The input bounds for one unit. The pound bounds round outward from the
 * kilogram ones, so the heaviest storable value still sits inside the
 * field after a unit switch.
 */
export function weightRange(unit: WeightUnit): { min: number; max: number } {
  if (unit === 'kg') return WEIGHT_RANGE_KG;
  return {
    min: Math.floor(WEIGHT_RANGE_KG.min / KG_PER_LB),
    max: Math.ceil(WEIGHT_RANGE_KG.max / KG_PER_LB),
  };
}

/** The stored kilograms as the number to show in `unit`, at one decimal. */
export function weightToDisplay(kg: number, unit: WeightUnit): number {
  const shown = unit === 'kg' ? kg : kg / KG_PER_LB;
  return Number(shown.toFixed(1));
}

/**
 * A number the user typed in `unit`, as the kilograms to store. Three
 * decimals of a kilogram is 0.002 lb, far below the 0.05 lb that would
 * move a one-decimal reading, so a value survives any number of unit
 * switches unchanged.
 */
export function weightToCanonical(value: number, unit: WeightUnit): number {
  const kg = unit === 'kg' ? value : value * KG_PER_LB;
  return Number(kg.toFixed(3));
}

// ------------------------------------------------------------------
// Journal tracker data - the per-entry payload
// ------------------------------------------------------------------

/** Stored inside the encrypted note payload alongside title/body/tags. */
export interface JournalTrackerData {
  mood?: number; // 1-10
  emotions?: string[]; // keys from EMOTION_TAGS
  sleep?: {
    quality: SleepQuality;
    hours?: number;
  };
  medications?: MedicationLogEntry[];
  activity?: ActivityLevel;
  sleepScore?: number; // 0-100 (Apple Watch, Fitbit, etc.)
  heartRate?: number; // average resting BPM
  energy?: number; // 0-10
  focus?: number; // 0-10
  /** Kilograms, always. `trackerSettings.weightUnit` picks the unit the
   *  app shows it in, and every reader converts on the way out. */
  weight?: number;
  steps?: number; // daily step count
  water?: number; // glasses (0-10)
  screenTime?: number; // hours
  caffeine?: number; // cups (0-5)
  pain?: number; // 0-10 scale
  social?: number; // 0-5 scale
  customTrackers?: CustomTrackerEntry[];
  /** The calendar day this entry is FOR, as a local ISO date
   *  (`YYYY-MM-DD`) - not the day it was typed, which is `createdAt`.
   *  The two differ whenever a past day is backfilled. Stamped on every
   *  entry the app creates; absent only on entries that predate the
   *  field. Read it through `journalDateOf()` in notesViewUtils.
   *  Spec: ops/docs/design-decisions.md (journal entry titles) */
  journalDate?: string;
  backfilled?: boolean;
  /** Weekly reflection text (stored on the Monday entry). */
  weekReflection?: string;
}

// ------------------------------------------------------------------
// Merging two devices' tracker payloads
// ------------------------------------------------------------------

/** Arrays inside `trackers` whose elements carry their own identity, and
 *  the field that identifies one. Each element is an independent fact the
 *  user recorded ("I took the morning pill"), so two devices that each
 *  recorded a different one must end up with both. */
const KEYED_TRACKER_ARRAYS: Record<string, string> = {
  medications: 'medicationId',
  customTrackers: 'trackerId',
};

function unionById(
  local: unknown,
  remote: unknown,
  idField: string
): unknown[] | undefined {
  if (!Array.isArray(local)) return Array.isArray(remote) ? remote : undefined;
  if (!Array.isArray(remote)) return local;
  const map = new Map<unknown, unknown>();
  // Remote first, then local: a device that logged a status for the same
  // item overwrites, matching the local-wins rule for every other key.
  for (const item of [...remote, ...local]) {
    const id = (item as Record<string, unknown> | null)?.[idField];
    if (id === undefined || id === null) continue;
    map.set(id, item);
  }
  return [...map.values()];
}

/**
 * Merge two devices' views of one journal entry's tracker payload.
 *
 * Sync sees a pill tap as a metadata-only change: the body and title are
 * untouched, so the whole `trackers` object used to be handed to the
 * local side wholesale. Two devices logging two different medications on
 * the same day therefore destroyed one of the logs silently - no conflict
 * modal, no error, a green tick on both. That is the medication-loss
 * report, and this function is the fix.
 *
 * Rules, in order of how much they protect:
 * - A key only one side set survives from that side. Nothing is dropped
 *   because the other device had not heard of it yet.
 * - `medications` and `customTrackers` union by their own id. Two
 *   different entries both survive; the same entry resolves local-wins.
 * - `emotions` unions as a set. A tag re-appearing is one tap to undo; a
 *   tag vanishing is invisible.
 * - Every other key resolves local-wins, unchanged from before: without a
 *   common base there is no way to tell which side moved a scalar, and
 *   local is the more recent intent on this device.
 */
export function mergeTrackers(
  local: Record<string, unknown> | undefined,
  remote: Record<string, unknown> | undefined
): Record<string, unknown> | undefined {
  if (!local) return remote;
  if (!remote) return local;
  const merged: Record<string, unknown> = { ...remote, ...local };
  for (const [key, idField] of Object.entries(KEYED_TRACKER_ARRAYS)) {
    const union = unionById(local[key], remote[key], idField);
    if (union !== undefined) merged[key] = union;
  }
  if (Array.isArray(local.emotions) || Array.isArray(remote.emotions)) {
    const l = Array.isArray(local.emotions) ? local.emotions : [];
    const r = Array.isArray(remote.emotions) ? remote.emotions : [];
    merged.emotions = [...new Set([...r, ...l])];
  }
  return merged;
}

/** Stable stringify so key order never reads as a difference. */
function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(',')}}`;
}

/** Whether two tracker payloads hold the same data, key order aside. */
export function trackersEqual(
  a: Record<string, unknown> | undefined,
  b: Record<string, unknown> | undefined
): boolean {
  return canonical(a ?? {}) === canonical(b ?? {});
}

// ------------------------------------------------------------------
// Mood anchors (for the 1-10 scale UI)
// ------------------------------------------------------------------

export const MOOD_ANCHORS: Record<number, string> = {
  1: 'awful',
  3: 'rough',
  5: 'okay',
  7: 'good',
  10: 'amazing',
};

// ------------------------------------------------------------------
// Tracker settings - which trackers are enabled
// ------------------------------------------------------------------

export interface TrackerSettings {
  activeBuiltins: BuiltinTrackerId[];
  customTrackers: CustomTrackerTemplate[];
  archivedMedications: MedicationTemplate[];
  /** The unit the weight tracker reads and writes in. The stored value is
   *  kilograms whichever way this is set, so switching it re-renders the
   *  history rather than reinterpreting it. */
  weightUnit: WeightUnit;
}

export function defaultTrackerSettings(): TrackerSettings {
  return {
    // sleepScore and heartRate available but off by default - users enable in config.
    activeBuiltins: ['mood', 'emotions', 'sleep', 'activity', 'medication', 'energy', 'focus'],
    customTrackers: [],
    archivedMedications: [],
    weightUnit: defaultWeightUnit(),
  };
}
