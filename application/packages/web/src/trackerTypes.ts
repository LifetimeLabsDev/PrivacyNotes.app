/**
 * Mood & wellness tracker types.
 *
 * All tracker data lives inside the encrypted note payload alongside
 * title/body/tags - zero new Supabase tables, zero new sync logic.
 * Medication templates and tracker configuration live in UserSettings.
 *
 * See ops/docs/mood-wellness-tracker.md for the full feature spec.
 */

import { PALETTE, TEXT_COLORS } from './editorColors';
import { mergeLoginExtras } from './loginExtras';
import { CLIP_SOURCE_KEY, SCHEDULE_KEYS, SOURCE_IDENTITY_KEY, type Repeat } from './schedule';

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

/** How a medication is taken; it names the unit of a dose and of the supply. */
export const MEDICATION_FORMS = ['tablet', 'capsule', 'liquid', 'injection', 'inhaler', 'patch', 'drops', 'other'] as const;
export type MedicationForm = (typeof MEDICATION_FORMS)[number];

/** One scheduled dose of a day. `id` is stable across edits of its time:
 *  the day's log points at it. The first dose of every medication is `main`
 *  and logs under the bare template id. */
export interface MedicationDose {
  id: string;
  /** `HH:MM`. Without one the dose has no reminder. */
  time?: string;
  amount: number;
}

/** One revision of a medication's schedule: the whole schedule as it held
 *  from `changedAt` (a local ISO day) on, so a past day keeps its own doses,
 *  times and amounts. Revisions union by `id` in the settings merge, and the
 *  template's schedule fields are always the newest revision (by `changedAt`,
 *  then `editedAt`), so a stale rename or refill on another device can never
 *  bring an old schedule back. */
export interface MedicationScheduleEntry {
  id: string;
  changedAt: string;
  /** ISO instant of the edit; breaks a tie between two revisions of one day. */
  editedAt: string;
  asNeeded?: boolean;
  maxPerDay?: number;
  repeat?: Repeat;
  doses: MedicationDose[];
  endsOn?: string;
}

/** A supply count, set at `at` (an ISO instant). */
interface MedicationRefill {
  id: string;
  at: string;
  count: number;
}

/** Persistent medication template - lives in UserSettings.
 *  Every field after `dosageHistory` is optional: absent means the behavior
 *  before it existed (every day, one dose, no time), which is also what an
 *  older client's template reads as. Spec: ops/docs/mood-wellness-tracker.md section 6.7 */
export interface MedicationTemplate {
  id: string;
  name: string;
  /** Shown as Strength ("50 mg"). */
  dosage: string;
  /** Never read; older clients still write it. */
  timing: MedicationTiming;
  startedAt: string; // ISO date
  dosageHistory: Array<{ dosage: string; changedAt: string }>;
  form?: MedicationForm;
  color?: TrackerColor;
  asNeeded?: boolean;
  /** As needed only: the most doses a day, 1 to 24. */
  maxPerDay?: number;
  /** Every N days or on weekdays, counted from `startedAt`. Absent: every day. */
  repeat?: Repeat;
  doses?: MedicationDose[];
  /** The last day it is taken (local ISO day). */
  endsOn?: string;
  /** Unioned by id in the settings merge; the schedule fields above are
   *  always its newest revision. Every client that knows schedules writes at
   *  least one, so a template without any was last written by an older one. */
  scheduleHistory?: MedicationScheduleEntry[];
  /** Unioned by id in the settings merge. Supply is computed from these. */
  refills?: MedicationRefill[];
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

/** Why a dose was skipped; optional, set from the chips under a skip. */
export const SKIP_REASONS = ['forgot', 'ranOut', 'sideEffects', 'doctor', 'other'] as const;
export type SkipReason = (typeof SKIP_REASONS)[number];

export interface MedicationLogEntry {
  /** The template id for its first dose; `<templateId>~<doseId>` for any
   *  other dose, so the union by this field keeps every dose in every
   *  client ever shipped. Parse with `logMedicationId` (medicationDoses.ts). */
  medicationId: string;
  status: MedicationStatus;
  /** `HH:MM`, when a Taken tap happened on the entry's own day. */
  at?: string;
  /** On a skip only. */
  reason?: SkipReason;
  /** ISO instant of the tap. Two stamped copies of one dose resolve to the
   *  newer; an unstamped one (an older client) keeps the local-wins rule. */
  ts?: string;
}

// ------------------------------------------------------------------
// Custom trackers
// ------------------------------------------------------------------

export type CustomTrackerType = 'scale10' | 'scale5' | 'slider100' | 'number' | 'yesno';

export const CUSTOM_TRACKER_TYPE_LABELS: Record<CustomTrackerType, string> = {
  scale10: 'Scale (0-10)',
  scale5: 'Scale (0-5)',
  slider100: 'Score (0-100)',
  number: 'Number',
  yesno: 'Yes / No',
};

/**
 * The colors a custom tracker can take: the editor's text colors, the one
 * palette of the app (gray, red, orange, yellow, green, teal, blue, purple,
 * pink), in the same order. They are made to read as text in every theme, so
 * no surface puts white text on them.
 * Spec: ops/docs/archive/ui-patterns.md section 141
 */
export const TRACKER_COLORS: readonly string[] = TEXT_COLORS.map((c) => c.value);

export type TrackerColor = string;

// The colors custom trackers took before they used the editor palette. A
// custom tracker stores its color, so one saved with them paints the
// palette color of the same hue.
const LEGACY_TRACKER_COLORS: Record<string, string> = {
  '#716AC5': '#7048e8', '#7F77DD': '#7048e8', // purple
  '#188562': '#0c8599', '#1D9E75': '#0c8599', // teal
  '#C2512B': '#e8590c', '#D85A30': '#e8590c', // coral, now orange
  '#C14C73': '#c2255c', '#D4537E': '#c2255c', // pink
  '#A46714': '#f08c00', '#BA7517': '#f08c00', // amber, now yellow
  '#2F77BE': '#1971c2', '#378ADD': '#1971c2', // blue
};

/** The color a custom tracker paints with. */
export function customTrackerColor(t: Pick<CustomTrackerTemplate, 'color'>): string {
  return LEGACY_TRACKER_COLORS[t.color] ?? t.color;
}

/** Custom tracker template - lives in UserSettings. */
export interface CustomTrackerTemplate {
  id: string;
  name: string;
  type: CustomTrackerType;
  color: TrackerColor;
  createdAt: string; // ISO date
  /** When set, tracker is hidden from new entries but data is preserved. */
  stoppedAt?: string;
  /**
   * False: an empty Number or Score panel starts blank instead of at the last
   * value logged. Absent means on, so trackers made before the switch keep
   * the behavior they had. The scales and yes or no ignore it.
   */
  startFromLast?: boolean;
  /** A look icon id (`looks/lookIcons.ts`), picked in the setup. Absent: the
   *  color dot marks the tracker, as before icons. */
  icon?: string;
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

/**
 * One factor of the person's own list: something that was part of a day.
 * Lives in the settings blob as a top-level list, never inside
 * `trackerSettings`, whose fields an older app rebuilds from a fixed list.
 * Merged by id with stamps and tombstones, like the custom trackers.
 * Spec: ops/issues/0439.md (Spec)
 */
export interface FactorDef {
  id: string;
  name: string;
  /** A group name from an import (Daylio's activity groups); not shown yet. */
  group?: string;
  createdAt: string;
  updatedAt?: string;
  deletedAt?: string;
}

/** One empty list, so a prop default keeps its identity across renders. */
export const NO_FACTORS: FactorDef[] = [];

/** The longest factor name, and the most factors a list holds. */
export const FACTOR_NAME_MAX = 40;
export const FACTORS_MAX = 200;

/** A factor name as it is stored: control characters out, spaces folded,
 *  cut to the cap. Empty when nothing usable is left. */
export function cleanFactorName(raw: string): string {
  // eslint-disable-next-line no-control-regex
  return raw.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, FACTOR_NAME_MAX);
}

/** The factors a picker offers: live ones, in the order they were made. */
export function activeFactors(list: FactorDef[]): FactorDef[] {
  return list.filter((f) => !f.deletedAt);
}

/** Read a stored factor list, dropping rows that are not factors. */
export function readFactors(raw: unknown): FactorDef[] {
  if (!Array.isArray(raw)) return [];
  const out: FactorDef[] = [];
  const seen = new Set<string>();
  for (const r of raw) {
    if (!r || typeof r !== 'object') continue;
    const f = r as Record<string, unknown>;
    if (typeof f.id !== 'string' || !f.id || seen.has(f.id) || typeof f.name !== 'string') continue;
    const name = cleanFactorName(f.name);
    if (!name) continue;
    seen.add(f.id);
    out.push({
      id: f.id,
      name,
      ...(typeof f.group === 'string' && f.group.trim() ? { group: cleanFactorName(f.group) } : {}),
      createdAt: typeof f.createdAt === 'string' ? f.createdAt : new Date(0).toISOString(),
      ...(typeof f.updatedAt === 'string' ? { updatedAt: f.updatedAt } : {}),
      ...(typeof f.deletedAt === 'string' ? { deletedAt: f.deletedAt } : {}),
    });
    if (out.length >= FACTORS_MAX * 2) break;
  }
  return out;
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
// Habits - built-in yes or no questions
// ------------------------------------------------------------------

/**
 * The questions the free Habits tracker can ask, in the order the panel asks
 * them. The ids are fixed and the names come from the catalog
 * (`trackers:habits.q.<id>`), so every locale asks the same question and a
 * stored answer never loses its name. A question is something the person
 * does; what happens to a day is a factor, and nothing here repeats a tracker
 * (exercise is Activity, friends is Social). The habits to build come first,
 * the habits to watch (`WATCH_HABITS`) last. A question the set lacks is a
 * custom yes or no tracker.
 * Spec: ops/docs/plans/mood-tracking-landscape.md (proposal 1)
 */
export const HABIT_IDS = [
  'meditate',
  'pray',
  'gratitude',
  'meTime',
  'read',
  'learn',
  'creative',
  'outside',
  'stretch',
  'nap',
  'eatWell',
  'cook',
  'tidy',
  'smoke',
  'alcohol',
  'cannabis',
  'drugs',
  'porn',
  'gambling',
  'impulseBuy',
  'gaming',
  'doomscroll',
] as const;

export type HabitId = (typeof HABIT_IDS)[number];

/**
 * The habits to watch: off until the person turns one on, and never named
 * outside the panel, the setup and the statistics. The folded check-in line
 * and the check-in row are read over a shoulder, so they show these as part
 * of a count only.
 */
export const WATCH_HABITS: ReadonlySet<HabitId> = new Set<HabitId>([
  'smoke', 'alcohol', 'cannabis', 'drugs', 'porn', 'gambling', 'impulseBuy', 'gaming', 'doomscroll',
]);

/** The questions on before any were picked: four habits to build. The panel
 *  links to the setup, where the person turns on the rest. */
const DEFAULT_HABITS: readonly HabitId[] = ['meditate', 'gratitude', 'read', 'outside'];

/** Read a stored question list: known ids only, each once, in the asked order. */
export function readHabits(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [...DEFAULT_HABITS];
  const set = new Set(raw.filter((id): id is HabitId => (HABIT_IDS as readonly string[]).includes(id as string)));
  // An id this build does not know (a person's own habit from a newer app)
  // is kept after the built-in ones, so saving the settings here never
  // switches it off on the devices that know it. Nothing here reads it.
  const unknown = raw.filter((id): id is string => typeof id === 'string' && id.length > 0 && id.length <= 64 && !(HABIT_IDS as readonly string[]).includes(id));
  return [...HABIT_IDS.filter((id) => set.has(id)), ...new Set(unknown)];
}

/** The answers of one day, question id to yes or no. */
export type HabitAnswers = Partial<Record<string, boolean>>;


// ------------------------------------------------------------------
// Built-in tracker IDs
// ------------------------------------------------------------------

export type BuiltinTrackerId =
  | 'mood'
  | 'emotions'
  | 'factors'
  | 'habits'
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

/** The built-in trackers' colors, on the charts and the setup chips: the
 *  palette of the app (`PALETTE`, the editor's text colors) and nothing
 *  else. Eighteen trackers share nine hues; a chart shows one at a time. */
export const BUILTIN_TRACKER_COLORS: Record<BuiltinTrackerId, string> = {
  mood: PALETTE.blue,
  emotions: PALETTE.purple,
  factors: PALETTE.teal,
  habits: PALETTE.green,
  sleep: PALETTE.purple,
  sleepScore: PALETTE.purple,
  heartRate: PALETTE.pink,
  medication: PALETTE.orange,
  activity: PALETTE.green,
  energy: PALETTE.yellow,
  focus: PALETTE.blue,
  weight: PALETTE.gray,
  steps: PALETTE.green,
  water: PALETTE.teal,
  screenTime: PALETTE.purple,
  caffeine: PALETTE.orange,
  pain: PALETTE.red,
  social: PALETTE.pink,
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
  // The platform decides what `navigator.language` says, and nothing
  // requires it to be a tag Intl accepts. A Linux box whose system locale
  // is `C`, or one that reports the POSIX underscore form `en_US`, hands
  // over exactly that string, and the constructor answers with a
  // RangeError rather than an empty region. This runs while the first
  // screen is being built, so the throw reaches React before anything is
  // painted. Kilograms is the answer for every region outside the set
  // above, which makes it the right answer for a region that cannot be
  // read at all.
  let region: string | undefined;
  try {
    region = new Intl.Locale(navigator.language || 'en').region;
  } catch {
    return 'kg';
  }
  return region && POUND_REGIONS.has(region) ? 'lb' : 'kg';
}

// ------------------------------------------------------------------
// Water units
// ------------------------------------------------------------------

/** Glasses, liters or US fluid ounces. The stored value is glasses, the
 *  unit the tracker has always written, so a unit switch re-renders the
 *  history and never rewrites it. */
export const WATER_UNITS = ['glasses', 'l', 'oz'] as const;

export type WaterUnit = (typeof WATER_UNITS)[number];

/** One glass is 250 ml. A US fluid ounce is 29.5735 ml. */
const ML_PER_GLASS = 250;
const ML_PER_OZ = 29.5735;

/** The most a day can hold, in glasses: five liters. */
const WATER_MAX_GLASSES = 20;

function defaultWaterUnit(): WaterUnit {
  return defaultWeightUnit() === 'lb' ? 'oz' : 'glasses';
}

/** The stored glasses as the number to show in `unit`: whole glasses and
 *  ounces, liters at two decimals. */
export function waterToDisplay(glasses: number, unit: WaterUnit): number {
  if (unit === 'glasses') return Number(glasses.toFixed(1));
  const ml = glasses * ML_PER_GLASS;
  return unit === 'l' ? Number((ml / 1000).toFixed(2)) : Math.round(ml / ML_PER_OZ);
}

/** A number typed in `unit`, as the glasses to store (two decimals). */
export function waterToCanonical(value: number, unit: WaterUnit): number {
  const ml = unit === 'glasses' ? value * ML_PER_GLASS : unit === 'l' ? value * 1000 : value * ML_PER_OZ;
  return Number((ml / ML_PER_GLASS).toFixed(2));
}

/** The stepper of one unit: its step, its maximum and its quick picks. */
export function waterInput(unit: WaterUnit): { step: number; max: number; quick: readonly number[] } {
  if (unit === 'l') return { step: 0.25, max: 5, quick: [1, 1.5, 2, 2.5] };
  if (unit === 'oz') return { step: 4, max: 170, quick: [32, 48, 64, 80] };
  return { step: 1, max: WATER_MAX_GLASSES, quick: [4, 6, 8, 10] };
}

// ------------------------------------------------------------------
// Caffeine units
// ------------------------------------------------------------------

/** Cups or milligrams. Cups are stored, one cup of brewed coffee being
 *  95 mg, so a switch re-renders the history and never rewrites it. */
export const CAFFEINE_UNITS = ['cups', 'mg'] as const;

export type CaffeineUnit = (typeof CAFFEINE_UNITS)[number];

const MG_PER_CUP = 95;

export function caffeineToDisplay(cups: number, unit: CaffeineUnit): number {
  return unit === 'cups' ? Number(cups.toFixed(1)) : Math.round(cups * MG_PER_CUP);
}

export function caffeineToCanonical(value: number, unit: CaffeineUnit): number {
  return Number((unit === 'cups' ? value : value / MG_PER_CUP).toFixed(2));
}

/** The stepper of one unit: its step, its maximum and its quick picks. */
export function caffeineInput(unit: CaffeineUnit): { step: number; max: number; quick: readonly number[] } {
  return unit === 'mg' ? { step: 25, max: 1000, quick: [100, 200, 300, 400] } : { step: 1, max: 10, quick: [1, 2, 3, 4] };
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
  water?: number; // glasses of 250 ml; `trackerSettings.waterUnit` picks the unit shown
  screenTime?: number; // hours
  caffeine?: number; // cups of 95 mg; `trackerSettings.caffeineUnit` picks the unit shown
  pain?: number; // 0-10 scale
  social?: number; // 0-5 scale
  customTrackers?: CustomTrackerEntry[];
  /** Ids from the person's own factor list (`UserSettings.factors`): the
   *  parts of a day, such as "sport" or "bad sleep". */
  factors?: string[];
  /** The Habits answers: a question id of `HABIT_IDS` to yes or no. A
   *  question with no answer has no key; an empty record is written as no
   *  key at all. */
  habits?: HabitAnswers;
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

/** Bookkeeping keys the app stamps on every journal entry at birth. They say
 *  when the entry is for, not anything the person tracked or typed: a
 *  `trackers` object holding only these is an untracked day, and a change to
 *  them is not an edit of the note. */
export const BOOKKEEPING_KEYS: ReadonlySet<string> = new Set(['journalDate', 'backfilled']);

/** Keys on a journal entry that say when it is or where it came from, never
 *  what the person logged: the bookkeeping, the schedule, an import's source
 *  identity and a clipped page's address. */
const NOT_LOGGED: ReadonlySet<string> = new Set([...BOOKKEEPING_KEYS, ...SCHEDULE_KEYS, SOURCE_IDENTITY_KEY, CLIP_SOURCE_KEY]);

/** Whether one tracker value holds anything: an empty list or an empty
 *  string is a cleared pill, not a value. A zero and a false are values. */
export function isLoggedValue(v: unknown): boolean {
  if (v === undefined || v === null) return false;
  if (Array.isArray(v)) return v.length > 0;
  if (typeof v === 'string') return v.trim() !== '';
  if (typeof v === 'object') return Object.keys(v).length > 0;
  return true;
}

/** Whether a journal entry's trackers hold a value the person logged. The
 *  weekly reflection is text and counts only when `withReflection` is set:
 *  it makes an entry content, but it is not a check-in value. */
export function hasLoggedTrackers(trackers: Record<string, unknown> | undefined, withReflection = true): boolean {
  if (!trackers) return false;
  return Object.entries(trackers).some(([key, v]) =>
    !NOT_LOGGED.has(key) && (withReflection || key !== 'weekReflection') && isLoggedValue(v));
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
  // A copy with a `ts` stamp (a medication dose, section 6.7 of the tracker
  // spec) resolves by it instead: the newer tap wins, and a stamped copy
  // beats an unstamped one, as a stamped template does, because every tap
  // since stamps existed carries one. So a correction from Taken to Skip on
  // one device is not undone by a stale Taken on another.
  for (const item of [...remote, ...local]) {
    const id = (item as Record<string, unknown> | null)?.[idField];
    if (id === undefined || id === null) continue;
    const held = map.get(id) as Record<string, unknown> | undefined;
    const ts = (item as Record<string, unknown>).ts;
    if (held && typeof held.ts === 'string' && (typeof ts !== 'string' || held.ts > ts)) continue;
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
 * - `habits` merges per question: an answer only one side gave survives,
 *   the same question resolves local-wins.
 * - `login` (a login's custom fields and extra websites) merges the same
 *   way, in mergeLoginExtras.
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
  if (local.login !== undefined && remote.login !== undefined) {
    merged.login = mergeLoginExtras(local.login, remote.login);
  }
  if (isRecord(local.habits) && isRecord(remote.habits)) {
    merged.habits = { ...remote.habits, ...local.habits };
  }
  return merged;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
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
  /** The Habits questions that are on, a subset of `HABIT_IDS`. A blob from
   *  a client that predates the field carries the object without the key,
   *  and the pull keeps this device's list then, as it keeps `weightUnit`. */
  habits: string[];
  /** The unit the weight tracker reads and writes in. The stored value is
   *  kilograms whichever way this is set, so switching it re-renders the
   *  history rather than reinterpreting it. */
  weightUnit: WeightUnit;
  /** The unit the water tracker reads and writes in; glasses are stored. */
  waterUnit: WaterUnit;
  /** The unit the caffeine tracker reads and writes in; cups are stored. */
  caffeineUnit: CaffeineUnit;
}

export function defaultTrackerSettings(): TrackerSettings {
  return {
    // sleepScore and heartRate available but off by default - users enable in config.
    // Every built-in on: the guided pass shows what the app can track, and
    // the gear at the start of the row turns off what a person does not want.
    activeBuiltins: ['mood', 'emotions', 'factors', 'habits', 'sleep', 'sleepScore', 'heartRate', 'activity', 'medication', 'energy', 'focus', 'weight', 'steps', 'water', 'screenTime', 'caffeine', 'pain', 'social'],
    customTrackers: [],
    archivedMedications: [],
    habits: [...DEFAULT_HABITS],
    weightUnit: defaultWeightUnit(),
    waterUnit: defaultWaterUnit(),
    caffeineUnit: 'cups',
  };
}
