import i18n from './i18n';
import { SCHEDULE_KEYS } from './schedule';
import {
  EMOTION_TAGS,
  type ActivityLevel,
  type CustomTrackerTemplate,
  type JournalTrackerData,
  type SleepQuality,
  type WeightUnit,
  weightToDisplay,
} from './trackerTypes';

/**
 * Journal tracker values as readable label/value pairs, for the export
 * formats a person READS rather than re-imports (HTML, print).
 *
 * Two rules that differ from `TrackerPills.tsx`, and both are deliberate:
 *
 *  1. **Every value that was recorded is listed, not just the pills that
 *     happen to be switched on.** The pill row is a view preference; an
 *     export is the data. Filtering an export through `activeBuiltins`
 *     would silently drop numbers the user had logged, which is the same
 *     class of bug as omitting trackers altogether.
 *  2. Nothing here is interactive, so no colours, icons or ordering by
 *     pill layout. Order is fixed and reads like a day: how it felt, how
 *     it slept, what the body did, then the counts.
 *
 * The machine-readable copy lives in the markdown front-matter instead
 * (`noteMarkdown.ts`), which is what an import reads back. This is the
 * human half of the same data, so the two must not be confused: changing
 * a label here cannot break a round trip, and changing the front-matter
 * grammar cannot change what a printed page says.
 */

export interface TrackerRow {
  label: string;
  value: string;
}

/** Bookkeeping the person did not log, and values printed by their own rule
 *  below. The week reflection is private prose, not a tracker value. The
 *  schedule keys share `trackers` and the export prints them as one line of
 *  their own under the title, so they are never tracker rows. */
const SKIP_KEYS = new Set<string>(['backfilled', 'weekReflection', 'customTrackers', ...SCHEDULE_KEYS]);

interface SleepValue {
  quality: SleepQuality;
  hours?: number;
}

function isSleep(v: unknown): v is SleepValue {
  return typeof v === 'object' && v !== null && 'quality' in v;
}

/**
 * Build the rows. Returns an empty array when the entry has nothing
 * recorded, so callers can skip the whole section rather than print a
 * heading over nothing.
 *
 * `weight` is stored in kilograms, so a caller that reads a person's own
 * unit passes it here. The default prints the stored number as it is.
 */
export function trackerRows(
  trackers: Record<string, unknown> | undefined,
  weightUnit: WeightUnit = 'kg',
  customTemplates: readonly CustomTrackerTemplate[] = [],
): TrackerRow[] {
  if (!trackers) return [];
  const d = trackers as JournalTrackerData & Record<string, unknown>;
  const t = (k: string, o?: Record<string, unknown>): string => i18n.t(`trackers:${k}`, o ?? {});
  const rows: TrackerRow[] = [];
  const add = (labelKey: string, value: string | null): void => {
    if (value !== null && value !== '') rows.push({ label: t(`labels.${labelKey}`), value });
  };

  add('mood', d.mood != null ? `${d.mood}/10` : null);

  if (d.emotions?.length) {
    add(
      'emotions',
      d.emotions
        .map((key) =>
          EMOTION_TAGS.some((tag) => tag.key === key) ? t(`emotions.tags.${key}`) : key,
        )
        .join(', '),
    );
  }

  if (isSleep(d.sleep)) {
    const quality = t(`sleep.quality.${d.sleep.quality}`);
    add('sleep', d.sleep.hours != null
      ? `${quality} (${d.sleep.hours}${t('units.hoursSuffix')})`
      : quality);
  }

  add('sleepScore', d.sleepScore != null ? `${d.sleepScore}` : null);
  add('heartRate', d.heartRate != null ? `${d.heartRate}${t('units.bpm')}` : null);
  add('activity', d.activity ? t(`activity.level.${d.activity as ActivityLevel}`) : null);
  add('energy', d.energy != null ? `${d.energy}/10` : null);
  add('focus', d.focus != null ? `${d.focus}/10` : null);
  add('pain', d.pain != null ? `${d.pain}/10` : null);
  add('social', d.social != null ? `${d.social}/5` : null);
  add('steps', d.steps != null ? `${d.steps}` : null);
  add('weight', d.weight != null
    ? `${weightToDisplay(d.weight, weightUnit)}${t(`units.${weightUnit}`)}`
    : null);
  add('water', d.water != null ? `${d.water}/10` : null);
  add('caffeine', d.caffeine != null ? `${d.caffeine}/5` : null);
  add('screenTime', d.screenTime != null ? `${d.screenTime}${t('units.hoursSuffix')}` : null);
  add('medication', d.medications?.length ? `${d.medications.length}` : null);

  // Custom values print under the template's name, tombstoned templates
  // included: a value logged before a tracker was deleted is still the data.
  for (const entry of d.customTrackers ?? []) {
    const tpl = customTemplates.find((c) => c.id === entry.trackerId);
    const v = entry.value;
    if (v == null || v === '') continue;
    const label = tpl?.name ?? entry.trackerId.slice(0, 8);
    let value: string;
    if (typeof v === 'boolean') value = v ? t('custom.yes') : t('custom.no');
    else if (tpl?.type === 'scale10') value = `${v}/10`;
    else if (tpl?.type === 'scale5') value = `${v}/5`;
    else value = String(v);
    rows.push({ label, value });
  }

  // Anything a future tracker adds still reaches the page: an unknown key
  // is printed under its own name rather than dropped, so a new value is
  // never invisible in an export just because this file has not caught up.
  const known = new Set([
    'mood', 'emotions', 'sleep', 'sleepScore', 'heartRate', 'activity', 'energy',
    'focus', 'pain', 'social', 'steps', 'weight', 'water', 'caffeine',
    'screenTime', 'medications',
  ]);
  for (const [key, value] of Object.entries(trackers)) {
    if (known.has(key) || SKIP_KEYS.has(key)) continue;
    if (value == null || typeof value === 'object') continue;
    rows.push({ label: key, value: String(value) });
  }

  return rows;
}

/** The section heading. Reuses the tracker panel's own translated title. */
export function trackerHeading(): string {
  return i18n.t('trackers:config.title');
}
