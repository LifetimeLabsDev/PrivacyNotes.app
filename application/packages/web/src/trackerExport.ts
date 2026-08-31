import i18n from './i18n';
import {
  EMOTION_TAGS,
  type ActivityLevel,
  type JournalTrackerData,
  type SleepQuality,
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

/** `journalDate` is the entry's day, shown in the header already. */
const SKIP_KEYS = new Set(['journalDate', 'customTrackers']);

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
 */
export function trackerRows(trackers: Record<string, unknown> | undefined): TrackerRow[] {
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
  add('weight', d.weight != null ? `${d.weight}${t('units.kg')}` : null);
  add('water', d.water != null ? `${d.water}/10` : null);
  add('caffeine', d.caffeine != null ? `${d.caffeine}/5` : null);
  add('screenTime', d.screenTime != null ? `${d.screenTime}${t('units.hoursSuffix')}` : null);
  add('medication', d.medications?.length ? `${d.medications.length}` : null);

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
