/**
 * Tracker analytics - computed client-side from journal notes' tracker data.
 *
 * All computation happens locally. Nothing leaves the device.
 */

import type { TFunction } from 'i18next';
import type { LocalNote } from './db';
import { activeLocale } from './languages';
import { formatDay, formatInstant, weekdayDate, weekdayLabel } from './intlFormat';
import { RTL_LOCALES } from './localeRoutes';
import { journalDateOf, toLocalIso } from './notesViewUtils';
import { moodStreak } from './trackerCompare';
import {
  BOOKKEEPING_KEYS,
  mergeTrackers,
  type JournalTrackerData,
  type MedicationTemplate,
  type CustomTrackerTemplate,
  EMOTION_TAGS,
  SLEEP_LABELS,
  SLEEP_QUALITIES,
  type SleepQuality,
  ACTIVITY_LABELS,
  ACTIVITY_LEVELS,
  type ActivityLevel,
} from './trackerTypes';

/** Average of an array of numbers (returns 0 for empty arrays). */
function avg(nums: number[]): number {
  return nums.length ? nums.reduce((a, b) => a + b, 0) / nums.length : 0;
}

/** Round to one decimal place. */
function round1(n: number): number {
  return Math.round(n * 10) / 10;
}

// ------------------------------------------------------------------
// Types
// ------------------------------------------------------------------

export type PatternInsight = {
  type: 'day_of_week' | 'streak' | 'trend';
  /** Key under `wellness.insights` in the stats catalog. */
  key: string;
  params: Record<string, string | number>;
};

export type TrackerStats = {
  /** Total journal entries with any tracker data. */
  trackedDays: number;
  /** Mood data points for charting (sorted by date). */
  moodTrend: { date: string; mood: number }[];
  /** Average mood over tracked period. */
  avgMood: number | null;
  /** Emotion frequency: key -> count, sorted descending. */
  emotionFrequency: { key: string; count: number }[];
  /** Sleep quality distribution. */
  sleepDistribution: { quality: SleepQuality; count: number }[];
  /** Average sleep hours (if logged). */
  avgSleepHours: number | null;
  /** Activity level distribution. */
  activityDistribution: { level: ActivityLevel; count: number }[];
  /** Medication adherence: % of expected doses taken. */
  medAdherence: number | null;
  /** Per-medication adherence. `id` disambiguates two medications that
   *  share a name; it is the template id the log entries point at. */
  medBreakdown: { id: string; name: string; taken: number; total: number; pct: number }[];
  /** Week-in-review data (last 7 days). */
  weekInReview: WeekInReview | null;
  /** Detected patterns and insights (Pro). */
  patterns: PatternInsight[];
  /** Day-of-week mood averages (0=Sun..6=Sat). */
  dayOfWeekMood: { day: number; avg: number; count: number }[] | null;
  /** Mood on heatmap (date->mood score for overlay). */
  moodHeatmap: Record<string, number>;
};

type WeekInReview = {
  startDate: string;
  endDate: string;
  daysLogged: number;
  avgMood: number | null;
  moodDelta: number | null; // vs previous week
  topEmotions: { key: string; count: number }[];
  avgSleepHours: number | null;
  medAdherence: number | null;
  dominantActivity: { level: ActivityLevel } | null;
};

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

/** The LOCAL calendar day a stamp falls on: for an entry predating the
 *  `journalDate` field, and for the instant a medication was deleted.
 *  Slicing the ISO string gives the UTC day, which can collide with, or sit
 *  a day away from, the local dates every entry is filed under. */
function dayKey(iso: string): string {
  return toLocalIso(new Date(iso));
}

/** The journal entries whose day (the entry date, or the creation day for an
 *  entry that predates it) falls in `range`, inclusive. Statistics built from
 *  these follow the range row of the Wellness tab. */
export function journalsInRange(notes: LocalNote[], range: { from: string; to: string }): LocalNote[] {
  return notes.filter((n) => {
    if (n.type !== 'journal') return false;
    const day = journalDateOf(n) ?? dayKey(n.createdAt);
    return day >= range.from && day <= range.to;
  });
}

/** Local calendar date `n` days back. Local, not UTC, so it compares
 *  like-for-like against the entry dates below (which come from
 *  `trackers.journalDate`, itself a local ISO date). Mixing the two
 *  bases shifted week boundaries and streaks by a day for anyone far
 *  enough from Greenwich. */
function daysAgo(n: number): string {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return toLocalIso(d);
}

export type JournalEntry = {
  date: string;
  data: JournalTrackerData;
};

/** True when the user actually logged something (a pill, a reflection),
 *  as opposed to the birth stamp every journal entry carries. */
function hasTrackerData(data: JournalTrackerData): boolean {
  const record = data as Record<string, unknown>;
  return Object.keys(record).some(
    (key) => !BOOKKEEPING_KEYS.has(key) && record[key] !== undefined,
  );
}

/**
 * Extract journal entries with tracker data, one per calendar day,
 * sorted by date ascending.
 *
 * The day an entry belongs to is `trackers.journalDate` (a LOCAL ISO
 * date), falling back to the UTC day of `createdAt` for entries that
 * predate that field. Reading `createdAt` unconditionally, as this used
 * to, filed every backfilled entry under the day it was typed rather
 * than the day it was for.
 * Spec: ops/docs/design-decisions.md (journal entry titles)
 *
 * Nothing stops a user from keeping two journal entries for the same
 * day, so entries are collapsed per day: later-created data wins key by
 * key. Left un-collapsed, one day counted twice in `trackedDays`, drew
 * two points on the mood chart, and rendered duplicate React keys.
 *
 * A journal the PIN guards right now (`isGated`) is left out: its mood,
 * sleep and doses are its content, and every reader below (the charts, the
 * insights, the doctor report, the AI prompt, Week in review, the JSON
 * export) comes through here.
 *
 * An entry for a day after today waits until that day comes: a plan written
 * ahead is not a tracked day, and counting it would move every average and
 * streak. The JSON export alone keeps every day (`withFuture`).
 * Spec: ops/docs/plans/dates.md (section 3.4)
 */
export function extractEntries(
  notes: LocalNote[],
  isGated: (n: LocalNote) => boolean,
  withFuture = false,
): JournalEntry[] {
  const today = toLocalIso(new Date());
  const byDate = new Map<string, JournalEntry>();
  const sourceOrder = [...notes].sort((a, b) =>
    a.createdAt < b.createdAt ? -1 : a.createdAt > b.createdAt ? 1 : 0,
  );
  for (const n of sourceOrder) {
    if (n.deleted === 1 || n.trashed === 1) continue;
    if (n.type !== 'journal') continue;
    // The type makes every caller in the app pass the predicate; a call that
    // passes none reads every journal.
    if (isGated?.(n)) continue;
    const data = n.trackers as JournalTrackerData | undefined;
    // Presence of `trackers` alone used to qualify, so every journal
    // created since the date stamp shipped counted as a tracked day.
    if (!data || !hasTrackerData(data)) continue;
    const date = journalDateOf(n) ?? dayKey(n.createdAt);
    if (!withFuture && date > today) continue;
    const existing = byDate.get(date);
    byDate.set(date, {
      date,
      // Same field-level merge sync uses, so two entries for one day
      // behave here exactly as two devices editing one entry do. The
      // shallow spread this replaced let the later entry's medications
      // array replace the earlier one's wholesale, so a second entry
      // created for a day erased the first one's doses from every
      // statistic and from the doctor report.
      data: existing
        ? (mergeTrackers(
            data as Record<string, unknown>,
            existing.data as Record<string, unknown>
          ) as JournalTrackerData)
        : data,
    });
  }
  return [...byDate.values()].sort((a, b) =>
    a.date < b.date ? -1 : a.date > b.date ? 1 : 0,
  );
}

// ------------------------------------------------------------------
// Main computation
// ------------------------------------------------------------------

/**
 * `isGated` is the view's lock predicate, passed by every caller: a journal
 * behind a closed gate is left out, and counts again once its gate opens.
 * Tested in tests/lockGateReads.test.ts.
 */
export function computeTrackerStats(
  notes: LocalNote[],
  medications: MedicationTemplate[],
  isGated: (n: LocalNote) => boolean,
): TrackerStats {
  const entries = extractEntries(notes, isGated);
  if (entries.length === 0) {
    return {
      trackedDays: 0,
      moodTrend: [],
      avgMood: null,
      emotionFrequency: [],
      sleepDistribution: [],
      avgSleepHours: null,
      activityDistribution: [],
      medAdherence: null,
      medBreakdown: [],
      weekInReview: null,
      patterns: [],
      dayOfWeekMood: null,
      moodHeatmap: {},
    };
  }

  // ── Mood ────────────────────────────────────────────────────────
  const moodTrend: { date: string; mood: number }[] = [];
  let moodSum = 0;
  let moodCount = 0;
  for (const e of entries) {
    if (e.data.mood != null) {
      moodTrend.push({ date: e.date, mood: e.data.mood });
      moodSum += e.data.mood;
      moodCount++;
    }
  }

  // ── Emotions ───────────────────────────────────────────────────
  const emotionCounts: Record<string, number> = {};
  for (const e of entries) {
    if (e.data.emotions) {
      for (const key of e.data.emotions) {
        emotionCounts[key] = (emotionCounts[key] ?? 0) + 1;
      }
    }
  }
  const emotionFrequency = Object.entries(emotionCounts)
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count);

  // ── Sleep ──────────────────────────────────────────────────────
  const sleepCounts: Record<string, number> = {
    terrible: 0, poor: 0, okay: 0, good: 0, great: 0,
  };
  let sleepHoursSum = 0;
  let sleepHoursCount = 0;
  for (const e of entries) {
    if (e.data.sleep) {
      sleepCounts[e.data.sleep.quality] = (sleepCounts[e.data.sleep.quality] ?? 0) + 1;
      if (e.data.sleep.hours != null) {
        sleepHoursSum += e.data.sleep.hours;
        sleepHoursCount++;
      }
    }
  }
  const sleepDistribution = SLEEP_QUALITIES.map(
    (quality) => ({ quality, count: sleepCounts[quality] ?? 0 })
  );

  // ── Activity ───────────────────────────────────────────────────
  const activityCounts: Record<string, number> = {
    sedentary: 0, light: 0, moderate: 0, active: 0, intense: 0,
  };
  for (const e of entries) {
    if (e.data.activity) {
      activityCounts[e.data.activity] = (activityCounts[e.data.activity] ?? 0) + 1;
    }
  }
  const activityDistribution = ACTIVITY_LEVELS.map(
    (level) => ({ level, count: activityCounts[level] ?? 0 })
  );

  // ── Medication ─────────────────────────────────────────────────
  //
  // A missed dose counts as a missed dose. The denominator used to be
  // "entries the user tapped", so forgetting to record a dose removed it
  // from the sum entirely and the figure could read 100% for someone who
  // took half their doses - on a page written for a clinician.
  //
  // The denominator is now every tracked day inside the medication's own
  // window, and the window runs from the first day it was LOGGED (not
  // from `startedAt`) to the day it was deleted. Starting at the first
  // log is what keeps the number honest in the other direction: days
  // before the user began recording a medication are unknown, not
  // missed, and a medication that was never logged at all stays out of
  // the figure rather than dragging it to zero. Days with no journal
  // entry are not counted either way - this measures the days the user
  // showed up, and inventing misses for days they did not journal would
  // punish not journalling rather than not taking a dose.
  const medWindows = new Map<string, { first: string; last: string }>();
  for (const e of entries) {
    for (const log of e.data.medications ?? []) {
      const w = medWindows.get(log.medicationId);
      if (!w) medWindows.set(log.medicationId, { first: e.date, last: e.date });
      else if (e.date > w.last) w.last = e.date;
    }
  }

  let totalExpected = 0;
  let totalTaken = 0;
  const medMap: Record<string, { name: string; taken: number; total: number }> = {};
  for (const med of medications) {
    const window = medWindows.get(med.id);
    if (!window) continue; // never logged - unknown, not missed
    const from = med.startedAt > window.first ? med.startedAt : window.first;
    const until = med.deletedAt ? dayKey(med.deletedAt) : null;
    let taken = 0;
    let total = 0;
    for (const e of entries) {
      if (e.date < from) continue;
      if (until && e.date > until) continue;
      total++;
      const log = e.data.medications?.find((l) => l.medicationId === med.id);
      if (log?.status === 'taken') taken++;
    }
    if (total === 0) continue;
    medMap[med.id] = { name: med.name, taken, total };
    totalExpected += total;
    totalTaken += taken;
  }
  // Log entries whose template is gone from the array entirely (legacy
  // data - deletion is a tombstone now). Nothing can name them, but the
  // dose was recorded, so it still counts.
  for (const e of entries) {
    for (const log of e.data.medications ?? []) {
      if (medWindows.has(log.medicationId) && !medications.some((m) => m.id === log.medicationId)) {
        totalExpected++;
        if (log.status === 'taken') totalTaken++;
      }
    }
  }
  const medBreakdown = Object.entries(medMap)
    .filter(([, m]) => m.total > 0)
    // The id rides along: the table keyed rows by NAME, so two
    // medications called the same thing collided as React keys and were
    // indistinguishable on the report.
    .map(([id, m]) => ({ id, ...m, pct: Math.round((m.taken / m.total) * 100) }));

  // ── Week-in-review ─────────────────────────────────────────────
  const weekStart = daysAgo(6);
  const weekEnd = daysAgo(0);
  const prevWeekStart = daysAgo(13);
  const thisWeek = entries.filter((e) => e.date >= weekStart && e.date <= weekEnd);
  const prevWeek = entries.filter((e) => e.date >= prevWeekStart && e.date < weekStart);

  let weekInReview: WeekInReview | null = null;
  if (thisWeek.length > 0) {
    const wMoods = thisWeek.filter((e) => e.data.mood != null).map((e) => e.data.mood!);
    const wAvgMood = wMoods.length > 0 ? avg(wMoods) : null;
    const pMoods = prevWeek.filter((e) => e.data.mood != null).map((e) => e.data.mood!);
    const pAvgMood = pMoods.length > 0 ? avg(pMoods) : null;

    const wEmotions: Record<string, number> = {};
    for (const e of thisWeek) {
      if (e.data.emotions) {
        for (const k of e.data.emotions) wEmotions[k] = (wEmotions[k] ?? 0) + 1;
      }
    }
    const topEmotions = Object.entries(wEmotions)
      .map(([key, count]) => ({ key, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    const wSleepHours = thisWeek
      .filter((e) => e.data.sleep?.hours != null)
      .map((e) => e.data.sleep!.hours!);
    const wAvgSleep = wSleepHours.length > 0 ? avg(wSleepHours) : null;

    // Same rule as the all-time figure above: every tracked day inside a
    // medication's window counts, whether or not the user remembered to
    // record it.
    let wMedTotal = 0;
    let wMedTaken = 0;
    for (const med of medications) {
      const window = medWindows.get(med.id);
      if (!window) continue;
      const from = med.startedAt > window.first ? med.startedAt : window.first;
      const until = med.deletedAt ? dayKey(med.deletedAt) : null;
      for (const e of thisWeek) {
        if (e.date < from) continue;
        if (until && e.date > until) continue;
        wMedTotal++;
        if (e.data.medications?.find((l) => l.medicationId === med.id)?.status === 'taken') {
          wMedTaken++;
        }
      }
    }

    const wActivityCounts: Record<string, number> = {};
    for (const e of thisWeek) {
      if (e.data.activity) wActivityCounts[e.data.activity] = (wActivityCounts[e.data.activity] ?? 0) + 1;
    }
    const topActivity = Object.entries(wActivityCounts).sort((a, b) => b[1] - a[1])[0];

    weekInReview = {
      startDate: weekStart,
      endDate: weekEnd,
      daysLogged: thisWeek.length,
      avgMood: wAvgMood != null ? round1(wAvgMood) : null,
      moodDelta: wAvgMood != null && pAvgMood != null ? round1(wAvgMood - pAvgMood) : null,
      topEmotions,
      avgSleepHours: wAvgSleep != null ? round1(wAvgSleep) : null,
      medAdherence: wMedTotal > 0 ? Math.round((wMedTaken / wMedTotal) * 100) : null,
      dominantActivity: topActivity
        ? { level: topActivity[0] as ActivityLevel }
        : null,
    };
  }

  // ── Mood heatmap ────────────────────────────────────────────────
  const moodHeatmap: Record<string, number> = {};
  for (const e of entries) {
    if (e.data.mood != null) moodHeatmap[e.date] = e.data.mood;
  }

  // ── Day-of-week mood ──────────────────────────────────────────
  const dowSums: number[] = [0, 0, 0, 0, 0, 0, 0];
  const dowCounts: number[] = [0, 0, 0, 0, 0, 0, 0];
  for (const e of entries) {
    if (e.data.mood != null) {
      const dow = new Date(e.date + 'T12:00:00').getDay();
      dowSums[dow] = (dowSums[dow] ?? 0) + e.data.mood;
      dowCounts[dow] = (dowCounts[dow] ?? 0) + 1;
    }
  }
  // The day index travels, never a name: the view owns the label, so it can
  // render one in the language on screen.
  const dayOfWeekMood = moodCount >= 7
    ? dowCounts.map((_, i) => {
        const cnt = dowCounts[i] ?? 0;
        const sum = dowSums[i] ?? 0;
        return { day: i, avg: cnt > 0 ? round1(sum / cnt) : 0, count: cnt };
      })
    : null;

  // ── Pattern detection ─────────────────────────────────────────
  const patterns = computePatterns(entries, moodCount, moodSum);

  return {
    trackedDays: entries.length,
    moodTrend,
    avgMood: moodCount > 0 ? round1(moodSum / moodCount) : null,
    emotionFrequency,
    sleepDistribution,
    avgSleepHours: sleepHoursCount > 0 ? round1(sleepHoursSum / sleepHoursCount) : null,
    activityDistribution,
    medAdherence: totalExpected > 0 ? Math.round((totalTaken / totalExpected) * 100) : null,
    medBreakdown,
    weekInReview,
    patterns,
    dayOfWeekMood,
    moodHeatmap,
  };
}

// ------------------------------------------------------------------
// Pattern detection
// ------------------------------------------------------------------

/**
 * The sentences that are not a comparison of one tracker against another:
 * the weekday, the mood streak, the trend. The comparisons, the sleep and
 * activity ones included, come from trackerCompare and are built where they
 * are shown.
 * Spec: ops/docs/plans/wellness-statistics.md (section 7)
 */
function computePatterns(
  entries: JournalEntry[],
  moodCount: number,
  moodSum: number,
): PatternInsight[] {
  const patterns: PatternInsight[] = [];
  if (moodCount < 5) return patterns;
  const avgMood = moodSum / moodCount;

  // ── Day-of-week pattern ─────────────────────────────────────────
  const dowSums2: number[] = [0, 0, 0, 0, 0, 0, 0];
  const dowCnts2: number[] = [0, 0, 0, 0, 0, 0, 0];
  for (const e of entries) {
    if (e.data.mood == null) continue;
    const dow = new Date(e.date + 'T12:00:00').getDay();
    dowSums2[dow] = (dowSums2[dow] ?? 0) + e.data.mood;
    dowCnts2[dow] = (dowCnts2[dow] ?? 0) + 1;
  }
  let bestDay = -1, worstDay = -1, bestAvg = 0, worstAvg = 11;
  for (let i = 0; i < 7; i++) {
    const cnt = dowCnts2[i] ?? 0;
    const sum = dowSums2[i] ?? 0;
    if (cnt < 2) continue;
    const a = sum / cnt;
    if (a > bestAvg) { bestAvg = a; bestDay = i; }
    if (a < worstAvg) { worstAvg = a; worstDay = i; }
  }
  if (bestDay >= 0 && worstDay >= 0 && bestAvg - worstAvg >= 1) {
    patterns.push({
      type: 'day_of_week',
      key: 'dayOfWeek',
      params: { bestDay, bestAvg: round1(bestAvg), worstDay, worstAvg: round1(worstAvg) },
    });
  }

  // ── Streak acknowledgment ─────────────────────────────────────
  // Counts mood days only: that is what the sentence says.
  const streak = moodStreak(entries, daysAgo(0));
  if (streak >= 7) {
    patterns.push({ type: 'streak', key: 'streak', params: { count: streak } });
  }

  // ── Mood trend (last 14 days vs overall) ──────────────────────
  const recent14 = entries.filter((e) => e.date >= daysAgo(13) && e.data.mood != null);
  if (recent14.length >= 5 && moodCount >= 14) {
    const recentAvg = recent14.reduce((s, e) => s + e.data.mood!, 0) / recent14.length;
    const delta = round1(recentAvg - avgMood);
    if (Math.abs(delta) >= 0.8) {
      patterns.push({
        type: 'trend',
        key: 'trend',
        params: { recent: round1(recentAvg), overall: round1(avgMood) },
      });
    }
  }

  return patterns;
}

// ------------------------------------------------------------------
// Insight sentences
// ------------------------------------------------------------------

/**
 * The sentence for one detected pattern, in the language on screen.
 *
 * The insight travels as a key and plain numbers, so the same pattern reads
 * correctly in a card, in the AI prompt and in the doctor report. Two cases
 * need more than interpolation: the day-of-week one carries two weekday
 * indexes and the medication one a stored day, and only the caller's locale
 * can write either.
 */
export function insightText(p: PatternInsight, t: TFunction): string {
  const params = p.type === 'day_of_week'
    ? {
        ...p.params,
        best: weekdayLabel(weekdayDate(Number(p.params.bestDay)), 'long'),
        worst: weekdayLabel(weekdayDate(Number(p.params.worstDay)), 'long'),
      }
    : p.params;
  return t(`wellness.insights.${p.key}`, params);
}

// ------------------------------------------------------------------
// JSON export
// ------------------------------------------------------------------

/** What turns the ids inside the entries into names, tombstones included. */
export type WellnessDefinitions = {
  customTrackers: readonly CustomTrackerTemplate[];
  medications: readonly MedicationTemplate[];
};

/**
 * The free data export: a versioned envelope with the range, the
 * definitions every id points at, and the raw entries with their ids, so a
 * later import can read them back and a person can read them now. Every
 * day is kept, a day planned ahead included.
 * Spec: ops/docs/plans/wellness-statistics.md (section 12)
 */
export function exportTrackerJSON(
  notes: LocalNote[],
  dateFrom: string | undefined,
  dateTo: string | undefined,
  isGated: (n: LocalNote) => boolean,
  definitions: WellnessDefinitions = { customTrackers: [], medications: [] },
  generated: string = toLocalIso(new Date()),
): string {
  const entries = extractEntries(notes, isGated, true).filter((e) => {
    if (dateFrom && e.date < dateFrom) return false;
    if (dateTo && e.date > dateTo) return false;
    return true;
  });
  return JSON.stringify(
    {
      version: 2,
      generated,
      range: {
        from: dateFrom ?? entries[0]?.date ?? null,
        to: dateTo ?? entries[entries.length - 1]?.date ?? null,
      },
      definitions: {
        customTrackers: definitions.customTrackers.map((t) => ({
          id: t.id,
          name: t.name,
          type: t.type,
          stoppedAt: t.stoppedAt ?? null,
          deletedAt: t.deletedAt ?? null,
        })),
        medications: definitions.medications.map((m) => ({
          id: m.id,
          name: m.name,
          dosage: m.dosage,
          startedAt: m.startedAt,
          dosageHistory: m.dosageHistory,
          deletedAt: m.deletedAt ?? null,
        })),
      },
      entries: entries.map((e) => ({ date: e.date, ...e.data })),
    },
    null,
    2,
  );
}
