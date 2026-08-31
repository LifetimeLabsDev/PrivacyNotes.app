/**
 * Tracker analytics - computed client-side from journal notes' tracker data.
 *
 * All computation happens locally. Nothing leaves the device.
 */

import type { LocalNote } from './db';
import { journalDateOf, toLocalIso } from './notesViewUtils';
import {
  mergeTrackers,
  type JournalTrackerData,
  type MedicationTemplate,
  EMOTION_TAGS,
  SLEEP_LABELS,
  type SleepQuality,
  ACTIVITY_LABELS,
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
  type: 'correlation' | 'day_of_week' | 'medication' | 'streak' | 'trend';
  text: string;
};

export type TrackerStats = {
  /** Total journal entries with any tracker data. */
  trackedDays: number;
  /** Mood data points for charting (sorted by date). */
  moodTrend: { date: string; mood: number }[];
  /** Average mood over tracked period. */
  avgMood: number | null;
  /** Emotion frequency: key -> count, sorted descending. */
  emotionFrequency: { key: string; label: string; count: number }[];
  /** Sleep quality distribution. */
  sleepDistribution: { quality: SleepQuality; label: string; count: number }[];
  /** Average sleep hours (if logged). */
  avgSleepHours: number | null;
  /** Activity level distribution. */
  activityDistribution: { level: ActivityLevel; label: string; count: number }[];
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
  dayOfWeekMood: { day: number; label: string; avg: number; count: number }[] | null;
  /** Mood on heatmap (date->mood score for overlay). */
  moodHeatmap: Record<string, number>;
};

type WeekInReview = {
  startDate: string;
  endDate: string;
  daysLogged: number;
  avgMood: number | null;
  moodDelta: number | null; // vs previous week
  topEmotions: { key: string; label: string; count: number }[];
  avgSleepHours: number | null;
  medAdherence: number | null;
  dominantActivity: { level: ActivityLevel; label: string } | null;
};

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

/** The LOCAL calendar day a stamp falls on. Only entries predating the
 *  `journalDate` field reach this, and slicing the ISO string gave their
 *  UTC day - which could collide with, or sit a day away from, the local
 *  dates every other entry is filed under. */
function dayKey(iso: string): string {
  return toLocalIso(new Date(iso));
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

type JournalEntry = {
  date: string;
  data: JournalTrackerData;
};

/** Bookkeeping keys the app stamps on every journal entry at birth.
 *  They say when the entry is for, not anything the user tracked, so a
 *  `trackers` object holding only these is an untracked day. */
const BOOKKEEPING_KEYS = new Set(['journalDate', 'backfilled']);

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
 */
function extractEntries(notes: LocalNote[]): JournalEntry[] {
  const byDate = new Map<string, JournalEntry>();
  const sourceOrder = [...notes].sort((a, b) =>
    a.createdAt < b.createdAt ? -1 : a.createdAt > b.createdAt ? 1 : 0,
  );
  for (const n of sourceOrder) {
    if (n.deleted === 1 || n.trashed === 1) continue;
    if (n.type !== 'journal') continue;
    const data = n.trackers as JournalTrackerData | undefined;
    // Presence of `trackers` alone used to qualify, so every journal
    // created since the date stamp shipped counted as a tracked day.
    if (!data || !hasTrackerData(data)) continue;
    const date = journalDateOf(n) ?? dayKey(n.createdAt);
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

export function computeTrackerStats(
  notes: LocalNote[],
  medications: MedicationTemplate[],
): TrackerStats {
  const entries = extractEntries(notes);
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
    .map(([key, count]) => ({
      key,
      label: EMOTION_TAGS.find((t) => t.key === key)?.label ?? key,
      count,
    }))
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
  const sleepDistribution = (Object.entries(SLEEP_LABELS) as [SleepQuality, string][]).map(
    ([quality, label]) => ({ quality, label, count: sleepCounts[quality] ?? 0 })
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
  const activityDistribution = (Object.entries(ACTIVITY_LABELS) as [ActivityLevel, string][]).map(
    ([level, label]) => ({ level, label, count: activityCounts[level] ?? 0 })
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
    const until = med.deletedAt ? med.deletedAt.slice(0, 10) : null;
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
      .map(([key, count]) => ({ key, label: EMOTION_TAGS.find((t) => t.key === key)?.label ?? key, count }))
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
      const until = med.deletedAt ? med.deletedAt.slice(0, 10) : null;
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
        ? { level: topActivity[0] as ActivityLevel, label: ACTIVITY_LABELS[topActivity[0] as ActivityLevel] }
        : null,
    };
  }

  // ── Mood heatmap ────────────────────────────────────────────────
  const moodHeatmap: Record<string, number> = {};
  for (const e of entries) {
    if (e.data.mood != null) moodHeatmap[e.date] = e.data.mood;
  }

  // ── Day-of-week mood ──────────────────────────────────────────
  const DOW_LABELS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const dowSums: number[] = [0, 0, 0, 0, 0, 0, 0];
  const dowCounts: number[] = [0, 0, 0, 0, 0, 0, 0];
  for (const e of entries) {
    if (e.data.mood != null) {
      const dow = new Date(e.date + 'T12:00:00').getDay();
      dowSums[dow] = (dowSums[dow] ?? 0) + e.data.mood;
      dowCounts[dow] = (dowCounts[dow] ?? 0) + 1;
    }
  }
  const dayOfWeekMood = moodCount >= 7
    ? DOW_LABELS.map((label, i) => {
        const cnt = dowCounts[i] ?? 0;
        const sum = dowSums[i] ?? 0;
        return { day: i, label, avg: cnt > 0 ? round1(sum / cnt) : 0, count: cnt };
      })
    : null;

  // ── Pattern detection ─────────────────────────────────────────
  const patterns = computePatterns(entries, moodCount, moodSum, medications);

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

const SLEEP_QUALITY_NUM: Record<string, number> = {
  terrible: 1, poor: 2, okay: 3, good: 4, great: 5,
};
const ACTIVITY_NUM: Record<string, number> = {
  sedentary: 1, light: 2, moderate: 3, active: 4, intense: 5,
};

function computePatterns(
  entries: JournalEntry[],
  moodCount: number,
  moodSum: number,
  medications: MedicationTemplate[],
): PatternInsight[] {
  const patterns: PatternInsight[] = [];
  if (moodCount < 5) return patterns;
  const avgMood = moodSum / moodCount;

  // ── Sleep-mood correlation ────────────────────────────────────
  const goodSleepMoods: number[] = [];
  const badSleepMoods: number[] = [];
  for (const e of entries) {
    if (e.data.mood == null || !e.data.sleep) continue;
    const sq = SLEEP_QUALITY_NUM[e.data.sleep.quality] ?? 3;
    if (sq >= 4) goodSleepMoods.push(e.data.mood);
    else if (sq <= 2) badSleepMoods.push(e.data.mood);
  }
  if (goodSleepMoods.length >= 3 && badSleepMoods.length >= 3) {
    const goodAvg = avg(goodSleepMoods);
    const badAvg = avg(badSleepMoods);
    const delta = round1(goodAvg - badAvg);
    if (Math.abs(delta) >= 0.5) {
      patterns.push({
        type: 'correlation',
        text: `Your mood is ${delta > 0 ? delta + ' points higher' : Math.abs(delta) + ' points lower'} on days you sleep well vs. poorly.`,
      });
    }
  }

  // ── Activity-mood correlation ─────────────────────────────────
  const activeMoods: number[] = [];
  const sedentaryMoods: number[] = [];
  for (const e of entries) {
    if (e.data.mood == null || !e.data.activity) continue;
    const al = ACTIVITY_NUM[e.data.activity] ?? 3;
    if (al >= 3) activeMoods.push(e.data.mood);
    else sedentaryMoods.push(e.data.mood);
  }
  if (activeMoods.length >= 3 && sedentaryMoods.length >= 3) {
    const activeAvg = avg(activeMoods);
    const sedAvg = avg(sedentaryMoods);
    const delta = round1(activeAvg - sedAvg);
    if (Math.abs(delta) >= 0.5) {
      patterns.push({
        type: 'correlation',
        text: `Your mood averages ${delta > 0 ? delta + ' points higher' : Math.abs(delta) + ' points lower'} on active days vs. sedentary days.`,
      });
    }
  }

  // ── Day-of-week pattern ─────────────────────────────────────────
  const DOW_NAMES = ['Sundays', 'Mondays', 'Tuesdays', 'Wednesdays', 'Thursdays', 'Fridays', 'Saturdays'];
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
      text: `Your best day tends to be ${DOW_NAMES[bestDay]} (avg ${round1(bestAvg)}) and toughest is ${DOW_NAMES[worstDay]} (avg ${round1(worstAvg)}).`,
    });
  }

  // ── Medication impact ─────────────────────────────────────────
  for (const med of medications) {
    const startDate = med.startedAt;
    const beforeMoods: number[] = [];
    const afterMoods: number[] = [];
    for (const e of entries) {
      if (e.data.mood == null) continue;
      if (e.date < startDate) beforeMoods.push(e.data.mood);
      else afterMoods.push(e.data.mood);
    }
    if (beforeMoods.length >= 5 && afterMoods.length >= 5) {
      const beforeAvg = avg(beforeMoods);
      const afterAvg = avg(afterMoods);
      const delta = round1(afterAvg - beforeAvg);
      if (Math.abs(delta) >= 0.5) {
        patterns.push({
          type: 'medication',
          text: `Since starting ${med.name} (${startDate}), your average mood ${delta > 0 ? 'improved' : 'declined'} by ${Math.abs(delta)} points.`,
        });
      }
    }
  }

  // ── Streak acknowledgment ───────���─────────────────────────────
  let streak = 0;
  const today = daysAgo(0);
  for (let i = 0; i <= 365; i++) {
    const d = daysAgo(i);
    if (entries.some((e) => e.date === d)) streak++;
    else break;
  }
  if (streak >= 7) {
    patterns.push({
      type: 'streak',
      text: `You've logged mood for ${streak} days in a row. Keep it up!`,
    });
  }

  // ── Mood trend (last 14 days vs overall) ──────────────────────
  const recent14 = entries.filter((e) => e.date >= daysAgo(13) && e.data.mood != null);
  if (recent14.length >= 5 && moodCount >= 14) {
    const recentAvg = recent14.reduce((s, e) => s + e.data.mood!, 0) / recent14.length;
    const delta = round1(recentAvg - avgMood);
    if (Math.abs(delta) >= 0.8) {
      patterns.push({
        type: 'trend',
        text: `Your mood over the last 2 weeks is ${delta > 0 ? delta + ' points above' : Math.abs(delta) + ' points below'} your overall average.`,
      });
    }
  }

  return patterns;
}

// ------------------------------------------------------------------
// AI prompt generator
// ------------------------------------------------------------------

export function generateAIPrompt(stats: TrackerStats, medications: MedicationTemplate[]): string {
  const lines: string[] = [
    'I\'ve been tracking my mood and wellness. Please analyze the data below for patterns, trends, and actionable insights.',
    '',
    '## Overview',
    `- Days tracked: ${stats.trackedDays}`,
  ];
  if (stats.avgMood != null) lines.push(`- Average mood: ${stats.avgMood}/10`);
  if (stats.avgSleepHours != null) lines.push(`- Average sleep: ${stats.avgSleepHours}h`);
  if (stats.medAdherence != null) lines.push(`- Medication adherence: ${stats.medAdherence}%`);
  if (stats.emotionFrequency.length > 0) {
    lines.push(`- Top emotions: ${stats.emotionFrequency.slice(0, 8).map((e) => `${e.label} (${e.count}x)`).join(', ')}`);
  }

  // Mood trend as readable table
  if (stats.moodTrend.length > 0) {
    lines.push('', '## Mood Trend (last 30 days)', '| Date | Mood |', '|------|------|');
    for (const d of stats.moodTrend.slice(-30)) {
      lines.push(`| ${d.date} | ${d.mood}/10 |`);
    }
  }

  // Sleep distribution
  if (stats.sleepDistribution.some((s) => s.count > 0)) {
    lines.push('', '## Sleep Quality Distribution');
    for (const s of stats.sleepDistribution) {
      if (s.count > 0) lines.push(`- ${s.label}: ${s.count} days`);
    }
  }

  // Activity distribution
  if (stats.activityDistribution.some((a) => a.count > 0)) {
    lines.push('', '## Activity Level Distribution');
    for (const a of stats.activityDistribution) {
      if (a.count > 0) lines.push(`- ${a.label}: ${a.count} days`);
    }
  }

  // Medications
  if (stats.medBreakdown.length > 0) {
    lines.push('', '## Medication Adherence');
    for (const m of stats.medBreakdown) {
      lines.push(`- ${m.name}: taken on ${m.taken} of ${m.total} tracked days (${m.pct}%)`);
    }
    const medsWithHistory = medications.filter((m) => m.dosageHistory.length > 0 || m.startedAt);
    if (medsWithHistory.length > 0) {
      lines.push('', '### Dosage Timeline');
      for (const m of medsWithHistory) {
        lines.push(`- ${m.name}: started ${startingDosage(m)} on ${m.startedAt}`);
        for (const h of m.dosageHistory.slice(1)) {
          lines.push(`  - Changed to ${h.dosage} on ${h.changedAt}`);
        }
      }
    }
  }

  // Detected patterns
  if (stats.patterns.length > 0) {
    lines.push('', '## Detected Patterns');
    for (const p of stats.patterns) {
      lines.push(`- ${p.text}`);
    }
  }

  lines.push('', '## What I\'d like to know');
  lines.push('1. Are there patterns in my mood over time?');
  lines.push('2. Do sleep quality and activity level correlate with mood?');
  lines.push('3. Any concerning trends I should discuss with a healthcare provider?');
  lines.push('4. Actionable suggestions based on the data.');
  lines.push('', '---', 'Generated by PrivacyNotes (privacynotes.app)');

  return lines.join('\n');
}

// ------------------------------------------------------------------
// Doctor PDF (printable HTML opened in new tab)
// ------------------------------------------------------------------

/** The dose a medication STARTED on. `dosage` is the CURRENT one, so
 *  printing it beside `startedAt` states a fact that never happened once
 *  the dose has changed. Templates created before dosageHistory was
 *  written fall back to it - the old value is genuinely unrecoverable. */
function startingDosage(m: MedicationTemplate): string {
  return m.dosageHistory[0]?.dosage || m.dosage || 'unknown dose';
}

/** Escape text destined for the printable report. Medication names and
 *  dosages are user-authored, and the report is written into a window
 *  opened with about:blank - which inherits the app's origin, so an
 *  unescaped name executed script next to the decrypted vault. */
function esc(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function generateDoctorReport(stats: TrackerStats, medications: MedicationTemplate[]): string {
  const moodSvgBars = stats.moodTrend.slice(-90).map((d, i) => {
    const h = (d.mood / 10) * 100;
    const color = d.mood <= 2 ? '#EF4444' : d.mood <= 4 ? '#F97316' : d.mood <= 6 ? '#EAB308' : d.mood <= 8 ? '#22C55E' : '#1E40AF';
    return `<rect x="${i * 8}" y="${100 - h}" width="6" height="${h}" fill="${color}" rx="1"/>`;
  }).join('');

  const sleepRows = stats.sleepDistribution
    .filter((s) => s.count > 0)
    .map((s) => `<tr><td>${s.label}</td><td>${s.count}</td></tr>`)
    .join('');

  const activityRows = stats.activityDistribution
    .filter((a) => a.count > 0)
    .map((a) => `<tr><td>${a.label}</td><td>${a.count}</td></tr>`)
    .join('');

  const medRows = stats.medBreakdown
    .map((m) => `<tr><td>${esc(m.name)}</td><td>${m.taken}/${m.total}</td><td>${m.pct}%</td></tr>`)
    .join('');

  const medTimeline = medications
    .filter((m) => m.dosageHistory.length > 0 || m.startedAt)
    .map((m) => {
      const events = [
        `<li>Started ${esc(startingDosage(m))} on ${esc(m.startedAt)}</li>`,
        ...m.dosageHistory
          .slice(1)
          .map((h) => `<li>Changed to ${esc(h.dosage)} on ${esc(h.changedAt)}</li>`),
      ].join('');
      return `<h4>${esc(m.name)}</h4><ul>${events}</ul>`;
    }).join('');

  const emotionList = stats.emotionFrequency.slice(0, 10)
    .map((e) => `${esc(e.label)} (${e.count}x)`).join(', ');

  const today = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  const earliest = stats.moodTrend[0]?.date ?? 'N/A';
  const latest = stats.moodTrend[stats.moodTrend.length - 1]?.date ?? 'N/A';

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Wellness Report</title>
<style>
body{font-family:-apple-system,sans-serif;max-width:700px;margin:40px auto;padding:0 20px;font-size:13px;color:#222}
h1{font-size:20px;margin-bottom:4px}h2{font-size:15px;margin-top:24px;border-bottom:1px solid #ddd;padding-bottom:4px}
h3{font-size:13px;margin-top:16px}h4{font-size:12px;margin:8px 0 4px}
table{border-collapse:collapse;width:100%;margin:8px 0}td,th{border:1px solid #ddd;padding:4px 8px;text-align:left;font-size:12px}
.meta{color:#666;font-size:11px}svg{display:block;margin:8px 0}
ul{margin:4px 0;padding-left:20px}li{font-size:12px;margin:2px 0}
.footer{margin-top:32px;border-top:1px solid #ddd;padding-top:8px;font-size:10px;color:#999}
@media print{body{margin:0;padding:20px}}
</style></head><body>
<h1>Mood & Wellness Report</h1>
<p class="meta">Generated ${today} | Period: ${earliest} to ${latest} | Days tracked: ${stats.trackedDays}</p>

<h2>Overview</h2>
<table><tr><th>Metric</th><th>Value</th></tr>
<tr><td>Average mood</td><td>${stats.avgMood ?? '-'}/10</td></tr>
<tr><td>Average sleep</td><td>${stats.avgSleepHours ?? '-'} hours</td></tr>
<tr><td>Medication adherence</td><td>${stats.medAdherence ?? '-'}%</td></tr>
<tr><td>Days tracked</td><td>${stats.trackedDays}</td></tr>
</table>

<h2>Mood Trend (last 90 days)</h2>
<svg width="${stats.moodTrend.slice(-90).length * 8}" height="100" viewBox="0 0 ${stats.moodTrend.slice(-90).length * 8} 100">${moodSvgBars}</svg>
<p class="meta">Red=1-2, Orange=3-4, Yellow=5-6, Green=7-8, Blue=9-10</p>

${sleepRows ? `<h2>Sleep Quality Distribution</h2><table><tr><th>Quality</th><th>Days</th></tr>${sleepRows}</table>` : ''}

${activityRows ? `<h2>Activity Level Distribution</h2><table><tr><th>Level</th><th>Days</th></tr>${activityRows}</table>` : ''}

${medRows ? `<h2>Medication Adherence</h2><p class="meta">Doses taken as a share of the journalled days on which each medication was being tracked. A day the medication was not marked counts as not taken. Days with no journal entry are not counted either way.</p><table><tr><th>Medication</th><th>Taken/Days</th><th>Rate</th></tr>${medRows}</table>` : ''}

${medTimeline ? `<h2>Medication Dosage Timeline</h2>${medTimeline}` : ''}

${emotionList ? `<h2>Most Frequent Emotions</h2><p>${emotionList}</p>` : ''}

${stats.patterns.length > 0 ? `<h2>Detected Patterns</h2><ul>${stats.patterns.map((p) => `<li>${esc(p.text)}</li>`).join('')}</ul>` : ''}

<p class="footer">Generated by PrivacyNotes &mdash; privacynotes.app</p>
<script>window.print();</script>
</body></html>`;
}

// ------------------------------------------------------------------
// JSON export
// ------------------------------------------------------------------

export function exportTrackerJSON(
  notes: LocalNote[],
  dateFrom?: string,
  dateTo?: string,
): string {
  const entries = extractEntries(notes);
  const filtered = entries.filter((e) => {
    if (dateFrom && e.date < dateFrom) return false;
    if (dateTo && e.date > dateTo) return false;
    return true;
  });
  return JSON.stringify(
    filtered.map((e) => ({ date: e.date, ...e.data })),
    null,
    2,
  );
}
