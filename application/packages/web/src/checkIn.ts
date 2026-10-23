import { answeredHabitIds, customHabitsNow, habitLabel, isWatchHabit } from './habitList';
import { createContext, useSyncExternalStore } from 'react';
import i18n from './i18n';
import { isDemoMode } from './demo';
import type { LocalNote } from './db';
import { journalDateOf } from './notesViewUtils';
import { toLocalIso } from './intlFormat';
import { shiftDay } from './schedule';
import type { ReminderItem } from './reminders';
import {
  EMOTION_TAGS,
  MOOD_ANCHORS,
  hasLoggedTrackers,
  weightToDisplay,
  type ActivityLevel,
  type FactorDef,
  type JournalTrackerData,
  type SleepQuality,
  type TrackerSettings,
} from './trackerTypes';
import { moodAnchor } from './moodMark';
import { waterText, type TrackerUnits } from './trackerExport';

/**
 * The daily check-in (GitHub #439): which entry a day's check-in writes to,
 * how its values read on one line, the device-local "Skip today", and the
 * device-local daily reminder.
 * Spec: ops/issues/0439.md (Spec, Reminder plan)
 */

/** The entry a check-in for `day` reads and writes: the newest live journal
 *  entry of that day that holds a mood, else the newest that holds any
 *  logged value, else the newest one. A second entry written that evening
 *  then takes the values of a day with none, and never hides a mood logged
 *  that morning from the card and the reminder. */
export function checkInEntry(notes: readonly LocalNote[], day: string): LocalNote | undefined {
  const best: (LocalNote | undefined)[] = [undefined, undefined, undefined];
  for (const n of notes) {
    if (n.type !== 'journal' || n.deleted !== 0 || n.trashed !== 0) continue;
    if (journalDateOf(n) !== day) continue;
    const trackers = n.trackers as Record<string, unknown> | undefined;
    const rank = typeof trackers?.mood === 'number' ? 0 : hasLoggedTrackers(trackers, false) ? 1 : 2;
    const held = best[rank];
    if (!held || n.createdAt > held.createdAt) best[rank] = n;
  }
  return best[0] ?? best[1] ?? best[2];
}

/**
 * The check-in run that ends today, and the last seven days, oldest first
 * and today last. A check-in day is a day whose entry holds a tracker value
 * (the streaks plan's definition), so a sleep-only day keeps the run. An
 * entry the PIN guards is not read, so its day does not count. The run has
 * no cap; the week is always seven days, so a long run never widens the strip.
 * Spec: ops/docs/plans/milestones-and-streaks.md (D2, section 4)
 */
export function checkInStreak(
  notes: readonly LocalNote[],
  today: string,
  isGated: (n: LocalNote) => boolean,
): { run: number; week: boolean[] } {
  const days = new Set<string>();
  for (const n of notes) {
    if (n.type !== 'journal' || n.deleted !== 0 || n.trashed !== 0 || isGated(n)) continue;
    if (!hasLoggedTrackers(n.trackers as Record<string, unknown> | undefined)) continue;
    const d = journalDateOf(n);
    if (d) days.add(d);
  }
  let run = 0;
  for (let d = today; days.has(d); d = shiftDay(d, -1)) run++;
  const week = Array.from({ length: 7 }, (_, i) => days.has(shiftDay(today, i - 6)));
  return { run, week };
}

/** The anchor word of a mood's band, capitalised to open a line: "Good"
 *  for a 7 or an 8. */
export function moodWord(mood: number): string {
  const anchor = moodAnchor(mood);
  const word = MOOD_ANCHORS[anchor] != null ? i18n.t(`trackers:mood.anchor.${anchor}`) : `${mood}/10`;
  return word.charAt(0).toLocaleUpperCase() + word.slice(1);
}

/** The units the check-in rows of a list print their numbers in. A context
 *  for the reason `chipFilter.ts` gives: the rows sit far below every list
 *  pane, and NotesView provides a value with a stable identity. */
export const CheckInUnitsContext = createContext<TrackerUnits>({});

/**
 * The values a day holds besides its mood, short and in the pill order: the
 * one-line summary of a folded card and of a check-in row. Only the trackers
 * switched on in the setup appear, as on the pills; custom trackers are left
 * out because their names are the person's and would crowd one line.
 */
export function checkInParts(data: JournalTrackerData, settings: TrackerSettings, factors: readonly FactorDef[]): string[] {
  const t = (k: string, o?: Record<string, unknown>) => i18n.t(`trackers:${k}`, o ?? {});
  const on = (id: string) => settings.activeBuiltins.includes(id as never);
  const out: string[] = [];
  if (on('emotions') && data.emotions?.length) {
    const first = data.emotions[0]!;
    out.push(data.emotions.length === 1 && EMOTION_TAGS.some((e) => e.key === first)
      ? t(`emotions.tags.${first}`)
      : t('emotions.count', { count: data.emotions.length }));
  }
  if (on('factors') && data.factors?.length) {
    // Two names fit a line; past that, or without the list, the count.
    const names = data.factors.map((id) => factors.find((f) => f.id === id)?.name).filter((n): n is string => !!n);
    out.push(names.length > 0 && names.length <= 2 && names.length === data.factors.length
      ? names.join(', ')
      : t('factors.count', { count: data.factors.length }));
  }
  if (on('habits') && answeredHabitIds(data.habits, customHabitsNow()).length > 0) {
    // The things done, by name when one or two habits to build; past that,
    // or when a habit to watch is among them, the yes count over the
    // answered questions, so a watched habit is never named on this line.
    const custom = customHabitsNow();
    const answered = answeredHabitIds(data.habits, custom);
    const yes = answered.filter((id) => data.habits?.[id] === true);
    const nameable = yes.length > 0 && yes.length <= 2 && !yes.some((id) => isWatchHabit(id, custom));
    out.push(nameable
      ? yes.map((id) => habitLabel(id, custom)).join(', ')
      : t('habits.count', { yes: yes.length, total: answered.length }));
  }
  if (on('sleep') && data.sleep) {
    const q = t(`sleep.quality.${data.sleep.quality as SleepQuality}`);
    out.push(data.sleep.hours != null ? `${q} (${data.sleep.hours}${t('units.hoursSuffix')})` : q);
  }
  if (on('activity') && data.activity) out.push(t(`activity.level.${data.activity as ActivityLevel}`));
  const scale = (id: 'energy' | 'focus' | 'pain', max: number) => {
    const v = data[id];
    if (on(id) && v != null) out.push(`${t(`labels.${id}`)} ${v}/${max}`);
  };
  scale('energy', 10);
  scale('focus', 10);
  scale('pain', 10);
  if (on('medication') && data.medications?.length) out.push(t('medication.takenCount', { count: data.medications.filter((m) => m.status === 'taken').length }));
  if (on('steps') && data.steps != null) out.push(`${data.steps} ${t('units.steps', { count: data.steps })}`);
  if (on('weight') && data.weight != null) out.push(`${weightToDisplay(data.weight, settings.weightUnit)}${t(`units.${settings.weightUnit}`)}`);
  if (on('water') && data.water != null) out.push(waterText(data.water, settings.waterUnit));
  return out;
}

// ------------------------------------------------------------------
// Skip today: this device only, until the next local day.
// ------------------------------------------------------------------

function skipKey(): string {
  return isDemoMode() ? 'privacynotes.demo.checkInSkipped' : 'privacynotes.checkInSkipped';
}
const listeners = new Set<() => void>();
/** The skip when storage refuses it (a private window): this page only. */
let pageSkip: string | null = null;
function readSkipped(): string | null {
  try {
    return localStorage.getItem(skipKey()) ?? pageSkip;
  } catch {
    return pageSkip;
  }
}
function subscribe(l: () => void): () => void {
  listeners.add(l);
  return () => { listeners.delete(l); };
}

/** Whether the card is skipped for `today` on this device. A skip of an
 *  earlier day has lapsed, so the card comes back at midnight by itself. */
export function useCheckInSkipped(today: string): boolean {
  return useSyncExternalStore(subscribe, readSkipped) === today;
}

/** Skip the card for today, or bring it back (`false`). */
export function setCheckInSkipped(on: boolean): void {
  pageSkip = on ? toLocalIso(new Date()) : null;
  try {
    if (on) localStorage.setItem(skipKey(), toLocalIso(new Date()));
    else localStorage.removeItem(skipKey());
  } catch {
    // Storage refused (a private window): `pageSkip` holds it for this page.
  }
  listeners.forEach((l) => l());
}

// ------------------------------------------------------------------
// The daily reminder: this device only, one time per day, off by default.
// ------------------------------------------------------------------

/** The item id the reminder rings under. Never a note id. */
export const CHECK_IN_REMINDER_ID = 'check-in';
/** The time the first switch-on takes. */
export const DEFAULT_CHECK_IN_TIME = '20:00';

function reminderKey(): string {
  return isDemoMode() ? 'privacynotes.demo.checkInReminder' : 'privacynotes.checkInReminder';
}
const reminderListeners = new Set<() => void>();
/** The time when storage refuses it (a private window): this page only. */
let pageReminder: string | null = null;
function readReminder(): string | null {
  try {
    const v = localStorage.getItem(reminderKey()) ?? pageReminder;
    return v && /^\d\d:\d\d$/.test(v) ? v : null;
  } catch {
    return pageReminder;
  }
}

/** The reminder time of this device, `HH:MM`, or null while it is off. */
export function useCheckInReminder(): string | null {
  return useSyncExternalStore(
    (l) => { reminderListeners.add(l); return () => { reminderListeners.delete(l); }; },
    readReminder,
  );
}

/** Set the time, or switch the reminder off (`null`). */
export function setCheckInReminder(time: string | null): void {
  pageReminder = time;
  try {
    if (time) localStorage.setItem(reminderKey(), time);
    else localStorage.removeItem(reminderKey());
  } catch {
    // Storage refused (a private window): `pageReminder` holds it for this page.
  }
  reminderListeners.forEach((l) => l());
}

/**
 * The reminder as one item of the device's reminder plan (useReminders.tsx):
 * every day at `time`, from today, or from tomorrow once today is `done`
 * (its entry holds a mood, or the day was skipped). The plan drops a time
 * that passed by itself, and the key of a day survives a re-plan.
 */
export function checkInReminderItem(time: string, today: string, done: boolean): ReminderItem {
  return {
    id: CHECK_IN_REMINDER_ID,
    schedule: { day: done ? shiftDay(today, 1) : today, time, repeat: { every: 'day', interval: 1 }, alerts: [{ before: 0 }] },
    title: '',
    gated: false,
  };
}

/** Whether a day's entry holds a mood. One behind a gate counts as none:
 *  the card never reads it either. The skip is `useCheckInSkipped`. */
export function checkInLogged(notes: readonly LocalNote[], day: string, isGated: (n: LocalNote) => boolean): boolean {
  const entry = checkInEntry(notes, day);
  if (!entry || isGated(entry)) return false;
  return typeof (entry.trackers as { mood?: unknown } | undefined)?.mood === 'number';
}
