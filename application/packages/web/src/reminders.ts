import { useSyncExternalStore } from 'react';
import { toLocalIso } from './intlFormat';
import { isDemoMode } from './demo';
import { occurrencesOf, shiftDay, type Alert, type Schedule } from './schedule';

/**
 * Calendar reminders. Each device plans the alerts of the items it holds and
 * fires them itself: a phone hands the soonest 64 to the OS through the Tauri
 * notification plugin, so they ring while the app is closed; a desktop app
 * and a browser keep a timer while they run. The server never sees a title, a
 * time or a day, and no push exists.
 *
 * Two calls reach the OS, both in notesView/useReminders.tsx: the device run
 * cancels what left the plan and schedules the new one, and while alerts are
 * locked (no Pro, a refund) the plan is empty, so the same call cancels
 * everything; `cancelDeviceReminders` takes every alert off when the account
 * leaves the device. Nothing else schedules or cancels.
 * Spec: ops/docs/archive/calendar-pillar-spec.md (step 7, section 8)
 */

/** The iOS limit of pending local notifications; the plan never holds more. */
export const MAX_PLANNED = 64;
/** A snooze, in minutes. */
const SNOOZE_MINUTES = 10;
/** An alert this late still fires: a timer or a wake-up can run a little behind. */
const GRACE_MS = 60_000;
/** How far ahead the plan looks for occurrences. */
const HORIZON_DAYS = 400;

/** One item that can ring: its schedule, and what a reminder may show. */
export type ReminderItem = {
  id: string;
  schedule: Schedule;
  title: string;
  /** The folder name, the reminder's second line. */
  folder?: string;
  /** Behind its PIN right now: the reminder shows "Reminder" and the time. */
  gated: boolean;
  /** A contact's birthday. Its days come from `birthdayIn`, not from the
   *  schedule, which carries only the alerts. */
  birthday?: { month: number; day: number };
};

/** One alert the device is to fire. `key` is stable: item, occurrence, offset. */
export type PlannedAlert = {
  key: string;
  /** The 31-bit id the OS takes, derived from `key`. */
  nid: number;
  itemId: string;
  /** The day the occurrence starts. */
  occurrence: string;
  /** When it fires, in ms since the epoch. */
  at: number;
  /** When the occurrence starts (its time, or the start of the day). */
  startsAt: number;
};

/** A local moment on a day at `HH:MM`. A time inside a daylight-saving gap
 *  fires at the next valid minute, the hour the clock jumps to. */
export function localMoment(day: string, time: string): Date {
  const y = Number(day.slice(0, 4));
  const m = Number(day.slice(5, 7)) - 1;
  const d = Number(day.slice(8, 10));
  const h = Number(time.slice(0, 2));
  const mi = Number(time.slice(3, 5));
  const at = new Date(y, m, d, h, mi);
  if (at.getHours() === h && at.getMinutes() === mi) return at;
  // In a gap the engine moves forward by the gap; the first minute after the
  // gap is the earliest minute that still has the new offset.
  const off = at.getTimezoneOffset();
  let x = at.getTime();
  while (new Date(x - 60_000).getTimezoneOffset() === off) x -= 60_000;
  return new Date(x);
}

/** When one alert of one occurrence fires. An all-day item counts days before
 *  at a time; a timed item minutes before its start. A minutes alert on an
 *  all-day item counts from 09:00. */
export function alertInstant(day: string, time: string | undefined, alert: Alert): number {
  if ('days' in alert) return localMoment(shiftDay(day, -alert.days), alert.at).getTime();
  return localMoment(day, time ?? '09:00').getTime() - alert.before * 60_000;
}

/** The day a birthday falls on in a year, the day the calendar draws it
 *  (`birthdaysOn` in notesViewUtils.ts): 29 February is the 28th in a year
 *  without one, and a day the month never has falls on no day at all. */
export function birthdayIn(year: number, month: number, day: number): string | null {
  const last = new Date(year, month, 0).getDate();
  const d = month === 2 && day === 29 && last === 28 ? 28 : day;
  if (d > last) return null;
  return `${String(year).padStart(4, '0')}-${String(month).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
}

function birthdayDays(b: { month: number; day: number }, from: string, to: string): string[] {
  const out: string[] = [];
  for (let y = Number(from.slice(0, 4)); y <= Number(to.slice(0, 4)); y++) {
    const d = birthdayIn(y, b.month, b.day);
    if (d && d >= from && d <= to) out.push(d);
  }
  return out;
}

function alertKey(itemId: string, day: string, alert: Alert): string {
  return `${itemId}|${day}|${'before' in alert ? `b${alert.before}` : `d${alert.days}@${alert.at}`}`;
}

/** A stable 31-bit id for the OS (the plugin takes a 32-bit integer). FNV-1a. */
export function notificationId(key: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < key.length; i++) {
    h ^= key.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 1) || 1;
}

/**
 * The next alerts of every item, soonest first, `limit` at most. An alert in
 * the past never fires (no storm after a week offline), except one that came
 * due in the last minute. A snoozed alert fires at its snooze, once.
 */
export function planAlerts(items: readonly ReminderItem[], now: number, snoozes: Readonly<Record<string, number>> = {}, limit = MAX_PLANNED): PlannedAlert[] {
  const today = toLocalIso(new Date(now));
  const from = shiftDay(today, -28);
  const to = shiftDay(today, HORIZON_DAYS);
  const out: PlannedAlert[] = [];
  const keys = new Set<string>();
  for (const item of items) {
    const s = item.schedule;
    if (!s.alerts?.length) continue;
    const days = item.birthday ? birthdayDays(item.birthday, from, to) : occurrencesOf(s.day, s.repeat, from, to);
    let kept = 0;
    for (const day of days) {
      const startsAt = localMoment(day, s.time ?? '00:00').getTime();
      for (const alert of s.alerts) {
        const key = alertKey(item.id, day, alert);
        const at = snoozes[key] ?? alertInstant(day, s.time, alert);
        if (at < now - GRACE_MS) continue;
        keys.add(key);
        out.push({ key, nid: notificationId(key), itemId: item.id, occurrence: day, at, startsAt });
        kept++;
      }
      // Enough alerts of one item: the plan only keeps the soonest.
      if (kept >= limit) break;
    }
  }
  // A snooze of an alert the plan no longer holds (its day passed) still fires.
  for (const [key, at] of Object.entries(snoozes)) {
    if (keys.has(key) || at < now - GRACE_MS) continue;
    const [itemId = '', day = ''] = key.split('|');
    const item = items.find((i) => i.id === itemId);
    if (!item) continue;
    // An occurrence the series took out (deleted, detached, or a medication
    // dose already logged) never rings again, snoozed or not.
    if (item.schedule.repeat?.skip?.includes(day)) continue;
    out.push({ key, nid: notificationId(key), itemId, occurrence: day, at, startsAt: localMoment(day, item.schedule.time ?? '00:00').getTime() });
  }
  return out.sort((a, b) => a.at - b.at || a.key.localeCompare(b.key)).slice(0, limit);
}

/** The day the plan reaches, for "Reminders scheduled through …": the day of
 *  the last alert when the plan is full, or null when everything fits. */
export function plannedThrough(plan: readonly PlannedAlert[]): string | null {
  if (plan.length < MAX_PLANNED) return null;
  return toLocalIso(new Date(plan[plan.length - 1]!.at));
}

/** What a reminder shows. A PIN-guarded item, or titles switched off, shows
 *  only the word and the time: a lock screen is a public surface. Never the body. */
export function reminderText(
  item: Pick<ReminderItem, 'title' | 'folder' | 'gated'>,
  when: string,
  opts: { titles: boolean; reminder: string; untitled: string },
): { title: string; body: string } {
  if (!opts.titles || item.gated) return { title: opts.reminder, body: when };
  return { title: item.title || opts.untitled, body: [when, item.folder].filter(Boolean).join(' · ') };
}

// ── Device state: snoozes and the unseen badge ─────────────────────────

// The demo runs on the same origin as a real install, so it keeps its own keys.
const snoozeKey = () => (isDemoMode() ? 'privacynotes.demo.reminderSnoozes' : 'privacynotes.reminderSnoozes');
const unseenKey = () => (isDemoMode() ? 'privacynotes.demo.calendarUnseenAlerts' : 'privacynotes.calendarUnseenAlerts');

function readJson<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}
function writeJson(key: string, value: unknown) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Storage refused (a private window): the state lasts for this page.
  }
}

export function readSnoozes(now = Date.now()): Record<string, number> {
  const all = readJson<Record<string, number>>(snoozeKey(), {});
  // A snooze that fired more than a day ago is spent.
  return Object.fromEntries(Object.entries(all).filter(([, at]) => typeof at === 'number' && at > now - 86_400_000));
}

/** Snooze one alert: it fires again ten minutes from now. */
export function snooze(key: string, now = Date.now()): number {
  const at = now + SNOOZE_MINUTES * 60_000;
  writeJson(snoozeKey(), { ...readSnoozes(now), [key]: at });
  return at;
}

const unseenListeners = new Set<() => void>();
type Unseen = { day: string; ids: string[] };

function readUnseen(): Unseen {
  const v = readJson<Unseen>(unseenKey(), { day: '', ids: [] });
  // The next day clears it.
  return v.day === toLocalIso(new Date()) && Array.isArray(v.ids) ? v : { day: '', ids: [] };
}
let unseenCache = '';
function unseenSnapshot(): string {
  const v = readUnseen().ids.join(',');
  if (v !== unseenCache) unseenCache = v;
  return unseenCache;
}

/** An alert fired for an item nobody has opened yet: the Calendar row takes the bell. */
export function markUnseen(itemId: string) {
  const v = readUnseen();
  if (v.ids.includes(itemId)) return;
  writeJson(unseenKey(), { day: toLocalIso(new Date()), ids: [...v.ids, itemId] });
  unseenListeners.forEach((l) => l());
}

/** Opening the item clears its bell. */
export function markSeen(itemId: string) {
  const v = readUnseen();
  if (!v.ids.includes(itemId)) return;
  writeJson(unseenKey(), { day: v.day, ids: v.ids.filter((id) => id !== itemId) });
  unseenListeners.forEach((l) => l());
}

/** Whether a fired alert's item is still unopened today. */
export function useUnseenAlerts(): boolean {
  const ids = useSyncExternalStore(
    (l) => { unseenListeners.add(l); return () => { unseenListeners.delete(l); }; },
    unseenSnapshot,
  );
  return ids !== '';
}

