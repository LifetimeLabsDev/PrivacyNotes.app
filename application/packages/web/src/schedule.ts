import type { NoteType } from '@notes/shared';

/**
 * The schedule of a dated item: its day, an end day, a time, an end time, a
 * repeat and alerts, all kept as keys in `trackers` so they sync and merge per
 * key like every tracker value. Pure: no Date in the local zone, no i18n, so
 * the rules are testable as a table of dates.
 *
 * Who may hold what: every dated type a day, a time and alerts; a note, a task
 * list and an event an end day; an event alone a repeat, because a repeating
 * task list would share one checklist and a repeating journal entry would move
 * its journal day ("a series is an event"). The index honors what it finds on
 * any type except those two rules.
 * Spec: ops/docs/plans/calendar-pillar-spec.md (section 4)
 */

export type RepeatUnit = 'day' | 'week' | 'month' | 'year';

export type Repeat = {
  every: RepeatUnit;
  interval: number;
  /** 0..6, 0 = Sunday. A weekly repeat on these days; the start day's weekday when absent. */
  weekdays?: number[];
  /** A monthly repeat on the day of the month, or on the Nth weekday of the start day. */
  monthly?: 'day' | 'weekday';
  /** With `monthly: 'weekday'`: 1..4, or -1 for the last. The start day's own when absent. */
  nth?: 1 | 2 | 3 | 4 | -1;
  /** The last day an occurrence may start on. */
  until?: string;
  /** How many occurrences the series has. Skipped days still count. */
  count?: number;
  /** Occurrence days taken out of the series (deleted, or detached into their own item). */
  skip?: string[];
};

/** Minutes before a timed item, or days before an all-day item at a time of day. */
export type Alert = { before: number } | { days: number; at: string };

export type Schedule = {
  day: string;
  end?: string;
  time?: string;
  timeEnd?: string;
  repeat?: Repeat;
  alerts?: Alert[];
};

/** The tracker keys a schedule writes. */
export const SCHEDULE_KEYS = ['journalDate', 'dateEnd', 'time', 'timeEnd', 'repeat', 'alerts', 'detachedFrom'] as const;

/**
 * The tracker key that names the event an item was imported from (`{ uid }`
 * or `{ uid, rid }`). An import skips a series whose UID the vault holds, and
 * the .ics writer reuses it as the UID, so a copy of an item must never carry
 * it: the copy is another event.
 * Spec: ops/docs/plans/google-calendar-import.md (section 4.10)
 */
export const SOURCE_IDENTITY_KEY = 'ics';

/** Tracker values without the source identity, for a copy of an item. */
export function withoutSourceIdentity(trackers: Record<string, unknown>): Record<string, unknown> {
  if (!(SOURCE_IDENTITY_KEY in trackers)) return trackers;
  const { [SOURCE_IDENTITY_KEY]: _, ...rest } = trackers;
  return rest;
}

/** The most alerts an item keeps. */
export const MAX_ALERTS = 5;
/** The longest span the calendar draws, so a typo of a year never fills a loop. */
const MAX_SPAN_DAYS = 366;
/** The most periods an expansion walks, a guard for a series nobody can see the end of. */
const MAX_PERIODS = 20000;

// ── Days as numbers ───────────────────────────────────────────────

const DAY_MS = 86_400_000;

/** A local ISO day as a count of days, through UTC so no time zone moves it. */
export function dayNumber(day: string): number {
  return Math.round(Date.UTC(Number(day.slice(0, 4)), Number(day.slice(5, 7)) - 1, Number(day.slice(8, 10))) / DAY_MS);
}

function dayFromNumber(n: number): string {
  const d = new Date(n * DAY_MS);
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}-${String(d.getUTCDate()).padStart(2, '0')}`;
}

export function shiftDay(day: string, n: number): string {
  return dayFromNumber(dayNumber(day) + n);
}

/** 0 = Sunday. */
export function weekdayOf(day: string): number {
  return new Date(dayNumber(day) * DAY_MS).getUTCDay();
}

function isDay(v: unknown): v is string {
  if (typeof v !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(v)) return false;
  return dayFromNumber(dayNumber(v)) === v;
}

export function isTime(v: unknown): v is string {
  return typeof v === 'string' && /^([01]\d|2[0-3]):[0-5]\d$/.test(v);
}

/** Minutes after midnight of an `HH:MM` time. */
export function minutesOf(time: string): number {
  return Number(time.slice(0, 2)) * 60 + Number(time.slice(3, 5));
}

export function timeFromMinutes(m: number): string {
  const v = ((m % 1440) + 1440) % 1440;
  return `${String(Math.floor(v / 60)).padStart(2, '0')}:${String(v % 60).padStart(2, '0')}`;
}

// ── Validation ────────────────────────────────────────────────────

function isRepeat(v: unknown): v is Repeat {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return false;
  const r = v as Record<string, unknown>;
  if (!['day', 'week', 'month', 'year'].includes(r.every as string)) return false;
  if (!Number.isInteger(r.interval) || (r.interval as number) < 1 || (r.interval as number) > 999) return false;
  if (r.weekdays !== undefined && (!Array.isArray(r.weekdays) || r.weekdays.length === 0
    || !r.weekdays.every((w) => Number.isInteger(w) && w >= 0 && w <= 6))) return false;
  if (r.monthly !== undefined && r.monthly !== 'day' && r.monthly !== 'weekday') return false;
  if (r.nth !== undefined && ![1, 2, 3, 4, -1].includes(r.nth as number)) return false;
  if (r.until !== undefined && !isDay(r.until)) return false;
  if (r.count !== undefined && (!Number.isInteger(r.count) || (r.count as number) < 1)) return false;
  if (r.skip !== undefined && (!Array.isArray(r.skip) || !r.skip.every(isDay))) return false;
  return true;
}

function isAlert(v: unknown): v is Alert {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return false;
  const a = v as Record<string, unknown>;
  if ('before' in a) return Number.isInteger(a.before) && (a.before as number) >= 0 && (a.before as number) <= 60 * 24 * 28;
  return Number.isInteger(a.days) && (a.days as number) >= 0 && (a.days as number) <= 28 && isTime(a.at);
}

/** Whether a set of tracker values holds a schedule the calendar can draw. */
export function isValidSchedule(trackers: Record<string, unknown> | undefined): boolean {
  if (!trackers || !isDay(trackers.journalDate)) return false;
  const t = trackers;
  if (t.dateEnd !== undefined && (!isDay(t.dateEnd) || (t.dateEnd as string) <= (t.journalDate as string))) return false;
  if (t.time !== undefined && !isTime(t.time)) return false;
  if (t.timeEnd !== undefined && (!isTime(t.timeEnd) || t.time === undefined || t.timeEnd === t.time)) return false;
  if (t.repeat !== undefined && !isRepeat(t.repeat)) return false;
  if (t.alerts !== undefined && (!Array.isArray(t.alerts) || t.alerts.length > MAX_ALERTS || !t.alerts.every(isAlert))) return false;
  return true;
}

/**
 * The tracker values with every schedule key that does not hold dropped: an
 * end day on or before the day, an end time with no start or equal to it, a
 * time that is not one, alerts past five or of no known shape, and a repeat on
 * anything but an event. Runs where a merged or edited item is written back,
 * so a schedule that no longer holds never persists. Keys it does not own pass
 * through. A journal entry keeps an end day it carries, unread, so a convert
 * back restores it.
 */
export function normalizeSchedule(trackers: Record<string, unknown> | undefined, type: NoteType | undefined): Record<string, unknown> | undefined {
  if (!trackers) return trackers;
  const t: Record<string, unknown> = { ...trackers };
  const day = isDay(t.journalDate) ? t.journalDate : null;
  if (t.dateEnd !== undefined && (!isDay(t.dateEnd) || day === null || t.dateEnd <= day
    || dayNumber(t.dateEnd) - dayNumber(day) > MAX_SPAN_DAYS)) delete t.dateEnd;
  if (t.time !== undefined && !isTime(t.time)) delete t.time;
  if (t.timeEnd !== undefined && (!isTime(t.timeEnd) || t.time === undefined || t.timeEnd === t.time)) delete t.timeEnd;
  if (t.alerts !== undefined) {
    const kept = Array.isArray(t.alerts) ? t.alerts.filter(isAlert).slice(0, MAX_ALERTS) : [];
    if (kept.length) t.alerts = kept;
    else delete t.alerts;
  }
  if (t.repeat !== undefined && ((type ?? 'note') !== 'event' || !isRepeat(t.repeat))) delete t.repeat;
  if (t.detachedFrom !== undefined && typeof t.detachedFrom !== 'string') delete t.detachedFrom;
  return t;
}

/**
 * The schedule an item's tracker values hold, read by type: a journal entry
 * never has an end day or a repeat, and only an event repeats. Null without a
 * day. The day of a journal entry from before the field is the caller's
 * (`entryDayOf`), passed as `day`.
 */
export function scheduleOf(trackers: Record<string, unknown> | undefined, type: NoteType | undefined, day?: string | null): Schedule | null {
  const t = trackers ?? {};
  const start = day ?? (isDay(t.journalDate) ? t.journalDate : null);
  if (!start) return null;
  const s: Schedule = { day: start };
  const journal = type === 'journal';
  if (!journal && isDay(t.dateEnd) && t.dateEnd > start && dayNumber(t.dateEnd) - dayNumber(start) <= MAX_SPAN_DAYS) s.end = t.dateEnd;
  if (isTime(t.time)) {
    s.time = t.time;
    if (isTime(t.timeEnd) && t.timeEnd !== t.time) s.timeEnd = t.timeEnd;
  }
  if (type === 'event' && isRepeat(t.repeat)) s.repeat = t.repeat;
  if (Array.isArray(t.alerts)) {
    const alerts = t.alerts.filter(isAlert).slice(0, MAX_ALERTS);
    if (alerts.length) s.alerts = alerts;
  }
  return s;
}

/**
 * Whether an item goes into the .ics export: an event, a note or a task list
 * with a schedule, not deleted and not in the trash. A journal entry is a
 * diary with exports of its own, and a calendar file is made to be uploaded
 * elsewhere. Spec: ops/docs/plans/google-calendar-import.md (section 5.1)
 */
export function goesToCalendarFile(n: { type?: NoteType; trackers?: Record<string, unknown>; deleted?: number; trashed?: number }): boolean {
  if (n.deleted === 1 || n.trashed === 1) return false;
  const type = n.type ?? 'note';
  if (type !== 'event' && type !== 'note' && type !== 'task') return false;
  return scheduleOf(n.trackers, type) !== null;
}

/** How many days after its first day an item ends: 0 for one day. */
export function spanLength(s: Pick<Schedule, 'day' | 'end'>): number {
  return s.end ? dayNumber(s.end) - dayNumber(s.day) : 0;
}

/**
 * The tracker values with the schedule fields set: `undefined` removes a
 * field, a missing key leaves it. Then `normalizeSchedule`, so a patch cannot
 * write a schedule that does not hold.
 */
export function withSchedule(
  trackers: Record<string, unknown> | undefined,
  type: NoteType | undefined,
  patch: Partial<{ day: string; end: string | undefined; time: string | undefined; timeEnd: string | undefined; repeat: Repeat | undefined; alerts: Alert[] | undefined }>,
): Record<string, unknown> {
  const t: Record<string, unknown> = { ...(trackers ?? {}) };
  const set = (key: string, v: unknown) => {
    if (v === undefined) delete t[key];
    else t[key] = v;
  };
  if ('day' in patch && patch.day) t.journalDate = patch.day;
  if ('end' in patch) set('dateEnd', patch.end);
  if ('time' in patch) set('time', patch.time);
  if ('timeEnd' in patch) set('timeEnd', patch.timeEnd);
  if ('repeat' in patch) set('repeat', patch.repeat);
  if ('alerts' in patch) set('alerts', patch.alerts && patch.alerts.length ? patch.alerts : undefined);
  return normalizeSchedule(t, type) ?? {};
}

// ── Repeats ───────────────────────────────────────────────────────

function ymd(day: string): [number, number, number] {
  return [Number(day.slice(0, 4)), Number(day.slice(5, 7)), Number(day.slice(8, 10))];
}

function daysInMonth(year: number, month: number): number {
  return new Date(Date.UTC(year, month, 0)).getUTCDate();
}

function isoOf(year: number, month: number, date: number): string {
  return `${year}-${String(month).padStart(2, '0')}-${String(date).padStart(2, '0')}`;
}

/** Which weekday of its month a day is: 1 for the first, 5 for a fifth. */
export function nthOf(day: string): number {
  return Math.floor((ymd(day)[2] - 1) / 7) + 1;
}

/** Whether a day is the last of its weekday in its month. */
export function isLastWeekdayOfMonth(day: string): boolean {
  const [y, m, d] = ymd(day);
  return d + 7 > daysInMonth(y, m);
}

/** The Nth (or, with -1, the last) `weekday` of a month, or null when the month has no fifth one. */
function nthWeekdayOfMonth(year: number, month: number, weekday: number, nth: number): string | null {
  const first = weekdayOf(isoOf(year, month, 1));
  const firstDate = 1 + ((weekday - first + 7) % 7);
  const len = daysInMonth(year, month);
  if (nth === -1) {
    let d = firstDate;
    while (d + 7 <= len) d += 7;
    return isoOf(year, month, d);
  }
  const d = firstDate + (nth - 1) * 7;
  return d <= len ? isoOf(year, month, d) : null;
}

/** The candidate start days of one period of a series, in order. */
function periodDays(start: string, r: Repeat, k: number): string[] {
  const [y, m, d] = ymd(start);
  const step = k * r.interval;
  switch (r.every) {
    case 'day':
      return [shiftDay(start, step)];
    case 'week': {
      const weekStart = shiftDay(start, -weekdayOf(start) + step * 7);
      const days = [...new Set(r.weekdays && r.weekdays.length ? r.weekdays : [weekdayOf(start)])].sort((a, b) => a - b);
      return days.map((w) => shiftDay(weekStart, w));
    }
    case 'month': {
      const total = (m - 1) + step;
      const year = y + Math.floor(total / 12);
      const month = (total % 12) + 1;
      if (r.monthly === 'weekday') {
        const nth = r.nth ?? (nthOf(start) > 4 ? -1 : nthOf(start));
        const hit = nthWeekdayOfMonth(year, month, weekdayOf(start), nth);
        return hit ? [hit] : [];
      }
      // A month without the day (the 31st) is skipped, as Google does.
      return d <= daysInMonth(year, month) ? [isoOf(year, month, d)] : [];
    }
    case 'year': {
      const year = y + step;
      return d <= daysInMonth(year, m) ? [isoOf(year, m, d)] : [];
    }
  }
}

/** The period that holds a day, counted from the start, before any interval. */
function periodsBetween(start: string, day: string, every: RepeatUnit): number {
  const [y1, m1] = ymd(start);
  const [y2, m2] = ymd(day);
  switch (every) {
    case 'day': return dayNumber(day) - dayNumber(start);
    case 'week': return Math.floor((dayNumber(day) - weekdayOf(day) - (dayNumber(start) - weekdayOf(start))) / 7);
    case 'month': return (y2 - y1) * 12 + (m2 - m1);
    case 'year': return y2 - y1;
  }
}

/**
 * How many occurrences start in the periods before period `k` (k > 0), the
 * start day included, counted rather than walked: every period after the
 * first holds the same number, except a monthly series on the 29th to 31st
 * and a yearly one on 29 February, whose periods are checked one by one with
 * no day built.
 */
function occurrencesBeforePeriod(start: string, r: Repeat, k: number): number {
  const first = 1 + periodDays(start, r, 0).filter((d) => d > start).length;
  const [y, m, d] = ymd(start);
  if (r.every === 'month' && r.monthly !== 'weekday' && d > 28) {
    let n = first;
    for (let j = 1; j < k; j++) {
      const total = (m - 1) + j * r.interval;
      if (d <= daysInMonth(y + Math.floor(total / 12), (total % 12) + 1)) n++;
    }
    return n;
  }
  if (r.every === 'year' && m === 2 && d === 29) {
    let n = first;
    for (let j = 1; j < k; j++) if (daysInMonth(y + j * r.interval, 2) === 29) n++;
    return n;
  }
  const per = r.every === 'week' ? new Set(r.weekdays && r.weekdays.length ? r.weekdays : [weekdayOf(start)]).size : 1;
  return first + (k - 1) * per;
}

/**
 * The days an item's occurrences start on, inside `from`..`to` (both
 * included), in order. Without a repeat that is its one day when it falls
 * inside. The first occurrence is always the start day, even when a weekly
 * repeat names other weekdays; `count` counts occurrences from it, skipped
 * days included, as RFC 5545 does; `until` is the last day one may start on;
 * a month without the day is skipped. A window far from the start jumps to
 * the period before it, and a counted series adds the occurrences it jumped
 * over, so the work is the window's, not the series' age.
 */
export function occurrencesOf(start: string, repeat: Repeat | undefined, from: string, to: string): string[] {
  if (to < from) return [];
  if (!repeat) return start >= from && start <= to ? [start] : [];
  const skip = new Set(repeat.skip ?? []);
  const out: string[] = [];
  const last = repeat.until && repeat.until < to ? repeat.until : to;
  let k = 0;
  let seen = 0;
  if (from > start) {
    k = Math.max(0, Math.floor(periodsBetween(start, from, repeat.every) / repeat.interval) - 1);
    if (k > 0 && repeat.count !== undefined) {
      seen = occurrencesBeforePeriod(start, repeat, k);
      if (seen >= repeat.count) return out;
    }
  }
  // The start day is an occurrence even when the rule would not produce it.
  if (k === 0 && start <= last) {
    seen = 1;
    if (start >= from && !skip.has(start)) out.push(start);
    if (repeat.count === 1) return out;
  }
  for (let walked = 0; walked < MAX_PERIODS; walked++, k++) {
    let past = false;
    for (const day of periodDays(start, repeat, k)) {
      if (day <= start) continue;
      if (day > last) { past = true; break; }
      seen++;
      if (repeat.count !== undefined && seen > repeat.count) return out;
      if (day >= from && !skip.has(day)) out.push(day);
    }
    if (past) break;
  }
  return out;
}

/** How many occurrences of a series start before a day (skipped ones
 *  counted), from the period before the day's on. */
function occurrencesBefore(start: string, repeat: Repeat, day: string): number {
  if (day <= start) return 0;
  const r: Repeat = { ...repeat, skip: [] };
  delete r.count;
  let k = Math.max(0, Math.floor(periodsBetween(start, day, r.every) / r.interval) - 1);
  let n = k > 0 ? occurrencesBeforePeriod(start, r, k) : 1;
  const cap = (v: number) => Math.min(v, repeat.count ?? v);
  for (let walked = 0; walked < MAX_PERIODS; walked++, k++) {
    for (const d of periodDays(start, r, k)) {
      if (d <= start) continue;
      if (d >= day || (r.until && d > r.until)) return cap(n);
      n++;
    }
  }
  return cap(n);
}

/**
 * The day of the last occurrence of a series that ends, by a count, an end
 * day or both (whichever comes first, skipped days counted); null when it
 * never ends. Found by halving on the counted occurrences, so an old series
 * costs no walk from its start.
 */
export function lastOccurrence(start: string, repeat: Repeat): string | null {
  const open: Repeat = { ...repeat, skip: [] };
  delete open.count;
  delete open.until;
  const before = (n: number) => occurrencesBefore(start, open, dayFromNumber(n));
  const first = dayNumber(start);
  const ceiling = dayNumber('9999-12-31');
  let target = repeat.count ?? Infinity;
  // An end on the last day the calendar holds bounds nothing it can count past.
  if (repeat.until && dayNumber(repeat.until) < ceiling) target = Math.min(target, repeat.until < start ? 0 : before(dayNumber(repeat.until) + 1));
  if (target === Infinity) return null;
  if (target <= 1) return start;
  // The first day before which `target` occurrences start is the day after the last.
  let lo = first + 1;
  let hi = first + 1;
  while (hi < ceiling && before(hi) < target) hi = Math.min(ceiling, first + (hi - first) * 2);
  if (before(hi) < target) return null;
  while (lo < hi) {
    const mid = Math.floor((lo + hi) / 2);
    if (before(mid) >= target) hi = mid;
    else lo = mid + 1;
  }
  return dayFromNumber(lo - 1);
}

/**
 * The day when it is a live occurrence of an item's repeating series: not
 * skipped, inside its count and its end. Null otherwise, and for an item that
 * does not repeat. The occurrence a screen remembers is read through this, so
 * a day the series lost since (a skip, a shorter count, a move) acts on nothing.
 */
export function liveOccurrence(trackers: Record<string, unknown> | undefined, type: NoteType | undefined, day: string | null | undefined): string | null {
  if (!day) return null;
  const s = scheduleOf(trackers, type);
  return s?.repeat && occurrencesOf(s.day, s.repeat, day, day).length === 1 ? day : null;
}

/**
 * The next occurrence start on or after a day, or null when the series has
 * ended. Looks a few years ahead at most.
 */
export function nextOccurrence(start: string, repeat: Repeat | undefined, day: string): string | null {
  for (let span = 62; span <= 62 * 64; span *= 4) {
    const hit = occurrencesOf(start, repeat, day, shiftDay(day, span))[0];
    if (hit) return hit;
    if (!repeat) return null;
  }
  return null;
}

// ── Editing one occurrence of a series ────────────────────────────

/**
 * "This occurrence": the series skips the day, and the caller makes a copy
 * that holds the day alone (`detachedFrom` names the series). Returns the
 * series' new repeat and the copy's tracker values.
 */
export function detachOccurrence(
  trackers: Record<string, unknown>,
  seriesId: string,
  occurrence: string,
): { seriesRepeat: Repeat; copyTrackers: Record<string, unknown> } | null {
  const s = scheduleOf(trackers, 'event');
  if (!s?.repeat) return null;
  const seriesRepeat: Repeat = { ...s.repeat, skip: [...new Set([...(s.repeat.skip ?? []), occurrence])].sort() };
  const len = spanLength(s);
  const copy: Record<string, unknown> = { ...withoutSourceIdentity(trackers), journalDate: occurrence, detachedFrom: seriesId };
  delete copy.repeat;
  if (len > 0) copy.dateEnd = shiftDay(occurrence, len);
  return { seriesRepeat, copyTrackers: normalizeSchedule(copy, 'event') ?? {} };
}

/**
 * "This and following": the series ends the day before, and the caller makes
 * a new series that starts on the occurrence with the remaining count. When
 * the occurrence is the first, nothing splits: the whole series is the edit.
 */
export function splitSeries(
  trackers: Record<string, unknown>,
  occurrence: string,
): { seriesRepeat: Repeat; restTrackers: Record<string, unknown> } | null {
  const s = scheduleOf(trackers, 'event');
  if (!s?.repeat || occurrence <= s.day) return null;
  const before = occurrencesBefore(s.day, s.repeat, occurrence);
  const seriesRepeat: Repeat = { ...s.repeat, until: shiftDay(occurrence, -1) };
  delete seriesRepeat.count;
  if (s.repeat.skip) seriesRepeat.skip = s.repeat.skip.filter((d) => d < occurrence);
  if (!seriesRepeat.skip?.length) delete seriesRepeat.skip;
  const rest: Repeat = { ...s.repeat };
  if (s.repeat.count !== undefined) rest.count = Math.max(1, s.repeat.count - before);
  if (s.repeat.skip) rest.skip = s.repeat.skip.filter((d) => d >= occurrence);
  if (!rest.skip?.length) delete rest.skip;
  const len = spanLength(s);
  const restTrackers: Record<string, unknown> = { ...withoutSourceIdentity(trackers), journalDate: occurrence, repeat: rest };
  if (len > 0) restTrackers.dateEnd = shiftDay(occurrence, len);
  delete restTrackers.detachedFrom;
  return { seriesRepeat, restTrackers: normalizeSchedule(restTrackers, 'event') ?? {} };
}

// ── One edit, applied to an item or an occurrence ────────────────

/**
 * A schedule change as the calendar asks for it, relative to the occurrence
 * it was made on: move by days (a drag, a new date picked), a time (the end
 * time follows and keeps the length unless given), an end day as the
 * occurrence's own end, alerts, a repeat. `null` removes a field.
 */
export type ScheduleEdit = {
  shiftDays?: number;
  time?: string | null;
  timeEnd?: string | null;
  end?: string | null;
  alerts?: Alert[] | null;
  repeat?: Repeat | null;
};

/**
 * The tracker values after an edit made on the occurrence that starts on
 * `anchor` (the item's own day when it does not repeat). A series edited as a
 * whole moves by the same days as the occurrence, so its other occurrences
 * keep their place relative to it, skipped days included.
 */
export function applyScheduleEdit(
  trackers: Record<string, unknown> | undefined,
  type: NoteType | undefined,
  anchor: string,
  edit: ScheduleEdit,
): Record<string, unknown> {
  const t: Record<string, unknown> = { ...(trackers ?? {}) };
  const day = typeof t.journalDate === 'string' && isDay(t.journalDate) ? t.journalDate : anchor;
  const oldLen = typeof t.dateEnd === 'string' && isDay(t.dateEnd) ? dayNumber(t.dateEnd) - dayNumber(day) : 0;
  const shift = edit.shiftDays ?? 0;
  if (shift) {
    t.journalDate = shiftDay(day, shift);
    if (oldLen > 0) t.dateEnd = shiftDay(t.journalDate as string, oldLen);
    if (isRepeat(t.repeat)) {
      const r: Repeat = { ...t.repeat };
      if (r.skip) r.skip = r.skip.map((d) => shiftDay(d, shift));
      if (r.until) r.until = shiftDay(r.until, shift);
      if (r.weekdays) r.weekdays = [...new Set(r.weekdays.map((w) => (((w + shift) % 7) + 7) % 7))].sort((a, b) => a - b);
      t.repeat = r;
    }
  }
  if (edit.end !== undefined) {
    const len = edit.end === null ? 0 : dayNumber(edit.end) - dayNumber(shiftDay(anchor, shift));
    if (len > 0) t.dateEnd = shiftDay(t.journalDate as string ?? day, len);
    else delete t.dateEnd;
  }
  if (edit.time !== undefined) {
    if (edit.time === null) {
      delete t.time;
      delete t.timeEnd;
    } else {
      const oldStart = isTime(t.time) ? minutesOf(t.time) : null;
      const oldEnd = isTime(t.timeEnd) ? minutesOf(t.timeEnd) : null;
      t.time = edit.time;
      if (edit.timeEnd === undefined && oldStart !== null && oldEnd !== null) {
        t.timeEnd = timeFromMinutes(minutesOf(edit.time) + ((oldEnd - oldStart + 1440) % 1440));
      }
    }
  }
  if (edit.timeEnd !== undefined) {
    if (edit.timeEnd === null) delete t.timeEnd;
    else t.timeEnd = edit.timeEnd;
  }
  if (edit.alerts !== undefined) {
    if (edit.alerts === null || edit.alerts.length === 0) delete t.alerts;
    else t.alerts = edit.alerts;
  }
  if (edit.repeat !== undefined) {
    if (edit.repeat === null) delete t.repeat;
    else {
      // A new rule keeps the days the series already took out, the stored ones
      // included: a deleted occurrence never comes back by a change of rule.
      const kept = [...new Set([...(edit.repeat.skip ?? []), ...(isRepeat(t.repeat) ? t.repeat.skip ?? [] : [])])].sort();
      t.repeat = kept.length ? { ...edit.repeat, skip: kept } : edit.repeat;
    }
  }
  return normalizeSchedule(t, type) ?? {};
}

/**
 * A time of day as a person types it: "15:00", "9:30", "1530", "3pm", "3 pm",
 * "3:30 PM", "15h", "15h30", "15.30". Null for anything else.
 */
export function parseTimeText(text: string): string | null {
  const m = /^\s*(\d{1,2})(?:(?:[:.h]|\s?h\s?)(\d{2})?)?\s*(am|pm|a\.m\.|p\.m\.|a|p)?\s*$/i.exec(text)
    ?? /^\s*(\d{2})(\d{2})\s*$/.exec(text);
  if (!m) return null;
  let h = Number(m[1]);
  const min = m[2] ? Number(m[2]) : 0;
  const half = (m[3] ?? '').toLowerCase().replace(/\./g, '');
  if (half) {
    if (h < 1 || h > 12) return null;
    if (half.startsWith('p') && h !== 12) h += 12;
    if (half.startsWith('a') && h === 12) h = 0;
  }
  if (h > 23 || min > 59) return null;
  return `${String(h).padStart(2, '0')}:${String(min).padStart(2, '0')}`;
}
