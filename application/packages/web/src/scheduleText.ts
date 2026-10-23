import type { TFunction } from 'i18next';
import { formatDay, weekdayDate, weekdayLabel } from './intlFormat';
import { intlLocale } from './languages';
import { isLastWeekdayOfMonth, minutesOf, nthOf, weekdayOf, type Alert, type Repeat, type Schedule } from './schedule';
import { timeLabel } from './JournalCalendar';

/**
 * The words of a schedule: the repeat presets computed from the item's own
 * day (the Google list), the sentence a repeat reads as, the label of an
 * alert, and the one-line summary under the Schedule view and in the quick
 * add. Every date and time through `intlFormat.ts`, every word from the
 * `shell` catalog. `t` is bound to `shell`.
 * Spec: ops/docs/archive/calendar-pillar-spec.md (steps 6 and 7)
 */

function weekdayName(w: number, width: 'long' | 'short' = 'long'): string {
  return weekdayLabel(weekdayDate(w), width);
}

function listOf(items: string[]): string {
  try {
    return new Intl.ListFormat(intlLocale(), { type: 'conjunction' }).format(items);
  } catch {
    return items.join(', ');
  }
}

/** The ordinal word of an Nth weekday: first, second, third, fourth, last. */
function nthWord(nth: number, t: TFunction): string {
  return t(nth === -1 ? 'repeat.nth.last' : `repeat.nth.${nth}`);
}

const WORKWEEK = [1, 2, 3, 4, 5];

/** A repeat read as one sentence, its end included. */
export function describeRepeat(r: Repeat, day: string, t: TFunction): string {
  const count = r.interval;
  let rule: string;
  if (r.every === 'day') rule = t('repeat.daily', { count });
  else if (r.every === 'week') {
    const days = [...new Set(r.weekdays?.length ? r.weekdays : [weekdayOf(day)])].sort((a, b) => a - b);
    rule = count === 1 && days.join() === WORKWEEK.join()
      ? t('repeat.weekdays')
      : t('repeat.weekly', { count, days: listOf(days.map((w) => weekdayName(w))) });
  } else if (r.every === 'month') {
    rule = r.monthly === 'weekday'
      ? t('repeat.monthlyNth', { count, nth: nthWord(r.nth ?? (nthOf(day) > 4 ? -1 : nthOf(day)), t), weekday: weekdayName(weekdayOf(day)) })
      : t('repeat.monthlyDay', { count, day: Number(day.slice(8, 10)) });
  } else rule = t('repeat.yearly', { count, date: formatDay(day, 'dayMonth') });
  if (r.until) return t('repeat.withUntil', { rule, date: formatDay(r.until, 'date') });
  if (r.count) return t('repeat.withCount', { rule, count: r.count });
  return rule;
}

/** The presets of the Repeat view, computed from the day: never, daily,
 *  weekdays, weekly, every two weeks, monthly on the day, monthly on the Nth
 *  weekday (the last one when the day is the last), yearly. */
export function repeatPresets(day: string): { key: string; repeat: Repeat | null }[] {
  const nth = isLastWeekdayOfMonth(day) && nthOf(day) >= 4 ? -1 : (nthOf(day) as 1 | 2 | 3 | 4);
  return [
    { key: 'never', repeat: null },
    { key: 'daily', repeat: { every: 'day', interval: 1 } },
    { key: 'weekdays', repeat: { every: 'week', interval: 1, weekdays: WORKWEEK } },
    { key: 'weekly', repeat: { every: 'week', interval: 1 } },
    { key: 'biweekly', repeat: { every: 'week', interval: 2 } },
    { key: 'monthlyDay', repeat: { every: 'month', interval: 1, monthly: 'day' } },
    { key: 'monthlyNth', repeat: { every: 'month', interval: 1, monthly: 'weekday', nth } },
    { key: 'yearly', repeat: { every: 'year', interval: 1 } },
  ];
}

/** The change a Repeat preset makes: none when it is the rule already, so
 *  picking it again writes nothing; otherwise the preset with the series' end
 *  and skipped days kept. */
export function presetEdit(preset: Repeat | null, current: Repeat | null): { repeat: Repeat | null } | null {
  if (sameRule(current, preset)) return null;
  if (!preset) return { repeat: null };
  return {
    repeat: {
      ...preset,
      ...(current?.until ? { until: current.until } : {}),
      ...(current?.count ? { count: current.count } : {}),
      ...(current?.skip?.length ? { skip: current.skip } : {}),
    },
  };
}

/** Whether two repeats are the same rule (the end and the skipped days aside). */
export function sameRule(a: Repeat | undefined | null, b: Repeat | undefined | null): boolean {
  if (!a || !b) return !a && !b;
  const norm = (r: Repeat) => JSON.stringify([r.every, r.interval, [...(r.weekdays ?? [])].sort(), r.monthly ?? 'day', r.nth ?? null]);
  return norm(a) === norm(b);
}

/** The alerts a timed item offers, in minutes before. */
export const TIMED_ALERTS = [0, 5, 10, 15, 30, 60, 120, 1440, 2880, 10080] as const;
/** The alerts an all-day item offers, in days before, at the default time. */
export const ALL_DAY_ALERTS = [0, 1, 2, 7] as const;

/** One alert in words: "10 minutes before", "1 day before at 09:00". */
export function alertLabel(a: Alert, day: string, t: TFunction): string {
  if ('before' in a) {
    const m = a.before;
    if (m === 0) return t('alerts.atTime');
    if (m % 10080 === 0) return t('alerts.weeksBefore', { count: m / 10080 });
    if (m % 1440 === 0) return t('alerts.daysBefore', { count: m / 1440 });
    if (m % 60 === 0) return t('alerts.hoursBefore', { count: m / 60 });
    return t('alerts.minutesBefore', { count: m });
  }
  const at = timeLabel(day, a.at);
  return a.days === 0 ? t('alerts.onDayAt', { time: at }) : t('alerts.daysBeforeAt', { count: a.days, time: at });
}

/** The alerts in a row's value: the first, and "+N" for the rest. */
export function alertsSummary(alerts: readonly Alert[] | undefined, day: string, t: TFunction): string {
  if (!alerts?.length) return t('alerts.none');
  const first = alertLabel(alerts[0]!, day, t);
  return alerts.length > 1 ? `${first} +${alerts.length - 1}` : first;
}

/** The time range of a schedule in words: "15:00 - 16:00", or "All day". */
function timeRange(s: Pick<Schedule, 'time' | 'timeEnd'>, day: string, t: TFunction): string {
  if (!s.time) return t('calendar.allDay');
  return s.timeEnd ? `${timeLabel(day, s.time)} - ${timeLabel(day, s.timeEnd)}` : timeLabel(day, s.time);
}

/** One line: the day (and end day), the time, the repeat. */
export function describeSchedule(s: Schedule, t: TFunction): string {
  const parts = [s.end ? `${formatDay(s.day, 'weekdayDate')} - ${formatDay(s.end, 'weekdayDate')}` : formatDay(s.day, 'weekdayDate')];
  if (s.time) parts.push(timeRange(s, s.day, t));
  if (s.repeat) parts.push(describeRepeat(s.repeat, s.day, t));
  if (s.alerts?.length) parts.push(alertsSummary(s.alerts, s.day, t));
  return parts.join(' · ');
}

/** Minutes an alert fires before an item's start, for sorting the list. */
export function alertOrder(a: Alert): number {
  return 'before' in a ? a.before : a.days * 1440 + (1440 - minutesOf(a.at));
}
