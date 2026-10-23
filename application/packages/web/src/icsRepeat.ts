import { nthOf, type Repeat, weekdayOf } from './schedule';

/**
 * RRULE (RFC 5545 section 3.3.10) to the calendar's `Repeat` and back. The
 * reading side is a whitelist: a rule is accepted only when every part of it
 * has a meaning `occurrencesOf` reproduces exactly, and anything else is
 * refused, so a series never lands on days its source did not have. The
 * start day is always the first occurrence, as in RFC 5545, so it is never
 * moved. `UNTIL` is returned raw: turning it into a day needs the event's
 * time and zone, which the caller holds.
 * Spec: ops/docs/archive/google-calendar-import.md (section 4.5)
 */

const WEEKDAYS = ['SU', 'MO', 'TU', 'WE', 'TH', 'FR', 'SA'] as const;
const FREQ: Record<string, Repeat['every']> = { DAILY: 'day', WEEKLY: 'week', MONTHLY: 'month', YEARLY: 'year' };
const KNOWN_PARTS = new Set(['FREQ', 'INTERVAL', 'BYDAY', 'BYMONTHDAY', 'BYMONTH', 'UNTIL', 'COUNT', 'WKST']);

export type RepeatRead =
  | { ok: true; repeat: Repeat; until?: string }
  | { ok: false };

function parts(rule: string): Map<string, string> | null {
  const out = new Map<string, string>();
  for (const piece of rule.trim().split(';')) {
    if (!piece) continue;
    const eq = piece.indexOf('=');
    if (eq <= 0) return null;
    const key = piece.slice(0, eq).toUpperCase();
    if (out.has(key)) return null;
    out.set(key, piece.slice(eq + 1).toUpperCase());
  }
  return out;
}

const mod7 = (n: number) => ((n % 7) + 7) % 7;

/**
 * Whether grouping weeks from `wkst` gives the same weeks as the model's
 * Sunday weeks for these weekdays: true when they all fall on one side of
 * the two cut points (all in wkst..Saturday, or all in Sunday..wkst-1).
 */
function sameWeeks(days: number[], wkst: number): boolean {
  if (wkst === 0) return true;
  return days.every((d) => d >= wkst) || days.every((d) => d < wkst);
}

/**
 * A rule read against the day the item will start on (`start`, local) and
 * the weekday shift the zone conversion gave it (`shift`: the local day
 * minus the source day). A monthly or yearly rule is only read with no
 * shift; the caller keeps such a series in its own zone.
 */
export function rruleToRepeat(rule: string, start: string, shift = 0): RepeatRead {
  const p = parts(rule);
  if (!p) return { ok: false };
  for (const key of p.keys()) if (!KNOWN_PARTS.has(key)) return { ok: false };
  const every = FREQ[p.get('FREQ') ?? ''];
  if (!every) return { ok: false };
  const repeat: Repeat = { every, interval: 1 };

  const interval = p.get('INTERVAL');
  if (interval !== undefined) {
    if (!/^\d{1,3}$/.test(interval) || Number(interval) < 1) return { ok: false };
    repeat.interval = Number(interval);
  }
  const count = p.get('COUNT');
  const until = p.get('UNTIL');
  if (count !== undefined && until !== undefined) return { ok: false };
  if (count !== undefined) {
    if (!/^\d{1,6}$/.test(count) || Number(count) < 1) return { ok: false };
    repeat.count = Number(count);
  }
  if (until !== undefined && !/^\d{8}(T\d{6}Z?)?$/.test(until)) return { ok: false };

  const byday = p.get('BYDAY');
  const bymonthday = p.get('BYMONTHDAY');
  const bymonth = p.get('BYMONTH');
  const [, sm, sd] = start.split('-').map(Number) as [number, number, number];

  if (every === 'day') {
    if (byday || bymonthday || bymonth) return { ok: false };
  } else if (every === 'week') {
    if (bymonthday || bymonth) return { ok: false };
    let days: number[] = [];
    if (byday) {
      for (const d of byday.split(',')) {
        const w = WEEKDAYS.indexOf(d as typeof WEEKDAYS[number]);
        if (w < 0) return { ok: false };
        days.push(mod7(w + shift));
      }
      days = [...new Set(days)].sort((a, b) => a - b);
      repeat.weekdays = days;
    }
    if (repeat.interval > 1) {
      const wkstName = p.get('WKST') ?? 'MO';
      const w = WEEKDAYS.indexOf(wkstName as typeof WEEKDAYS[number]);
      if (w < 0) return { ok: false };
      if (!sameWeeks([...days, weekdayOf(start)], mod7(w + shift))) return { ok: false };
    }
  } else {
    if (shift !== 0) return { ok: false };
    if (every === 'month') {
      if (bymonth) return { ok: false };
      if (bymonthday && byday) return { ok: false };
      if (bymonthday !== undefined && Number(bymonthday) !== sd) return { ok: false };
      if (byday) {
        const m = /^(-1|[1-4])(SU|MO|TU|WE|TH|FR|SA)$/.exec(byday);
        if (!m) return { ok: false };
        const nth = Number(m[1]) as 1 | 2 | 3 | 4 | -1;
        // The model repeats on the start's weekday and honors `nth` even when
        // the start itself is another ordinal (a series moved by a week): the
        // start is the first occurrence, then the Nth of each month, as in RFC 5545.
        if (WEEKDAYS.indexOf(m[2] as typeof WEEKDAYS[number]) !== weekdayOf(start)) return { ok: false };
        repeat.monthly = 'weekday';
        repeat.nth = nth;
      } else {
        repeat.monthly = 'day';
      }
    } else {
      if (byday) return { ok: false };
      // A month day without a month repeats in every month (RFC 5545 expands it).
      if (bymonthday !== undefined && bymonth === undefined) return { ok: false };
      if (bymonth !== undefined && Number(bymonth) !== sm) return { ok: false };
      if (bymonthday !== undefined && Number(bymonthday) !== sd) return { ok: false };
    }
  }
  return until !== undefined ? { ok: true, repeat, until } : { ok: true, repeat };
}

/**
 * The RRULE value for a repeat. `untilValue` writes a day in the start's own
 * value type (a date, or a floating end of day). A weekly rule always says
 * `WKST=SU`, the model's weeks.
 */
export function repeatToRrule(repeat: Repeat, start: string, untilValue: (day: string) => string, untilDay?: string): string {
  const out = [`FREQ=${Object.entries(FREQ).find(([, v]) => v === repeat.every)![0]}`];
  if (repeat.interval > 1) out.push(`INTERVAL=${repeat.interval}`);
  if (repeat.every === 'week') {
    if (repeat.weekdays?.length) out.push(`BYDAY=${[...repeat.weekdays].sort((a, b) => a - b).map((w) => WEEKDAYS[w]).join(',')}`);
    out.push('WKST=SU');
  }
  if (repeat.every === 'month' && repeat.monthly === 'weekday') {
    const nth = repeat.nth ?? (nthOf(start) > 4 ? -1 : nthOf(start));
    out.push(`BYDAY=${nth}${WEEKDAYS[weekdayOf(start)]}`);
  }
  const until = untilDay ?? repeat.until;
  if (until) out.push(`UNTIL=${untilValue(until)}`);
  else if (repeat.count !== undefined) out.push(`COUNT=${repeat.count}`);
  return out.join(';');
}
