import { useSyncExternalStore } from 'react';
import { activeLocale, deviceLocaleTags, intlLocale } from './languages';

/**
 * Every date the app shows a person goes through this file: list rows,
 * menus, charts, and the exports a person reads. A date written for a
 * machine (a stored stamp, a file name, a JSON field) stays ISO and does not
 * come here.
 */

// An Intl formatter binds its locale at construction, and the language can
// change without a page reload, so every cache key carries the resolved tag.
const weekdayFormatters = new Map<string, Intl.DateTimeFormat>();
const relativeFormatters = new Map<string, Intl.RelativeTimeFormat>();
const dateFormatters = new Map<string, Intl.DateTimeFormat>();

/**
 * One weekday label. 'narrow' is a single letter in most languages; 'short'
 * is the abbreviated form, which some languages spell out in full
 * ("domingo"), so only an axis with room to spare may ask for it; 'long' is
 * the full name, for a sentence rather than an axis.
 *
 * A bare YYYY-MM-DD string parses as UTC midnight, so the formatter has to
 * stay on UTC to read back the same day. In local time every user west of
 * Greenwich would see the previous weekday.
 */
export function weekdayLabel(date: Date, width: 'narrow' | 'short' | 'long'): string {
  const loc = intlLocale();
  const key = `${loc}:${width}`;
  let fmt = weekdayFormatters.get(key);
  if (!fmt) {
    fmt = new Intl.DateTimeFormat(loc, { weekday: width, timeZone: 'UTC' });
    weekdayFormatters.set(key, fmt);
  }
  return fmt.format(date);
}

/**
 * A date that falls on the given weekday index (0 = Sunday), for turning a
 * day-of-week statistic into a name. Any week does; this one starts on a
 * Sunday, and it is read back in UTC like every other date here.
 */
export function weekdayDate(day: number): Date {
  return new Date(Date.UTC(2023, 0, 1) + day * 86_400_000);
}

function relativeFormatter(numeric: 'always' | 'auto'): Intl.RelativeTimeFormat {
  const loc = intlLocale();
  const key = `${loc}:${numeric}`;
  let fmt = relativeFormatters.get(key);
  if (!fmt) {
    // The narrow style drops the "ago" sense in several languages and returns
    // a bare minus sign instead, so metadata rows use the short one.
    fmt = new Intl.RelativeTimeFormat(loc, { numeric, style: 'short' });
    relativeFormatters.set(key, fmt);
  }
  return fmt;
}

/**
 * Compact age of a timestamp for a settings metadata row ("8 hr. ago",
 * "vor 8 Std.", "قبل 8 ساعات"). Intl owns the wording and the plural
 * category of each language, so no catalog carries these strings.
 *
 * Anything under a minute reads as the bare present form ("now", "agora"),
 * which only the 'auto' mode produces: 'always' would render "in 0 seconds".
 */
export function formatRelative(iso: string): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return iso;
  const m = Math.floor((Date.now() - then) / 60_000);
  if (m < 1) return relativeFormatter('auto').format(0, 'second');
  if (m < 60) return relativeFormatter('always').format(-m, 'minute');
  const h = Math.floor(m / 60);
  if (h < 24) return relativeFormatter('always').format(-h, 'hour');
  return relativeFormatter('always').format(-Math.floor(h / 24), 'day');
}

/** "Today" (0), "Yesterday" (-1) or "Tomorrow" (1) in the app language, from
 *  Intl, as a list group header names a day. Lower case in most languages. */
export function relativeDayName(offset: -1 | 0 | 1): string {
  return relativeFormatter('auto').format(offset, 'day');
}

/** The name of a month standing alone ("October", "říjen"), as a list group
 *  header names one. Lower case in some languages. */
export function monthName(year: number, monthIndex: number): string {
  const loc = intlLocale();
  const key = `${loc}:monthName`;
  let fmt = dateFormatters.get(key);
  if (!fmt) {
    fmt = new Intl.DateTimeFormat(loc, { month: 'long' });
    dateFormatters.set(key, fmt);
  }
  return fmt.format(new Date(year, monthIndex, 1));
}

/** The one-letter month of a column axis ("J", "F"), where a year fits in twelve columns. */
export function monthInitial(monthIndex: number): string {
  const loc = intlLocale();
  const key = `${loc}:monthInitial`;
  let fmt = dateFormatters.get(key);
  if (!fmt) {
    fmt = new Intl.DateTimeFormat(loc, { month: 'narrow', timeZone: 'UTC' });
    dateFormatters.set(key, fmt);
  }
  return fmt.format(new Date(Date.UTC(2024, monthIndex, 1)));
}

/** Local calendar date as `YYYY-MM-DD`. Never UTC: an entry belongs to
 *  the day the writer is living, not to the day in Greenwich. */
export function toLocalIso(d: Date): string {
  const pad = (n: number) => (n < 10 ? `0${n}` : String(n));
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

// ── The date settings ─────────────────────────────────────────────
//
// "Date format" and "Clock" in Settings > Date & Time, synced. Automatic is the
// app language plus the device region (`dateLocale`), resolved on each device.

export const DATE_ORDERS = ['auto', 'dmy', 'mdy', 'ymd'] as const;
export type DateOrder = (typeof DATE_ORDERS)[number];
export const CLOCKS = ['auto', 'h23', 'h12'] as const;
export type Clock = (typeof CLOCKS)[number];

export function isDateOrder(v: unknown): v is DateOrder {
  return typeof v === 'string' && (DATE_ORDERS as readonly string[]).includes(v);
}

export function isClock(v: unknown): v is Clock {
  return typeof v === 'string' && (CLOCKS as readonly string[]).includes(v);
}

export interface DatePrefs {
  order: DateOrder;
  clock: Clock;
}

const AUTOMATIC: DatePrefs = { order: 'auto', clock: 'auto' };
let datePrefs: DatePrefs = AUTOMATIC;
let prefsVersion = 0;
const prefsListeners = new Set<() => void>();

/** Apply the synced date settings. Every formatter is rebuilt, and every
 *  memo that lists `useDateFormatKey()` formats again, without a remount. */
export function setDatePrefs(order: DateOrder, clock: Clock): void {
  if (datePrefs.order === order && datePrefs.clock === clock) return;
  datePrefs = { order, clock };
  resolvedDateLocale = undefined;
  resolvedPrefs.clear();
  dateFormatters.clear();
  prefsVersion++;
  for (const cb of prefsListeners) cb();
}

function subscribeDatePrefs(cb: () => void) {
  prefsListeners.add(cb);
  return () => {
    prefsListeners.delete(cb);
  };
}

/**
 * What a memo of a formatted date depends on besides its value: the app
 * language and the date settings. A memo keyed on the note alone shows a new
 * setting only after the note's next edit.
 */
export function useDateFormatKey(): string {
  const version = useSyncExternalStore(subscribeDatePrefs, () => prefsVersion, () => prefsVersion);
  return `${activeLocale()}:${version}`;
}

/**
 * The shapes a date takes on screen. A new screen picks the nearest one
 * rather than writing options of its own, or two screens print the same date
 * in two orders.
 */
const DATE_STYLES = {
  /** A list row. */
  row: { weekday: 'short', day: 'numeric', month: 'short', hour: 'numeric', minute: '2-digit' },
  /** A grid tile or a file row. */
  tile: { day: 'numeric', month: 'short' },
  /** One moment in full: the Details lines, note history, a conflict, a printed note. */
  dateTime: { day: 'numeric', month: 'short', year: 'numeric', hour: 'numeric', minute: '2-digit' },
  /** One day in full: a plan date, a release, a stats tooltip, a medication change. */
  date: { day: 'numeric', month: 'short', year: 'numeric' },
  /** A day in a short list or under a chart. */
  dayMonth: { day: 'numeric', month: 'short' },
  /** A day with its weekday: a calendar agenda header, a schedule row. */
  weekdayDate: { weekday: 'short', day: 'numeric', month: 'short' },
  /** A time of day. */
  time: { hour: 'numeric', minute: '2-digit' },
  /** A weekday name in a menu. */
  weekday: { weekday: 'long' },
  /** The month and weekday lines of a date tile (the event card). */
  monthShort: { month: 'short' },
  weekdayShort: { weekday: 'short' },
  /** A month heading: a calendar of days in Statistics. */
  monthYear: { month: 'long', year: 'numeric' },
  /** Day, month and year as digits, in the order the date setting names. */
  numeric: { day: 'numeric', month: 'numeric', year: 'numeric' },
} satisfies Record<string, Intl.DateTimeFormatOptions>;

type DateStyle = keyof typeof DATE_STYLES;

/** A row or a tile names the year only when it is not the current one. */
const YEAR_WHEN_OLD: ReadonlySet<DateStyle> = new Set(['row', 'tile', 'weekdayDate']);

let resolvedDateLocale: { language: string; tag: string } | undefined;

/**
 * The tag a date is written in: the app language plus the region the device
 * reports. The app language carries no region ("en", never "en-GB"), and
 * Intl reads a bare "en" as American English, so without the region a reader
 * in London or Sydney gets month-first dates.
 */
export function dateLocale(language: string = activeLocale()): string {
  if (resolvedDateLocale?.language !== language) {
    resolvedDateLocale = { language, tag: resolveDateLocale(language, deviceLocaleTags()) };
  }
  return resolvedDateLocale.tag;
}

/**
 * The first region among the device's tags joins the app language. A
 * language we ship as a regional variant (pt-PT, pt-BR, zh-TW) keeps its own
 * region: it already names its conventions, and a swap could change the
 * variant, or the script for Chinese.
 */
export function resolveDateLocale(language: string, deviceTags: readonly string[]): string {
  if (!language.includes('-')) {
    for (const tag of deviceTags) {
      const region = regionOf(tag);
      if (region) return intlLocale(`${language}-${region}`);
    }
  }
  return intlLocale(language);
}

/** The region of a raw device tag. The POSIX form "en_US" still names one;
 *  a tag Intl refuses ("C") names none. */
function regionOf(tag: string): string | undefined {
  try {
    return new Intl.Locale(tag.replace(/_/g, '-')).region;
  } catch {
    return undefined;
  }
}

const cycles = new Map<string, 'h23' | 'h12'>();
/** The hour cycle a tag writes on its own. */
function cycleOf(tag: string): 'h23' | 'h12' {
  let cycle = cycles.get(tag);
  if (!cycle) {
    const c = new Intl.DateTimeFormat(tag, { hour: 'numeric' }).resolvedOptions().hourCycle;
    cycles.set(tag, (cycle = c === 'h23' || c === 'h24' ? 'h23' : 'h12'));
  }
  return cycle;
}

/** The order a tag writes a date in digits, read off the formatter itself:
 *  'dmy', 'mdy' or 'ymd' (anything else for a tag that writes none of them). */
function orderOf(tag: string): string {
  return new Intl.DateTimeFormat(tag, { day: '2-digit', month: '2-digit', year: 'numeric' })
    .formatToParts(new Date(2026, 9, 6, 12))
    .filter((p) => p.type === 'day' || p.type === 'month' || p.type === 'year')
    .map((p) => p.type[0])
    .join('');
}

/** Tags of the same language that may write the other order, tried in turn.
 *  The order is read off each one rather than assumed, because the data moves:
 *  es-US writes a date in digits day first. A language with none keeps its
 *  text order, and only a date in digits is reordered. */
const CARRIERS: Record<string, Record<'dmy' | 'mdy', readonly string[]>> = {
  en: { dmy: ['en-GB'], mdy: ['en-US'] },
  es: { dmy: ['es-ES'], mdy: ['es-US', 'es-PR', 'es-PA'] },
};

interface Resolved {
  /** The tag every style is written in. */
  tag: string;
  /** Set when the clock is chosen, or when a carrier must not bring its own. */
  hourCycle?: 'h23' | 'h12';
  /** Every date in ISO numbers. */
  iso: boolean;
  /** The order a date in digits is rebuilt in, when no carrier writes it. */
  reorder?: 'dmy' | 'mdy';
}

const resolvedPrefs = new Map<string, Resolved>();

/**
 * The date settings applied to the automatic tag. Year first writes ISO
 * numbers. Day first or month first keeps the automatic tag when it already
 * writes that order, and otherwise takes a carrier of the same language.
 * Automatic keeps the clock of the automatic tag, never the carrier's, so
 * choosing day first never changes the clock.
 */
function resolve(prefs: DatePrefs): Resolved {
  const auto = dateLocale();
  const key = `${auto}:${prefs.order}:${prefs.clock}`;
  let r = resolvedPrefs.get(key);
  if (r) return r;
  const chosenCycle = prefs.clock === 'auto' ? undefined : prefs.clock;
  const order = prefs.order;
  if (order === 'ymd') {
    r = { tag: auto, iso: true, ...(chosenCycle ? { hourCycle: chosenCycle } : {}) };
  } else if (order === 'auto' || orderOf(auto) === order) {
    r = { tag: auto, iso: false, ...(chosenCycle ? { hourCycle: chosenCycle } : {}) };
  } else {
    const carrier = CARRIERS[new Intl.Locale(auto).language]?.[order]
      .map((tag) => intlLocale(tag))
      .find((tag) => orderOf(tag) === order);
    r = carrier
      ? { tag: carrier, iso: false, hourCycle: chosenCycle ?? cycleOf(auto) }
      : { tag: auto, iso: false, reorder: order, ...(chosenCycle ? { hourCycle: chosenCycle } : {}) };
  }
  resolvedPrefs.set(key, r);
  return r;
}

function dateFormatter(r: Resolved, opts: Intl.DateTimeFormatOptions, key: string): Intl.DateTimeFormat {
  const fullKey = `${r.tag}:${r.hourCycle ?? ''}:${key}`;
  let fmt = dateFormatters.get(fullKey);
  if (!fmt) {
    const o: Intl.DateTimeFormatOptions = { ...opts };
    if (o.hour) {
      if (r.hourCycle) o.hourCycle = r.hourCycle;
      // Intl pads the hour whenever it is asked to, which reads "09:05" on a
      // 24-hour clock and "09:05 AM" on a 12-hour one. Only the first is right.
      o.hour = (r.hourCycle ?? cycleOf(r.tag)) === 'h23' ? '2-digit' : 'numeric';
    }
    fmt = new Intl.DateTimeFormat(r.tag, o);
    dateFormatters.set(fullKey, fmt);
  }
  return fmt;
}

/** Day, month and year as digits in another order, kept in the tag's own
 *  digits and separator. */
function reordered(fmt: Intl.DateTimeFormat, d: Date, order: 'dmy' | 'mdy'): string {
  const parts = fmt.formatToParts(d);
  const value = (type: string) => parts.find((p) => p.type === type)?.value ?? '';
  const separator = parts.find((p) => p.type === 'literal')?.value ?? '/';
  const fields = order === 'dmy' ? ['day', 'month', 'year'] : ['month', 'day', 'year'];
  return fields.map(value).join(separator);
}

/** A moment as the date settings write it. `formatInstant` is this with the
 *  synced settings; the settings rows preview each option through it. */
export function formatInstantWith(prefs: DatePrefs, value: string | Date, style: DateStyle): string {
  const d = typeof value === 'string' ? new Date(value) : value;
  if (Number.isNaN(d.getTime())) return '';
  const r = resolve(prefs);
  // A full hour on a 12-hour clock drops its ":00": "3 PM", not "3:00 PM".
  // A 24-hour clock always keeps "15:00".
  const fullHour = d.getMinutes() === 0 && (r.hourCycle ?? cycleOf(r.tag)) === 'h12';
  const time = () => (fullHour
    ? dateFormatter(r, { hour: 'numeric' }, 'hour')
    : dateFormatter(r, DATE_STYLES.time, 'time')).format(d);
  // Standalone labels have no date order. The event tile asks for its month
  // and weekday separately; replacing either with a full ISO date breaks it.
  if (r.iso && style !== 'time' && style !== 'weekday' && style !== 'monthShort' && style !== 'weekdayShort') {
    const day = toLocalIso(d);
    switch (style) {
      case 'row':
        return `${dateFormatter(r, { weekday: 'short' }, 'weekdayShort').format(d)} ${day} ${time()}`;
      case 'dateTime':
        return `${day} ${time()}`;
      case 'dayMonth':
        return day.slice(5);
      case 'weekdayDate':
        return `${dateFormatter(r, { weekday: 'short' }, 'weekdayShort').format(d)} ${day}`;
      default:
        return day;
    }
  }
  const withYear = YEAR_WHEN_OLD.has(style) && d.getFullYear() !== new Date().getFullYear();
  const opts: Intl.DateTimeFormatOptions = { ...DATE_STYLES[style], ...(withYear ? { year: 'numeric' } : {}) };
  const short = fullHour && 'minute' in opts;
  if (short) delete opts.minute;
  const fmt = dateFormatter(r, opts, `${style}:${withYear}:${short}`);
  return style === 'numeric' && r.reorder ? reordered(fmt, d, r.reorder) : fmt.format(d);
}

/** The tag a date in words is written in under the synced date settings, so
 *  a journal title spelled out follows Day first or Month first like every
 *  other date. */
export function writtenDateLocale(): string {
  return resolve(datePrefs).tag;
}

/** A moment (a stored ISO stamp or a Date) in the reader's own time zone.
 *  An unreadable stamp gives an empty string. */
export function formatInstant(value: string | Date, style: DateStyle): string {
  return formatInstantWith(datePrefs, value, style);
}

// ── Title patterns ────────────────────────────────────────────────
//
// A journal title built from Day.js token names (GitHub #200). Formatting
// only: the app holds a Date and writes a string, so nothing is parsed back.

/** The tokens, in the order the help lists them. */
export const PATTERN_TOKENS = ['YYYY', 'YY', 'MMMM', 'MMM', 'MM', 'M', 'DD', 'D', 'dddd', 'ddd'] as const;
type PatternToken = (typeof PATTERN_TOKENS)[number];
/** Longest first, so `MMMM` is never read as `MM` twice. */
const MATCH_ORDER = [...PATTERN_TOKENS].sort((a, b) => b.length - a.length);

export type PatternResult =
  | { text: string }
  | { error: 'letter'; letter: string }
  | { error: 'bracket' }
  | { error: 'empty' };

function tokenValue(token: PatternToken, d: Date, tag: string): string {
  const two = (n: number) => String(n).padStart(2, '0');
  switch (token) {
    case 'YYYY':
      return String(d.getFullYear()).padStart(4, '0');
    case 'YY':
      return two(d.getFullYear() % 100);
    case 'MMMM':
      return new Intl.DateTimeFormat(tag, { month: 'long' }).format(d);
    case 'MMM':
      return new Intl.DateTimeFormat(tag, { month: 'short' }).format(d);
    case 'MM':
      return two(d.getMonth() + 1);
    case 'M':
      return String(d.getMonth() + 1);
    case 'DD':
      return two(d.getDate());
    case 'D':
      return String(d.getDate());
    case 'dddd':
      return new Intl.DateTimeFormat(tag, { weekday: 'long' }).format(d);
    case 'ddd':
      return new Intl.DateTimeFormat(tag, { weekday: 'short' }).format(d);
  }
}

/**
 * A date written through a pattern: `YYYY`, `YY`, `MMMM`, `MMM`, `MM`, `M`,
 * `DD`, `D`, `dddd` and `ddd`, and `[text]` as it is. Numbers are Gregorian
 * and in Western digits, as in Day.js and ISO, Thai included; month and
 * weekday names come from the date locale. Any other Latin letter outside
 * brackets is an error that names it, and so are an unclosed bracket and a
 * pattern that writes nothing. A letter of another script is text.
 * Spec: ops/docs/archive/dates.md (section 3.5)
 */
export function formatPattern(d: Date, pattern: string, language: string = activeLocale()): PatternResult {
  const tag = dateLocale(language);
  let out = '';
  let i = 0;
  while (i < pattern.length) {
    const c = pattern[i]!;
    if (c === '[') {
      const end = pattern.indexOf(']', i + 1);
      if (end === -1) return { error: 'bracket' };
      out += pattern.slice(i + 1, end);
      i = end + 1;
      continue;
    }
    const token = MATCH_ORDER.find((t) => pattern.startsWith(t, i));
    if (token) {
      out += tokenValue(token, d, tag);
      i += token.length;
      continue;
    }
    if (/[A-Za-z]/.test(c)) return { error: 'letter', letter: c };
    out += c;
    i += 1;
  }
  return out.trim() ? { text: out } : { error: 'empty' };
}

/**
 * A calendar day stored as YYYY-MM-DD: a journal day, a stats day, a
 * medication change. It is read as noon of that local day, because
 * `new Date` reads the bare string as midnight UTC, which is the day before
 * anywhere west of Greenwich. Text in any other shape is returned as it is.
 */
export function formatDay(day: string, style: DateStyle): string {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(day);
  return m ? formatInstant(new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), 12), style) : day;
}
