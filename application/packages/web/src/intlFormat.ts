import { intlLocale } from './languages';

/**
 * Locale-aware formatting for chart axes and metadata rows. It lives apart
 * from the language switcher because every consumer is a lazily loaded
 * screen, and the switcher itself sits on the boot path.
 */

// An Intl formatter binds its locale at construction, and the language can
// change without a page reload, so every cache key carries the resolved tag.
const weekdayFormatters = new Map<string, Intl.DateTimeFormat>();
const relativeFormatters = new Map<string, Intl.RelativeTimeFormat>();

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
