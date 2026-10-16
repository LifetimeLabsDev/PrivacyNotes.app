import JSZip from 'jszip';
import i18n from '../i18n';
import { escapeMarkdownText } from '../fileNames';
import {
  ICS_LIMITS,
  parseIcs,
  param,
  prop,
  props,
  splitTextList,
  unescapeText,
  unfoldBytes,
  type IcsComponent,
  type IcsProp,
} from '../icsLines';
import { rruleToRepeat } from '../icsRepeat';
import { normalizeTag } from '../notesRepo';
import {
  MAX_ALERTS,
  dayNumber,
  minutesOf,
  normalizeSchedule,
  shiftDay,
  timeFromMinutes,
  type Alert,
  type Repeat,
} from '../schedule';
import { buildFolderTree } from './folderImport';
import { linkifyLiteralText, linkifyMarkdown } from './linkify';
import { htmlNoteToMarkdown } from './notesnook';
import type { ImportedNote, ParsedImport } from './types';
import { ImportTooLargeError, zipEntryBytes } from './zipEntry';

/**
 * Google Calendar importer, and through it any iCalendar (.ics) file: the
 * .zip of Google's full export (one .ics per calendar), a single calendar's
 * file, or a Takeout zip. Every event becomes an item of type `event`, each
 * calendar a folder.
 *
 * The calendar holds floating local days and times, so an instant becomes the
 * wall time it shows on this device. A series is converted as one unit: the
 * day shift its first start takes moves its weekdays, its end and every day
 * it skips by the same amount, so the skip days stay on days the series
 * produces. A monthly or yearly series whose day would move cannot be
 * shifted (the 31st plus a day is no rule), so it keeps its own zone's day
 * and time and says so in its text.
 *
 * A re-import adds nothing: each event carries `ics` ({ uid } or
 * { uid, rid }), and apply.ts skips a series whose UID the vault holds.
 * Spec: ops/docs/plans/google-calendar-import.md (section 4)
 */

/** The most .ics bytes one import reads in total. */
const TOTAL_BYTES = 64 * 1024 * 1024;
/** The ignored trigger value of RFC 9074 section 8 (Apple's "no alert"). */
const IGNORED_TRIGGER = '19760401T005545Z';
/** The longest lead time an alert keeps, the validator's ceiling. */
const MAX_LEAD_MINUTES = 28 * 24 * 60;
/** The longest span the calendar draws (schedule.ts MAX_SPAN_DAYS). */
const MAX_SPAN_DAYS = 366;

// ── Reading the files ──────────────────────────────────────────────

export type CalendarFile = { name: string; bytes: Uint8Array };

async function readFiles(file: File): Promise<CalendarFile[]> {
  const head = new Uint8Array(await file.slice(0, 4).arrayBuffer());
  const isZip = head[0] === 0x50 && head[1] === 0x4b;
  if (!isZip) {
    if (file.size > TOTAL_BYTES) throw new ImportTooLargeError('This calendar file is larger than 64 MB.');
    return [{ name: file.name, bytes: new Uint8Array(await file.arrayBuffer()) }];
  }
  const zip = await JSZip.loadAsync(file);
  const entries = Object.values(zip.files).filter((e) => !e.dir && /\.ics$/i.test(e.name) && !e.name.split('/').some((s) => s.startsWith('__MACOSX')));
  if (entries.length === 0) throw new Error('This .zip holds no .ics file. Use the .zip from Google Calendar > Settings > Import & export > Export, or one .ics file.');
  const out: CalendarFile[] = [];
  let left = TOTAL_BYTES;
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    const bytes = await zipEntryBytes(entry, left);
    left -= bytes.byteLength;
    out.push({ name: entry.name, bytes });
  }
  return out;
}

// ── Time ───────────────────────────────────────────────────────────

type Wall = { y: number; m: number; d: number; hh: number; mm: number };

const pad = (n: number, w = 2) => String(n).padStart(w, '0');
const dayOf = (w: Wall) => `${pad(w.y, 4)}-${pad(w.m)}-${pad(w.d)}`;
const timeOf = (w: Wall) => `${pad(w.hh)}:${pad(w.mm)}`;
const sameWall = (a: Wall, b: Wall) => a.y === b.y && a.m === b.m && a.d === b.d && a.hh === b.hh && a.mm === b.mm;

const formatters = new Map<string, Intl.DateTimeFormat>();
function formatter(zone: string): Intl.DateTimeFormat | null {
  if (formatters.has(zone)) return formatters.get(zone)!;
  try {
    const f = new Intl.DateTimeFormat('en-US', { // date-ok: reads clock parts for a zone conversion, never shown
      timeZone: zone, hourCycle: 'h23', year: 'numeric', month: 'numeric', day: 'numeric', hour: 'numeric', minute: 'numeric',
    });
    formatters.set(zone, f);
    return f;
  } catch {
    return null;
  }
}

function wallIn(ms: number, zone: string): Wall {
  const f = formatter(zone)!;
  const get: Record<string, number> = {};
  for (const p of f.formatToParts(new Date(ms))) if (p.type !== 'literal') get[p.type] = Number(p.value);
  return { y: get.year!, m: get.month!, d: get.day!, hh: get.hour! % 24, mm: get.minute! };
}

const wallUtc = (w: Wall) => Date.UTC(w.y, w.m - 1, w.d, w.hh, w.mm);

/** Minutes the zone is ahead of UTC at an instant. */
function offsetAt(ms: number, zone: string): number {
  const minute = Math.floor(ms / 60000) * 60000;
  return (wallUtc(wallIn(minute, zone)) - minute) / 60000;
}

/**
 * The instant a wall time names in a zone. A time inside a daylight-saving
 * gap moves forward by the gap's length (02:30 becomes 03:30), as RFC 5545
 * section 3.3.5 says; a repeated hour takes the first.
 */
function instantOf(w: Wall, zone: string): number {
  const guess = wallUtc(w);
  const candidates = [offsetAt(guess - 864e5, zone), offsetAt(guess, zone), offsetAt(guess + 864e5, zone)]
    .map((o) => guess - o * 60000);
  const exact = candidates.filter((t) => sameWall(wallIn(t, zone), w)).sort((a, b) => a - b);
  if (exact.length) return exact[0]!;
  // In a gap: the later offset's reading lands after the gap.
  return Math.max(...candidates);
}

function addDaysToWall(w: Wall, days: number): Wall {
  const [y, m, d] = shiftDay(dayOf(w), days).split('-').map(Number) as [number, number, number];
  return { ...w, y, m, d };
}

/** A DATE or DATE-TIME as read from the file, before any conversion. */
type When =
  | { allDay: true; day: string }
  | { allDay: false; wall: Wall; zone: string | null; utc: boolean };

/** Whether a year, month and day name a day the calendar has, from the year 1000 on. */
function isRealDay(y: number, m: number, d: number): boolean {
  return y >= 1000 && m >= 1 && m <= 12 && d >= 1 && d <= new Date(Date.UTC(y, m, 0)).getUTCDate();
}

/** A value naming a day the calendar does not have (month 13, or 31 February) is
 *  unreadable, never moved to another day. */
function readValue(value: string, tzid: string | undefined, zones: Map<string, number>): When | null {
  const v = value.trim();
  const dm = /^(\d{4})(\d{2})(\d{2})$/.exec(v);
  if (dm) return isRealDay(+dm[1]!, +dm[2]!, +dm[3]!) ? { allDay: true, day: `${dm[1]}-${dm[2]}-${dm[3]}` } : null;
  const m = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})(Z?)$/.exec(v);
  if (!m) return null;
  const wall: Wall = { y: +m[1]!, m: +m[2]!, d: +m[3]!, hh: +m[4]!, mm: +m[5]! };
  if (!isRealDay(wall.y, wall.m, wall.d) || wall.hh > 23 || wall.mm > 59) return null;
  if (m[7]) return { allDay: false, wall, zone: 'UTC', utc: true };
  if (tzid && formatter(tzid)) return { allDay: false, wall, zone: tzid, utc: false };
  // A zone name that is not IANA (Outlook's): a fixed offset from its VTIMEZONE when there is one, else floating.
  if (tzid && zones.has(tzid)) {
    const ms = wallUtc(wall) - zones.get(tzid)! * 60000;
    return { allDay: false, wall: wallIn(ms, 'UTC'), zone: 'UTC', utc: true };
  }
  return { allDay: false, wall, zone: null, utc: false };
}

function read(p: IcsProp | undefined, zones: Map<string, number>): When | null {
  return p ? readValue(p.value, param(p, 'TZID'), zones) : null;
}

/** The instant a timed value names, or null when it floats. */
function instantOfWhen(w: When & { allDay: false }): number | null {
  if (!w.zone) return null;
  return w.utc ? wallUtc(w.wall) : instantOf(w.wall, w.zone);
}

/** The wall time a timed value shows in a frame zone (a floating value shows its own). */
function wallInFrame(w: When & { allDay: false }, frame: string): Wall {
  const at = instantOfWhen(w);
  return at === null ? w.wall : wallIn(at, frame);
}

/** Signed `P..` duration as days (wall) and minutes (exact). */
function parseDuration(v: string): { days: number; minutes: number } | null {
  const m = /^([+-])?P(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$/.exec(v.trim());
  if (!m || v.trim() === 'P' || v.trim().endsWith('T')) return null;
  const sign = m[1] === '-' ? -1 : 1;
  const days = (Number(m[2] ?? 0) * 7 + Number(m[3] ?? 0)) * sign;
  const minutes = (Number(m[4] ?? 0) * 60 + Number(m[5] ?? 0) + Math.floor(Number(m[6] ?? 0) / 60)) * sign;
  return { days, minutes };
}

// ── Text ───────────────────────────────────────────────────────────

/**
 * UTF-8 that was read as Latin-1 once (`Ã¼` for `ü`), decoded again. Kept
 * only when every character is below U+0100 and the bytes decode cleanly,
 * so correct text is left alone.
 */
export function repairMojibake(s: string): string {
  if (!/[ÃÂ][\u0080-¿]/.test(s) || /[^\u0000-ÿ]/.test(s)) return s;
  try {
    const out = new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(s, (c) => c.charCodeAt(0)));
    return out.includes('�') ? s : out;
  } catch {
    return s;
  }
}

const HTML_TAG = /<(a|b|i|u|p|br|ul|ol|li|span|div|strong|em|h[1-6])(\s[^>]*)?\/?>/i;

function textValue(p: IcsProp | undefined): { text: string; repaired: boolean } {
  if (!p) return { text: '', repaired: false };
  const raw = unescapeText(p.value);
  const text = repairMojibake(raw);
  return { text, repaired: text !== raw };
}

const mailOf = (v: string) => v.replace(/^mailto:/i, '').trim();
/** A URL with every character markdown could read percent-encoded, so it is never live markdown. */
const safeUrl = (v: string) => v.trim().replace(/[^A-Za-z0-9\-._~:/?#@$&*+,;=%]/g, (c) =>
  [...new TextEncoder().encode(c)].map((b) => `%${b.toString(16).toUpperCase().padStart(2, '0')}`).join(''));
const linkText = (v: string) => `<${safeUrl(v)}>`;
const isEmail = (v: string) => /^[^\s@]+@[^\s@]+$/.test(v);
const isWebLink = (v: string) => /^(https?:\/\/|mailto:)\S+$/i.test(v.trim());
const label = (key: string) => i18n.t(`importExport:importCalendar.${key}`);

// ── Alerts ─────────────────────────────────────────────────────────

type AlertContext =
  | { allDay: false; startAt: number | null; durationMinutes: number; repeating: boolean; time: string }
  | { allDay: true; startDay: string; days: number; repeating: boolean; zone: string };

function readAlert(a: IcsComponent, ctx: AlertContext, zones: Map<string, number>): Alert | null {
  const action = (prop(a, 'ACTION')?.value ?? 'DISPLAY').trim().toUpperCase();
  if (action === 'NONE') return null;
  const trigger = prop(a, 'TRIGGER');
  if (!trigger || trigger.value.trim() === IGNORED_TRIGGER) return null;
  let minutes: number;
  if (param(trigger, 'VALUE')?.toUpperCase() === 'DATE-TIME') {
    if (ctx.repeating) return null;
    const at = read(trigger, zones);
    if (!at || at.allDay) return null;
    const ms = instantOfWhen(at);
    if (ms === null) return null;
    if (ctx.allDay) {
      minutes = Math.round((ms - instantOf({ ...wallFromDay(ctx.startDay), hh: 0, mm: 0 }, ctx.zone)) / 60000);
    } else {
      if (ctx.startAt === null) return null;
      minutes = Math.round((ms - ctx.startAt) / 60000);
    }
  } else {
    const d = parseDuration(trigger.value);
    if (!d) return null;
    minutes = d.days * 1440 + d.minutes;
    if (param(trigger, 'RELATED')?.toUpperCase() === 'END') {
      minutes += ctx.allDay ? ctx.days * 1440 : ctx.durationMinutes;
    }
  }
  if (ctx.allDay) {
    if (minutes >= 1440) return null;
    const days = minutes < 0 ? Math.ceil(-minutes / 1440) : 0;
    if (days > 28) return null;
    return { days, at: timeFromMinutes(minutes) };
  }
  const before = -minutes;
  if (before >= 0 && before <= MAX_LEAD_MINUTES) return { before };
  // After the start, or further ahead than a minutes alert holds: the wall
  // time it fires, as days before the start day at a time (the .ics writer's
  // form for such an alert).
  const wall = minutesOf(ctx.time) + minutes;
  const days = wall < 0 ? Math.ceil(-wall / 1440) : 0;
  if (wall >= 1440 || days > 28) return null;
  return { days, at: timeFromMinutes(wall) };
}

function wallFromDay(day: string): Wall {
  const [y, m, d] = day.split('-').map(Number) as [number, number, number];
  return { y, m, d, hh: 0, mm: 0 };
}

/** Without duplicates, sorted nearest first. */
function uniqueAlerts(list: Alert[]): Alert[] {
  const seen = new Set<string>();
  const out = list.filter((a) => {
    const k = JSON.stringify(a);
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  const lead = (a: Alert) => ('before' in a ? a.before : a.days * 1440 - (Number(a.at.slice(0, 2)) * 60 + Number(a.at.slice(3))));
  return out.sort((a, b) => lead(a) - lead(b));
}

// ── Events ─────────────────────────────────────────────────────────

type Counts = {
  emptyCalendars: number;
  cancelled: number;
  declined: number;
  noStart: number;
  refusedRules: number;
  keptInZone: number;
  drifting: number;
  spansCut: number;
  alertsDropped: number;
  alertsKept: number;
  noUid: number;
  repaired: number;
  repeating: number;
  comingWithoutAlert: number;
};

type Calendar = { name: string; self: string | null; zones: Map<string, number>; events: IcsComponent[] };

/**
 * The calendar's name. Google names each file `<calendar name>_<calendar
 * id>.ics` and writes the account's e-mail as X-WR-CALNAME for the primary
 * calendar AND for the Birthdays calendar, so when the header is an e-mail
 * and the file name starts with something else, the file name's first part
 * is the name. Otherwise X-WR-CALNAME, else the file name.
 */
function calendarName(cal: IcsComponent, fileName: string): string {
  const named = repairMojibake(unescapeText(prop(cal, 'X-WR-CALNAME')?.value ?? '').trim());
  const stem = fileName.split('/').pop()!.replace(/\.ics$/i, '');
  const cut = stem.indexOf('_');
  if (isEmail(named) && cut > 0 && /@/.test(stem.slice(cut)) && stem.slice(0, cut).toLowerCase() !== named.toLowerCase()) {
    return stem.slice(0, cut);
  }
  if (named) return named;
  return cut > 0 && /@/.test(stem.slice(cut)) ? stem.slice(0, cut) : stem;
}

/** Fixed offsets of VTIMEZONE blocks with one observance, for zone names that are not IANA. */
function fixedZones(cal: IcsComponent): Map<string, number> {
  const out = new Map<string, number>();
  for (const tz of cal.children.filter((c) => c.type === 'VTIMEZONE')) {
    const id = prop(tz, 'TZID')?.value.trim();
    if (!id || tz.children.length !== 1) continue;
    const m = /^([+-])(\d{2})(\d{2})/.exec(prop(tz.children[0]!, 'TZOFFSETTO')?.value.trim() ?? '');
    if (m) out.set(id, (m[1] === '-' ? -1 : 1) * (Number(m[2]) * 60 + Number(m[3])));
  }
  return out;
}

type Built = { trackers: Record<string, unknown>; lines: string[] };

/**
 * One VEVENT's schedule, in the frame the series uses. `skipFor` turns a
 * RECURRENCE-ID or EXDATE of this series into the stored day.
 */
function buildSchedule(
  ev: IcsComponent,
  cal: Calendar,
  device: string,
  counts: Counts,
  todayDay: string,
): (Built & { skipFor: (p: IcsProp) => string[] }) | null {
  const start = read(prop(ev, 'DTSTART'), cal.zones);
  if (!start) {
    counts.noStart++;
    return null;
  }
  const lines: string[] = [];
  const t: Record<string, unknown> = {};
  const rrule = prop(ev, 'RRULE');
  const extraRules = props(ev, 'RRULE').length > 1 || props(ev, 'RDATE').length > 0 || props(ev, 'EXRULE').length > 0;
  const recurrenceLines = () => ['RRULE', 'RDATE', 'EXRULE', 'EXDATE']
    .flatMap((n) => props(ev, n).map((p) => `${n}:${p.value}`))
    .join(' ');

  if (start.allDay) {
    t.journalDate = start.day;
    const end = read(prop(ev, 'DTEND'), cal.zones);
    const dur = parseDuration(prop(ev, 'DURATION')?.value ?? '');
    const endEx = end?.allDay ? end.day : dur ? shiftDay(start.day, Math.max(1, dur.days)) : shiftDay(start.day, 1);
    const last = shiftDay(endEx, -1);
    const span = dayNumber(last) - dayNumber(start.day);
    if (span > MAX_SPAN_DAYS) {
      counts.spansCut++;
      lines.push(`- ${label('ends')}: ${last}`);
    } else if (span > 0) {
      t.dateEnd = last;
    }
    const days = Math.max(1, span + 1);
    let repeat: Repeat | undefined;
    if (rrule) {
      const r = extraRules ? { ok: false as const } : rruleToRepeat(rrule.value, start.day, 0);
      // An end the file names but nobody can read refuses the rule: without it the series would never end.
      const u = r.ok && r.until ? readValue(r.until, undefined, cal.zones) : null;
      if (r.ok && (!r.until || u)) {
        repeat = r.repeat;
        if (u) repeat.until = u.allDay ? u.day : dayOf(u.wall);
      } else {
        counts.refusedRules++;
        lines.push(`- ${label('repeats')}: ${escapeMarkdownText(recurrenceLines())}`);
      }
    }
    const skipFor = (p: IcsProp) => p.value.split(',').flatMap((v) => {
      const w = readValue(v, param(p, 'TZID'), cal.zones);
      if (!w) return [];
      return [w.allDay ? w.day : dayOf(w.wall)];
    });
    finishRepeat(t, repeat, start.day, counts);
    const alerts = alertsOf(ev, { allDay: true, startDay: start.day, days, repeating: !!t.repeat, zone: device }, cal.zones, counts);
    if (alerts.length) t.alerts = alerts;
    else if (start.day >= todayDay) counts.comingWithoutAlert++;
    return { trackers: t, lines, skipFor };
  }

  // Timed.
  const sourceZone = start.zone;
  const startAt = instantOfWhen(start);
  let frame: string | null = start.zone ? device : null;
  let local = frame ? wallInFrame(start, frame) : start.wall;
  let shift = dayNumber(dayOf(local)) - dayNumber(dayOf(start.wall));

  const freq = /(?:^|;)FREQ=([A-Z]+)/i.exec(rrule?.value ?? '')?.[1]?.toUpperCase();
  const shiftable = !freq || freq === 'DAILY' || freq === 'WEEKLY';
  let shownZoneLine = false;
  if (rrule && shift !== 0 && !shiftable && sourceZone && !start.utc) {
    // A monthly or yearly series keeps its own zone's day and time.
    frame = sourceZone;
    local = start.wall;
    shift = 0;
    counts.keptInZone++;
    lines.push(`- ${label('timeZone')}: ${sourceZone}, ${timeOf(start.wall)}`);
    shownZoneLine = true;
  }
  if (!shownZoneLine && startAt !== null && sourceZone && !start.utc && offsetAt(startAt, sourceZone) !== offsetAt(startAt, device)) {
    lines.push(`- ${label('timeZone')}: ${sourceZone}, ${timeOf(start.wall)}`);
  }

  t.journalDate = dayOf(local);
  t.time = timeOf(local);

  // The end, in the same frame.
  let endWall: Wall | null = null;
  const end = read(prop(ev, 'DTEND'), cal.zones);
  const dur = parseDuration(prop(ev, 'DURATION')?.value ?? '');
  if (end && !end.allDay) {
    endWall = frame ? wallInFrame(end, frame) : end.wall;
  } else if (dur) {
    const base = addDaysToWall(start.wall, dur.days);
    if (start.zone && startAt !== null) {
      const baseAt = start.utc ? wallUtc(base) : instantOf(base, start.zone);
      endWall = wallIn(baseAt + dur.minutes * 60000, frame ?? 'UTC');
    } else {
      endWall = wallIn(wallUtc(base) + dur.minutes * 60000, 'UTC');
    }
  }
  let durationMinutes = 0;
  if (endWall) {
    durationMinutes = Math.round((wallUtc(endWall) - wallUtc(local)) / 60000);
    const endDay = dayOf(endWall);
    const endTime = timeOf(endWall);
    const days = dayNumber(endDay) - dayNumber(t.journalDate as string);
    if (days === 0) {
      if (endTime > (t.time as string)) t.timeEnd = endTime;
    } else if (days === 1 && endTime < (t.time as string)) {
      t.timeEnd = endTime;
    } else if (days > 0) {
      if (days > MAX_SPAN_DAYS) {
        counts.spansCut++;
        lines.push(`- ${label('ends')}: ${endDay} ${endTime}`);
      } else {
        t.dateEnd = endDay;
        if (endTime !== t.time) t.timeEnd = endTime;
      }
    }
  }

  let repeat: Repeat | undefined;
  if (rrule) {
    const r = extraRules ? { ok: false as const } : rruleToRepeat(rrule.value, t.journalDate as string, shift);
    // An end the file names but nobody can read refuses the rule: without it the series would never end.
    const u = r.ok && r.until ? readValue(r.until, undefined, cal.zones) : null;
    if (r.ok && (!r.until || u)) {
      repeat = r.repeat;
      if (u) {
        // The last occurrence that starts on or before the bound, in the source's own frame.
        const srcFrame = sourceZone && !start.utc ? sourceZone : 'UTC';
        const uw = u.allDay ? { ...wallFromDay(u.day), hh: 23, mm: 59 } : start.zone ? wallInFrame(u, srcFrame) : u.wall;
        let untilSource = dayOf(uw);
        if (timeOf(uw) < timeOf(start.wall)) untilSource = shiftDay(untilSource, -1);
        repeat.until = shiftDay(untilSource, shift);
      }
      if (startAt !== null && sourceZone && frame === device) {
        // Four dates across a year: a clock change in either zone shows as a different gap.
        const gaps = new Set([0, 91, 182, 273].map((d) => {
          const at = startAt + d * 864e5;
          return offsetAt(at, sourceZone) - offsetAt(at, device);
        }));
        if (gaps.size > 1) counts.drifting++;
      }
    } else {
      counts.refusedRules++;
      lines.push(`- ${label('repeats')}: ${escapeMarkdownText(recurrenceLines())}`);
    }
  }
  const skipFor = (p: IcsProp) => p.value.split(',').flatMap((v) => {
    const w = readValue(v, param(p, 'TZID'), cal.zones);
    if (!w) return [];
    if (w.allDay) return [shiftDay(w.day, shift)];
    // The day in the series' own source frame, then the series' one shift.
    const src = w.zone && sourceZone && !start.utc ? wallInFrame(w, sourceZone) : w.zone ? wallInFrame(w, 'UTC') : w.wall;
    return [shiftDay(dayOf(src), shift)];
  });
  finishRepeat(t, repeat, t.journalDate as string, counts);
  const alerts = alertsOf(ev, { allDay: false, startAt, durationMinutes, repeating: !!t.repeat, time: t.time as string }, cal.zones, counts);
  if (alerts.length) t.alerts = alerts;
  else if ((t.journalDate as string) >= todayDay) counts.comingWithoutAlert++;
  return { trackers: t, lines, skipFor };
}

function finishRepeat(t: Record<string, unknown>, repeat: Repeat | undefined, start: string, counts: Counts): void {
  if (!repeat) return;
  // A bound before the start leaves one occurrence: no series.
  if (repeat.until && repeat.until < start) return;
  t.repeat = repeat;
  counts.repeating++;
}

function alertsOf(ev: IcsComponent, ctx: AlertContext, zones: Map<string, number>, counts: Counts): Alert[] {
  const found = ev.children.filter((c) => c.type === 'VALARM').map((a) => {
    const alert = readAlert(a, ctx, zones);
    const action = (prop(a, 'ACTION')?.value ?? '').trim().toUpperCase();
    const ignored = action === 'NONE' || prop(a, 'TRIGGER')?.value.trim() === IGNORED_TRIGGER;
    if (!alert && !ignored) counts.alertsDropped++;
    return alert;
  }).filter((a): a is Alert => a !== null);
  const unique = uniqueAlerts(found);
  const kept = unique.slice(0, MAX_ALERTS);
  counts.alertsDropped += unique.length - kept.length;
  counts.alertsKept += kept.length;
  return kept;
}

/** A field shown as typed; a URL or address in it stays a working link. */
const literal = (s: string): string => linkifyLiteralText(s, escapeMarkdownText).markdown;

/** The details list and the description, as the event's markdown body. */
function buildBody(ev: IcsComponent, cal: Calendar, scheduleLines: string[], counts: Counts): string {
  const lines: string[] = [];
  let repaired = false;
  const loc = textValue(prop(ev, 'LOCATION'));
  repaired ||= loc.repaired;
  if (loc.text.trim()) {
    lines.push(`- ${label('location')}: ${isWebLink(loc.text) ? linkText(loc.text) : literal(loc.text.trim().replace(/\n+/g, ', '))}`);
  } else {
    const apple = prop(ev, 'X-APPLE-STRUCTURED-LOCATION');
    const place = [param(apple, 'X-TITLE'), param(apple, 'X-ADDRESS')]
      .filter(Boolean).map((v) => v!.replace(/\\\\n|\\n/g, ', ').trim()).filter(Boolean);
    if (place.length) lines.push(`- ${label('location')}: ${literal(place.join(', '))}`);
  }
  const conference = prop(ev, 'X-GOOGLE-CONFERENCE')?.value.trim();
  if (conference && isWebLink(conference)) lines.push(`- ${label('videoCall')}: ${linkText(conference)}`);

  const organizer = prop(ev, 'ORGANIZER');
  const organizerMail = organizer ? mailOf(organizer.value).toLowerCase() : '';
  if (organizer && organizerMail !== cal.self) {
    const name = param(organizer, 'CN') || organizerMail;
    if (name) lines.push(`- ${label('organizer')}: ${literal(repairMojibake(name))}`);
  }
  const guests = props(ev, 'ATTENDEE')
    .filter((a) => !['ROOM', 'RESOURCE'].includes((param(a, 'CUTYPE') ?? '').toUpperCase()))
    .filter((a) => {
      const mail = mailOf(a.value).toLowerCase();
      return mail !== cal.self && mail !== organizerMail;
    })
    .map((a) => repairMojibake(param(a, 'CN') || mailOf(a.value)))
    .filter(Boolean);
  if (guests.length) lines.push(`- ${label('guests')}: ${guests.map(literal).join(', ')}`);

  for (const att of props(ev, 'ATTACH')) {
    const url = att.value.trim();
    if (!isWebLink(url)) continue;
    const name = param(att, 'FILENAME');
    lines.push(`- ${label('file')}: ${name ? `[${escapeMarkdownText(name)}](${safeUrl(url)})` : linkText(url)}`);
  }
  const url = prop(ev, 'URL')?.value.trim();
  if (url && isWebLink(url)) lines.push(`- ${label('link')}: ${linkText(url)}`);
  lines.push(...scheduleLines);

  const desc = textValue(prop(ev, 'DESCRIPTION'));
  repaired ||= desc.repaired;
  let text = desc.text.replace(/\r\n?/g, '\n').trim();
  if (text && HTML_TAG.test(text)) text = htmlNoteToMarkdown(text).trim();
  const summary = textValue(prop(ev, 'SUMMARY'));
  if (repaired || summary.repaired) counts.repaired++;

  const body = [lines.join('\n'), text].filter(Boolean).join('\n\n');
  return body ? linkifyMarkdown(body) : '';
}

const isoStamp = (p: IcsProp | undefined, zones: Map<string, number>): string | null => {
  const w = read(p, zones);
  if (!w || w.allDay) return null;
  const at = instantOfWhen(w);
  return at === null ? null : new Date(at).toISOString();
};

/** The person's own e-mail: the primary calendar is named after it. */
function selfOf(cal: IcsComponent): string | null {
  const name = unescapeText(prop(cal, 'X-WR-CALNAME')?.value ?? '').trim().toLowerCase();
  return isEmail(name) ? name : null;
}

const isDeclinedBySelf = (ev: IcsComponent, self: string | null) =>
  !!self && props(ev, 'ATTENDEE').some((a) => mailOf(a.value).toLowerCase() === self && (param(a, 'PARTSTAT') ?? '').toUpperCase() === 'DECLINED');

/** The UID as text: RFC 5545 types it TEXT, and the .ics writer escapes it once. */
const uidOf = (ev: IcsComponent) => unescapeText(prop(ev, 'UID')?.value ?? '').trim();

const isCancelled = (ev: IcsComponent) => (prop(ev, 'STATUS')?.value ?? '').trim().toUpperCase() === 'CANCELLED';

/**
 * The importer's core, on files already read. `zone` is the device's zone
 * (an option so tests can pin one); `today` decides which events are coming.
 */
export function parseCalendarFiles(
  files: CalendarFile[],
  opts: { zone?: string; today?: string } = {},
): ParsedImport {
  const device = opts.zone ?? Intl.DateTimeFormat().resolvedOptions().timeZone;
  const todayDay = opts.today ?? dayOf(wallIn(Date.now(), device));
  const now = new Date().toISOString();
  const counts: Counts = {
    emptyCalendars: 0, cancelled: 0, declined: 0, noStart: 0, refusedRules: 0, keptInZone: 0, drifting: 0,
    spansCut: 0, alertsDropped: 0, alertsKept: 0, noUid: 0, repaired: 0, repeating: 0, comingWithoutAlert: 0,
  };

  const calendars: Calendar[] = [];
  let components = 0;
  for (const f of files) {
    for (const cal of parseIcs(unfoldBytes(f.bytes))) {
      if (cal.type !== 'VCALENDAR') continue;
      components += 1 + cal.children.length;
      if (components > ICS_LIMITS.components) throw new ImportTooLargeError(`The calendar files hold more than ${ICS_LIMITS.components} entries.`);
      const events = cal.children.filter((c) => c.type === 'VEVENT');
      if (events.length === 0) {
        counts.emptyCalendars++;
        continue;
      }
      calendars.push({ name: calendarName(cal, f.name), self: selfOf(cal), zones: fixedZones(cal), events });
    }
  }
  if (calendars.length === 0 && counts.emptyCalendars === 0) {
    throw new Error('Not a calendar file - expected BEGIN:VCALENDAR with events.');
  }

  const { folders, dirToFolderId } = buildFolderTree(calendars.map((c) => c.name));
  const notes: ImportedNote[] = [];
  // Which calendar's group of a UID lands: the first that holds the series
  // itself, else the first. An invitation in two of the person's calendars
  // lands once, and a calendar holding only one moved occurrence never
  // hides the series another calendar holds.
  const winner = new Map<string, { cal: Calendar; master: boolean }>();
  const exceptionsByUid = new Map<string, Map<string, IcsComponent>>();
  for (const cal of calendars) {
    const here = new Map<string, boolean>();
    for (const ev of cal.events) {
      const uid = uidOf(ev);
      if (!uid) continue;
      here.set(uid, (here.get(uid) ?? false) || !prop(ev, 'RECURRENCE-ID'));
      const rid = prop(ev, 'RECURRENCE-ID')?.value.trim();
      if (rid) {
        const byRid = exceptionsByUid.get(uid) ?? new Map<string, IcsComponent>();
        if (!byRid.has(rid)) byRid.set(rid, ev);
        exceptionsByUid.set(uid, byRid);
      }
    }
    for (const [uid, master] of here) {
      const held = winner.get(uid);
      if (!held || (master && !held.master)) winner.set(uid, { cal, master });
    }
  }

  for (const cal of calendars) {
    // Group by UID: the master and its changed or cancelled occurrences.
    const groups = new Map<string, IcsComponent[]>();
    const loose: IcsComponent[] = [];
    for (const ev of cal.events) {
      const uid = uidOf(ev);
      if (!uid) loose.push(ev);
      else {
        const group = groups.get(uid);
        if (group) group.push(ev);
        else groups.set(uid, [ev]);
      }
    }
    const emit = (ev: IcsComponent, built: Built, ics: Record<string, string> | null) => {
      const title = textValue(prop(ev, 'SUMMARY')).text.replace(/\s+/g, ' ').trim();
      const tags = splitTextList(prop(ev, 'CATEGORIES')?.value ?? '')
        .map((c) => normalizeTag(repairMojibake(c))).filter((c): c is string => !!c);
      const createdAt = isoStamp(prop(ev, 'CREATED'), cal.zones) ?? isoStamp(prop(ev, 'DTSTAMP'), cal.zones) ?? now;
      const updatedAt = isoStamp(prop(ev, 'LAST-MODIFIED'), cal.zones) ?? createdAt;
      const trackers = normalizeSchedule({ ...built.trackers, ...(ics ? { ics } : {}) }, 'event') ?? {};
      notes.push({
        title,
        body: buildBody(ev, cal, built.lines, counts),
        tags: [...new Set(tags)],
        createdAt,
        updatedAt,
        type: 'event',
        trackers,
        folderId: dirToFolderId.get(cal.name) ?? null,
        folderPath: [cal.name],
      });
    };

    for (const ev of loose) {
      if (isCancelled(ev) || isDeclinedBySelf(ev, cal.self)) {
        counts[isCancelled(ev) ? 'cancelled' : 'declined']++;
        continue;
      }
      const built = buildSchedule(ev, cal, device, counts, todayDay);
      if (!built) continue;
      counts.noUid++;
      emit(ev, built, null);
    }

    for (const [uid, group] of groups) {
      if (winner.get(uid)?.cal !== cal) continue;
      const master = group.find((e) => !prop(e, 'RECURRENCE-ID'));
      // Changed occurrences from every calendar, one per RECURRENCE-ID.
      const exceptions = [...(exceptionsByUid.get(uid)?.values() ?? [])];
      let masterBuilt: ReturnType<typeof buildSchedule> = null;
      if (master) {
        if (isCancelled(master) || isDeclinedBySelf(master, cal.self)) {
          counts[isCancelled(master) ? 'cancelled' : 'declined']++;
          continue;
        }
        masterBuilt = buildSchedule(master, cal, device, counts, todayDay);
      }
      if (masterBuilt) {
        const repeat = masterBuilt.trackers.repeat as Repeat | undefined;
        if (repeat) {
          const skip = new Set<string>(repeat.skip ?? []);
          for (const ex of props(master!, 'EXDATE')) for (const d of masterBuilt.skipFor(ex)) skip.add(d);
          for (const ex of exceptions) for (const d of masterBuilt.skipFor(prop(ex, 'RECURRENCE-ID')!)) skip.add(d);
          if (skip.size) repeat.skip = [...skip].sort();
        }
        emit(master!, masterBuilt, { uid });
      }
      for (const ex of exceptions) {
        if (isCancelled(ex) || isDeclinedBySelf(ex, cal.self)) continue;
        const built = buildSchedule(ex, cal, device, counts, todayDay);
        if (!built) continue;
        delete built.trackers.repeat;
        emit(ex, built, { uid, rid: prop(ex, 'RECURRENCE-ID')!.value.trim() });
      }
    }
  }

  const warnings: string[] = [];
  const transforms: string[] = [];
  const n = (k: number, one: string, many: string) => `${k} ${k === 1 ? one : many}`;
  if (folders.length) transforms.push(`Each calendar became a folder (${n(folders.length, 'folder', 'folders')}).`);
  if (counts.repeating) transforms.push(counts.repeating === 1 ? '1 repeating event keeps its rule.' : `${counts.repeating} repeating events keep their rule.`);
  if (counts.alertsKept) transforms.push(`${n(counts.alertsKept, 'reminder', 'reminders')} kept.`);
  if (counts.repaired) transforms.push(`Repaired garbled characters in ${n(counts.repaired, 'event', 'events')}.`);
  if (counts.emptyCalendars) warnings.push(`${n(counts.emptyCalendars, 'calendar was', 'calendars were')} empty and skipped.`);
  if (counts.cancelled) warnings.push(`${n(counts.cancelled, 'cancelled event was', 'cancelled events were')} skipped.`);
  if (counts.declined) warnings.push(`${n(counts.declined, 'invitation you declined was', 'invitations you declined were')} skipped.`);
  if (counts.noStart) warnings.push(`${n(counts.noStart, 'event has', 'events have')} no start and ${counts.noStart === 1 ? 'was' : 'were'} skipped.`);
  if (counts.refusedRules) warnings.push(`${n(counts.refusedRules, 'repeat rule', 'repeat rules')} could not be kept: the first occurrence is imported and the rule is in the event's text.`);
  if (counts.keptInZone) warnings.push(`${n(counts.keptInZone, 'monthly or yearly event keeps', 'monthly or yearly events keep')} the day and time of ${counts.keptInZone === 1 ? 'its' : 'their'} own time zone.`);
  if (counts.drifting) warnings.push(`${n(counts.drifting, 'repeating event is', 'repeating events are')} set in a time zone that changes its clocks on other dates, so ${counts.drifting === 1 ? 'it' : 'they'} can be an hour off for part of the year.`);
  if (counts.spansCut) warnings.push(`${n(counts.spansCut, 'event lasts', 'events last')} longer than a year: the end is in the text.`);
  if (counts.alertsDropped) warnings.push(`${n(counts.alertsDropped, 'reminder', 'reminders')} could not be kept.`);
  if (counts.comingWithoutAlert) warnings.push(`${n(counts.comingWithoutAlert, 'coming event has', 'coming events have')} no reminder in the file. Google leaves out reminders that come from a calendar's defaults.`);
  if (counts.noUid) warnings.push(`${n(counts.noUid, 'event has', 'events have')} no id, so importing the file again adds ${counts.noUid === 1 ? 'it' : 'them'} again.`);

  const uniqueTags = new Set(notes.flatMap((x) => x.tags));
  return {
    notes,
    warnings,
    transforms,
    stats: {
      totalNotes: notes.length,
      emptyNotes: notes.filter((x) => !x.title.trim() && !x.body.trim()).length,
      untaggedNotes: notes.filter((x) => x.tags.length === 0).length,
      uniqueTags: uniqueTags.size,
    },
    source: 'google-calendar',
    folders,
  };
}

export async function parseGoogleCalendar(file: File, onProgress?: (msg: string) => void): Promise<ParsedImport> {
  onProgress?.('Reading calendar…');
  const files = await readFiles(file);
  onProgress?.('Reading events…');
  return parseCalendarFiles(files);
}
