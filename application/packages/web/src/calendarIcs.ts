import type { LocalNote } from './db';
import i18n from './i18n';
import { escapeText, foldLine } from './icsLines';
import { repeatToRrule } from './icsRepeat';
import { deriveDisplayTitle } from './notesViewUtils';
import {
  SOURCE_IDENTITY_KEY,
  goesToCalendarFile,
  lastOccurrence,
  minutesOf,
  scheduleOf,
  shiftDay,
  type Alert,
  type Schedule,
} from './schedule';

/**
 * The calendar as an iCalendar file: every event, dated note and dated task
 * list (`goesToCalendarFile`). Times are written floating, the model's own
 * rule, so 15:00 is 15:00 wherever the file is opened; Google reads a
 * floating time in the target calendar's zone, Outlook in the user's, Apple
 * keeps it floating. A PIN-protected item goes out as a busy block with no
 * content, because this file is made to be uploaded elsewhere.
 *
 * Google refuses a file over 1 MB, so the export made for other apps can be
 * cut into parts of whole events; the copy inside a backup is one file.
 * Spec: ops/docs/archive/google-calendar-import.md (section 5)
 */

/** Google's import limit, in bytes. */
const PART_LIMIT = 1_000_000;

const HEADER = [
  'BEGIN:VCALENDAR',
  'VERSION:2.0',
  'PRODID:-//PrivacyNotes//Calendar//EN',
  'CALSCALE:GREGORIAN',
  'METHOD:PUBLISH',
  'X-WR-CALNAME:PrivacyNotes',
].map(foldLine).join('');
const FOOTER = foldLine('END:VCALENDAR');

const compactDay = (day: string) => day.replaceAll('-', '');
const floating = (day: string, time: string) => `${compactDay(day)}T${time.replace(':', '')}00`;

function utcStamp(iso: string | undefined, fallback: Date): string {
  const at = iso ? Date.parse(iso) : NaN;
  return (Number.isNaN(at) ? fallback : new Date(at)).toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
}

/** The body as plain text: pictures and files by name, note-links by their title. */
function descriptionOf(body: string): string {
  return body
    .replace(/!\[([^\]]*)\]\(pn:img\/[^)]*\)/g, (_, alt: string) => alt)
    .replace(/\[([^\]]*)\]\(pn:file\/[^)]*\)/g, (_, name: string) => name)
    .replace(/\[\[([^\]|]+)(?:\|([^\]]*))?\]\]/g, (_, target: string, alias?: string) => alias || target)
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

/**
 * An alert as an offset from the event's DTSTART, at the wall time the app
 * fires it (`alertInstant` in reminders.ts): an all-day item starts at
 * midnight and counts a minutes alert from 09:00, a timed one counts a days
 * alert from its own start. Either kind survives the all-day switch.
 */
function triggerOf(a: Alert, s: Schedule): string {
  const start = s.time ? minutesOf(s.time) : 0;
  const fires = 'before' in a ? (s.time ? start : minutesOf('09:00')) - a.before : -a.days * 1440 + minutesOf(a.at);
  const minutes = fires - start;
  return minutes < 0 ? `-PT${-minutes}M` : `PT${minutes}M`;
}

function scheduleLines(s: Schedule): string[] {
  const lines: string[] = [];
  if (!s.time) {
    lines.push(`DTSTART;VALUE=DATE:${compactDay(s.day)}`);
    lines.push(`DTEND;VALUE=DATE:${compactDay(shiftDay(s.end ?? s.day, 1))}`);
  } else {
    lines.push(`DTSTART:${floating(s.day, s.time)}`);
    if (s.timeEnd) {
      const endDay = s.end ?? (s.timeEnd < s.time ? shiftDay(s.day, 1) : s.day);
      lines.push(`DTEND:${floating(endDay, s.timeEnd)}`);
    } else if (s.end) {
      // An end day with no end time ends at the start's time (24 hours and multiples).
      lines.push(`DTEND:${floating(s.end, s.time)}`);
    }
  }
  if (s.repeat) {
    const untilValue = (day: string) => (s.time ? `${compactDay(day)}T235959` : compactDay(day));
    let untilDay: string | undefined;
    if (s.repeat.until !== undefined && s.repeat.count !== undefined) {
      // RFC 5545 forbids both; the series ends at whichever comes first.
      untilDay = lastOccurrence(s.day, s.repeat) ?? s.repeat.until;
    }
    lines.push(`RRULE:${repeatToRrule(s.repeat, s.day, untilValue, untilDay)}`);
    if (s.repeat.skip?.length) {
      const values = s.repeat.skip.map((d) => (s.time ? floating(d, s.time) : compactDay(d))).join(',');
      lines.push(s.time ? `EXDATE:${values}` : `EXDATE;VALUE=DATE:${values}`);
    }
  }
  return lines;
}

/** One VEVENT, or null when the item does not go into a calendar file. */
function eventOf(n: LocalNote, usedUids: Set<string>, now: Date): string | null {
  if (!goesToCalendarFile(n)) return null;
  const s = scheduleOf(n.trackers, n.type);
  if (!s) return null;
  const hidden = n.pinProtected === 1;

  const source = n.trackers?.[SOURCE_IDENTITY_KEY] as { uid?: unknown; rid?: unknown } | undefined;
  let uid = typeof source?.uid === 'string' && source.uid && source.rid === undefined ? source.uid : '';
  if (!uid || usedUids.has(uid)) uid = `${n.id}@privacynotes.app`;
  usedUids.add(uid);

  const summary = hidden ? i18n.t('importExport:export.calendarPrivate') : deriveDisplayTitle(n);
  const lines = [
    'BEGIN:VEVENT',
    `UID:${escapeText(uid)}`,
    `DTSTAMP:${utcStamp(undefined, now)}`,
    `CREATED:${utcStamp(n.createdAt, now)}`,
    `LAST-MODIFIED:${utcStamp(n.editedAt ?? n.updatedAt, now)}`,
    `SUMMARY:${escapeText(summary)}`,
    ...scheduleLines(s),
  ];
  if (hidden) {
    lines.push('CLASS:PRIVATE');
  } else {
    const description = descriptionOf(n.body ?? '');
    if (description) lines.push(`DESCRIPTION:${escapeText(description)}`);
    if (n.tags?.length) lines.push(`CATEGORIES:${n.tags.map(escapeText).join(',')}`);
  }
  for (const a of s.alerts ?? []) {
    lines.push('BEGIN:VALARM', 'ACTION:DISPLAY', `DESCRIPTION:${escapeText(summary)}`, `TRIGGER:${triggerOf(a, s)}`, 'END:VALARM');
  }
  lines.push('END:VEVENT');
  return lines.map(foldLine).join('');
}

/**
 * The calendar files for a set of items: one, or with `split` as many parts
 * of whole events, oldest first, as keep each under Google's 1 MB. An event
 * that alone passes the limit gets a part of its own. Empty when no item
 * goes into a calendar file.
 */
export function buildCalendarFiles(notes: LocalNote[], opts: { split: boolean; now?: Date } = { split: false }): string[] {
  const now = opts.now ?? new Date();
  const used = new Set<string>();
  const dated = notes
    .filter(goesToCalendarFile)
    .map((n) => ({ n, day: scheduleOf(n.trackers, n.type)!.day }))
    .sort((a, b) => (a.day < b.day ? -1 : a.day > b.day ? 1 : 0));
  const events = dated.map(({ n }) => eventOf(n, used, now)).filter((e): e is string => e !== null);
  if (events.length === 0) return [];
  if (!opts.split) return [HEADER + events.join('') + FOOTER];

  const encoder = new TextEncoder();
  const frame = encoder.encode(HEADER + FOOTER).length;
  const parts: string[] = [];
  let current: string[] = [];
  let size = frame;
  for (const e of events) {
    const bytes = encoder.encode(e).length;
    if (current.length && size + bytes > PART_LIMIT) {
      parts.push(HEADER + current.join('') + FOOTER);
      current = [];
      size = frame;
    }
    current.push(e);
    size += bytes;
  }
  if (current.length) parts.push(HEADER + current.join('') + FOOTER);
  return parts;
}
