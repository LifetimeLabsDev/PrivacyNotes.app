import { foldForMatch } from './textMatch';
import { shiftDay, weekdayOf, dayNumber, parseTimeText, minutesOf, timeFromMinutes, nextOccurrence, type Alert, type Repeat } from './schedule';

/**
 * Quick add: a title with a day, a span, a time, a range, a duration, a
 * repeat, an end, alerts, a folder, a tag, a space and a type read out of the
 * typed words. Two sources of words, both folded the same way: the engine's
 * own (weekday and month names, today, tomorrow, next week, in N days, from
 * `Intl`, in every language) and one small catalog per language
 * (`quickAdd.json`). Text in quotes is never read; a bare number is never a
 * day; a month name alone is never a date; everything read leaves the title,
 * and the rest is the title. Pure: the caller hands in the words, the locale
 * and today.
 * Spec: ops/docs/plans/calendar-pillar-spec.md (step 8)
 */

export type QuickAddType = 'event' | 'note' | 'task' | 'journal';
type QuickAddPartKind = 'date' | 'span' | 'time' | 'duration' | 'repeat' | 'alert' | 'tag' | 'folder' | 'space' | 'type';

export type QuickAdd = {
  title: string;
  type: QuickAddType | null;
  day?: string;
  end?: string;
  time?: string;
  timeEnd?: string;
  repeat?: Repeat;
  alerts: Alert[];
  tags: string[];
  folderId: string | null;
  space: 'work' | 'personal' | null;
  /** What was read, in the order typed, with the text it came from. */
  parts: { kind: QuickAddPartKind; text: string }[];
};

/** The catalog words, each a list of folded alternatives. */
export type QuickAddWords = Record<
  'every' | 'weekday' | 'daily' | 'weekly' | 'monthly' | 'yearly' | 'until' | 'for' | 'at' | 'from' | 'to' | 'next'
  | 'this' | 'last' | 'other' | 'noon' | 'midnight' | 'tonight' | 'dayAfter'
  | 'before' | 'alert' | 'oclock' | 'on' | 'and' | 'task' | 'journal' | 'note' | 'event' | 'minute' | 'hour' | 'day'
  | 'week' | 'month' | 'year' | 'times' | 'ordinal' | 'work' | 'personal',
  string[]
>;

/** The catalog's comma lists, split and folded. English fills a missing word. */
export function readWords(catalog: Record<string, string> | undefined, english: Record<string, string>): QuickAddWords {
  const out = {} as QuickAddWords;
  for (const key of Object.keys(english) as (keyof QuickAddWords)[]) {
    const raw = catalog?.[key] || english[key] || '';
    out[key] = raw.split(',').map((w) => foldForMatch(apos(w)).trim()).filter(Boolean);
  }
  return out;
}

/** The words the engine names in a language: weekdays, months, relative days. */
export type EngineWords = {
  weekdays: string[][];
  /** The same names with their accents, which tell apart two names that fold
   *  alike (Slovak "št" Thursday and "st" Wednesday). */
  weekdaysExact: string[][];
  months: string[][];
  /** Offset in days to the folded phrase: -1, 0, 1, 2. */
  relative: Map<string, number>;
  /** "next week" as the engine writes it. */
  nextWeek: string[];
  /** "in N days" as a pattern of folded words with `#` for the number. */
  inDays: string[];
  inWeeks: string[];
  /** Day first or month first, for a date in digits. */
  order: 'dmy' | 'mdy' | 'ymd';
};

/** One apostrophe: the engine writes a curly one or a modifier letter
 *  (French "aujourd’hui", Ukrainian "пʼятниця"), a keyboard types a straight one. */
function apos(w: string): string {
  return w.replace(/[’‘ʼ`´]/g, "'");
}

function strip(w: string): string {
  return foldForMatch(apos(w)).replace(/[.,]+$/, '').trim();
}

/** Lower case with the accents kept. */
function lower(w: string): string {
  return apos(w.normalize('NFC')).toLowerCase().replace(/[.,]+$/, '').trim();
}

// Building the names takes many Intl formatters, which are slow to construct
// in some engines, so each locale and order is built once.
const engineCache = new Map<string, EngineWords>();

/** Engine words for a locale, from Intl. */
export function engineWords(locale: string, order: 'dmy' | 'mdy' | 'ymd'): EngineWords {
  const key = `${locale}|${order}`;
  let words = engineCache.get(key);
  if (!words) engineCache.set(key, (words = buildEngineWords(locale, order)));
  return words;
}

function buildEngineWords(locale: string, order: 'dmy' | 'mdy' | 'ymd'): EngineWords {
  const names = (opts: Intl.DateTimeFormatOptions, dates: Date[]) =>
    dates.map((d) => [...new Set([strip(new Intl.DateTimeFormat(locale, { ...opts, timeZone: 'UTC' }).format(d)), strip(new Intl.DateTimeFormat('en', { ...opts, timeZone: 'UTC' }).format(d))])]); // date-ok: names to read, never shown
  const weekdayDates = Array.from({ length: 7 }, (_, w) => new Date(Date.UTC(2026, 9, 11 + w)));
  const monthDates = Array.from({ length: 12 }, (_, m) => new Date(Date.UTC(2026, m, 15)));
  const shortWeekdays = names({ weekday: 'short' }, weekdayDates);
  const shortMonths = names({ month: 'short' }, monthDates);
  const weekdays = names({ weekday: 'long' }, weekdayDates).map((l, w) => [...new Set([...l, ...shortWeekdays[w]!])]);
  const exact = (opts: Intl.DateTimeFormatOptions, d: Date) => lower(new Intl.DateTimeFormat(locale, { ...opts, timeZone: 'UTC' }).format(d)); // date-ok: names to read, never shown
  const weekdaysExact = weekdayDates.map((d) => [...new Set([exact({ weekday: 'long' }, d), exact({ weekday: 'short' }, d)])]);
  const months = names({ month: 'long' }, monthDates).map((l, m) => [...new Set([...l, ...shortMonths[m]!])]);
  const relative = new Map<string, number>();
  const rtf = (loc: string) => new Intl.RelativeTimeFormat(loc, { numeric: 'auto' });
  for (const loc of [locale, 'en']) {
    for (const n of [-1, 0, 1, 2]) {
      const phrase = strip(rtf(loc).format(n, 'day'));
      if (!/\d/.test(phrase) && !relative.has(phrase)) relative.set(phrase, n);
    }
  }
  const pattern = (unit: Intl.RelativeTimeFormatUnit) => strip(rtf(locale).format(5, unit)).replace('5', '#').split(/\s+/);
  return {
    weekdays,
    weekdaysExact,
    months,
    relative,
    nextWeek: strip(rtf(locale).format(1, 'week')).split(/\s+/),
    inDays: pattern('day'),
    inWeeks: pattern('week'),
    order,
  };
}

// ── Tokens ────────────────────────────────────────────────────────

type Token = { raw: string; f: string; used: boolean; quoted: boolean };

function tokenize(input: string): Token[] {
  const out: Token[] = [];
  const re = /"([^"]*)"|“([^”]*)”|«([^»]*)»|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(input))) {
    const quoted = m[4] === undefined;
    const raw = quoted ? (m[1] ?? m[2] ?? m[3] ?? '') : m[4]!;
    out.push({ raw, f: quoted ? '' : strip(raw), used: false, quoted });
  }
  return out;
}

const UNIT_MINUTES = { minute: 1, hour: 60, day: 1440, week: 10080 } as const;

/**
 * Read a quick-add line. `today` is the local ISO day, `defaultDay` the day
 * a calendar cell gave (or today); `folders` the names that `/Name` finds.
 */
export function parseQuickAdd(
  input: string,
  ctx: {
    words: QuickAddWords;
    engine: EngineWords;
    today: string;
    defaultDay?: string;
    folders?: readonly { id: string; name: string }[];
  },
): QuickAdd {
  const { words: W, engine: E, today } = ctx;
  const t = tokenize(input);
  const res: QuickAdd = { title: '', type: null, alerts: [], tags: [], folderId: null, space: null, parts: [] };
  const free = (i: number) => i >= 0 && i < t.length && !t[i]!.used && !t[i]!.quoted;
  const is = (i: number, list: string[]) => free(i) && list.includes(t[i]!.f);
  const take = (from: number, len: number, kind: QuickAddPartKind) => {
    const text: string[] = [];
    for (let k = from; k < from + len; k++) {
      t[k]!.used = true;
      text.push(t[k]!.raw);
    }
    res.parts.push({ kind, text: text.join(' ') });
  };
  /** A phrase of folded words at `i`, `#` matching a number; the number when it has one. */
  const phraseAt = (i: number, phrase: string[]): { len: number; n?: number } | null => {
    let n: number | undefined;
    for (let k = 0; k < phrase.length; k++) {
      if (!free(i + k)) return null;
      const want = phrase[k]!;
      const got = t[i + k]!.f;
      if (want === '#') {
        if (!/^\d{1,3}$/.test(got)) return null;
        n = Number(got);
      } else if (want !== got) return null;
    }
    return phrase.length ? { len: phrase.length, n } : null;
  };

  // A number glued to a unit ("10m", "2h", "3days") or standing before one.
  const amountAt = (i: number): { len: number; n: number; unit: keyof typeof UNIT_MINUTES | 'month' | 'year' } | null => {
    if (!free(i)) return null;
    const units: [keyof QuickAddWords, keyof typeof UNIT_MINUTES | 'month' | 'year'][] = [['minute', 'minute'], ['hour', 'hour'], ['day', 'day'], ['week', 'week'], ['month', 'month'], ['year', 'year']];
    const glued = /^(\d{1,3})([^\d\s]+)$/.exec(t[i]!.f);
    if (glued) {
      const hit = units.find(([k]) => W[k].includes(glued[2]!));
      if (hit) return { len: 1, n: Number(glued[1]), unit: hit[1] };
    }
    if (/^\d{1,3}$/.test(t[i]!.f) && free(i + 1)) {
      const hit = units.find(([k]) => W[k].includes(t[i + 1]!.f));
      if (hit) return { len: 2, n: Number(t[i]!.f), unit: hit[1] };
    }
    return null;
  };

  // ── Dates ──
  const weekdayAt = (i: number): number | null => {
    if (!free(i)) return null;
    const raw = lower(t[i]!.raw);
    const exact = E.weekdaysExact.findIndex((l) => l.includes(raw));
    if (exact !== -1) return exact;
    const w = E.weekdays.findIndex((l) => l.includes(t[i]!.f));
    return w === -1 ? null : w;
  };
  const monthAt = (i: number): number | null => {
    if (!free(i)) return null;
    const m = E.months.findIndex((l) => l.includes(t[i]!.f));
    return m === -1 ? null : m;
  };
  const ordinalDay = (i: number): number | null => {
    if (!free(i)) return null;
    const m = /^(\d{1,2})(.*)$/.exec(t[i]!.f);
    if (!m || (m[2] && !W.ordinal.includes(m[2]))) return null;
    const d = Number(m[1]);
    return d >= 1 && d <= 31 ? d : null;
  };
  /** The day of a monthly repeat ("on the 1st"), never an alert's amount ("1 day before"). */
  const monthDay = (j: number): number | null => {
    const d = ordinalDay(j);
    const a = d === null ? null : amountAt(j);
    return a && is(j + a.len, W.before) ? null : d;
  };
  /** A day and month with no year: the next time it comes, today included. */
  const upcoming = (month: number, d: number): string | null => {
    const year = Number(today.slice(0, 4));
    for (const y of [year, year + 1]) {
      const iso = `${y}-${String(month + 1).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
      if (dayNumber(iso) !== dayNumber(iso) || shiftDay(iso, 0) !== iso) continue;
      if (iso >= today) return iso;
    }
    return null;
  };
  const numericDate = (raw: string): string | null => {
    const iso = /^(\d{4})-(\d{2})-(\d{2})$/.exec(raw);
    if (iso) return shiftDay(raw, 0) === raw ? raw : null;
    const dots = /^(\d{1,2})\.(\d{1,2})\.(\d{2,4})?$/.exec(raw);
    const slash = /^(\d{1,2})\/(\d{1,2})(?:\/(\d{2,4}))?$/.exec(raw);
    const m = dots ?? slash;
    if (!m) return null;
    let d = Number(m[1]);
    let mo = Number(m[2]);
    // Month first wherever the year is not last: "10/20" is October 20 in mdy and ymd.
    if (slash && E.order !== 'dmy') [d, mo] = [mo, d];
    if (mo < 1 || mo > 12 || d < 1 || d > 31) return null;
    if (m[3]) {
      const y = m[3].length === 2 ? 2000 + Number(m[3]) : Number(m[3]);
      const out = `${y}-${String(mo).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
      return shiftDay(out, 0) === out ? out : null;
    }
    return upcoming(mo - 1, d);
  };
  /** A date phrase at `i`: its day and length, or null. */
  const dateAt = (i: number): { len: number; day: string } | null => {
    if (!free(i)) return null;
    let lead = 0;
    if (is(i, W.on)) lead = 1;
    const j = i + lead;
    if (!free(j)) return null;
    const rel = E.relative.get(t[j]!.f);
    if (rel !== undefined) return { len: lead + 1, day: shiftDay(today, rel) };
    // Two-word relative phrases ("day after tomorrow" in some languages).
    for (const [phrase, n] of E.relative) {
      const p = phrase.split(/\s+/);
      if (p.length > 1 && phraseAt(j, p)) return { len: lead + p.length, day: shiftDay(today, n) };
    }
    // "day after tomorrow": a catalog phrase, for a language whose engine writes "in 2 days".
    for (const phrase of W.dayAfter) {
      const hit = phraseAt(j, phrase.split(/\s+/));
      if (hit) return { len: lead + hit.len, day: shiftDay(today, 2) };
    }
    const nw = phraseAt(j, E.nextWeek);
    if (nw && E.nextWeek.length > 1) return { len: lead + nw.len, day: shiftDay(today, 7) };
    for (const [p, per] of [[E.inDays, 1], [E.inWeeks, 7]] as const) {
      const hit = phraseAt(j, p);
      if (hit?.n !== undefined) return { len: lead + hit.len, day: shiftDay(today, hit.n * per) };
    }
    // "next friday" is a week on; "this friday" is the coming one, as "friday" is.
    const nextWord = is(j, W.next);
    const thisWord = !nextWord && is(j, W.this) && weekdayAt(j + 1) !== null;
    const w = weekdayAt(j + (nextWord || thisWord ? 1 : 0));
    if (w !== null) {
      const ahead = (w - weekdayOf(today) + 7) % 7;
      return { len: lead + (nextWord || thisWord ? 2 : 1), day: shiftDay(today, ahead + (nextWord ? 7 : 0)) };
    }
    const num = numericDate(t[j]!.raw.replace(/,$/, ''));
    if (num) return { len: lead + 1, day: num };
    // "16 Oct", "Oct 16", "16th of October": a month name only with a day.
    const d1 = ordinalDay(j);
    if (d1 !== null) {
      const of = is(j + 1, W.on) ? 1 : 0;
      const m = monthAt(j + 1 + of);
      if (m !== null) {
        const day = upcoming(m, d1);
        if (day) return { len: lead + 2 + of, day };
      }
    }
    const m2 = monthAt(j);
    if (m2 !== null) {
      const d2 = ordinalDay(j + 1);
      if (d2 !== null) {
        const day = upcoming(m2, d2);
        if (day) return { len: lead + 2, day };
      }
    }
    return null;
  };

  // ── Times ──
  const timeToken = (raw: string, strict: boolean): string | null => {
    const f = foldForMatch(raw);
    // A bare number is a time only after "at" or before "o'clock"; a date in
    // digits with a closing dot ("16.10.") is a date.
    if (strict && /^\d{1,2}$/.test(f)) return null;
    if (/^\d{1,2}\.\d{1,2}\./.test(f)) return null;
    return parseTimeText(f.replace(/\.$/, ''));
  };
  const timeAt = (i: number, afterAt = false): { len: number; time: string } | null => {
    if (!free(i)) return null;
    // "at 3pm", and a run of "at" words ("a las 12"): skipped in a loop, so a
    // pasted run of thousands costs no stack.
    if (!afterAt && is(i, W.at)) {
      let k = i + 1;
      while (free(k) && is(k, W.at)) k++;
      // A number before a day or week word is a date ("o 5 dní", Slovak for
      // "in 5 days", where "o" is also "at"), never a clock time.
      if (free(k) && !(is(k + 1, W.day) || is(k + 1, W.week))) {
        const at = timeAt(k, true) ?? (parseTimeText(t[k]!.f) ? { len: 1, time: parseTimeText(t[k]!.f)! } : null);
        if (at) return { len: k - i + at.len, time: at.time };
      }
    }
    // "3 pm", "15 Uhr".
    if (/^\d{1,2}(:\d{2})?$/.test(t[i]!.f) && free(i + 1)) {
      const two = parseTimeText(`${t[i]!.f}${t[i + 1]!.f}`);
      if (two && /^(am|pm|a|p|a\.m\.|p\.m\.)$/.test(t[i + 1]!.f)) return { len: 2, time: two };
      if (W.oclock.includes(t[i + 1]!.f)) {
        const one = parseTimeText(t[i]!.f);
        if (one) return { len: 2, time: one };
      }
    }
    // "noon", "midnight", and a language's phrase for them ("منتصف الليل").
    for (const [list, time] of [[W.noon, '12:00'], [W.midnight, '00:00']] as const) {
      const hit = list.map((phrase) => phraseAt(i, phrase.split(/\s+/))).find(Boolean);
      if (hit) return { len: hit.len, time };
    }
    const single = timeToken(t[i]!.raw, true);
    return single ? { len: 1, time: single } : null;
  };
  const rangeAt = (i: number): { len: number; time: string; end: string } | null => {
    if (!free(i)) return null;
    // "3-4pm", "15:00-16:00", "9:30-10".
    const m = /^(\d{1,2}(?::\d{2})?)\s*(am|pm)?[-–](\d{1,2}(?::\d{2})?)\s*(am|pm)?$/i.exec(t[i]!.f);
    if (m) {
      const half = m[4] ?? m[2] ?? '';
      const a = parseTimeText(`${m[1]}${m[2] ?? (m[4] && !m[1]!.includes(':') ? m[4] : '')}`) ?? parseTimeText(m[1]!);
      const b = parseTimeText(`${m[3]}${half}`);
      if (a && b) {
        // "11-1pm": a start after its pm end reads as morning. "14-15 Uhr"
        // carries its clock word after the range.
        return { len: is(i + 1, W.oclock) ? 2 : 1, time: a, end: b };
      }
    }
    const fromWord = is(i, W.from) ? 1 : 0;
    const a = timeAt(i + fromWord);
    if (!a) return null;
    const k = i + fromWord + a.len;
    const sep = free(k) && (W.to.includes(t[k]!.f) || t[k]!.f === '-') ? 1 : 0;
    if (!sep) return null;
    // A day written with dots ("20.", "20.12.") after "to" is an end day, never a time.
    const endIsDay = free(k + 1) && /^\d{1,2}\.(\d{1,2}\.?)?$/.test(t[k + 1]!.raw.trim());
    const b = endIsDay ? null : timeAt(k + 1) ?? (free(k + 1) && parseTimeText(t[k + 1]!.f) ? { len: 1, time: parseTimeText(t[k + 1]!.f)! } : null);
    if (!b) return null;
    return { len: fromWord + a.len + sep + b.len, time: a.time, end: b.time };
  };

  // ── Reading, longest patterns first, left to right ──
  const out: { day?: string; end?: string; time?: string; timeEnd?: string; durationMin?: number; durationDays?: number; tonight?: boolean } = {};

  /** A monthly rule after "every month" or "monthly", at `j0`: "on the 1st",
   *  "on the 2nd tuesday", "on the last friday". Where it ends, and the repeat. */
  const monthRule = (j0: number): { end: number; monthly: 'day' | 'weekday'; nth?: 1 | 2 | 3 | 4 | -1; day: string } | null => {
    let j = j0;
    while (is(j, W.on)) j++;
    if (is(j, W.last)) {
      const wd = weekdayAt(j + 1);
      return wd === null ? null : { end: j + 2, monthly: 'weekday', nth: -1, day: nextNthWeekday(today, -1, wd) };
    }
    const d = monthDay(j);
    if (d === null) return null;
    const wd = d <= 4 ? weekdayAt(j + 1) : null;
    if (wd !== null) return { end: j + 2, monthly: 'weekday', nth: d as 1 | 2 | 3 | 4, day: nextNthWeekday(today, d, wd) };
    return { end: j + 1, monthly: 'day', day: nextMonthDay(today, d) };
  };

  // Type: the first or the last word.
  const typeOf = (f: string): QuickAddType | null =>
    W.event.includes(f) ? 'event' : W.task.includes(f) ? 'task' : W.journal.includes(f) ? 'journal' : W.note.includes(f) ? 'note' : null;
  for (const i of [0, t.length - 1]) {
    if (res.type || !free(i) || t.length < 2) continue;
    const ty = typeOf(t[i]!.f);
    if (ty) {
      res.type = ty;
      take(i, 1, 'type');
    }
  }

  for (let i = 0; i < t.length; i++) {
    if (!free(i)) continue;
    const raw = t[i]!.raw;
    // #tag, /Folder, @space
    if (/^#[^\s#]+$/.test(raw)) {
      res.tags.push(raw.slice(1));
      take(i, 1, 'tag');
      continue;
    }
    if (/^\/\S+$/.test(raw) && ctx.folders) {
      const want = foldForMatch(raw.slice(1));
      const f = ctx.folders.find((x) => foldForMatch(x.name) === want);
      if (f) {
        res.folderId = f.id;
        take(i, 1, 'folder');
        continue;
      }
    }
    if (/^@\S+$/.test(raw)) {
      const w = strip(raw.slice(1));
      const space = W.work.includes(w) ? 'work' : W.personal.includes(w) ? 'personal' : null;
      if (space) {
        res.space = space;
        take(i, 1, 'space');
        continue;
      }
    }
    // Alerts: "10m before", "1 hour before", "alert 10m", "remind 1 day",
    // and a list after the word: "alert 1d and 1h".
    if (is(i, W.alert)) {
      let k = i + 1;
      const found: number[] = [];
      for (;;) {
        const a = amountAt(k);
        if (!a || a.unit === 'month' || a.unit === 'year') break;
        found.push(a.n * UNIT_MINUTES[a.unit]);
        k += a.len;
        if (is(k, W.before)) k++;
        const sep = is(k, W.and) || (free(k) && t[k]!.f === ',') ? 1 : 0;
        // "1d, 1h": the comma came with the word before it.
        const glued = !sep && t[k - 1]!.raw.endsWith(',');
        const next = sep || glued ? amountAt(k + sep) : null;
        if (!next || next.unit === 'month' || next.unit === 'year') break;
        k += sep;
      }
      if (found.length) {
        for (const before of found) res.alerts.push({ before });
        take(i, k - i, 'alert');
        continue;
      }
    }
    {
      const a = amountAt(i);
      if (a && a.unit !== 'month' && a.unit !== 'year' && is(i + a.len, W.before)) {
        res.alerts.push({ before: a.n * UNIT_MINUTES[a.unit] });
        take(i, a.len + 1, 'alert');
        continue;
      }
    }
    // Durations: "for 30m", "for 2 hours", "for 3 days".
    if (is(i, W.for)) {
      const a = amountAt(i + 1);
      if (a && a.unit !== 'month' && a.unit !== 'year') {
        if (a.unit === 'day' || a.unit === 'week') out.durationDays = a.n * (a.unit === 'week' ? 7 : 1);
        else out.durationMin = a.n * UNIT_MINUTES[a.unit];
        take(i, 1 + a.len, 'duration');
        continue;
      }
    }
    // Repeats.
    // "Weekly review": a repeat word that opens the line is its title.
    if (i > 0 && (is(i, W.daily) || is(i, W.weekly) || is(i, W.monthly) || is(i, W.yearly))) {
      const every: Repeat['every'] = is(i, W.daily) ? 'day' : is(i, W.weekly) ? 'week' : is(i, W.monthly) ? 'month' : 'year';
      res.repeat = { every, interval: 1 };
      let len = 1;
      // "monthly on the 1st", as after "every month".
      const rule = every === 'month' ? monthRule(i + 1) : null;
      if (rule) {
        res.repeat.monthly = rule.monthly;
        if (rule.nth !== undefined) res.repeat.nth = rule.nth;
        out.day ??= rule.day;
        len = rule.end - i;
      }
      take(i, len, 'repeat');
      continue;
    }
    if (is(i, W.every)) {
      // "every other week", "every second friday": twice the step.
      const other = is(i + 1, W.other) ? 1 : 0;
      // "every last friday": the last one of each month.
      if (!other && is(i + 1, W.last)) {
        const wd = weekdayAt(i + 2);
        if (wd !== null) {
          res.repeat = { every: 'month', interval: 1, monthly: 'weekday', nth: -1 };
          out.day ??= nextNthWeekday(today, -1, wd);
          take(i, 3, 'repeat');
          continue;
        }
      }
      if (!other && is(i + 1, W.weekday)) {
        res.repeat = { every: 'week', interval: 1, weekdays: [1, 2, 3, 4, 5] };
        take(i, 2, 'repeat');
        continue;
      }
      // "every monday and wednesday", "every fri".
      const days: number[] = [];
      let k = i + 1 + other;
      while (free(k)) {
        const w = weekdayAt(k);
        if (w !== null) { days.push(w); k++; continue; }
        if (days.length && (is(k, W.and) || t[k]!.f === ',') && weekdayAt(k + 1) !== null) { k++; continue; }
        break;
      }
      if (days.length) {
        res.repeat = { every: 'week', interval: 1 + other, weekdays: [...new Set(days)].sort((a, b) => a - b) };
        take(i, k - i, 'repeat');
        continue;
      }
      // "every 2 weeks", "every day", "every month on the 1st".
      const a = other ? null : amountAt(i + 1);
      const unitWord = (j: number): Repeat['every'] | null =>
        is(j, W.day) ? 'day' : is(j, W.week) ? 'week' : is(j, W.month) ? 'month' : is(j, W.year) ? 'year' : null;
      const single = unitWord(i + 1 + other);
      const every = a ? (a.unit === 'minute' || a.unit === 'hour' ? null : a.unit) : single;
      if (every) {
        let len = 1 + other + (a ? a.len : 1);
        const repeat: Repeat = { every, interval: a ? Math.max(1, a.n) : 1 + other };
        // "every month on the 1st", "on the 2nd tuesday", "on the last friday".
        const rule = every === 'month' ? monthRule(i + len) : null;
        if (rule) {
          repeat.monthly = rule.monthly;
          if (rule.nth !== undefined) repeat.nth = rule.nth;
          out.day ??= rule.day;
          len = rule.end - i;
        }
        res.repeat = repeat;
        take(i, len, 'repeat');
        continue;
      }
    }
    if (res.repeat && is(i, W.until)) {
      const d = dateAt(i + 1);
      if (d) {
        res.repeat = { ...res.repeat, until: d.day };
        take(i, 1 + d.len, 'repeat');
        continue;
      }
    }
    if (res.repeat && is(i, W.for)) {
      const n = free(i + 1) && /^\d{1,3}$/.test(t[i + 1]!.f) && is(i + 2, W.times) ? Number(t[i + 1]!.f) : null;
      if (n) {
        res.repeat = { ...res.repeat, count: n };
        take(i, 3, 'repeat');
        continue;
      }
    }
    // "10 times" after a repeat, with or without "for".
    if (res.repeat && free(i) && /^\d{1,3}$/.test(t[i]!.f) && is(i + 1, W.times)) {
      res.repeat = { ...res.repeat, count: Number(t[i]!.f) };
      take(i, 2, 'repeat');
      continue;
    }
    // "last friday of every month", "2nd tuesday of the month, monthly".
    {
      const nth = is(i, W.last) ? -1 : ordinalDay(i);
      const wd = nth !== null && (nth === -1 || nth <= 4) ? weekdayAt(i + 1) : null;
      if (nth !== null && wd !== null) {
        let j = i + 2;
        while (is(j, W.on)) j++;
        const len = is(j, W.every) && is(j + 1, W.month) ? 2 : is(j, W.monthly) ? 1 : 0;
        if (len) {
          res.repeat = { every: 'month', interval: 1, monthly: 'weekday', nth: nth as 1 | 2 | 3 | 4 | -1 };
          out.day ??= nextNthWeekday(today, nth, wd);
          take(i, j - i + len, 'repeat');
          continue;
        }
      }
    }
    // "tonight", "ce soir", "esta noche": the evening of today, or of the
    // day typed with it ("viernes por la noche" is Friday evening).
    {
      const hit = W.tonight.map((phrase) => phraseAt(i, phrase.split(/\s+/))).find(Boolean);
      if (hit) {
        out.tonight = true;
        take(i, hit.len, 'date');
        continue;
      }
    }
    // "oct 20-25", "20-25 oct": a span inside one month, written as one word.
    {
      const span = /^(\d{1,2})[-–](\d{1,2})$/;
      const m1 = monthAt(i);
      const r1 = m1 !== null && free(i + 1) ? span.exec(t[i + 1]!.f) : null;
      const r2 = r1 || !free(i) ? null : span.exec(t[i]!.f);
      const m2 = r2 ? monthAt(i + 1) : null;
      const hit = r1 && m1 !== null ? { mo: m1, r: r1 } : r2 && m2 !== null ? { mo: m2, r: r2 } : null;
      if (hit && Number(hit.r[2]) > Number(hit.r[1])) {
        const start = upcoming(hit.mo, Number(hit.r[1]));
        const end = start ? `${start.slice(0, 8)}${hit.r[2]!.padStart(2, '0')}` : null;
        if (start && end && shiftDay(end, 0) === end) {
          out.day = start;
          out.end = end;
          take(i, 2, 'span');
          continue;
        }
      }
    }
    // Time ranges, then times.
    // The first time wins: a later one stays in the title, never replaces it.
    const r = out.time ? null : rangeAt(i);
    if (r) {
      out.time = r.time;
      out.timeEnd = r.end;
      take(i, r.len, 'time');
      continue;
    }
    const tm = out.time ? null : timeAt(i);
    if (tm) {
      out.time = tm.time;
      take(i, tm.len, 'time');
      continue;
    }
    // Dates, and a span "16.10. to 18.10.".
    // "from" before a span is part of it: "from oct 20 to oct 25".
    const lead = is(i, W.from) ? 1 : 0;
    const d = dateAt(i + lead);
    if (d) {
      const k = i + lead + d.len;
      if (free(k) && (W.to.includes(t[k]!.f) || t[k]!.f === '-')) {
        const e = dateAt(k + 1);
        if (e && e.day > d.day) {
          out.day = d.day;
          out.end = e.day;
          take(i, lead + d.len + 1 + e.len, 'span');
          continue;
        }
      }
      if (lead) continue;
      if (!out.day) {
        out.day = d.day;
        take(i, d.len, 'date');
        continue;
      }
    }
  }

  res.title = t.filter((x) => !x.used).map((x) => x.raw).join(' ').trim();
  // A dangling "at" or "on" read nothing; it stays text only inside the title.

  // "tonight": an evening time; "tonight at 8" is 8 in the evening.
  if (out.tonight) {
    if (!out.time) out.time = '19:00';
    else {
      const h = Number(out.time.slice(0, 2));
      const text = res.parts.find((p) => p.kind === 'time')?.text ?? '';
      if (h >= 1 && h < 12 && !/\d\s*a/i.test(text)) out.time = timeFromMinutes(minutesOf(out.time) + 720);
      // Midnight tonight is where today ends, not where it began.
      if (out.time === '00:00' && (out.day ?? today) === today && !res.repeat) out.day = shiftDay(today, 1);
    }
  }
  if (out.durationMin && out.time && !out.timeEnd) out.timeEnd = timeFromMinutes(minutesOf(out.time) + out.durationMin);
  if (res.repeat && !out.day) {
    // A series starts on its first occurrence from today.
    const start = res.repeat.weekdays?.length
      ? shiftDay(today, Math.min(...res.repeat.weekdays.map((w) => (w - weekdayOf(today) + 7) % 7)))
      : today;
    out.day = res.repeat.until ? start : (nextOccurrence(start, undefined, start) ?? start);
  }
  if (out.tonight && !out.day) out.day = today;
  if ((out.time || res.alerts.length || out.durationDays) && !out.day) out.day = ctx.defaultDay ?? today;
  if (out.durationDays && out.day && !out.end && out.durationDays > 1) out.end = shiftDay(out.day, out.durationDays - 1);
  if (out.day) res.day = out.day;
  if (out.end) res.end = out.end;
  if (out.time) res.time = out.time;
  if (out.timeEnd && out.time && out.timeEnd !== out.time) res.timeEnd = out.timeEnd;
  return res;
}

/** The next `nth` (1..4, or -1 for the last) weekday `wd` of a month, from today on. */
function nextNthWeekday(today: string, nth: number, wd: number): string {
  for (let k = 0; k < 70; k++) {
    const iso = shiftDay(today, k);
    if (weekdayOf(iso) !== wd) continue;
    if (nth === -1 ? shiftDay(iso, 7).slice(5, 7) !== iso.slice(5, 7) : Math.ceil(Number(iso.slice(8)) / 7) === nth) return iso;
  }
  return today;
}

/** The next day of the month `d` from today on, skipping months without it. */
function nextMonthDay(today: string, d: number): string {
  for (let m = 0; m < 14; m++) {
    const y = Number(today.slice(0, 4));
    const mo = Number(today.slice(5, 7)) - 1 + m;
    const iso = `${y + Math.floor(mo / 12)}-${String((mo % 12) + 1).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
    if (shiftDay(iso, 0) === iso && iso >= today) return iso;
  }
  return today;
}
