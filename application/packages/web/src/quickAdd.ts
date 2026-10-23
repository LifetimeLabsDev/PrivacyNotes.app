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
 * Spec: ops/docs/archive/calendar-pillar-spec.md (step 8)
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
  /** The day is a date typed with no year ("oct 1", "10/1"), read as the next
   *  time it comes; a jump to that day may want the nearer, past one. */
  guessedYear?: boolean;
};

/** The catalog words, each a list of folded alternatives. */
export type QuickAddWords = Record<
  'every' | 'weekday' | 'daily' | 'weekly' | 'monthly' | 'yearly' | 'until' | 'for' | 'at' | 'from' | 'to' | 'next'
  | 'this' | 'last' | 'other' | 'noon' | 'midnight' | 'tonight' | 'dayAfter'
  | 'before' | 'alert' | 'oclock' | 'on' | 'and' | 'task' | 'journal' | 'note' | 'event' | 'minute' | 'hour' | 'day'
  | 'week' | 'month' | 'year' | 'times' | 'ordinal' | 'work' | 'personal'
  /** Before an amount of days or weeks ("in 3 days"), or after it where the language puts it there. */
  | 'in'
  /** Typed first with a space, it opens the quick add in the switcher, as "+" does. */
  | 'add',
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
  /** "in N days" as patterns of folded words with `#` for the number, one
   *  per plural form the language writes ("za 2 dny", "za 5 dní"). */
  inDays: string[][];
  inWeeks: string[][];
  /** The long weekday names alone, folded: the ones a plural, a case ending
   *  or a stem may change ("fridays", "cuması", "пятницу"). */
  weekdaysLong: string[][];
  /** Endings a long weekday name takes in this language, folded. */
  weekdayEndings: string[];
  /** Stems with case endings, for a language that declines its weekday
   *  names: each weekday's stems and the endings they take. */
  weekdayStems: { stems: string[][]; endings: string[] };
  /** The language's words for morning and afternoon on a 12-hour clock ("午後", "오후"). */
  dayPeriods: { am: string[]; pm: string[] };
  /** The number comes before its word ("3 日後", "3 gün sonra"): the language
   *  puts "for", "in", "until" and "every" after what they govern. */
  postposed: boolean;
  /** Day first or month first, for a date in digits. */
  order: 'dmy' | 'mdy' | 'ymd';
};

/**
 * Endings a weekday name takes, per language, folded as the parser folds:
 * Swedish "fredagen", Turkish "cuması". A language that declines its names
 * by case swaps the ending for another, so it has a stem table instead.
 */
const WEEKDAY_ENDINGS: Record<string, string[]> = {
  sv: ['en', 'ar', 'arna'],
  tr: ['si', 'su', 'ya', 'ye', 'da', 'de', 'ta', 'te', 'dan', 'den', 'lari', 'leri'],
};
/** Case endings for the stem of a weekday name: Czech "sobotu", Polish
 *  "piątku", Russian "пятницу", Ukrainian "кожної п'ятниці". */
const WEEKDAY_CASES: Record<string, string[]> = {
  cs: ['u', 'y', 'i', 'e', 'ku', 'ka'],
  sk: ['u', 'y', 'i', 'e', 'ku', 'ka'],
  pl: ['e', 'y', 'i', 'ku', 'ki', 'ach', 'ami'],
  ru: ['у', 'ю', 'ы', 'е', 'а', 'я', 'ам', 'ям', 'ах', 'ях'],
  uk: ['у', 'ю', 'і', 'и', 'а', 'ка', 'га', 'ам', 'ям'],
};
/** A word a weekday name starts with that a speaker leaves out: Arabic
 *  "الجمعة" is also "جمعة", Thai "วันศุกร์" is also "ศุกร์". */
const WEEKDAY_PREFIXES = ['ال', 'วัน'];

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
  // A long name also without the word a speaker leaves out ("جمعة", "ศุกร์"),
  // and a Portuguese "sexta-feira" also as "sexta".
  const weekdaysLong = names({ weekday: 'long' }, weekdayDates).map((l) => [...new Set(l.flatMap((n) => [
    n,
    ...WEEKDAY_PREFIXES.filter((p) => n.startsWith(p) && n.length > p.length + 1).map((p) => n.slice(p.length)),
    ...(/^[^-]{3,}-/.test(n) ? [n.split('-')[0]!] : []),
  ]))]);
  const weekdays = weekdaysLong.map((l, w) => [...new Set([...l, ...shortWeekdays[w]!])]);
  const exact = (opts: Intl.DateTimeFormatOptions, d: Date) => lower(new Intl.DateTimeFormat(locale, { ...opts, timeZone: 'UTC' }).format(d)); // date-ok: names to read, never shown
  const weekdaysExact = weekdayDates.map((d) => [...new Set([exact({ weekday: 'long' }, d), exact({ weekday: 'short' }, d)])]);
  // The month as it is written after a day number: the genitive "31 října",
  // "31 октября", and the Catalan "31 d'octubre".
  const withDay = monthDates.map((d) => strip(new Intl.DateTimeFormat(locale, { day: 'numeric', month: 'long', timeZone: 'UTC' }).formatToParts(d).find((p) => p.type === 'month')?.value ?? '')); // date-ok: names to read, never shown
  const months = names({ month: 'long' }, monthDates).map((l, m) => [...new Set([...l, ...shortMonths[m]!, ...(withDay[m] && !/\d/.test(withDay[m]!) ? [withDay[m]!] : [])])]);
  const lang = locale.split('-')[0]!.toLowerCase();
  const fold = (list: string[]) => list.map((e) => strip(e));
  const cases = fold(WEEKDAY_CASES[lang] ?? []);
  // A stem drops a final vowel ("sobot-a") or a vowel that falls out ("pát-ek", "понедел-ок").
  const stems = weekdaysLong.map((l) => [...new Set(l.flatMap((n) => [n, n.replace(/[aeiouyаеиоуыэюяіїєё]$/, ''), n.replace(/(ek|ok|ек|ок)$/, '')]).filter((s) => s.length >= 3))]);
  const dayPeriod = (h: number) => strip(new Intl.DateTimeFormat(locale, { hour: 'numeric', hour12: true, timeZone: 'UTC' }).formatToParts(new Date(Date.UTC(2026, 0, 1, h))).find((p) => p.type === 'dayPeriod')?.value ?? ''); // date-ok: words to read, never shown
  const relative = new Map<string, number>();
  const rtf = (loc: string) => new Intl.RelativeTimeFormat(loc, { numeric: 'auto' });
  for (const loc of [locale, 'en']) {
    for (const n of [-1, 0, 1, 2]) {
      const phrase = strip(rtf(loc).format(n, 'day'));
      if (!/\d/.test(phrase) && !relative.has(phrase)) relative.set(phrase, n);
    }
  }
  // One pattern per plural form: Czech writes "za 2 dny" and "za 5 dní".
  const always = new Intl.RelativeTimeFormat(locale, { numeric: 'always' });
  const patterns = (unit: Intl.RelativeTimeFormatUnit) => {
    const out = new Map<string, string[]>();
    for (const n of [5, 1, 2, 3, 21]) {
      const p = strip(always.format(n, unit)).replace(String(n), '#').split(/\s+/);
      if (p.some((w) => w.includes('#'))) out.set(p.join(' '), p);
    }
    return [...out.values()];
  };
  const inDays = patterns('day');
  return {
    weekdays,
    weekdaysExact,
    months,
    relative,
    nextWeek: strip(rtf(locale).format(1, 'week')).split(/\s+/),
    inDays,
    inWeeks: patterns('week'),
    weekdaysLong,
    weekdayEndings: fold(WEEKDAY_ENDINGS[lang] ?? []),
    weekdayStems: { stems: cases.length ? stems : [], endings: cases },
    dayPeriods: { am: [dayPeriod(3)].filter(Boolean), pm: [dayPeriod(15)].filter(Boolean) },
    postposed: !!inDays[0]?.[0]?.startsWith('#'),
    order,
  };
}

// ── Tokens ────────────────────────────────────────────────────────

/** `group`: the pieces of one typed word that a script without spaces split. */
type Token = { raw: string; f: string; used: boolean; quoted: boolean; group?: number };

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

/** Scripts written without a space between words, and Korean, which glues
 *  a particle to its word ("20일까지"). */
const NO_SPACE = /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Thai}\p{Script=Hangul}]/u;

const HANGUL_SYLLABLE = /^\p{Script=Hangul}$/u;

type Vocab = { words: Set<string>; maxLen: number; glue: string[]; phrases: string[][] };
const vocabCache = new WeakMap<QuickAddWords, WeakMap<EngineWords, Vocab>>();

/** Every word the parser knows in a language: what a word with no spaces is
 *  split into, and the catalog phrases of several words. */
function vocabOf(W: QuickAddWords, E: EngineWords): Vocab {
  let byEngine = vocabCache.get(W);
  if (!byEngine) vocabCache.set(W, (byEngine = new WeakMap()));
  let v = byEngine.get(E);
  if (v) return v;
  const catalog = Object.values(W).flat();
  const patterns = [...E.inDays, ...E.inWeeks, E.nextWeek].flat();
  const words = new Set([
    ...catalog.filter((w) => !w.includes(' ')),
    ...E.weekdays.flat(), ...E.months.flat(), ...E.relative.keys(),
    ...patterns.map((w) => w.replace('#', '')),
    ...E.dayPeriods.am, ...E.dayPeriods.pm,
  ].filter(Boolean));
  // A word glued to a number: "31日", "30分", "3시", "10회".
  const glue = [...new Set([W.ordinal, W.minute, W.hour, W.day, W.week, W.month, W.year, W.times, W.oclock, E.dayPeriods.pm, E.dayPeriods.am].flat())].filter(Boolean);
  // The engine's own phrases too ("la setmana que ve"), so a catalog phrase
  // inside one ("que ve") does not break it.
  const engine = [...E.relative.keys(), E.nextWeek.join(' ')];
  const phrases = [...new Set([...engine, ...catalog].filter((w) => w.includes(' ')))].map((w) => w.split(' ')).sort((a, b) => b.length - a.length);
  v = { words, maxLen: Math.max(1, ...[...words].map((w) => w.length)), glue, phrases };
  byEngine.set(E, v);
  return v;
}

/**
 * A word with no spaces in known pieces: the fewest pieces, and on a tie the
 * longer last piece ("ทุก|วันศุกร์", every Friday, over "ทุกวัน|ศุกร์").
 * Null when a piece is unknown: a title word stays whole.
 */
function segment(s: string, v: Vocab): [number, number][] | null {
  const n = s.length;
  const best: ({ cost: number; from: number } | undefined)[] = [{ cost: 0, from: -1 }];
  for (let k = 0; k < n; k++) {
    const here = best[k];
    if (!here) continue;
    const ends: number[] = [];
    const digits = /^\d+/.exec(s.slice(k))?.[0].length ?? 0;
    if (digits) {
      ends.push(k + digits);
      for (const g of v.glue) if (s.startsWith(g, k + digits)) ends.push(k + digits + g.length);
    }
    // Korean writes words apart and glues only a particle: a lone syllable is
    // no piece, so "전화" stays a word and is not "before" and "Tuesday".
    for (let len = 1; len <= v.maxLen && k + len <= n; len++) {
      const w = s.slice(k, k + len);
      if (v.words.has(w) && !HANGUL_SYLLABLE.test(w)) ends.push(k + len);
    }
    for (const e of ends) {
      const cur = best[e];
      if (!cur || here.cost + 1 < cur.cost || (here.cost + 1 === cur.cost && k < cur.from)) best[e] = { cost: here.cost + 1, from: k };
    }
  }
  if (!best[n] || best[n]!.cost < 2) return null;
  const out: [number, number][] = [];
  for (let e = n; e > 0; e = best[e]!.from) out.unshift([best[e]!.from, e]);
  return out;
}

/**
 * Tokens as the parser reads them: a number and a Chinese or Japanese word
 * typed apart ("10 月") joined, a word of a script with no spaces split into
 * known pieces, and a catalog phrase of several words ("dia útil") made one.
 */
function prepare(tokens: Token[], W: QuickAddWords, E: EngineWords): Token[] {
  const v = vocabOf(W, E);
  const joined: Token[] = [];
  for (const tk of tokens) {
    const prev = joined[joined.length - 1];
    if (prev && !prev.quoted && !tk.quoted && /^\d{1,4}$/.test(prev.f) && NO_SPACE.test(tk.f)
      && (E.months.some((l) => l.includes(prev.f + tk.f)) || W.ordinal.includes(tk.f) || W.month.includes(tk.f))) {
      joined[joined.length - 1] = { ...prev, raw: `${prev.raw} ${tk.raw}`, f: prev.f + tk.f };
    } else joined.push(tk);
  }
  const split: Token[] = [];
  let group = 0;
  for (const tk of joined) {
    if (tk.quoted || !NO_SPACE.test(tk.f)) { split.push(tk); continue; }
    // Fold letter by letter, so each piece maps back to the letters typed.
    const chars = Array.from(tk.raw);
    let folded = '';
    const at: number[] = [];
    let pos = 0;
    for (const c of chars) {
      const fc = foldForMatch(apos(c));
      for (let u = 0; u < fc.length; u++) at.push(pos);
      folded += fc;
      pos += c.length;
    }
    const body = folded.replace(/[.,]+$/, '');
    const pieces = segment(body, v);
    if (!pieces) { split.push(tk); continue; }
    group++;
    pieces.forEach(([a, b], k) => {
      const raw = tk.raw.slice(at[a]!, k === pieces.length - 1 ? tk.raw.length : at[b]!);
      split.push({ raw, f: strip(raw), used: false, quoted: false, group });
    });
  }
  const out: Token[] = [];
  for (let i = 0; i < split.length; i++) {
    const hit = split[i]!.quoted ? undefined : v.phrases.find((p) => p.every((w, k) => split[i + k] && !split[i + k]!.quoted && split[i + k]!.f === w));
    if (!hit) { out.push(split[i]!); continue; }
    const parts = split.slice(i, i + hit.length);
    out.push({ raw: parts.map((p) => p.raw).join(' '), f: hit.join(' '), used: false, quoted: false });
    i += hit.length - 1;
  }
  return out;
}

/** How many years from now a year typed after a date may be. */
const YEAR_REACH = 30;

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
  const t = prepare(tokenize(input), W, E);
  const res: QuickAdd = { title: '', type: null, alerts: [], tags: [], folderId: null, space: null, parts: [] };
  const free = (i: number) => i >= 0 && i < t.length && !t[i]!.used && !t[i]!.quoted;
  const is = (i: number, list: string[]) => free(i) && list.includes(t[i]!.f);
  /** The words typed from `from`, the pieces of one word with no space between them. */
  const textOf = (from: number, len: number): string => {
    let text = '';
    for (let k = from; k < from + len; k++) text += (k > from && !(t[k]!.group !== undefined && t[k]!.group === t[k - 1]!.group) ? ' ' : '') + t[k]!.raw;
    return text;
  };
  const take = (from: number, len: number, kind: QuickAddPartKind) => {
    for (let k = from; k < from + len; k++) t[k]!.used = true;
    res.parts.push({ kind, text: textOf(from, len) });
  };
  /** How many a unit word alone means: one, or two for an Arabic dual
   *  ("ساعتين", two hours), which is the singular with "ين" after it. */
  const unitCount = (f: string, list: string[]): number => {
    const base = f.endsWith('ين') ? f.slice(0, -2) : '';
    return base && (list.includes(base) || list.includes(`${base.slice(0, -1)}${strip('ة')}`)) ? 2 : 1;
  };
  /** A phrase of folded words at `i`, `#` matching a number; the number when it has one. */
  const phraseAt = (i: number, phrase: string[]): { len: number; n?: number } | null => {
    let n: number | undefined;
    for (let k = 0; k < phrase.length; k++) {
      if (!free(i + k)) return null;
      const want = phrase[k]!;
      const got = t[i + k]!.f;
      if (want.includes('#')) {
        // "#" alone, or glued to a word: Korean "3일" in "3일 후".
        const [head, tail] = want.split('#') as [string, string];
        if (!got.startsWith(head) || !got.endsWith(tail)) return null;
        const num = got.slice(head.length, got.length - tail.length);
        if (!/^\d{1,3}$/.test(num)) return null;
        n = Number(num);
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
    const f = t[i]!.f;
    const w = E.weekdays.findIndex((l) => l.includes(f));
    if (w !== -1) return w;
    // A long name in the plural ("fridays", "sextas-feiras"), with an ending
    // ("fredagen", "cuması"), or in another case ("sobotu", "пятницу").
    if (f.length < 4) return null;
    const long = (name: string) => E.weekdaysLong.findIndex((l) => l.includes(name));
    const plural = f.replace(/s(?=-|$)/g, '');
    if (plural !== f && long(plural) !== -1) return long(plural);
    for (const end of E.weekdayEndings) if (f.endsWith(end) && long(f.slice(0, -end.length)) !== -1) return long(f.slice(0, -end.length));
    const { stems, endings } = E.weekdayStems;
    const s = stems.findIndex((l) => l.some((st) => f.startsWith(st) && endings.includes(f.slice(st.length))));
    return s === -1 ? null : s;
  };
  const monthAt = (i: number): number | null => {
    if (!free(i)) return null;
    const f = t[i]!.f;
    let m = E.months.findIndex((l) => l.includes(f));
    // A case suffix after an apostrophe: Turkish "Aralık'a".
    if (m === -1 && /^[^']{3,}'[^']{1,4}$/.test(f)) m = E.months.findIndex((l) => l.includes(f.split("'")[0]!));
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
    // Four years ahead at most: the next 29 February can be that far.
    for (let y = year; y <= year + 4; y++) {
      const iso = `${y}-${String(month + 1).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
      if (dayNumber(iso) !== dayNumber(iso) || shiftDay(iso, 0) !== iso) continue;
      if (iso >= today) return iso;
    }
    return null;
  };
  /** The days a month and day with no year gave, read as the next time they come. */
  const guessed = new Set<string>();
  /** A month and day, in the year typed at `k` ("2027") or else the next time it comes.
   *  Only a near year counts, so "oct 20 1500" keeps its time. */
  const inYear = (month: number, d: number, k: number): { day: string; len: number } | null => {
    const near = free(k) && /^\d{4}$/.test(t[k]!.f) && Math.abs(Number(t[k]!.f) - Number(today.slice(0, 4))) <= YEAR_REACH;
    const y = near ? t[k]!.f : null;
    if (!y) {
      const day = upcoming(month, d);
      if (day) guessed.add(day);
      return day ? { day, len: 0 } : null;
    }
    const iso = `${y}-${String(month + 1).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
    return shiftDay(iso, 0) === iso ? { day: iso, len: 1 } : null;
  };
  /** This year's start of a span inside one month that began before today
   *  and ends today or later: "oct 20-25" on the 23rd is the trip under way. */
  const runningSpan = (month: number, from: number, to: number): string | null => {
    const at = (d: number) => `${today.slice(0, 4)}-${String(month + 1).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
    const start = at(from);
    const end = at(to);
    return shiftDay(start, 0) === start && shiftDay(end, 0) === end && start < today && end >= today ? start : null;
  };
  const numericDate = (raw: string): string | null => {
    const iso = /^(\d{4})[-/](\d{1,2})[-/](\d{1,2})$/.exec(raw);
    if (iso) {
      const out = `${iso[1]}-${iso[2]!.padStart(2, '0')}-${iso[3]!.padStart(2, '0')}`;
      return shiftDay(out, 0) === out ? out : null;
    }
    // "24.12" with no closing dot: the clock read "10.30" before a date can.
    const dots = /^(\d{1,2})\.(\d{1,2})(?:\.(\d{2,4})?)?$/.exec(raw);
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
    const day = upcoming(mo - 1, d);
    if (day) guessed.add(day);
    return day;
  };
  /** A date phrase at `i`: its day and length, or null. */
  const dateAt = (i: number): { len: number; day: string; kind?: 'weekday' | 'month' } | null => {
    if (!free(i)) return null;
    let lead = 0;
    if (is(i, W.on)) lead = 1;
    const j = i + lead;
    if (!free(j)) return null;
    // A relative day of several words ("pasado mañana") is one token by now.
    const rel = E.relative.get(t[j]!.f);
    if (rel !== undefined) return { len: lead + 1, day: shiftDay(today, rel) };
    // "day after tomorrow": a catalog phrase, for a language whose engine writes "in 2 days".
    if (is(j, W.dayAfter)) return { len: lead + 1, day: shiftDay(today, 2) };
    if (E.nextWeek.length > 1 && is(j, [E.nextWeek.join(' ')])) return { len: lead + 1, day: shiftDay(today, 7) };
    for (const [list, per] of [[E.inDays, 1], [E.inWeeks, 7]] as const) {
      for (const p of list) {
        const hit = phraseAt(j, p);
        if (hit?.n !== undefined) return { len: lead + hit.len, day: shiftDay(today, hit.n * per) };
      }
    }
    // "in 3 days", and "3 gün içinde" where the language puts the word after.
    {
      const days = (a: ReturnType<typeof amountAt>) => (a && (a.unit === 'day' || a.unit === 'week') ? a.n * (a.unit === 'week' ? 7 : 1) : null);
      const before = is(j, W.in) ? days(amountAt(j + 1)) : null;
      if (before !== null) return { len: lead + 1 + amountAt(j + 1)!.len, day: shiftDay(today, before) };
      // The "in" word was read as "on" (Arabic "في").
      const asLead = lead && W.in.includes(t[i]!.f) ? days(amountAt(j)) : null;
      if (asLead !== null) return { len: lead + amountAt(j)!.len, day: shiftDay(today, asLead) };
      const a = E.postposed ? amountAt(j) : null;
      if (a && days(a) !== null && is(j + a.len, W.in)) return { len: lead + a.len + 1, day: shiftDay(today, days(a)!) };
    }
    // "next friday" is a week on; "this friday" is the coming one, as "friday" is.
    // Either word may come after the name: "dilluns vinent", "ศุกร์นี้".
    const nextWord = is(j, W.next);
    const thisWord = !nextWord && is(j, W.this) && weekdayAt(j + 1) !== null;
    const w = weekdayAt(j + (nextWord || thisWord ? 1 : 0));
    if (w !== null) {
      let len = lead + (nextWord || thisWord ? 2 : 1);
      const after = i + len;
      const unitAfter = (k: number) => is(k, W.day) || is(k, W.week) || is(k, W.month) || is(k, W.year);
      const postNext = !nextWord && !thisWord && is(after, W.next) && !unitAfter(after + 1);
      if (postNext || (!nextWord && !thisWord && is(after, W.this) && !unitAfter(after + 1))) len++;
      const ahead = (w - weekdayOf(today) + 7) % 7;
      return { len, day: shiftDay(today, ahead + (nextWord || postNext ? 7 : 0)), kind: 'weekday' };
    }
    const num = numericDate(t[j]!.raw.replace(/,$/, ''));
    if (num) return { len: lead + 1, day: num };
    // "31. 10.": a Czech or Slovak date in digits with a space after the day.
    if (E.order === 'dmy' && /^\d{1,2}\.$/.test(t[j]!.raw) && free(j + 1) && /^\d{1,2}\.(\d{2,4})?$/.test(t[j + 1]!.raw)) {
      const two = numericDate(`${t[j]!.raw}${t[j + 1]!.raw}`);
      if (two) return { len: lead + 2, day: two };
    }
    // "16 Oct", "Oct 16", "16th of October": a month name only with a day.
    // A year after it is that year ("Oct 31 2027"), never a time.
    const d1 = ordinalDay(j);
    if (d1 !== null) {
      const of = is(j + 1, W.on) ? 1 : 0;
      const m = monthAt(j + 1 + of);
      if (m !== null) {
        const day = inYear(m, d1, j + 2 + of);
        if (day) return { len: lead + 2 + of + day.len, day: day.day, kind: 'month' };
      }
    }
    const m2 = monthAt(j);
    if (m2 !== null) {
      const d2 = ordinalDay(j + 1);
      if (d2 !== null) {
        const day = inYear(m2, d2, j + 2);
        if (day) return { len: lead + 2 + day.len, day: day.day, kind: 'month' };
      }
    }
    return null;
  };

  // ── Times ──
  const timeToken = (raw: string, strict: boolean): string | null => {
    const f = foldForMatch(raw);
    // A bare number is a time only after "at" or before "o'clock"; a date in
    // digits with a closing dot ("16.10.") is a date.
    if (strict && /^\d{1,2}\.?$/.test(f)) return null;
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
    // "3 pm", "15 Uhr", "15.00 น.". A lone "a" that is also "to" ("de 9 a 17") is no "am".
    if (/^\d{1,2}([:.]\d{2})?$/.test(t[i]!.f) && free(i + 1)) {
      const two = parseTimeText(`${t[i]!.f}${t[i + 1]!.f}`);
      const half = t[i + 1]!.f;
      if (two && /^(am|pm|a|p|a\.m\.|p\.m\.)$/.test(half) && !(half.length === 1 && (W.to.includes(half) || W.at.includes(half)))) return { len: 2, time: two };
      if (W.oclock.includes(half)) {
        const one = parseTimeText(t[i]!.f);
        if (one) return { len: 2, time: one };
      }
    }
    // The language's afternoon word before or after the hour ("午後3時",
    // "오후 3시", "3 م"), and an hour with its clock word glued ("3時").
    {
      const period = (k: number) => (!free(k) ? null : E.dayPeriods.pm.includes(t[k]!.f) ? 'pm' : E.dayPeriods.am.includes(t[k]!.f) ? 'am' : null);
      const hourAt = (k: number, bare: boolean): { len: number; h: number; time: string } | null => {
        if (!free(k)) return null;
        const f = t[k]!.f;
        const glued = /^(\d{1,2})(\D+)$/.exec(f);
        const word = glued && (W.oclock.includes(glued[2]!) || E.dayPeriods.pm.includes(glued[2]!) || E.dayPeriods.am.includes(glued[2]!)) ? glued : null;
        if (word) {
          const time = parseTimeText(word[1]!);
          return time ? { len: 1, h: Number(word[1]), time } : null;
        }
        if (/^\d{1,2}([:.]\d{2})?$/.test(f)) {
          const time = parseTimeText(f);
          const len = W.oclock.includes(t[k + 1]?.f ?? '') && free(k + 1) ? 2 : 1;
          return time && (bare || len === 2) ? { len, h: Number(time.slice(0, 2)), time } : null;
        }
        return null;
      };
      const shift = (time: string, p: 'am' | 'pm' | null) => {
        const h = Number(time.slice(0, 2));
        return p === 'pm' && h < 12 ? timeFromMinutes(minutesOf(time) + 720) : p === 'am' && h === 12 ? timeFromMinutes(minutesOf(time) - 720) : time;
      };
      const before = period(i);
      const h1 = before ? hourAt(i + 1, true) : null;
      if (before && h1) return { len: 1 + h1.len, time: shift(h1.time, before) };
      const h2 = hourAt(i, true);
      const glued = h2 && /\D/.test(t[i]!.f) ? /^\d{1,2}(\D+)$/.exec(t[i]!.f)?.[1] : null;
      const after = h2 ? period(i + h2.len) : null;
      if (h2 && after) return { len: h2.len + 1, time: shift(h2.time, after) };
      if (h2 && glued) return { len: h2.len, time: shift(h2.time, E.dayPeriods.pm.includes(glued) ? 'pm' : E.dayPeriods.am.includes(glued) ? 'am' : null) };
    }
    // "noon", "midnight", a language's phrase for them ("منتصف الليل"), and
    // an "on" word before them ("w południe").
    for (const [list, time] of [[W.noon, '12:00'], [W.midnight, '00:00']] as const) {
      if (is(i, list)) return { len: 1, time };
      if (is(i, W.on) && is(i + 1, list)) return { len: 2, time };
    }
    const single = timeToken(t[i]!.raw, true);
    return single ? { len: 1, time: single } : null;
  };
  const rangeAt = (i: number): { len: number; time: string; end: string } | null => {
    if (!free(i)) return null;
    // "3-4pm", "15:00-16:00", "9:30-10".
    // "9h-17h": an "h" after each hour, as French and Portuguese write it.
    const m = /^(\d{1,2}(?::\d{2})?)h?\s*(am|pm)?[-–](\d{1,2}(?::\d{2})?)h?\s*(am|pm)?$/i.exec(t[i]!.f);
    if (m) {
      const half = m[4] ?? m[2] ?? '';
      const a = parseTimeText(`${m[1]}${m[2] ?? (m[4] && !m[1]!.includes(':') ? m[4] : '')}`) ?? parseTimeText(m[1]!);
      let b = parseTimeText(`${m[3]}${half}`);
      // "9-5" with no am or pm is a working day: an end before the start
      // that the afternoon puts after it ends then ("22-6" stays a night).
      if (a && b && !m[2] && !m[4] && minutesOf(b) < minutesOf(a) && minutesOf(b) + 720 > minutesOf(a)) {
        b = timeFromMinutes(minutesOf(b) + 720);
      }
      if (a && b) {
        // "11-1pm": a start after its pm end reads as morning. "14-15 Uhr"
        // carries its clock word after the range.
        return { len: is(i + 1, W.oclock) ? 2 : 1, time: a, end: b };
      }
    }
    // "в 9-17": the same after an "at" word.
    if (is(i, W.at) && free(i + 1) && /^\d{1,2}(?:[:h]\d{2})?h?[-–]\d/.test(t[i + 1]!.f)) {
      const r = rangeAt(i + 1);
      if (r) return { ...r, len: r.len + 1 };
    }
    const fromWord = is(i, W.from) ? 1 : 0;
    // After "from", a bare hour is a time: "de 9 a 17", "с 9 до 17".
    const bare = (k: number) => (fromWord && free(k) && /^\d{1,2}$/.test(t[k]!.f) && parseTimeText(t[k]!.f) ? { len: 1, time: parseTimeText(t[k]!.f)! } : null);
    const a = timeAt(i + fromWord) ?? bare(i + fromWord);
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

  /** "of the month" after a monthly rule, at `j`: "v měsíci", "im monat",
   *  "do mês". How many words it takes. */
  const ofMonth = (j: number): number => (is(j, W.on) || is(j, W.from) || is(j, W.for)) && is(j + 1, W.month) ? 2 : 0;
  /** A unit word with no number, as one of it: "час", "يوم". A letter alone ("h") is no unit. */
  const unitOnly = (k: number): ReturnType<typeof amountAt> => {
    if (!free(k) || t[k]!.f.length < 2 || /\d/.test(t[k]!.f)) return null;
    const hit = (['minute', 'hour', 'day', 'week'] as const).find((u) => W[u].includes(t[k]!.f));
    return hit ? { len: 1, n: unitCount(t[k]!.f, W[hit]), unit: hit } : null;
  };

  /** A monthly rule after "every month" or "monthly", at `j0`: "on the 1st",
   *  "on the 2nd tuesday", "on the last friday". Where it ends, and the repeat. */
  const monthRule = (j0: number): { end: number; monthly: 'day' | 'weekday'; nth?: 1 | 2 | 3 | 4 | -1; day: string } | null => {
    let j = j0;
    while (is(j, W.on)) j++;
    if (is(j, W.last)) {
      const wd = weekdayAt(j + 1);
      return wd === null ? null : { end: j + 2 + ofMonth(j + 2), monthly: 'weekday', nth: -1, day: nextNthWeekday(today, -1, wd) };
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

  let untilAfter: { day: string; from: number; len: number; part: number } | null = null;
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
      // "เตือนล่วงหน้า 1 ชั่วโมง": a "before" word right after the alert word.
      let k = is(i + 1, W.before) ? i + 2 : i + 1;
      const found: number[] = [];
      for (;;) {
        // A unit word with no number is one of it: "за час", "قبل يوم".
        const a = amountAt(k) ?? (found.length === 0 ? unitOnly(k) : null);
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
    // "1h before", and a list before the word: "1 tag und 1 stunde vorher".
    {
      const found: number[] = [];
      let k = i;
      for (;;) {
        const a = amountAt(k);
        if (!a || a.unit === 'month' || a.unit === 'year') break;
        found.push(a.n * UNIT_MINUTES[a.unit]);
        k += a.len;
        if (!(is(k, W.and) || (free(k) && t[k]!.f === ',')) || !amountAt(k + 1)) break;
        k++;
      }
      if (found.length && is(k, W.before)) {
        for (const before of found) res.alerts.push({ before });
        take(i, k - i + 1, 'alert');
        continue;
      }
    }
    // Durations: "for 30m", "for 2 hours", "for 3 days", and "30분 동안"
    // where the language puts the word after.
    {
      const pre = is(i, W.for) ? amountAt(i + 1) : null;
      const post = !pre && E.postposed ? amountAt(i) : null;
      const a = pre ?? (post && is(i + post.len, W.for) ? post : null);
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
    // "금요일마다", "평일마다": the "every" word after the day, where the language puts it there.
    if (E.postposed && is(i + 1, W.every) && !W.other.includes(t[i + 1]!.f)) {
      const wd = weekdayAt(i);
      if (wd !== null || is(i, W.weekday)) {
        res.repeat = { every: 'week', interval: 1, weekdays: wd === null ? [1, 2, 3, 4, 5] : [wd] };
        take(i, 2, 'repeat');
        continue;
      }
    }
    if (is(i, W.every)) {
      // "every other week", "every second friday": twice the step. A word in
      // both lists says it alone: "varannan", "cada dos", "隔週".
      const self = W.other.includes(t[i]!.f);
      const other = self || is(i + 1, W.other) ? 1 : 0;
      const step = self ? 0 : other;
      // "every last friday": the last one of each month, and "of the month"
      // after it ("každý poslední pátek v měsíci").
      if (!other && is(i + 1, W.last)) {
        const wd = weekdayAt(i + 2);
        if (wd !== null) {
          res.repeat = { every: 'month', interval: 1, monthly: 'weekday', nth: -1 };
          out.day ??= nextNthWeekday(today, -1, wd);
          take(i, 3 + ofMonth(i + 3), 'repeat');
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
      let k = i + 1 + step;
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
      const single = unitWord(i + 1 + step);
      const every = a ? (a.unit === 'minute' || a.unit === 'hour' ? null : a.unit) : single;
      if (every) {
        let len = 1 + step + (a ? a.len : 1);
        const word = a ? null : t[i + 1 + step]!.f;
        const repeat: Repeat = { every, interval: a ? Math.max(1, a.n) : word && unitCount(word, W[every]) === 2 && !other ? 2 : 1 + other };
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
    // "10 times" after a repeat, with or without "for", and glued: "10krát", "10-krát", "10회".
    if (res.repeat && free(i) && /^\d{1,3}$/.test(t[i]!.f) && is(i + 1, W.times)) {
      res.repeat = { ...res.repeat, count: Number(t[i]!.f) };
      take(i, 2, 'repeat');
      continue;
    }
    {
      const glued = res.repeat && free(i) ? /^(\d{1,3})-?(\D+)$/.exec(t[i]!.f) : null;
      if (glued && W.times.includes(glued[2]!) && Number(glued[1]) > 0) {
        res.repeat = { ...res.repeat!, count: Number(glued[1]) };
        take(i, 1, 'repeat');
        continue;
      }
    }
    // "last friday of every month", "2nd tuesday of the month, monthly".
    {
      const nth = is(i, W.last) ? -1 : ordinalDay(i);
      const wd = nth !== null && (nth === -1 || nth <= 4) ? weekdayAt(i + 1) : null;
      if (nth !== null && wd !== null) {
        let j = i + 2;
        // "of": an "on" word, or a "from" or "for" word some languages use ("de", "van", "i").
        while (is(j, W.on) || is(j, W.from) || is(j, W.for)) j++;
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
      if (is(i, W.tonight)) {
        out.tonight = true;
        take(i, 1, 'date');
        continue;
      }
    }
    // "oct 20-25", "20-25 oct": a span inside one month, written as one word,
    // with a dot or an ordinal after each day ("20.-25. října", "20일~25일"),
    // or with the month in digits ("24.-26.10.").
    {
      const ord = W.ordinal.filter((o) => o !== '.').map((o) => o.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
      const span = new RegExp(`^(\\d{1,2})(?:${ord || '(?!)'})?\\.?[-–~〜](\\d{1,2})(?:${ord || '(?!)'})?$`);
      const inDigits = free(i) ? /^(\d{1,2})\.?[-–](\d{1,2})\.(\d{1,2})\.?$/.exec(t[i]!.f) : null;
      const m1 = monthAt(i);
      const r1 = m1 !== null && free(i + 1) ? span.exec(t[i + 1]!.f) : null;
      const r2 = r1 || !free(i) ? null : span.exec(t[i]!.f);
      const m2 = r2 ? monthAt(i + 1) : null;
      const hit = inDigits && Number(inDigits[3]) >= 1 && Number(inDigits[3]) <= 12 ? { mo: Number(inDigits[3]) - 1, r: inDigits, one: true }
        : r1 && m1 !== null ? { mo: m1, r: r1, one: false } : r2 && m2 !== null ? { mo: m2, r: r2, one: false } : null;
      if (hit && Number(hit.r[2]) > Number(hit.r[1])) {
        const start = runningSpan(hit.mo, Number(hit.r[1]), Number(hit.r[2])) ?? upcoming(hit.mo, Number(hit.r[1]));
        const end = start ? `${start.slice(0, 8)}${hit.r[2]!.padStart(2, '0')}` : null;
        if (start && end && shiftDay(end, 0) === end) {
          out.day = start;
          out.end = end;
          take(i, hit.one ? 1 : 2, 'span');
          continue;
        }
      }
    }
    // "20. bis 25. okt", "del 20 al 25 d'octubre": a day, "to", then a date
    // that names the month for both.
    {
      const lead = is(i, W.from) || is(i, W.on) ? 1 : 0;
      const d1 = /^\d{1,2}\.?$/.test(t[i + lead]?.raw ?? '') || NO_SPACE.test(t[i + lead]?.f ?? '') ? ordinalDay(i + lead) : null;
      const k = i + lead + 1;
      const e = d1 !== null && free(k) && (W.to.includes(t[k]!.f) || t[k]!.f === '-') ? dateAt(k + 1) : null;
      if (d1 !== null && e?.kind === 'month' && d1 < Number(e.day.slice(8))) {
        out.day = `${e.day.slice(0, 8)}${String(d1).padStart(2, '0')}`;
        out.end = e.day;
        take(i, lead + 2 + e.len, 'span');
        continue;
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
        // "fri to sun", "seg a sex": a weekday end is the first one after the start.
        if (e && e.kind === 'weekday' && d.kind === 'weekday' && e.day <= d.day) e.day = shiftDay(e.day, 7);
        // "10月 20日 〜 25日": a day alone after a date with a month ends in that
        // month. A number that starts an amount is no end day: Turkish "kadar"
        // is "to" and "until", and "20 Aralık'a kadar 30 dk" is until Dec 20.
        const amount = amountAt(k + 1);
        const startsAmount = !!amount && !(amount.len === 1 && W.ordinal.some((o) => o !== '.' && t[k + 1]!.f.endsWith(o)));
        const endDay = !e && d.kind === 'month' && !startsAmount ? ordinalDay(k + 1) : null;
        if (endDay !== null && endDay > Number(d.day.slice(8)) && monthAt(k + 2) === null) {
          const end = `${d.day.slice(0, 8)}${String(endDay).padStart(2, '0')}`;
          if (shiftDay(end, 0) === end) {
            out.day = d.day;
            out.end = end;
            take(i, lead + d.len + 2, 'span');
            continue;
          }
        }
        // A start the reader rolled into next year, with an end still to
        // come this year, is a span under way: "oct 10 to oct 20" on the 14th.
        const lastYear = `${Number(d.day.slice(0, 4)) - 1}${d.day.slice(4)}`;
        const thisYear = (day: string) => day.slice(0, 4) === today.slice(0, 4);
        if (e && e.day < d.day && shiftDay(lastYear, 0) === lastYear && thisYear(lastYear) && thisYear(e.day) && lastYear < e.day && e.day >= today) d.day = lastYear;
        if (e && e.day > d.day) {
          out.day = d.day;
          out.end = e.day;
          take(i, lead + d.len + 1 + e.len, 'span');
          continue;
        }
      }
      // "every friday from oct 16": after a repeat, "from" names where it starts.
      if (lead && res.repeat && !out.day) {
        out.day = d.day;
        take(i, lead + d.len, 'date');
        continue;
      }
      if (lead) continue;
      // "12月20日 まで", "20 Aralık'a kadar": "until" after the date, where the
      // language puts it there. It ends a repeat read before or after it.
      if (E.postposed && is(k, W.until) && !untilAfter) {
        untilAfter = { day: d.day, from: i, len: d.len + 1, part: res.parts.length };
        take(i, d.len + 1, 'repeat');
        continue;
      }
      if (!out.day) {
        out.day = d.day;
        if (guessed.has(d.day)) res.guessedYear = true;
        take(i, d.len, 'date');
        continue;
      }
    }
  }

  if (untilAfter) {
    if (res.repeat) res.repeat = { ...res.repeat, until: untilAfter.day };
    else {
      // No repeat: the date is the day, and the word stays in the title.
      t[untilAfter.from + untilAfter.len - 1]!.used = false;
      res.parts[untilAfter.part] = { kind: 'date', text: textOf(untilAfter.from, untilAfter.len - 1) };
      out.day ??= untilAfter.day;
    }
  }
  // The pieces of one word with no spaces join again with no space between them.
  res.title = t.filter((x) => !x.used).map((x, k, all) => (k > 0 && x.group !== undefined && x.group === all[k - 1]!.group ? '' : ' ') + x.raw).join('').trim();
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
  // A weekly repeat on named weekdays starts on the first of them from the
  // day typed: "every other friday in 3 days" begins on a Friday.
  if (res.repeat?.weekdays?.length && out.day && !res.repeat.weekdays.includes(weekdayOf(out.day))) {
    const from = out.day;
    out.day = shiftDay(from, Math.min(...res.repeat.weekdays.map((w) => (w - weekdayOf(from) + 7) % 7)));
  }
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
