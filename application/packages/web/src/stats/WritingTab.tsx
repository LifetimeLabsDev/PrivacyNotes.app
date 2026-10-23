import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { LocalNote } from '../db';
import type { Stats } from '../stats';
import { SectionEyebrow, SettingsSegmented, StatTile as Tile } from '../settingsUI';
import { BookOpen, Books, CalendarBlank, ChartLineUp, Check, Clock, FileText, Fire, Hash, PencilSimple, TextAa, Timer, Trophy } from '../icons';
import { formatDay, weekdayDate, weekdayLabel } from '../intlFormat';
import { toLocalIso } from '../notesViewUtils';
import { backfillLedger, readLedger, type LedgerRow } from '../dayLedger';
import { milestoneLabel, milestoneProgress } from '../milestones';
import { countWords } from '../wordCountUtils';
import { intlLocale } from '../languages';
import { TrackerChart } from '../TrackerChart';
import { StatPill } from './statsParts';

/** The ranges of the Writing tab, in days; "all" spans the account. */
const RANGES = [['7d', 7], ['30d', 30], ['3mo', 91], ['12mo', 365], ['all', 0]] as const;
type WritingRange = (typeof RANGES)[number][0];
/** Ranges longer than this draw one bar per week. */
const WEEKLY_AFTER_DAYS = 92;
/** Words a minute of reading, and words in a typical novel, for the two fun facts. */
const READ_WPM = 230;
const NOVEL_WORDS = 80_000;
const YEAR_WEEKS = 52;
const TAGS_MAX = 5;
const LONGEST_MAX = 3;
/** Note lengths in words: the upper bound of each bucket. */
const LENGTH_BUCKETS = [50, 200, 500, 1000, 5000, Infinity];
const WRITING_GREEN = '#10b981';

function shift(day: string, n: number): string {
  const d = new Date(`${day}T12:00:00`);
  d.setDate(d.getDate() + n);
  return toLocalIso(d);
}

/**
 * The Writing tab: how much, when and what a person writes. Tiles that
 * follow the range, two facts for fun, words per day, the writing year,
 * weekday by hour, top tags, note lengths, the longest notes, milestones.
 * Spec: ops/docs/archive/wellness-statistics.md (section 22)
 */
export function WritingTab({ notes, stats, isNoteLocked, notesCreated, firstSeenAt }: {
  notes: LocalNote[];
  stats: Stats;
  isNoteLocked: (n: LocalNote) => boolean;
  notesCreated: number;
  firstSeenAt: string | null;
}) {
  const { t } = useTranslation('stats');
  const fmt = (n: number) => Math.round(n).toLocaleString(intlLocale());
  const today = toLocalIso(new Date());
  const [rangeId, setRangeId] = useState<WritingRange>('30d');
  // "All" counts calendar days from the first note's own day, so a note written late yesterday keeps yesterday.
  const firstDay = stats.firstNoteDate ? toLocalIso(new Date(stats.firstNoteDate)) : today;
  const allDays = Math.max(1, Math.round((Date.parse(`${today}T12:00:00`) - Date.parse(`${firstDay}T12:00:00`)) / 86_400_000) + 1);
  const span = RANGES.find(([id]) => id === rangeId)![1] || allDays;
  const from = shift(today, -(span - 1));
  const prevFrom = shift(from, -span);
  const days = useMemo(() => Array.from({ length: span }, (_, i) => shift(from, i)), [from, span]);

  const [ledger, setLedger] = useState<LedgerRow[] | null>(null);
  useEffect(() => {
    let alive = true;
    void backfillLedger(notes)
      .catch(() => false)
      .then(() => readLedger(prevFrom, today))
      .then((rows) => { if (alive) setLedger(rows); })
      // A database that cannot be read leaves the ledger blocks empty.
      .catch(() => { if (alive) setLedger([]); });
    return () => { alive = false; };
  }, [prevFrom, today, notes.length]);
  const wordsByDay = useMemo(() => new Map((ledger ?? []).map((r) => [r.date, Math.max(0, r.words)])), [ledger]);
  const sumWords = (a: string, b: string) => {
    let s = 0;
    for (const [d, w] of wordsByDay) if (d >= a && d <= b) s += w;
    return s;
  };
  const words = sumWords(from, today);
  const wordsBefore = sumWords(prevFrom, shift(from, -1));

  const live = useMemo(() => notes.filter((n) => n.deleted === 0 && n.trashed === 0 && !isNoteLocked(n)), [notes, isNoteLocked]);
  const dayOf = (iso: string) => toLocalIso(new Date(iso));
  // A day with writing is a day the ledger saw an edit or a new note; the heatmap keeps only each note's first and last day.
  const ledgerActive = useMemo(() => new Set((ledger ?? []).filter((r) => r.edits + r.creates > 0).map((r) => r.date)), [ledger]);
  const writtenDays = ledger ? days.filter((d) => ledgerActive.has(d)).length : days.filter((d) => (stats.heatmap[d] ?? 0) > 0).length;
  const started = live.filter((n) => n.type !== 'journal' && dayOf(n.createdAt) >= from).length;
  const startedBefore = live.filter((n) => n.type !== 'journal' && dayOf(n.createdAt) >= prevFrom && dayOf(n.createdAt) < from).length;
  const change = (now: number, before: number, percent: boolean) => {
    if (before === 0) return null;
    const delta = percent ? Math.round(((now - before) / before) * 100) : now - before;
    const text = percent ? `${delta >= 0 ? '+' : '-'}${Math.abs(delta)}%` : `${delta >= 0 ? '+' : '-'}${fmt(Math.abs(delta))}`;
    return <span className={delta > 0 ? 'text-success' : delta < 0 ? 'text-danger' : ''}>{t('writingTab.vsBefore', { delta: text })}</span>;
  };

  // Words per day, or per week on the long ranges.
  const weekly = span > WEEKLY_AFTER_DAYS;
  // On the long ranges a bar is a week's total, one point per Monday; the chart's own weekly mode would average the days.
  const series = useMemo(() => {
    if (!weekly) return { from, to: today, points: days.map((d) => ({ date: d, value: wordsByDay.get(d) ?? 0 })) };
    const weeks = new Map<string, number>();
    for (const d of days) {
      const monday = shift(d, -((new Date(`${d}T12:00:00`).getDay() + 6) % 7));
      weeks.set(monday, (weeks.get(monday) ?? 0) + (wordsByDay.get(d) ?? 0));
    }
    const points = [...weeks].map(([date, value]) => ({ date, value }));
    return { from: points[0]?.date ?? from, to: points[points.length - 1]?.date ?? today, points };
  }, [from, today, days, wordsByDay, weekly]);
  const biggest = useMemo(() => days.reduce<{ d: string; w: number } | null>((best, d) => {
    const w = wordsByDay.get(d) ?? 0;
    return w > 0 && (!best || w > best.w) ? { d, w } : best;
  }, null), [days, wordsByDay]);
  const bestWeekday = useMemo(() => {
    const sums = new Array<number>(7).fill(0);
    for (const d of days) sums[new Date(`${d}T12:00:00`).getDay()]! += wordsByDay.get(d) ?? 0;
    const max = Math.max(...sums);
    return max > 0 ? sums.indexOf(max) : null;
  }, [days, wordsByDay]);

  // Weekday by hour of the edits, from the ledger, Monday first.
  const punch = useMemo(() => {
    const grid = Array.from({ length: 7 }, () => new Array<number>(24).fill(0));
    for (const r of ledger ?? []) {
      if (r.date < from) continue;
      const wd = (new Date(`${r.date}T12:00:00`).getDay() + 6) % 7;
      r.hours.forEach((h, i) => { grid[wd]![i]! += h; });
    }
    return grid;
  }, [ledger, from]);
  const punchMax = Math.max(1, ...punch.flat());

  // The writing year: 52 week columns, Monday first, ending this week.
  const year = useMemo(() => {
    const dow = (new Date(`${today}T12:00:00`).getDay() + 6) % 7;
    const first = shift(shift(today, 6 - dow), -(YEAR_WEEKS * 7 - 1));
    return Array.from({ length: YEAR_WEEKS * 7 }, (_, i) => {
      const date = shift(first, i);
      return { date, edits: stats.heatmap[date] ?? 0, future: date > today };
    });
  }, [stats.heatmap, today]);
  // Shades by the quartiles of the active days, so one huge day (an import) does not pale every other.
  const yearCuts = useMemo(() => {
    const active = year.map((c) => c.edits).filter((e) => e > 0).sort((a, b) => a - b);
    const q = (p: number) => active[Math.min(active.length - 1, Math.floor(active.length * p))] ?? 1;
    return [q(0.25), q(0.5), q(0.75)];
  }, [year]);
  const yearLevel = (edits: number) => (edits === 0 ? 0 : 1 + yearCuts.filter((cut) => edits > cut).length);
  const yearFills = ['rgba(127,127,127,0.12)', '#d1fae5', '#6ee7b7', '#10b981', '#047857'];

  const tags = useMemo(() => {
    const counts = new Map<string, number>();
    for (const n of live) if (dayOf(n.updatedAt) >= from) for (const tag of n.tags) counts.set(tag, (counts.get(tag) ?? 0) + 1);
    return [...counts].sort((a, b) => b[1] - a[1]).slice(0, TAGS_MAX);
  }, [live, from]);
  const tagsUsed = useMemo(() => new Set(live.filter((n) => dayOf(n.updatedAt) >= from).flatMap((n) => n.tags)).size, [live, from]);

  const lengths = useMemo(() => live.filter((n) => n.type === 'note').map((n) => ({ n, w: countWords(n.body) })), [live]);
  const buckets = LENGTH_BUCKETS.map((top, i) => lengths.filter(({ w }) => w <= top && w > (LENGTH_BUCKETS[i - 1] ?? -1)).length);
  const median = useMemo(() => {
    const ws = lengths.map((x) => x.w).sort((a, b) => a - b);
    return ws.length ? ws[Math.floor(ws.length / 2)]! : null;
  }, [lengths]);
  const longest = useMemo(() => [...lengths].sort((a, b) => b.w - a.w).slice(0, LONGEST_MAX), [lengths]);

  const meters = useMemo(() => milestoneProgress(stats, notesCreated, firstSeenAt), [stats, notesCreated, firstSeenAt]);
  const reached = meters.flatMap((row) => row.reached.map((v) => ({ family: row.family, v })));
  const topReached = meters.filter((row) => row.reached.length > 0).map((row) => ({ family: row.family, v: row.reached[row.reached.length - 1]! }));

  const readMinutes = Math.round(words / READ_WPM);
  const novels = stats.totalWords / NOVEL_WORDS;

  return (
    <>
      <SettingsSegmented
        label={t('writing.timeRangeAria')}
        value={rangeId}
        onChange={setRangeId}
        options={RANGES.map(([id]) => ({ value: id, label: t(`range.${id}`) }))}
      />

      <div data-setting="stats.writing">
        <SectionEyebrow className="mb-2" icon={PencilSimple}>{t('writingTab.inOneLook')}</SectionEyebrow>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          <Tile label={<span className="inline-flex items-center gap-1"><TextAa size={12} aria-hidden="true" />{t('writingTab.wordsWritten')}</span>} value={ledger ? fmt(words) : '-'} sub={change(words, wordsBefore, true)} />
          <Tile label={<span className="inline-flex items-center gap-1"><CalendarBlank size={12} aria-hidden="true" />{t('writingTab.daysWrote')}</span>} value={t('overview.daysLoggedOf', { logged: writtenDays, days: span })} sub={writtenDays > 0 ? t('writingTab.perDay', { words: fmt(words / writtenDays) }) : undefined} />
          <Tile label={<span className="inline-flex items-center gap-1"><FileText size={12} aria-hidden="true" />{t('writingTab.notesStarted')}</span>} value={fmt(started)} sub={change(started, startedBefore, false)} />
          <div data-setting="stats.streak" className="min-w-0">
            <Tile label={<span className="inline-flex items-center gap-1"><Fire size={12} aria-hidden="true" />{t('writing.currentStreak')}</span>} value={t('writing.streakValue', { count: stats.currentStreak })} sub={t('overview.longestStreak', { count: stats.longestStreak })} />
          </div>
        </div>
        <div className="flex flex-wrap gap-1.5 mt-2">
          {readMinutes > 0 && <StatPill tone="neutral" icon={<Timer size={12} aria-hidden="true" />}>{readMinutes >= 60 ? t('writingTab.readHours', { count: Math.round(readMinutes / 60) }) : t('writingTab.readTime', { count: readMinutes })}</StatPill>}
          {novels >= 0.1 && <StatPill tone="neutral" icon={<Books size={12} aria-hidden="true" />}>{t('writingTab.novels', { count: Math.round(novels * 10) / 10 })}</StatPill>}
          <StatPill tone="neutral" icon={<Hash size={12} aria-hidden="true" />}>{t('writingTab.tagsUsed', { count: stats.uniqueTags, used: tagsUsed })}</StatPill>
        </div>
      </div>

      {ledger && words > 0 && (
        <div>
          <div className="flex items-center justify-between gap-2 mb-2">
            <SectionEyebrow icon={ChartLineUp}>{t(weekly ? 'writingTab.wordsPerWeek' : 'writingTab.wordsPerDay')}</SectionEyebrow>
            {!weekly && <span className="hidden sm:inline text-[11px] text-pn-muted">{t('home.moodLegend')}</span>}
          </div>
          <div className="rounded-lg border border-divider bg-surface-2 p-3 space-y-2">
            <TrackerChart spec={{ form: 'bars', series, color: WRITING_GREEN, min: 0 }} height={96} average={!weekly} ariaLabel={t('writingTab.wordsPerDay')} />
            <div className="flex justify-between text-[11px] text-pn-muted">
              <span>{formatDay(from, 'dayMonth')}</span>
              <span>{formatDay(today, 'dayMonth')}</span>
            </div>
            {biggest && bestWeekday !== null && (
              <p className="text-sm text-pn">{t('writingTab.biggest', { day: formatDay(biggest.d, 'date'), words: fmt(biggest.w), weekday: weekdayLabel(weekdayDate(bestWeekday), 'long') })}</p>
            )}
          </div>
        </div>
      )}

      <div>
        <div className="flex items-center justify-between gap-2 mb-2">
          <SectionEyebrow icon={CalendarBlank}>{t('writingTab.year')}</SectionEyebrow>
          <span className="text-[11px] text-pn-muted">{t('writingTab.yearHint')}</span>
        </div>
        <div className="rounded-lg border border-divider bg-surface-2 p-3" dir="ltr">
          <svg viewBox={`0 0 ${YEAR_WEEKS * 12} ${7 * 12}`} width="100%" role="img" aria-label={t('writingTab.year')} style={{ display: 'block' }}>
            {year.map((c, i) => {
              const level = yearLevel(c.edits);
              return (
                <rect key={c.date} x={Math.floor(i / 7) * 12} y={(i % 7) * 12} width={10} height={10} rx={2} fill={c.future ? 'none' : yearFills[level]} stroke={c.future ? 'currentColor' : 'none'} strokeOpacity={0.15}>
                  <title>{`${formatDay(c.date, 'date')}: ${c.edits}`}</title>
                </rect>
              );
            })}
          </svg>
          <div className="flex justify-between text-[11px] text-pn-muted mt-1">
            <span>{formatDay(year[0]!.date, 'dayMonth')}</span>
            <span>{formatDay(today, 'dayMonth')}</span>
          </div>
        </div>
      </div>

      {punchMax > 1 && (
        <div>
          <div className="flex items-center justify-between gap-2 mb-2">
            <SectionEyebrow icon={Clock}>{t('overview.hours')}</SectionEyebrow>
            <span className="text-[11px] text-pn-muted">{t('writingTab.hoursHint')}</span>
          </div>
          <div className="rounded-lg border border-divider bg-surface-2 p-3" dir="ltr">
            <svg viewBox={`0 0 ${24 * 14 + 16} ${7 * 14 + 12}`} width="100%" role="img" aria-label={t('overview.hours')} style={{ display: 'block' }}>
              {punch.map((row, wd) => (
                <g key={wd}>
                  <text x={0} y={wd * 14 + 10} fontSize={9} fill="currentColor" opacity={0.6}>{weekdayLabel(weekdayDate((wd + 1) % 7), 'narrow')}</text>
                  {row.map((v, h) => v > 0 && (
                    <circle key={h} cx={16 + h * 14 + 7} cy={wd * 14 + 7} r={1.5 + (v / punchMax) * 5} fill={WRITING_GREEN} fillOpacity={0.25 + (v / punchMax) * 0.75} />
                  ))}
                </g>
              ))}
              {[0, 6, 12, 18].map((h) => <text key={h} x={16 + h * 14 + 2} y={7 * 14 + 10} fontSize={9} fill="currentColor" opacity={0.6}>{`${String(h).padStart(2, '0')}:00`}</text>)}
            </svg>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {tags.length > 0 && (
          <div>
            <SectionEyebrow className="mb-2" icon={Hash}>{t('writingTab.topTags')}</SectionEyebrow>
            <div className="rounded-lg border border-divider bg-surface-2 px-3 py-2 space-y-2">
              {tags.map(([tag, n]) => (
                <div key={tag} className="grid grid-cols-[minmax(0,8rem)_1fr_auto] items-center gap-2">
                  <span title={`#${tag}`} className="justify-self-start inline-flex max-w-full items-center text-[11px] px-1.5 py-0.5 rounded pn-chip text-accent-strong">
                    <span className="truncate" dir="auto">#{tag}</span>
                  </span>
                  <span aria-hidden="true" className="block h-1.5 rounded-full bg-accent-fill" style={{ width: `${(n / tags[0]![1]) * 100}%` }} />
                  <span className="text-[11px] tabular-nums text-pn-muted">{fmt(n)}</span>
                </div>
              ))}
            </div>
          </div>
        )}
        {lengths.length > 0 && (
          <div>
            <SectionEyebrow className="mb-2" icon={FileText}>{t('writingTab.lengths')}</SectionEyebrow>
            <div className="rounded-lg border border-divider bg-surface-2 p-3 space-y-2">
              <div className="flex items-end gap-1.5 h-16">
                {buckets.map((c, i) => (
                  <span key={i} title={String(c)} className="flex-1 rounded-t-sm bg-accent-fill" style={{ height: `${Math.max(4, (c / Math.max(...buckets, 1)) * 100)}%`, opacity: 0.85 }} />
                ))}
              </div>
              <div className="flex justify-between text-[11px] text-pn-muted"><span>{t('writingTab.short')}</span><span>1k</span><span>5k+</span></div>
              {median !== null && <p className="text-xs text-pn">{t('writingTab.median', { words: fmt(median) })}</p>}
            </div>
          </div>
        )}
      </div>

      {longest.length > 0 && (
        <div>
          <SectionEyebrow className="mb-2" icon={BookOpen}>{t('writingTab.longest')}</SectionEyebrow>
          <div className="rounded-lg border border-divider bg-surface-2 px-3 divide-y divide-divider">
            {longest.map(({ n, w }) => (
              <div key={n.id} className="flex items-center justify-between gap-3 py-2 text-sm">
                <span className="truncate text-pn" dir="auto">{n.title || t('common:state.untitled')}</span>
                <span className="shrink-0 text-[11px] text-pn-muted tabular-nums">{t('writingTab.words', { count: w, formatted: fmt(w) })}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div data-setting="stats.milestones">
        <div className="flex items-center justify-between gap-2 mb-2">
          <SectionEyebrow icon={Trophy}>{t('milestones.heading')}</SectionEyebrow>
          {reached.length > 0 && <span className="text-[11px] text-pn-muted">{t('milestones.reached', { count: reached.length })}</span>}
        </div>
        <div className="rounded-lg border border-divider bg-surface-2 p-3 space-y-2.5">
          {meters.filter((row) => row.next !== null).map((row) => (
            <div key={row.family} className="flex items-center gap-3">
              <span className="w-40 shrink-0 truncate text-xs text-pn">{t('milestones.next', { label: milestoneLabel(row.family, row.next!) })}</span>
              <span className="flex-1 h-1.5 rounded-full bg-surface-0 overflow-hidden"><span className="block h-full rounded-full bg-accent-fill" style={{ width: `${Math.round(row.progress * 100)}%` }} /></span>
              <span className="shrink-0 text-[11px] text-pn-muted tabular-nums">{t('milestones.ofTarget', { current: fmt(row.current), target: fmt(row.next!) })}</span>
            </div>
          ))}
          {topReached.length > 0 && (
            <div className="flex flex-wrap gap-1.5 pt-1">
              {topReached.map(({ family, v }) => (
                <StatPill key={family} icon={<Check size={12} aria-hidden="true" />}>{milestoneLabel(family, v)}</StatPill>
              ))}
            </div>
          )}
        </div>
      </div>
    </>
  );
}
