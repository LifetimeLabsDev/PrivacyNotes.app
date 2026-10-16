import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { LocalNote } from '../db';
import type { Stats } from '../stats';
import type { MedicationTemplate, TrackerSettings } from '../trackerTypes';
import { computeTrackerStats } from '../trackerStats';
import { SectionEyebrow } from '../settingsUI';
import { formatDay, weekdayDate, weekdayLabel } from '../intlFormat';
import { toLocalIso } from '../notesViewUtils';
import { checkedTaskCount, longestNotes } from './overviewCounts';
import { proUnlocked } from '../demo';
import { backfillLedger, firstCountedDay, firstLedgerDay, readLedger, type LedgerRow } from '../dayLedger';
import { milestoneLabel, milestoneProgress } from '../milestones';
import { aggregate, buildSeries } from '../trackerSeries';
import { compareAll, qualifiesForInsight } from '../trackerCompare';
import { intlLocale } from '../languages';
import type { Tab } from '../StatsModal';
import { buildWellnessModel, formatNumber, moodColor, trackerName } from './wellnessModel';

const DAY_MS = 86_400_000;
const RHYTHM_WEEKS = 26;
const HOURS_DAYS = 30;

function shift(date: string, days: number): string {
  const d = new Date(`${date}T12:00:00`);
  d.setDate(d.getDate() + days);
  return toLocalIso(d);
}

function Tile({ label, value, sub, children }: { label: string; value: string; sub?: string; children?: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-divider bg-surface-2 px-3 py-2.5 min-w-0">
      <div className="text-[11px] text-pn-muted">{label}</div>
      <div className="text-xl font-semibold mt-0.5">{value}</div>
      {children}
      {sub && <div className="text-[11px] text-pn-soft mt-1">{sub}</div>}
    </div>
  );
}

function DotRow({ days, color }: { days: boolean[]; color: string }) {
  return (
    <svg viewBox={`0 0 ${days.length * 17} 14`} width={days.length * 17} height={14} className="mt-1" style={{ color: 'var(--color-pn-muted, currentColor)' }} aria-hidden="true">
      {days.map((on, i) => (
        <circle key={i} cx={8 + i * 17} cy={7} r={5} fill={on ? color : 'none'} stroke={on ? 'none' : 'currentColor'} strokeOpacity={0.5} strokeWidth={1} />
      ))}
    </svg>
  );
}

function MiniBars({ values, max, color, ramp }: { values: (number | null)[]; max: number; color: string; ramp?: (v: number) => string }) {
  const w = values.length * 17;
  return (
    <svg viewBox={`0 0 ${w} 28`} width={w} height={28} className="mt-1" aria-hidden="true">
      {values.map((v, i) => {
        if (v === null) return null;
        const h = Math.max(2, (v / Math.max(max, 1)) * 26);
        return <rect key={i} x={i * 17 + 2} y={28 - h} width={13} height={h} rx={2} fill={ramp ? ramp(v) : color} />;
      })}
    </svg>
  );
}

/** Spec: ops/docs/plans/wellness-statistics.md (section 20) */
export function OverviewTab({ notes, stats, isNoteLocked, trackerSettings, medications, isPro, notesCreated, firstSeenAt, onOpenUpgrade, onOpenTab }: {
  notes: LocalNote[];
  stats: Stats;
  isNoteLocked: (n: LocalNote) => boolean;
  trackerSettings: TrackerSettings;
  medications: MedicationTemplate[];
  isPro: boolean;
  notesCreated: number;
  firstSeenAt: string | null;
  onOpenUpgrade?: () => void;
  onOpenTab: (tab: Tab) => void;
}) {
  const { t } = useTranslation('stats');
  const unlocked = proUnlocked(isPro);
  const today = toLocalIso(new Date());
  const weekFrom = shift(today, -6);
  const prevWeekFrom = shift(today, -13);

  const week = useMemo(() => buildWellnessModel(notes, isNoteLocked, trackerSettings, medications, '7d'), [notes, isNoteLocked, trackerSettings, medications]);
  const month = useMemo(() => buildWellnessModel(notes, isNoteLocked, trackerSettings, medications, '30d'), [notes, isNoteLocked, trackerSettings, medications]);
  const tStats = useMemo(() => computeTrackerStats(notes, medications, isNoteLocked), [notes, medications, isNoteLocked]);

  // `since` is the first day the ledger holds, estimated or not, which says
  // whether there is anything to show; `counted` is the first day counted at
  // the keyboard, the only day "Counted on this device since" may name.
  const [ledger, setLedger] = useState<{ rows: LedgerRow[]; since: string | null; counted: string | null; estimated: boolean } | null>(null);
  useEffect(() => {
    let alive = true;
    // An empty ledger is estimated once from the notes' own stamps, so the
    // two blocks show something on the first day instead of a week later.
    void backfillLedger(notes)
      .catch(() => false)
      .then(() => Promise.all([readLedger(shift(today, -HOURS_DAYS + 1), today), firstLedgerDay(), firstCountedDay()]))
      .then(([rows, since, counted]) => { if (alive) setLedger({ rows, since, counted, estimated: rows.some((r) => r.estimated) }); })
      // A database that cannot be read leaves the two ledger blocks empty.
      .catch(() => { if (alive) setLedger({ rows: [], since: null, counted: null, estimated: false }); });
    return () => { alive = false; };
  }, [today, notes.length]);

  // The week tiles.
  const mood = week.byId('mood');
  const moodWeek = mood ? aggregate(week.seriesOf(mood), mood) : null;
  const moodPrev = mood ? aggregate(buildSeries(week.entries, mood, { from: prevWeekFrom, to: shift(weekFrom, -1) }), mood) : null;
  const moodAvg = moodWeek?.kind === 'numeric' ? moodWeek.avg : null;
  const moodDelta = moodAvg !== null && moodPrev?.kind === 'numeric' && moodPrev.avg !== null && moodPrev.n >= 3 ? moodAvg - moodPrev.avg : null;
  const weekDays = Array.from({ length: 7 }, (_, i) => shift(weekFrom, i));
  const loggedDays = weekDays.map((d) => week.entries.some((e) => e.date === d));
  const writtenDays = weekDays.map((d) => (stats.heatmap[d] ?? 0) > 0);
  const wroteToday = (stats.heatmap[today] ?? 0) > 0;
  const ledgerByDay = new Map((ledger?.rows ?? []).map((r) => [r.date, r]));
  const wordsWeek = weekDays.reduce((s, d) => s + Math.max(0, ledgerByDay.get(d)?.words ?? 0), 0);
  const wordsPrev = Array.from({ length: 7 }, (_, i) => shift(prevWeekFrom, i)).reduce((s, d) => s + Math.max(0, ledgerByDay.get(d)?.words ?? 0), 0);
  const sleep = week.byId('sleepHours');
  const sleepWeek = sleep ? aggregate(week.seriesOf(sleep), sleep) : null;
  const moodWeekValues = mood ? week.seriesOf(mood).points.map((p) => (typeof p.value === 'number' ? p.value : null)) : [];

  // The rhythm grid: one column per week, Monday first, ending this week.
  const rhythm = useMemo(() => {
    const end = new Date(`${today}T12:00:00`);
    const dow = (end.getDay() + 6) % 7;
    const last = shift(today, 6 - dow);
    const first = shift(last, -(RHYTHM_WEEKS * 7 - 1));
    const cells: { date: string; edits: number; mood: number | null; future: boolean }[] = [];
    for (let i = 0; i < RHYTHM_WEEKS * 7; i++) {
      const date = shift(first, i);
      cells.push({ date, edits: stats.heatmap[date] ?? 0, mood: tStats.moodHeatmap[date] ?? null, future: date > today });
    }
    return { first, cells };
  }, [stats.heatmap, tStats.moodHeatmap, today]);
  const [layer, setLayer] = useState<'both' | 'writing' | 'mood'>('both');
  const maxEdits = Math.max(1, ...rhythm.cells.map((c) => c.edits));

  // Edits by hour over the last 30 days, from the ledger.
  const hours = useMemo(() => {
    const sums = new Array<number>(24).fill(0);
    for (const r of ledger?.rows ?? []) r.hours.forEach((h, i) => { sums[i] = (sums[i] ?? 0) + h; });
    return sums;
  }, [ledger]);
  const hoursTotal = hours.reduce((a, b) => a + b, 0);
  const peak = useMemo(() => {
    let best = 0, bestAt = 0;
    for (let i = 0; i < 24; i++) {
      const s = (hours[i] ?? 0) + (hours[(i + 1) % 24] ?? 0) + (hours[(i + 2) % 24] ?? 0);
      if (s > best) { best = s; bestAt = i; }
    }
    return { from: bestAt, to: (bestAt + 3) % 24 };
  }, [hours]);

  // The highlights, each behind its minimum.
  const highlights = useMemo(() => {
    const out: { icon: string; text: string; sub: string }[] = [];
    if (ledger && sleep) {
      const series = month.seriesOf(sleep);
      const long: number[] = []; const short: number[] = [];
      for (const p of series.points) {
        if (typeof p.value !== 'number') continue;
        const w = Math.max(0, ledgerByDay.get(p.date)?.words ?? 0);
        (p.value >= 7 ? long : short).push(w);
      }
      // Needs words on the ledger: before the first week of counting, there is nothing to compare.
      if (long.length >= 5 && short.length >= 5 && [...long, ...short].some((w) => w > 0)) {
        const mean = (xs: number[]) => xs.reduce((a, b) => a + b, 0) / xs.length;
        out.push({ icon: 'moon', text: t('overview.highlightSleep', { hours: 7, a: Math.round(mean(long)), b: Math.round(mean(short)) }), sub: t('overview.highlightSleepSub', { long: long.length, short: short.length, days: month.rangeDays }) });
      }
    }
    if (tStats.dayOfWeekMood) {
      const best = [...tStats.dayOfWeekMood].filter((d) => d.count >= 4).sort((a, b) => b.avg - a.avg)[0];
      if (best) {
        const longest = longestNotes(notes, isNoteLocked);
        const onDay = longest.filter(({ n }) => new Date(n.createdAt).getDay() === best.day).length;
        const day = weekdayLabel(weekdayDate(best.day), 'long');
        out.push({ icon: 'calendar', text: t('overview.highlightWeekday', { day, mood: formatNumber(best.avg), count: onDay, total: longest.length }), sub: t('overview.highlightWeekdaySub', { count: best.count, day }) });
      }
    }
    if (mood) {
      const row = compareAll(month.entries, month.registry, mood, month.range, 0).filter(qualifiesForInsight).find((r) => r.rule.kind === 'yesno');
      if (row) {
        const d = month.byId(row.trackerId)!;
        out.push({ icon: 'run', text: t('overview.highlightEffect', { name: trackerName(d, t), direction: t((row.delta ?? 0) >= 0 ? 'overview.higher' : 'overview.lower'), a: formatNumber(row.a.mean ?? 0), b: formatNumber(row.b.mean ?? 0) }), sub: t('overview.highlightEffectSub', { count: row.a.n, name: trackerName(d, t), days: month.rangeDays }) });
      }
    }
    {
      const now = new Map<string, number>(); const before = new Map<string, number>();
      const monthFrom = shift(today, -29); const prevFrom = shift(today, -59);
      for (const n of notes) {
        if (n.deleted === 1 || n.trashed === 1) continue;
        const day = toLocalIso(new Date(n.createdAt));
        const bucket = day >= monthFrom ? now : day >= prevFrom ? before : null;
        if (!bucket) continue;
        for (const tag of n.tags) bucket.set(tag, (bucket.get(tag) ?? 0) + 1);
      }
      const grown = [...now].map(([tag, c]) => ({ tag, c, b: before.get(tag) ?? 0 })).filter((x) => x.c >= 3 && x.b >= 1 && x.c > x.b).sort((a, b) => (b.c - b.b) - (a.c - a.b))[0];
      if (grown) out.push({ icon: 'tag', text: t('overview.highlightTag', { tag: grown.tag, now: grown.c, before: grown.b }), sub: t('overview.highlightTagSub', { count: stats.uniqueTags }) });
    }
    return out;
  }, [ledger, sleep, month, ledgerByDay, tStats.dayOfWeekMood, notes, isNoteLocked, mood, today, stats.uniqueTags, t]);

  const pillars = useMemo(() => {
    const live = notes.filter((n) => n.deleted === 0 && n.trashed === 0);
    const count = (type: string) => live.filter((n) => n.type === type);
    const fresh = (xs: LocalNote[]) => xs.filter((n) => toLocalIso(new Date(n.createdAt)) >= weekFrom).length;
    const tasks = count('task');
    const done = checkedTaskCount(tasks, isNoteLocked);
    return [
      { key: 'notes', n: count('note').length, sub: fresh(count('note')) },
      { key: 'journals', n: count('journal').length, sub: fresh(count('journal')) },
      { key: 'tasks', n: tasks.length, sub: done, done: true },
      { key: 'files', n: count('file').length, sub: fresh(count('file')) },
      { key: 'bookmarks', n: count('bookmark').length, sub: fresh(count('bookmark')) },
      { key: 'contacts', n: count('contact').length, sub: fresh(count('contact')) },
      { key: 'logins', n: count('login').length, sub: fresh(count('login')) },
    ].filter((p) => p.n > 0);
  }, [notes, isNoteLocked, weekFrom]);

  const meters = useMemo(() => milestoneProgress(stats, notesCreated, firstSeenAt), [stats, notesCreated, firstSeenAt]);
  const fmt = (n: number) => n.toLocaleString(intlLocale());
  const hour = (h: number) => `${String(h).padStart(2, '0')}:00`;

  return (
    <>
      <SectionEyebrow>{t('overview.week')}</SectionEyebrow>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 -mt-3">
        <Tile label={t('overview.streak')} value={t('overview.streakDays', { count: stats.currentStreak })} sub={wroteToday ? t('overview.streakKept') : t('overview.streakNudge')}>
          <DotRow days={writtenDays} color="#10b981" />
        </Tile>
        <Tile label={t('overview.words')} value={ledger && ledger.since ? fmt(wordsWeek) : '-'} sub={ledger?.estimated ? t('overview.ledgerEstimated') : ledger && ledger.since && wordsPrev > 0 ? t('overview.wordsDelta', { delta: `${wordsWeek >= wordsPrev ? '+' : '-'}${Math.round((Math.abs(wordsWeek - wordsPrev) / wordsPrev) * 100)}%` }) : ledger?.counted ? t('overview.ledgerSince', { date: formatDay(ledger.counted, 'date') }) : t('overview.ledgerEmpty')}>
          <MiniBars values={weekDays.map((d) => (ledgerByDay.has(d) ? Math.max(0, ledgerByDay.get(d)!.words) : null))} max={Math.max(...weekDays.map((d) => Math.max(0, ledgerByDay.get(d)?.words ?? 0)), 1)} color="#10b981" />
        </Tile>
        <Tile label={t('overview.mood')} value={moodAvg === null ? '-' : formatNumber(moodAvg)} sub={moodDelta === null ? undefined : t('overview.moodDelta', { delta: `${moodDelta >= 0 ? '+' : ''}${formatNumber(moodDelta)}` })}>
          <MiniBars values={moodWeekValues} max={10} color="#2F77BE" ramp={moodColor} />
        </Tile>
        <Tile label={t('overview.daysLogged')} value={t('overview.daysLoggedOf', { logged: loggedDays.filter(Boolean).length, days: 7 })} sub={sleepWeek?.kind === 'numeric' && sleepWeek.avg !== null ? `${t('wellness.tiles.avgSleep')} ${formatNumber(sleepWeek.avg)} h` : undefined}>
          <DotRow days={loggedDays} color="#2F77BE" />
        </Tile>
      </div>

      <div>
        <div className="flex items-center justify-between mb-2 gap-2">
          <SectionEyebrow>{t('overview.rhythm', { weeks: RHYTHM_WEEKS })}</SectionEyebrow>
          <div className="inline-flex rounded-md border border-divider overflow-hidden text-[10px]">
            {(['both', 'writing', 'mood'] as const).map((l) => (
              <button key={l} type="button" onClick={() => setLayer(l)} className={`px-2 py-0.5 ${layer === l ? 'bg-pn text-surface-2' : 'text-pn-soft'}`}>
                {t(l === 'both' ? 'overview.layerBoth' : l === 'writing' ? 'overview.layerWriting' : 'overview.layerMood')}
              </button>
            ))}
          </div>
        </div>
        <div dir="ltr">
          <svg viewBox={`0 0 ${RHYTHM_WEEKS * 15 + 16} 112`} width="100%" role="img" aria-label={t('overview.rhythmLegend')} style={{ display: 'block' }}>
            {/* Rows run Monday first, so rows 0, 2 and 4 are Monday, Wednesday and Friday (0 = Sunday). */}
            {[1, 3, 5].map((wd, i) => (
              <text key={wd} x={2} y={i * 30 + 12} fontSize={9} fill="currentColor" opacity={0.6}>{weekdayLabel(weekdayDate(wd), 'narrow')}</text>
            ))}
            {rhythm.cells.map((c, i) => {
              const x = 16 + Math.floor(i / 7) * 15;
              const y = (i % 7) * 15;
              const level = c.edits === 0 ? 0 : Math.min(4, Math.ceil((c.edits / maxEdits) * 4));
              const fills = ['rgba(127,127,127,0.12)', '#d1fae5', '#6ee7b7', '#10b981', '#047857'];
              return (
                <g key={c.date}>
                  <title>{`${formatDay(c.date, 'date')}: ${c.edits}${c.mood !== null ? `, ${c.mood}/10` : ''}`}</title>
                  <rect x={x} y={y} width={13} height={13} rx={2} fill={c.future ? 'none' : layer === 'mood' ? 'rgba(127,127,127,0.12)' : fills[level]} stroke={c.future ? 'currentColor' : 'none'} strokeOpacity={0.2} />
                  {layer !== 'writing' && c.mood !== null && <circle cx={x + 6.5} cy={y + 6.5} r={3} fill={moodColor(c.mood)} stroke="#fff" strokeWidth={1} />}
                </g>
              );
            })}
          </svg>
        </div>
        <div className="flex justify-between text-[10px] text-pn-muted mt-1">
          <span>{formatDay(rhythm.first, 'dayMonth')}</span>
          <span>{t('overview.rhythmLegend')}</span>
        </div>
      </div>

      <div>
        <div className="flex items-center justify-between mb-2 gap-2">
          <SectionEyebrow>{t('overview.hours')}</SectionEyebrow>
          <span className="text-[10px] text-pn-muted">{t('overview.hoursSub', { days: HOURS_DAYS })}</span>
        </div>
        {hoursTotal === 0 ? (
          <p className="text-[11px] text-pn-muted">{ledger?.counted ? t('overview.ledgerSince', { date: formatDay(ledger.counted, 'date') }) : ledger?.estimated ? t('overview.ledgerEstimated') : t('overview.ledgerEmpty')}</p>
        ) : (
          <div dir="ltr">
            <svg viewBox="0 0 600 54" width="100%" style={{ display: 'block' }} aria-label={t('overview.hours')} role="img">
              {hours.map((v, i) => {
                const h = Math.max(2, (v / Math.max(...hours, 1)) * 40);
                const inPeak = ((i - peak.from + 24) % 24) < 3;
                return <rect key={i} x={i * 25 + 2} y={42 - h} width={21} height={h} rx={2} fill="#2F77BE" fillOpacity={inPeak ? 1 : 0.45} />;
              })}
              {[0, 6, 12, 18, 23].map((h) => (
                <text key={h} x={h * 25 + 2} y={53} fontSize={9} fill="currentColor" opacity={0.6}>{hour(h)}</text>
              ))}
            </svg>
            <p className="text-[11px] text-pn-muted mt-1">{t('overview.hoursPeak', { from: hour(peak.from), to: hour(peak.to) })} {ledger?.estimated ? t('overview.ledgerEstimated') : ledger?.counted ? t('overview.ledgerSince', { date: formatDay(ledger.counted, 'date') }) : ''}</p>
          </div>
        )}
      </div>

      {highlights.length > 0 && (
        <div>
          <div className="flex items-center gap-2 mb-2">
            <SectionEyebrow>{t('overview.highlights')}</SectionEyebrow>
            {!isPro && <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-bold bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-300">{t('wellness.patterns.proBadge')}</span>}
            <span className="ms-auto text-[10px] text-pn-muted">{t('overview.computed')}</span>
          </div>
          {unlocked ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {highlights.map((h, i) => (
                <div key={i} className="rounded-lg border border-divider bg-surface-2 px-3 py-2.5">
                  <p className="text-xs text-pn-soft leading-relaxed">{h.text}</p>
                  <p className="text-[10px] text-pn-muted mt-1">{h.sub}</p>
                </div>
              ))}
            </div>
          ) : (
            <button type="button" onClick={onOpenUpgrade} className="w-full rounded-lg border border-dashed border-divider p-3 text-xs text-pn-muted hover:text-pn hover:border-pn-muted transition-colors text-center">
              {t('overview.highlightsLocked')}
            </button>
          )}
        </div>
      )}

      <div>
        <div className="flex items-center justify-between mb-2">
          <SectionEyebrow>{t('overview.vault')}</SectionEyebrow>
          <span className="text-[10px] text-pn-muted">{t('overview.vaultSub')}</span>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {pillars.map((p) => (
            <span key={p.key} className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-divider bg-surface-2 text-xs">
              {t(`overview.pillars.${p.key}`)} {fmt(p.n)}
              <span className="text-[10px] text-pn-muted">{p.done ? t('overview.done', { count: p.sub }) : p.sub > 0 ? `+${p.sub}` : ''}</span>
            </span>
          ))}
        </div>
      </div>

      <div>
        <div className="flex items-center justify-between mb-2">
          <SectionEyebrow>{t('overview.milestones')}</SectionEyebrow>
          <span className="text-[10px] text-pn-muted">{t('overview.longestStreak', { count: stats.longestStreak })}</span>
        </div>
        <div className="rounded-lg border border-divider bg-track p-3 space-y-2">
          {meters.map((row) => (
            <div key={row.family}>
              <div className="flex items-baseline justify-between gap-3 text-xs">
                <span className="text-pn-soft truncate">{row.next === null ? t('milestones.allReached', { label: milestoneLabel(row.family, row.reached[row.reached.length - 1]!) }) : t('milestones.next', { label: milestoneLabel(row.family, row.next) })}</span>
                {row.next !== null && <span className="text-pn-muted tabular-nums whitespace-nowrap">{t('milestones.ofTarget', { current: fmt(row.current), target: fmt(row.next) })}</span>}
              </div>
              <div className="mt-1 h-1.5 rounded-full bg-surface-0 overflow-hidden"><div className="h-full rounded-full bg-accent-fill" style={{ width: `${Math.round(row.progress * 100)}%` }} /></div>
            </div>
          ))}
          <div className="flex gap-2 pt-1">
            <button type="button" onClick={() => onOpenTab('writing')} className="px-3 py-1 rounded-md text-xs border border-divider hover:bg-surface-1">{t('overview.openWriting')}</button>
            <button type="button" onClick={() => onOpenTab('wellness')} className="px-3 py-1 rounded-md text-xs border border-divider hover:bg-surface-1">{t('overview.openWellness')}</button>
          </div>
        </div>
      </div>
    </>
  );
}
