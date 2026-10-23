import { useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { ArrowDown, ArrowUp, CalendarBlank, CalendarCheck, ChartLineUp, CheckCircle, DownloadSimple, Fire, PencilSimple, Pill, Pulse, SmileySad, Sparkle } from '../icons';
import type { LocalNote } from '../db';
import { NO_FACTORS, type FactorDef, type MedicationTemplate, type TrackerSettings } from '../trackerTypes';
import { computeTrackerStats, journalsInRange } from '../trackerStats';
import { proUnlocked } from '../demo';
import { SETTINGS_BTN, SETTINGS_HELP, SectionEyebrow, SettingsSegmented, StatTile } from '../settingsUI';
import { IconUpgrade, ProMark } from '../UpgradeModal';
import { HelpChip } from '../HelpChip';
import { Button, ItemSwitcher, SubViewHeader, type SwitcherItem } from '../ui';
import { intlLocale } from '../languages';
import { toLocalIso } from '../notesViewUtils';
import { TrackerChart } from '../TrackerChart';
import { adaptiveRange, aggregate, buildSeries, previousWindow } from '../trackerSeries';
import { compareAll, echoesOutcome, moodStreak, qualifiesForInsight, MIN_PER_SIDE } from '../trackerCompare';
import { visibleInUi } from '../trackerRegistry';
import type { CompareResult, DaySeries, RangeId, TrackerDescriptor } from '../wellnessTypes';
import { ExploreSubTab } from './ExploreSubTab';
import { MedicationSubTab } from './MedicationSubTab';
import { PatternsSubTab } from './PatternsSubTab';
import { WeekRecap } from './WeekRecap';
import { YearInPixels } from './YearInPixels';
import { cardNumbers, chartSpecFor } from './TrackerCard';
import { buildWellnessModel, formatDelta, formatNumber, hasData, standoutLabel, trackerName, type WellnessModel } from './wellnessModel';
import { DayCalendar, EffectBarRow, MoodMix, StatPill, SureDots, TONE_TEXT, TrackerPill, TrackerTile, WeekdayChart, changeTone, weekdayAverages } from './statsParts';
import { MoodMark } from '../moodMark';
import { moodWord } from '../checkIn';
import { formatDay, weekdayLabel } from '../intlFormat';
import { RANGE_IDS, readWellnessRange, savedWellnessRange, writeWellnessRange } from './wellnessRange';

/** What the page shows: the one list, one tracker, or the medications. */
export type StatsView = { kind: 'home' } | { kind: 'tracker'; id: string } | { kind: 'medication' };


/**
 * Settings > Statistics: one page. Days logged, the plain sentences of what
 * stands out, one row per tracker and the writing rows; a tap opens that
 * thing's own page with a Back row. No tabs, so nothing hides behind one.
 * Spec: ops/docs/archive/wellness-statistics.md (section 22)
 */
export function StatsPage({ notes, isNoteLocked, trackerSettings, factors = NO_FACTORS, medications, isPro, onOpenUpgrade, weekReflection, onWeekReflectionChange, onOpenDay, onOpenExport, initialView }: {
  notes: LocalNote[];
  isNoteLocked: (n: LocalNote) => boolean;
  trackerSettings: TrackerSettings;
  factors?: FactorDef[];
  medications: MedicationTemplate[];
  isPro: boolean;
  onOpenUpgrade?: () => void;
  weekReflection?: string;
  onWeekReflectionChange?: (text: string) => void;
  onOpenDay?: (date: string) => void;
  /** Opens Settings > Import & Export on its Trackers tab. */
  onOpenExport?: () => void;
  initialView?: StatsView;
}) {
  const { t } = useTranslation('stats');
  const [view, setView] = useState<StatsView>(initialView ?? { kind: 'home' });
  const unlocked = proUnlocked(isPro);
  const today = toLocalIso(new Date());

  const [rangeId, setRangeId] = useState<RangeId>(readWellnessRange);
  const model = useMemo(
    () => buildWellnessModel(notes, isNoteLocked, trackerSettings, medications, rangeId, factors),
    [notes, isNoteLocked, trackerSettings, medications, rangeId, factors],
  );
  // Everything follows the range; the weekly recap reads whole weeks from the model's entries.
  const stats = useMemo(
    () => computeTrackerStats(journalsInRange(notes, model.range), medications, isNoteLocked),
    [notes, model.range, medications, isNoteLocked],
  );
  // The first open lands on the smallest preset that covers the journal.
  useEffect(() => {
    if (savedWellnessRange() === null) setRangeId(adaptiveRange(model.firstDay));
    // eslint-disable-next-line react-hooks/exhaustive-deps -- once, on mount
  }, []);
  useEffect(() => { writeWellnessRange(rangeId); }, [rangeId]);

  // A new view opens at its top, not at the scroll position the last one was left at.
  const top = useRef<HTMLDivElement>(null);
  const viewKey = view.kind === 'tracker' ? `tracker:${view.id}` : view.kind;
  const opened = useRef(false);
  // Back to the list lands where the list was left, not at its top.
  const homeScroll = useRef<number | null>(null);
  const scroller = () => top.current?.closest('.overflow-y-auto') ?? null;
  useLayoutEffect(() => {
    // Not on the first open: the settings search scrolls to its own marker then.
    if (opened.current) {
      const box = scroller();
      if (view.kind === 'home' && homeScroll.current !== null && box) box.scrollTop = homeScroll.current;
      else top.current?.scrollIntoView({ block: 'start' });
    }
    opened.current = true;
    // eslint-disable-next-line react-hooks/exhaustive-deps -- the view key names every view
  }, [viewKey]);
  const home = () => setView({ kind: 'home' });
  const back = (children: ReactNode) => <SubViewHeader backLabel={t('title')} onBack={home} anchorRef={top}>{children}</SubViewHeader>;
  const range = (
    <SettingsSegmented
      label={t('writing.timeRangeAria')}
      value={rangeId}
      onChange={setRangeId}
      options={RANGE_IDS.map((id) => ({ value: id, label: t(`range.${id}`) }))}
    />
  );

  if (view.kind === 'medication') {
    return (
      <div data-setting="stats.medication" className="space-y-6">
        {back(<span className="text-sm font-semibold text-pn">{t('wellness.subTabs.medication')}</span>)}
        {range}
        <MedicationSubTab model={model} stats={stats} medications={medications} unlocked={unlocked} isPro={isPro} onOpenDay={onOpenDay} />
        <HelpChip surface="wellness" className="pt-1" />
      </div>
    );
  }

  if (view.kind === 'tracker') {
    const d = model.byId(view.id);
    return (
      <div className="space-y-6">
        {back(d ? <TrackerSwitcher model={model} current={d} onPick={(id) => setView({ kind: 'tracker', id })} /> : <span className="text-sm font-semibold text-pn">{t('title')}</span>)}
        {range}
        {d ? (
          <ExploreSubTab model={model} trackerId={d.id} unlocked={unlocked} isPro={isPro} onOpenUpgrade={onOpenUpgrade} onOpenDay={onOpenDay} />
        ) : (
          <p className={SETTINGS_HELP}>{t('wellness.trackers.empty')}</p>
        )}
        {d?.id === 'mood' && (
          <>
            <YearInPixels model={model} onOpenDay={onOpenDay} />
            <PatternsSubTab model={model} stats={stats} unlocked={unlocked} isPro={isPro} onOpenUpgrade={onOpenUpgrade} />
          </>
        )}
        <HelpChip surface="wellness" className="pt-1" />
      </div>
    );
  }

  const open = (d: TrackerDescriptor) => {
    homeScroll.current = scroller()?.scrollTop ?? null;
    setView(d.kind === 'medication' ? { kind: 'medication' } : { kind: 'tracker', id: d.id });
  };
  const hasEntries = model.entries.length > 0;

  return (
    <div ref={top} className="space-y-6 scroll-mt-6">
      {hasEntries && (
        <div className="space-y-2">
          {range}
          <p className={SETTINGS_HELP}>{t('wellness.sourceLine')}</p>
        </div>
      )}

      {hasEntries ? <Overview model={model} today={today} medAdherence={stats.medAdherence} /> : (
        <div className="rounded-lg border border-divider bg-track px-4 py-6 text-center">
          <p className="text-sm text-pn">{t('wellness.empty.title')}</p>
          <p className="text-xs text-pn-muted mt-1">{t('wellness.empty.hint')}</p>
        </div>
      )}

      {hasEntries && <MoodByDay model={model} />}

      {model.entries.length >= MIN_PER_SIDE && <StandsOut model={model} unlocked={unlocked} isPro={isPro} onOpen={open} onOpenUpgrade={onOpenUpgrade} />}

      {hasEntries && <YourWeek model={model} />}

      {hasEntries && <TrackerRows model={model} onOpen={open} />}

      {hasEntries && (
        <div>
          <SectionEyebrow className="mb-2" icon={CalendarBlank}>{t('home.yourDays')}</SectionEyebrow>
          <div className="rounded-lg border border-divider bg-surface-2 p-3">
            <DayCalendar model={model} onOpenDay={onOpenDay} />
          </div>
        </div>
      )}

      {hasEntries && (
        <div>
          <div className="flex items-center gap-2 mb-2">
            <SectionEyebrow icon={CalendarCheck}>{t('wellness.week.heading')}</SectionEyebrow>
            {!isPro && <ProMark />}
          </div>
          {unlocked ? (
            <WeekRecap model={model} notes={notes} reflection={weekReflection} onReflectionChange={onWeekReflectionChange} />
          ) : (
            <Button variant="upgrade" icon={<IconUpgrade size={14} onFill />} onClick={onOpenUpgrade}>
              {t('wellness.week.locked')}
            </Button>
          )}
        </div>
      )}

      {/* The full list, also at the end of the Mood page: every tracker against mood, same day or next. */}
      {hasEntries && <PatternsSubTab model={model} stats={stats} unlocked={unlocked} isPro={isPro} onOpenUpgrade={onOpenUpgrade} />}

      {/* The exports live in Settings > Import & Export > Trackers, with
          every other export; this door leads there, after the data it exports. */}
      {hasEntries && onOpenExport && (
        <button type="button" onClick={onOpenExport} className={`${SETTINGS_BTN} self-start`}>
          <DownloadSimple size={15} className="text-accent" aria-hidden="true" />
          {t('wellness.export.openExport')}
        </button>
      )}
      <HelpChip surface="wellness" className="pt-1" />
    </div>
  );
}

/** The change of a tracker's average against the window just before the range; none for "All". */
function changeOf(model: WellnessModel, d: TrackerDescriptor, series: DaySeries): number | null {
  if (model.rangeId === 'all' || d.aggregate === 'sum') return null;
  const now = aggregate(series, d);
  if (now.kind !== 'numeric' || now.avg === null) return null;
  const before = aggregate(buildSeries(model.entries, d, previousWindow(model.range)), d);
  if (before.kind !== 'numeric' || before.avg === null || before.n < 3) return null;
  return now.avg - before.avg;
}

/** The arrow and the change, green when the change is good for that tracker. */
function Change({ d, delta, long = false }: { d: TrackerDescriptor; delta: number; long?: boolean }) {
  const { t } = useTranslation('stats');
  const Arrow = delta >= 0 ? ArrowUp : ArrowDown;
  // Counted units (steps, beats) change in whole numbers.
  const text = formatDelta(delta, d.unit === 'steps' || d.unit === 'bpm' ? 0 : 1);
  return (
    <span className={`inline-flex items-center gap-0.5 text-[11px] font-medium tabular-nums ${TONE_TEXT[changeTone(d, delta)]}`}>
      <Arrow size={11} aria-hidden="true" />
      {long ? t('home.delta', { delta: text }) : text}
    </span>
  );
}

/** The range in one look: the average mood on its square, its word and change, then the logged pills. */
function Overview({ model, today, medAdherence }: { model: WellnessModel; today: string; medAdherence: number | null }) {
  const { t } = useTranslation('stats');
  const mood = model.byId('mood');
  const moodSeries = mood ? model.seriesOf(mood) : null;
  const moodAgg = mood && moodSeries ? aggregate(moodSeries, mood) : null;
  const avg = moodAgg?.kind === 'numeric' ? moodAgg.avg : null;
  const moodDelta = mood && moodSeries ? changeOf(model, mood, moodSeries) : null;
  const streak = moodStreak(model.entries, today);
  const early = model.entries.length < MIN_PER_SIDE;
  // The averages of the trackers after mood, the ones a person logs most, as pills.
  const rank = (d: TrackerDescriptor) => { const i = PILL_ORDER.indexOf(d.id); return i < 0 ? PILL_ORDER.length : i; };
  const pills = model.registry
    .filter((d) => d.id !== 'mood' && d.kind !== 'medication' && visibleInUi(d))
    .map((d) => ({ d, series: model.seriesOf(d) }))
    .filter(({ series }) => hasData(series))
    .sort((a, b) => rank(a.d) - rank(b.d))
    .slice(0, PILL_MAX);
  // A pill's value as the journal pills write it: a scale out of its top, a set by its first tag.
  const pillValue = (d: TrackerDescriptor, series: DaySeries) => {
    const { headline } = cardNumbers(d, series, t);
    if (d.kind === 'scale' && d.max) return `${headline}/${d.max}`;
    if (d.kind === 'set') return headline.split(', ')[0];
    return headline;
  };

  return (
    <div className="rounded-xl border border-divider bg-surface-2 p-3 space-y-3">
      {avg !== null && (
        <div className="flex items-center gap-3">
          <MoodMark mood={Math.round(avg * 10) / 10} size={40} />
          <div className="min-w-0">
            <p className="text-sm font-semibold text-pn">{t('home.onAverage', { word: moodWord(Math.round(avg)) })}</p>
            {mood && moodDelta !== null && <Change d={mood} delta={moodDelta} long />}
          </div>
        </div>
      )}
      <div className="flex flex-wrap gap-1.5">
        <StatPill icon={<CheckCircle size={12} aria-hidden="true" />}>{t('home.daysOf', { logged: model.inRange.length, days: model.rangeDays })}</StatPill>
        {streak >= 2 && <StatPill icon={<Fire size={12} aria-hidden="true" />}>{t('home.inARow', { count: streak })}</StatPill>}
        {medAdherence != null && <StatPill icon={<Pill size={12} aria-hidden="true" />}>{t('home.medsTaken', { pct: medAdherence })}</StatPill>}
        {pills.map(({ d, series }) => <TrackerPill key={d.id} d={d}>{pillValue(d, series)}</TrackerPill>)}
      </div>
      {early && <p className="text-[11px] text-pn-muted">{t('home.firstInsight', { count: MIN_PER_SIDE })}</p>}
    </div>
  );
}

/** Mood, one bar per day in its band's color with the 7-day line, then the mix of bands. */
function MoodByDay({ model }: { model: WellnessModel }) {
  const { t } = useTranslation('stats');
  const mood = model.byId('mood');
  if (!mood) return null;
  const series = model.seriesOf(mood);
  if (!hasData(series)) return null;
  return (
    <div data-setting="stats.moodTrend">
      <div className="flex items-center justify-between gap-2 mb-2">
        <SectionEyebrow icon={ChartLineUp}>{t('home.moodByDay')}</SectionEyebrow>
        <span className="hidden sm:inline text-[11px] text-pn-muted">{t('home.moodLegend')}</span>
      </div>
      <div className="rounded-lg border border-divider bg-surface-2 p-3 space-y-3">
        <TrackerChart spec={chartSpecFor(mood, series, model.rangeDays > 182)} height={96} average ariaLabel={trackerName(mood, t)} />
        <div className="flex justify-between text-[11px] text-pn-muted -mt-2">
          <span>{formatDay(model.range.from, 'dayMonth')}</span>
          <span>{formatDay(model.range.to, 'dayMonth')}</span>
        </div>
        <MoodMix series={series} />
      </div>
    </div>
  );
}

/** Average mood per weekday, with the best and the hardest day named. */
function YourWeek({ model }: { model: WellnessModel }) {
  const { t } = useTranslation('stats');
  const mood = model.byId('mood');
  if (!mood || model.entries.length < WEEK_MIN_DAYS) return null;
  const values = weekdayAverages(model.seriesOf(mood));
  const known = values.map((v, i) => ({ v, i })).filter((x): x is { v: number; i: number } => x.v !== null);
  if (known.length < 7) return null;
  const best = known.reduce((a, b) => (b.v > a.v ? b : a));
  const worst = known.reduce((a, b) => (b.v < a.v ? b : a));
  const day = (i: number) => weekdayLabel(new Date(2024, 0, 1 + i, 12), 'long');
  return (
    <div>
      <div className="flex items-center justify-between gap-2 mb-2">
        <SectionEyebrow icon={CalendarCheck}>{t('home.yourWeek')}</SectionEyebrow>
        <span className="hidden sm:inline text-[11px] text-pn-muted">{t('home.yourWeekHint')}</span>
      </div>
      <div className="rounded-lg border border-divider bg-surface-2 p-3 space-y-2">
        <WeekdayChart values={values} format={(v) => formatNumber(v, 1)} />
        <p className="text-sm text-pn">{t('home.weekLine', { best: day(best.i), bestAvg: formatNumber(best.v, 1), worst: day(worst.i), worstAvg: formatNumber(worst.v, 1) })}</p>
      </div>
    </div>
  );
}

/** How many rows each side of "What stands out" shows a Pro account. */
const SIDE_MAX = 3;
/** How many tracker pills the overview card shows after the days logged, and which come first. */
const PILL_MAX = 6;
const PILL_ORDER = ['sleepHours', 'energy', 'steps', 'caffeine', 'emotions', 'water', 'focus', 'pain', 'social'];
/** Days logged before the weekday chart is drawn: a week of each weekday at least. */
const WEEK_MIN_DAYS = 14;

/**
 * What goes with a better mood and what with a worse one, same day or next:
 * the glyph, a short name with how sure it is, and a bar from the middle;
 * the full comparison one tap away.
 */
function StandsOut({ model, unlocked, isPro, onOpen, onOpenUpgrade }: {
  model: WellnessModel;
  unlocked: boolean;
  isPro: boolean;
  onOpen: (d: TrackerDescriptor) => void;
  onOpenUpgrade?: () => void;
}) {
  const { t } = useTranslation('stats');
  const mood = model.byId('mood');
  const rows = useMemo(() => {
    if (!mood) return [] as CompareResult[];
    const seen = new Set<string>();
    const moodSeries = model.seriesOf(mood);
    // A tracker that only restates the mood (a day rating, a stress scale, the
    // emotions felt) would fill the list with the obvious.
    const echoes = new Set(model.registry.filter((d) => d.id === 'emotions' || echoesOutcome(model.seriesOf(d), moodSeries)).map((d) => d.id));
    return ([0, 1] as const)
      .flatMap((lag) => compareAll(model.entries, model.registry, mood, model.range, lag))
      .filter((r) => qualifiesForInsight(r) && !echoes.has(r.trackerId))
      .sort((a, b) => Math.abs(b.delta ?? 0) - Math.abs(a.delta ?? 0))
      // One row per tracker and tag: the stronger of same day and next day.
      .filter((r) => {
        const key = `${r.trackerId}:${r.tag ?? ''}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });
  }, [model, mood]);
  if (!mood || rows.length === 0) return null;
  // A free account sees the strongest row; the rest wait behind one locked line.
  const lifts = rows.filter((r) => (r.delta ?? 0) > 0).slice(0, SIDE_MAX);
  const drags = rows.filter((r) => (r.delta ?? 0) < 0).slice(0, SIDE_MAX);
  const free = rows[0]!;
  const shownLifts = unlocked ? lifts : lifts.filter((r) => r === free);
  const shownDrags = unlocked ? drags : drags.filter((r) => r === free);
  const hidden = lifts.length + drags.length - shownLifts.length - shownDrags.length;
  // One scale for both lists, so a longer bar is a bigger difference.
  const scale = Math.max(1, ...[...shownLifts, ...shownDrags].map((r) => Math.abs(r.delta ?? 0)));

  const row = (r: CompareResult) => {
    const d = model.byId(r.trackerId);
    if (!d) return null;
    const label = (
      <>
        {standoutLabel(r, d, t)}
        {r.lag === 1 && <span className="ms-1.5 text-[11px] text-pn-muted">{t('home.nextDay')}</span>}
      </>
    );
    return (
      <EffectBarRow
        key={`${r.trackerId}:${r.tag ?? ''}`}
        d={d}
        label={label}
        sub={t('home.daysSplit', { a: r.a.n, b: r.b.n })}
        delta={r.delta ?? 0}
        sure={<SureDots r={r} />}
        share={Math.abs(r.delta ?? 0) / scale}
        onOpen={() => onOpen(d)}
      />
    );
  };
  const group = (label: string, icon: typeof Sparkle, list: CompareResult[]) => list.length > 0 && (
    <div>
      <SectionEyebrow className="mb-2" icon={icon}>{label}</SectionEyebrow>
      <div className="@container rounded-lg border border-divider bg-surface-2 px-3 divide-y divide-divider">{list.map(row)}</div>
    </div>
  );

  return (
    <div data-setting="stats.patterns" className="space-y-4">
      {group(t('home.lifts'), Sparkle, shownLifts)}
      {group(t('home.drags'), SmileySad, shownDrags)}
      {hidden > 0 && (
        <button type="button" onClick={onOpenUpgrade} className="w-full flex items-center gap-2 text-start text-xs text-pn-muted hover:text-pn">
          {!isPro && <ProMark />}
          {t('wellness.patterns.insightsLocked', { count: hidden })}
        </button>
      )}
      <p className="text-[11px] text-pn-muted">{t('home.footnoteShort')}</p>
    </div>
  );
}

/** The series from its first day with a value, so a short log does not draw as a mostly empty line. */
/** The span from the first to the last logged day, so a card's small chart fills its box; null under two logged days. */
function loggedSpan(series: DaySeries): DaySeries | null {
  const logged = (p: DaySeries['points'][number]) => p.value !== undefined && !(Array.isArray(p.value) && p.value.length === 0);
  const first = series.points.findIndex(logged);
  let last = series.points.length - 1;
  while (last > first && !logged(series.points[last]!)) last--;
  if (first < 0 || first === last) return null;
  const points = series.points.slice(first, last + 1);
  return { from: points[0]!.date, to: points[points.length - 1]!.date, points };
}

/** One card per tracker with data in the range, mood first, two to a row where there is room; stopped ones fold away. */
function TrackerRows({ model, onOpen }: { model: WellnessModel; onOpen: (d: TrackerDescriptor) => void }) {
  const { t } = useTranslation('stats');
  const weekly = model.rangeDays > 182;
  const rows = useMemo(() => {
    const all = model.registry
      .map((d) => ({ d, series: model.seriesOf(d) }))
      .filter(({ series }) => hasData(series))
      .sort((a, b) => (a.d.id === 'mood' ? -1 : b.d.id === 'mood' ? 1 : 0));
    return { live: all.filter(({ d }) => visibleInUi(d)), stopped: all.filter(({ d }) => !visibleInUi(d)) };
  }, [model]);
  // A card's number, short enough for a half-width card: a yes or no as "10 of 29".
  const cardValue = (d: TrackerDescriptor, series: DaySeries) => {
    const a = aggregate(series, d);
    if (a.kind === 'yesno') return t('home.yesOf', { yes: a.yes, total: a.yes + a.no });
    return cardNumbers(d, series, t).headline;
  };
  const card = ({ d, series }: { d: TrackerDescriptor; series: DaySeries }) => {
    const { sub } = cardNumbers(d, series, t);
    const headline = cardValue(d, series);
    const span = loggedSpan(series);
    const raw = changeOf(model, d, series);
    // A change that rounds to nothing is not shown.
    const delta = raw !== null && Math.abs(raw) >= (d.unit === 'steps' || d.unit === 'bpm' ? 0.5 : 0.05) ? raw : null;
    return (
      <div key={d.id} className="@container min-w-0 rounded-lg border border-divider bg-surface-2 hover:border-pn-muted transition-colors">
      <button type="button" onClick={() => onOpen(d)} className="w-full flex items-center gap-2.5 px-3 py-2.5 text-start min-w-0">
        <TrackerTile d={d} />
        <span className="flex-1 min-w-0">
          <span className="block text-sm text-pn truncate">{trackerName(d, t)}</span>
          <span className="block text-[11px] text-pn-muted truncate">{sub}</span>
        </span>
        {span && (
          <span aria-hidden="true" className="hidden @[17rem]:block w-14 shrink-0">
            <TrackerChart spec={chartSpecFor(d, span, weekly)} height={22} ariaLabel={`${trackerName(d, t)}: ${headline}`} />
          </span>
        )}
        <span className="shrink-0 text-end max-w-[35%]">
          <span className="block text-sm font-semibold tabular-nums truncate">{headline}</span>
          {delta !== null && <Change d={d} delta={delta} />}
        </span>
      </button>
      </div>
    );
  };
  if (rows.live.length === 0 && rows.stopped.length === 0) return null;
  return (
    <div data-setting="stats.wellness" className="@container">
      <div className="flex items-center justify-between mb-2">
        <SectionEyebrow icon={Pulse}>{t('home.trackers')}</SectionEyebrow>
        <span className="text-[11px] text-pn-muted">{t('home.tapHint')}</span>
      </div>
      {rows.live.length > 0 && <div className="grid @xl:grid-cols-2 gap-2">{rows.live.map(card)}</div>}
      {rows.stopped.length > 0 && (
        <details className="mt-2">
          <summary className="text-[11px] text-pn-muted cursor-pointer">{t('wellness.trackers.stoppedChip', { count: rows.stopped.length })}</summary>
          <div className="grid @xl:grid-cols-2 gap-2 mt-2">{rows.stopped.map(card)}</div>
        </details>
      )}
    </div>
  );
}

/**
 * The statistics of one tracker switch to every other tracker with data,
 * with its glyph and number, without going back to the list.
 */
function TrackerSwitcher({ model, current, onPick }: { model: WellnessModel; current: TrackerDescriptor; onPick: (id: string) => void }) {
  const { t } = useTranslation('stats');
  const items = useMemo<SwitcherItem[]>(() => model.registry
    .filter((d) => d.kind !== 'medication' && visibleInUi(d))
    .map((d) => ({ d, series: model.seriesOf(d) }))
    .filter(({ series }) => hasData(series))
    .sort((a, b) => (a.d.id === 'mood' ? -1 : b.d.id === 'mood' ? 1 : 0))
    .map(({ d, series }) => ({
      id: d.id,
      name: trackerName(d, t),
      tile: (size: number) => <TrackerTile d={d} size={size} />,
      detail: cardNumbers(d, series, t).headline,
    })), [model, t]);
  return <ItemSwitcher items={items} currentId={current.id} label={t('home.trackers')} onPick={onPick} />;
}

