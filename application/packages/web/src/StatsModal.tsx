import { useMemo, useState, useCallback, useEffect } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import { Heartbeat, PencilSimple, SquaresFour, X } from './icons';
import type { LocalNote } from './db';
import { computeStats } from './stats';
import { countWords } from './wordCountUtils';
import { toLocalIso } from './notesViewUtils';
import { computeTrackerStats } from './trackerStats';
import type { MedicationTemplate, TrackerSettings } from './trackerTypes';
import { WellnessTab } from './stats/WellnessTab';
import { OverviewTab } from './stats/OverviewTab';
import { moodColor } from './stats/wellnessModel';
import { useEscapeToClose } from './useEscapeToClose';
import { SectionEyebrow, SettingsTabStrip, settingsTabClass } from './settingsUI';
import { intlLocale } from './languages';
import { formatDay, weekdayLabel } from './intlFormat';
import { milestoneLabel, milestoneProgress } from './milestones';

type Props = {
  notes: LocalNote[];
  /** The view's lock predicate: the wellness readers leave out a journal
   *  whose gate is closed, and count it again once the gate opens. */
  isNoteLocked: (n: LocalNote) => boolean;
  medications: MedicationTemplate[];
  isPro: boolean;
  onOpenUpgrade?: () => void;
  onClose: () => void;
  /** Current week's reflection text (from Monday journal entry). */
  weekReflection?: string;
  /** Save reflection to the Monday journal entry. */
  onWeekReflectionChange?: (text: string) => void;
  /** Render inline as a settings pane (no overlay, no own header/footer/escape). */
  embedded?: boolean;
  /** Which tab to open on. Defaults to Overview. */
  initialTab?: Tab;
  trackerSettings: TrackerSettings;
  /** Opens the journal entry of a day picked on a chart; absent in the modal path. */
  onOpenDay?: (date: string) => void;
  /** Items created in the app, the honest count behind the notes milestones. */
  notesCreated: number;
  /** When the account was first seen; null on an account older than the stamp. */
  firstSeenAt: string | null;
};

export type Tab = 'overview' | 'writing' | 'wellness';

/**
 * The Statistics pane: Overview (the landing, writing and wellness on one
 * screen), Writing (heatmap and streaks) and Wellness (tracker analytics).
 * Spec: ops/docs/plans/wellness-statistics.md (sections 3, 20)
 */
export function StatsModal({ notes, isNoteLocked, onClose, medications, isPro, onOpenUpgrade, weekReflection, onWeekReflectionChange, embedded = false, initialTab = 'overview', notesCreated, firstSeenAt, trackerSettings, onOpenDay }: Props) {
  const { t } = useTranslation('stats');
  const { t: tc } = useTranslation('common');
  useEscapeToClose(onClose, !embedded);
  const [tab, setTab] = useState<Tab>(initialTab);
  const stats = useMemo(() => computeStats(notes), [notes]);
  const tStats = useMemo(() => computeTrackerStats(notes, medications, isNoteLocked), [notes, medications, isNoteLocked]);

  return (
    <div
      className={embedded ? 'contents' : 'fixed inset-0 bg-black/50 dark:bg-black/70 flex items-center justify-center p-4 sm:p-6 z-50'}
      onClick={embedded ? undefined : onClose}
    >
      <div
        className={
          embedded
            ? 'flex-1 min-h-0 overflow-hidden flex flex-col text-pn'
            : 'bg-surface-2 border border-divider text-pn rounded-lg max-w-2xl w-full max-h-[90vh] overflow-hidden flex flex-col'
        }
        onClick={(e) => e.stopPropagation()}
      >
        {!embedded && (
          <div className="flex items-center justify-between px-6 py-4 border-b border-divider">
            <h2 className="text-lg font-semibold">{t('title')}</h2>
            <button
              onClick={onClose}
              className="text-pn-muted hover:text-pn transition p-1 -m-1"
              aria-label={tc('actions.close')}
            >
              <X size={18} />
            </button>
          </div>
        )}

        {/* Tabs */}
        <SettingsTabStrip className="shrink-0 px-4 sm:px-6 pt-2">
          <button type="button" data-setting="stats.overview" aria-pressed={tab === 'overview'} className={settingsTabClass(tab === 'overview')} onClick={() => setTab('overview')}>
            <SquaresFour aria-hidden="true" />
            <span>{t('tabs.overview')}</span>
          </button>
          <button type="button" data-setting="stats.writing" aria-pressed={tab === 'writing'} className={settingsTabClass(tab === 'writing')} onClick={() => setTab('writing')}>
            <PencilSimple aria-hidden="true" />
            <span>{t('tabs.writing')}</span>
          </button>
          <button type="button" data-setting="stats.wellness" aria-pressed={tab === 'wellness'} className={settingsTabClass(tab === 'wellness')} onClick={() => setTab('wellness')}>
            <Heartbeat aria-hidden="true" />
            <span>{t('tabs.wellness')}</span>
          </button>
        </SettingsTabStrip>

        <div className="flex-1 overflow-y-auto p-6 [scrollbar-width:none] [&::-webkit-scrollbar]:hidden space-y-6">
          {tab === 'overview' && (
            <OverviewTab
              notes={notes}
              stats={stats}
              isNoteLocked={isNoteLocked}
              trackerSettings={trackerSettings}
              medications={medications}
              isPro={isPro}
              notesCreated={notesCreated}
              firstSeenAt={firstSeenAt}
              onOpenUpgrade={onOpenUpgrade}
              onOpenTab={setTab}
            />
          )}
          {tab === 'writing' && (
            <WritingTab stats={stats} moodHeatmap={tStats.moodHeatmap} notesCreated={notesCreated} firstSeenAt={firstSeenAt} />
          )}
          {tab === 'wellness' && (
            <WellnessTab
              notes={notes}
              isNoteLocked={isNoteLocked}
              trackerSettings={trackerSettings}
              medications={medications}
              isPro={isPro}
              onOpenUpgrade={onOpenUpgrade}
              weekReflection={weekReflection}
              onWeekReflectionChange={onWeekReflectionChange}
              onOpenDay={onOpenDay}
            />
          )}
        </div>

        {!embedded && (
          <div className="flex justify-end px-6 py-3 border-t border-divider">
            <button
              onClick={onClose}
              className="rounded-md border border-divider px-4 py-2 text-sm transition hover:bg-surface-1"
            >
              {tc('actions.close')}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

// ------------------------------------------------------------------
// Writing tab (existing content)
// ------------------------------------------------------------------

type RangeId = '7d' | '14d' | '30d' | '3mo' | '6mo' | '12mo' | 'all';

// Short ranges render as a daily bar chart; long ranges as the contribution
// heatmap (a weekday grid only earns its keep across many week-columns).
const RANGES: { id: RangeId; days?: number; weeks?: number; form: 'bars' | 'heatmap' }[] = [
  { id: '7d', days: 7, form: 'bars' },
  { id: '14d', days: 14, form: 'bars' },
  { id: '30d', days: 30, form: 'bars' },
  { id: '3mo', days: 91, form: 'bars' },
  { id: '6mo', weeks: 26, form: 'heatmap' },
  { id: '12mo', weeks: 52, form: 'heatmap' },
  // `all` spans the account's age, in one grid per year of 52 week-columns.
  { id: 'all', form: 'heatmap' },
];

const WEEKS_PER_ROW = 52;

// Per-device view preference; not synced (a phone and a 27" monitor want
// different ranges).
const STATS_RANGE_KEY = 'pn-stats-range';

// Default to the smallest preset whose window covers the account's age, so a
// new account opens on a dense view instead of a near-empty 12-month grid.
function adaptiveRange(ageDays: number): RangeId {
  if (ageDays <= 7) return '7d';
  if (ageDays <= 14) return '14d';
  if (ageDays <= 30) return '30d';
  if (ageDays <= 91) return '3mo';
  if (ageDays <= 182) return '6mo';
  return '12mo';
}

type DayCell = { date: string; count: number };

// Last n calendar days ending today (oldest first).
function barDays(heatmap: Record<string, number>, n: number): DayCell[] {
  const out: DayCell[] = [];
  const today = new Date();
  for (let i = n - 1; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    // Local, not UTC. The heatmap is keyed by `trackers.journalDate`,
    // itself a LOCAL ISO date, so a toISOString() key looked up the wrong
    // day for every user whose offset pushes local midnight across UTC's.
    const key = toLocalIso(d);
    out.push({ date: key, count: heatmap[key] ?? 0 });
  }
  return out;
}

// Week-aligned grid of the last `weeks` weeks, ending at the current week.
function heatmapDays(heatmap: Record<string, number>, weeks: number): DayCell[] {
  const out: DayCell[] = [];
  const today = new Date();
  const dow = today.getDay();
  const endCursor = new Date(today);
  endCursor.setDate(endCursor.getDate() + (6 - dow));
  for (let i = weeks * 7 - 1; i >= 0; i--) {
    const d = new Date(endCursor);
    d.setDate(d.getDate() - i);
    const key = toLocalIso(d);
    out.push({ date: key, count: heatmap[key] ?? 0 });
  }
  return out;
}

function WritingTab({
  stats,
  moodHeatmap,
  notesCreated,
  firstSeenAt,
}: {
  stats: ReturnType<typeof computeStats>;
  moodHeatmap: Record<string, number>;
  notesCreated: number;
  firstSeenAt: string | null;
}) {
  const { t } = useTranslation('stats');
  const { t: tc } = useTranslation('common');
  const milestones = useMemo(
    () => milestoneProgress(stats, notesCreated, firstSeenAt),
    [stats, notesCreated, firstSeenAt],
  );
  const reachedCount = milestones.reduce((n, row) => n + row.reached.length, 0);
  const fmt = (n: number) => n.toLocaleString(intlLocale());
  const [heatmapMode, setHeatmapMode] = useState<'activity' | 'mood'>('activity');
  const hasMoodData = Object.keys(moodHeatmap).length > 0;

  const [rangeId, setRangeId] = useState<RangeId>(() => {
    try {
      const saved = localStorage.getItem(STATS_RANGE_KEY);
      if (saved && RANGES.some((r) => r.id === saved)) return saved as RangeId;
    } catch { /* localStorage unavailable */ }
    return adaptiveRange(stats.ageDays);
  });
  useEffect(() => {
    try { localStorage.setItem(STATS_RANGE_KEY, rangeId); } catch { /* ignore */ }
  }, [rangeId]);

  const range = RANGES.find((r) => r.id === rangeId)!;
  const days = useMemo(
    () =>
      range.form === 'bars'
        ? barDays(stats.heatmap, range.days!)
        : heatmapDays(stats.heatmap, range.weeks ?? Math.max(WEEKS_PER_ROW, Math.ceil(stats.ageDays / 7) + 1)),
    [stats.heatmap, stats.ageDays, range],
  );
  const maxCount = Math.max(1, ...days.map((d) => d.count));
  // One grid per 52 weeks, oldest first; the first grid is the partial one.
  const heatmapRows = useMemo(() => {
    const per = WEEKS_PER_ROW * 7;
    const rows: DayCell[][] = [];
    for (let end = days.length; end > 0; end -= per) rows.unshift(days.slice(Math.max(0, end - per), end));
    return rows;
  }, [days]);

  return (
    <>
      <div className="grid grid-cols-[repeat(auto-fit,minmax(9rem,1fr))] gap-4">
        <Stat label={t('writing.notes')} value={stats.totalNotes} />
        <Stat label={t('writing.words')} value={stats.totalWords.toLocaleString(intlLocale())} />
        <Stat label={t('writing.tags')} value={stats.uniqueTags} />
        <Stat setting="stats.streak" label={t('writing.currentStreak')} value={t('writing.streakValue', { count: stats.currentStreak })} />
        <Stat label={t('writing.longestStreak')} value={t('writing.streakValue', { count: stats.longestStreak })} />
      </div>
      <div>
        <div className="flex items-center justify-between mb-2 gap-2">
          <select
            value={rangeId}
            onChange={(e) => setRangeId(e.target.value as RangeId)}
            aria-label={t('writing.timeRangeAria')}
            className="text-xs font-medium text-pn-muted bg-transparent border border-divider rounded px-2 py-1 cursor-pointer focus:outline-none focus:ring-1 focus:ring-emerald-500"
          >
            {RANGES.map((r) => (
              <option key={r.id} value={r.id} className="bg-surface-2">
                {t(`range.${r.id}`)}
              </option>
            ))}
          </select>
          {hasMoodData && (
            <div className="flex gap-1">
              <button
                type="button"
                onClick={() => setHeatmapMode('activity')}
                className={`px-2 py-0.5 rounded text-[10px] font-medium transition-colors ${
                  heatmapMode === 'activity'
                    ? 'bg-emerald-100 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-300'
                    : 'text-pn-soft hover:text-pn'
                }`}
              >
                {t('writing.modeActivity')}
              </button>
              <button
                type="button"
                onClick={() => setHeatmapMode('mood')}
                className={`px-2 py-0.5 rounded text-[10px] font-medium transition-colors ${
                  heatmapMode === 'mood'
                    ? 'bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-300'
                    : 'text-pn-soft hover:text-pn'
                }`}
              >
                {t('writing.modeMood')}
              </button>
            </div>
          )}
        </div>

        {range.form === 'bars' ? (
          <>
            <div className="flex items-end h-24" style={{ gap: (range.days ?? 0) > 30 ? '1px' : '3px' }}>
              {days.map((d) => {
                if (heatmapMode === 'mood') {
                  const mood = moodHeatmap[d.date];
                  const h = mood != null ? Math.max(8, (mood / 10) * 100) : 4;
                  return (
                    <div
                      key={d.date}
                      title={mood != null ? t('writing.tooltipMood', { date: formatDay(d.date, 'date'), mood }) : t('writing.tooltipNoMood', { date: formatDay(d.date, 'date') })}
                      className={`flex-1 rounded-[2px] ${mood == null ? 'bg-track' : ''}`}
                      style={{ height: `${h}%`, ...(mood != null ? { backgroundColor: moodColor(mood), opacity: 0.85 } : {}) }}
                    />
                  );
                }
                const h = d.count > 0 ? Math.max(8, (d.count / maxCount) * 100) : 4;
                return (
                  <div
                    key={d.date}
                    title={t('writing.tooltipEdits', { date: formatDay(d.date, 'date'), count: d.count })}
                    className={`flex-1 rounded-[2px] ${d.count > 0 ? 'bg-emerald-500 dark:bg-emerald-400' : 'bg-track'}`}
                    style={{ height: `${h}%` }}
                  />
                );
              })}
            </div>
            {range.days != null && range.days <= 14 && (
              <div className="flex gap-[3px] mt-1">
                {days.map((d) => (
                  <div key={d.date} className="flex-1 text-center text-[9px] text-pn-muted">
                    {weekdayLabel(new Date(d.date), 'narrow')}
                  </div>
                ))}
              </div>
            )}
          </>
        ) : (
          <div className="space-y-2">
            {heatmapRows.map((row) => (
              <div
                key={row[0]!.date}
                className="grid grid-rows-7 grid-flow-col gap-[2px] w-full"
                style={{ gridTemplateColumns: `repeat(${WEEKS_PER_ROW}, minmax(0, 1fr))` }}
              >
                {Array.from({ length: WEEKS_PER_ROW * 7 - row.length }, (_, i) => <div key={`pad-${i}`} />)}
                {row.map((d) => {
                  if (heatmapMode === 'mood') {
                    const mood = moodHeatmap[d.date];
                    return (
                      <div
                        key={d.date}
                        title={mood != null ? t('writing.tooltipMood', { date: formatDay(d.date, 'date'), mood }) : t('writing.tooltipNoMood', { date: formatDay(d.date, 'date') })}
                        className={`aspect-square rounded-[2px] ${mood == null ? 'bg-track' : ''}`}
                        style={mood != null ? { backgroundColor: moodColor(mood), opacity: 0.8 } : undefined}
                      />
                    );
                  }
                  return (
                    <div
                      key={d.date}
                      title={t('writing.tooltipEdits', { date: formatDay(d.date, 'date'), count: d.count })}
                      className={`aspect-square rounded-[2px] ${cellColor(d.count)}`}
                    />
                  );
                })}
              </div>
            ))}
          </div>
        )}
      </div>
      <div data-setting="stats.milestones">
        <SectionEyebrow className="mb-2">{t('milestones.heading')}</SectionEyebrow>
        <div className="rounded-lg border border-divider bg-track p-4 space-y-3">
          {milestones.map((row) => {
            const pct = Math.round(row.progress * 100);
            return (
              <div key={row.family}>
                <div className="flex items-baseline justify-between gap-3 text-xs">
                  <span className="text-pn-soft truncate">
                    {row.next === null
                      ? t('milestones.allReached', { label: milestoneLabel(row.family, row.reached[row.reached.length - 1]!) })
                      : t('milestones.next', { label: milestoneLabel(row.family, row.next) })}
                  </span>
                  {row.next !== null && (
                    <span className="text-pn-muted tabular-nums whitespace-nowrap">
                      {t('milestones.ofTarget', { current: fmt(row.current), target: fmt(row.next) })}
                    </span>
                  )}
                </div>
                <div
                  className="mt-1.5 h-1.5 rounded-full bg-surface-0 overflow-hidden"
                  role="progressbar"
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={pct}
                >
                  <div className="h-full rounded-full bg-accent-fill" style={{ width: `${pct}%` }} />
                </div>
              </div>
            );
          })}
          <p className="text-[11px] text-pn-muted">
            {reachedCount > 0 && <>{t('milestones.reached', { count: reachedCount })} </>}
            {t('milestones.source')}
          </p>
        </div>
      </div>
      {stats.longestNote && (
        <div className="text-sm text-pn-muted">
          <Trans
            i18nKey="stats:writing.longestNote"
            values={{ title: stats.longestNote.title || tc('state.untitled'), count: countWords(stats.longestNote.body) }}
            components={{ name: <span className="text-pn-soft" /> }}
          />
        </div>
      )}
    </>
  );
}

// ------------------------------------------------------------------
// Shared helpers
// ------------------------------------------------------------------

function cellColor(count: number): string {
  if (count === 0) return 'bg-track';
  if (count === 1) return 'bg-emerald-200 dark:bg-emerald-700';
  if (count < 4) return 'bg-emerald-400 dark:bg-emerald-600';
  if (count < 8) return 'bg-emerald-500';
  return 'bg-emerald-600 dark:bg-emerald-300';
}

function Stat({ label, value, setting }: { label: string; value: number | string; setting?: string }) {
  return (
    <div data-setting={setting}>
      <div className="text-2xl font-semibold tabular-nums whitespace-nowrap">{value}</div>
      <SectionEyebrow className="mt-0.5">
        {label}
      </SectionEyebrow>
    </div>
  );
}
