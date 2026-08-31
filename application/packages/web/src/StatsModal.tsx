import { useMemo, useState, useCallback, useEffect } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import { X } from './icons';
import type { LocalNote } from './db';
import { computeStats } from './stats';
import { countWords } from './wordCountUtils';
import { toLocalIso } from './notesViewUtils';
import { computeTrackerStats, exportTrackerJSON, generateAIPrompt, generateDoctorReport, type TrackerStats, type PatternInsight } from './trackerStats';
import type { MedicationTemplate } from './trackerTypes';
import { useEscapeToClose } from './useEscapeToClose';
import { MOOD_ANCHORS } from './trackerTypes';
import { saveBlob } from './saveFile';
import { detectPlatform } from './devices';
import { proUnlocked } from './demo';
import { SectionEyebrow, SETTINGS_EYEBROW } from './settingsUI';
import { intlLocale } from './languages';
import { HelpChip } from './HelpChip';

type Props = {
  notes: LocalNote[];
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
};

type Tab = 'writing' | 'wellness';

/**
 * Stats overlay with two tabs: Writing (heatmap + streaks) and
 * Wellness (tracker analytics).
 */
export function StatsModal({ notes, onClose, medications, isPro, onOpenUpgrade, weekReflection, onWeekReflectionChange, embedded = false }: Props) {
  const { t } = useTranslation('stats');
  const { t: tc } = useTranslation('common');
  useEscapeToClose(onClose, !embedded);
  const [tab, setTab] = useState<Tab>('writing');
  const stats = useMemo(() => computeStats(notes), [notes]);
  const tStats = useMemo(() => computeTrackerStats(notes, medications), [notes, medications]);

  const tabClass = (t: Tab) =>
    `px-4 py-2 text-sm font-medium rounded-t-md transition-colors ${
      tab === t
        ? 'text-accent border-b-2 border-accent'
        : 'text-pn-soft hover:text-pn'
    }`;

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
        <div className="flex gap-1 px-6 pt-2 border-b border-divider">
          <button type="button" className={tabClass('writing')} onClick={() => setTab('writing')}>
            {t('tabs.writing')}
          </button>
          <button type="button" className={tabClass('wellness')} onClick={() => setTab('wellness')}>
            {t('tabs.wellness')}
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-6 [scrollbar-width:none] [&::-webkit-scrollbar]:hidden space-y-6">
          {tab === 'writing' ? (
            <WritingTab stats={stats} moodHeatmap={tStats.moodHeatmap} />
          ) : (
            <WellnessTab
              stats={tStats}
              notes={notes}
              medications={medications}
              isPro={isPro}
              onOpenUpgrade={onOpenUpgrade}
              weekReflection={weekReflection}
              onWeekReflectionChange={onWeekReflectionChange}
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

type RangeId = '7d' | '14d' | '30d' | '3mo' | '6mo' | '12mo';

// Short ranges render as a daily bar chart; long ranges as the contribution
// heatmap (a weekday grid only earns its keep across many week-columns).
const RANGES: { id: RangeId; days?: number; weeks?: number; form: 'bars' | 'heatmap' }[] = [
  { id: '7d', days: 7, form: 'bars' },
  { id: '14d', days: 14, form: 'bars' },
  { id: '30d', days: 30, form: 'bars' },
  { id: '3mo', days: 91, form: 'bars' },
  { id: '6mo', weeks: 26, form: 'heatmap' },
  { id: '12mo', weeks: 52, form: 'heatmap' },
];

// Per-device view preference; not synced (a phone and a 27" monitor want
// different ranges).
const STATS_RANGE_KEY = 'pn-stats-range';
const WEEKDAY = ['S', 'M', 'T', 'W', 'T', 'F', 'S'];

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
}: {
  stats: ReturnType<typeof computeStats>;
  moodHeatmap: Record<string, number>;
}) {
  const { t } = useTranslation('stats');
  const { t: tc } = useTranslation('common');
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
        : heatmapDays(stats.heatmap, range.weeks!),
    [stats.heatmap, range],
  );
  const maxCount = Math.max(1, ...days.map((d) => d.count));

  return (
    <>
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
        <Stat label={t('writing.notes')} value={stats.totalNotes} />
        <Stat label={t('writing.words')} value={stats.totalWords.toLocaleString(intlLocale())} />
        <Stat label={t('writing.tags')} value={stats.uniqueTags} />
        <Stat label={t('writing.currentStreak')} value={t('writing.streakValue', { count: stats.currentStreak })} />
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
                      title={mood != null ? t('writing.tooltipMood', { date: d.date, mood }) : t('writing.tooltipNoMood', { date: d.date })}
                      className={`flex-1 rounded-[2px] ${mood == null ? 'bg-track' : ''}`}
                      style={{ height: `${h}%`, ...(mood != null ? { backgroundColor: moodColor(mood), opacity: 0.85 } : {}) }}
                    />
                  );
                }
                const h = d.count > 0 ? Math.max(8, (d.count / maxCount) * 100) : 4;
                return (
                  <div
                    key={d.date}
                    title={t('writing.tooltipEdits', { date: d.date, count: d.count })}
                    className={`flex-1 rounded-[2px] ${d.count > 0 ? 'bg-emerald-500 dark:bg-emerald-400' : 'bg-track'}`}
                    style={{ height: `${h}%` }}
                  />
                );
              })}
            </div>
            {range.days != null && range.days <= 14 && (
              <div className="flex gap-[3px] mt-1">
                {days.map((d) => (
                  <div key={d.date} className="flex-1 text-center text-[9px] text-pn-muted/75">
                    {WEEKDAY[new Date(d.date).getUTCDay()]}
                  </div>
                ))}
              </div>
            )}
          </>
        ) : (
          <div
            className="grid grid-rows-7 grid-flow-col gap-[2px] w-full"
            style={{ gridAutoColumns: 'minmax(0, 1fr)' }}
          >
            {days.map((d) => {
              if (heatmapMode === 'mood') {
                const mood = moodHeatmap[d.date];
                return (
                  <div
                    key={d.date}
                    title={mood != null ? t('writing.tooltipMood', { date: d.date, mood }) : t('writing.tooltipNoMood', { date: d.date })}
                    className={`aspect-square rounded-[2px] ${mood == null ? 'bg-track' : ''}`}
                    style={mood != null ? { backgroundColor: moodColor(mood), opacity: 0.8 } : undefined}
                  />
                );
              }
              return (
                <div
                  key={d.date}
                  title={t('writing.tooltipEdits', { date: d.date, count: d.count })}
                  className={`aspect-square rounded-[2px] ${cellColor(d.count)}`}
                />
              );
            })}
          </div>
        )}
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
// Wellness tab (new)
// ------------------------------------------------------------------

type WellnessSubTab = 'overview' | 'sleep_activity' | 'medication' | 'patterns';

function WellnessTab({
  stats,
  notes,
  medications,
  isPro,
  onOpenUpgrade,
  weekReflection,
  onWeekReflectionChange,
}: {
  stats: TrackerStats;
  notes: LocalNote[];
  medications: MedicationTemplate[];
  isPro: boolean;
  onOpenUpgrade?: () => void;
  weekReflection?: string;
  onWeekReflectionChange?: (text: string) => void;
}) {
  const { t } = useTranslation('stats');
  const [sub, setSub] = useState<WellnessSubTab>('overview');
  const [copied, setCopied] = useState(false);
  const [exportRange, setExportRange] = useState<'all' | '30' | '90' | '7'>('all');
  // Insights, week in review, the doctor report, the AI prompt and the
  // medication timeline are Pro, and all of them run entirely on local
  // data - so the public demo unlocks them. The amber PRO badges keep
  // keying off isPro so they stay marked as Pro features.
  const unlocked = proUnlocked(isPro);

  const handleExportJSON = useCallback(() => {
    const from = exportRange === '7' ? daysAgoStr(6)
      : exportRange === '30' ? daysAgoStr(29)
      : exportRange === '90' ? daysAgoStr(89)
      : undefined;
    const json = exportTrackerJSON(notes, from);
    const blob = new Blob([json], { type: 'application/json' });
    void saveBlob(blob, `privacy-notes-wellness-${new Date().toISOString().slice(0, 10)}.json`);
  }, [notes, exportRange]);

  const handleCopyAIPrompt = useCallback(() => {
    if (!unlocked) { onOpenUpgrade?.(); return; }
    const prompt = generateAIPrompt(stats, medications);
    void navigator.clipboard.writeText(prompt).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }, [unlocked, stats, medications, onOpenUpgrade]);

  if (stats.trackedDays === 0) {
    return (
      <div className="text-center py-12 text-pn-muted">
        <p className="text-sm">{t('wellness.empty.title')}</p>
        <p className="text-xs mt-1">{t('wellness.empty.hint')}</p>
      </div>
    );
  }

  const subTabClass = (t: WellnessSubTab) =>
    `px-3 py-1.5 text-[11px] font-medium rounded-md transition-colors whitespace-nowrap ${
      sub === t
        ? 'bg-accent/10 text-accent'
        : 'text-pn-soft hover:text-pn hover:bg-surface-1'
    }`;

  return (
    <>
      {/* Sub-tab bar */}
      <div className="flex gap-1 overflow-x-auto pb-1 -mt-1 [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
        <button type="button" className={subTabClass('overview')} onClick={() => setSub('overview')}>{t('wellness.subTabs.all')}</button>
        <button type="button" className={subTabClass('sleep_activity')} onClick={() => setSub('sleep_activity')}>{t('wellness.subTabs.sleepActivity')}</button>
        <button type="button" className={subTabClass('medication')} onClick={() => setSub('medication')}>{t('wellness.subTabs.medication')}</button>
        <button type="button" className={subTabClass('patterns')} onClick={() => setSub('patterns')}>{t('wellness.subTabs.patterns')}</button>
      </div>

      <HelpChip surface="wellness" className="pt-1" />

      {/* ── Overview sub-tab ─────────────────────────────── */}
      {sub === 'overview' && (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <Stat label={t('wellness.overview.daysTracked')} value={stats.trackedDays} />
            <Stat label={t('wellness.overview.avgMood')} value={stats.avgMood != null ? `${stats.avgMood}/10` : '-'} />
            <Stat label={t('wellness.overview.avgSleep')} value={stats.avgSleepHours != null ? `${stats.avgSleepHours}h` : '-'} />
            <Stat label={t('wellness.overview.medAdherence')} value={stats.medAdherence != null ? `${stats.medAdherence}%` : '-'} />
          </div>

          {/* Mood trend */}
          {stats.moodTrend.length > 0 && (
            <div>
              <SectionEyebrow className="mb-2">{t('wellness.overview.moodTrend')}</SectionEyebrow>
              <div className="flex items-end gap-[3px] h-24">
                {stats.moodTrend.slice(-30).map((d) => {
                  const pct = (d.mood / 10) * 100;
                  const anchor = MOOD_ANCHORS[d.mood];
                  return (
                    <div
                      key={d.date}
                      title={anchor ? t('wellness.overview.moodTrendTooltipAnchor', { date: d.date, mood: d.mood, anchor }) : t('wellness.overview.moodTrendTooltip', { date: d.date, mood: d.mood })}
                      className="flex-1 min-w-[4px] max-w-[16px] rounded-t transition-all"
                      style={{ height: `${pct}%`, backgroundColor: moodColor(d.mood) }}
                    />
                  );
                })}
              </div>
              <div className="flex justify-between text-[10px] text-pn-muted mt-1">
                <span>{stats.moodTrend.slice(-30)[0]?.date.slice(5)}</span>
                <span>{stats.moodTrend[stats.moodTrend.length - 1]?.date.slice(5)}</span>
              </div>
            </div>
          )}

          {/* Day-of-week mood */}
          {stats.dayOfWeekMood && (
            <div>
              <SectionEyebrow className="mb-2">{t('wellness.overview.moodByDayOfWeek')}</SectionEyebrow>
              <div className="flex items-end gap-2 h-20">
                {stats.dayOfWeekMood.map((d) => {
                  const pct = d.avg > 0 ? (d.avg / 10) * 100 : 0;
                  return (
                    <div key={d.day} className="flex-1 flex flex-col items-center gap-0.5">
                      <span className="text-[9px] text-pn-muted tabular-nums">{d.avg || ''}</span>
                      <div
                        className="w-full rounded-t"
                        style={{ height: `${pct}%`, backgroundColor: moodColor(d.avg), opacity: d.count > 0 ? 0.8 : 0.2 }}
                      />
                      <span className="text-[9px] text-pn-muted">{d.label}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Export */}
          <div className="border-t border-divider pt-4">
            <SectionEyebrow className="mb-3">{t('wellness.export.heading')}</SectionEyebrow>
            <div className="flex flex-wrap items-center gap-2">
              <select
                value={exportRange}
                onChange={(e) => setExportRange(e.target.value as typeof exportRange)}
                className="px-2 py-1.5 rounded-md text-xs border border-divider bg-surface-0 text-pn"
              >
                <option value="all">{t('wellness.export.allTime')}</option>
                <option value="90">{t('wellness.export.last90Days')}</option>
                <option value="30">{t('wellness.export.last30Days')}</option>
                <option value="7">{t('wellness.export.last7Days')}</option>
              </select>
              <button type="button" onClick={handleExportJSON} className="px-3 py-1.5 rounded-md text-xs font-medium border border-divider hover:bg-surface-1 transition-colors">
                {t('wellness.export.downloadJSON')}
              </button>
              <button
                type="button"
                onClick={async () => {
                  if (!unlocked) { onOpenUpgrade?.(); return; }
                  const html = generateDoctorReport(stats, medications);
                  if (detectPlatform() === 'web') {
                    const w = window.open('', '_blank');
                    if (w) { w.document.write(html); w.document.close(); }
                  } else {
                    // The webview can't open a print window; save the report as
                    // HTML the user can open and print in a real browser.
                    const blob = new Blob([html], { type: 'text/html' });
                    await saveBlob(blob, `privacy-notes-doctor-report-${new Date().toISOString().slice(0, 10)}.html`);
                  }
                }}
                className="inline-flex items-center gap-1 px-3 py-1.5 rounded-md text-xs font-medium border border-divider hover:bg-surface-1 transition-colors"
              >
                {t('wellness.export.doctorPDF')}
                {!isPro && <span className="inline-flex items-center px-1 py-0 rounded text-[8px] font-bold bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-300">{t('wellness.export.proBadge')}</span>}
              </button>
              <button
                type="button"
                onClick={handleCopyAIPrompt}
                className="inline-flex items-center gap-1 px-3 py-1.5 rounded-md text-xs font-medium bg-accent/10 text-accent hover:bg-accent/20 transition-colors"
              >
                {copied ? t('wellness.export.copied') : t('wellness.export.copyAIPrompt')}
                {!isPro && <span className="inline-flex items-center px-1 py-0 rounded text-[8px] font-bold bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-300">{t('wellness.export.proBadge')}</span>}
              </button>
            </div>
          </div>
        </>
      )}

      {/* ── Sleep & Activity sub-tab ─────────────────────── */}
      {sub === 'sleep_activity' && (
        <>
          {stats.sleepDistribution.some((s) => s.count > 0) && (
            <div>
              <SectionEyebrow className="mb-2">{t('wellness.sleepActivity.sleepQuality')}</SectionEyebrow>
              <div className="space-y-1">
                {stats.sleepDistribution.map((s) => {
                  const total = stats.sleepDistribution.reduce((a, b) => a + b.count, 0);
                  const pct = total > 0 ? (s.count / total) * 100 : 0;
                  return (
                    <div key={s.quality} className="flex items-center gap-2">
                      <span className="text-[11px] w-14 text-end text-pn-muted">{s.label}</span>
                      <div className="flex-1 h-4 bg-surface-0 rounded overflow-hidden">
                        <div className="h-full rounded transition-all" style={{ width: `${pct}%`, backgroundColor: '#7F77DD' }} />
                      </div>
                      <span className="text-[10px] text-pn-muted w-6 text-end">{s.count}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {stats.activityDistribution.some((a) => a.count > 0) && (
            <div>
              <SectionEyebrow className="mb-2">{t('wellness.sleepActivity.activity')}</SectionEyebrow>
              <div className="space-y-1">
                {stats.activityDistribution.map((a) => {
                  const total = stats.activityDistribution.reduce((s, b) => s + b.count, 0);
                  const pct = total > 0 ? (a.count / total) * 100 : 0;
                  return (
                    <div key={a.level} className="flex items-center gap-2">
                      <span className="text-[11px] w-14 text-end text-pn-muted">{a.label}</span>
                      <div className="flex-1 h-4 bg-surface-0 rounded overflow-hidden">
                        <div className="h-full rounded transition-all" style={{ width: `${pct}%`, backgroundColor: '#1D9E75' }} />
                      </div>
                      <span className="text-[10px] text-pn-muted w-6 text-end">{a.count}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Avg sleep hours stat if available */}
          {stats.avgSleepHours != null && (
            <div className="rounded-md bg-track border border-divider px-4 py-3 text-center">
              <div className="text-2xl font-semibold tabular-nums">{stats.avgSleepHours}h</div>
              <SectionEyebrow>{t('wellness.sleepActivity.avgSleepPerNight')}</SectionEyebrow>
            </div>
          )}
        </>
      )}

      {/* ── Medication sub-tab ───────────────────────────── */}
      {sub === 'medication' && (
        <>
          {stats.medBreakdown.length > 0 ? (
            <div>
              <SectionEyebrow className="mb-2">{t('wellness.medication.adherence')}</SectionEyebrow>
              <div className="space-y-1.5">
                {stats.medBreakdown.map((m) => (
                  <div key={m.id} className="flex items-center gap-2">
                    <span className="text-xs text-pn-soft flex-1 truncate">{m.name}</span>
                    <div className="w-24 h-3 bg-surface-0 rounded overflow-hidden">
                      <div
                        className="h-full rounded transition-all"
                        style={{
                          width: `${m.pct}%`,
                          backgroundColor: m.pct >= 80 ? '#1D9E75' : m.pct >= 50 ? '#BA7517' : '#D85A30',
                        }}
                      />
                    </div>
                    <span className="text-[11px] text-pn-muted w-12 text-end">{m.pct}%</span>
                  </div>
                ))}
              </div>
              {unlocked && medications.length > 0 && <MedTimeline medications={medications} />}
            </div>
          ) : (
            <div className="text-center py-8 text-pn-muted">
              <p className="text-sm">{t('wellness.medication.empty.title')}</p>
              <p className="text-xs mt-1">{t('wellness.medication.empty.hint')}</p>
            </div>
          )}
        </>
      )}

      {/* ── Patterns sub-tab ─────────────────────────────── */}
      {sub === 'patterns' && (
        <>
          {/* Emotion frequency */}
          {stats.emotionFrequency.length > 0 && (
            <div>
              <SectionEyebrow className="mb-2">{t('wellness.patterns.topEmotions')}</SectionEyebrow>
              <div className="flex flex-wrap gap-1.5">
                {stats.emotionFrequency.slice(0, 12).map((e) => (
                  <span key={e.key} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-surface-0 text-pn-soft">
                    {e.label}
                    <span className="text-pn-muted">{e.count}</span>
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Pattern insights (Pro) */}
          {stats.patterns.length > 0 && (
            <div>
              <div className="flex items-center gap-2 mb-2">
                <span className={SETTINGS_EYEBROW}>{t('wellness.patterns.insights')}</span>
                {!isPro && <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-bold bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-300">{t('wellness.patterns.proBadge')}</span>}
              </div>
              {unlocked ? (
                <div className="space-y-2">
                  {stats.patterns.map((p, i) => <PatternCard key={i} pattern={p} />)}
                </div>
              ) : (
                <button type="button" onClick={onOpenUpgrade} className="w-full rounded-lg border border-dashed border-divider p-3 text-xs text-pn-muted hover:text-pn hover:border-pn-muted transition-colors text-center">
                  {t('wellness.patterns.insightsLocked', { count: stats.patterns.length })}
                </button>
              )}
            </div>
          )}

          {/* Week in review (Pro) */}
          {stats.weekInReview && (
            <div>
              <div className="flex items-center gap-2 mb-2">
                <span className={SETTINGS_EYEBROW}>{t('wellness.patterns.weekInReview')}</span>
                {!isPro && <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-bold bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-300">{t('wellness.patterns.proBadge')}</span>}
              </div>
              {unlocked ? (
                <WeekCard week={stats.weekInReview} reflection={weekReflection} onReflectionChange={onWeekReflectionChange} />
              ) : (
                <button type="button" onClick={onOpenUpgrade} className="w-full rounded-lg border border-dashed border-divider p-4 text-sm text-pn-muted hover:text-pn hover:border-pn-muted transition-colors text-center">
                  {t('wellness.patterns.weekInReviewLocked')}
                </button>
              )}
            </div>
          )}
        </>
      )}
    </>
  );
}

// ------------------------------------------------------------------
// Pattern insight card
// ------------------------------------------------------------------

const PATTERN_ICONS: Record<string, string> = {
  correlation: '~',
  day_of_week: '#',
  medication: '+',
  streak: '*',
  trend: '^',
};

function PatternCard({ pattern }: { pattern: PatternInsight }) {
  return (
    <div className="flex items-start gap-2 rounded-md bg-track border border-divider px-3 py-2">
      <span className="text-xs font-mono text-accent mt-0.5">{PATTERN_ICONS[pattern.type] ?? '?'}</span>
      <span className="text-xs text-pn-soft leading-relaxed">{pattern.text}</span>
    </div>
  );
}

// ------------------------------------------------------------------
// Medication dosage timeline
// ------------------------------------------------------------------

function MedTimeline({ medications }: { medications: MedicationTemplate[] }) {
  const { t } = useTranslation('stats');
  const meds = medications.filter((m) => m.dosageHistory.length > 0 || m.startedAt);
  if (meds.length === 0) return null;

  return (
    <div className="mt-3 space-y-3">
      <SectionEyebrow>{t('wellness.medication.dosageTimeline')}</SectionEyebrow>
      {meds.map((med) => {
        // dosageHistory[0] is the dose the medication STARTED on, stamped
        // when it was created. `med.dosage` is the CURRENT one, so using
        // it here labelled the start date with a dose that only began
        // later. Templates predating the history fall back to it.
        const events: { date: string; label: string }[] = [
          {
            date: med.startedAt,
            label: t('wellness.medication.started', {
              dosage: med.dosageHistory[0]?.dosage || med.dosage || med.name,
            }),
          },
          ...med.dosageHistory.slice(1).map((h) => ({ date: h.changedAt, label: t('wellness.medication.changedTo', { dosage: h.dosage }) })),
        ];
        events.sort((a, b) => a.date.localeCompare(b.date));
        return (
          <div key={med.id} className="ps-2 border-s-2 border-divider space-y-1.5">
            <span className="text-xs font-medium text-pn-soft">{med.name}</span>
            {events.map((ev, i) => (
              <div key={i} className="flex items-center gap-2 ms-2">
                <div className="w-2 h-2 rounded-full bg-accent -ms-[13px]" />
                <span className="text-[10px] text-pn-muted tabular-nums w-20">{ev.date}</span>
                <span className="text-[11px] text-pn-muted">{ev.label}</span>
              </div>
            ))}
          </div>
        );
      })}
    </div>
  );
}

// ------------------------------------------------------------------
// Week-in-review card
// ------------------------------------------------------------------

function WeekCard({ week, reflection, onReflectionChange }: {
  week: NonNullable<TrackerStats['weekInReview']>;
  reflection?: string;
  onReflectionChange?: (text: string) => void;
}) {
  const { t } = useTranslation('stats');
  return (
    <div className="rounded-lg border border-divider bg-track p-4 space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-xs text-pn-muted">
          {t('wellness.week.range', { start: week.startDate, end: week.endDate })}
        </span>
        <span className="text-xs text-pn-muted">{t('wellness.week.daysLogged', { count: week.daysLogged })}</span>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {week.avgMood != null && (
          <div>
            <div className="text-lg font-semibold tabular-nums">{week.avgMood}/10</div>
            <SectionEyebrow>{t('wellness.week.avgMood')}</SectionEyebrow>
            {week.moodDelta != null && (
              <div className={`text-[10px] font-medium ${week.moodDelta > 0 ? 'text-emerald-600' : week.moodDelta < 0 ? 'text-red-500' : 'text-pn-muted'}`}>
                {t('wellness.week.moodDelta', { delta: `${week.moodDelta > 0 ? '+' : ''}${week.moodDelta}` })}
              </div>
            )}
          </div>
        )}
        {week.avgSleepHours != null && (
          <div>
            <div className="text-lg font-semibold tabular-nums">{week.avgSleepHours}h</div>
            <SectionEyebrow>{t('wellness.week.avgSleep')}</SectionEyebrow>
          </div>
        )}
        {week.medAdherence != null && (
          <div>
            <div className="text-lg font-semibold tabular-nums">{week.medAdherence}%</div>
            <SectionEyebrow>{t('wellness.week.medsTaken')}</SectionEyebrow>
          </div>
        )}
        {week.dominantActivity && (
          <div>
            <div className="text-lg font-semibold">{week.dominantActivity.label}</div>
            <SectionEyebrow>{t('wellness.week.topActivity')}</SectionEyebrow>
          </div>
        )}
      </div>
      {week.topEmotions.length > 0 && (
        <div>
          <SectionEyebrow className="mb-1">{t('wellness.week.topEmotions')}</SectionEyebrow>
          <div className="flex flex-wrap gap-1">
            {week.topEmotions.map((e) => (
              <span key={e.key} className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-track text-pn-muted">
                {e.label} ({e.count})
              </span>
            ))}
          </div>
        </div>
      )}
      {/* Editable weekly reflection */}
      <div>
        <SectionEyebrow className="mb-1">{t('wellness.week.reflection')}</SectionEyebrow>
        <textarea
          placeholder={t('wellness.week.reflectionPlaceholder')}
          className="w-full rounded-md border border-divider bg-surface-0 text-xs text-pn-soft p-2 resize-none h-16 placeholder:text-pn-muted"
          value={reflection ?? ''}
          onChange={(e) => onReflectionChange?.(e.target.value)}
        />
      </div>
    </div>
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

function moodColor(mood: number): string {
  if (mood <= 2) return '#EF4444';
  if (mood <= 4) return '#F97316';
  if (mood <= 6) return '#EAB308';
  if (mood <= 8) return '#22C55E';
  return '#1E40AF';
}

function daysAgoStr(n: number): string {
  const d = new Date();
  d.setDate(d.getDate() - n);
  // Local: this bound is compared against entry dates, which are local.
  return toLocalIso(d);
}

function Stat({ label, value }: { label: string; value: number | string }) {
  return (
    <div>
      <div className="text-2xl font-semibold tabular-nums">{value}</div>
      <SectionEyebrow className="mt-0.5">
        {label}
      </SectionEyebrow>
    </div>
  );
}
