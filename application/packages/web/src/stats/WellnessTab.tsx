import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ChartLine, MagnifyingGlass, Pill, SquaresFour } from '../icons';
import type { LocalNote } from '../db';
import type { MedicationTemplate, TrackerSettings } from '../trackerTypes';
import { computeTrackerStats, exportTrackerJSON, journalsInRange } from '../trackerStats';
import { generateAIPrompt, generateDoctorReport } from './wellnessReport';
import { saveBlob } from '../saveFile';
import { detectPlatform } from '../devices';
import { proUnlocked } from '../demo';
import { SectionEyebrow, SettingsTabStrip, settingsTabClass } from '../settingsUI';
import { HelpChip } from '../HelpChip';
import { journalOn, toLocalIso } from '../notesViewUtils';
import { adaptiveRange } from '../trackerSeries';
import type { RangeId } from '../wellnessTypes';
import { AllSubTab } from './AllSubTab';
import { ExploreSubTab } from './ExploreSubTab';
import { MedicationSubTab } from './MedicationSubTab';
import { PatternsSubTab } from './PatternsSubTab';
import { buildWellnessModel } from './wellnessModel';

export type WellnessSub = 'all' | 'explore' | 'medication' | 'patterns';

const RANGE_IDS: RangeId[] = ['7d', '14d', '30d', '3mo', '6mo', '12mo', 'all'];
// Per-device view preference, like the Writing tab's range; not synced.
const RANGE_KEY = 'pn-wellness-range';

/**
 * The Wellness tab: one range row for everything below it, four sub-tabs
 * over one model, and the export row that reads the same range.
 * Spec: ops/docs/plans/wellness-statistics.md (section 3)
 */
export function WellnessTab({ notes, isNoteLocked, trackerSettings, medications, isPro, onOpenUpgrade, weekReflection, onWeekReflectionChange, onOpenDay }: {
  notes: LocalNote[];
  isNoteLocked: (n: LocalNote) => boolean;
  trackerSettings: TrackerSettings;
  medications: MedicationTemplate[];
  isPro: boolean;
  onOpenUpgrade?: () => void;
  weekReflection?: string;
  onWeekReflectionChange?: (text: string) => void;
  onOpenDay?: (date: string) => void;
}) {
  const { t } = useTranslation('stats');
  const [sub, setSub] = useState<WellnessSub>('all');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  // The copied prompt stays readable in the pane, so the person knows what left the clipboard.
  const [promptText, setPromptText] = useState<string | null>(null);
  // A failed native save can leave an empty or partial file, so the message
  // stays until a save succeeds; a dismissed dialog changes nothing.
  const [saveFailed, setSaveFailed] = useState(false);
  const unlocked = proUnlocked(isPro);
  const today = toLocalIso(new Date());
  // Shown for an entry with no tracker value yet: that is the one a person
  // opens to fill them in.
  const todayEntry = journalOn(notes, today);

  const [rangeId, setRangeId] = useState<RangeId>(() => {
    try {
      const saved = localStorage.getItem(RANGE_KEY);
      if (saved && RANGE_IDS.includes(saved as RangeId)) return saved as RangeId;
    } catch { /* localStorage unavailable */ }
    return 'all';
  });
  const model = useMemo(
    () => buildWellnessModel(notes, isNoteLocked, trackerSettings, medications, rangeId),
    [notes, isNoteLocked, trackerSettings, medications, rangeId],
  );
  // Everything below the range row follows it, the doctor report and the AI
  // prompt included. The week card alone keeps all time, because it compares
  // this week with the one before whatever range is picked.
  const allTime = useMemo(() => computeTrackerStats(notes, medications, isNoteLocked), [notes, medications, isNoteLocked]);
  const stats = useMemo(
    () => ({ ...computeTrackerStats(journalsInRange(notes, model.range), medications, isNoteLocked), weekInReview: allTime.weekInReview }),
    [notes, model.range, medications, isNoteLocked, allTime],
  );
  // The first open lands on the smallest preset that covers the journal.
  useEffect(() => {
    try {
      if (!localStorage.getItem(RANGE_KEY)) setRangeId(adaptiveRange(model.firstDay));
    } catch { /* ignore */ }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- once, on mount
  }, []);
  useEffect(() => {
    try { localStorage.setItem(RANGE_KEY, rangeId); } catch { /* ignore */ }
  }, [rangeId]);

  const definitions = useMemo(() => ({ customTrackers: trackerSettings.customTrackers, medications }), [trackerSettings, medications]);
  const handleExportJSON = useCallback(async () => {
    const json = exportTrackerJSON(notes, model.range.from, model.range.to, isNoteLocked, definitions);
    const saved = await saveBlob(new Blob([json], { type: 'application/json' }), `privacy-notes-wellness-${toLocalIso(new Date())}.json`);
    if (saved.ok) setSaveFailed(false);
    else if (saved.reason === 'failed') setSaveFailed(true);
  }, [notes, model.range, isNoteLocked, definitions]);

  const handleCopyAIPrompt = useCallback(() => {
    if (!unlocked) { onOpenUpgrade?.(); return; }
    const prompt = generateAIPrompt(stats, medications, t, model);
    setPromptText(prompt);
    void navigator.clipboard.writeText(prompt).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }, [unlocked, stats, medications, model, t, onOpenUpgrade]);

  const handleReport = useCallback(async () => {
    if (!unlocked) { onOpenUpgrade?.(); return; }
    const html = generateDoctorReport(stats, medications, t, model);
    if (detectPlatform() === 'web') {
      const w = window.open('', '_blank');
      if (w) { w.document.write(html); w.document.close(); }
    } else {
      // The webview cannot open a print window; the report saves as HTML the
      // person opens and prints in a browser.
      const saved = await saveBlob(new Blob([html], { type: 'text/html' }), `privacy-notes-doctor-report-${toLocalIso(new Date())}.html`);
      if (saved.ok) setSaveFailed(false);
      else if (saved.reason === 'failed') setSaveFailed(true);
    }
  }, [unlocked, stats, medications, model, t, onOpenUpgrade]);

  if (model.entries.length === 0) {
    return (
      <div className="text-center py-12 text-pn-muted">
        <p className="text-sm">{t('wellness.empty.title')}</p>
        <p className="text-xs mt-1">{t('wellness.empty.hint')}</p>
      </div>
    );
  }

  const proBadge = !isPro && <span className="inline-flex items-center px-1 py-0 rounded text-[8px] font-bold bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-300">{t('wellness.export.proBadge')}</span>;
  // Literal markers: the settings search test reads them from the source.
  const tabs: { id: WellnessSub; icon: typeof SquaresFour; label: string; setting: string }[] = [
    { id: 'all', icon: SquaresFour, label: t('wellness.subTabs.all'), setting: 'stats.wellness' },
    { id: 'explore', icon: MagnifyingGlass, label: t('wellness.subTabs.explore'), setting: 'stats.explore' },
    { id: 'medication', icon: Pill, label: t('wellness.subTabs.medication'), setting: 'stats.medication' },
    { id: 'patterns', icon: ChartLine, label: t('wellness.subTabs.patterns'), setting: 'stats.patterns' },
  ];

  return (
    <>
      <SettingsTabStrip className="-mt-1">
        {tabs.map(({ id, icon: Icon, label, setting }) => (
          <button key={id} type="button" data-setting={setting} aria-pressed={sub === id} className={settingsTabClass(sub === id)} onClick={() => setSub(id)}>
            <Icon aria-hidden="true" />
            <span>{label}</span>
          </button>
        ))}
      </SettingsTabStrip>

      <div className="flex flex-wrap items-center gap-1.5 pt-1" role="group" aria-label={t('writing.timeRangeAria')}>
        {RANGE_IDS.map((id) => (
          <button
            key={id}
            type="button"
            aria-pressed={rangeId === id}
            onClick={() => setRangeId(id)}
            className={`px-2.5 py-0.5 rounded-full text-[11px] font-medium border transition-colors ${rangeId === id ? 'bg-pn text-surface-2 border-transparent' : 'border-divider text-pn-soft hover:border-pn-muted'}`}
          >
            {t(`range.${id}`)}
          </button>
        ))}
      </div>

      <p className="text-[11px] text-pn-muted -mt-2">
        {t('wellness.sourceLine')}
        {onOpenDay && todayEntry && !isNoteLocked(todayEntry) && (
          <>
            {' '}
            <button type="button" onClick={() => onOpenDay(today)} className="text-accent hover:underline">{t('wellness.openToday')}</button>
          </>
        )}
      </p>

      {sub === 'all' && (
        <AllSubTab
          model={model}
          stats={stats}
          medications={medications}
          unlocked={unlocked}
          isPro={isPro}
          onExplore={(id) => { setSelectedId(id); setSub('explore'); }}
          onPatterns={() => setSub('patterns')}
          weekReflection={weekReflection}
          onWeekReflectionChange={onWeekReflectionChange}
          onOpenUpgrade={onOpenUpgrade}
        />
      )}
      {sub === 'explore' && (
        <ExploreSubTab model={model} selectedId={selectedId} onSelect={setSelectedId} unlocked={unlocked} isPro={isPro} onOpenUpgrade={onOpenUpgrade} onOpenDay={onOpenDay} />
      )}
      {sub === 'medication' && (
        <MedicationSubTab model={model} stats={stats} medications={medications} unlocked={unlocked} isPro={isPro} onOpenDay={onOpenDay} />
      )}
      {sub === 'patterns' && (
        <PatternsSubTab model={model} stats={stats} unlocked={unlocked} isPro={isPro} onOpenUpgrade={onOpenUpgrade} />
      )}

      {sub === 'all' && (
        <div className="border-t border-divider pt-4">
          <div className="flex items-center justify-between mb-3">
            <SectionEyebrow setting="stats.wellnessExport">{t('wellness.export.heading')}</SectionEyebrow>
            <span className="text-[10px] text-pn-muted">{t('wellness.export.usesRange')}</span>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" onClick={handleCopyAIPrompt} className="inline-flex items-center gap-1 px-3 py-1.5 rounded-md text-xs font-medium bg-accent/10 text-accent-strong hover:bg-accent/20 transition-colors">
              {copied ? t('wellness.export.copied') : t('wellness.export.copyAIPrompt')}{proBadge}
            </button>
            <button type="button" onClick={handleReport} className="inline-flex items-center gap-1 px-3 py-1.5 rounded-md text-xs font-medium border border-divider hover:bg-surface-1 transition-colors">
              {t('wellness.export.doctorPDF')}{proBadge}
            </button>
            <button type="button" onClick={handleExportJSON} className="px-3 py-1.5 rounded-md text-xs font-medium border border-divider hover:bg-surface-1 transition-colors">
              {t('wellness.export.downloadJSON')}
            </button>
          </div>
          {saveFailed && <p className="mt-2 text-xs text-danger">{t('wellness.export.saveFailed')}</p>}
          {promptText !== null && (
            <div className="mt-3">
              <div className="flex items-center justify-between mb-1">
                <span className="text-[11px] text-pn-muted">{t('wellness.export.promptShown')}</span>
                <button type="button" onClick={() => setPromptText(null)} className="text-[11px] text-accent hover:underline">{t('wellness.export.hidePrompt')}</button>
              </div>
              <textarea readOnly value={promptText} className="w-full h-56 rounded-md border border-divider bg-surface-0 text-xs text-pn-soft p-2 font-mono resize-y" />
            </div>
          )}
        </div>
      )}
      <HelpChip surface="wellness" className="pt-1" />
    </>
  );
}
