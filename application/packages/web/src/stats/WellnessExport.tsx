import { useCallback, useMemo, useState, type ComponentType, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type { LocalNote } from '../db';
import { NO_FACTORS, type FactorDef, type MedicationTemplate, type TrackerSettings } from '../trackerTypes';
import { computeTrackerStats, exportTrackerJSON, journalsInRange } from '../trackerStats';
import { generateAIPrompt, generateDoctorReport } from './wellnessReport';
import { saveBlob } from '../saveFile';
import { detectPlatform } from '../devices';
import { proUnlocked } from '../demo';
import { SETTINGS_HELP, SETTINGS_SELECT } from '../settingsUI';
import { toLocalIso } from '../notesViewUtils';
import type { RangeId } from '../wellnessTypes';
import { buildWellnessModel, levelLabel, trackerName } from './wellnessModel';
import { trackerCsv } from '../trackerCsv';
import { BracketsCurly, FileCsv, FilePdf, Sparkle } from '../icons';
import { RANGE_IDS, readWellnessRange, writeWellnessRange } from './wellnessRange';

/** The Export tab's row, passed in so this file does not import the modal. */
export type ExportRow = ComponentType<{
  setting: string;
  title: string;
  description: string;
  glyph?: ReactNode;
  pro?: boolean;
  onClick: () => void;
}>;

/**
 * Settings > Import & Export > Trackers: the tracker exports, over a range
 * picked here. The range is the one Statistics > Trackers shows, so both
 * places agree on what "the last 30 days" holds.
 * Spec: ops/docs/archive/wellness-statistics.md (section 3)
 */
export function WellnessExportTab({ notes, isNoteLocked, trackerSettings, factors = NO_FACTORS, medications, isPro, onOpenUpgrade, Row }: {
  notes: LocalNote[];
  isNoteLocked: (n: LocalNote) => boolean;
  trackerSettings: TrackerSettings;
  factors?: FactorDef[];
  medications: MedicationTemplate[];
  isPro: boolean;
  onOpenUpgrade?: () => void;
  Row: ExportRow;
}) {
  const { t } = useTranslation('stats');
  const [rangeId, setRangeId] = useState<RangeId>(readWellnessRange);
  const [copied, setCopied] = useState(false);
  // The copied prompt stays readable in the pane, so the person knows what left the clipboard.
  const [promptText, setPromptText] = useState<string | null>(null);
  // A failed native save can leave an empty or partial file, so the message
  // stays until a save succeeds; a dismissed dialog changes nothing.
  const [saveFailed, setSaveFailed] = useState(false);
  const unlocked = proUnlocked(isPro);

  const pickRange = (id: RangeId) => { setRangeId(id); writeWellnessRange(id); };
  const model = useMemo(
    () => buildWellnessModel(notes, isNoteLocked, trackerSettings, medications, rangeId, factors),
    [notes, isNoteLocked, trackerSettings, medications, rangeId, factors],
  );
  const stats = useMemo(() => {
    const allTime = computeTrackerStats(notes, medications, isNoteLocked);
    return { ...computeTrackerStats(journalsInRange(notes, model.range), medications, isNoteLocked), weekInReview: allTime.weekInReview };
  }, [notes, model.range, medications, isNoteLocked]);
  const definitions = useMemo(() => ({ customTrackers: trackerSettings.customTrackers, medications, factors }), [trackerSettings, medications, factors]);

  const handleExportJSON = useCallback(async () => {
    const json = exportTrackerJSON(notes, model.range.from, model.range.to, isNoteLocked, definitions);
    const saved = await saveBlob(new Blob([json], { type: 'application/json' }), `privacy-notes-wellness-${toLocalIso(new Date())}.json`);
    if (saved.ok) setSaveFailed(false);
    else if (saved.reason === 'failed') setSaveFailed(true);
  }, [notes, model.range, isNoteLocked, definitions]);

  const handleExportCSV = useCallback(async () => {
    const csv = trackerCsv(model.inRange, model.registry, {
      date: t('wellness.export.csvDate'),
      name: (d) => trackerName(d, t),
      level: (d, level) => levelLabel(d, level, t),
    });
    const saved = await saveBlob(new Blob([csv], { type: 'text/csv;charset=utf-8' }), `privacy-notes-wellness-${toLocalIso(new Date())}.csv`);
    if (saved.ok) setSaveFailed(false);
    else if (saved.reason === 'failed') setSaveFailed(true);
  }, [model, t]);

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

  const glyph = (G: typeof Sparkle) => <G size={20} aria-hidden="true" />;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
        <p className={`${SETTINGS_HELP} min-w-0 flex-1`}>{t('wellness.export.intro')}</p>
        <select
          value={rangeId}
          onChange={(e) => pickRange(e.target.value as RangeId)}
          aria-label={t('writing.timeRangeAria')}
          className={SETTINGS_SELECT}
        >
          {RANGE_IDS.map((id) => <option key={id} value={id}>{t(`range.${id}`)}</option>)}
        </select>
      </div>

      {model.entries.length === 0 ? (
        <p className={SETTINGS_HELP}>{t('wellness.empty.title')}</p>
      ) : (
        <div className="space-y-1.5">
          <Row setting="wellness.doctorReport" title={t('wellness.export.doctorPDF')} description={t('wellness.export.doctorDesc')} glyph={glyph(FilePdf)} pro={!isPro} onClick={() => void handleReport()} />
          <Row setting="wellness.json" title={t('wellness.export.downloadJSON')} description={t('wellness.export.jsonDesc')} glyph={glyph(BracketsCurly)} onClick={() => void handleExportJSON()} />
          <Row setting="wellness.csv" title={t('wellness.export.downloadCSV')} description={t('wellness.export.csvDesc')} glyph={glyph(FileCsv)} onClick={() => void handleExportCSV()} />
          <Row setting="wellness.aiPrompt" title={copied ? t('wellness.export.copied') : t('wellness.export.copyAIPrompt')} description={t('wellness.export.aiPromptDesc')} glyph={glyph(Sparkle)} pro={!isPro} onClick={handleCopyAIPrompt} />
        </div>
      )}

      {promptText !== null && (
        <div>
          <div className="flex items-center justify-between mb-1">
            <span className="text-[11px] text-pn-muted">{t('wellness.export.promptShown')}</span>
            <button type="button" onClick={() => setPromptText(null)} className="text-[11px] text-accent hover:underline">{t('wellness.export.hidePrompt')}</button>
          </div>
          <textarea readOnly value={promptText} className="w-full h-56 rounded-md border border-divider bg-surface-0 text-xs text-pn-soft p-2 font-mono resize-y" />
        </div>
      )}
      {saveFailed && <p className="text-xs text-danger">{t('wellness.export.saveFailed')}</p>}
    </div>
  );
}
