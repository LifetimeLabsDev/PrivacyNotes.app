import { useTranslation } from 'react-i18next';
import type { LocalNote } from '../db';
import { type MedicationTemplate } from '../trackerTypes';
import { computeTrackerStats } from '../trackerStats';

export function WeekInReview({
  notes,
  medications,
}: {
  notes: LocalNote[];
  medications: MedicationTemplate[];
}) {
  const { t } = useTranslation('notes');
  const { t: tt } = useTranslation('trackers');
  // Full list, tombstones included - a deleted medication's logged doses
  // still need a name to render against.
  const tStats = computeTrackerStats(notes, medications);
  if (!tStats.weekInReview) return null;
  const w = tStats.weekInReview;
  return (
    <div className="mx-4 sm:mx-6 mt-2 mb-1 rounded-lg border border-accent/30 bg-accent/5 p-3 space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-[10px] font-semibold text-accent uppercase tracking-wide">{t('weekReview.title')}</span>
        <span className="text-[10px] text-neutral-400">{t('weekReview.daysLogged', { count: w.daysLogged })}</span>
      </div>
      <div className="flex flex-wrap gap-3 text-xs">
        {w.avgMood != null && (
          <span className="text-neutral-700 dark:text-neutral-300">
            {t('weekReview.mood')} <strong>{w.avgMood}</strong>/10
            {w.moodDelta != null && (
              <span className={w.moodDelta > 0 ? ' text-emerald-600' : w.moodDelta < 0 ? ' text-red-500' : ''}>
                {' '}({w.moodDelta > 0 ? '+' : ''}{w.moodDelta})
              </span>
            )}
          </span>
        )}
        {w.avgSleepHours != null && <span className="text-neutral-700 dark:text-neutral-300">{t('weekReview.sleep')} <strong>{w.avgSleepHours}h</strong></span>}
        {w.medAdherence != null && <span className="text-neutral-700 dark:text-neutral-300">{t('weekReview.meds')} <strong>{w.medAdherence}%</strong></span>}
        {w.dominantActivity && <span className="text-neutral-700 dark:text-neutral-300">{t('weekReview.activity')} <strong>{tt(`activity.level.${w.dominantActivity.level}`)}</strong></span>}
      </div>
      {w.topEmotions.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {w.topEmotions.slice(0, 3).map((em) => (
            <span key={em.key} className="px-1.5 py-0.5 rounded text-[10px] bg-neutral-200 dark:bg-neutral-800 text-neutral-600 dark:text-neutral-300">
              {tt(`emotions.tags.${em.key}`)}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
