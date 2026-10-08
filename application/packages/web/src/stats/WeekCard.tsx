import { useTranslation } from 'react-i18next';
import type { TrackerStats } from '../trackerStats';
import { SectionEyebrow } from '../settingsUI';
import { formatDay } from '../intlFormat';

/** The week in review card: the last seven days, with the reflection field. */
export function WeekCard({ week, reflection, onReflectionChange }: {
  week: NonNullable<TrackerStats['weekInReview']>;
  reflection?: string;
  onReflectionChange?: (text: string) => void;
}) {
  const { t } = useTranslation('stats');
  const { t: tt } = useTranslation('trackers');
  return (
    <div className="rounded-lg border border-divider bg-track p-4 space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-xs text-pn-muted">
          {t('wellness.week.range', { start: formatDay(week.startDate, 'dayMonth'), end: formatDay(week.endDate, 'dayMonth') })}
        </span>
        <span className="text-xs text-pn-muted">{t('wellness.week.daysLogged', { count: week.daysLogged })}</span>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {week.avgMood != null && (
          <div>
            <div className="text-lg font-semibold tabular-nums">{week.avgMood}/10</div>
            <SectionEyebrow>{t('wellness.week.avgMood')}</SectionEyebrow>
            {week.moodDelta != null && (
              <div className={`text-[10px] font-medium ${week.moodDelta > 0 ? 'text-success' : week.moodDelta < 0 ? 'text-danger' : 'text-pn-muted'}`}>
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
            <div className="text-lg font-semibold">{tt(`activity.level.${week.dominantActivity.level}`)}</div>
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
                {tt(`emotions.tags.${e.key}`)} ({e.count})
              </span>
            ))}
          </div>
        </div>
      )}
      {/* Absent while the week's journal is behind a closed gate: the text is
          its content, and an empty field typed into would overwrite what the
          gate hides. */}
      {onReflectionChange && (
        <div>
          <SectionEyebrow className="mb-1">{t('wellness.week.reflection')}</SectionEyebrow>
          <textarea
            placeholder={t('wellness.week.reflectionPlaceholder')}
            className="w-full rounded-md border border-divider bg-surface-0 text-xs text-pn-soft p-2 resize-none h-16 placeholder:text-pn-muted"
            value={reflection ?? ''}
            onChange={(e) => onReflectionChange(e.target.value)}
          />
        </div>
      )}
    </div>
  );
}
