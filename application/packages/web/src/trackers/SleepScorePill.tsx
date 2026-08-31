import { useTranslation } from 'react-i18next';
import { BUILTIN_TRACKER_COLORS } from '../trackerTypes';
import { PillShell } from './PillShell';
import { TRACKER_ICONS } from './icons';

/**
 * Sleep Score pill - 0-100 slider for smartwatch/wearable sleep scores.
 */
export function SleepScorePill({
  value,
  expanded,
  onToggle,
  onChange,
  readOnly,
}: {
  value?: number;
  expanded: boolean;
  onToggle: () => void;
  onChange: (v: number) => void;
  readOnly?: boolean;
}) {
  const { t } = useTranslation('trackers');
  return (
    <PillShell
      label={t('labels.sleepScore')}
      color={BUILTIN_TRACKER_COLORS.sleepScore}
      filled={value != null}
      expanded={expanded}
      onToggle={onToggle}
      filledLabel={value != null ? `${value}` : undefined}
      icon={TRACKER_ICONS.sleepScore}
      readOnly={readOnly}
    >
      <div className="flex flex-col gap-3">
        <span className="text-xs font-medium text-neutral-600 dark:text-neutral-300">
          {t('sleepScore.prompt')}
        </span>
        <div className="flex items-center gap-3">
          <input
            type="range"
            min={0}
            max={100}
            step={1}
            value={value ?? 75}
            onChange={(e) => onChange(parseInt(e.target.value, 10))}
            className="flex-1 h-1.5 cursor-pointer"
            style={{ accentColor: BUILTIN_TRACKER_COLORS.sleepScore }}
          />
          <span className="text-sm font-medium text-neutral-700 dark:text-neutral-200 w-8 text-end tabular-nums">
            {value ?? 75}
          </span>
        </div>
      </div>
    </PillShell>
  );
}
