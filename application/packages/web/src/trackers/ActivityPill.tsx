import { useTranslation } from 'react-i18next';
import {
  ACTIVITY_LEVELS,
  BUILTIN_TRACKER_COLORS,
  type ActivityLevel,
} from '../trackerTypes';
import { PillShell } from './PillShell';
import { TRACKER_ICONS } from './icons';

/**
 * Activity pill - single-select activity level.
 */
export function ActivityPill({
  value,
  expanded,
  onToggle,
  onChange,
  readOnly,
}: {
  value?: ActivityLevel;
  expanded: boolean;
  onToggle: () => void;
  onChange: (v: ActivityLevel) => void;
  readOnly?: boolean;
}) {
  const { t } = useTranslation('trackers');
  return (
    <PillShell
      label={t('labels.activity')}
      color={BUILTIN_TRACKER_COLORS.activity}
      filled={value != null}
      expanded={expanded}
      onToggle={onToggle}
      filledLabel={value ? t(`activity.level.${value}`) : undefined}
      icon={TRACKER_ICONS.activity}
      readOnly={readOnly}
    >
      <div className="flex flex-col gap-2">
        <span className="text-xs font-medium text-neutral-600 dark:text-neutral-300">
          {t('activity.prompt')}
        </span>
        <div className="flex gap-1">
          {ACTIVITY_LEVELS.map((level) => (
            <button
              key={level}
              type="button"
              onClick={() => { onChange(level); onToggle(); }}
              className={`flex-1 px-1 py-1.5 rounded-md text-[11px] font-medium text-center transition-colors ${
                value === level
                  ? 'text-white'
                  : 'bg-surface-0 text-neutral-600 dark:text-neutral-300'
              }`}
              style={
                value === level
                  ? { backgroundColor: BUILTIN_TRACKER_COLORS.activity }
                  : undefined
              }
              onMouseEnter={(e) => {
                if (value !== level) e.currentTarget.style.backgroundColor = `${BUILTIN_TRACKER_COLORS.activity}33`;
              }}
              onMouseLeave={(e) => {
                if (value !== level) e.currentTarget.style.backgroundColor = '';
              }}
            >
              {t(`activity.level.${level}`)}
            </button>
          ))}
        </div>
      </div>
    </PillShell>
  );
}
