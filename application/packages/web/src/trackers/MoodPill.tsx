import { useTranslation } from 'react-i18next';
import { BUILTIN_TRACKER_COLORS, MOOD_ANCHORS } from '../trackerTypes';
import { PillShell } from './PillShell';
import { TRACKER_ICONS } from './icons';

/**
 * Mood pill - 1..10 scale with anchor word labels (e.g. "7 good").
 */
export function MoodPill({
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
  const anchorWord = value != null && MOOD_ANCHORS[value] != null ? t(`mood.anchor.${value}`) : undefined;
  return (
    <PillShell
      label={t('labels.mood')}
      color={BUILTIN_TRACKER_COLORS.mood}
      filled={value != null}
      expanded={expanded}
      onToggle={onToggle}
      filledLabel={value != null ? (anchorWord ? `${value} ${anchorWord}` : `${value}/10`) : undefined}
      icon={TRACKER_ICONS.mood}
      readOnly={readOnly}
    >
      <div className="flex flex-col gap-2 items-start">
        <span className="text-xs font-medium text-neutral-600 dark:text-neutral-300">
          {t('mood.prompt')}
        </span>
        <div className="inline-flex flex-col gap-1">
          <div className="flex gap-1">
            {Array.from({ length: 10 }, (_, i) => i + 1).map((n) => (
              <button
                key={n}
                type="button"
                onClick={() => { onChange(n); onToggle(); }}
                className={`w-7 h-7 rounded-md text-xs font-semibold transition-colors ${
                  value === n
                    ? 'bg-accent text-white'
                    : 'bg-surface-0 text-neutral-700 dark:text-neutral-300 hover:bg-accent/20'
                }`}
              >
                {n}
              </button>
            ))}
          </div>
          <div className="flex justify-between text-[10px] text-neutral-400 dark:text-neutral-500 px-0.5">
            <span>{t('mood.low')}</span>
            <span>{t('mood.high')}</span>
          </div>
        </div>
      </div>
    </PillShell>
  );
}
