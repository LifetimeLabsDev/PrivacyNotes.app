import { useTranslation } from 'react-i18next';
import {
  BUILTIN_TRACKER_COLORS,
  EMOTION_TAGS,
} from '../trackerTypes';
import { PillShell } from './PillShell';
import { TRACKER_ICONS } from './icons';

/**
 * Multi-select emotion tags grouped by valence (positive/neutral/negative).
 */
export function EmotionsPill({
  value,
  expanded,
  onToggle,
  onChange,
  readOnly,
}: {
  value?: string[];
  expanded: boolean;
  onToggle: () => void;
  onChange: (v: string[]) => void;
  readOnly?: boolean;
}) {
  const { t } = useTranslation('trackers');
  const count = value?.length ?? 0;
  const toggleTag = (key: string) => {
    const current = value ?? [];
    const next = current.includes(key)
      ? current.filter((k) => k !== key)
      : [...current, key];
    onChange(next);
  };

  const filledLabel = count === 1
    ? (EMOTION_TAGS.some((tag) => tag.key === value![0]) ? t(`emotions.tags.${value![0]}`) : '1')
    : t('emotions.count', { count });

  return (
    <PillShell
      label={t('labels.emotions')}
      color={BUILTIN_TRACKER_COLORS.emotions}
      filled={count > 0}
      expanded={expanded}
      onToggle={onToggle}
      filledLabel={filledLabel}
      icon={TRACKER_ICONS.emotions}
      readOnly={readOnly}
    >
      <div className="flex flex-col gap-2">
        <span className="text-xs font-medium text-neutral-600 dark:text-neutral-300">
          {t('emotions.prompt')}
        </span>
        {(['positive', 'neutral', 'negative'] as const).map((valence) => (
          <div key={valence}>
            <span className={`block text-[11px] font-medium mb-1 ${
              valence === 'positive'
                ? 'text-emerald-600 dark:text-emerald-400'
                : valence === 'neutral'
                  ? 'text-amber-600 dark:text-amber-400'
                  : 'text-red-600 dark:text-red-400'
            }`}>
              {t(`emotions.valence.${valence}`)}
            </span>
            <div className="flex flex-wrap gap-1">
            {EMOTION_TAGS.filter((tag) => tag.valence === valence).map((tag) => (
              <TagChip
                key={tag.key}
                label={t(`emotions.tags.${tag.key}`)}
                selected={value?.includes(tag.key) ?? false}
                onClick={() => toggleTag(tag.key)}
                colorClass={
                  valence === 'positive'
                    ? 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300'
                    : valence === 'neutral'
                      ? 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300'
                      : 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300'
                }
              />
            ))}
            </div>
          </div>
        ))}
      </div>
    </PillShell>
  );
}

function TagChip({
  label,
  selected,
  onClick,
  colorClass,
}: {
  label: string;
  selected: boolean;
  onClick: () => void;
  colorClass: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`px-2 py-0.5 rounded-full text-[11px] font-medium transition-all ${
        selected
          ? `${colorClass} ring-2 ring-current/30`
          : 'bg-surface-0 text-neutral-500 dark:text-neutral-400 hover:bg-neutral-200 dark:hover:bg-neutral-700'
      }`}
    >
      {label}
    </button>
  );
}
