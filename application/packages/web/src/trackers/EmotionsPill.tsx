import { useTranslation } from 'react-i18next';
import { EMOTION_TAGS } from '../trackerTypes';
import { PillShell } from './PillShell';
import { TRACKER_ICONS } from './icons';
import { PanelQuestion } from './panelUI';

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
      filled={count > 0}
      expanded={expanded}
      onToggle={onToggle}
      filledLabel={filledLabel}
      icon={TRACKER_ICONS.emotions}
      readOnly={readOnly}
    >
      <div className="flex flex-col gap-2">
        <PanelQuestion>{t('emotions.prompt')}</PanelQuestion>
        {(['positive', 'neutral', 'negative'] as const).map((valence) => (
          <div key={valence}>
            <span className={`block text-[11px] font-medium mb-1 ${
              valence === 'positive'
                ? 'text-success'
                : valence === 'neutral'
                  ? 'text-warning'
                  : 'text-danger'
            }`}>
              {t(`emotions.valence.${valence}`)}
            </span>
            <div className="flex flex-wrap gap-1.5">
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
      aria-pressed={selected}
      className={`inline-flex items-center h-7 px-2.5 rounded-md border text-[12px] font-medium transition-colors ${
        selected
          ? `${colorClass} border-current/25`
          : 'border-transparent bg-surface-0 text-pn-soft hover:bg-pn/10 hover:text-pn'
      }`}
    >
      {label}
    </button>
  );
}
