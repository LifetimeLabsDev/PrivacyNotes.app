import { useTranslation } from 'react-i18next';
import { ACTIVITY_LEVELS, type ActivityLevel } from '../trackerTypes';
import { PillShell } from './PillShell';
import { TRACKER_ICONS } from './icons';
import { ChoiceGrid, PanelQuestion } from './panelUI';

/** Activity pill - one activity level; the tap commits and closes. */
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
      filled={value != null}
      expanded={expanded}
      onToggle={onToggle}
      filledLabel={value ? t(`activity.level.${value}`) : undefined}
      icon={TRACKER_ICONS.activity}
      readOnly={readOnly}
    >
      <div className="max-w-[420px]">
        <PanelQuestion>{t('activity.prompt')}</PanelQuestion>
        <ChoiceGrid
          options={ACTIVITY_LEVELS.map((level) => ({ key: level, label: t(`activity.level.${level}`) }))}
          value={value}
          onPick={(level) => { onChange(level); onToggle(); }}
        />
      </div>
    </PillShell>
  );
}
