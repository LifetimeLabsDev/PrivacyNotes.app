import { useTranslation } from 'react-i18next';
import { PillShell } from './PillShell';
import { useLastLogged } from '../trackerLastLogged';
import { TRACKER_ICONS } from './icons';
import { NumberStepper, PanelQuestion } from './panelUI';

/** The scores the quick picks offer. */
const QUICK_SCORES = [60, 70, 80, 90] as const;

/** Sleep Score pill - a watch's 0 to 100 score, as a stepper. */
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
  const last = useLastLogged((d) => d.sleepScore);
  return (
    <PillShell
      label={t('labels.sleepScore')}
      filled={value != null}
      expanded={expanded}
      onToggle={onToggle}
      filledLabel={value != null ? `${value}` : undefined}
      icon={TRACKER_ICONS.sleepScore}
      readOnly={readOnly}
    >
      <div className="max-w-[420px]">
        <PanelQuestion>{t('sleepScore.prompt')}</PanelQuestion>
        <NumberStepper value={value} onChange={onChange} min={0} max={100} step={1} quick={QUICK_SCORES} start={last} placeholder="75" expanded={expanded} />
      </div>
    </PillShell>
  );
}
