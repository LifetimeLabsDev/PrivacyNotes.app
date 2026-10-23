import { useTranslation } from 'react-i18next';
import { PillShell } from './PillShell';
import { useLastLogged } from '../trackerLastLogged';
import { TRACKER_ICONS } from './icons';
import { NumberStepper, PanelQuestion } from './panelUI';

/** The resting rates the quick picks offer. */
const QUICK_BPM = [60, 70, 80, 90] as const;

/** Heart Rate pill - a stepper in bpm, 30 to 250 (resting to exercise). */
export function HeartRatePill({
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
  const last = useLastLogged((d) => d.heartRate);
  return (
    <PillShell
      label={t('labels.heartRate')}
      filled={value != null}
      expanded={expanded}
      onToggle={onToggle}
      filledLabel={value != null ? `${value} ${t('units.bpm')}` : undefined}
      icon={TRACKER_ICONS.heartRate}
      readOnly={readOnly}
    >
      <div className="max-w-[420px]">
        <PanelQuestion>{t('heartRate.prompt')}</PanelQuestion>
        <NumberStepper value={value} onChange={onChange} min={30} max={250} step={1} unit={t('units.bpm')} quick={QUICK_BPM} start={last} placeholder="72" expanded={expanded} />
      </div>
    </PillShell>
  );
}
