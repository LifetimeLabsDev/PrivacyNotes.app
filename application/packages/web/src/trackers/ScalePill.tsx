import { useTranslation } from 'react-i18next';
import { PillShell } from './PillShell';
import { TRACKER_ICONS } from './icons';
import { ScaleTiles } from '../MoodScale';
import { PanelQuestion } from './panelUI';

/**
 * Generic scale pill with configurable range, 0 to 10 by default: the same
 * tiles as the mood, in the accent. A tap commits and closes the panel.
 */
export function ScalePill({
  id,
  label,
  value,
  expanded,
  onToggle,
  onChange,
  readOnly,
  min = 0,
  max = 10,
  suffix,
  lowLabel,
  highLabel,
  prompt,
}: {
  id: string;
  label: string;
  value?: number;
  expanded: boolean;
  onToggle: () => void;
  onChange: (v: number) => void;
  readOnly?: boolean;
  min?: number;
  max?: number;
  suffix?: string;
  lowLabel?: string;
  highLabel?: string;
  /** The question over the tiles; "Label (min-max)" when absent. */
  prompt?: string;
}) {
  const { t } = useTranslation('trackers');
  const filledText = value != null ? `${value}${suffix ?? `/${max}`}` : undefined;
  const low = lowLabel ?? t('scaleEnds.low');
  const high = highLabel ?? t('scaleEnds.high');

  return (
    <PillShell
      label={label}
      filled={value != null}
      expanded={expanded}
      onToggle={onToggle}
      filledLabel={filledText}
      icon={TRACKER_ICONS[id]}
      readOnly={readOnly}
    >
      <PanelQuestion>{prompt ?? t('scalePill.prompt', { label, min, max })}</PanelQuestion>
      <ScaleTiles
        min={min}
        max={max}
        value={value}
        onPick={(n) => { onChange(n); onToggle(); }}
        label={label}
        ends={[/\d/.test(low) ? low : `${min} · ${low}`, /\d/.test(high) ? high : `${max} · ${high}`]}
        className="w-full max-w-[420px]"
      />
    </PillShell>
  );
}
