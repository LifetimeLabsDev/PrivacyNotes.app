import { useTranslation } from 'react-i18next';
import { PillShell } from './PillShell';
import { TRACKER_ICONS } from './icons';
import { MoodScale } from '../MoodScale';
import { PanelQuestion } from './panelUI';
import { MoodDot, moodAnchor } from '../moodMark';

/**
 * Mood pill - the 1 to 10 tiles in the band colors (`MoodScale`), the same
 * picker the check-in card draws; the logged pill carries the number on its
 * band's chip and the band's word, "7 good".
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
  return (
    <PillShell
      label={t('labels.mood')}
      filled={value != null}
      expanded={expanded}
      onToggle={onToggle}
      filledLabel={value != null ? `${value} ${t(`mood.anchor.${moodAnchor(value)}`)}` : undefined}
      ariaLabel={value != null ? `${t('labels.mood')}: ${value} ${t(`mood.anchor.${moodAnchor(value)}`)}` : undefined}
      icon={TRACKER_ICONS.mood}
      mark={value != null ? <MoodDot mood={value} /> : undefined}
      readOnly={readOnly}
    >
      <div className="flex flex-col gap-2 items-start">
        <PanelQuestion>{t('mood.prompt')}</PanelQuestion>
        <MoodScale value={value} onPick={(n) => { onChange(n); onToggle(); }} label={t('mood.prompt')} className="w-full max-w-[420px]" />
      </div>
    </PillShell>
  );
}
