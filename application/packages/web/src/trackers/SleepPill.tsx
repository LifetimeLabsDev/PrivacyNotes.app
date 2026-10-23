import { useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { SLEEP_QUALITIES, type SleepQuality } from '../trackerTypes';
import { PillShell } from './PillShell';
import { useLastLogged } from '../trackerLastLogged';
import { TRACKER_ICONS } from './icons';
import { ChoiceGrid, NumberStepper, PanelQuestion } from './panelUI';

/** The hours the quick picks offer; the usual nights. */
const QUICK_HOURS = [6, 7, 8, 9] as const;
const DEFAULT_HOURS = 7.5;

/**
 * Sleep pill - the hours as a stepper (0 to 14, half hours), then the
 * quality as one choice. The hours save as they change; the quality tap
 * commits both and closes the panel, so it is the step that moves the pass
 * on. A quality without hours takes the default night.
 */
export function SleepPill({
  value,
  expanded,
  onToggle,
  onChange,
  readOnly,
}: {
  value?: { quality: SleepQuality; hours?: number };
  expanded: boolean;
  onToggle: () => void;
  onChange: (v: { quality: SleepQuality; hours?: number }) => void;
  readOnly?: boolean;
}) {
  const { t } = useTranslation('trackers');
  const lastHours = useLastLogged((d) => d.sleep?.hours);
  const filledLabel = value
    ? `${t(`sleep.quality.${value.quality}`)} (${value.hours ?? DEFAULT_HOURS}${t('units.hoursSuffix')})`
    : undefined;
  const qualities = SLEEP_QUALITIES.map((q) => ({ key: q, label: t(`sleep.quality.${q}`) }));
  // The hours and the quality each write the pair, built from the last pair
  // this pill wrote: the typed hours save on blur or on close, a moment
  // before or after the quality tap, and `value` can still be the pair from
  // before the other write.
  type Sleep = { quality: SleepQuality; hours?: number };
  const latest = useRef<Sleep | undefined>(value);
  useEffect(() => { latest.current = value; }, [value]);
  const write = (v: Sleep) => { latest.current = v; onChange(v); };

  return (
    <PillShell
      label={t('labels.sleep')}
      filled={value != null}
      expanded={expanded}
      onToggle={onToggle}
      filledLabel={filledLabel}
      icon={TRACKER_ICONS.sleep}
      readOnly={readOnly}
    >
      <div className="flex flex-col gap-4 max-w-[420px]">
        <div>
          <PanelQuestion>{t('sleep.hoursLabel')}</PanelQuestion>
          <NumberStepper
            value={value?.hours ?? null}
            onChange={(h) => write({ quality: latest.current?.quality ?? 'okay', hours: h })}
            min={0}
            max={14}
            step={0.5}
            unit={t('units.hoursSuffix')}
            quick={QUICK_HOURS}
            start={lastHours}
            placeholder={String(DEFAULT_HOURS)}
            expanded={expanded}
          />
        </div>
        <div>
          <PanelQuestion>{t('sleep.prompt')}</PanelQuestion>
          <ChoiceGrid
            options={qualities}
            value={value?.quality}
            onPick={(q) => { write({ quality: q, hours: latest.current?.hours ?? DEFAULT_HOURS }); onToggle(); }}
          />
        </div>
      </div>
    </PillShell>
  );
}
