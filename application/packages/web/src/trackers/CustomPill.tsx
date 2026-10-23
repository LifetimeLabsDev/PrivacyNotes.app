import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import type { CustomTrackerTemplate, CustomTrackerType, JournalTrackerData } from '../trackerTypes';
import { useLastLogged } from '../trackerLastLogged';
import { PillShell } from './PillShell';
import { CustomTrackerGlyph } from './CustomTrackerGlyph';
import { ScaleTiles } from '../MoodScale';
import { ChoiceGrid, NumberStepper, PanelQuestion } from './panelUI';

// Spec: ops/docs/design-decisions.md (number tracker bounds - prevents scientific-notation display)
const MAX_NUMBER = 1e12;

/** Clamp to a sane magnitude and round to 4 decimals so the value never stringifies to exponential form. */
function sanitizeNumber(n: number): number {
  const clamped = Math.max(-MAX_NUMBER, Math.min(MAX_NUMBER, n));
  return Math.round(clamped * 10000) / 10000;
}

/** The quick picks of a 0 to 100 slider tracker. */
const QUICK_HUNDRED = [25, 50, 75, 100] as const;

/**
 * Custom (Pro) tracker pill. Picker shape by template type:
 * scale10 (0-10) and scale5 (0-5) are tiles, slider100 (0-100) and number
 * (+unit) are steppers, yesno is a two-tile choice.
 */
export function CustomPill({
  template,
  value,
  expanded,
  onToggle,
  onChange,
  readOnly,
}: {
  template: CustomTrackerTemplate;
  value?: number | boolean | string;
  expanded: boolean;
  onToggle: () => void;
  onChange: (v: number | boolean | string) => void;
  readOnly?: boolean;
}) {
  const { t } = useTranslation('trackers');
  const readOwn = (d: JournalTrackerData) => {
    const v = d.customTrackers?.find((e) => e.trackerId === template.id)?.value;
    return typeof v === 'number' ? v : undefined;
  };
  const last = useLastLogged(readOwn);

  const filledLabel = useMemo(() => {
    if (value == null) return undefined;
    if (template.type === 'yesno') return value ? t('custom.yes') : t('custom.no');
    if (template.type === 'slider100') return `${value}`;
    if (template.type === 'number') return `${value}`;
    return `${value}/${template.type === 'scale5' ? 5 : 10}`;
  }, [value, template.type, t]);
  const num = typeof value === 'number' ? value : null;

  return (
    <PillShell
      label={template.name}
      filled={value != null}
      expanded={expanded}
      onToggle={onToggle}
      filledLabel={filledLabel}
      icon={<CustomTrackerGlyph icon={template.icon} />}
      readOnly={readOnly}
    >
      <div className="max-w-[420px]">
        <PanelQuestion>{template.name}</PanelQuestion>
        <CustomTrackerInput
          name={template.name}
          type={template.type}
          value={value}
          onChange={onChange}
          onDone={onToggle}
          expanded={expanded}
          start={template.startFromLast === false ? undefined : last}
          autoFocus
        />
      </div>
    </PillShell>
  );
}

/**
 * The input of a custom tracker, by type: tiles for the two scales, a
 * stepper for the slider and the number, a two-tile choice for yes or no.
 * The pill draws it, and so does the preview of the new-tracker dialog, so
 * the preview is what the person will tap. `onDone` runs after a tap that
 * commits a single value (a tile, a choice).
 */
export function CustomTrackerInput({ name, type, value, onChange, onDone, expanded, start, autoFocus = false }: {
  name: string;
  type: CustomTrackerType;
  value: number | boolean | string | undefined;
  onChange: (v: number | boolean) => void;
  onDone?: () => void;
  expanded: boolean;
  start?: number;
  autoFocus?: boolean;
}) {
  const { t } = useTranslation('trackers');
  const num = typeof value === 'number' ? value : null;
  if (type === 'scale10' || type === 'scale5') {
    const max = type === 'scale5' ? 5 : 10;
    return (
      <ScaleTiles
        min={0}
        max={max}
        value={num}
        onPick={(n) => { onChange(n); onDone?.(); }}
        label={name}
        ends={[`0 · ${t('scaleEnds.low')}`, `${max} · ${t('scaleEnds.high')}`]}
      />
    );
  }
  if (type === 'slider100') {
    return <NumberStepper value={num} onChange={onChange} min={0} max={100} step={1} quick={QUICK_HUNDRED} start={start} placeholder="50" expanded={expanded} />;
  }
  if (type === 'number') {
    return <NumberStepper value={num} onChange={(n) => onChange(sanitizeNumber(n))} step={1} freeDecimals start={start} placeholder="0" expanded={expanded} autoFocus={autoFocus} />;
  }
  return (
    <ChoiceGrid
      options={[{ key: true, label: t('custom.yes') }, { key: false, label: t('custom.no') }]}
      value={typeof value === 'boolean' ? value : null}
      onPick={(v) => { onChange(v); onDone?.(); }}
      size="lg"
    />
  );
}
