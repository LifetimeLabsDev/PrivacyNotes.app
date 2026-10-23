import { PillShell } from './PillShell';
import { TRACKER_ICONS } from './icons';
import { NumberStepper, PanelQuestion, Segmented } from './panelUI';

/**
 * Generic number pill: a stepper with quick picks and a unit. Used for
 * Weight, Steps, Screen Time.
 *
 * Pass `unitOptions` to turn the static unit into a segmented picker. The
 * pill does no converting of its own: it hands the new unit to the caller
 * and shows the `value` that comes back, so there is one owner for the
 * conversion, the caller that knows what the number means.
 */
export function NumberInputPill({
  id,
  label,
  prompt,
  filledText,
  value,
  expanded,
  onToggle,
  onChange,
  readOnly,
  unit,
  placeholder,
  min,
  max,
  step,
  quick,
  start,
  unitOptions,
  activeUnit,
  onUnitChange,
}: {
  id: string;
  label: string;
  /** The question over the stepper; the label when absent. */
  prompt?: string;
  /** The logged pill's text; the value and the unit when absent. */
  filledText?: string;
  value?: number;
  expanded: boolean;
  onToggle: () => void;
  onChange: (v: number) => void;
  readOnly?: boolean;
  unit: string;
  placeholder?: string;
  min?: number;
  max?: number;
  step?: number;
  quick?: readonly number[];
  start?: number;
  unitOptions?: readonly { key: string; label: string }[];
  activeUnit?: string;
  onUnitChange?: (key: string) => void;
}) {
  return (
    <PillShell
      label={label}
      filled={value != null}
      expanded={expanded}
      onToggle={onToggle}
      filledLabel={value != null ? (filledText ?? `${value} ${unit}`) : undefined}
      icon={TRACKER_ICONS[id]}
      readOnly={readOnly}
    >
      <div className="max-w-[420px]">
        {/* The unit picker sits on the question's line, so the number and
            its plus and minus stay one centred group. */}
        <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 mb-2">
          <PanelQuestion className="mb-0">{prompt ?? label}</PanelQuestion>
          {unitOptions && activeUnit && onUnitChange && (
            <Segmented size="sm" options={unitOptions} value={activeUnit} onPick={onUnitChange} ariaLabel={label} />
          )}
        </div>
        <NumberStepper
          value={value}
          onChange={onChange}
          min={min}
          max={max}
          step={step}
          quick={quick}
          start={start}
          placeholder={placeholder}
          expanded={expanded}
          unit={unit}
          unitKey={activeUnit}
        />
      </div>
    </PillShell>
  );
}
