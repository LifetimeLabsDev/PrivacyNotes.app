import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { PillShell, useCommitOnCollapse } from './PillShell';
import { TRACKER_ICONS } from './icons';

/**
 * Generic number input pill with configurable unit suffix.
 * Used for Weight, Steps, Screen Time.
 *
 * Pass `unitOptions` to turn the static suffix into a picker. The pill
 * does no converting of its own: it commits what is typed under the unit
 * that was active, hands the new unit to the caller, and re-seeds its
 * field from the `value` that comes back. That keeps one owner for the
 * conversion, which is the caller that knows what the number means.
 */
export function NumberInputPill({
  id,
  label,
  color,
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
  unitOptions,
  activeUnit,
  onUnitChange,
}: {
  id: string;
  label: string;
  color: string;
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
  unitOptions?: readonly { key: string; label: string }[];
  activeUnit?: string;
  onUnitChange?: (key: string) => void;
}) {
  const { t } = useTranslation('trackers');
  const [draft, setDraft] = useState('');

  // Snap a value to the step grid (anchored at min, or 0) so the field can't
  // accept sub-step or fractional values the way the raw input would. Float
  // noise from the multiply is trimmed to the step's own decimal precision.
  const snapToStep = (n: number) => {
    if (step == null || step <= 0) return n;
    const base = min ?? 0;
    const snapped = base + Math.round((n - base) / step) * step;
    const decimals = (String(step).split('.')[1] ?? '').length;
    return Number(snapped.toFixed(decimals));
  };

  /** Parse and store the draft. Returns false when it is not a usable
   *  number, so the caller can decide whether to keep the picker open. */
  const commitValue = () => {
    const raw = parseFloat(draft || String(value ?? ''));
    if (isNaN(raw)) return false;
    const n = snapToStep(raw);
    if ((min != null && n < min) || (max != null && n > max)) return false;
    onChange(n);
    return true;
  };

  const commit = () => {
    if (commitValue()) onToggle();
  };

  // Closing the picker saves what is in the field - see the hook.
  useCommitOnCollapse(expanded, commitValue);

  // A unit change arrives as a new `value` in the new unit, so the field
  // has to follow it. Keyed on the unit rather than the value, because
  // every other reason `value` moves is the field's own commit.
  const seededUnit = useRef(activeUnit);
  useEffect(() => {
    if (seededUnit.current === activeUnit) return;
    seededUnit.current = activeUnit;
    setDraft(value != null ? String(value) : '');
  }, [activeUnit, value]);

  const changeUnit = (key: string) => {
    if (key === activeUnit) return;
    // Save first, under the unit that is still active, so a number typed
    // but not yet saved is not read as the new unit. A field nobody
    // touched is left alone: writing it back would round the stored value
    // to what the field shows and mark the note changed for nothing.
    if (parseFloat(draft) !== value) commitValue();
    onUnitChange?.(key);
  };

  return (
    <PillShell
      label={label}
      color={color}
      filled={value != null}
      expanded={expanded}
      onToggle={() => {
        if (!expanded) setDraft(value != null ? String(value) : '');
        onToggle();
      }}
      filledLabel={value != null ? `${value} ${unit}` : undefined}
      icon={TRACKER_ICONS[id]}
      readOnly={readOnly}
    >
      <div className="flex flex-col gap-3 items-start">
        <span className="text-xs font-medium text-neutral-600 dark:text-neutral-300">
          {label}
        </span>
        <div className="inline-flex items-center gap-2">
          <input
            type="number"
            inputMode="decimal"
            min={min}
            max={max}
            step={step}
            placeholder={placeholder}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') commit(); }}
            className="w-24 px-2.5 py-1.5 rounded-md text-sm border border-neutral-300 dark:border-neutral-600 bg-surface-0 text-neutral-800 dark:text-neutral-200 tabular-nums"
            autoFocus
          />
          {unitOptions ? (
            <div className="inline-flex rounded-md overflow-hidden border border-neutral-300 dark:border-neutral-600">
              {unitOptions.map((option) => {
                const on = option.key === activeUnit;
                return (
                  <button
                    key={option.key}
                    type="button"
                    onClick={() => changeUnit(option.key)}
                    aria-pressed={on}
                    className={`px-2.5 py-1.5 text-xs font-medium transition-colors ${
                      on
                        ? 'text-white'
                        : 'text-neutral-500 dark:text-neutral-400 hover:text-neutral-700 dark:hover:text-neutral-200'
                    }`}
                    style={on ? { backgroundColor: color } : undefined}
                  >
                    {option.label}
                  </button>
                );
              })}
            </div>
          ) : (
            <span className="text-xs text-neutral-400 dark:text-neutral-500">{unit}</span>
          )}
          <button
            type="button"
            onClick={commit}
            className="px-3 py-1.5 rounded-md text-xs font-medium text-white transition-colors"
            style={{ backgroundColor: color }}
          >
            {t('common:actions.save')}
          </button>
        </div>
      </div>
    </PillShell>
  );
}
