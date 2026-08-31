import { useTranslation } from 'react-i18next';
import { PillShell } from './PillShell';
import { TRACKER_ICONS } from './icons';

/**
 * Generic scale pill with configurable range. Defaults to 0-10.
 */
export function ScalePill({
  id,
  label,
  color,
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
}: {
  id: string;
  label: string;
  color: string;
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
}) {
  const { t } = useTranslation('trackers');
  const count = max - min + 1;
  const filledText = value != null ? `${value}${suffix ?? `/${max}`}` : undefined;
  const low = lowLabel ?? t('scaleEnds.low');
  const high = highLabel ?? t('scaleEnds.high');

  return (
    <PillShell
      label={label}
      color={color}
      filled={value != null}
      expanded={expanded}
      onToggle={onToggle}
      filledLabel={filledText}
      icon={TRACKER_ICONS[id]}
      readOnly={readOnly}
    >
      <div className="flex flex-col gap-2 items-start">
        <span className="text-xs font-medium text-neutral-600 dark:text-neutral-300">
          {t('scalePill.prompt', { label, min, max })}
        </span>
        <div className="inline-flex flex-col gap-1">
          <div className="flex gap-1">
            {Array.from({ length: count }, (_, i) => min + i).map((n) => (
              <button
                key={n}
                type="button"
                onClick={() => { onChange(n); onToggle(); }}
                className={`w-7 h-7 rounded-md text-xs font-semibold transition-colors ${
                  value === n
                    ? 'text-white'
                    : 'bg-surface-0 text-neutral-700 dark:text-neutral-300 hover:opacity-80'
                }`}
                style={value === n ? { backgroundColor: color } : undefined}
              >
                {n}
              </button>
            ))}
          </div>
          <div className="flex justify-between text-[10px] text-neutral-400 dark:text-neutral-500 px-0.5">
            <span>{low}</span>
            <span>{high}</span>
          </div>
        </div>
      </div>
    </PillShell>
  );
}
