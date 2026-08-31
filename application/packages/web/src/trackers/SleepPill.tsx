import { useTranslation } from 'react-i18next';
import {
  BUILTIN_TRACKER_COLORS,
  SLEEP_QUALITIES,
  type SleepQuality,
} from '../trackerTypes';
import { PillShell } from './PillShell';
import { TRACKER_ICONS } from './icons';

/**
 * Sleep pill - quality (4 buckets) + optional hours slider (0..14 step 0.5).
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
  const filledLabel = value
    ? `${t(`sleep.quality.${value.quality}`)} (${value.hours ?? 7.5}${t('units.hoursSuffix')})`
    : undefined;

  return (
    <PillShell
      label={t('labels.sleep')}
      color={BUILTIN_TRACKER_COLORS.sleep}
      filled={value != null}
      expanded={expanded}
      onToggle={onToggle}
      filledLabel={filledLabel}
      icon={TRACKER_ICONS.sleep}
      readOnly={readOnly}
    >
      <div className="flex flex-col gap-3">
        <span className="text-xs font-medium text-neutral-600 dark:text-neutral-300">
          {t('sleep.prompt')}
        </span>
        <div className="flex gap-1">
          {SLEEP_QUALITIES.map((q) => (
            <button
              key={q}
              type="button"
              onClick={() => {
                onChange({ quality: q, hours: value?.hours });
                onToggle();
              }}
              className={`flex-1 px-1.5 py-1.5 rounded-md text-[11px] font-medium text-center transition-colors ${
                value?.quality === q
                  ? 'text-white'
                  : 'bg-surface-0 text-neutral-600 dark:text-neutral-300'
              }`}
              style={
                value?.quality === q
                  ? { backgroundColor: BUILTIN_TRACKER_COLORS.sleep }
                  : undefined
              }
              onMouseEnter={(e) => {
                if (value?.quality !== q) e.currentTarget.style.backgroundColor = `${BUILTIN_TRACKER_COLORS.sleep}33`;
              }}
              onMouseLeave={(e) => {
                if (value?.quality !== q) e.currentTarget.style.backgroundColor = '';
              }}
            >
              {t(`sleep.quality.${q}`)}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2">
          <label className="text-[11px] text-neutral-500 dark:text-neutral-400 shrink-0">{t('sleep.hoursLabel')}</label>
          <input
            type="range"
            min={0}
            max={14}
            step={0.5}
            value={value?.hours ?? 7.5}
            onChange={(e) => {
              const h = parseFloat(e.target.value);
              if (value) onChange({ ...value, hours: h });
              else onChange({ quality: 'okay', hours: h });
            }}
            className="flex-1 h-1.5 cursor-pointer"
            style={{ accentColor: BUILTIN_TRACKER_COLORS.sleep }}
          />
          <span className="text-xs font-medium text-neutral-700 dark:text-neutral-200 w-7 text-end tabular-nums">
            {value?.hours ?? 7.5}
          </span>
        </div>
      </div>
    </PillShell>
  );
}
