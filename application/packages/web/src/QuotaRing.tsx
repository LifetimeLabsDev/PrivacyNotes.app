import { Trans, useTranslation } from 'react-i18next';
import { formatBytes } from './formatBytes';
import { SETTINGS_EYEBROW } from './settingsUI';

/** Storage quota radial gauge. */
export function QuotaRing({
  label,
  usedBytes,
  maxBytes,
  compact = false,
}: {
  label: string;
  usedBytes: number;
  maxBytes: number;
  /** Horizontal small-ring + stats layout. Saves vertical space (e.g. modals). */
  compact?: boolean;
}) {
  const { t } = useTranslation('settings');
  const pct = maxBytes > 0 ? Math.min((usedBytes / maxBytes) * 100, 100) : 0;
  const isHigh = pct > 80;
  const radius = 43;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference * (1 - Math.max(pct, 0.5) / 100);
  const gb = maxBytes / 1000 ** 3;
  const gbRounded = Math.round(gb * 2) / 2;
  const maxLabel =
    gb >= 1
      ? t('quota.gb', { value: Number.isInteger(gbRounded) ? gbRounded : gbRounded.toFixed(1) })
      : t('quota.mb', { value: Math.round(maxBytes / 1000 ** 2 / 50) * 50 });
  const pctLabel = pct === 0 ? '0%' : pct < 1 ? '<1%' : `${Math.round(pct)}%`;

  if (compact) {
    return (
      <div className="flex items-center gap-4">
        <div className="relative h-16 w-16 shrink-0">
          <svg viewBox="0 0 100 100" className="h-16 w-16">
            <circle
              cx="50"
              cy="50"
              r={radius}
              fill="none"
              strokeWidth="9"
              className="stroke-neutral-300 dark:stroke-neutral-700"
            />
            <circle
              cx="50"
              cy="50"
              r={radius}
              fill="none"
              strokeWidth="9"
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={dashOffset}
              transform="rotate(-90 50 50)"
              className={`transition-all ${isHigh ? 'stroke-amber-500 dark:stroke-amber-400' : 'stroke-accent'}`}
            />
          </svg>
          <div className="absolute inset-0 flex items-center justify-center">
            <span className="text-[15px] font-medium leading-none text-neutral-900 dark:text-white">
              {pctLabel}
            </span>
          </div>
        </div>
        <div className="min-w-0">
          <div className="text-lg font-medium text-neutral-900 dark:text-white">
            {formatBytes(usedBytes)}{' '}
            <span className="font-normal text-neutral-500 dark:text-neutral-400">
              <Trans
                i18nKey="settings:quota.ofMax"
                values={{ max: maxLabel }}
                components={{ max: <span className="font-medium text-accent" /> }}
              />
            </span>
          </div>
          <div className="mt-0.5 text-[13px] text-neutral-600 dark:text-neutral-400">{label}</div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col items-center text-center">
      <div className="relative h-[152px] w-[152px]">
        <svg viewBox="0 0 100 100" className="h-[152px] w-[152px]">
          <circle
            cx="50"
            cy="50"
            r={radius}
            fill="none"
            strokeWidth="8"
            className="stroke-neutral-300 dark:stroke-neutral-700"
          />
          <circle
            cx="50"
            cy="50"
            r={radius}
            fill="none"
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={dashOffset}
            transform="rotate(-90 50 50)"
            className={`transition-all ${isHigh ? 'stroke-amber-500 dark:stroke-amber-400' : 'stroke-accent'}`}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-medium leading-none text-neutral-900 dark:text-white">
            {pctLabel}
          </span>
          <span className={`mt-1 ${SETTINGS_EYEBROW}`}>
            {t('quota.used')}
          </span>
        </div>
      </div>
      <div className="mt-3 text-[15px] font-medium text-neutral-900 dark:text-white">
        {formatBytes(usedBytes)}{' '}
        <span className="font-normal text-neutral-500 dark:text-neutral-400">
          <Trans
            i18nKey="settings:quota.ofMax"
            values={{ max: maxLabel }}
            components={{ max: <span className="font-medium text-accent" /> }}
          />
        </span>
      </div>
      <div className="mt-0.5 text-[13px] text-neutral-600 dark:text-neutral-400">{label}</div>
    </div>
  );
}
