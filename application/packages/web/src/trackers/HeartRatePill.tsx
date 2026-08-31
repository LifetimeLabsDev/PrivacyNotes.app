import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { BUILTIN_TRACKER_COLORS } from '../trackerTypes';
import { PillShell, useCommitOnCollapse } from './PillShell';
import { TRACKER_ICONS } from './icons';

/**
 * Heart Rate pill - numeric input with "bpm" suffix.
 * Accepts 30-250 BPM (reasonable resting + exercise range).
 */
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
  const [draft, setDraft] = useState('');

  /** Parse and store the draft; false when it is not a usable reading. */
  const commitValue = () => {
    const n = parseInt(draft || String(value ?? ''), 10);
    if (isNaN(n) || n < 30 || n > 250) return false;
    onChange(n);
    return true;
  };

  const commit = () => {
    if (commitValue()) onToggle();
  };

  // Closing the picker saves the reading - see the hook.
  useCommitOnCollapse(expanded, commitValue);

  return (
    <PillShell
      label={t('labels.heartRate')}
      color={BUILTIN_TRACKER_COLORS.heartRate}
      filled={value != null}
      expanded={expanded}
      onToggle={() => {
        if (!expanded) setDraft(value != null ? String(value) : '');
        onToggle();
      }}
      filledLabel={value != null ? `${value} ${t('units.bpm')}` : undefined}
      icon={TRACKER_ICONS.heartRate}
      readOnly={readOnly}
    >
      <div className="flex flex-col gap-3 items-start">
        <span className="text-xs font-medium text-neutral-600 dark:text-neutral-300">
          {t('heartRate.prompt')}
        </span>
        <div className="inline-flex items-center gap-2">
          <input
            type="number"
            inputMode="numeric"
            min={30}
            max={250}
            placeholder="72"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') commit(); }}
            className="w-20 px-2.5 py-1.5 rounded-md text-sm border border-neutral-300 dark:border-neutral-600 bg-surface-0 text-neutral-800 dark:text-neutral-200 tabular-nums"
            autoFocus
          />
          <span className="text-xs text-neutral-400 dark:text-neutral-500">{t('units.bpm')}</span>
          <button
            type="button"
            onClick={commit}
            className="px-3 py-1.5 rounded-md text-xs font-medium text-white transition-colors"
            style={{ backgroundColor: BUILTIN_TRACKER_COLORS.heartRate }}
          >
            {t('common:actions.save')}
          </button>
        </div>
      </div>
    </PillShell>
  );
}
