import { useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import type { NewMilestone } from './milestones';

type Props = {
  milestone: NewMilestone;
  onDismiss: () => void;
};

export function MilestoneToast({ milestone, onDismiss }: Props) {
  const { t } = useTranslation('stats');
  // The parent passes a fresh callback on every render; reading it through a
  // ref keeps the timer at fifteen seconds from when this milestone appeared.
  const dismissRef = useRef(onDismiss);
  dismissRef.current = onDismiss;
  useEffect(() => {
    const timer = window.setTimeout(() => dismissRef.current(), 15000);
    return () => window.clearTimeout(timer);
  }, [milestone]);

  return (
    <div
      role="status"
      aria-live="polite"
      className="fixed bottom-4 end-4 sm:bottom-6 sm:end-6 bg-surface-2 border border-divider text-pn rounded-lg ps-5 pe-3 py-3 shadow-xl z-40 max-w-xs flex items-start gap-3"
    >
      <div className="min-w-0">
        <div className="text-[10px] text-accent uppercase tracking-wide mb-1">
          {t('milestoneToast.unlocked')}
        </div>
        <div className="text-sm font-medium">{milestone.label}</div>
      </div>
      <button
        type="button"
        onClick={onDismiss}
        aria-label={t('common:updateToast.dismiss')}
        className="shrink-0 text-pn-muted hover:text-pn px-1 text-lg leading-none -me-0.5"
      >
        ×
      </button>
    </div>
  );
}
