import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import type { NewMilestone } from './milestones';

type Props = {
  milestone: NewMilestone;
  onDismiss: () => void;
};

export function MilestoneToast({ milestone, onDismiss }: Props) {
  const { t } = useTranslation('stats');
  useEffect(() => {
    const t = window.setTimeout(onDismiss, 15000);
    return () => window.clearTimeout(t);
  }, [onDismiss]);

  return (
    <div className="fixed bottom-4 end-4 sm:bottom-6 sm:end-6 bg-surface-2 border border-divider text-pn rounded-lg px-5 py-3 shadow-xl z-40 max-w-xs">
      <div className="text-[10px] text-accent uppercase tracking-wide mb-1">
        {t('milestoneToast.unlocked')}
      </div>
      <div className="text-sm font-medium">{milestone.label}</div>
    </div>
  );
}
