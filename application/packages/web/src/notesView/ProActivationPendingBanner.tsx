import { useTranslation } from 'react-i18next';

export function ProActivationPendingBanner({
  onDismiss,
}: {
  onDismiss: () => void;
}) {
  const { t } = useTranslation('notes');
  return (
    <div className="flex items-center justify-between gap-2 border-b text-sm px-4 py-2 bg-amber-50 dark:bg-amber-950/30 border-amber-300 dark:border-amber-800 text-amber-800 dark:text-amber-300">
      <span>
        {t('banner.proActivationPending')}
      </span>
      <button
        type="button"
        onClick={onDismiss}
        className="text-amber-600 dark:text-amber-500 hover:text-amber-900 dark:hover:text-amber-200 shrink-0"
        aria-label={t('banner.dismiss')}
      >
        ×
      </button>
    </div>
  );
}
