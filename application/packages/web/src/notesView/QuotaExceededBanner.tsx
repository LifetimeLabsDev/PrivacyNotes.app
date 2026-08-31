import { useTranslation } from 'react-i18next';

/**
 * Storage-quota warning banner pinned below the header. Three states:
 *  - Sync frozen (90+ days over):     red, non-dismissable
 *  - Grace period (1..89 days):       amber, with a remaining-days hint
 *  - Just-now exceeded:               amber, generic message
 *
 * Copy and CTA adapt to whether the storage add-on is purchasable
 * (`storageConfigured`). When Paddle isn't wired (self-host, dev, env
 * vars missing), the banner stops suggesting "re-subscribe" - there's
 * nothing to subscribe to - and points users at trimming notes
 * instead. See gap #25.
 *
 * Visibility is owned by the parent (NotesView) so dismissal can flip
 * the same state that drives the read.
 */
export function QuotaExceededBanner({
  quotaExceededSince,
  storageConfigured,
  onManageStorage,
  onDismiss,
}: {
  quotaExceededSince: string | null;
  storageConfigured: boolean;
  onManageStorage: () => void;
  onDismiss: () => void;
}) {
  const { t } = useTranslation('notesChrome');
  const graceDaysRemaining = quotaExceededSince
    ? Math.max(0, 90 - Math.floor((Date.now() - new Date(quotaExceededSince).getTime()) / 86400000))
    : null;
  const syncFrozen = graceDaysRemaining !== null && graceDaysRemaining <= 0;
  const isGracePeriod = graceDaysRemaining !== null && graceDaysRemaining > 0;

  const message = (() => {
    if (syncFrozen) {
      return storageConfigured
        ? t('quota.frozen.configured')
        : t('quota.frozen.unconfigured');
    }
    if (isGracePeriod) {
      return storageConfigured
        ? t('quota.grace.configured', { count: graceDaysRemaining })
        : t('quota.grace.unconfigured', { count: graceDaysRemaining });
    }
    return storageConfigured
      ? t('quota.full.configured')
      : t('quota.full.unconfigured');
  })();

  const ctaLabel = storageConfigured ? t('quota.manageStorage') : t('quota.viewUsage');

  return (
    <div className={`flex items-center justify-between gap-2 border-b text-sm px-4 py-2 ${
      syncFrozen
        ? 'bg-red-50 dark:bg-red-950/30 border-red-300 dark:border-red-800 text-red-800 dark:text-red-300'
        : 'bg-amber-50 dark:bg-amber-950/30 border-amber-300 dark:border-amber-800 text-amber-800 dark:text-amber-300'
    }`}>
      <span>{message}</span>
      <div className="flex items-center gap-2 shrink-0">
        <button
          type="button"
          onClick={onManageStorage}
          className="text-xs font-medium underline hover:no-underline"
        >
          {ctaLabel}
        </button>
        {!syncFrozen && (
          <button
            type="button"
            onClick={onDismiss}
            className={syncFrozen
              ? 'text-red-600 dark:text-red-500 hover:text-red-900 dark:hover:text-red-200'
              : 'text-amber-600 dark:text-amber-500 hover:text-amber-900 dark:hover:text-amber-200'}
            aria-label={t('dismiss')}
          >
            ×
          </button>
        )}
      </div>
    </div>
  );
}
