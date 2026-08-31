import { useTranslation } from 'react-i18next';

/**
 * Sync-error banner shown when one or more notes failed to push for a
 * non-quota, non-auth reason during the most recent sync. The notes
 * stay `dirty=1` and retry on the next sync pass - this banner exists
 * so a persistent failure (e.g. a 1 MB CHECK violation, a novel
 * server-side reject) doesn't stay invisible. See gap #4.
 *
 * Visibility is owned by the parent (NotesView) so dismissal can flip
 * the same state that drives the read.
 */
export function SyncErrorBanner({
  count,
  lastMessage,
  onDismiss,
}: {
  count: number;
  lastMessage: string;
  onDismiss: () => void;
}) {
  const { t } = useTranslation('notesChrome');
  return (
    <div className="flex items-center justify-between gap-2 border-b text-sm px-4 py-2 bg-amber-50 dark:bg-amber-950/30 border-amber-300 dark:border-amber-800 text-amber-800 dark:text-amber-300">
      <span>
        {t('syncError.failed', { count })}
        {lastMessage && (
          <span className="ms-1 opacity-80">{t('syncError.lastError', { message: lastMessage })}</span>
        )}
      </span>
      <button
        type="button"
        onClick={onDismiss}
        className="text-amber-600 dark:text-amber-500 hover:text-amber-900 dark:hover:text-amber-200 shrink-0"
        aria-label={t('dismiss')}
      >
        ×
      </button>
    </div>
  );
}
