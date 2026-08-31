import { Trans, useTranslation } from 'react-i18next';
import { useEscapeToClose } from '../useEscapeToClose';
import { WarningCircle, X } from '../icons';

/**
 * Phrase-reminder confirmation shown when the user clicks Sign Out
 * unless they previously checked "Don't remind me again". Two paths:
 *   - "No, show phrase" opens the Phrase tab of Security (the explicit
 *     ask is honoured even if "Don't remind" is checked).
 *   - "Yes, sign out" tears down the session.
 *
 * unsyncedCount > 0 adds an amber warning: this device holds notes the
 * server has not confirmed. unsyncedKept picks the copy - forced
 * sign-outs (dead session) preserve those rows through the wipe, a
 * voluntary sign-out destroys them if the final flush fails. The
 * warning also forces this modal open even for users who opted out of
 * the phrase reminder (see handleSignOutClick): they consented to
 * skipping a reminder, not to data loss. Same principle as #121.
 */
export function SignOutConfirmModal({
  dontRemind,
  onDontRemindChange,
  onShowPhrase,
  onConfirmSignOut,
  unsyncedCount,
  unsyncedKept,
}: {
  dontRemind: boolean;
  onDontRemindChange: (next: boolean) => void;
  onShowPhrase: () => void;
  onConfirmSignOut: () => void;
  /** Local rows with dirty=1 at the moment the modal opened. */
  unsyncedCount: number;
  /** True when the sign-out preserves unsynced rows (forced context). */
  unsyncedKept: boolean;
}) {
  const { t } = useTranslation('notesChrome');
  useEscapeToClose(onShowPhrase);
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 dark:bg-black/70 p-4"
      onClick={onShowPhrase}
    >
      <div
        className="w-full max-w-sm rounded-lg bg-surface-2 border border-divider text-pn p-6 space-y-4"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between">
          <h2 className="text-lg font-semibold">
            {t('signOutConfirm.title')}
          </h2>
          <button
            onClick={onShowPhrase}
            className="text-neutral-400 hover:text-neutral-600 dark:hover:text-neutral-300 transition p-1 -m-1"
            aria-label={t('close')}
          >
            <X size={18} />
          </button>
        </div>
        <p className="text-sm text-neutral-600 dark:text-neutral-400 leading-relaxed">
          <Trans
            i18nKey="notesChrome:signOutConfirm.body"
            components={{ only: <strong />, action: <strong /> }}
          />
        </p>
        {unsyncedCount > 0 && (
          <div className="flex items-start gap-2 rounded-md border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/30 text-amber-800 dark:text-amber-300 text-[13px] leading-snug p-3">
            <WarningCircle size={16} className="shrink-0 mt-0.5" />
            <span>
              {t(unsyncedKept ? 'signOutConfirm.unsyncedKept' : 'signOutConfirm.unsyncedWarn', {
                count: unsyncedCount,
              })}
            </span>
          </div>
        )}
        <label className="flex items-center gap-2 text-[13px] text-neutral-500 dark:text-neutral-500 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={dontRemind}
            onChange={(e) => onDontRemindChange(e.target.checked)}
            className="accent-accent"
          />
          {t('signOutConfirm.dontRemind')}
        </label>
        <div className="flex gap-2 pt-2">
          <button
            onClick={onShowPhrase}
            className="flex-1 rounded-md border border-neutral-300 dark:border-neutral-800 hover:bg-surface-1 px-4 py-2 text-sm transition"
          >
            {t('signOutConfirm.showPhrase')}
          </button>
          <button
            onClick={onConfirmSignOut}
            className="flex-1 rounded-md bg-accent text-white hover:bg-accent-hover px-4 py-2 text-sm font-medium transition"
          >
            {t('signOutConfirm.confirm')}
          </button>
        </div>
      </div>
    </div>
  );
}
