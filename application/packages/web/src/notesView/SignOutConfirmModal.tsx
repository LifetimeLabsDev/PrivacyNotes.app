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
 * voluntary sign-out destroys them if the final flush fails.
 * unsyncedFiles > 0 adds the pictures and files the server does not hold.
 * No sign-out uploads one first; a voluntary sign-out deletes them and a
 * forced one keeps them, so only the voluntary copy names them. Either
 * count forces this modal open even for users who opted out of the phrase
 * reminder (maySkipSignOutConfirm): they consented to skipping a
 * reminder, not to data loss. Same principle as #121.
 */
export function SignOutConfirmModal({
  dontRemind,
  onDontRemindChange,
  onShowPhrase,
  onConfirmSignOut,
  onStay,
  unsyncedCount,
  unsyncedFiles,
  unsyncedKept,
  neverBackedUp,
}: {
  dontRemind: boolean;
  onDontRemindChange: (next: boolean) => void;
  onShowPhrase: () => void;
  onConfirmSignOut: () => void;
  /** Closes the confirm and keeps the session. The default action while
   *  unsynced notes or files are at stake: they rest sealed on this
   *  device, so staying costs nothing and signing out destroys them. */
  onStay: () => void;
  /** Local rows with an unsynced change (dirty 1 or 2) when the modal opened. */
  unsyncedCount: number;
  /** Pictures and files waiting to upload or refused for good at the
   *  moment the modal opened (countOnlyOnThisDevice). */
  unsyncedFiles: number;
  /** True when the sign-out preserves unsynced rows (forced context). */
  unsyncedKept: boolean;
  /** The subset that exists on this device only (neverBackedUp.ts). */
  neverBackedUp: ReadonlyArray<{ id: string; title: string }>;
}) {
  const { t } = useTranslation('notesChrome');
  // With unsynced rows or files at stake, every dismissal keeps the
  // session; the phrase escape hatch stays as an explicit button.
  const filesAtRisk = unsyncedFiles > 0 && !unsyncedKept;
  const risky = (unsyncedCount > 0 && !unsyncedKept) || filesAtRisk;
  const loseLabel = !filesAtRisk
    ? t('signOutConfirm.signOutLose', { count: unsyncedCount })
    : unsyncedCount > 0
      ? t('signOutConfirm.signOutLoseBoth', {
          count: unsyncedCount,
          files: t('signOutConfirm.fileCount', { count: unsyncedFiles }),
        })
      : t('signOutConfirm.signOutLoseFiles', { count: unsyncedFiles });
  const dismiss = risky ? onStay : onShowPhrase;
  useEscapeToClose(dismiss);
  const shown = neverBackedUp.slice(0, 5);
  const more = neverBackedUp.length - shown.length;
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 dark:bg-black/70 p-4"
      onClick={dismiss}
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
            onClick={dismiss}
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
        {(unsyncedCount > 0 || filesAtRisk) && (
          <div className="flex items-start gap-2 rounded-md border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/30 text-amber-800 dark:text-amber-300 text-[13px] leading-snug p-3">
            <WarningCircle size={16} className="shrink-0 mt-0.5" />
            <div className="space-y-2">
              {unsyncedCount > 0 && (
                <p>
                  {t(unsyncedKept ? 'signOutConfirm.unsyncedKept' : 'signOutConfirm.unsyncedWarn', {
                    count: unsyncedCount,
                  })}
                </p>
              )}
              {filesAtRisk && <p>{t('signOutConfirm.unsyncedFilesWarn', { count: unsyncedFiles })}</p>}
              {risky && shown.length > 0 && (
                <div>
                  <p className="font-medium">{t('signOutConfirm.neverBackedUp', { count: neverBackedUp.length })}</p>
                  <ul className="mt-1 list-disc ps-4 space-y-0.5">
                    {shown.map((n) => (
                      <li key={n.id} className="truncate" dir="auto">{n.title}</li>
                    ))}
                    {more > 0 && <li className="list-none -ms-4 opacity-80">{t('signOutConfirm.moreNotes', { count: more })}</li>}
                  </ul>
                </div>
              )}
              {risky && <p className="opacity-90">{t('signOutConfirm.appLockHint')}</p>}
            </div>
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
        {risky ? (
          // Data at stake: the primary action keeps it, and the sign-out
          // names its cost. Two clicks to lose data is the point.
          <div className="space-y-2 pt-2">
            <div className="flex gap-2">
              <button
                onClick={onShowPhrase}
                className="flex-1 rounded-md border border-neutral-300 dark:border-neutral-800 hover:bg-surface-1 px-4 py-2 text-sm transition"
              >
                {t('signOutConfirm.showPhrase')}
              </button>
              <button
                onClick={onStay}
                className="flex-1 rounded-md bg-accent text-white hover:bg-accent-hover px-4 py-2 text-sm font-medium transition"
              >
                {t('signOutConfirm.stay')}
              </button>
            </div>
            <button
              onClick={onConfirmSignOut}
              className="w-full rounded-md border border-red-300 dark:border-red-900 text-red-700 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/30 px-4 py-2 text-sm transition"
            >
              {loseLabel}
            </button>
          </div>
        ) : (
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
        )}
      </div>
    </div>
  );
}
