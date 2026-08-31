import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { logAuthEvent } from '../authDiag';
import { WarningCircle } from '../icons';

/**
 * Hard-block modal shown when the Supabase session has expired or the
 * device has been revoked. The only path forward is signing in again.
 *
 * Deliberately NOT escapable, and its button does NOT sign out
 * directly: `signOut()` erases the stored phrase, the biometric- and
 * PIN-wrapped phrase blobs and the whole local database, so a user who
 * never wrote their phrase down would lose the vault permanently. The
 * caller routes this through the same phrase-backup confirm the
 * voluntary sign-out uses. Escape used to run the wipe on a keypress -
 * removed. Backlog #121.
 */
export function SessionExpiredModal({ onSignOut }: { onSignOut: () => void }) {
  const { t } = useTranslation('notesChrome');
  // Anchors the breadcrumb timeline to the moment the user saw the
  // modal - mount fires once per shown modal, so no dedupe needed.
  useEffect(() => {
    logAuthEvent('ui:session-expired-modal');
  }, []);
  return (
    <div className="fixed inset-0 bg-black/50 dark:bg-black/70 flex items-center justify-center p-4 z-[70]">
      <div className="bg-surface-2 border border-divider text-pn rounded-lg max-w-sm w-full p-6 space-y-4">
        <div className="flex items-center gap-2.5">
          <WarningCircle size={20} className="text-amber-500 shrink-0" />
          <h2 className="text-lg font-semibold">{t('sessionExpired.title')}</h2>
        </div>
        <p className="text-sm text-neutral-600 dark:text-neutral-400 leading-relaxed">
          {t('sessionExpired.body')}
        </p>
        <button
          type="button"
          onClick={onSignOut}
          className="w-full rounded-md bg-accent hover:bg-accent-hover text-white text-sm font-medium px-3 py-2.5 transition"
        >
          {t('sessionExpired.signInAgain')}
        </button>
      </div>
    </div>
  );
}
