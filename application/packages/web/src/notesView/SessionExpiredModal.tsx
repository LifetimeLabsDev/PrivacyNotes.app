import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { logAuthEvent } from '../authDiag';
import { WarningCircle } from '../icons';
import { Modal } from '../ui';

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
    <Modal title={t('sessionExpired.title')} icon={<WarningCircle size={16} />} layer="z-[70]" className="max-w-sm p-6 space-y-4">
        <p className="text-sm text-pn-muted leading-relaxed">
          {t('sessionExpired.body')}
        </p>
        <button
          type="button"
          onClick={onSignOut}
          className="w-full rounded-md bg-accent-fill hover:bg-accent-fill-hover text-white text-sm font-medium px-3 py-2.5 transition"
        >
          {t('sessionExpired.signInAgain')}
        </button>
    </Modal>
  );
}
