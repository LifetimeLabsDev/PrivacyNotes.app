import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useAccountLogins } from './accountLogins';
import { useAuth } from './auth';
import { SETTINGS_HELP, SettingsCallout } from './settingsUI';

/** Only known server refusals get specific copy; transport text is never
 * rendered as if it were a user-facing explanation. */
export function accountErrorKey(error: unknown): string {
  const message = typeof error === 'string' ? error : (error as { message?: unknown } | null)?.message;
  switch (message) {
    case 'account_alias_conflict': return 'connectedAccounts.anotherVault';
    case 'account_last_custodial_provider': case 'account_custody_provider_required': return 'connectedAccounts.lastCustodial';
    case 'account_too_many_requests': case 'auth_rate_limited': return 'connectedAccounts.rateLimited';
    case 'account_setup_unavailable': return 'connectedAccounts.unavailable';
    case 'account_connection_missing': return 'connectedAccounts.connectionMissing';
    default: return 'connectedAccounts.actionFailed';
  }
}

/** One explicit transition before account management or first MFA setup.
 * Mounting this screen never activates or changes the account. The accounts
 * purpose names the step by what it is for, and while setup is closed it
 * shows one line instead of a step nobody can take. */
export function AccountSignInSetup({ onReady, purpose = 'twoFactor' }: { onReady?: () => void; purpose?: 'accounts' | 'twoFactor' }) {
  const { t } = useTranslation('security');
  const account = useAccountLogins();
  const { auth } = useAuth();
  const pubkey = auth.status === 'authenticated' ? auth.pubkey : null;
  const [acknowledged, setAcknowledged] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const working = useRef(false);
  const alive = useRef(false);
  const generation = useRef(0);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  useEffect(() => {
    generation.current++;
    working.current = false; setBusy(false); setAcknowledged(false); setFailed(false);
  }, [pubkey]);
  const repairing = Boolean(account.status?.managed && !account.status.deleted && account.status.wrong_login);
  const reclaiming = Boolean(account.status?.deleted);
  const allowed = repairing || Boolean(account.status?.setup_enabled && (reclaiming || !account.status.wrong_login));
  const forAccounts = purpose === 'accounts' && !repairing && !reclaiming;
  async function activate() {
    if (!allowed || (!repairing && !acknowledged) || working.current) return;
    const epoch = generation.current;
    working.current = true; setBusy(true); setFailed(false);
    try {
      await account.activate();
      if (alive.current && generation.current === epoch) onReady?.();
    } catch { if (alive.current && generation.current === epoch) setFailed(true); }
    finally { if (alive.current && generation.current === epoch) { working.current = false; setBusy(false); } }
  }
  const closed = Boolean(account.status && !allowed) || account.error === 'account_setup_unavailable';
  return <div className="space-y-3">
    {!(forAccounts && closed) && <SettingsCallout>
      <p className="font-medium">{t(repairing ? 'connectedAccounts.repairTitle' : reclaiming ? 'connectedAccounts.reclaimTitle' : forAccounts ? 'connectedAccounts.setupTitle' : 'connectedAccounts.updateTitle')}</p>
      <p className="mt-1">{t(repairing ? 'connectedAccounts.repairDescription' : reclaiming ? 'connectedAccounts.reclaimDescription' : forAccounts ? 'connectedAccounts.setupDescription' : 'connectedAccounts.updateDescription')}</p>
      {!repairing && <p className="mt-1">{t('connectedAccounts.updateDevices')}</p>}
    </SettingsCallout>}
    {account.loading && <p role="status" className={SETTINGS_HELP}>{t('connectedAccounts.loading')}</p>}
    {closed && <p className={SETTINGS_HELP}>{t(forAccounts ? 'connectedAccounts.closed' : 'connectedAccounts.unavailable')}</p>}
    {((account.error && account.error !== 'account_setup_unavailable') || failed) && <p role="alert" className="text-xs text-red-600 dark:text-red-400">{t(failed ? accountErrorKey(account.error) : 'custody.connectionsUnavailable')}</p>}
    {!account.loading && (!account.status || account.error) && <button type="button" disabled={busy}
      className="text-sm text-accent" onClick={() => void account.refresh().catch(() => {})}>{t('connectedAccounts.retry')}</button>}
    {allowed && <>
      {!repairing && <label className="flex items-start gap-2 text-sm text-pn-soft">
        <input type="checkbox" checked={acknowledged} disabled={busy} className="mt-1 accent-accent"
          onChange={(event) => setAcknowledged(event.target.checked)} />
        <span>{t('connectedAccounts.updateAcknowledgment')}</span>
      </label>}
      <button type="button" disabled={busy || account.loading || (!repairing && !acknowledged)} onClick={() => void activate()}
        className="rounded-md bg-accent text-white hover:bg-accent-hover px-3 py-2 text-sm disabled:opacity-40 disabled:cursor-not-allowed">
        {t(busy ? 'connectedAccounts.working' : repairing ? 'connectedAccounts.repairAction' : reclaiming ? 'connectedAccounts.reclaimAction' : forAccounts ? 'connectedAccounts.setupAction' : 'connectedAccounts.updateAction')}
      </button>
    </>}
  </div>;
}
