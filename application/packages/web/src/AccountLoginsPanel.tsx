import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useAuth } from './auth';
import { useAccountLogins } from './accountLogins';
import { AccountConnectionError, beginAccountConnection, type AccountConnection } from './accountConnection';
import { accountErrorKey, AccountSignInSetup } from './AccountSignInSetup';
import { ConnectedAccounts, ProviderLabel, type ConnectedAccountProvider } from './ConnectedAccounts';
import { mfaSessionIdentity } from './sessionWriteGuard';
import { isDemoMode } from './demo';
import { SETTINGS_HELP, SectionEyebrow } from './settingsUI';
import { BetaReportLink } from './BetaReportLink';

const PROVIDERS: ConnectedAccountProvider[] = ['google', 'apple', 'github'];

/** Only mounts for a real, open vault. All network mutations stay in the
 * account adapter; OAuth here is an isolated proof that cannot sign in. */
export function AccountLoginsPanel({ onOpenCustody, onOpenPhrase, autoFocus = false }: { onOpenCustody: () => void; onOpenPhrase?: () => void; autoFocus?: boolean }) {
  if (isDemoMode()) return null;
  return <RealAccountLoginsPanel onOpenCustody={onOpenCustody} onOpenPhrase={onOpenPhrase} autoFocus={autoFocus} />;
}

function RealAccountLoginsPanel({ onOpenCustody, onOpenPhrase, autoFocus }: { onOpenCustody: () => void; onOpenPhrase?: () => void; autoFocus: boolean }) {
  const { t } = useTranslation('security');
  const { auth, supabase } = useAuth();
  const account = useAccountLogins();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [connection, setConnection] = useState<AccountConnection | null>(null);
  const [returnUrl, setReturnUrl] = useState('');
  const [invalidReturn, setInvalidReturn] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const controller = useRef<AbortController | null>(null);
  const alive = useRef(false);
  const working = useRef(false);
  const operation = useRef(0);
  const pubkey = auth.status === 'authenticated' ? auth.pubkey : null;
  const livePubkey = useRef(pubkey); livePubkey.current = pubkey;

  useEffect(() => {
    alive.current = true;
    return () => { alive.current = false; operation.current++; controller.current?.abort(); };
  }, []);
  useEffect(() => {
    operation.current++;
    controller.current?.abort(); controller.current = null;
    working.current = false; setBusy(false); setConnection(null); setReturnUrl(''); setError(null);
  }, [pubkey]);
  useEffect(() => { if (autoFocus) root.current?.scrollIntoView?.({ block: 'start' }); }, [autoFocus]);
  // How this session signed in, read from the session the SDK holds. Before
  // account setup the server keeps no list of connections, so this is the one
  // sign-in method the tab can name.
  const [signedIn, setSignedIn] = useState<{ provider: ConnectedAccountProvider | null; email: string } | null>(null);
  useEffect(() => {
    let cancelled = false;
    void supabase.auth.getSession().then(({ data }) => {
      const user = data.session?.user;
      if (cancelled || !user || user.app_metadata?.pubkey !== pubkey) return;
      const claim = user.app_metadata?.provider;
      setSignedIn({ provider: PROVIDERS.find((entry) => entry === claim) ?? null, email: user.email ?? '' });
    }, () => {});
    return () => { cancelled = true; setSignedIn(null); };
  }, [supabase, pubkey]);

  async function connect(provider: ConnectedAccountProvider) {
    if (working.current || !pubkey || account.loading || !account.status?.managed) throw new Error('account_not_ready');
    const epoch = ++operation.current;
    working.current = true; setBusy(true); setError(null); setReturnUrl(''); setInvalidReturn(false);
    const abort = new AbortController(); controller.current = abort;
    let actor: string | null = null;
    let unsubscribe: (() => void) | undefined;
    const current = () => alive.current && operation.current === epoch && livePubkey.current === pubkey && !abort.signal.aborted;
    const flow = beginAccountConnection(provider, { signal: abort.signal, prepare: async () => {
      const initial = await supabase.auth.getSession();
      actor = mfaSessionIdentity(initial.data.session);
      if (!current() || initial.error || !actor || initial.data.session?.user.app_metadata.pubkey !== pubkey) throw new Error('account_changed');
      const { data } = supabase.auth.onAuthStateChange((_event, session) => {
        if (mfaSessionIdentity(session) !== actor) abort.abort();
      });
      unsubscribe = () => data.subscription.unsubscribe();
      // Close the subscribe/read race without an SDK call inside the event.
      const latest = await supabase.auth.getSession();
      if (!current() || latest.error || mfaSessionIdentity(latest.data.session) !== actor) throw new Error('account_changed');
    } });
    setConnection(flow);
    try {
      const proof = await flow.result;
      if (!current() || !actor) throw new AccountConnectionError('connectCancelled');
      setConnection(null); setReturnUrl('');
      await account.connect({ ...proof, expectedIdentity: actor, expectedProvider: provider });
      if (!current()) throw new AccountConnectionError('connectCancelled');
    } catch (failure) {
      if (alive.current && operation.current === epoch) setError(t(failure instanceof AccountConnectionError
        ? `connectedAccounts.${failure.reason}` : accountErrorKey(failure)));
      throw failure;
    } finally {
      unsubscribe?.();
      abort.abort();
      if (alive.current && operation.current === epoch) {
        controller.current = null; working.current = false; setBusy(false); setConnection(null); setReturnUrl('');
      }
    }
  }

  if (auth.status !== 'authenticated') return null;
  const status = account.status;
  const backendUnavailable = account.error === 'account_setup_unavailable';
  return <div ref={root} className="space-y-3">
    {status && (!status.managed || status.wrong_login || status.deleted) ? <>
      <SectionEyebrow setting="account.connectedAccounts">{t('connectedAccounts.title')}</SectionEyebrow>
      {!status.managed && signedIn && <>
        <p className={SETTINGS_HELP}>{t('connectedAccounts.description')}</p>
        <div className="divide-y divide-divider rounded-md border border-divider">
          {PROVIDERS.map((provider) => <div key={provider} className="flex items-center justify-between gap-2 p-3">
            <ProviderLabel provider={provider} detail={signedIn.provider === provider ? signedIn.email || t('connectedAccounts.emailHidden') : undefined} />
            {signedIn.provider === provider && <span className="shrink-0 text-xs text-accent">{t('connectedAccounts.signedInNow')}</span>}
          </div>)}
        </div>
        {!signedIn.provider && <p className={SETTINGS_HELP}>{t('connectedAccounts.signedInPhrase')}</p>}
      </>}
      <AccountSignInSetup purpose="accounts" onReady={() => { void account.refresh().catch(() => {}); }} />
    </> : <ConnectedAccounts
      accounts={status ? status.connections.filter((entry) => entry.active).map((entry) => ({ ...entry, email: entry.email ?? '' })) : null}
      error={error || (account.error && !backendUnavailable ? t('custody.connectionsUnavailable') : null)}
      unavailable={backendUnavailable || Boolean(status && (status.deleted || status.wrong_login || account.mfaEnabled === null))}
      busy={busy || account.loading} isCustodial={status?.custodial ?? auth.isCustodial}
      mfaEnabled={account.mfaEnabled === true} phrase={auth.phrase}
      onRetry={() => { setError(null); void account.refresh().catch(() => {}); }}
      onConnect={connect} onDisconnect={async (id) => {
        const epoch = operation.current;
        const owner = livePubkey.current;
        setError(null);
        try { await account.disconnect(id); }
        catch (failure) {
          if (alive.current && operation.current === epoch && livePubkey.current === owner) setError(t(accountErrorKey(failure)));
          throw failure;
        }
      }} onOpenCustody={onOpenCustody} onOpenPhrase={onOpenPhrase}
    />}
    {connection && <div className="rounded-md border border-divider bg-track p-3 space-y-3">
      <p role="status" className={SETTINGS_HELP}>{t('connectedAccounts.connectWaiting')}</p>
      {(connection.platform === 'desktop' || connection.platform === 'web') && <form className="space-y-2"
        onSubmit={(event) => { event.preventDefault(); setInvalidReturn(!connection.acceptReturn(returnUrl.trim())); }}>
        <label className="block text-xs text-pn-soft">
          {t('connectedAccounts.returnLink')}
          <input type="text" value={returnUrl} dir="ltr" maxLength={16384} autoComplete="off" autoCapitalize="none" autoCorrect="off" spellCheck={false}
            onChange={(event) => { setReturnUrl(event.target.value); setInvalidReturn(false); }}
            className="mt-1 w-full rounded-md border border-divider bg-surface-1 px-3 py-2 text-sm text-pn" />
        </label>
        <p className={SETTINGS_HELP}>{t('connectedAccounts.returnHelp')}</p>
        {invalidReturn && <p role="alert" className="text-xs text-red-600 dark:text-red-400">{t('connectedAccounts.invalidReturn')}</p>}
        <button type="submit" disabled={!returnUrl.trim()} className="text-sm text-accent disabled:opacity-40">{t('connectedAccounts.finishConnection')}</button>
      </form>}
      <button type="button" className="text-sm text-accent" onClick={() => controller.current?.abort()}>{t('connectedAccounts.cancelConnection')}</button>
    </div>}
    <BetaReportLink />
  </div>;
}
