import { useEffect, useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { SETTINGS_HELP, SectionEyebrow, SettingsCallout } from './settingsUI';
import { PROVIDER_ICON, PROVIDER_NAME } from './providerIcons';

export type ConnectedAccountProvider = 'google' | 'apple' | 'github';
export type ConnectedAccount = { id: string; provider: ConnectedAccountProvider; email: string };

type Confirmation = { kind: 'connect'; provider: ConnectedAccountProvider }
  | { kind: 'disconnect'; accountId: string };

const PROVIDERS: ConnectedAccountProvider[] = ['google', 'apple', 'github'];
const BUTTON = 'rounded-md border border-divider px-3 py-2 text-sm text-pn-soft hover:bg-surface-1 transition disabled:opacity-40 disabled:cursor-not-allowed';

/** Logo, brand name and one line under it, the same in every account row. */
export function ProviderLabel({ provider, detail }: { provider: ConnectedAccountProvider; detail?: string }) {
  const Icon = PROVIDER_ICON[provider];
  return <div className="flex min-w-0 flex-1 items-center gap-3">
    <span className="flex h-5 w-5 shrink-0 items-center justify-center text-pn"><Icon /></span>
    <div className="min-w-0">
      <p className="text-sm text-pn">{PROVIDER_NAME[provider]}</p>
      {detail && <p className="break-all text-xs text-pn-soft">{detail}</p>}
    </div>
  </div>;
}

function normalizedPhrase(value: string): string {
  return value.trim().toLowerCase().replace(/\s+/g, ' ');
}

/** Presentation and saved-copy confirmation only. The adapter owns session
 * binding, fresh MFA, and reconciliation before its callbacks resolve. */
export function ConnectedAccounts({
  accounts, error, unavailable, busy, isCustodial, mfaEnabled, phrase,
  onRetry, onConnect, onDisconnect, onOpenCustody, onOpenPhrase,
}: {
  accounts: ConnectedAccount[] | null;
  error: string | null;
  unavailable: boolean;
  busy: boolean;
  isCustodial: boolean;
  mfaEnabled: boolean;
  phrase: string;
  onRetry: () => void;
  onConnect: (provider: ConnectedAccountProvider) => Promise<void>;
  onDisconnect: (accountId: string) => Promise<void>;
  onOpenCustody: () => void;
  onOpenPhrase?: () => void;
}) {
  const { t } = useTranslation('security');
  const titleId = useId();
  const phraseId = useId();
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const [answer, setAnswer] = useState('');
  const [working, setWorking] = useState(false);
  const [failed, setFailed] = useState(false);
  const [completed, setCompleted] = useState<'connect' | 'disconnect' | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const formRef = useRef<HTMLFormElement>(null);
  const triggerRef = useRef<HTMLElement | null>(null);
  const operation = useRef(0);
  const inFlight = useRef(false);
  const alive = useRef(false);
  const vaultPhrase = useRef(phrase);
  vaultPhrase.current = phrase;
  const blocked = busy || working || unavailable || accounts === null;
  const account = confirmation?.kind === 'disconnect'
    ? accounts?.find((entry) => entry.id === confirmation.accountId) : null;
  const lastCustodialAccount = Boolean(isCustodial && account && accounts?.length === 1);
  const savedPhraseMatches = normalizedPhrase(phrase).split(' ').length === 12
    && normalizedPhrase(answer) === normalizedPhrase(phrase);

  useEffect(() => {
    alive.current = true;
    return () => { alive.current = false; operation.current++; };
  }, []);

  useEffect(() => {
    operation.current++;
    inFlight.current = false;
    setConfirmation(null);
    setAnswer('');
    setWorking(false);
    setFailed(false);
    setCompleted(null);
  }, [phrase, isCustodial]);

  useEffect(() => {
    if (confirmation) (inputRef.current ?? formRef.current?.querySelector<HTMLElement>('h3'))?.focus();
  }, [confirmation]);

  function reset() {
    setConfirmation(null);
    setAnswer('');
    setFailed(false);
    if (triggerRef.current?.isConnected) triggerRef.current.focus();
  }

  function confirm(next: Confirmation) {
    if (blocked) return;
    setAnswer('');
    setFailed(false);
    setCompleted(null);
    triggerRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    setConfirmation(next);
  }

  function openCustody(viewPhrase = false) {
    if (busy || working) return;
    reset();
    if (viewPhrase && onOpenPhrase) onOpenPhrase();
    else onOpenCustody();
  }

  async function submit() {
    if (blocked || inFlight.current || !confirmation) return;
    if (confirmation.kind === 'disconnect' && (!account || lastCustodialAccount || !savedPhraseMatches)) return;
    const requested = confirmation;
    const owner = phrase;
    const currentOperation = ++operation.current;
    inFlight.current = true;
    setWorking(true);
    setFailed(false);
    const isCurrent = () => alive.current && operation.current === currentOperation && vaultPhrase.current === owner;
    try {
      if (requested.kind === 'connect') await onConnect(requested.provider);
      else await onDisconnect(requested.accountId);
      if (!isCurrent()) return;
      reset();
      setCompleted(requested.kind);
    } catch {
      // Error details come from the adapter's safe, translated error prop.
      // Never render a raw OAuth error, URL, or credential-bearing response.
      if (isCurrent()) setFailed(true);
    } finally {
      if (isCurrent()) { inFlight.current = false; setWorking(false); }
    }
  }

  const providerName = (provider: ConnectedAccountProvider) => t(`connectedAccounts.providers.${provider}`);
  const remaining = (accounts ?? []).filter((entry) => entry.id !== account?.id);
  const remainingNames = [...new Set(remaining.map((entry) => providerName(entry.provider)))].join(', ');

  return (
    <section className="space-y-3">
      <SectionEyebrow setting="account.connectedAccounts">{t('connectedAccounts.title')}</SectionEyebrow>
      <p className={SETTINGS_HELP}>{t('connectedAccounts.description')}</p>
      <SettingsCallout>
        <p>{t(isCustodial ? 'connectedAccounts.custodial' : 'connectedAccounts.selfCustody')}</p>
        {mfaEnabled && <p className="mt-1">{t('connectedAccounts.mfaRequired')}</p>}
      </SettingsCallout>

      {unavailable ? <div className="space-y-2">
        <p className={SETTINGS_HELP}>{t('connectedAccounts.unavailable')}</p>
        {!error && <button type="button" className={BUTTON} disabled={busy || working}
          onClick={onRetry}>{t('connectedAccounts.retry')}</button>}
      </div> : (
        <>
          {accounts === null && !error && <p role="status" className={SETTINGS_HELP}>{t('connectedAccounts.loading')}</p>}
          {accounts !== null && (
            <div className="divide-y divide-divider rounded-md border border-divider">
              {accounts.map((entry) => (
                <div key={entry.id} className="flex flex-wrap items-center justify-between gap-2 p-3">
                  <ProviderLabel provider={entry.provider} detail={entry.email || t('connectedAccounts.emailHidden')} />
                  <button type="button" className={BUTTON} disabled={blocked}
                    aria-label={t('connectedAccounts.disconnectAccount', { provider: providerName(entry.provider), email: entry.email })}
                    onClick={() => confirm({ kind: 'disconnect', accountId: entry.id })}>
                    {t('connectedAccounts.disconnect')}
                  </button>
                </div>
              ))}
              {PROVIDERS.map((provider) => (
                <div key={provider} className="flex flex-wrap items-center justify-between gap-2 p-3">
                  <ProviderLabel provider={provider} />
                  <button type="button" className={BUTTON} disabled={blocked}
                    onClick={() => confirm({ kind: 'connect', provider })}>
                    {t(accounts.some((entry) => entry.provider === provider) ? 'connectedAccounts.connectAnotherProvider' : 'connectedAccounts.connectProvider', { provider: providerName(provider) })}
                  </button>
                </div>
              ))}
            </div>
          )}
          {accounts?.length === 0 && <p className={SETTINGS_HELP}>{t('connectedAccounts.noAccounts')}</p>}
        </>
      )}

      {(error || failed) && <div role="alert" className="space-y-2">
        <p className="text-xs text-red-600 dark:text-red-400">{error || t('connectedAccounts.actionFailed')}</p>
        <button type="button" className={BUTTON} disabled={busy || working}
          onClick={() => { setFailed(false); onRetry(); }}>{t('connectedAccounts.retry')}</button>
      </div>}
      {completed && <p role="status" className={SETTINGS_HELP}>{t(`connectedAccounts.${completed}Done`)}</p>}

      {confirmation && (
        <form ref={formRef} className="space-y-3 rounded-md border border-divider bg-track p-3"
          aria-labelledby={titleId} onSubmit={(event) => { event.preventDefault(); void submit(); }}>
          {confirmation.kind === 'connect' ? (
            <>
              <h3 id={titleId} tabIndex={-1} className="text-sm font-medium text-pn">
                {t('connectedAccounts.confirmConnect', { provider: providerName(confirmation.provider) })}
              </h3>
              <p className={SETTINGS_HELP}>{t('connectedAccounts.connectKeepsCustody')}</p>
              <p className={SETTINGS_HELP}>{t('connectedAccounts.noMerge')}</p>
              {mfaEnabled && <p className={SETTINGS_HELP}>{t('connectedAccounts.freshMfa')}</p>}
              <div className="flex flex-wrap gap-2">
                <button type="submit" disabled={blocked} className="rounded-md bg-accent px-3 py-2 text-sm text-white hover:bg-accent-hover disabled:opacity-40 disabled:cursor-not-allowed">
                  {working ? t('connectedAccounts.working') : t('connectedAccounts.continueProvider', { provider: providerName(confirmation.provider) })}
                </button>
                <button type="button" disabled={busy || working} onClick={reset} className={BUTTON}>{t('connectedAccounts.cancel')}</button>
              </div>
            </>
          ) : (
            <>
              <h3 id={titleId} tabIndex={-1} className="text-sm font-medium text-pn">
                {t('connectedAccounts.confirmDisconnect', { provider: account ? providerName(account.provider) : t('connectedAccounts.account') })}
              </h3>
              {account && <p className="break-all text-xs text-pn-soft">{account.email}</p>}
              {lastCustodialAccount ? (
                <>
                  <SettingsCallout>{t('connectedAccounts.lastCustodial')}</SettingsCallout>
                  <button type="button" disabled={busy || working} className={BUTTON} onClick={() => openCustody()}>
                    {t('connectedAccounts.openCustody')}
                  </button>
                </>
              ) : (
                <>
                  <p className={SETTINGS_HELP}>{t(remaining.length ? 'connectedAccounts.remainingAccounts' : 'connectedAccounts.phraseOnly', { providers: remainingNames })}</p>
                  {mfaEnabled && <p className={SETTINGS_HELP}>{t('connectedAccounts.freshMfa')}</p>}
                  <p className={SETTINGS_HELP}>{t('connectedAccounts.confirmSavedPhrase')}</p>
                  <label htmlFor={phraseId} className="block text-xs text-pn-soft">{t('connectedAccounts.savedPhrase')}</label>
                  <input ref={inputRef} id={phraseId} type="password" value={answer} dir="ltr"
                    autoComplete="off" autoCapitalize="none" autoCorrect="off" spellCheck={false}
                    disabled={blocked} onChange={(event) => setAnswer(event.target.value)}
                    className="w-full rounded-md border border-divider bg-surface-1 px-3 py-2 text-sm text-pn focus:outline-none focus:ring-2 focus:ring-accent/40" />
                  <button type="button" className="text-xs text-accent hover:underline disabled:opacity-40"
                    disabled={busy || working} onClick={() => openCustody(true)}>{t('connectedAccounts.savePhrase')}</button>
                </>
              )}
              <div className="flex flex-wrap gap-2">
                {!lastCustodialAccount && <button type="submit" disabled={blocked || !account || !savedPhraseMatches}
                  className="rounded-md border border-red-500/40 px-3 py-2 text-sm text-red-600 dark:text-red-400 disabled:opacity-40">
                  {working ? t('connectedAccounts.working') : t('connectedAccounts.confirmRemoval')}
                </button>}
                <button type="button" disabled={busy || working} onClick={reset} className={BUTTON}>{t('connectedAccounts.cancel')}</button>
              </div>
            </>
          )}
        </form>
      )}
    </section>
  );
}
