import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Shield, X } from './icons';
import { PinInput, type PinInputHandle } from './PinInput';
import { MfaCancelledError, submitMfaCode, dismissMfaPrompt, type MfaPromptRequest } from './mfaStep';
import { useEscapeToClose } from './useEscapeToClose';
import { useAccountLogins } from './accountLogins';
import { accountErrorKey } from './AccountSignInSetup';

/** A backup restores the authenticator. It never goes to an app endpoint. */
export function MfaRecoveryHelp() {
  const { t } = useTranslation('security');
  return (
    <details className="text-sm text-pn-soft leading-relaxed">
      <summary className="cursor-pointer text-accent py-1">{t('mfaPrompt.lostAuthenticator')}</summary>
      <div className="pt-2 space-y-2">
        <p>{t('mfaPrompt.restore')}</p>
        <p>{t('mfaPrompt.noBackup')}</p>
      </div>
    </details>
  );
}

/** The repair swaps the session, which closes the wrong-login prompt and
 * opens the code prompt of the canonical login. It runs here, outside the
 * prompt, so that swap cannot unmount it halfway. */
function WrongLoginRepair({ onEnd }: { onEnd: (error: string | null) => void }) {
  const account = useAccountLogins();
  const started = useRef(false);
  useEffect(() => {
    if (started.current) return;
    started.current = true;
    account.activate().then(() => onEnd(null),
      (error: unknown) => onEnd(error instanceof MfaCancelledError ? null : accountErrorKey(error)));
  }, [account, onEnd]);
  return null;
}

export function MfaPromptLayer({ request }: { request: MfaPromptRequest | null }) {
  const [repairing, setRepairing] = useState(false);
  const [repairError, setRepairError] = useState<string | null>(null);
  const endRepair = useCallback((error: string | null) => { setRepairing(false); setRepairError(error); }, []);
  return <>
    {repairing && <WrongLoginRepair onEnd={endRepair} />}
    {request && <MfaPrompt request={request} onSubmit={submitMfaCode} onDismiss={dismissMfaPrompt}
      repairing={repairing} repairError={repairError}
      onRepair={() => { setRepairError(null); setRepairing(true); }} />}
  </>;
}

/** Dismissal only cancels the server operation. It never wipes local notes. */
export function MfaPrompt({ request, onSubmit, onDismiss, onRepair, repairing = false, repairError = null }: {
  request: MfaPromptRequest;
  onSubmit: (code: string) => Promise<void>;
  onDismiss: () => void;
  onRepair?: () => void;
  repairing?: boolean;
  repairError?: string | null;
}) {
  const { t } = useTranslation('security');
  const [code, setCode] = useState('');
  const titleId = useId();
  const errorId = useId();
  const input = useRef<PinInputHandle>(null);
  const dialog = useRef<HTMLDivElement>(null);
  useEscapeToClose(onDismiss);
  useEffect(() => {
    setCode('');
    const previous = document.activeElement;
    if (input.current) input.current.focus();
    else dialog.current?.querySelector<HTMLElement>('summary, button')?.focus();
    return () => { if (previous instanceof HTMLElement && previous.isConnected) previous.focus(); };
  }, [request.id]);
  useEffect(() => { if (request.error) { setCode(''); input.current?.clear(); } }, [request.error]);
  const submit = (value: string) => { if (!request.busy && /^\d{6}$/.test(value)) void onSubmit(value); };

  return (
    <div className="fixed inset-0 bg-black/50 dark:bg-black/70 flex items-center justify-center p-4 z-[80]">
      <div
        ref={dialog}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        className="bg-surface-2 border border-divider text-pn rounded-lg max-w-sm w-full p-6 space-y-4 max-h-[90dvh] overflow-y-auto"
        onKeyDown={(event) => {
          if (event.key !== 'Tab') return;
          const controls = dialog.current?.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), summary');
          if (!controls?.length) return;
          const first = controls[0];
          const last = controls[controls.length - 1];
          if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
          else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
        }}
      >
        <div className="flex items-center justify-between gap-2.5">
          <div className="flex items-center gap-2.5">
            <Shield size={20} className="text-accent shrink-0" aria-hidden="true" />
            <h2 id={titleId} className="text-lg font-semibold">{t(request.wrongLogin ? 'mfaPrompt.wrongLoginTitle' : 'mfaPrompt.title')}</h2>
          </div>
          <button type="button" onClick={onDismiss} aria-label={t('common:actions.close')}
            className="text-pn-muted hover:text-pn transition p-1 -m-1">
            <X size={18} />
          </button>
        </div>
        {request.wrongLogin ? (
          <div className="space-y-3">
            <p className="text-sm text-pn-soft leading-relaxed">{t('mfaPrompt.wrongLogin')}</p>
            {repairError && <p role="alert" className="text-sm text-danger">{t(repairError)}</p>}
            <button type="button" onClick={onRepair} disabled={repairing} className="w-full rounded-md bg-accent-fill hover:bg-accent-fill-hover text-white text-sm font-medium px-4 py-2 transition disabled:opacity-40 disabled:cursor-not-allowed">
              {t(repairing ? 'connectedAccounts.working' : 'mfaPrompt.signInAgain')}
            </button>
          </div>
        ) : (
          <form className="space-y-3" onSubmit={(event) => { event.preventDefault(); submit(code); }}>
            <p className="text-sm text-pn-soft">{t('mfaPrompt.enterCode')}</p>
            <div aria-describedby={request.error ? errorId : undefined}>
              <PinInput ref={input} value={code} onChange={setCode} onComplete={submit} length={6} reveal compact
                ariaLabel={t('mfaPrompt.codeLabel')} disabled={request.busy} />
            </div>
            {request.error && <p id={errorId} role="alert" className="text-sm text-center text-danger">{t(request.error)}</p>}
            <button type="submit" disabled={request.busy || code.length !== 6} className="w-full rounded-md bg-accent-fill hover:bg-accent-fill-hover text-white text-sm font-medium px-4 py-2 transition disabled:opacity-40 disabled:cursor-not-allowed">
              {t(request.busy ? 'mfaPrompt.verifying' : 'mfaPrompt.verify')}
            </button>
          </form>
        )}
        {!request.wrongLogin && <MfaRecoveryHelp />}
        {request.allowLocalUse && <>
          {!request.wrongLogin && <p className="text-sm text-pn-soft">{t('mfaPrompt.localNotes')}</p>}
          <button type="button" onClick={onDismiss} className="w-full rounded-md border border-divider text-pn hover:bg-surface-1 px-4 py-2 text-sm transition">
            {t('mfaPrompt.useLocalNotes')}
          </button>
        </>}
      </div>
    </div>
  );
}
