import { useEffect, useRef, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { clearPinFailures, getPinLockoutState, markPinUnlocked, pinCredentialStamp, pinIsPasscode, recordPinFailure, shouldPromptForPin, verifyPin } from '../pin';
import type { PinInputHandle } from '../PinInput';
import { SecretInput } from '../PasscodeInput';
import { secretReady, type SecretKind } from '../secretKind';
import { ForgotPinLink, PinRecoveryForm } from '../PinRecoveryForm';
import type { UserSettings } from '../userSettings';

/** What the gate needs to offer the phrase reset for a forgotten PIN. */
export type PinGateRecovery = {
  phrase: string;
  userSettings: UserSettings;
  onSettingsChange: (next: UserSettings, base: UserSettings) => void;
};

type Props = {
  pubkey: string;
  /** Changes to the synced PIN remount the gate and discard pending checks. */
  pinCredential?: string;
  hasPin: boolean;
  pinTimeoutMinutes: number;
  onCancel: () => void;
  prompt?: string;
  recovery?: PinGateRecovery;
  children: ReactNode;
};

/** The phrase and custody pages share the same local PIN boundary. The
 * synced hasPin flag is authoritative even if the local PIN cache is late. */
export function PhrasePinGate(props: Props) {
  const owner = `${props.pubkey}:${props.pinCredential ?? ''}:${props.hasPin}:${props.pinTimeoutMinutes}`;
  return <GateForOwner key={owner} {...props} />;
}

function GateForOwner({ hasPin, pinTimeoutMinutes, onCancel, prompt = 'phraseGate.enterToView', recovery, children }: Props) {
  const [locked, setLocked] = useState(() => hasPin && shouldPromptForPin(pinTimeoutMinutes));
  useEffect(() => {
    if (!hasPin || locked || pinTimeoutMinutes <= 0) return;
    const check = () => { if (shouldPromptForPin(pinTimeoutMinutes)) setLocked(true); };
    const timer = setInterval(check, 1000);
    window.addEventListener('focus', check);
    return () => { clearInterval(timer); window.removeEventListener('focus', check); };
  }, [hasPin, locked, pinTimeoutMinutes]);
  if (locked) return <InlinePinGate onSuccess={() => setLocked(false)} onCancel={onCancel} prompt={prompt} recovery={recovery} />;
  return <>{children}</>;
}

/** The prompt keys this gate is opened with, and their passcode forms. */
const PASSCODE_PROMPTS: Record<string, string> = {
  'phraseGate.enterToView': 'phraseGate.enterToViewPasscode',
  'phraseGate.enterToChangeCustody': 'phraseGate.enterToChangeCustodyPasscode',
};

/**
 * Chromeless PIN entry embedded in the tab body. Draws the field of the secret
 * the account holds, read from the cached hash (`pinIsPasscode`). Reuses verifyPin +
 * markPinUnlocked directly rather than wrapping the full-screen
 * PinPrompt - that would double-stack modals.
 */
function InlinePinGate({
  onSuccess,
  onCancel,
  prompt,
  recovery,
}: {
  onSuccess: () => void;
  onCancel: () => void;
  prompt: string;
  recovery?: PinGateRecovery;
}) {
  const { t } = useTranslation('security');
  const [kind] = useState<SecretKind>(() => (pinIsPasscode() ? 'passcode' : 'pin'));
  const [recovering, setRecovering] = useState(false);
  const [value, setValue] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [lockout, setLockout] = useState(() => getPinLockoutState());
  const inputRef = useRef<PinInputHandle>(null);
  const alive = useRef(false);
  const working = useRef(false);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);

  useEffect(() => {
    if (!lockout.locked) return;
    const id = setInterval(() => {
      const state = getPinLockoutState();
      setLockout(state);
      if (!state.locked) setErr(null);
    }, 1000);
    return () => clearInterval(id);
  }, [lockout.locked]);

  async function submit(candidate: string) {
    if (!secretReady(kind, candidate) || working.current) return;
    // The counter is shared by every PIN surface, so it is read at submit and
    // not only from the state this gate mounted with.
    const current = getPinLockoutState();
    if (current.locked) {
      setLockout(current);
      setErr(t('phraseGate.tooManyAttempts', { seconds: current.secondsLeft }));
      return;
    }
    working.current = true;
    setBusy(true);
    setErr(null);
    try {
      const stamp = pinCredentialStamp();
      const { valid: ok } = await verifyPin(candidate);
      if (!alive.current) return;
      // The secret changed on another device during the check: the answer is
      // about a secret the account no longer holds, so it opens nothing.
      if (pinCredentialStamp() !== stamp) {
        setValue('');
        inputRef.current?.clear();
        return;
      }
      if (ok) {
        clearPinFailures();
        markPinUnlocked();
        onSuccess();
      } else {
        const state = recordPinFailure();
        setLockout(state);
        setErr(state.locked
          ? t('phraseGate.tooManyAttempts', { seconds: state.secondsLeft })
          : kind === 'passcode' ? t('phraseGate.incorrectPasscodeRetry') : t('phraseGate.incorrectPinRetry'));
        setValue('');
        inputRef.current?.clear();
      }
    } catch {
      if (alive.current) setErr(kind === 'passcode' ? t('phraseGate.checkFailedPasscode') : t('phraseGate.checkFailed'));
    } finally {
      if (alive.current) { working.current = false; setBusy(false); }
    }
  }

  const disabled = busy || lockout.locked;

  // The gate guards the phrase, so typing the phrase is proof enough to
  // clear a forgotten PIN. The cleared PIN opens the page behind it.
  if (recovering && recovery) {
    return <PinRecoveryForm {...recovery} kind={kind} onCleared={onSuccess} onCancel={() => setRecovering(false)} />;
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-pn-soft leading-relaxed">
        {t(kind === 'passcode' ? PASSCODE_PROMPTS[prompt] ?? prompt : prompt)}
      </p>
      <SecretInput
        kind={kind}
        ref={inputRef}
        value={value}
        onChange={(v) => {
          setValue(v);
          setErr(null);
        }}
        onComplete={(v) => void submit(v)}
        autoFocus
        compact
        disabled={disabled}
      />
      {err && (
        <p className="text-sm text-danger text-center">
          {err}
        </p>
      )}
      {lockout.locked && (
        <p className="text-xs text-pn-soft text-center">
          {t('phraseGate.lockedFor', { seconds: lockout.secondsLeft })}
        </p>
      )}
      <div className="flex gap-2">
        <button
          onClick={onCancel}
          className="flex-1 rounded-md border border-divider hover:bg-surface-1 px-3 py-2 text-sm transition"
        >
          {t('common:actions.cancel')}
        </button>
        <button
          onClick={() => void submit(value)}
          disabled={!secretReady(kind, value) || disabled}
          className="flex-1 rounded-md bg-accent-fill text-white hover:bg-accent-fill-hover px-3 py-2 text-sm font-medium transition disabled:opacity-40 disabled:cursor-not-allowed"
        >
          {busy ? t('phraseGate.checking') : t('phraseGate.unlock')}
        </button>
      </div>
      {recovery && <ForgotPinLink kind={kind} onClick={() => setRecovering(true)} />}
    </div>
  );
}
