/**
 * Full-app lock screen.
 *
 * Shown when `appLockEnabled` is true and the session has timed out, and on
 * any start where a PIN wrap or a fingerprint is the only way back into the
 * session because no phrase is at rest, whatever the flag says (App.tsx).
 * Supports biometric unlock (WebAuthn PRF) and PIN unlock, with
 * full phrase re-entry as last resort.
 *
 * The PIN field is the one the wrap was made with: four boxes for a PIN, one
 * field for a passcode. It reads the wrap's own salt, never the cached hash,
 * because the two can come from different writes and the wrap is what this
 * screen opens. Spec: ops/docs/plans/app-lock-passcode.md (section 4.2)
 *
 * The phrase opens two different doors, so the screen asks which one. Plain
 * re-entry unlocks and leaves the PIN alone, for somebody who simply
 * prefers typing the words. "Forgot your PIN?" unlocks and clears the PIN,
 * which is the only route out of one nobody remembers - the hash is synced,
 * so signing out and back in restores it.
 * Spec: ops/docs/plans/pin-recovery.md
 *
 * The lock screen unwraps the phrase from an encrypted blob and
 * passes it back to the parent via `onUnlock(phrase)`. No note
 * content is visible behind it.
 */

import { useEffect, useRef, useState } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import { ArrowLeft, Fingerprint, Lock } from './icons';
import {
  hasBiometricCredential,
  unlockWithBiometricDetailed,
  hasPinWrappedPhrase,
  onWrappedBlobChange,
  pinWrapIsPasscode,
  pinWrapStamp,
  unwrapPhraseWithPin,
  type PinWrapBlob,
} from './biometric';
import type { PinInputHandle } from './PinInput';
import { SecretInput } from './PasscodeInput';
import { secretReady, type SecretKind } from './secretKind';
import {
  recordPinFailure,
  clearPinFailures,
  getPinLockoutState,
} from './pin';
import { isValidPhrase } from '@notes/shared';
import { Brand } from './Brand';

type Props = {
  /** Answers false when the phrase does not belong to the account behind the
   *  lock, which every view below turns into a visible line rather than a
   *  button that does nothing. `recover` asks the caller to clear the PIN
   *  once the unlock lands: this screen holds no settings, and the account
   *  check that has to precede that removal lives with the session. */
  onUnlock: (phrase: string, recover?: boolean) => Promise<boolean>;
  /**
   * The post-unlock sign-in, driven by App.tsx: 'busy' while
   * signInWithPhrase runs, 'error' when it failed on a transient
   * (offline, rate limit). The shell stays up with a status line and a
   * retry, so a failed sign-in never silently lands the user on the
   * signed-out landing page (session audit 2026-08-25).
   */
  signInState?: 'idle' | 'busy' | 'error';
  onRetrySignIn?: () => void;
  /**
   * A legacy-iteration PIN wrap was re-wrapped after a successful unlock.
   * This screen holds no settings, so the caller carries the new blob to the
   * synced row; left local, every other device would replace it with the
   * account's old one on the next pass and the next unlock would redo it.
   */
  onWrapUpgraded?: (blob: PinWrapBlob) => void;
};

type View = 'main' | 'pin' | 'phrase' | 'recover';

// After this many cumulative failures, drop the user into phrase
// recovery. The exponential backoff in pin.ts kicks in earlier (5
// failures → 30s, 60s, 120s, ...), but eventually we should just hand
// them the phrase escape hatch instead of making them wait minutes. It is
// the recovery door rather than the plain one: ten wrong guesses means the
// PIN is forgotten, not mistyped.
const HARD_EXHAUSTION_THRESHOLD = 10;

export function LockScreen({ onUnlock, signInState = 'idle', onRetrySignIn, onWrapUpgraded }: Props) {
  const { t } = useTranslation('security');
  const [view, setView] = useState<View>('main');
  const [biometricAvailable] = useState(() => hasBiometricCredential());
  const [pinAvailable] = useState(() => hasPinWrappedPhrase());
  // Never throws: a malformed salt reads as a PIN, so the recovery links below
  // always render.
  const [kind, setKind] = useState<SecretKind>(() => (pinWrapIsPasscode() ? 'passcode' : 'pin'));
  // Another tab can replace the wrap (a PIN changed to a passcode there), and
  // the field must follow the wrap this screen will open.
  useEffect(() => onWrappedBlobChange(() => setKind(pinWrapIsPasscode() ? 'passcode' : 'pin')), []);
  const [biometricBusy, setBiometricBusy] = useState(false);
  const [biometricError, setBiometricError] = useState<string | null>(null);
  const autoTriggered = useRef(false);

  // Auto-trigger biometric on mount. If it fails silently (e.g.
  // browser requires a user gesture), swallow the error - the user
  // can tap the button manually.
  useEffect(() => {
    if (biometricAvailable && !autoTriggered.current) {
      autoTriggered.current = true;
      void handleBiometric(true);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleBiometric(silent = false) {
    setBiometricBusy(true);
    setBiometricError(null);
    // The button label doubles as the reason line the OS prompt renders; Android
    // also draws its own cancel button, which is why that label goes too.
    const { phrase, failure } = await unlockWithBiometricDetailed(
      t('lockScreen.unlockWithBiometrics'),
      t('common:actions.cancel'),
    );
    if (phrase) {
      // A wrap belongs to whichever account enrolled it, and a sign-out
      // removes it, so a refusal here means this blob outlived its account.
      if (!(await onUnlock(phrase))) {
        setBiometricError(t('pinRecovery.wrongPhrase'));
        setBiometricBusy(false);
      }
    } else {
      // A passed prompt whose key opened nothing is said even on the automatic
      // first try: the PIN, the passcode or the phrase is the way in, and
      // pressing the button again cannot help. A cancel says nothing then.
      if (failure === 'unopened') {
        setBiometricError(t('lockScreen.biometricUnopened'));
      } else if (!silent) {
        setBiometricError(t('lockScreen.biometricFailed'));
      }
      setBiometricBusy(false);
    }
  }

  // The local unlock already succeeded; the account sign-in is in
  // flight or failed. Replaces every view - there is nothing else to
  // do here until the sign-in lands or the user retries.
  if (signInState !== 'idle') {
    return (
      <LockShell>
        <div className="space-y-4 text-center">
          {signInState === 'busy' ? (
            <p className="text-sm text-pn-muted">
              {t('lockScreen.signingIn')}
            </p>
          ) : (
            <>
              <p className="text-sm text-danger">
                {t('lockScreen.signInFailed')}
              </p>
              <button
                type="button"
                onClick={onRetrySignIn}
                className="w-full rounded-lg bg-accent-fill hover:bg-accent-fill-hover text-white text-sm font-semibold px-4 py-2.5 transition"
              >
                {t('lockScreen.retrySignIn')}
              </button>
            </>
          )}
        </div>
      </LockShell>
    );
  }

  if (view === 'pin') {
    return (
      <LockShell>
        <PinUnlock
          key={kind}
          kind={kind}
          onUnlock={onUnlock}
          onBack={() => setView('main')}
          onExhausted={() => setView('recover')}
          onForgotPin={() => setView('recover')}
          onWrapUpgraded={onWrapUpgraded}
        />
      </LockShell>
    );
  }

  if (view === 'phrase' || view === 'recover') {
    return (
      <LockShell>
        <PhraseUnlock
          kind={kind}
          recover={view === 'recover'}
          onUnlock={onUnlock}
          onBack={() => setView('main')}
        />
      </LockShell>
    );
  }

  return (
    <LockShell>
      <div className="space-y-6 text-center">
        {/* Lock icon */}
        <div className="flex justify-center">
          <div className="w-16 h-16 rounded-full bg-accent/10 flex items-center justify-center">
            <Lock size={28} weight="duotone" className="text-accent" />
          </div>
        </div>

        <div>
          <h1 className="text-lg font-semibold text-pn">
            <Trans
              i18nKey="security:lockScreen.unlockApp"
              components={{ brand: <Brand /> }}
            />
          </h1>
          <p className="text-sm text-pn-muted mt-1">
            {kind === 'passcode'
              ? biometricAvailable ? t('lockScreen.subtitleWithBioPasscode') : t('lockScreen.subtitleNoBioPasscode')
              : biometricAvailable ? t('lockScreen.subtitleWithBio') : t('lockScreen.subtitleNoBio')}
          </p>
        </div>

        {biometricError && (
          <p className="text-sm text-danger">{biometricError}</p>
        )}

        <div className="space-y-3">
          {biometricAvailable && (
            // The first way in takes the focus, so Enter starts it without a
            // mouse (GitHub #395 thread).
            <button
              autoFocus
              onClick={() => void handleBiometric(false)}
              disabled={biometricBusy}
              className="w-full inline-flex items-center justify-center gap-2 rounded-md bg-accent-fill text-white hover:bg-accent-fill-hover px-4 py-2.5 text-sm font-medium transition disabled:opacity-50"
            >
              {/* Fingerprint icon */}
              <Fingerprint size={18} />
              {biometricBusy ? t('lockScreen.verifying') : t('lockScreen.unlockWithBiometrics')}
            </button>
          )}

          {pinAvailable && (
            <button
              autoFocus={!biometricAvailable}
              onClick={() => setView('pin')}
              className={`w-full rounded-md px-4 py-2.5 text-sm font-medium transition ${
                biometricAvailable
                  ? 'border border-divider text-pn-soft hover:bg-pn/5'
                  : 'bg-accent-fill text-white hover:bg-accent-fill-hover'
              }`}
            >
              {kind === 'passcode' ? t('lockScreen.unlockWithPasscode') : t('lockScreen.unlockWithPin')}
            </button>
          )}

          <button
            onClick={() => setView('phrase')}
            className="w-full text-sm text-pn-muted hover:text-pn py-2 transition"
          >
            {t('lockScreen.signInWithPhrase')}
          </button>
        </div>
      </div>
    </LockShell>
  );
}

// ── Lock screen shell ───────────────────────────────────────────

function LockShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="fixed inset-0 z-[100] bg-surface-2 flex items-center justify-center p-6">
      <div className="w-full max-w-sm">{children}</div>
    </div>
  );
}

// ── PIN unlock sub-view ─────────────────────────────────────────

function PinUnlock({
  kind,
  onUnlock,
  onBack,
  onExhausted,
  onForgotPin,
  onWrapUpgraded,
}: {
  kind: SecretKind;
  onUnlock: (phrase: string) => Promise<boolean>;
  onBack: () => void;
  onExhausted: () => void;
  onForgotPin: () => void;
  onWrapUpgraded?: (blob: PinWrapBlob) => void;
}) {
  const { t } = useTranslation('security');
  const [value, setValue] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Lockout state is owned by pin.ts (localStorage-backed, shared with
  // ProtectedNoteGate's PIN paths). We just mirror it for rendering.
  const [lockout, setLockout] = useState(() => getPinLockoutState());
  const inputRef = useRef<PinInputHandle>(null);
  const alive = useRef(false);
  useEffect(() => {
    alive.current = true;
    return () => { alive.current = false; };
  }, []);

  // Countdown timer while locked.
  useEffect(() => {
    if (!lockout.locked) return;
    const id = setInterval(() => {
      const state = getPinLockoutState();
      setLockout(state);
      if (!state.locked) setError(null);
    }, 1000);
    return () => clearInterval(id);
  }, [lockout.locked]);

  async function submit(pin: string) {
    if (!secretReady(kind, pin) || busy) return;
    // The counter is shared by every PIN surface, so it is read at submit and
    // not only from the state this view mounted with.
    const current = getPinLockoutState();
    if (current.locked) {
      setLockout(current);
      setError(t('lockScreen.tooManyAttempts', { seconds: current.secondsLeft }));
      return;
    }

    setBusy(true);
    setError(null);

    const stamp = pinWrapStamp();
    const phrase = await unwrapPhraseWithPin(pin, onWrapUpgraded);
    // The wrap was replaced during the derivation (another tab changed the
    // secret), or this view was left: the answer opens nothing and counts for
    // nothing.
    if (!alive.current) return;
    if (pinWrapStamp() !== stamp) {
      setBusy(false);
      setValue('');
      inputRef.current?.clear();
      return;
    }
    if (phrase) {
      // The PIN was right for the blob, whatever the blob turns out to hold,
      // so the backoff it earned is spent either way.
      clearPinFailures();
      if (!(await onUnlock(phrase))) {
        setError(t('pinRecovery.wrongPhrase'));
        setValue('');
        inputRef.current?.clear();
      }
    } else {
      const state = recordPinFailure();
      setLockout(state);
      if (state.attempts >= HARD_EXHAUSTION_THRESHOLD) {
        // Don't make the user wait through 240s+ backoff - drop them
        // into phrase entry directly.
        onExhausted();
        return;
      }
      setError(state.locked
        ? t('lockScreen.tooManyAttempts', { seconds: state.secondsLeft })
        : kind === 'passcode' ? t('lockScreen.incorrectPasscodeRetry') : t('lockScreen.incorrectPinRetry'));
      setValue('');
      inputRef.current?.clear();
    }
    setBusy(false);
  }

  return (
    <div className="space-y-5">
      <button
        onClick={onBack}
        className="text-sm text-pn-muted hover:text-pn transition flex items-center gap-1"
      >
        <ArrowLeft />
        {t('common:actions.back')}
      </button>

      <div className="text-center space-y-2">
        <h2 className="text-lg font-semibold text-pn">
          {kind === 'passcode' ? t('lockScreen.enterPasscode') : t('lockScreen.enterPin')}
        </h2>
        <p className="text-sm text-pn-muted">
          {kind === 'passcode' ? t('lockScreen.enterPasscodeSubtitle') : t('lockScreen.enterPinSubtitle')}
        </p>
      </div>

      <SecretInput
        kind={kind}
        ref={inputRef}
        value={value}
        onChange={(v) => {
          setValue(v);
          setError(null);
        }}
        onComplete={(v) => void submit(v)}
        autoFocus
        disabled={busy || lockout.locked}
      />

      {error && (
        <p className="text-sm text-danger text-center">{error}</p>
      )}

      <div className="flex gap-2">
        <button
          onClick={onBack}
          className="flex-1 rounded-md border border-divider px-3 py-2 text-sm hover:bg-pn/5 transition"
        >
          {t('common:actions.cancel')}
        </button>
        <button
          onClick={() => void submit(value)}
          disabled={!secretReady(kind, value) || busy || lockout.locked}
          className="flex-1 rounded-md bg-accent-fill text-white hover:bg-accent-fill-hover px-3 py-2 text-sm font-medium transition disabled:opacity-40 disabled:cursor-not-allowed"
        >
          {busy ? t('lockScreen.checking') : t('lockScreen.unlock')}
        </button>
      </div>

      <button
        onClick={onForgotPin}
        className="w-full text-sm text-accent hover:underline py-1 transition"
      >
        {kind === 'passcode' ? t('pinRecovery.forgotPasscode') : t('pinRecovery.forgotPin')}
      </button>
    </div>
  );
}

// ── Phrase re-entry sub-view ────────────────────────────────────

function PhraseUnlock({
  kind,
  onUnlock,
  onBack,
  recover = false,
}: {
  kind: SecretKind;
  onUnlock: (phrase: string, recover?: boolean) => Promise<boolean>;
  onBack: () => void;
  /** Came from "Forgot your PIN?", so the unlock also clears the PIN. */
  recover?: boolean;
}) {
  const { t } = useTranslation('security');
  const [input, setInput] = useState('');
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit() {
    const trimmed = input.trim().toLowerCase();
    if (!isValidPhrase(trimmed)) {
      setError(t('lockScreen.invalidPhrase'));
      return;
    }
    // Two different refusals, and they must not share a line. The checksum
    // above is about the words; this one is about whose they are, and the
    // words can be flawless and still belong elsewhere.
    if (!(await onUnlock(trimmed, recover))) {
      setError(t('pinRecovery.wrongPhrase'));
    }
  }

  return (
    <div className="space-y-5">
      <button
        onClick={onBack}
        className="text-sm text-pn-muted hover:text-pn transition flex items-center gap-1"
      >
        <ArrowLeft />
        {t('common:actions.back')}
      </button>

      <div className="text-center space-y-2">
        <h2 className="text-lg font-semibold text-pn">
          {!recover
            ? t('lockScreen.recoveryPhrase')
            : kind === 'passcode' ? t('pinRecovery.titlePasscode') : t('pinRecovery.title')}
        </h2>
        <p className="text-sm text-pn-muted">
          {!recover
            ? t('lockScreen.recoveryPhraseSubtitle')
            : kind === 'passcode' ? t('pinRecovery.lockIntroPasscode') : t('pinRecovery.lockIntro')}
        </p>
      </div>

      <textarea
        value={input}
        onChange={(e) => {
          setInput(e.target.value);
          setError(null);
        }}
        placeholder={t('lockScreen.phrasePlaceholder')}
        // A phone keyboard must neither rewrite a phrase word nor learn it.
        spellCheck={false}
        autoCapitalize="none"
        autoCorrect="off"
        autoComplete="off"
        rows={3}
        dir="ltr" // rtl-ok: BIP-39 phrase words, always LTR
        className="w-full rounded-md bg-surface-1 border border-divider text-pn focus:border-accent p-3 text-sm font-mono focus:outline-none placeholder:text-pn-muted"
        autoFocus
      />

      {error && (
        <p className="text-sm text-danger">{error}</p>
      )}

      <div className="flex gap-2">
        <button
          onClick={onBack}
          className="flex-1 rounded-md border border-divider px-3 py-2 text-sm hover:bg-pn/5 transition"
        >
          {t('common:actions.cancel')}
        </button>
        <button
          onClick={() => void handleSubmit()}
          disabled={!input.trim()}
          className="flex-1 rounded-md bg-accent-fill text-white hover:bg-accent-fill-hover px-3 py-2 text-sm font-medium transition disabled:opacity-40 disabled:cursor-not-allowed"
        >
          {!recover
            ? t('lockScreen.unlock')
            : kind === 'passcode' ? t('pinRecovery.lockActionPasscode') : t('pinRecovery.lockAction')}
        </button>
      </div>
    </div>
  );
}
