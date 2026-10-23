/**
 * Full-app lock screen.
 *
 * Shown when `appLockEnabled` is true and the session has timed out, and on
 * any start where a PIN wrap or a fingerprint is the only way back into the
 * session because no phrase is at rest, whatever the flag says (App.tsx).
 * Supports biometric unlock (WebAuthn PRF) and PIN unlock, with
 * full phrase re-entry as last resort. It also shows after the Lock app
 * button, with the app lock off too: a device with a PIN and no wrap then
 * gets a PIN door that checks the hash while the session is live
 * (`onPinVerified`, GitHub #594).
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
 * Spec: ops/docs/archive/pin-recovery.md
 *
 * The lock screen unwraps the phrase from an encrypted blob and
 * passes it back to the parent via `onUnlock(phrase)`. No note
 * content is visible behind it.
 */

import { useEffect, useRef, useState } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import { ArrowRight, Fingerprint, LockKeyOpen, Pause, Play } from './icons';
import { Button, IconButton } from './ui';
import { TypewriterRotation } from './LoadingScreen';
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
  hasPin,
  pinIsPasscode,
  verifyPin,
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
   * signed-out landing page.
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
  /**
   * Given only while the session is live. A device with a PIN or passcode but
   * no wrap (Lock app with the app lock off) then gets a PIN door that checks
   * the secret against its hash and calls this, instead of opening a wrap.
   */
  onPinVerified?: () => void;
};

type View = 'main' | 'phrase' | 'recover';

/** The field the PIN door shows. Never throws: a malformed salt reads as a
 *  PIN, so the recovery links always render. Without a wrap it is the kind of
 *  the cached hash. */
function kindNow(): SecretKind {
  return (hasPinWrappedPhrase() ? pinWrapIsPasscode() : pinIsPasscode()) ? 'passcode' : 'pin';
}

// After this many cumulative failures, drop the user into phrase
// recovery. The exponential backoff in pin.ts kicks in earlier (5
// failures → 30s, 60s, 120s, ...), but eventually we should just hand
// them the phrase escape hatch instead of making them wait minutes. It is
// the recovery door rather than the plain one: ten wrong guesses means the
// PIN is forgotten, not mistyped.
const HARD_EXHAUSTION_THRESHOLD = 10;

export function LockScreen({ onUnlock, signInState = 'idle', onRetrySignIn, onWrapUpgraded, onPinVerified }: Props) {
  const { t } = useTranslation('security');
  const [view, setView] = useState<View>('main');
  const [biometricAvailable, setBiometricAvailable] = useState(() => hasBiometricCredential());
  const [pinWrapped] = useState(() => hasPinWrappedPhrase());
  // No wrap, but a PIN this device knows: checked by its hash, and only while
  // the caller offers that door (a live session).
  const byHash = !pinWrapped && onPinVerified !== undefined && hasPin();
  const pinAvailable = pinWrapped || byHash;
  const [kind, setKind] = useState<SecretKind>(kindNow);
  // Another tab can replace the wrap (a PIN changed to a passcode there), and
  // the field must follow the wrap this screen will open.
  useEffect(() => onWrappedBlobChange(() => setKind(kindNow())), []);
  const [biometricBusy, setBiometricBusy] = useState(false);
  const [biometricError, setBiometricError] = useState<string | null>(null);
  const autoTriggered = useRef(false);
  // The automatic first try below is the mount render's handleBiometric, and
  // the prompt can outlast the boot. Its answer goes to the newest onUnlock,
  // which knows the session the boot made since: the mount render's copy
  // still saw 'loading' and refused a right phrase.
  const onUnlockRef = useRef(onUnlock);
  onUnlockRef.current = onUnlock;

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
      if (!(await onUnlockRef.current(phrase))) {
        setBiometricError(t('pinRecovery.wrongPhrase'));
        setBiometricBusy(false);
      }
    } else {
      // A passed prompt whose key opened nothing is said even on the automatic
      // first try: the PIN, the passcode or the phrase is the way in, and
      // pressing the button again cannot help. A cancel says nothing then.
      // A hardware key the OS destroyed never comes back: the button goes, and
      // the line says biometric unlock must be set up again. The doors below
      // stay. Spec: ops/docs/plans/biometric-key-binding.md (D6)
      if (failure === 'gone') {
        setBiometricAvailable(false);
        setBiometricError(t('lockScreen.biometricGone'));
      } else if (failure === 'unopened') {
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
              <Button action="retry" variant="primary" onClick={onRetrySignIn} className="w-full">
                {t('lockScreen.retrySignIn')}
              </Button>
            </>
          )}
        </div>
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
        <LockLines />

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
          {/* Biometrics takes the four PIN boxes' width too (w-fit), so the
              buttons line up with the boxes. */}
          <div className={`space-y-3 ${pinAvailable && kind === 'pin' ? 'mx-auto w-fit' : ''}`}>
          {biometricAvailable && (
            // The first way in takes the focus, so Enter starts it without a
            // mouse (GitHub #395 thread).
            <Button
              autoFocus
              variant="primary"
              icon={<Fingerprint size={15} aria-hidden="true" className="shrink-0" />}
              onClick={() => void handleBiometric(false)}
              disabled={biometricBusy}
              className="w-full"
            >
              {biometricBusy ? t('lockScreen.verifying') : t('lockScreen.unlockWithBiometrics')}
            </Button>
          )}

          {/* The secret's own field, straight on the screen: four boxes for
              a PIN, one field for a passcode (GitHub #594 thread). */}
          {pinAvailable && (
            <PinUnlock
              key={kind}
              kind={kind}
              autoFocus={!biometricAvailable}
              quiet={biometricAvailable}
              onUnlock={onUnlock}
              onVerified={byHash ? onPinVerified : undefined}
              onExhausted={() => setView('recover')}
              onForgotPin={() => setView('recover')}
              onWrapUpgraded={onWrapUpgraded}
            />
          )}
          </div>

          <button
            type="button"
            onClick={() => setView('phrase')}
            className="w-full inline-flex items-center justify-center gap-1 text-sm text-pn-muted hover:text-pn hover:underline py-2 transition"
          >
            {t('lockScreen.signInWithPhrase')}
            <ArrowRight size={14} aria-hidden="true" className="shrink-0" />
          </button>

        </div>
      </div>
    </LockShell>
  );
}

// ── The typewriter lines ────────────────────────────────────────

/** This device's choice, read once per lock screen. Not synced: a person may
 *  want the lines on a laptop and still on a phone. */
const LINES_PAUSED_KEY = 'privacynotes.lockLinesPaused';

function linesStartPaused(): boolean {
  try {
    const saved = localStorage.getItem(LINES_PAUSED_KEY);
    if (saved !== null) return saved === '1';
  } catch {
    /* storage refused: fall through to the motion setting */
  }
  return window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
}

/**
 * The loading screen's typewriter lines as the screen's opener, above the title,
 * so the lock screen is not a bare form (owner, 2026-10-22, variant C1 of the
 * mockups). The line is centered; the pause button sits in the middle of a
 * short divider under it, so it never moves while the line types. A pause
 * shows the whole line and stops.
 */
function LockLines() {
  const { t } = useTranslation('common');
  const [paused, setPaused] = useState(linesStartPaused);
  function toggle() {
    const next = !paused;
    setPaused(next);
    try {
      localStorage.setItem(LINES_PAUSED_KEY, next ? '1' : '0');
    } catch {
      /* the choice holds for this screen only */
    }
  }
  return (
    <div className="space-y-3">
      {/* Wider than the column (up to the screen, centered), so a long line
          fits on one row on a desktop; and two rows tall with the line at the
          bottom, so a line that still wraps (a phone, a long language) grows
          upward and nothing below it moves. */}
      <div className="relative left-1/2 flex min-h-10 w-[calc(100vw-3rem)] max-w-xl -translate-x-1/2 items-end justify-center">
        {/* A person typing, not the loading screen's machine: calmer, and it
            does not pull the eye from the PIN. */}
        <TypewriterRotation paused={paused} human />
      </div>
      <div className="mx-auto flex w-32 items-center gap-2">
        <span className="h-px flex-1 bg-divider" />
        <IconButton
          label={paused ? t('loading.play') : t('loading.pause')}
          aria-pressed={paused}
          onClick={toggle}
          className="!h-7 !w-7 !rounded-full border border-divider bg-surface-1"
        >
          {paused ? <Play size={12} aria-hidden="true" /> : <Pause size={12} aria-hidden="true" />}
        </IconButton>
        <span className="h-px flex-1 bg-divider" />
      </div>
    </div>
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
  autoFocus,
  quiet,
  onUnlock,
  onVerified,
  onExhausted,
  onForgotPin,
  onWrapUpgraded,
}: {
  kind: SecretKind;
  /** The field takes the focus when it is the first way in. */
  autoFocus: boolean;
  /** The fingerprint button above is the filled one; Unlock is outlined. */
  quiet: boolean;
  onUnlock: (phrase: string) => Promise<boolean>;
  /** Set when there is no wrap: the secret is checked against its hash. */
  onVerified?: () => void;
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

    if (onVerified) {
      const { valid } = await verifyPin(pin);
      if (!alive.current) return;
      if (valid) {
        clearPinFailures();
        onVerified();
        return;
      }
      failed();
      setBusy(false);
      return;
    }

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
      failed();
    }
    setBusy(false);
  }

  /** A wrong secret, by either check: one count on the shared lockout. */
  function failed() {
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

  return (
    <div className="space-y-3">
      {/* The boxes, the error and Unlock share one width: the four PIN boxes'
          own (w-fit). The error takes no width of its own (w-0 min-w-full), so
          a long message wraps instead of widening the box. A passcode field
          fills the column, so its box does too. */}
      <div className={`space-y-3 ${kind === 'pin' ? 'mx-auto w-fit' : ''}`}>
      <SecretInput
        kind={kind}
        ref={inputRef}
        value={value}
        onChange={(v) => {
          setValue(v);
          setError(null);
        }}
        onComplete={(v) => void submit(v)}
        autoFocus={autoFocus}
        disabled={busy || lockout.locked}
      />

      {error && (
        <p className="w-0 min-w-full text-sm text-danger text-center">{error}</p>
      )}

        <Button
          variant={quiet ? 'secondary' : 'primary'}
          icon={<LockKeyOpen size={15} aria-hidden="true" className="shrink-0" />}
          onClick={() => void submit(value)}
          disabled={!secretReady(kind, value) || busy || lockout.locked}
          className="w-full"
        >
          {busy ? t('lockScreen.checking') : t(kind === 'pin' ? 'lockScreen.unlockWithPin' : 'lockScreen.unlockWithPasscode')}
        </Button>
      </div>

      {/* A link with a trailing arrow (owner's pick of four, 2026-10-22): it
          names where it goes, the reset view, by that view's own title. */}
      <button
        type="button"
        onClick={onForgotPin}
        className="w-full inline-flex items-center justify-center gap-1 text-sm text-accent hover:underline py-1 transition"
      >
        {kind === 'passcode' ? t('pinRecovery.titlePasscode') : t('pinRecovery.title')}
        <ArrowRight size={14} aria-hidden="true" className="shrink-0" />
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
      {/* One way out, Cancel below: a Back link here did the same. */}
      <div className="text-center space-y-2">
        <h2 className="text-lg font-semibold text-pn">
          {!recover
            ? t('lockScreen.recoveryPhrase')
            : kind === 'passcode' ? t('pinRecovery.titlePasscode') : t('pinRecovery.title')}
        </h2>
        <p className="text-sm text-pn-muted text-balance">
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
        <Button action="cancel" onClick={onBack} className="flex-1" />
        <Button
          variant="primary"
          icon={<LockKeyOpen size={15} aria-hidden="true" className="shrink-0" />}
          onClick={() => void handleSubmit()}
          disabled={!input.trim()}
          className="flex-1"
        >
          {/* "Unlock" in both views: the title and the line above already
              say that a reset also clears the PIN. */}
          {t('lockScreen.unlock')}
        </Button>
      </div>
    </div>
  );
}
