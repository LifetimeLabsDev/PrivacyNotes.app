import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Fingerprint, Lock, ShieldSlash } from './icons';
import { PinInput, type PinInputHandle } from './PinInput';
import { SecretInput } from './PasscodeInput';
import { hashPin, hasPin, pinCredentialStamp, pinIsPasscode, verifyPin, recordPinFailure, clearPinFailures, getPinLockoutState, stagePinHash } from './pin';
import { secretReady, type SecretKind } from './secretKind';
import { hasBiometricCredential, unlockWithBiometricDetailed } from './biometric';
import { ForgotPinLink, PinRecoveryForm } from './PinRecoveryForm';
import { useEscapeToClose } from './useEscapeToClose';
import { signInStamp, signedOutSince } from './liveSignIn';
import { saveCredential, type UserSettings } from './userSettings';

/**
 * Inline gate for protected notes. Renders in the editor pane when
 * the selected note is gated. Unlock bubbles up via `onUnlock` so the
 * parent can refresh the shared session timer and all other protected
 * notes become accessible.
 *
 * Handles three modes automatically:
 *
 *   1. **Biometric** - device has biometric enrolled; prompt fingerprint/face.
 *      The PIN screen is one tap away, and so is the way back.
 *   2. **Verify** - a PIN is set; user enters it to unlock.
 *   3. **Bootstrap** - no PIN or biometric. Inline "Set a PIN" prompt.
 *
 * The verify screens draw the field of the secret the account holds, a PIN or
 * a passcode, from the cached hash (`pinIsPasscode`). The bootstrap stays four
 * digits: a passcode is set only in the PIN tab.
 * Spec: ops/docs/plans/app-lock-passcode.md (section 4.4)
 *
 * A fourth screen sits behind all of them: the recovery phrase, for a PIN
 * nobody remembers. Without it a forgotten PIN shuts these notes forever,
 * because the hash is synced and every screen that changes it asks for the
 * old one. Spec: ops/docs/archive/pin-recovery.md
 */
export function ProtectedNoteGate({
  phrase,
  onUnlock,
  onRemoveProtection,
  onCancel,
  initialIntent = 'unlock',
  onExitRemove,
  userSettings,
  onSettingsChange,
}: {
  /** The account's phrase, so a forgotten PIN has a way out. */
  phrase: string;
  onUnlock: () => void;
  /** Drop the note's protection. Runs only behind the same check as an
   *  unlock, so it is no weaker a gate than the one it removes. */
  onRemoveProtection: () => void;
  /** Rendered below md only: on desktop the pane auto-reselects, so
   *  Cancel was a no-op there (the quick-add Cancel had the same fate);
   *  on a phone the gate IS the screen and needs the way back. */
  onCancel?: () => void;
  /** 'remove' opens the gate straight into removal, for the menu action that
   *  has no other screen to ask on. */
  initialIntent?: Intent;
  /** Told when the user backs out of a removal, so a gate opened only to
   *  remove can close. A gate that is also holding a locked note stays: it
   *  simply falls back to unlocking. */
  onExitRemove?: () => void;
  userSettings: UserSettings;
  /** `base` is the copy this surface was rendered with; the parent applies
   *  only the credential keys that differ between it and `next`. */
  onSettingsChange: (next: UserSettings, base: UserSettings) => void;
}) {
  const { t } = useTranslation('security');
  const pinIsSet = hasPin();
  const kind: SecretKind = pinIsPasscode() ? 'passcode' : 'pin';
  const bioEnrolled = hasBiometricCredential();
  const [recovering, setRecovering] = useState(false);
  // Which of the two screens is showing. The PIN screen never sets this
  // back, because its biometric button prompts where it stands.
  const [usePin, setUsePin] = useState(false);
  // Why the gate is open. It belongs to the gate rather than to a button on
  // one screen, so a refused fingerprint leaves the user where they meant to
  // be instead of dropping them back into plain unlocking.
  const [intent, setIntent] = useState<Intent>(initialIntent);
  // A gate already on screen for a locked note keeps its own mounted state, so
  // a fresh request from a menu would otherwise land on nothing. Following the
  // prop here is what lets the menus reach a gate that is already open. It runs
  // only when the caller's answer changes, so the gate's own buttons still win.
  useEffect(() => {
    setIntent(initialIntent);
  }, [initialIntent]);
  const removing = intent === 'remove';
  const done = removing ? onRemoveProtection : onUnlock;
  // Backing out of a removal always falls back to unlocking. Whether the gate
  // survives that is the parent's call: it keeps the gate for a locked note
  // and drops it for one that was only ever open to be unprotected.
  const onCancelRemove = () => {
    setIntent('unlock');
    onExitRemove?.();
  };

  // Clearing the PIN drops this gate into BootstrapMode, whose own "set a
  // PIN" step ends in the unlock the user came for.
  if (recovering) {
    return (
      <div className="max-w-sm mx-auto mt-16 space-y-4">
        <h2 className="text-lg font-semibold tracking-tight text-center">
          {kind === 'passcode' ? t('pinRecovery.titlePasscode') : t('pinRecovery.title')}
        </h2>
        <PinRecoveryForm
          kind={kind}
          phrase={phrase}
          userSettings={userSettings}
          onSettingsChange={onSettingsChange}
          onCleared={() => setRecovering(false)}
          onCancel={() => setRecovering(false)}
        />
      </div>
    );
  }

  if (bioEnrolled && !usePin) {
    return (
      <BiometricMode
        done={done}
        removing={removing}
        onStartRemove={() => setIntent('remove')}
        onRemoveProtection={onRemoveProtection}
        onCancelRemove={onCancelRemove}
        onCancel={onCancel}
        showPinFallback={pinIsSet}
        pinKind={kind}
        onUsePin={() => setUsePin(true)}
      />
    );
  }
  return pinIsSet ? (
    <VerifyMode
      kind={kind}
      done={done}
      removing={removing}
      onStartRemove={() => setIntent('remove')}
      onCancelRemove={onCancelRemove}
      onCancel={onCancel}
      showBiometric={bioEnrolled}
      onForgotPin={() => setRecovering(true)}
    />
  ) : (
    <BootstrapMode onUnlock={done} onCancel={onCancel} userSettings={userSettings} onSettingsChange={onSettingsChange} />
  );
}

/** Unlocking the note, or taking its protection off. Both pass the same check. */
type Intent = 'unlock' | 'remove';

/**
 * Runs the OS or WebAuthn prompt and reports a refusal through `setErr`.
 * Shared by the biometric screen and by the "Use biometric instead" button
 * on both PIN screens, which prompt in place rather than switching screens.
 */
function useBiometricUnlock(setErr: (msg: string | null) => void) {
  const { t } = useTranslation('security');
  const [busy, setBusy] = useState(false);

  async function run(onSuccess: () => void) {
    setBusy(true);
    setErr(null);
    // Reason line the OS prompt renders; reuses the lock-screen label. The
    // second string labels the cancel button Android draws itself.
    const { phrase, failure } = await unlockWithBiometricDetailed(
      t('lockScreen.unlockWithBiometrics'),
      t('common:actions.cancel'),
    );
    if (phrase) {
      onSuccess();
    } else {
      // A hardware key the OS destroyed gets the lock screen's line: biometric
      // unlock must be set up again, and the PIN below still opens the item.
      setErr(
        failure === 'gone' ? t('lockScreen.biometricGone')
          : failure === 'unopened' ? t('lockScreen.biometricUnopened')
          : t('protectedGate.biometricFailed'),
      );
      setBusy(false);
    }
  }

  return { busy, run };
}

/* ────────────────────────────────────────────────────────────────
 * Biometric - device has fingerprint/face enrolled
 * ──────────────────────────────────────────────────────────────── */

function BiometricMode({
  done,
  removing = false,
  onStartRemove,
  onRemoveProtection,
  onCancelRemove,
  onCancel,
  showPinFallback,
  pinKind = 'pin',
  onUsePin,
  compact = false,
}: {
  /** What a passed check performs: unlock the note, or take the lock off. */
  done: () => void;
  removing?: boolean;
  /** Absent where removing protection is not on offer, such as the modal
   *  that gates a delete. */
  onStartRemove?: () => void;
  onRemoveProtection?: () => void;
  onCancelRemove?: () => void;
  onCancel?: () => void;
  showPinFallback: boolean;
  /** Names the fallback button after the secret the account holds. */
  pinKind?: SecretKind;
  onUsePin: () => void;
  /** Inside the modal the box supplies its own padding. */
  compact?: boolean;
}) {
  const { t } = useTranslation('security');
  const [err, setErr] = useState<string | null>(null);
  const { busy, run } = useBiometricUnlock(setErr);
  const offersRemove = Boolean(onStartRemove && onRemoveProtection);

  return (
    <div className={`max-w-sm mx-auto ${compact ? '' : 'mt-16 '}space-y-4 text-center`}>
      <GateHeader
        title={removing ? t('protectedGate.disableProtection') : t('protectedGate.protectedItem')}
        subtitle={removing
          ? t('protectedGate.disableBiometricSubtitle')
          : t('protectedGate.biometricSubtitle')}
        icon={removing ? 'removeProtection' : 'biometric'}
      />
      <div className="flex flex-col gap-2">
        <div className="flex gap-2">
          {onCancel && !removing && (
            <button
              onClick={onCancel}
              className="md:hidden flex-1 rounded-md border border-divider hover:bg-surface-1 px-4 py-2 text-sm transition"
            >
              {t('common:actions.cancel')}
            </button>
          )}
          <button
            onClick={() => void run(done)}
            disabled={busy}
            className={`flex-1 inline-flex items-center justify-center gap-2 rounded-md text-white px-4 py-2 text-sm font-medium transition disabled:opacity-40 disabled:cursor-not-allowed ${
              removing ? 'bg-red-500 hover:bg-red-600' : 'bg-accent-fill hover:bg-accent-fill-hover'
            }`}
          >
            {removing ? <ShieldSlash size={15} /> : <Fingerprint size={15} />}
            {busy
              ? t('protectedGate.verifying')
              : removing
                ? t('protectedGate.disableProtection')
                : t('protectedGate.unlock')}
          </button>
        </div>
        {showPinFallback && (
          <button
            onClick={onUsePin}
            className="inline-flex items-center justify-center gap-2 rounded-md border border-divider text-pn-muted hover:bg-surface-1 px-4 py-2 text-sm transition"
          >
            <Lock size={15} />
            {pinKind === 'passcode' ? t('protectedGate.usePasscodeInstead') : t('protectedGate.usePinInstead')}
          </button>
        )}
        {offersRemove && (
          <>
            {/* The two above are ways INTO the note. What follows changes the
                note itself, so it loses the border and sits under a rule
                rather than reading as a third way in. */}
            <div className="border-t border-divider mt-1" />
            {removing ? (
              <button
                onClick={() => { setErr(null); onCancelRemove?.(); }}
                className="rounded-md px-4 py-2 text-sm text-pn-muted hover:bg-surface-1 transition"
              >
                {t('common:actions.cancel')}
              </button>
            ) : (
              <button
                // Sets the intent AND prompts, so the common case is one press.
                // The callback is passed explicitly because `done` still reads
                // the old intent during this render.
                onClick={() => { onStartRemove?.(); void run(onRemoveProtection!); }}
                disabled={busy}
                className="inline-flex items-center justify-center gap-2 rounded-md px-4 py-2 text-sm text-danger hover:bg-red-50 dark:hover:bg-red-950/30 transition disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <ShieldSlash size={15} />
                {t('protectedGate.disableProtection')}
              </button>
            )}
          </>
        )}
      </div>
      {err && (
        <p className="text-sm text-danger">{err}</p>
      )}
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────
 * Verify - device already has a PIN
 * ──────────────────────────────────────────────────────────────── */

function VerifyMode({
  kind,
  done,
  removing = false,
  onStartRemove,
  onCancelRemove,
  onCancel,
  showBiometric = false,
  onForgotPin,
}: {
  kind: SecretKind;
  /** What a correct PIN performs: unlock the note, or take the lock off. */
  done: () => void;
  removing?: boolean;
  /** Absent where removing protection is not on offer. */
  onStartRemove?: () => void;
  onCancelRemove?: () => void;
  onCancel?: () => void;
  /** True only when this device has biometric enrolled, so the button is
   *  absent where there is no finger to ask for. */
  showBiometric?: boolean;
  /** Opens the phrase route. Absent while removing protection, where the
   *  user is not locked out of anything. */
  onForgotPin?: () => void;
}) {
  const { t } = useTranslation('security');
  const [value, setValue] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [lockout, setLockout] = useState(() => getPinLockoutState());
  const inputRef = useRef<PinInputHandle>(null);
  const bio = useBiometricUnlock(setErr);

  // Switching between unlock and remove keeps the same input mounted, so its
  // autoFocus does not fire again and the caret is left wherever the button
  // click put it.
  useEffect(() => {
    inputRef.current?.focus();
  }, [removing]);

  // Countdown timer during lockout.
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
    if (!secretReady(kind, candidate) || busy) return;
    // The counter is shared by every PIN surface, so it is read at submit and
    // not only from the state this screen mounted with.
    const current = getPinLockoutState();
    if (current.locked) {
      setLockout(current);
      setErr(t('protectedGate.tooManyAttempts', { seconds: current.secondsLeft }));
      return;
    }
    setBusy(true);
    setErr(null);
    const stamp = pinCredentialStamp();
    const { valid: ok } = await verifyPin(candidate);
    // The secret changed on another device during the check: the answer is
    // about a secret the account no longer holds, so it opens nothing.
    if (pinCredentialStamp() !== stamp) {
      setValue('');
      setBusy(false);
      inputRef.current?.clear();
      return;
    }
    if (ok) {
      clearPinFailures();
      done();
    } else {
      const state = recordPinFailure();
      setLockout(state);
      setErr(state.locked
        ? t('protectedGate.tooManyAttempts', { seconds: state.secondsLeft })
        : kind === 'passcode' ? t('protectedGate.incorrectPasscodeRetry') : t('protectedGate.incorrectPinRetry'));
      setValue('');
      setBusy(false);
      inputRef.current?.clear();
    }
  }

  const disabled = busy || lockout.locked;

  return (
    <div className="max-w-sm mx-auto mt-16 space-y-4 text-center">
      <GateHeader
        title={removing
          ? kind === 'passcode' ? t('protectedGate.disableTitlePasscode') : t('protectedGate.disableTitle')
          : t('protectedGate.protectedItem')}
        subtitle={removing
          ? t('protectedGate.disableSubtitle')
          : kind === 'passcode' ? t('protectedGate.verifySubtitlePasscode') : t('protectedGate.verifySubtitle')}
        icon={removing ? 'removeProtection' : 'lock'}
      />
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
        disabled={disabled}
      />
      {err && (
        <p className="text-sm text-danger">{err}</p>
      )}
      {lockout.locked && (
        <p className="text-xs text-pn-muted">
          {t('protectedGate.lockedFor', { seconds: lockout.secondsLeft })}
        </p>
      )}
      <div className="flex flex-col gap-2">
        <div className="flex gap-2">
          {onCancel && !removing && (
            <button
              onClick={onCancel}
              className="md:hidden flex-1 rounded-md border border-divider hover:bg-surface-1 px-3 py-2 text-sm transition"
            >
              {t('common:actions.cancel')}
            </button>
          )}
          <button
            onClick={() => void submit(value)}
            disabled={!secretReady(kind, value) || disabled}
            className={`flex-1 rounded-md text-white px-3 py-2 text-sm font-medium transition disabled:opacity-40 disabled:cursor-not-allowed ${
              removing ? 'bg-red-500 hover:bg-red-600' : 'bg-accent-fill hover:bg-accent-fill-hover'
            }`}
          >
            {busy
              ? t('protectedGate.checking')
              : removing
                ? t('protectedGate.disableProtection')
                : t('protectedGate.unlock')}
          </button>
        </div>
        {showBiometric && (
          <button
            onClick={() => void bio.run(done)}
            disabled={bio.busy}
            className="inline-flex items-center justify-center gap-2 rounded-md border border-divider text-pn-muted hover:bg-surface-1 px-4 py-2 text-sm transition disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <Fingerprint size={15} />
            {bio.busy ? t('protectedGate.verifying') : t('protectedGate.useBiometricInstead')}
          </button>
        )}
        {onForgotPin && !removing && <ForgotPinLink kind={kind} onClick={onForgotPin} />}
        {onStartRemove && (
          <>
            <div className="border-t border-divider mt-1" />
            {removing ? (
              <button
                onClick={() => { setErr(null); onCancelRemove?.(); }}
                className="rounded-md px-4 py-2 text-sm text-pn-muted hover:bg-surface-1 transition"
              >
                {t('common:actions.cancel')}
              </button>
            ) : (
              <button
                onClick={() => { setErr(null); onStartRemove(); }}
                className="inline-flex items-center justify-center gap-2 rounded-md px-4 py-2 text-sm text-danger hover:bg-red-50 dark:hover:bg-red-950/30 transition"
              >
                <ShieldSlash size={15} />
                {t('protectedGate.disableProtection')}
              </button>
            )}
          </>
        )}
      </div>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────
 * Bootstrap - no PIN set yet
 * ──────────────────────────────────────────────────────────────── */

function BootstrapMode({
  onUnlock,
  onCancel,
  userSettings,
  onSettingsChange,
}: {
  onUnlock: () => void;
  onCancel?: () => void;
  userSettings: UserSettings;
  /** `base` is the copy this surface was rendered with; the parent applies
   *  only the credential keys that differ between it and `next`. */
  onSettingsChange: (next: UserSettings, base: UserSettings) => void;
}) {
  const { t } = useTranslation('security');
  const [pin, setNewPin] = useState('');
  const [confirm, setConfirm] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const confirmRef = useRef<PinInputHandle>(null);

  async function submit(pinVal: string, confirmVal: string) {
    setErr(null);
    if (pinVal.length !== 4) {
      setErr(t('protectedGate.pinFourDigits'));
      return;
    }
    if (pinVal !== confirmVal) {
      setErr(t('protectedGate.pinsDoNotMatch'));
      return;
    }
    setBusy(true);
    const startedAt = signInStamp();
    try {
      const hashed = await hashPin(pinVal);
      // A sign-out during the hash cleared the settings this would write back.
      if (signedOutSince(startedAt)) {
        setBusy(false);
        return;
      }
      // The hash goes into this device's cache first, read back, then the
      // settings save commits, read back too; a refusal of either says so and
      // leaves no PIN anywhere. A PIN set elsewhere meanwhile is not replaced
      // by this first one.
      const putBackHash = stagePinHash(hashed);
      if (!putBackHash || !saveCredential({ ...userSettings, ...hashed }, userSettings, onSettingsChange, { pinSalt: null, pinHash: null })) {
        putBackHash?.();
        setErr(t('pinTab.changeNotSaved'));
        setBusy(false);
        return;
      }
      // Storing the PIN is enough - the session is now considered
      // unlocked and the parent advances.
      onUnlock();
    } catch (e) {
      setErr((e as Error).message);
      setBusy(false);
    }
  }

  return (
    <div className="max-w-sm mx-auto mt-12 space-y-4">
      <GateHeader
        title={t('protectedGate.bootstrapTitle')}
        subtitle={t('protectedGate.bootstrapSubtitle')}
      />
      <div className="rounded-md border border-amber-400/40 bg-amber-50 dark:border-amber-600/30 dark:bg-amber-950/20 text-warning text-xs leading-relaxed px-3 py-2">
        {t('protectedGate.bootstrapWarning')}
      </div>
      <div className="space-y-2">
        <div className="text-xs text-pn-muted uppercase tracking-wide text-center">
          {t('protectedGate.newPin')}
        </div>
        <PinInput
          value={pin}
          onChange={(v) => {
            setNewPin(v);
            setErr(null);
          }}
          onComplete={() => confirmRef.current?.focus()}
          autoFocus
          disabled={busy}
        />
      </div>
      <div className="space-y-2">
        <div className="text-xs text-pn-muted uppercase tracking-wide text-center">
          {t('protectedGate.confirmPin')}
        </div>
        <PinInput
          ref={confirmRef}
          value={confirm}
          onChange={(v) => {
            setConfirm(v);
            setErr(null);
          }}
          onComplete={(v) => void submit(pin, v)}
          disabled={busy}
        />
      </div>
      {err && (
        <p className="text-sm text-danger text-center">
          {err}
        </p>
      )}
      <div className="flex gap-2">
        {onCancel && (
          <button
            onClick={onCancel}
            className="md:hidden flex-1 rounded-md border border-divider hover:bg-surface-1 px-3 py-2 text-sm transition"
          >
            {t('common:actions.cancel')}
          </button>
        )}
        <button
          onClick={() => void submit(pin, confirm)}
          disabled={busy || pin.length !== 4 || confirm.length !== 4}
          className="flex-1 rounded-md bg-accent-fill text-white hover:bg-accent-fill-hover px-3 py-2 text-sm font-medium transition disabled:opacity-40 disabled:cursor-not-allowed"
        >
          {busy ? t('protectedGate.saving') : t('protectedGate.setPinUnlock')}
        </button>
      </div>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────
 * PinGateModal - modal overlay for PIN verification before an action on
 * a protected note: a destructive one (delete, shred), or one that reads
 * the note out (an export, its history), which is worded as an unlock.
 * ──────────────────────────────────────────────────────────────── */

export type PinGatePurpose = 'delete' | 'unlock';

export function PinGateModal({
  onUnlock,
  onCancel,
  purpose,
  userSettings,
  onSettingsChange,
}: {
  onUnlock: () => void;
  onCancel: () => void;
  purpose: PinGatePurpose;
  /** For the PIN this modal asks to be set when none is. */
  userSettings: UserSettings;
  onSettingsChange: (next: UserSettings, base: UserSettings) => void;
}) {
  const { t } = useTranslation('security');
  const pinIsSet = hasPin();
  const kind: SecretKind = pinIsPasscode() ? 'passcode' : 'pin';
  const bioEnrolled = hasBiometricCredential();
  const [usePin, setUsePin] = useState(false);
  useEscapeToClose(onCancel);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 dark:bg-black/70"
      onClick={(e) => { if (e.target === e.currentTarget) onCancel(); }}
    >
      <div className="bg-surface-2 border border-divider rounded-lg text-pn w-full max-w-sm mx-4 p-6 space-y-4">
        {bioEnrolled && !usePin ? (
          <BiometricMode
            done={onUnlock}
            showPinFallback={pinIsSet}
            pinKind={kind}
            onUsePin={() => setUsePin(true)}
            compact
          />
        ) : pinIsSet ? (
          <ModalVerifyMode kind={kind} onUnlock={onUnlock} showBiometric={bioEnrolled} purpose={purpose} />
        ) : (
          /* No PIN and no fingerprint: set a PIN first, as the read gate on
             the same note asks, and the action runs once it is stored. */
          <BootstrapMode onUnlock={onUnlock} userSettings={userSettings} onSettingsChange={onSettingsChange} />
        )}
        <button
          onClick={onCancel}
          className="w-full rounded-md border border-divider text-pn-muted hover:bg-surface-1 px-3 py-2 text-sm font-medium transition"
        >
          {t('common:actions.cancel')}
        </button>
      </div>
    </div>
  );
}

/**
 * Compact verify mode for the modal - same logic as VerifyMode but
 * with a shorter subtitle and no top margin. A delete asks in red with the
 * delete wording; anything else asks with the unlock wording the note pane
 * uses, so an export never reads as a deletion.
 */
function ModalVerifyMode({
  kind,
  onUnlock,
  showBiometric = false,
  purpose,
}: {
  kind: SecretKind;
  onUnlock: () => void;
  showBiometric?: boolean;
  purpose: PinGatePurpose;
}) {
  const { t } = useTranslation('security');
  const [value, setValue] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [lockout, setLockout] = useState(() => getPinLockoutState());
  const inputRef = useRef<PinInputHandle>(null);
  const bio = useBiometricUnlock(setErr);

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
    if (!secretReady(kind, candidate) || busy) return;
    // The counter is shared by every PIN surface, so it is read at submit and
    // not only from the state this screen mounted with.
    const current = getPinLockoutState();
    if (current.locked) {
      setLockout(current);
      setErr(t('protectedGate.tooManyAttempts', { seconds: current.secondsLeft }));
      return;
    }
    setBusy(true);
    setErr(null);
    const stamp = pinCredentialStamp();
    const { valid: ok } = await verifyPin(candidate);
    // The secret changed on another device during the check: the answer is
    // about a secret the account no longer holds, so it opens nothing.
    if (pinCredentialStamp() !== stamp) {
      setValue('');
      setBusy(false);
      inputRef.current?.clear();
      return;
    }
    if (ok) {
      clearPinFailures();
      onUnlock();
    } else {
      const state = recordPinFailure();
      setLockout(state);
      setErr(state.locked
        ? t('protectedGate.tooManyAttempts', { seconds: state.secondsLeft })
        : kind === 'passcode' ? t('protectedGate.incorrectPasscodeRetry') : t('protectedGate.incorrectPinRetry'));
      setValue('');
      setBusy(false);
      inputRef.current?.clear();
    }
  }

  const disabled = busy || lockout.locked;

  return (
    <div className="space-y-4 text-center">
      {purpose === 'delete' ? (
        <GateHeader
          title={kind === 'passcode' ? t('protectedGate.passcodeRequired') : t('protectedGate.pinRequired')}
          subtitle={kind === 'passcode' ? t('protectedGate.deleteSubtitlePasscode') : t('protectedGate.deleteSubtitle')}
        />
      ) : (
        <GateHeader
          title={t('protectedGate.protectedItem')}
          subtitle={kind === 'passcode' ? t('protectedGate.verifySubtitlePasscode') : t('protectedGate.verifySubtitle')}
        />
      )}
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
        disabled={disabled}
      />
      {err && (
        <p className="text-sm text-danger">{err}</p>
      )}
      {lockout.locked && (
        <p className="text-xs text-pn-muted">
          {t('protectedGate.lockedFor', { seconds: lockout.secondsLeft })}
        </p>
      )}
      <div className="flex flex-col gap-2">
        <button
          onClick={() => void submit(value)}
          disabled={!secretReady(kind, value) || disabled}
          className={`w-full rounded-md text-white px-3 py-2 text-sm font-medium transition disabled:opacity-40 disabled:cursor-not-allowed ${
            purpose === 'delete' ? 'bg-red-500 hover:bg-red-600' : 'bg-accent-fill hover:bg-accent-fill-hover'
          }`}
        >
          {busy
            ? t('protectedGate.checking')
            : purpose === 'delete' ? t('protectedGate.confirmDelete') : t('protectedGate.unlock')}
        </button>
        {showBiometric && (
          <button
            onClick={() => void bio.run(onUnlock)}
            disabled={bio.busy}
            className="inline-flex items-center justify-center gap-2 rounded-md border border-divider text-pn-muted hover:bg-surface-1 px-3 py-2 text-sm transition disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <Fingerprint size={15} />
            {bio.busy ? t('protectedGate.verifying') : t('protectedGate.useBiometricInstead')}
          </button>
        )}
      </div>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────
 * Shared header
 * ──────────────────────────────────────────────────────────────── */

function GateHeader({
  title,
  subtitle,
  icon = 'lock',
}: {
  title: string;
  subtitle: string;
  icon?: 'lock' | 'biometric' | 'removeProtection';
}) {
  return (
    <>
      <div className="flex justify-center">
        <div className="inline-flex items-center justify-center w-14 h-14 rounded-full bg-accent/10 text-accent-strong">
          {icon === 'biometric' ? (
            <Fingerprint size={28} weight="duotone" aria-hidden="true" />
          ) : icon === 'removeProtection' ? (
            <ShieldSlash size={28} weight="duotone" aria-hidden="true" />
          ) : (
            <Lock size={28} weight="duotone" aria-hidden="true" />
          )}
        </div>
      </div>
      <div className="text-center">
        <h2 className="text-lg font-semibold tracking-tight">{title}</h2>
        <p className="text-sm text-pn-muted mt-1 leading-relaxed">
          {subtitle}
        </p>
      </div>
    </>
  );
}
