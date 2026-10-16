import { Check, Minus, Timer, Warning } from '../icons';
import { useEffect, useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useEscapeToClose } from '../useEscapeToClose';
import {
  buildPinWrap,
  hasBiometricCredential,
  hasPinWrappedPhrase,
  isBiometricKeyBound,
  onWrappedBlobChange,
  removeStoredPhrase,
  storeBuiltPinWrap,
} from '../biometric';
import { HelpChip } from '../HelpChip';
import {
  cachedPinCredential,
  clearPinFailures,
  credentialStamp,
  getPinLockoutState,
  hashPin,
  hasPin,
  markPinUnlocked,
  pinChangeNeedsWrap,
  pinCredentialStamp,
  pinIsPasscode,
  recordPinFailure,
  stagePinHash,
  verifyPin,
  type PinCredential,
} from '../pin';
import { clearPin, restoreUnsavedClear } from '../pinRecovery';
import { isTrustedDevice } from '../trustStorage';
import { signInStamp, signedOutSince } from '../liveSignIn';
import { ForgotPinLink, PinRecoveryForm } from '../PinRecoveryForm';
import { PinInput, type PinInputHandle } from '../PinInput';
import { PasscodeInput, SecretInput } from '../PasscodeInput';
import {
  isValidPasscode,
  normalizeSecret,
  PASSCODE_MAX_CHARS,
  PASSCODE_MIN_CHARS,
  PASSCODE_SETUP_ENABLED,
  passcodeRules,
  secretReady,
  type SecretKind,
} from '../secretKind';
import { SectionEyebrow, SETTINGS_HELP, SettingsCallout } from '../settingsUI';
import { loadLocalSettings, saveCredential, type UserSettings } from '../userSettings';
import { TIMEOUT_OPTIONS } from './timeoutOptions';

/**
 * PIN tab - set, change, or remove the account's secret inline, a 4-digit PIN
 * or a longer passcode, switch between the two, and pick how long an unlock
 * lasts. That window covers the phrase view and PIN-protected notes; the app
 * lock screen has its own, in the Biometric tab. A switch is a change: the
 * current secret first, then the new hash and wrap in one write.
 * Spec: ops/docs/plans/app-lock-passcode.md
 */
export function PinTab({
  phrase,
  timeoutMinutes,
  onTimeoutChange,
  userSettings,
  onSettingsChange,
  reason,
  onPinCreated,
}: {
  phrase: string;
  timeoutMinutes: number;
  onTimeoutChange: (minutes: number) => void;
  userSettings: UserSettings;
  /** `base` is the copy this surface was rendered with; the parent applies
   *  only the credential keys that differ between it and `next`. */
  onSettingsChange: (next: UserSettings, base: UserSettings) => void;
  /** Why the user landed here, when it was not their own idea. Protecting
   *  a note opens this tab, and without a word of explanation the demand
   *  for a PIN reads as an arbitrary one. */
  reason?: 'protect';
  /** A PIN now exists. The parent uses it to return a user who was sent here
   *  from another tab to create one. */
  onPinCreated?: () => void;
}) {
  const { t } = useTranslation('security');
  // Read `hasPin()` once on mount and flip locally on set/remove so the
  // UI transitions without remounting.
  const [pinExists, setPinExists] = useState(() => hasPin());
  // The kind the account holds, read from its hash salt, and the kind the
  // new-secret step sets. Setting a passcode is behind PASSCODE_SETUP_ENABLED;
  // checking one never is, so an older device can change an account's
  // passcode back to a PIN.
  const [existingKind, setExistingKind] = useState<SecretKind>(() => (pinIsPasscode() ? 'passcode' : 'pin'));
  const [newKind, setNewKind] = useState<SecretKind>(() =>
    PASSCODE_SETUP_ENABLED && pinIsPasscode() ? 'passcode' : 'pin');
  const [oldPinVerified, setOldPinVerified] = useState(false);
  // The phrase route out of a forgotten PIN, and the line that says it
  // worked. Spec: ops/docs/plans/pin-recovery.md
  const [recovering, setRecovering] = useState(false);
  // The kind that was cleared, for the line that says it worked.
  const [recovered, setRecovered] = useState<SecretKind | null>(null);
  const [oldPin, setOldPin] = useState('');
  const [oldPinError, setOldPinError] = useState<string | null>(null);
  const [oldPinBusy, setOldPinBusy] = useState(false);
  const [pin, setPin] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // The confirm box of the older-apps notice below; a passcode is set only
  // once it is ticked.
  const [devicesUpdated, setDevicesUpdated] = useState(false);
  const kindFromTiles = useRef(false);
  const [savedFlash, setSavedFlash] = useState(false);
  const [lockout, setLockout] = useState(() => getPinLockoutState());
  const oldPinRef = useRef<PinInputHandle>(null);
  const newPinRef = useRef<PinInputHandle>(null);
  const confirmRef = useRef<PinInputHandle>(null);

  useEffect(() => {
    if (!lockout.locked) return;
    const id = setInterval(() => {
      const state = getPinLockoutState();
      setLockout(state);
      if (!state.locked) setOldPinError(null);
    }, 1000);
    return () => clearInterval(id);
  }, [lockout.locked]);

  // A secret changed on another device reaches this tab as new settings, after
  // the sync pass refreshed the hash cache. The tab re-reads what the account
  // holds and asks for the current secret again, so it never draws a field for
  // a secret the account no longer has. Its own writes land here too, and find
  // the state they already set.
  const credential = `${userSettings.pinHash ?? ''}:${userSettings.pinSalt ?? ''}`;
  const seenCredential = useRef(credential);
  // The cached hash the current-secret step proved, which a change must
  // still find in place when it saves.
  const proved = useRef<PinCredential | null>(null);
  function followAccount() {
    const kind: SecretKind = pinIsPasscode() ? 'passcode' : 'pin';
    setPinExists(hasPin());
    setExistingKind(kind);
    setNewKind(PASSCODE_SETUP_ENABLED ? kind : 'pin');
    setOldPinVerified(false);
    proved.current = null;
    setOldPin('');
    setOldPinError(null);
    setPin('');
    setConfirm('');
  }
  useEffect(() => {
    if (seenCredential.current === credential) return;
    seenCredential.current = credential;
    followAccount();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [credential]);

  // The biometric line below reads storage while it renders; a change another
  // tab makes (an enrollment, a set-up-again, a removal) renders it again.
  const [, setBlobVersion] = useState(0);
  useEffect(() => onWrappedBlobChange(() => setBlobVersion((v) => v + 1)), []);

  const needsOldPin = pinExists && !oldPinVerified;
  // While biometric unlock on this device is a presence gate, its wrap key
  // sits beside the wrap it opens, so it is the weaker door and a longer
  // secret here does not raise the cost of a stolen copy of the storage.
  // Spec: ops/docs/plans/biometric-key-binding.md (part C)
  const biometricWeaker = hasBiometricCredential() && !isBiometricKeyBound();

  async function verifyOldPin(candidate: string) {
    if (!secretReady(existingKind, candidate) || oldPinBusy) return;
    // The counter is shared by every PIN surface, so it is read at submit and
    // not only from the state this tab mounted with.
    const current = getPinLockoutState();
    if (current.locked) {
      setLockout(current);
      setOldPinError(t('pinTab.tooManyAttempts', { seconds: current.secondsLeft }));
      return;
    }
    setOldPinBusy(true);
    setOldPinError(null);
    const startedAt = signInStamp();
    const credentialAtStart = seenCredential.current;
    const checked = cachedPinCredential();
    const stamp = credentialStamp(checked);
    const { valid: ok } = await verifyPin(candidate);
    // The secret changed during the check, on another device or in another
    // tab of this browser (which reaches the cache and not these props): this
    // answer is about a secret the account no longer holds, so it opens nothing.
    if (seenCredential.current !== credentialAtStart || pinCredentialStamp() !== stamp) {
      setOldPinBusy(false);
      return;
    }
    if (ok) {
      clearPinFailures();
      // If app lock is enabled but no local PIN wrap exists, create it
      // and sync the blob so all devices get it.
      // The flag is synced and the wrap is not: a device the user marked
      // untrusted can be told the lock is on by another device, and must
      // still not write a durable copy of the phrase here.
      if (userSettings.appLockEnabled && isTrustedDevice() && !hasPinWrappedPhrase()) {
        // Built in memory and stored only while the secret is still the
        // account's, with no await in between, so a wrap under a secret
        // replaced meanwhile never overwrites the newer one.
        const blob = await buildPinWrap(phrase, candidate);
        if (pinCredentialStamp() !== stamp || seenCredential.current !== credentialAtStart) {
          setOldPinBusy(false);
          return;
        }
        storeBuiltPinWrap(blob, startedAt);
        removeStoredPhrase();
        onSettingsChange({ ...userSettings, ...blob }, userSettings);
      }
      proved.current = checked;
      setOldPinVerified(true);
      setOldPin('');
      setTimeout(() => newPinRef.current?.focus(), 50);
    } else {
      const state = recordPinFailure();
      setLockout(state);
      setOldPinError(state.locked
        ? t('pinTab.tooManyAttempts', { seconds: state.secondsLeft })
        : existingKind === 'passcode' ? t('pinTab.incorrectPasscode') : t('pinTab.incorrectPin'));
      setOldPin('');
      oldPinRef.current?.clear();
    }
    setOldPinBusy(false);
  }

  function reset() {
    setPin('');
    setConfirm('');
    setError(null);
    setDevicesUpdated(false);
  }

  async function submit(pinVal: string, confirmVal: string) {
    setError(null);
    // A passcode that breaks a rule gets no line here: the live checks under
    // the field already say which one.
    const problem = newKind === 'passcode'
      ? !isValidPasscode(pinVal) || !devicesUpdated ? ''
        : normalizeSecret(pinVal) !== normalizeSecret(confirmVal) ? t('pinTab.passcodesDoNotMatch') : null
      : pinVal.length !== 4 ? t('pinTab.pinFourDigits')
        : pinVal !== confirmVal ? t('pinTab.pinsDoNotMatch') : null;
    if (problem !== null) {
      if (problem) setError(problem);
      return;
    }
    // The secret this replaces: the one the current-secret step proved, or
    // none when the account has none yet.
    const replacing: PinCredential | null = pinExists ? proved.current : { pinSalt: null, pinHash: null };
    if (!replacing) {
      followAccount();
      return;
    }
    setBusy(true);
    const startedAt = signInStamp();
    try {
      // Built in memory, nothing written yet. The wrap follows the hash
      // (pinChangeNeedsWrap), on every device, so the account's wrap follows
      // the new PIN. Pinned by tests/pinChange.test.ts.
      const hashed = await hashPin(pinVal);
      const updated: UserSettings = { ...userSettings, ...hashed };
      // Asked of the cache as well, after the hash derived: it knows of a lock
      // armed in another tab before this tab's copy does, and when no wrap is
      // built nothing awaits between this answer and the commit below.
      const wrap = pinChangeNeedsWrap(updated) || pinChangeNeedsWrap(loadLocalSettings())
        ? await buildPinWrap(phrase, pinVal)
        : null;
      if (wrap) Object.assign(updated, wrap);
      // A sign-out during the PIN hash or the wrap cleared the settings this
      // would write back, the new PIN and its wrap.
      if (signedOutSince(startedAt)) return;
      // Another tab of this browser, or a sync pass, replaced the secret after
      // the step that proved it: this tab saves nothing and asks for the
      // secret the account holds now.
      if (pinCredentialStamp() !== credentialStamp(replacing)) {
        followAccount();
        return;
      }
      // Whether the lock is on now, which the strip below follows.
      const now = loadLocalSettings();
      // This device's copies go in first, each read back and each with a
      // put-back: the hash every gate here checks, and on a trusted device the
      // new wrap (an untrusted one keeps no copy). A refused one says so and
      // leaves everything as it was.
      const putBackHash = stagePinHash(hashed);
      if (!putBackHash) {
        setError(t('pinTab.changeNotSaved'));
        return;
      }
      let putBackWrap: (() => void) | null = null;
      if (wrap && isTrustedDevice()) {
        try {
          putBackWrap = storeBuiltPinWrap(wrap, startedAt);
        } catch {
          putBackHash();
          setError(t('pinTab.changeNotSaved'));
          return;
        }
      }
      // The settings save is the commit, read back whole: until it lands the
      // old secret stays in force everywhere, its hash, its wrap and the
      // phrase at rest. Pinned by tests/pinTabWrites.test.ts.
      if (!saveCredential(updated, userSettings, onSettingsChange, replacing)) {
        putBackWrap?.();
        putBackHash();
        setError(t('pinTab.changeNotSaved'));
        return;
      }
      // Last, once the new wrap is this device's door: with the lock on, the
      // phrase at rest goes so the lock is the only door.
      if (putBackWrap && now.appLockEnabled) removeStoredPhrase();
      // This tab's own write: the settings that come back with it are not a
      // change made elsewhere, and must not reset the steps below.
      seenCredential.current = `${updated.pinHash ?? ''}:${updated.pinSalt ?? ''}`;
      // Mark unlocked so the user isn't immediately re-prompted for
      // the PIN they just created.
      markPinUnlocked();
      setPinExists(true);
      setExistingKind(newKind);
      setOldPinVerified(false);
      reset();
      setSavedFlash(true);
      setTimeout(() => setSavedFlash(false), 1800);
      onPinCreated?.();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const [showRemoveConfirm, setShowRemoveConfirm] = useState(false);

  /** `checked` is the cached hash the remove dialog proved the secret against. */
  async function doRemovePin(checked: PinCredential) {
    const stamp = credentialStamp(checked);
    // The same clear the phrase route performs, so the two cannot drift.
    // App lock is left alone: it is a synced setting and an enrolled
    // fingerprint is not, so removing a PIN here used to switch off a lock
    // another device could still open. clearPin carries the reasoning, and
    // answers null, having removed nothing, when the wrap is this device's
    // last door and the phrase did not read back at rest, or when another tab
    // replaced the secret meanwhile, which takes nothing off and says nothing.
    const cleared = await clearPin(userSettings, phrase, () => pinCredentialStamp() === stamp);
    if (!cleared) {
      if (pinCredentialStamp() === stamp) setError(t('appLock.phraseNotSaved'));
      return;
    }
    // A save the store refused, or settings that hold a secret saved since,
    // leave the account's PIN in force, so this device gets its hash and its
    // wrap back.
    if (!saveCredential(cleared.settings, userSettings, onSettingsChange, checked)) {
      await restoreUnsavedClear(phrase, cleared);
      setError(t('pinTab.changeNotSaved'));
      return;
    }
    seenCredential.current = ':';
    setPinExists(false);
    setExistingKind('pin');
    setOldPinVerified(false);
    reset();
  }

  if (recovering) {
    return (
      <div className="space-y-3">
        <PinRecoveryForm
          kind={existingKind}
          phrase={phrase}
          userSettings={userSettings}
          onSettingsChange={onSettingsChange}
          onCleared={() => {
            seenCredential.current = ':';
            setRecovering(false);
            setRecovered(existingKind);
            setPinExists(false);
            setExistingKind('pin');
            setOldPinVerified(false);
            reset();
          }}
          onCancel={() => setRecovering(false)}
        />
        <HelpChip surface="pin" className="pt-2 border-t border-divider" />
      </div>
    );
  }

  return (
    <div className="@container space-y-3">
      {needsOldPin && biometricWeaker && (
        <SettingsCallout>{t('pinTab.biometricWeaker')}</SettingsCallout>
      )}
      {needsOldPin ? (
        <>
          <p className={`${SETTINGS_HELP} leading-relaxed`}>
            {existingKind === 'passcode' ? t('pinTab.enterCurrentPasscode') : t('pinTab.enterCurrent')}
          </p>
          <div className="space-y-1.5">
            <SectionEyebrow className="text-center">
              {existingKind === 'passcode' ? t('pinTab.currentPasscode') : t('pinTab.currentPin')}
            </SectionEyebrow>
            <SecretInput
              kind={existingKind}
              ref={oldPinRef}
              value={oldPin}
              onChange={(v) => {
                setOldPin(v);
                setOldPinError(null);
              }}
              onComplete={(v) => void verifyOldPin(v)}
              autoFocus
              compact
              disabled={oldPinBusy || lockout.locked}
            />
          </div>
          {oldPinError && (
            <p className="text-sm text-danger text-center">
              {oldPinError}
            </p>
          )}
          <button
            onClick={() => void verifyOldPin(oldPin)}
            disabled={!secretReady(existingKind, oldPin) || oldPinBusy}
            className="w-full rounded-md bg-accent-fill text-white hover:bg-accent-fill-hover px-3 py-2 text-sm font-medium transition disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {oldPinBusy ? t('pinTab.checking') : t('pinTab.verify')}
          </button>
          <ForgotPinLink kind={existingKind} onClick={() => setRecovering(true)} />
        </>
      ) : (
        <>
          <div className="space-y-2">
            {reason === 'protect' && (
              <SettingsCallout>{t('pinTab.protectReason')}</SettingsCallout>
            )}
            {recovered && (
              <p className="text-sm text-accent">
                {recovered === 'passcode' ? t('pinRecovery.clearedPasscode') : t('pinRecovery.cleared')}
              </p>
            )}
            <p className={`${SETTINGS_HELP} leading-relaxed`}>
              {!pinExists
                ? (PASSCODE_SETUP_ENABLED ? t('pinTab.chooseIntro') : t('pinTab.setIntro'))
                : newKind === 'passcode'
                  ? t('pinTab.replaceWithPasscode')
                  : existingKind === 'passcode'
                    ? t('pinTab.replacePasscodeWithPin')
                    : t('pinTab.replaceExisting')}
            </p>
          </div>

          {PASSCODE_SETUP_ENABLED && (
            <SecretKindTiles
              value={newKind}
              appLock={userSettings.appLockEnabled}
              disabled={busy}
              onChange={(kind) => {
                // Arrow keys move through the tiles, so a choice made there
                // keeps the focus in the group instead of jumping to a field.
                kindFromTiles.current = true;
                setNewKind(kind);
                reset();
              }}
            />
          )}
          {biometricWeaker && (
            <SettingsCallout>{t('pinTab.biometricWeaker')}</SettingsCallout>
          )}

          {newKind === 'passcode' ? (
            <>
              <OlderAppsNotice />
              <NewPasscodeFields
                value={pin}
                confirm={confirm}
                busy={busy}
                onChange={(v) => { setPin(v); setError(null); }}
                onConfirmChange={(v) => { setConfirm(v); setError(null); }}
                onSubmit={() => void submit(pin, confirm)}
                autoFocus={!kindFromTiles.current}
              />
              <OlderAppsConfirm checked={devicesUpdated} onChange={setDevicesUpdated} disabled={busy} />
            </>
          ) : (
            <div className={NEW_SECRET_FIELDS}>
              <div className="space-y-1.5">
                <SectionEyebrow className="text-center">
                  {t('pinTab.newPin')}
                </SectionEyebrow>
                <PinInput
                  ref={newPinRef}
                  value={pin}
                  onChange={(v) => {
                    setPin(v);
                    setError(null);
                  }}
                  onComplete={() => confirmRef.current?.focus()}
                  compact
                  disabled={busy}
                />
              </div>

              <div className="space-y-1.5">
                <SectionEyebrow className="text-center">
                  {t('pinTab.confirmPin')}
                </SectionEyebrow>
                <PinInput
                  ref={confirmRef}
                  value={confirm}
                  onChange={(v) => {
                    setConfirm(v);
                    setError(null);
                  }}
                  onComplete={(v) => void submit(pin, v)}
                  compact
                  disabled={busy}
                />
              </div>
            </div>
          )}

          {error && (
            <p className="text-sm text-danger text-center">
              {error}
            </p>
          )}
          {savedFlash && (
            <p className="text-sm text-accent text-center">
              {existingKind === 'passcode' ? t('pinTab.passcodeSaved') : t('pinTab.pinSaved')}
            </p>
          )}

          <div data-setting="security.setPin" className="flex gap-2">
            <button
              onClick={() => void submit(pin, confirm)}
              disabled={busy || (newKind === 'passcode'
                ? !isValidPasscode(pin) || normalizeSecret(pin) !== normalizeSecret(confirm) || !devicesUpdated
                : pin.length !== 4 || confirm.length !== 4)}
              className="flex-1 rounded-md bg-accent-fill text-white hover:bg-accent-fill-hover px-4 py-2 text-sm font-medium transition disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {busy
                ? t('common:state.saving')
                : newKind === 'passcode'
                  ? t('pinTab.setPasscode')
                  : pinExists ? t('pinTab.updatePin') : t('pinTab.setPin')}
            </button>
            {pinExists && (
              <button
                data-setting="security.removePin"
                onClick={() => setShowRemoveConfirm(true)}
                disabled={busy}
                className="rounded-md border border-divider text-pn-muted hover:bg-surface-1 hover:text-danger px-4 py-2 text-sm transition"
              >
                {existingKind === 'passcode' ? t('removePinDialog.removePasscode') : t('pinTab.removePin')}
              </button>
            )}
          </div>
        </>
      )}

      {/* One window for the phrase view and every PIN-protected note, from
          the moment of the unlock. Disabled when no PIN is set (nothing to
          time). */}
      <div data-setting="security.reaskAfter" className="pt-3 border-t border-divider">
        <label className="block">
          <SectionEyebrow className="mb-1.5" icon={Timer}>
            {t('pinTab.reaskAfter')}
          </SectionEyebrow>
          <select
            value={String(timeoutMinutes)}
            onChange={(e) => onTimeoutChange(Number(e.target.value))}
            disabled={!pinExists}
            className="w-full rounded-md bg-surface-1 border border-divider px-3 py-2 text-sm focus:outline-none focus:border-accent disabled:opacity-50"
          >
            {TIMEOUT_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {t(opt.labelKey)}
              </option>
            ))}
          </select>
          <p className={`${SETTINGS_HELP} mt-1.5 leading-relaxed`}>
            {t('pinTab.reaskHint')}
          </p>
        </label>
      </div>

      <HelpChip surface="pin" className="pt-3 border-t border-divider" />

      {showRemoveConfirm && (
        <RemovePinDialog
          kind={existingKind}
          credential={seenCredential}
          onConfirm={(checked) => {
            void doRemovePin(checked);
            setShowRemoveConfirm(false);
          }}
          onClose={() => setShowRemoveConfirm(false)}
        />
      )}
    </div>
  );
}

/**
 * Removal-of-PIN gate: requires fresh re-entry of the current PIN
 * regardless of whether a prior `oldPinVerified` flag is still set
 * earlier in the session. Without this gate, a casual passerby who
 * watched one PIN entry could remove protection in two clicks. See
 * gap #26.
 */
function RemovePinDialog({
  kind,
  credential,
  onConfirm,
  onClose,
}: {
  kind: SecretKind;
  /** The account credential the tab last saw, so a check that outlives a
   *  change made elsewhere removes nothing. */
  credential: { readonly current: string };
  /** Receives the cached hash the secret was checked against. */
  onConfirm: (checked: PinCredential) => void;
  onClose: () => void;
}) {
  const { t } = useTranslation('security');
  const [pin, setPin] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lockout, setLockout] = useState(() => getPinLockoutState());
  const inputRef = useRef<PinInputHandle>(null);
  const hasBio = hasBiometricCredential();

  useEscapeToClose(onClose);

  useEffect(() => {
    if (!lockout.locked) return;
    const id = setInterval(() => {
      const state = getPinLockoutState();
      setLockout(state);
      if (!state.locked) setError(null);
    }, 1000);
    return () => clearInterval(id);
  }, [lockout.locked]);

  async function submit(candidate: string) {
    if (!secretReady(kind, candidate) || busy) return;
    const current = getPinLockoutState();
    if (current.locked) {
      setLockout(current);
      setError(t('pinTab.tooManyAttempts', { seconds: current.secondsLeft }));
      return;
    }
    setBusy(true);
    setError(null);
    const credentialAtStart = credential.current;
    const checked = cachedPinCredential();
    const { valid } = await verifyPin(candidate);
    // A secret replaced during the check, on another device or in another tab
    // of this browser, is not the one this answer is about.
    if (credential.current !== credentialAtStart || pinCredentialStamp() !== credentialStamp(checked)) {
      onClose();
      return;
    }
    if (valid) {
      clearPinFailures();
      onConfirm(checked);
    } else {
      const state = recordPinFailure();
      setLockout(state);
      setError(state.locked
        ? t('pinTab.tooManyAttempts', { seconds: state.secondsLeft })
        : kind === 'passcode' ? t('pinTab.incorrectPasscodeRetry') : t('pinTab.incorrectPinRetry'));
      setPin('');
      setBusy(false);
      inputRef.current?.clear();
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 dark:bg-black/70"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="bg-surface-2 border border-divider rounded-lg max-w-sm w-full mx-4 p-5 space-y-4 text-pn">
        <h2 className="text-lg font-semibold">
          {kind === 'passcode' ? t('removePinDialog.titlePasscode') : t('removePinDialog.title')}
        </h2>
        <p className="text-sm text-pn-soft leading-relaxed">
          {kind === 'passcode'
            ? (hasBio ? t('removePinDialog.introWithBioPasscode') : t('removePinDialog.introNoBioPasscode'))
            : (hasBio ? t('removePinDialog.introWithBio') : t('removePinDialog.introNoBio'))}
        </p>
        <SecretInput
          kind={kind}
          ref={inputRef}
          value={pin}
          onChange={(v) => {
            setPin(v);
            setError(null);
          }}
          onComplete={(v) => void submit(v)}
          autoFocus
          disabled={busy || lockout.locked}
        />
        {error && (
          <p className="text-sm text-danger text-center">
            {error}
          </p>
        )}
        <div className="flex gap-2">
          <button
            type="button"
            onClick={onClose}
            className="flex-1 rounded-md border border-divider hover:bg-surface-1 px-3 py-2 text-sm transition"
          >
            {t('common:actions.cancel')}
          </button>
          <button
            type="button"
            onClick={() => void submit(pin)}
            disabled={!secretReady(kind, pin) || busy || lockout.locked}
            className="flex-1 rounded-md bg-red-600 text-white hover:bg-red-700 px-3 py-2 text-sm font-medium transition disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {busy
              ? t('removePinDialog.verifying')
              : kind === 'passcode' ? t('removePinDialog.removePasscode') : t('removePinDialog.removePin')}
          </button>
        </div>
      </div>
    </div>
  );
}

/**
 * The new passcode, its confirmation and the live rule checks. The set button
 * below stays disabled until both rules pass and the two fields match; the
 * field never submits itself at a length.
 */
/** The new and the confirm field side by side once the tab is wide enough for
 *  both rows of PIN boxes, stacked below that. */
const NEW_SECRET_FIELDS = 'grid grid-cols-1 @md:grid-cols-2 items-start gap-x-6 gap-y-3';

function NewPasscodeFields({
  value,
  confirm,
  busy,
  onChange,
  onConfirmChange,
  onSubmit,
  autoFocus,
}: {
  value: string;
  confirm: string;
  busy: boolean;
  onChange: (v: string) => void;
  onConfirmChange: (v: string) => void;
  onSubmit: () => void;
  autoFocus: boolean;
}) {
  const { t } = useTranslation('security');
  const confirmRef = useRef<PinInputHandle>(null);
  const rules = passcodeRules(value);
  const mismatch = confirm.length > 0 && normalizeSecret(confirm) !== normalizeSecret(value);
  const checks = [
    { ok: rules.longEnough, label: t('pinTab.ruleLength', { min: PASSCODE_MIN_CHARS }) },
    { ok: rules.notOnlyDigits, label: t('pinTab.ruleNotDigits') },
  ];
  return (
    <div className={NEW_SECRET_FIELDS}>
      <div className="space-y-1.5">
        <SectionEyebrow className="text-center">{t('pinTab.newPasscode')}</SectionEyebrow>
        <PasscodeInput
          value={value}
          onChange={onChange}
          onSubmit={() => confirmRef.current?.focus()}
          ariaLabel={t('pinTab.newPasscode')}
          autoFocus={autoFocus}
          compact
          disabled={busy}
        />
        <ul className="space-y-0.5 pt-1">
          {checks.map((c) => (
            <li key={c.label} className={`flex items-center gap-1.5 text-xs ${c.ok ? 'text-success' : 'text-pn-soft'}`}>
              <Check size={13} weight="bold" className={c.ok ? '' : 'opacity-30'} aria-hidden="true" />
              {c.label}
            </li>
          ))}
          {!rules.notTooLong && (
            <li className="text-xs text-danger">{t('pinTab.ruleMax', { max: PASSCODE_MAX_CHARS })}</li>
          )}
        </ul>
      </div>
      <div className="space-y-1.5">
        <SectionEyebrow className="text-center">{t('pinTab.confirmPasscode')}</SectionEyebrow>
        <PasscodeInput
          ref={confirmRef}
          value={confirm}
          onChange={onConfirmChange}
          onSubmit={onSubmit}
          ariaLabel={t('pinTab.confirmPasscode')}
          compact
          disabled={busy}
        />
        {mismatch && <p className="text-xs text-pn-soft">{t('pinTab.passcodesDoNotMatch')}</p>}
      </div>
    </div>
  );
}

/**
 * The choice between the two kinds of secret, as two tiles that compare them
 * row by row. The one real difference is what a person who gets past the
 * device's screen lock can do with the stored hash: try all 10,000 PINs, or
 * face a passcode's length and alphabet. That difference exists only while
 * the app lock is on: with it off, the app opens without asking for either
 * secret, so the row then reads the same in both tiles. Native radios keep
 * arrow-key moves and the group's name for screen readers. Each tile is a
 * subgrid of the group, so a row that wraps in one tile keeps the next row
 * level in both.
 * Spec: ops/docs/THREAT_MODEL.md (PIN protection)
 */
function SecretKindTiles({
  value,
  appLock,
  onChange,
  disabled,
}: {
  value: SecretKind;
  appLock: boolean;
  onChange: (kind: SecretKind) => void;
  disabled: boolean;
}) {
  const { t } = useTranslation('security');
  const name = useId();
  const stolenNoLock: [string, 'meh', string] = [t('pinTab.rowStolen'), 'meh', t('pinTab.stolenNoLock')];
  const tiles: { kind: SecretKind; title: string; badge: string; rows: [string, 'yes' | 'no' | 'meh', string][] }[] = [
    {
      kind: 'pin',
      title: t('pinTab.kindPin'),
      badge: t('pinTab.badgeDefault'),
      rows: [
        [t('pinTab.rowTyping'), 'yes', t('pinTab.typingPin')],
        [t('pinTab.rowNearby'), 'yes', t('pinTab.nearby')],
        appLock ? [t('pinTab.rowStolen'), 'no', t('pinTab.stolenPin')] : stolenNoLock,
        [t('pinTab.rowForgot'), 'yes', t('pinTab.forgot')],
      ],
    },
    {
      kind: 'passcode',
      title: t('pinTab.kindPasscode'),
      badge: t('pinTab.badgeStronger'),
      rows: [
        [t('pinTab.rowTyping'), 'meh', t('pinTab.typingPasscode', { min: PASSCODE_MIN_CHARS })],
        [t('pinTab.rowNearby'), 'yes', t('pinTab.nearby')],
        appLock ? [t('pinTab.rowStolen'), 'yes', t('pinTab.stolenPasscode')] : stolenNoLock,
        [t('pinTab.rowForgot'), 'yes', t('pinTab.forgot')],
      ],
    },
  ];
  return (
    <div role="radiogroup" aria-label={t('pinTab.kindGroup')} className="grid grid-cols-1 @lg:grid-cols-2 gap-2.5">
      {tiles.map((tile) => {
        const on = value === tile.kind;
        return (
          <label
            key={tile.kind}
            className={`relative grid grid-rows-subgrid row-span-5 gap-y-2.5 rounded-lg border bg-surface-1 px-3.5 py-3 cursor-pointer transition has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-offset-2 has-[:focus-visible]:outline-accent ${
              on ? 'border-accent ring-1 ring-accent' : 'border-divider hover:border-pn-soft'
            } ${disabled ? 'opacity-60 cursor-not-allowed' : ''}`}
          >
            <input
              type="radio"
              name={name}
              value={tile.kind}
              checked={on}
              disabled={disabled}
              onChange={() => onChange(tile.kind)}
              className="sr-only"
            />
            <span className="flex items-center justify-between gap-2 mb-0.5">
              <span className="flex items-center gap-2 text-sm font-medium text-pn">
                <span
                  aria-hidden="true"
                  className={`grid place-items-center size-4 rounded-full border ${on ? 'border-accent' : 'border-pn-soft'}`}
                >
                  {on && <span className="size-2 rounded-full bg-accent-fill" />}
                </span>
                {tile.title}
              </span>
              <span
                className={`rounded px-2 py-0.5 text-[11px] font-medium ${
                  tile.kind === 'pin' ? 'bg-accent/10 text-accent' : 'bg-success/10 text-success'
                }`}
              >
                {tile.badge}
              </span>
            </span>
            {tile.rows.map(([label, mark, text]) => (
              <span key={label} className="block">
                <span className="block text-[11px] text-pn-soft">{label}</span>
                <span className="flex items-start gap-1.5 text-xs leading-relaxed text-pn">
                  {mark === 'yes' && <Check size={14} aria-hidden="true" className="shrink-0 mt-0.5 text-success" />}
                  {mark === 'no' && <Warning size={14} aria-hidden="true" className="shrink-0 mt-0.5 text-warning" />}
                  {mark === 'meh' && <Minus size={14} aria-hidden="true" className="shrink-0 mt-0.5 text-pn-soft" />}
                  <span>{text}</span>
                </span>
              </span>
            ))}
          </label>
        );
      })}
    </div>
  );
}

// ---- Temporary, English only: the older-apps notice ---------------------------
//
// Setting a passcode shipped in the same release that taught every app to read
// one, so a device still on an older version shows four PIN boxes and cannot
// take the passcode; there, only the recovery phrase gets in. This notice and
// its confirm box carry the people who set a passcode across that gap. They
// are English in every locale by the owner's decision of 2026-10-15 and stay
// out of the catalogs on purpose, so no translation batch picks them up. Remove
// both, with the devicesUpdated state, once every channel ships v0.632.5 or
// newer. Spec: ops/docs/plans/app-lock-passcode.md (section 11, step 6)
const OLDER_APPS_NOTICE =
  'Before you switch, update PrivacyNotes on every device you use. An older version asks for a 4-digit PIN and will not take your passcode. If that happens, use your recovery phrase there.';
const OLDER_APPS_CONFIRM = 'I updated PrivacyNotes on all my devices';

function OlderAppsNotice() {
  return (
    <div className="rounded-md border border-amber-200 dark:border-amber-800/50 bg-amber-50 dark:bg-amber-900/20 p-3 text-xs leading-relaxed text-amber-800 dark:text-amber-200">
      {OLDER_APPS_NOTICE}
    </div>
  );
}

function OlderAppsConfirm({
  checked,
  onChange,
  disabled,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled: boolean;
}) {
  return (
    <label className="flex items-start gap-2 text-xs leading-relaxed text-pn cursor-pointer">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        disabled={disabled}
        className="mt-0.5 accent-accent"
      />
      <span>{OLDER_APPS_CONFIRM}</span>
    </label>
  );
}
// ---- end of the temporary older-apps notice ------------------------------------
