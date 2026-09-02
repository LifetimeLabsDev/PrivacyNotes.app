import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useEscapeToClose } from '../useEscapeToClose';
import {
  hasBiometricCredential,
  hasPinWrappedPhrase,
  removeStoredPhrase,
  wrapPhraseWithPin,
} from '../biometric';
import { HelpChip } from '../HelpChip';
import {
  clearPinFailures,
  getPinLockoutState,
  hasPin,
  markPinUnlocked,
  recordPinFailure,
  setPin as storePin,
  verifyPin,
} from '../pin';
import { clearPin } from '../pinRecovery';
import { ForgotPinLink, PinRecoveryForm } from '../PinRecoveryForm';
import { PinInput, type PinInputHandle } from '../PinInput';
import { SectionEyebrow, SETTINGS_HELP, SettingsCallout } from '../settingsUI';
import type { UserSettings } from '../userSettings';
import { TIMEOUT_OPTIONS } from './timeoutOptions';

/**
 * PIN tab - set, change, or remove a 4-digit PIN inline. Shares the
 * re-lock timeout selector with the Biometric tab so the user has one
 * setting governing both gates.
 */
export function PinTab({
  phrase,
  timeoutMinutes,
  onTimeoutChange,
  userSettings,
  onSettingsChange,
  reason,
}: {
  phrase: string;
  timeoutMinutes: number;
  onTimeoutChange: (minutes: number) => void;
  userSettings: UserSettings;
  onSettingsChange: (next: UserSettings) => void;
  /** Why the user landed here, when it was not their own idea. Protecting
   *  a note opens this tab, and without a word of explanation the demand
   *  for a PIN reads as an arbitrary one. */
  reason?: 'protect';
}) {
  const { t } = useTranslation('security');
  // Read `hasPin()` once on mount and flip locally on set/remove so the
  // UI transitions without remounting.
  const [pinExists, setPinExists] = useState(() => hasPin());
  const [oldPinVerified, setOldPinVerified] = useState(false);
  // The phrase route out of a forgotten PIN, and the line that says it
  // worked. Spec: ops/docs/plans/pin-recovery.md
  const [recovering, setRecovering] = useState(false);
  const [recovered, setRecovered] = useState(false);
  const [oldPin, setOldPin] = useState('');
  const [oldPinError, setOldPinError] = useState<string | null>(null);
  const [oldPinBusy, setOldPinBusy] = useState(false);
  const [pin, setPin] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
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

  const needsOldPin = pinExists && !oldPinVerified;

  async function verifyOldPin(candidate: string) {
    if (candidate.length !== 4 || oldPinBusy || lockout.locked) return;
    setOldPinBusy(true);
    setOldPinError(null);
    const { valid: ok } = await verifyPin(candidate);
    if (ok) {
      clearPinFailures();
      // If app lock is enabled but no local PIN wrap exists, create it
      // and sync the blob so all devices get it.
      if (userSettings.appLockEnabled && !hasPinWrappedPhrase()) {
        const blob = await wrapPhraseWithPin(phrase, candidate);
        removeStoredPhrase();
        onSettingsChange({ ...userSettings, ...blob });
      }
      setOldPinVerified(true);
      setOldPin('');
      setTimeout(() => newPinRef.current?.focus(), 50);
    } else {
      const state = recordPinFailure();
      setLockout(state);
      setOldPinError(state.locked
        ? t('pinTab.tooManyAttempts', { seconds: state.secondsLeft })
        : t('pinTab.incorrectPin'));
      setOldPin('');
      oldPinRef.current?.clear();
    }
    setOldPinBusy(false);
  }

  function reset() {
    setPin('');
    setConfirm('');
    setError(null);
  }

  async function submit(pinVal: string, confirmVal: string) {
    setError(null);
    if (pinVal.length !== 4) {
      setError(t('pinTab.pinFourDigits'));
      return;
    }
    if (pinVal !== confirmVal) {
      setError(t('pinTab.pinsDoNotMatch'));
      return;
    }
    setBusy(true);
    try {
      const updated = await storePin(pinVal, userSettings);
      if (updated.appLockEnabled) {
        const blob = await wrapPhraseWithPin(phrase, pinVal);
        removeStoredPhrase();
        Object.assign(updated, blob);
      }
      onSettingsChange(updated);
      // Mark unlocked so the user isn't immediately re-prompted for
      // the PIN they just created.
      markPinUnlocked();
      setPinExists(true);
      setOldPinVerified(false);
      reset();
      setSavedFlash(true);
      setTimeout(() => setSavedFlash(false), 1800);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const [showRemoveConfirm, setShowRemoveConfirm] = useState(false);

  function doRemovePin() {
    // The same clear the phrase route performs, so the two cannot drift.
    // App lock is left alone: it is a synced setting and an enrolled
    // fingerprint is not, so removing a PIN here used to switch off a lock
    // another device could still open. clearPin carries the reasoning.
    onSettingsChange(clearPin(userSettings, phrase));
    setPinExists(false);
    setOldPinVerified(false);
    reset();
  }

  if (recovering) {
    return (
      <div className="space-y-3">
        <PinRecoveryForm
          phrase={phrase}
          userSettings={userSettings}
          onSettingsChange={onSettingsChange}
          onCleared={() => {
            setRecovering(false);
            setRecovered(true);
            setPinExists(false);
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
    <div className="space-y-3">
      {needsOldPin ? (
        <>
          <p className={`${SETTINGS_HELP} leading-relaxed`}>
            {t('pinTab.enterCurrent')}
          </p>
          <div className="space-y-1.5">
            <SectionEyebrow className="text-center">
              {t('pinTab.currentPin')}
            </SectionEyebrow>
            <PinInput
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
            <p className="text-sm text-red-500 dark:text-red-400 text-center">
              {oldPinError}
            </p>
          )}
          <button
            onClick={() => void verifyOldPin(oldPin)}
            disabled={oldPin.length !== 4 || oldPinBusy}
            className="w-full rounded-md bg-accent text-white hover:bg-accent-hover px-3 py-2 text-sm font-medium transition disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {oldPinBusy ? t('pinTab.checking') : t('pinTab.verify')}
          </button>
          <ForgotPinLink onClick={() => setRecovering(true)} />
        </>
      ) : (
        <>
          <div className="space-y-2">
            {reason === 'protect' && (
              <SettingsCallout>{t('pinTab.protectReason')}</SettingsCallout>
            )}
            {recovered && (
              <p className="text-sm text-accent">{t('pinRecovery.cleared')}</p>
            )}
            <p className={`${SETTINGS_HELP} leading-relaxed`}>
              {pinExists
                ? t('pinTab.replaceExisting')
                : t('pinTab.setIntro')}
            </p>
          </div>

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

          {error && (
            <p className="text-sm text-red-500 dark:text-red-400 text-center">
              {error}
            </p>
          )}
          {savedFlash && (
            <p className="text-sm text-accent text-center">{t('pinTab.pinSaved')}</p>
          )}

          <div className="flex gap-2">
            <button
              onClick={() => void submit(pin, confirm)}
              disabled={busy || pin.length !== 4 || confirm.length !== 4}
              className="flex-1 rounded-md bg-accent text-white hover:bg-accent-hover px-4 py-2 text-sm font-medium transition disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {busy ? t('common:state.saving') : pinExists ? t('pinTab.updatePin') : t('pinTab.setPin')}
            </button>
            {pinExists && (
              <button
                onClick={() => setShowRemoveConfirm(true)}
                disabled={busy}
                className="rounded-md border border-divider text-pn-muted hover:bg-surface-1 hover:text-red-500 dark:hover:text-red-400 px-4 py-2 text-sm transition"
              >
                {t('pinTab.removePin')}
              </button>
            )}
          </div>
        </>
      )}

      {/* Shared unlock-timeout selector - same rule governs the phrase
          view and any PIN-protected note once unlocked this session.
          Disabled when no PIN is set (nothing to time). */}
      <div className="pt-3 border-t border-divider">
        <label className="block">
          <SectionEyebrow className="mb-1.5">
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
                {opt.label}
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
          onConfirm={() => {
            doRemovePin();
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
  onConfirm,
  onClose,
}: {
  onConfirm: () => void;
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
    if (candidate.length !== 4 || busy || lockout.locked) return;
    setBusy(true);
    setError(null);
    const { valid } = await verifyPin(candidate);
    if (valid) {
      clearPinFailures();
      onConfirm();
    } else {
      const state = recordPinFailure();
      setLockout(state);
      setError(state.locked
        ? t('pinTab.tooManyAttempts', { seconds: state.secondsLeft })
        : t('pinTab.incorrectPinRetry'));
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
        <h2 className="text-lg font-semibold">{t('removePinDialog.title')}</h2>
        <p className="text-sm text-pn-soft leading-relaxed">
          {hasBio
            ? t('removePinDialog.introWithBio')
            : t('removePinDialog.introNoBio')}
        </p>
        <PinInput
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
          <p className="text-sm text-red-500 dark:text-red-400 text-center">
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
            disabled={pin.length !== 4 || busy || lockout.locked}
            className="flex-1 rounded-md bg-red-600 text-white hover:bg-red-700 px-3 py-2 text-sm font-medium transition disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {busy ? t('removePinDialog.verifying') : t('removePinDialog.removePin')}
          </button>
        </div>
      </div>
    </div>
  );
}
