import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Check } from '../icons';
import { useEscapeToClose } from '../useEscapeToClose';
import {
  hasBiometricCredential,
  hasPinWrappedPhrase,
  removePinWrappedPhrase,
  removeStoredPhrase,
  wrapPhraseWithPin,
} from '../biometric';
import { persistStoredPhrase } from '../phraseAtRest';
import {
  clearPinFailures,
  clearPinFromSettings,
  getPinLockoutState,
  hasPin,
  markPinUnlocked,
  recordPinFailure,
  setPin as storePin,
  verifyPin,
} from '../pin';
import { PinInput, type PinInputHandle } from '../PinInput';
import { SectionEyebrow, SettingsCallout } from '../settingsUI';
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
  onCancel,
  userSettings,
  onSettingsChange,
  reason,
}: {
  phrase: string;
  timeoutMinutes: number;
  onTimeoutChange: (minutes: number) => void;
  onCancel: () => void;
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
    const hasBio = hasBiometricCredential();
    removePinWrappedPhrase();
    if (!hasBio && userSettings.appLockEnabled) {
      // Fire-and-forget: persist wraps the phrase at rest and falls
      // back to the old plaintext write on a degraded browser, so the
      // sync caller keeps the same guarantees restore had.
      void persistStoredPhrase(phrase);
    }
    const updated = clearPinFromSettings(userSettings);
    if (!hasBio) {
      updated.appLockEnabled = false;
    }
    // Clear synced PIN wrap blob
    updated.pinWrapSalt = null;
    updated.pinWrapIV = null;
    updated.pinWrapCiphertext = null;
    updated.pinWrapIterations = null;
    onSettingsChange(updated);
    setPinExists(false);
    setOldPinVerified(false);
    reset();
  }

  return (
    <div className="space-y-5">
      {needsOldPin ? (
        <>
          <p className="text-sm text-pn-soft leading-relaxed">
            {t('pinTab.enterCurrent')}
          </p>
          <div className="space-y-2">
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
        </>
      ) : (
        <>
          <div className="space-y-3">
            {reason === 'protect' && (
              <SettingsCallout>{t('pinTab.protectReason')}</SettingsCallout>
            )}
            <p className="text-sm text-pn-soft leading-relaxed">
              {pinExists
                ? t('pinTab.replaceExisting')
                : t('pinTab.setIntro')}
            </p>
          </div>

          <div className="space-y-2">
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
              disabled={busy}
            />
          </div>

          <div className="space-y-2">
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
      <div className="pt-4 border-t border-divider">
        <label className="block">
          <SectionEyebrow className="mb-2">
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
          <p className="text-xs text-pn-soft mt-1.5 leading-relaxed">
            {t('pinTab.reaskHint')}
          </p>
        </label>
      </div>

      <div className="flex gap-2">
        <button
          onClick={onCancel}
          className="flex-1 rounded-md border border-divider hover:bg-surface-1 px-3 py-2 text-sm transition"
        >
          {t('common:actions.cancel')}
        </button>
        <button
          onClick={onCancel}
          className="flex-1 inline-flex items-center justify-center gap-2 rounded-md bg-accent text-white hover:bg-accent-hover px-3 py-2 text-sm font-medium transition"
        >
          <Check size={16} aria-hidden="true" />
          {t('common:actions.done')}
        </button>
      </div>

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
