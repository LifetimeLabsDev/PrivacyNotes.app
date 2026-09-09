import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Check, Fingerprint } from '../icons';
import { ConfirmModal } from '../ConfirmModal';
import {
  canUseBiometric,
  enrollBiometric,
  hasBiometricCredential,
  hasPinWrappedPhrase,
  removeBiometricCredential,
  removeStoredPhrase,
  wrapPhraseWithPin,
} from '../biometric';
import { hasPin, markPinUnlocked, verifyPin } from '../pin';
import { PinInput, type PinInputHandle } from '../PinInput';
import { SectionEyebrow } from '../settingsUI';
import { isTrustedDevice } from '../trustStorage';
import { isDemoMode } from '../demo';
import { persistStoredPhrase } from '../phraseAtRest';
import type { UserSettings } from '../userSettings';
import { TIMEOUT_OPTIONS } from './timeoutOptions';
import { HelpChip } from '../HelpChip';

/**
 * Biometric tab - enroll/disable WebAuthn platform authenticator
 * (Touch ID, Face ID, Windows Hello) plus the app-lock toggle and
 * shared re-lock timeout selector.
 */
export function BiometricTab({
  phrase,
  pubkey,
  userSettings,
  onSettingsChange,
  pinTimeoutMinutes,
  onPinTimeoutChange,
}: {
  phrase: string;
  pubkey: string;
  userSettings: UserSettings;
  onSettingsChange: (next: UserSettings) => void;
  pinTimeoutMinutes: number;
  onPinTimeoutChange: (minutes: number) => void;
}) {
  const { t } = useTranslation('security');
  const [deviceSupported, setDeviceSupported] = useState<boolean | null>(null);
  const [enrolled, setEnrolled] = useState(() => hasBiometricCredential());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successFlash, setSuccessFlash] = useState(false);
  // The demo never reaches the sign-in screen that owns the "Trust this
  // device" checkbox, so without this it can offer a Biometric Lock tab that
  // nothing can ever enable. What the flag guards does not apply there: the
  // phrase the demo wraps is a public constant, and every demo credential is
  // cleared on the next fresh tab session (clearFreshDemoCredentials).
  const trusted = isTrustedDevice() || isDemoMode();

  useEffect(() => {
    void canUseBiometric().then(setDeviceSupported);
  }, []);

  async function handleEnroll() {
    setBusy(true);
    setError(null);

    // The label doubles as the reason line the OS prompt renders; Android also
    // draws its own cancel button, which is why that label goes too.
    const result = await enrollBiometric(
      phrase,
      pubkey,
      t('biometricTab.enable'),
      t('common:actions.cancel'),
    );
    if (result.ok) {
      // Biometric wrap is the primary; PIN wrap (if a PIN is set) is
      // created when the user enables app lock and enters their PIN.
      removeStoredPhrase();
      setEnrolled(true);
      onSettingsChange({
        ...userSettings,
        appLockEnabled: true,
      });
      setSuccessFlash(true);
      setTimeout(() => setSuccessFlash(false), 2000);
    } else {
      setError(result.message);
    }
    setBusy(false);
  }

  const [showDisableConfirm, setShowDisableConfirm] = useState(false);

  function doDisable() {
    removeBiometricCredential();
    if (!hasPinWrappedPhrase()) {
      void persistStoredPhrase(phrase);
      onSettingsChange({
        ...userSettings,
        appLockEnabled: false,
      });
    }
    setEnrolled(false);
  }

  // The PIN-confirm step for turning app lock ON with an existing PIN
  // and no wrap. The lock screen can only open a WRAPPED phrase, and
  // the wrap needs the PIN VALUE - so a bare settings flip was a
  // silent no-op: appLockEnabled went true, no blob existed, and the
  // lock never engaged (found live 2026-08-25; the only wrap sites
  // were PIN create/change in PinTab). The toggle now collects the
  // PIN once, wraps, and only then commits the setting.
  const [pinConfirm, setPinConfirm] = useState(false);
  const [pinConfirmValue, setPinConfirmValue] = useState('');
  const [pinConfirmBusy, setPinConfirmBusy] = useState(false);
  const [pinConfirmError, setPinConfirmError] = useState<string | null>(null);
  const pinConfirmRef = useRef<PinInputHandle>(null);

  async function confirmPinForAppLock(candidate: string) {
    if (candidate.length !== 4 || pinConfirmBusy || !trusted) return;
    setPinConfirmBusy(true);
    setPinConfirmError(null);
    const { valid } = await verifyPin(candidate);
    if (!valid) {
      setPinConfirmError(t('pinTab.incorrectPin'));
      setPinConfirmValue('');
      pinConfirmRef.current?.clear();
      setPinConfirmBusy(false);
      return;
    }
    const blob = await wrapPhraseWithPin(phrase, candidate);
    removeStoredPhrase();
    // The user proved the PIN seconds ago - no immediate re-prompt.
    markPinUnlocked();
    setPinConfirm(false);
    setPinConfirmValue('');
    setPinConfirmBusy(false);
    // The synced blob fields ride along so every device gets the wrap.
    onSettingsChange({ ...userSettings, appLockEnabled: true, ...blob });
  }

  function handleAppLockToggle() {
    const next = !userSettings.appLockEnabled;
    // Inside the handler as well as in the markup above, so a third caller
    // cannot reintroduce the write by forgetting it - which is how the wrap
    // sites came to disagree with `hydrateLocalPinWrap` in the first place.
    if (next && !trusted) return;
    if (!next) {
      // Arming the lock strips the phrase at rest, so a door is the only way
      // back into this device - and every door here opens through the lock
      // screen, which stops rendering the moment the flag goes false. The
      // wrap and the fingerprint that survive the switch-off are therefore
      // not a way in; they are two things that can no longer be reached. The
      // phrase goes back first, before the flag commits, so a boot between
      // the two still has a session to restore.
      void persistStoredPhrase(phrase);
      setPinConfirm(false);
      onSettingsChange({ ...userSettings, appLockEnabled: false });
      return;
    }
    if (!enrolled && !hasPinWrappedPhrase()) {
      // Existing PIN, no wrap yet: collect the PIN first (see the
      // comment above). The setting commits inside the confirm.
      setPinConfirm(true);
      return;
    }
    onSettingsChange({ ...userSettings, appLockEnabled: true });
  }

  if (deviceSupported === null) {
    return (
      <div className="py-8 text-center text-sm text-pn-muted">
        {t('biometricTab.checkingSupport')}
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <p className="text-sm text-pn-soft leading-relaxed">
        {t('biometricTab.description')}
      </p>

      {!trusted && (
        <div className="rounded-md border border-amber-200 dark:border-amber-800/50 bg-amber-50 dark:bg-amber-900/20 p-3 text-sm text-amber-800 dark:text-amber-200">
          {t('biometricTab.trustFirst')}
        </div>
      )}

      {!deviceSupported && (
        <div className="rounded-md border border-divider bg-track p-3 text-sm text-pn-soft">
          {t('biometricTab.notAvailable')}
        </div>
      )}

      {error && (
        <p className="text-sm text-red-500 dark:text-red-400">{error}</p>
      )}
      {successFlash && (
        <p className="text-sm text-accent text-center">{t('biometricTab.enabledFlash')}</p>
      )}

      {deviceSupported && trusted && (
        enrolled ? (
          <div className="space-y-4">
            <div className="flex items-center justify-between rounded-md border border-emerald-200 dark:border-emerald-800/50 bg-emerald-50 dark:bg-emerald-900/20 p-3">
              <div className="flex items-center gap-2">
                <Check size={16} className="text-emerald-600 dark:text-emerald-400" />
                <span className="text-sm font-medium text-emerald-800 dark:text-emerald-200">{t('biometricTab.enrolledOnDevice')}</span>
              </div>
            </div>

            <button
              onClick={() => setShowDisableConfirm(true)}
              className="w-full rounded-md border border-divider text-pn-muted hover:text-red-500 dark:hover:text-red-400 hover:border-red-300 dark:hover:border-red-800 px-3 py-2 text-sm transition"
            >
              {t('biometricTab.disable')}
            </button>
          </div>
        ) : (
          <div className="space-y-2">
            <button
              onClick={() => void handleEnroll()}
              disabled={busy}
              className="w-full inline-flex items-center justify-center gap-2 rounded-md bg-accent text-white hover:bg-accent-hover px-4 py-2.5 text-sm font-medium transition disabled:opacity-50"
            >
              <Fingerprint size={16} />
              {busy ? t('biometricTab.settingUp') : t('biometricTab.enable')}
            </button>
          </div>
        )
      )}

      {/* Not offered on a device the user marked untrusted: the wrap it
          creates is a durable, offline-crackable copy of the master phrase,
          which is the opposite of what that checkbox promises. A lock that
          is already armed keeps its switch, so nobody is left without a way
          to turn one off. */}
      {(enrolled || hasPin()) && (trusted || userSettings.appLockEnabled) && (
        <div className="pt-4 border-t border-divider">
          <label className="flex items-center justify-between cursor-pointer">
            <div>
              <div className="text-sm font-medium text-pn">{t('biometricTab.lockOnOpen')}</div>
              <div className="text-xs text-pn-soft mt-0.5">
                {t('biometricTab.lockOnOpenHint')}
              </div>
            </div>
            <div className="relative">
              <input
                type="checkbox"
                checked={userSettings.appLockEnabled}
                onChange={handleAppLockToggle}
                className="sr-only peer"
              />
              <div className="w-9 h-5 bg-pn-muted/35 peer-checked:bg-accent rounded-full transition-colors" />
              <div className="absolute start-0.5 top-0.5 w-4 h-4 bg-white rounded-full shadow-sm transition-transform peer-checked:translate-x-4 peer-checked:rtl:-translate-x-4" />
            </div>
          </label>
        </div>
      )}

      {pinConfirm && (
        <div className="rounded-md border border-divider bg-surface-1 p-3 space-y-3">
          <p className="text-sm text-pn-soft leading-relaxed">
            {t('biometricTab.confirmPinForLock')}
          </p>
          <div className="flex justify-center">
            <PinInput
              ref={pinConfirmRef}
              value={pinConfirmValue}
              onChange={(v) => {
                setPinConfirmValue(v);
                setPinConfirmError(null);
              }}
              onComplete={(v) => void confirmPinForAppLock(v)}
              autoFocus
              disabled={pinConfirmBusy}
            />
          </div>
          {pinConfirmError && (
            <p className="text-sm text-red-500 dark:text-red-400 text-center">
              {pinConfirmError}
            </p>
          )}
          <button
            type="button"
            onClick={() => {
              setPinConfirm(false);
              setPinConfirmValue('');
              setPinConfirmError(null);
            }}
            className="w-full rounded-md border border-divider hover:bg-surface-2 px-3 py-2 text-sm transition"
          >
            {t('common:actions.cancel')}
          </button>
        </div>
      )}

      {(enrolled || hasPin()) && userSettings.appLockEnabled && (
        <div>
          <label className="block">
            <SectionEyebrow className="mb-2">
              {t('biometricTab.relockAfter')}
            </SectionEyebrow>
            <select
              value={String(pinTimeoutMinutes)}
              onChange={(e) => onPinTimeoutChange(Number(e.target.value))}
              className="w-full rounded-md bg-surface-1 border border-divider px-3 py-2 text-sm focus:outline-none focus:border-accent"
            >
              {TIMEOUT_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
            <p className="text-xs text-pn-soft mt-1.5 leading-relaxed">
              {t('biometricTab.relockHint')}
            </p>
          </label>
        </div>
      )}

      <p className="text-xs text-pn-soft leading-relaxed">
        {t('biometricTab.perDeviceNote')}
      </p>

      <HelpChip surface="biometric" />

      {showDisableConfirm && (
        <ConfirmModal
          title={t('biometricTab.disableConfirmTitle')}
          confirmLabel={t('biometricTab.disableConfirmLabel')}
          variant="warning"
          onConfirm={doDisable}
          onClose={() => setShowDisableConfirm(false)}
        >
          {hasPinWrappedPhrase()
            ? t('biometricTab.disableConfirmBody')
            : t('biometricTab.disableConfirmBodyAppLock')}
        </ConfirmModal>
      )}
    </div>
  );
}
