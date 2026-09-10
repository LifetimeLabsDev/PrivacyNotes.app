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
import { SectionEyebrow, SETTINGS_HELP, SettingsCallout } from '../settingsUI';
import { isTrustedDevice } from '../trustStorage';
import { isDemoMode } from '../demo';
import { persistStoredPhrase } from '../phraseAtRest';
import type { UserSettings } from '../userSettings';
import { TIMEOUT_OPTIONS } from './timeoutOptions';
import { HelpChip } from '../HelpChip';

/**
 * Biometric tab - enroll/disable WebAuthn platform authenticator
 * (Touch ID, Face ID, Windows Hello) plus the app-lock toggle and the
 * app lock's own re-lock window.
 */
export function BiometricTab({
  phrase,
  pubkey,
  userSettings,
  onSettingsChange,
  timeoutMinutes,
  onTimeoutChange,
  onSetUpPin,
}: {
  phrase: string;
  pubkey: string;
  userSettings: UserSettings;
  /** `base` is the copy this surface was rendered with; the parent applies
   *  only the credential keys that differ between it and `next`. */
  onSettingsChange: (next: UserSettings, base: UserSettings) => void;
  /** The app lock's own re-lock window. The PIN tab owns a separate one for
   *  the phrase view and PIN-protected notes. */
  timeoutMinutes: number;
  onTimeoutChange: (minutes: number) => void;
  /** Send the user to the PIN tab to create the credential the app lock
   *  needs. The parent brings them back here once it exists. */
  onSetUpPin: () => void;
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
  // Whether the app lock can do anything on THIS device: a wrap it could
  // open, or a credential it could build one from. Every predicate reads the
  // device rather than the account, because `verifyPin` reads the same local
  // cache `hasPin` checks and the lock screen can only open a wrap that is
  // here. A synced `pinHash` is not the question: a PIN this device has not
  // cached yet unwraps nothing.
  const lockReady = enrolled || hasPin() || hasPinWrappedPhrase();

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
      onSettingsChange({ ...userSettings, appLockEnabled: true }, userSettings);
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
      onSettingsChange({ ...userSettings, appLockEnabled: false }, userSettings);
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
    onSettingsChange({ ...userSettings, appLockEnabled: true, ...blob }, userSettings);
  }

  function handleAppLockToggle() {
    const next = !userSettings.appLockEnabled;
    // Inside the handler as well as in the markup above, so a third caller
    // cannot reintroduce the write by forgetting it - which is how the wrap
    // sites came to disagree with `hydrateLocalPinWrap` in the first place.
    if (next && !trusted) return;
    // Arming a lock with no door behind it strips the phrase and leaves the
    // twelve words as the only way back in. The disabled control above says
    // so; this says it where the write happens.
    if (next && !lockReady) return;
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
      onSettingsChange({ ...userSettings, appLockEnabled: false }, userSettings);
      return;
    }
    if (!enrolled && !hasPinWrappedPhrase()) {
      // Existing PIN, no wrap yet: collect the PIN first (see the
      // comment above). The setting commits inside the confirm.
      setPinConfirm(true);
      return;
    }
    onSettingsChange({ ...userSettings, appLockEnabled: true }, userSettings);
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
      {(trusted || userSettings.appLockEnabled) && (
        <div className="pt-4 border-t border-divider">
          <label
            className={`flex items-center justify-between ${lockReady ? 'cursor-pointer' : 'cursor-default'}`}
          >
            <div>
              <div className={`text-sm font-medium ${lockReady ? 'text-pn' : 'text-pn-muted'}`}>
                {t('biometricTab.lockOnOpen')}
              </div>
              <div className="text-xs text-pn-soft mt-0.5">
                {t('biometricTab.lockOnOpenHint')}
              </div>
            </div>
            <div className="relative">
              {/* The switch shows what this device does, not what the synced
                  flag says. The flag can arrive from another device and sit
                  true here with nothing to open the lock with, where the lock
                  never engages - a switch reading "on" over a line explaining
                  that it cannot work is the confusing half of that state. */}
              <input
                type="checkbox"
                checked={lockReady && userSettings.appLockEnabled}
                onChange={handleAppLockToggle}
                disabled={!lockReady}
                className="sr-only peer"
              />
              <div
                className={`w-9 h-5 rounded-full transition-colors ${lockReady ? 'bg-pn-muted/35 peer-checked:bg-accent' : 'bg-pn-muted/20'}`}
              />
              <div
                className={`absolute start-0.5 top-0.5 w-4 h-4 rounded-full shadow-sm transition-transform peer-checked:translate-x-4 peer-checked:rtl:-translate-x-4 ${lockReady ? 'bg-white' : 'bg-white/50'}`}
              />
            </div>
          </label>
          {/* The switch used to be absent instead of dim, which left the tab
              silent about the app lock on a device with neither credential -
              nothing on screen said the feature existed or what it wanted. */}
          {!lockReady && (
            <SettingsCallout className="mt-2.5">
              <span>{t('biometricTab.lockNeedsCredential')}</span>{' '}
              <button
                type="button"
                onClick={onSetUpPin}
                className="text-accent underline underline-offset-2 hover:no-underline"
              >
                {t('biometricTab.setUpPin')}
              </button>
            </SettingsCallout>
          )}
        </div>
      )}

      {pinConfirm && (
        <div className="rounded-md border border-divider bg-surface-1 p-3 space-y-3">
          <p className={`${SETTINGS_HELP} leading-relaxed`}>
            {t('biometricTab.confirmPinForLock')}
          </p>
          {/* Same shape as the PIN tab's current-PIN step: eyebrow, compact
              boxes, then the buttons. The keys live under pinTab because that
              tab owns this wording; the control is the same control. */}
          <div className="space-y-1.5">
            <SectionEyebrow className="text-center">
              {t('pinTab.currentPin')}
            </SectionEyebrow>
            <PinInput
              ref={pinConfirmRef}
              value={pinConfirmValue}
              onChange={(v) => {
                setPinConfirmValue(v);
                setPinConfirmError(null);
              }}
              onComplete={(v) => void confirmPinForAppLock(v)}
              autoFocus
              compact
              disabled={pinConfirmBusy}
            />
          </div>
          {pinConfirmError && (
            <p className="text-sm text-red-500 dark:text-red-400 text-center">
              {pinConfirmError}
            </p>
          )}
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => void confirmPinForAppLock(pinConfirmValue)}
              disabled={pinConfirmValue.length !== 4 || pinConfirmBusy}
              className="flex-1 rounded-md bg-accent text-white hover:bg-accent-hover px-3 py-2 text-sm font-medium transition disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {pinConfirmBusy ? t('pinTab.checking') : t('pinTab.verify')}
            </button>
            <button
              type="button"
              onClick={() => {
                setPinConfirm(false);
                setPinConfirmValue('');
                setPinConfirmError(null);
              }}
              className="flex-1 rounded-md border border-divider hover:bg-surface-2 px-3 py-2 text-sm transition"
            >
              {t('common:actions.cancel')}
            </button>
          </div>
        </div>
      )}

      {(enrolled || hasPin()) && userSettings.appLockEnabled && (
        <div>
          <label className="block">
            <SectionEyebrow className="mb-2">
              {t('biometricTab.relockAfter')}
            </SectionEyebrow>
            <select
              value={String(timeoutMinutes)}
              onChange={(e) => onTimeoutChange(Number(e.target.value))}
              className="w-full rounded-md bg-surface-1 border border-divider px-3 py-2 text-sm focus:outline-none focus:border-accent"
            >
              {TIMEOUT_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {t(opt.labelKey)}
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
