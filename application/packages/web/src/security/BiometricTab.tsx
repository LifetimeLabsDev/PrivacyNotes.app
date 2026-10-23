import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Check, Fingerprint, LockKey, ShieldSlash } from '../icons';
import { ConfirmModal } from '../ConfirmModal';
import { Button } from '../ui';
import {
  answerBindingOffer,
  buildPinWrap,
  canSetUpBiometricAgain,
  canUseBiometric,
  enrollBiometric,
  hasBiometricCredential,
  hasPinWrappedPhrase,
  isBiometricKeyBound,
  onWrappedBlobChange,
  removeBiometricCredential,
  removeStoredPhrase,
  setUpBiometricAgain,
  noPrfHere,
  shouldOfferBinding,
  storeBuiltPinWrap,
  unlockWithBiometricDetailed,
} from '../biometric';
import {
  clearPinFailures,
  getPinLockoutState,
  hasPin,
  markPinUnlocked,
  pinCredentialStamp,
  pinIsPasscode,
  recordPinFailure,
  verifyPin,
} from '../pin';
import { signInStamp } from '../liveSignIn';
import type { PinInputHandle } from '../PinInput';
import { SecretInput } from '../PasscodeInput';
import { secretReady } from '../secretKind';
import { ROW_TITLE, SectionEyebrow, SETTINGS_BTN_PRIMARY, SETTINGS_HELP, SETTINGS_SELECT, SettingsCallout } from '../settingsUI';
import { Switch } from '../Switch';
import { isTrustedDevice } from '../trustStorage';
import { isDemoMode } from '../demo';
import { persistStoredPhrase } from '../phraseAtRest';
import type { UserSettings } from '../userSettings';
import { detectPlatform } from '../devices';
import { captureBlockSupported, setCaptureBlock, shouldArmPrivacyScreen, useCaptureBlock } from '../privacyScreen';
import { TIMEOUT_OPTIONS } from './timeoutOptions';
import { HelpChip } from '../HelpChip';

/**
 * Biometric tab - enroll/disable WebAuthn platform authenticator
 * (Touch ID, Face ID, Windows Hello) plus the app-lock toggle and the
 * app lock's own re-lock window.
 */
/** True only where a backgrounded app leaves a picture behind. */
const COVERS_ON_SWITCH = shouldArmPrivacyScreen(true, detectPlatform());
/** True only where the operating system lets an app stay out of a capture. */
const CAPTURE_BLOCK_SUPPORTED = captureBlockSupported();

export function BiometricTab({
  phrase,
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
  const captureBlocked = useCaptureBlock();
  const [deviceSupported, setDeviceSupported] = useState<boolean | null>(null);
  const [enrolled, setEnrolled] = useState(() => hasBiometricCredential());
  // Bound: the passkey's PRF (in a browser) or the device's secure hardware
  // (in the apps) gives the key, and nothing beside the wrap opens it. An
  // unbound browser enrollment is offered a set-up-again; an unbound app
  // enrollment converts on its next unlock.
  // Spec: ops/docs/plans/app-lock-passcode.md (section 4.6),
  // ops/docs/plans/biometric-key-binding.md (section 8.2)
  const [bound, setBound] = useState(() => isBiometricKeyBound());
  const [canAgain, setCanAgain] = useState(() => canSetUpBiometricAgain());
  const [againBusy, setAgainBusy] = useState(false);
  // Shown for good once this browser's passkey gave no PRF, in place of a
  // Set up again that could only fail the same way.
  const [cannotBind, setCannotBind] = useState(() => noPrfHere());
  // An unbound enrollment in a browser whose passkeys have PRF is asked once,
  // with the reason, to set up again; the plain button stays after an answer.
  const [offerBind, setOfferBind] = useState(false);
  useEffect(() => {
    if (!canAgain) {
      setOfferBind(false);
      return;
    }
    let live = true;
    void shouldOfferBinding().then((offer) => { if (live) setOfferBind(offer); });
    return () => { live = false; };
  }, [canAgain]);
  function answerOffer() {
    answerBindingOffer();
    setOfferBind(false);
  }
  function readBinding() {
    setBound(isBiometricKeyBound());
    setCanAgain(canSetUpBiometricAgain());
    setCannotBind(noPrfHere());
  }
  // Another tab can enroll, set up again or remove; this one follows.
  useEffect(() => onWrappedBlobChange(() => {
    setEnrolled(hasBiometricCredential());
    readBinding();
  }), []);
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
      t('biometricTab.enable'),
      t('common:actions.cancel'),
    );
    if (result.ok) {
      // Biometric wrap is the primary; PIN wrap (if a PIN is set) is
      // created when the user enables app lock and enters their PIN.
      removeStoredPhrase();
      setEnrolled(true);
      readBinding();
      onSettingsChange({ ...userSettings, appLockEnabled: true }, userSettings);
      setSuccessFlash(true);
      setTimeout(() => setSuccessFlash(false), 2000);
    } else if (result.reason === 'changed') {
      // Another tab enrolled meanwhile; this one follows it and says nothing.
      setEnrolled(hasBiometricCredential());
      readBinding();
    } else {
      setError(result.message);
    }
    setBusy(false);
  }

  const [showDisableConfirm, setShowDisableConfirm] = useState(false);

  async function handleSetUpAgain() {
    setAgainBusy(true);
    setError(null);
    const result = await setUpBiometricAgain(phrase);
    // A success needs no flash: the bound status line replaces the button. A
    // cancel, or a change another tab made meanwhile, says nothing. A passkey
    // without PRF answers the ask for good: asking again cannot change it.
    if (!result.ok && result.reason === 'no_prf') {
      setCannotBind(true);
      answerOffer();
    }
    if (!result.ok && result.reason === 'error') setError(result.message);
    readBinding();
    setAgainBusy(false);
  }

  async function doDisable() {
    // With no PIN wrap behind it the fingerprint is this device's last door,
    // and the app lock goes with it. The phrase goes back at rest first, and
    // the fingerprint and the flag come off only once it reads back: a write
    // the store refused leaves both where they were.
    const lastDoor = !hasPinWrappedPhrase();
    setError(null);
    // The fingerprint that turned the lock on turns it off. An open app alone
    // is not enough: removing the last door puts the phrase back at rest, and
    // every later start opens without a prompt. A hardware key the OS
    // destroyed has nothing left to ask, so it goes without one.
    // Spec: ops/docs/biometric-unlock.md (Disabling biometric)
    const proof = await unlockWithBiometricDetailed(t('biometricTab.disable'), t('common:actions.cancel'));
    if (!proof.phrase && proof.failure !== 'gone') {
      setError(t('lockScreen.biometricFailed'));
      return;
    }
    if (lastDoor && !(await persistStoredPhrase(phrase))) {
      setError(t('appLock.phraseNotSaved'));
      return;
    }
    removeBiometricCredential();
    if (lastDoor) onSettingsChange({ ...userSettings, appLockEnabled: false }, userSettings);
    setEnrolled(false);
    setCannotBind(false);
    readBinding();
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
  // Read on every render, from the cached hash `verifyPin` checks, so the
  // field follows a secret changed on another device.
  const pinConfirmKind = pinIsPasscode() ? 'passcode' : 'pin';

  async function confirmPinForAppLock(candidate: string) {
    if (!secretReady(pinConfirmKind, candidate) || pinConfirmBusy || !trusted) return;
    // The lockout counter is shared by every PIN surface, so this one reads
    // it at submit time and records its failures like the others do.
    const lockout = getPinLockoutState();
    if (lockout.locked) {
      setPinConfirmError(t('pinTab.tooManyAttempts', { seconds: lockout.secondsLeft }));
      setPinConfirmValue('');
      pinConfirmRef.current?.clear();
      return;
    }
    setPinConfirmBusy(true);
    setPinConfirmError(null);
    const startedAt = signInStamp();
    const stamp = pinCredentialStamp();
    const { valid } = await verifyPin(candidate);
    // A secret changed on another device during the check or the wrap below
    // answers for nothing: no wrap under the retired secret, no strip, no flag.
    if (pinCredentialStamp() !== stamp) {
      setPinConfirmValue('');
      setPinConfirmBusy(false);
      pinConfirmRef.current?.clear();
      return;
    }
    if (!valid) {
      const state = recordPinFailure();
      setPinConfirmError(state.locked
        ? t('pinTab.tooManyAttempts', { seconds: state.secondsLeft })
        : pinConfirmKind === 'passcode' ? t('pinTab.incorrectPasscode') : t('pinTab.incorrectPin'));
      setPinConfirmValue('');
      pinConfirmRef.current?.clear();
      setPinConfirmBusy(false);
      return;
    }
    clearPinFailures();
    // Built in memory and stored only once the secret is known to be still the
    // account's, with no await in between: a wrap under a secret replaced
    // meanwhile would overwrite the newer wrap another tab already stored.
    const blob = await buildPinWrap(phrase, candidate);
    if (pinCredentialStamp() !== stamp) {
      setPinConfirmValue('');
      setPinConfirmBusy(false);
      pinConfirmRef.current?.clear();
      return;
    }
    storeBuiltPinWrap(blob, startedAt);
    removeStoredPhrase();
    // The user proved the PIN seconds ago - no immediate re-prompt.
    markPinUnlocked();
    setPinConfirm(false);
    setPinConfirmValue('');
    setPinConfirmBusy(false);
    // The synced blob fields ride along so every device gets the wrap.
    onSettingsChange({ ...userSettings, appLockEnabled: true, ...blob }, userSettings);
  }

  async function handleAppLockToggle() {
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
      // back into this device, and a door opens only through the lock
      // screen. The switch-off puts the phrase back; with it at rest and the
      // flag off, App.tsx starts straight into the session and the wrap and
      // the fingerprint that survive stay unused. The flag commits only once
      // the phrase reads back: a start in between still meets the lock
      // screen, and a write the store refused keeps the lock on and says so.
      setPinConfirm(false);
      setError(null);
      if (!(await persistStoredPhrase(phrase))) {
        setError(t('appLock.phraseNotSaved'));
        return;
      }
      onSettingsChange({ ...userSettings, appLockEnabled: false }, userSettings);
      return;
    }
    if (!enrolled && !hasPinWrappedPhrase()) {
      // Existing PIN, no wrap yet: collect the PIN first (see the
      // comment above). The setting commits inside the confirm.
      setPinConfirm(true);
      return;
    }
    // A wrap or a fingerprint is already here, so the lock has a door. The
    // switch-off above put the phrase back at rest; arming takes it off again,
    // or the lock screen would guard a device whose phrase is still on disk.
    removeStoredPhrase();
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
      <p className={SETTINGS_HELP}>
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
        <p className="text-sm text-danger">{error}</p>
      )}
      {successFlash && (
        <p className="text-sm text-accent text-center">{t('biometricTab.enabledFlash')}</p>
      )}

      {deviceSupported && trusted && (
        enrolled ? (
          <div className="space-y-4">
            <div className="flex items-center justify-between rounded-md border border-emerald-200 dark:border-emerald-800/50 bg-emerald-50 dark:bg-emerald-900/20 p-3">
              <div className="flex items-center gap-2">
                <Check size={16} className="text-success" />
                <span className="text-sm font-medium text-emerald-800 dark:text-emerald-200">{t('biometricTab.enrolledOnDevice')}</span>
              </div>
            </div>

            {bound && (
              <p className={`${SETTINGS_HELP} leading-relaxed`}>
                {t(detectPlatform() === 'web' ? 'biometricTab.boundStatus' : 'biometricTab.boundStatusNative')}
              </p>
            )}
            {canAgain && (
              <div data-setting="security.biometricSetUpAgain">
                {offerBind ? (
                  <SettingsCallout>
                    <p>{t('biometricTab.bindOffer')}</p>
                    <div className="mt-2 flex flex-wrap gap-2">
                      <button
                        onClick={() => void handleSetUpAgain()}
                        disabled={againBusy}
                        className={SETTINGS_BTN_PRIMARY}
                      >
                        <Fingerprint size={14} />
                        {againBusy ? t('biometricTab.settingUp') : t('biometricTab.setUpAgain')}
                      </button>
                      <button
                        onClick={answerOffer}
                        disabled={againBusy}
                        className="rounded-md border border-divider text-pn-soft hover:bg-surface-1 hover:text-pn px-3 py-1.5 text-xs transition disabled:opacity-50"
                      >
                        {t('biometricTab.bindOfferLater')}
                      </button>
                    </div>
                  </SettingsCallout>
                ) : (
                  <button
                    onClick={() => void handleSetUpAgain()}
                    disabled={againBusy}
                    className="w-full inline-flex items-center justify-center gap-2 rounded-md border border-divider text-pn hover:bg-surface-1 px-3 py-2 text-sm transition disabled:opacity-50"
                  >
                    <Fingerprint size={16} />
                    {againBusy ? t('biometricTab.settingUp') : t('biometricTab.setUpAgain')}
                  </button>
                )}
              </div>
            )}
            {cannotBind && (
              <SettingsCallout>{t('biometricTab.cannotBind')}</SettingsCallout>
            )}

            {/* The quiet look: it only opens the confirm, which carries the danger. */}
            <Button icon={<ShieldSlash size={15} aria-hidden="true" className="shrink-0" />} className="w-full justify-center" onClick={() => setShowDisableConfirm(true)}>
              {t('biometricTab.disable')}
            </Button>
          </div>
        ) : (
          <div className="space-y-2">
            <button
              data-setting="security.enableBiometric"
              onClick={() => void handleEnroll()}
              disabled={busy}
              className={`w-full ${SETTINGS_BTN_PRIMARY}`}
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
          {/* The switch shows what this device does, not what the synced
              flag says. The flag can arrive from another device and sit
              true here with nothing to open the lock with, where the lock
              never engages - a switch reading "on" over a line explaining
              that it cannot work is the confusing half of that state. */}
          <Switch
            setting="security.appLock"
            icon={<LockKey size={14} className="text-accent" />}
            label={t('biometricTab.lockOnOpen')}
            labelClassName={`${ROW_TITLE} ${lockReady ? 'text-pn' : 'text-pn-muted'}`}
            description={
              <>
                {t('biometricTab.lockOnOpenHint')}
                {/* Phone only. The desktop apps and the browser show no stored
                    picture of a backgrounded app, so there is nothing to cover
                    and the sentence would be untrue on three platforms.
                    Spec: ops/docs/archive/app-switcher-privacy-screen.md */}
                {COVERS_ON_SWITCH && (
                  <span className="block mt-0.5">{t('biometricTab.lockHidesOnSwitch')}</span>
                )}
              </>
            }
            checked={lockReady && userSettings.appLockEnabled}
            onChange={() => void handleAppLockToggle()}
            disabled={!lockReady}
          />
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
            {pinConfirmKind === 'passcode' ? t('biometricTab.confirmPasscodeForLock') : t('biometricTab.confirmPinForLock')}
          </p>
          {/* Same shape as the PIN tab's current-PIN step: eyebrow, compact
              boxes, then the buttons. The keys live under pinTab because that
              tab owns this wording; the control is the same control. */}
          <div className="space-y-1.5">
            <SectionEyebrow className="text-center">
              {pinConfirmKind === 'passcode' ? t('pinTab.currentPasscode') : t('pinTab.currentPin')}
            </SectionEyebrow>
            <SecretInput
              kind={pinConfirmKind}
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
            <p className="text-sm text-danger text-center">
              {pinConfirmError}
            </p>
          )}
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => void confirmPinForAppLock(pinConfirmValue)}
              disabled={!secretReady(pinConfirmKind, pinConfirmValue) || pinConfirmBusy}
              className={`flex-1 ${SETTINGS_BTN_PRIMARY}`}
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
        <div data-setting="security.relockAfter">
          <label className="block">
            <SectionEyebrow className="mb-2">
              {t('biometricTab.relockAfter')}
            </SectionEyebrow>
            <select
              value={String(timeoutMinutes)}
              onChange={(e) => onTimeoutChange(Number(e.target.value))}
              className={`w-full ${SETTINGS_SELECT}`}
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

      {/* Independent of the app lock and of trust: it stores no secret, and it
          is offered only where the platform can honour it. One text for every
          platform, so it promises no more than the weakest of them, iOS, whose
          screenshot block rests on an undocumented layer an update can end.
          Spec: ops/docs/archive/app-switcher-privacy-screen.md (section 14) */}
      {CAPTURE_BLOCK_SUPPORTED && (
        <div className="pt-4 border-t border-divider">
          <Switch
            setting="security.blockCapture"
            label={t('biometricTab.blockCapture')}
            description={t('biometricTab.blockCaptureHint')}
            checked={captureBlocked}
            onChange={setCaptureBlock}
          />
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
          onConfirm={() => void doDisable()}
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
