import { useEffect, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Fingerprint, Key, Lock, X } from './icons';
import { AccentBar, HeadlineRule } from './settingsUI';
import { BiometricTab } from './security/BiometricTab';
import { PhraseTab } from './security/PhraseTab';
import { PinTab } from './security/PinTab';
import type { UserSettings } from './userSettings';
import { useEscapeToClose } from './useEscapeToClose';

type Tab = 'pin' | 'phrase' | 'biometric';

type Props = {
  phrase: string;
  onClose: () => void;
  /** Which tab to open on. Defaults to 'pin'. */
  defaultTab?: Tab;
  /** Why the PIN tab was opened, when something else opened it. */
  reason?: 'protect';
  /** Current PIN-unlock timeout from UserSettings. */
  pinTimeoutMinutes: number;
  /** Persist a new timeout. Parent owns the settings blob + sync. */
  onPinTimeoutChange: (minutes: number) => void;
  /** Current settings - needed so PIN set/clear can return updated blob. */
  userSettings: UserSettings;
  /** Persist updated settings (PIN changes). Parent owns save + sync. */
  onSettingsChange: (next: UserSettings) => void;
  /** The user's hex pubkey - needed for WebAuthn credential creation. */
  pubkey: string;
  /** Render inline as a settings pane (no overlay, no own header/escape). */
  embedded?: boolean;
};

/**
 * Security modal - three-tab dialog for biometric enrollment, PIN
 * management, and viewing the recovery phrase. The tab bodies live in
 * `./security/`; this file owns the chrome (overlay, tab strip, close
 * handling) and dispatches to the active tab.
 */
export function SecurityModal({
  phrase,
  onClose,
  defaultTab = 'pin',
  reason,
  pinTimeoutMinutes,
  onPinTimeoutChange,
  userSettings,
  onSettingsChange,
  pubkey,
  embedded = false,
}: Props) {
  const { t } = useTranslation('security');
  useEscapeToClose(onClose, !embedded);
  const [tab, setTab] = useState<Tab>(defaultTab);

  // Guard against ghost clicks from the element that opened us (e.g. the
  // mobile drawer "Security" button fires a delayed synthetic click at the
  // same coordinates after the drawer unmounts, landing on our backdrop).
  const [mountReady, setMountReady] = useState(false);
  useEffect(() => {
    const id = requestAnimationFrame(() => setMountReady(true));
    return () => cancelAnimationFrame(id);
  }, []);

  return (
    <div
      className={embedded ? 'contents' : 'fixed inset-0 bg-black/50 dark:bg-black/70 flex items-center justify-center p-4 sm:p-6 z-50'}
      onClick={embedded ? undefined : (e) => { if (mountReady && e.target === e.currentTarget) onClose(); }}
    >
      <div
        className={
          embedded
            ? 'flex-1 min-h-0 overflow-y-auto px-6 pb-6 pt-3 space-y-5 text-pn'
            : 'bg-surface-2 border border-divider text-pn rounded-lg max-w-md w-full p-6 space-y-5 max-h-[90vh] overflow-y-auto'
        }
        onClick={(e) => e.stopPropagation()}
      >
        {!embedded && (
          <div className="flex items-center gap-2.5">
            <AccentBar />
            <h2 className="text-lg font-semibold">{t('modal.title')}</h2>
            <HeadlineRule />
            <button
              onClick={onClose}
              aria-label={t('common:actions.close')}
              className="text-pn-muted hover:text-pn transition p-1 -m-1"
            >
              <X size={18} />
            </button>
          </div>
        )}

        {/* Tab strip - underlined, full-width, minimal chrome. */}
        <div className="flex border-b border-divider -mx-6 px-6">
          <TabButton active={tab === 'pin'} onClick={() => setTab('pin')}>
            <Lock className="text-accent" aria-hidden="true" />
            {t('modal.tabPin')}
          </TabButton>
          <TabButton active={tab === 'biometric'} onClick={() => setTab('biometric')}>
            <Fingerprint className="text-accent" aria-hidden="true" />
            <span className="sm:hidden">{t('modal.tabBiometricShort')}</span>
            <span className="hidden sm:inline">{t('modal.tabBiometric')}</span>
          </TabButton>
          <TabButton active={tab === 'phrase'} onClick={() => setTab('phrase')}>
            <Key className="text-accent" aria-hidden="true" />
            <span className="sm:hidden">{t('modal.tabPhraseShort')}</span>
            <span className="hidden sm:inline">{t('modal.tabPhrase')}</span>
          </TabButton>
        </div>

        {tab === 'pin' && (
          <PinTab
            phrase={phrase}
            timeoutMinutes={pinTimeoutMinutes}
            onTimeoutChange={onPinTimeoutChange}
            userSettings={userSettings}
            onSettingsChange={onSettingsChange}
            reason={reason}
          />
        )}

        {tab === 'biometric' && (
          <BiometricTab
            phrase={phrase}
            pubkey={pubkey}
            userSettings={userSettings}
            onSettingsChange={onSettingsChange}
            pinTimeoutMinutes={pinTimeoutMinutes}
            onPinTimeoutChange={onPinTimeoutChange}
          />
        )}

        {tab === 'phrase' && (
          <PhraseTab
            phrase={phrase}
            pinTimeoutMinutes={pinTimeoutMinutes}
            // Derived from synced settings, NOT pin.hasPin() - on a
            // fresh device the localStorage cache lags settings sync.
            hasPin={Boolean(userSettings.pinHash && userSettings.pinSalt)}
            onCancel={onClose}
          />
        )}
      </div>
    </div>
  );
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={`inline-flex items-center gap-1.5 px-4 py-2 -mb-px text-sm font-medium border-b-2 transition ${
        active
          ? 'border-accent text-pn'
          : 'border-transparent text-pn-soft hover:text-pn dark:hover:text-white'
      }`}
    >
      {children}
    </button>
  );
}
