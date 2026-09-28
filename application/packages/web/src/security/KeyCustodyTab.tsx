import { useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { CustodyPanel } from './CustodyPanel';
import { PhrasePinGate } from './PhrasePinGate';
import type { UserSettings } from '../userSettings';

/** No phrase is rendered here. Backups stay on the PIN-gated phrase page,
 * so the custody saved-copy challenge cannot be answered from this screen. */
export function KeyCustodyTab({ phrase, pubkey, hasPin, pinCredential, pinTimeoutMinutes,
  onCancel, onOpenPhrase, onOpenConnectedAccounts, userSettings, onSettingsChange }: {
  phrase: string;
  pubkey: string;
  hasPin: boolean;
  pinCredential: string;
  pinTimeoutMinutes: number;
  onCancel: () => void;
  onOpenPhrase: () => void;
  onOpenConnectedAccounts: () => void;
  userSettings?: UserSettings;
  onSettingsChange?: (next: UserSettings, base: UserSettings) => void;
}) {
  const { t } = useTranslation('security');
  const onReleaseCheckChange = useCallback(() => {}, []);
  return <PhrasePinGate pubkey={pubkey} hasPin={hasPin} pinCredential={pinCredential}
    pinTimeoutMinutes={pinTimeoutMinutes} onCancel={onCancel} prompt="phraseGate.enterToChangeCustody"
    recovery={userSettings && onSettingsChange ? { phrase, userSettings, onSettingsChange } : undefined}>
    <div className="space-y-4">
      <CustodyPanel phrase={phrase} onReleaseCheckChange={onReleaseCheckChange} onOpenConnectedAccounts={onOpenConnectedAccounts} />
      <button type="button" className="text-sm text-accent hover:underline" onClick={onOpenPhrase}>{t('custody.openPhrase')}</button>
    </div>
  </PhrasePinGate>;
}
