import { useTranslation } from 'react-i18next';
import { PhraseView } from './PhraseView';
import { PhraseOdds } from './PhraseOdds';
import { PhrasePinGate, type PinGateRecovery } from './PhrasePinGate';
import { HelpChip } from '../HelpChip';

/** Phrase reveal and backup stay separate from account custody changes. */
export function PhraseTab({
  phrase, pubkey, pinTimeoutMinutes, hasPin, pinCredential, onCancel, onOpenCustody, recovery,
}: {
  phrase: string;
  pubkey: string;
  pinTimeoutMinutes: number;
  hasPin: boolean;
  pinCredential?: string;
  onCancel: () => void;
  onOpenCustody?: () => void;
  recovery?: PinGateRecovery;
}) {
  const { t } = useTranslation('security');
  return <PhrasePinGate pubkey={pubkey} pinTimeoutMinutes={pinTimeoutMinutes} hasPin={hasPin}
    pinCredential={pinCredential} onCancel={onCancel} recovery={recovery}>
    <div className="space-y-4">
      <PhraseView phrase={phrase} onCancel={onCancel} hideDismiss gated hasPin={hasPin} />
      {onOpenCustody && <button type="button" className="text-sm text-accent hover:underline" onClick={onOpenCustody}>
        {t('connectedAccounts.openCustody')}
      </button>}
      <PhraseOdds />
      <HelpChip surface="phrase" />
    </div>
  </PhrasePinGate>;
}
