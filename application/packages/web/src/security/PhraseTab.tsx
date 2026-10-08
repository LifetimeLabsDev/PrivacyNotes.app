import { useTranslation } from 'react-i18next';
import { PhraseView } from './PhraseView';
import { PhraseOdds } from './PhraseOdds';
import { PhrasePinGate, type PinGateRecovery } from './PhrasePinGate';
import { HelpChip } from '../HelpChip';
import { RedditLogo } from '../icons';

// The thread's own title, shown untranslated: the thread is written in English.
const PHRASE_MEGATHREAD = {
  href: 'https://www.reddit.com/r/PrivacyNotes/comments/1wsy3ky/megathread_your_12word_phrase_explained_privacy/',
  title: 'Megathread: Your 12-word phrase explained, privacy, security and recovery',
};

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
      <div className="flex flex-col items-start gap-1.5">
        <a href={PHRASE_MEGATHREAD.href} target="_blank" rel="noopener noreferrer"
          className="inline-flex items-start gap-2 max-w-full text-[13px] text-accent hover:underline">
          <span className="flex h-5 shrink-0 items-center">
            <RedditLogo size={15} weight="fill" aria-hidden="true" />
          </span>
          <span>{PHRASE_MEGATHREAD.title}</span>
        </a>
        <HelpChip surface="phrase" />
      </div>
    </div>
  </PhrasePinGate>;
}
