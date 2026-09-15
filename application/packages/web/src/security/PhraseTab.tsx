import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  clearPinFailures,
  getPinLockoutState,
  markPinUnlocked,
  recordPinFailure,
  shouldPromptForPin,
  verifyPin,
} from '../pin';
import { PinInput, type PinInputHandle } from '../PinInput';
import { CustodyPanel } from './CustodyPanel';
import { PhraseView } from './PhraseView';
import { HelpChip } from '../HelpChip';

/**
 * Phrase tab - gated behind the PIN if one is set and the unlock
 * timeout says the user should be prompted again.
 *
 * `hasPin` is supplied by the parent from `userSettings.pinHash`
 * directly, NOT via the `pin.hasPin()` localStorage cache. On a fresh
 * device the cache lags settings sync, and the OAuth onboarding flow
 * may auto-open this tab before sync completes - see v0.154.3 fix.
 */
export function PhraseTab({
  phrase,
  pinTimeoutMinutes,
  hasPin,
  onCancel,
}: {
  phrase: string;
  pinTimeoutMinutes: number;
  hasPin: boolean;
  onCancel: () => void;
}) {
  // Re-evaluated whenever this tab mounts. Once the user unlocks here
  // it flips false for the rest of the session (within timeout).
  const [locked, setLocked] = useState<boolean>(() => {
    if (!hasPin) return false;
    return shouldPromptForPin(pinTimeoutMinutes);
  });

  // Re-evaluate when:
  //  - timeout pref changes, or
  //  - hasPin flips (e.g. settings land async after mount on a fresh
  //    browser - without this the tab stays unlocked, exposing the
  //    phrase until the next remount).
  useEffect(() => {
    if (!hasPin) {
      setLocked(false);
      return;
    }
    setLocked(shouldPromptForPin(pinTimeoutMinutes));
  }, [pinTimeoutMinutes, hasPin]);

  if (locked) {
    return (
      <InlinePinGate
        onSuccess={() => setLocked(false)}
        onCancel={onCancel}
      />
    );
  }

  // CustodyPanel renders itself away when there is no custody decision
  // to offer. Placed under the phrase, never above it: the release
  // challenge is answered from the word grid, so the words have to be
  // on screen first.
  //
  // PhraseView's dismiss button is suppressed here. The settings modal
  // already closes via its own X and back arrow, and a full-width
  // "Done" sitting above the custody section made the pane look like
  // it ended there.
  //
  // `gated` covers the phrase behind a reveal banner for everyone, PIN
  // or no PIN (GitHub #316). A PIN answers "is this the owner"; the gate
  // answers "is anybody else looking at this screen right now", which is
  // a different question and the one the reader is standing in front of.
  return (
    <div className="space-y-4">
      <PhraseView phrase={phrase} onCancel={onCancel} hideDismiss gated hasPin={hasPin} />
      <CustodyPanel phrase={phrase} />
      <HelpChip surface="phrase" />
    </div>
  );
}

/**
 * Chromeless PIN entry embedded in the tab body. Reuses verifyPin +
 * markPinUnlocked directly rather than wrapping the full-screen
 * PinPrompt - that would double-stack modals.
 */
function InlinePinGate({
  onSuccess,
  onCancel,
}: {
  onSuccess: () => void;
  onCancel: () => void;
}) {
  const { t } = useTranslation('security');
  const [value, setValue] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [lockout, setLockout] = useState(() => getPinLockoutState());
  const inputRef = useRef<PinInputHandle>(null);

  useEffect(() => {
    if (!lockout.locked) return;
    const id = setInterval(() => {
      const state = getPinLockoutState();
      setLockout(state);
      if (!state.locked) setErr(null);
    }, 1000);
    return () => clearInterval(id);
  }, [lockout.locked]);

  async function submit(candidate: string) {
    if (candidate.length !== 4 || busy || lockout.locked) return;
    setBusy(true);
    setErr(null);
    const { valid: ok } = await verifyPin(candidate);
    if (ok) {
      clearPinFailures();
      markPinUnlocked();
      onSuccess();
    } else {
      const state = recordPinFailure();
      setLockout(state);
      setErr(state.locked
        ? t('phraseGate.tooManyAttempts', { seconds: state.secondsLeft })
        : t('phraseGate.incorrectPinRetry'));
      setValue('');
      setBusy(false);
      inputRef.current?.clear();
    }
  }

  const disabled = busy || lockout.locked;

  return (
    <div className="space-y-4">
      <p className="text-sm text-pn-soft leading-relaxed">
        {t('phraseGate.enterToView')}
      </p>
      <PinInput
        ref={inputRef}
        value={value}
        onChange={(v) => {
          setValue(v);
          setErr(null);
        }}
        onComplete={(v) => void submit(v)}
        autoFocus
        compact
        disabled={disabled}
      />
      {err && (
        <p className="text-sm text-red-500 dark:text-red-400 text-center">
          {err}
        </p>
      )}
      {lockout.locked && (
        <p className="text-xs text-pn-soft text-center">
          {t('phraseGate.lockedFor', { seconds: lockout.secondsLeft })}
        </p>
      )}
      <div className="flex gap-2">
        <button
          onClick={onCancel}
          className="flex-1 rounded-md border border-divider hover:bg-surface-1 px-3 py-2 text-sm transition"
        >
          {t('common:actions.cancel')}
        </button>
        <button
          onClick={() => void submit(value)}
          disabled={value.length !== 4 || disabled}
          className="flex-1 rounded-md bg-accent text-white hover:bg-accent-hover px-3 py-2 text-sm font-medium transition disabled:opacity-40 disabled:cursor-not-allowed"
        >
          {busy ? t('phraseGate.checking') : t('phraseGate.unlock')}
        </button>
      </div>
    </div>
  );
}

