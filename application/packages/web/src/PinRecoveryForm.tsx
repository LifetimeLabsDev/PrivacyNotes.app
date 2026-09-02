import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { clearPin, phraseMatches } from './pinRecovery';
import type { UserSettings } from './userSettings';

/**
 * The recovery phrase, offered wherever a forgotten PIN would otherwise be
 * a dead end. Shared by the PIN tab and the protected-note gate, which
 * both run inside an unlocked app and can therefore check the phrase
 * against the one already in memory.
 *
 * Layout-neutral on purpose: no icon and no heading, so the note gate can
 * put its own centred header above and the settings pane can keep its
 * left-aligned column.
 *
 * The lock screen does NOT use this. There the phrase is the sign-in, so
 * recovery rides the phrase screen it already has.
 *
 * Spec: ops/docs/plans/pin-recovery.md
 */
export function PinRecoveryForm({
  phrase,
  userSettings,
  onSettingsChange,
  onCleared,
  onCancel,
}: {
  /** The account's phrase, held by the signed-in app. */
  phrase: string;
  userSettings: UserSettings;
  onSettingsChange: (next: UserSettings) => void;
  /** The PIN is gone. Callers move on to setting a new one. */
  onCleared: () => void;
  onCancel: () => void;
}) {
  const { t } = useTranslation('security');
  const [input, setInput] = useState('');
  const [error, setError] = useState<string | null>(null);

  function submit() {
    if (!input.trim()) return;
    if (!phraseMatches(input, phrase)) {
      // One message for every failure. Naming the word that was wrong
      // would turn this box into a checker for a phrase somebody found.
      setError(t('pinRecovery.wrongPhrase'));
      return;
    }
    onSettingsChange(clearPin(userSettings, phrase));
    onCleared();
  }

  return (
    <div className="space-y-3 text-start">
      <p className="text-xs text-pn-soft leading-relaxed">
        {t('pinRecovery.intro')}
      </p>
      <textarea
        value={input}
        onChange={(e) => {
          setInput(e.target.value);
          setError(null);
        }}
        placeholder={t('lockScreen.phrasePlaceholder')}
        rows={3}
        dir="ltr" // rtl-ok: BIP-39 phrase words, always LTR
        autoFocus
        className="w-full rounded-md bg-surface-1 border border-divider text-pn focus:border-accent p-2.5 text-sm font-mono focus:outline-none placeholder:text-pn-muted"
      />
      <p className="text-xs text-pn-soft leading-relaxed">
        {t('pinRecovery.consequence')}
      </p>
      {error && (
        <p className="text-sm text-red-500 dark:text-red-400">{error}</p>
      )}
      <div className="flex gap-2">
        <button
          type="button"
          onClick={onCancel}
          className="flex-1 rounded-md border border-divider hover:bg-surface-1 px-3 py-2 text-sm transition"
        >
          {t('common:actions.cancel')}
        </button>
        <button
          type="button"
          onClick={submit}
          disabled={!input.trim()}
          className="flex-1 rounded-md bg-accent text-white hover:bg-accent-hover px-3 py-2 text-sm font-medium transition disabled:opacity-40 disabled:cursor-not-allowed"
        >
          {t('pinRecovery.clearPin')}
        </button>
      </div>
    </div>
  );
}

/** The link into the form. Same wording everywhere a PIN is demanded. */
export function ForgotPinLink({ onClick }: { onClick: () => void }) {
  const { t } = useTranslation('security');
  return (
    <button
      type="button"
      onClick={onClick}
      className="w-full text-sm text-accent hover:underline py-1 transition"
    >
      {t('pinRecovery.forgotPin')}
    </button>
  );
}
