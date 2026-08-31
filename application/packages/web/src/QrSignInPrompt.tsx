import { useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useEscapeToClose } from './useEscapeToClose';
import { TurnstileWidget } from './TurnstileWidget';

/**
 * Confirmation modal shown when the app boots with a `#phrase=…` fragment
 * in the URL (i.e., the user just scanned a sign-in QR with their native
 * camera app and tapped the resulting link).
 *
 * We NEVER auto-sign-in from a fragment. A malicious QR in the wild
 * could otherwise silently swap a user's session with an attacker's
 * phrase and trick them into typing private notes into an account the
 * attacker controls. The explicit confirm step makes the user
 * acknowledge the intent before any local state changes.
 *
 * The phrase is shown truncated by default with a reveal toggle - the
 * common case is "yes that's my phrase" and we don't want to leave the
 * master secret visible on screen any longer than necessary for a
 * shoulder-surfing observer.
 */
export function QrSignInPrompt({
  phrase,
  onConfirm,
  onCancel,
  busy,
  error,
  captchaRequired,
  trustDevice,
  onTrustDeviceChange,
}: {
  phrase: string;
  /** Receives the one-shot Turnstile token (undefined until a challenge
   *  has run, and in keyless builds) for the captchaToken pass-through
   *  to the link-pubkey gate. */
  onConfirm: (captchaToken?: string) => void;
  onCancel: () => void;
  busy: boolean;
  error: string | null;
  /** True once the server has refused a tokenless confirm for want of a
   *  challenge token - the only thing that puts a widget on screen. */
  captchaRequired: boolean;
  trustDevice: boolean;
  onTrustDeviceChange: (v: boolean) => void;
}) {
  const { t } = useTranslation('auth');
  useEscapeToClose(onCancel, !busy);
  const [revealed, setRevealed] = useState(false);
  const words = phrase.split(' ');

  // Turnstile, mirroring Onboarding's SignInStep: no challenge runs
  // until the server actually refuses a tokenless confirm, and only
  // then does the button wait on one. Nothing in the client can read
  // the Supabase Auth CAPTCHA toggle, so the refusal is the signal.
  // Tokens are single-use, so confirm consumes the token at click time
  // and immediately re-arms the widget - keying the reset off `error`
  // would miss a second failure with an identical message and
  // resubmit a spent token.
  const [turnstileOk, setTurnstileOk] = useState(false);
  const [turnstileKey, setTurnstileKey] = useState(0);
  const captchaTokenRef = useRef<string | null>(null);
  // Set when the challenge never resolves: without it Sign in just
  // stays greyed out with no explanation (#120).
  const [stalled, setStalled] = useState<string | null>(null);

  function handleToken(token: string | null) {
    setStalled(null);
    if (token === 'dev-bypass') {
      // Missing-site-key builds: no real token to forward - see
      // Onboarding's handleToken for the contract.
      setTurnstileOk(true);
      return;
    }
    if (!token) {
      // Errored or expired (the user can idle here past the ~300s token
      // lifetime while reading the prompt). Close the gate with the
      // token, or Sign in stays clickable and submits tokenless.
      captchaTokenRef.current = null;
      setTurnstileOk(false);
      return;
    }
    captchaTokenRef.current = token;
    setTurnstileOk(true);
  }

  return (
    <div
      className="fixed inset-0 bg-black/50 dark:bg-black/70 z-50 flex items-center justify-center p-4"
      onClick={busy ? undefined : onCancel}
    >
      <div
        className="bg-surface-2 border border-divider rounded-lg max-w-md w-full p-5 space-y-4"
        onClick={(e) => e.stopPropagation()}
      >
        <div>
          <h2 className="text-lg font-semibold">{t('qrSignInPrompt.title')}</h2>
          <p className="mt-1 text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed">
            {t('qrSignInPrompt.body')}
          </p>
        </div>

        <div className="rounded-lg border border-divider p-3">
          <div className="flex items-center justify-between mb-2">
            <div className="text-[10px] uppercase tracking-wide text-neutral-500 dark:text-neutral-600">
              {t('qrSignInPrompt.scannedPhrase')}
            </div>
            <button
              type="button"
              onClick={() => setRevealed((v) => !v)}
              className="text-xs text-accent hover:underline"
            >
              {revealed ? t('qrSignInPrompt.hide') : t('qrSignInPrompt.reveal')}
            </button>
          </div>
          {revealed ? (
            <div className="grid grid-cols-3 gap-1.5" dir="ltr">
              {/* rtl-ok: BIP-39 phrase words, always LTR */}
              {words.map((w, i) => (
                <div
                  key={i}
                  className="rounded bg-neutral-100 dark:bg-neutral-900 border border-divider px-2 py-1 text-[11px] font-mono truncate"
                >
                  <span className="text-neutral-400 dark:text-neutral-600 me-1">
                    {i + 1}.
                  </span>
                  {w}
                </div>
              ))}
            </div>
          ) : (
            <div className="font-mono text-xs text-neutral-500 dark:text-neutral-500 tracking-wider select-none">
              •••• •••• •••• •••• •••• •••• •••• •••• •••• •••• •••• ••••
            </div>
          )}
        </div>

        <label className="flex items-start gap-2 text-xs text-neutral-700 dark:text-neutral-300 cursor-pointer rounded-md border border-divider bg-neutral-50 dark:bg-neutral-900/40 p-2.5">
          <input
            type="checkbox"
            checked={trustDevice}
            onChange={(e) => onTrustDeviceChange(e.target.checked)}
            disabled={busy}
            className="mt-0.5 accent-accent"
          />
          <span>
            <span className="font-medium">{t('trustDevice.label')}</span>
            <span className="block text-[11px] text-neutral-500 dark:text-neutral-500 mt-0.5 leading-relaxed">
              {t('trustDevice.descriptionRestarts')}
            </span>
          </span>
        </label>

        {(error ?? stalled) && (
          <div className="rounded border border-red-400/40 bg-red-50 dark:bg-red-950/20 text-red-700 dark:text-red-300 px-3 py-2 text-xs">
            {error ?? stalled}
          </div>
        )}

        {captchaRequired && (
          <TurnstileWidget
            key={turnstileKey}
            onToken={handleToken}
            onTimeout={() => setStalled(t('signIn.timedOut'))}
            className="flex justify-center"
          />
        )}

        <div className="flex gap-2 justify-end pt-1">
          <button
            type="button"
            disabled={busy}
            onClick={onCancel}
            className="text-sm rounded border border-neutral-300 dark:border-neutral-800 px-3 py-1.5 hover:bg-surface-1 transition disabled:opacity-50"
          >
            {t('common:actions.cancel')}
          </button>
          <button
            type="button"
            disabled={busy || (captchaRequired && !turnstileOk)}
            onClick={() => {
              const token = captchaTokenRef.current ?? undefined;
              // Spent the moment it is submitted - re-arm now so any
              // failed attempt retries with a fresh token.
              captchaTokenRef.current = null;
              setTurnstileOk(false);
              setTurnstileKey((k) => k + 1);
              onConfirm(token);
            }}
            className="text-sm rounded bg-accent text-white px-4 py-1.5 hover:bg-accent-hover transition font-medium disabled:opacity-50"
          >
            {busy ? t('signIn.signingIn') : t('qrSignInPrompt.signIn')}
          </button>
        </div>
      </div>
    </div>
  );
}
