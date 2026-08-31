import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useAuth } from './auth';
import { LogoIcon } from './LogoIcon';

/**
 * Full-screen error state for a failed OAuth hydration
 * (`auth.status === 'oauth_hydrate_failed'`).
 *
 * Deliberately loud: swallowing a hydrate failure would fall through to
 * the custody-choice / phrase-entry screens, offering an existing user a
 * fresh account, which orphans their data.
 * This screen makes the failure visible and recoverable: retry against
 * the current session, or give up and return to the sign-in options.
 * Nothing is wiped either way.
 * Spec: ops/docs/domain-split.md (pre-cutover gate)
 */
export function OAuthRetryScreen({ trust }: { trust: boolean }) {
  const { t } = useTranslation('auth');
  const { retryOAuthHydration, abandonOAuthHydration } = useAuth();
  const [busy, setBusy] = useState(false);

  return (
    <div className="min-h-dvh flex items-center justify-center p-4">
      <div className="bg-surface-2 border border-divider text-pn rounded-lg max-w-md w-full p-6 space-y-5 text-center">
        <div className="flex justify-center">
          <LogoIcon size={40} />
        </div>
        <div className="space-y-2">
          <h1 className="text-lg font-semibold">{t('hydrateError.title')}</h1>
          <p className="text-sm text-neutral-600 dark:text-neutral-400 leading-relaxed">
            {t('hydrateError.body')}
          </p>
        </div>
        <button
          type="button"
          disabled={busy}
          onClick={() => {
            setBusy(true);
            void retryOAuthHydration(trust).finally(() => setBusy(false));
          }}
          className="w-full rounded-lg bg-accent text-white hover:bg-accent-hover px-4 py-3 font-medium transition shadow-sm disabled:opacity-60"
        >
          {t('signIn.tryAgain')}
        </button>
        <button
          type="button"
          disabled={busy}
          onClick={() => void abandonOAuthHydration()}
          className="w-full text-sm text-neutral-600 dark:text-neutral-400 hover:text-pn transition"
        >
          {t('oauthHandoff.backToOptions')}
        </button>
      </div>
    </div>
  );
}
