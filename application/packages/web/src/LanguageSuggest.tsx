import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Flag, setLanguage, activeLocale, preferredLocale, LANGUAGE_META } from './languages';
import { LOCALE_TO_SLUG } from './localeRoutes';
import { X } from './icons';

const DISMISS_KEY = 'privacynotes.langSuggestDismissed';

/**
 * One-time dismissible banner offering the visitor's own browser language when
 * the page is showing a different one (e.g. landing on /es with an English
 * browser). Hidden once the page already matches their language, once they pick
 * a language explicitly, or once dismissed. The offer is labelled in the
 * suggested language and navigates to its marketing slug.
 */
export function LanguageSuggest({ className }: { className?: string }) {
  const { t } = useTranslation('settings');
  const [hidden, setHidden] = useState(false);
  const current = activeLocale();
  const suggested = preferredLocale();
  const explicit = localStorage.getItem('privacynotes.langExplicit') === '1';
  const dismissed = localStorage.getItem(DISMISS_KEY) === '1';

  if (hidden || explicit || dismissed || suggested === current) return null;

  return (
    <div className={`flex items-center gap-1 rounded-full border border-accent/40 bg-accent/[0.08] ps-2.5 pe-1 py-1 text-sm ${className ?? ''}`}>
      <button
        type="button"
        onClick={() => {
          setLanguage(suggested);
          window.location.assign(LOCALE_TO_SLUG[suggested] ?? '/');
        }}
        // Washi variables, not neutral grays: this banner renders only on
        // the landing (inside .pn-washi), and gray-on-ink was unreadable
        // in dark mode.
        className="inline-flex items-center gap-1.5 font-medium text-[var(--wl-ink)] hover:text-accent transition"
      >
        <Flag code={suggested} />
        {t('langSuggest.action', { lng: suggested, lang: LANGUAGE_META[suggested]?.native ?? suggested })}
      </button>
      <button
        type="button"
        onClick={() => {
          localStorage.setItem(DISMISS_KEY, '1');
          setHidden(true);
        }}
        aria-label={t('langSuggest.dismiss', { lng: suggested })}
        className="rounded-full p-1 text-[var(--wl-muted)] hover:bg-[var(--wl-ink)]/10 hover:text-[var(--wl-ink)] transition"
      >
        <X size={14} />
      </button>
    </div>
  );
}
