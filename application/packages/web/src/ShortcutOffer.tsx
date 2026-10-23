import { useTranslation } from 'react-i18next';
import { Monitor, X } from './icons';
import { desktopShortcutUrl, dismissDesktopOffer, type ShortcutTarget } from './noteShortcut';
import { useEscapeToClose } from './useEscapeToClose';

/**
 * The offer to open a shortcut in the desktop app, in a computer browser.
 * Loaded only when a shortcut is waiting, so the boot path does not carry it.
 *
 * Spec: ops/docs/archive/note-shortcuts.md (6)
 */

/** The bar over a note a shortcut opened in a computer browser. "Open in
 *  app" hides it for this tab; the x hides it on this browser for good. */
export function ShortcutDesktopBar({ target, onClose }: { target: ShortcutTarget; onClose: () => void }) {
  const { t } = useTranslation('shell');
  function dismiss() {
    dismissDesktopOffer();
    onClose();
  }
  return (
    <div className="shrink-0 flex items-center gap-2 sm:gap-3 border-b border-divider bg-accent/10 px-3 sm:px-4 py-2">
      <Monitor size={16} className="shrink-0 text-accent" aria-hidden="true" />
      <p className="min-w-0 flex-1 truncate text-[13px] leading-snug text-pn">{t('shortcut.offerText')}</p>
      <a
        href={desktopShortcutUrl(target)}
        onClick={onClose}
        className="shrink-0 rounded-lg bg-accent-fill hover:bg-accent-fill-hover text-white text-[13px] font-semibold px-3 py-1.5 transition"
      >
        {t('shortcut.offerOpen')}
      </a>
      <button
        type="button"
        onClick={dismiss}
        aria-label={t('shortcut.offerDismiss')}
        className="shrink-0 rounded-md p-1 text-pn-muted hover:bg-accent/15 transition"
      >
        <X />
      </button>
    </div>
  );
}

/** The card over the sign-in form when a shortcut is waiting. "Sign in here"
 *  closes it and leaves the shortcut waiting for the vault. */
export function ShortcutSignInCard({ target, onSignIn }: { target: ShortcutTarget; onSignIn: () => void }) {
  const { t } = useTranslation('shell');
  useEscapeToClose(onSignIn);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div role="dialog" aria-modal="true" aria-labelledby="shortcut-card-title" className="w-full max-w-sm rounded-2xl border border-divider bg-surface-2 p-6 text-center shadow-xl">
        <Monitor size={28} className="mx-auto text-accent" aria-hidden="true" />
        <h2 id="shortcut-card-title" className="mt-3 text-lg font-semibold text-pn">{t('shortcut.cardTitle')}</h2>
        <p className="mt-1 text-sm text-pn-muted">{t('shortcut.cardBody')}</p>
        <div className="mt-5 flex flex-col gap-2 sm:flex-row sm:justify-center">
          <a
            href={desktopShortcutUrl(target)}
            className="rounded-lg bg-accent-fill hover:bg-accent-fill-hover text-white text-sm font-semibold px-4 py-2 transition"
          >
            {t('shortcut.cardOpen')}
          </a>
          <button
            type="button"
            onClick={onSignIn}
            className="rounded-lg border border-divider text-pn text-sm font-medium px-4 py-2 hover:bg-surface-1 transition"
          >
            {t('shortcut.cardSignIn')}
          </button>
        </div>
        <p className="mt-4 text-[12px] text-pn-muted">{t('shortcut.cardAfter')}</p>
      </div>
    </div>
  );
}
