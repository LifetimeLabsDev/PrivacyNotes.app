import { useTranslation } from 'react-i18next';
import { DEMO_APP_URL } from './demo';
import { withSource } from './campaignSource';
import { Lock, X } from './icons';

type Props = {
  onDismiss: () => void;
};

/**
 * Dismissable demo banner: a full-width bar at the top of the app shell,
 * above the header. Frames the sandbox as zero-risk rather than as a
 * warning, and is explicit that demo notes do not carry over: an account
 * starts a fresh, encrypted notebook of the user's own. Carries the single
 * conversion CTA (sign up on the real app).
 *
 * Rendered as the first child of NotesView's h-dvh flex column, so it owns
 * its own strip and the header and panes below reflow around it. That is the
 * entire point. Earlier versions floated - pinned bottom-right, then centered
 * on the editor column - and each position landed on top of something else,
 * most recently the editor's word-count row and its "Show markdown" link. A
 * bar in the flow cannot occlude anything, and needs none of the
 * overlay-yielding or column-measuring machinery the floating one required.
 *
 * Dismissable, unlike the floating version. The permanent "nothing is saved"
 * signal is carried by SyncStatus in the footer, which reads "Not saved" in
 * demo and cannot be dismissed, so closing the conversion CTA costs no
 * honesty. Dismissal is session state: a reload brings it back.
 *
 * Spec: ops/specs/editor-mode-toggle.md (that row's bottom position varies by note length via mt-auto)
 */
export function DemoBanner({ onDismiss }: Props) {
  const { t } = useTranslation('shell');
  return (
    <div className="shrink-0 flex items-center gap-2 sm:gap-3 border-b border-emerald-300/80 dark:border-emerald-800/70 bg-emerald-50 dark:bg-emerald-950/90 px-3 sm:px-4 py-2">
      <Lock size={16} className="shrink-0 text-emerald-700 dark:text-emerald-400" aria-hidden="true" />
      <p className="min-w-0 flex-1 truncate text-[13px] leading-snug text-emerald-950 dark:text-emerald-100">
        <span className="font-semibold">{t('demoBanner.title')}</span>
        {/* Mini on phones: the description drops, leaving icon + title + CTA. */}
        <span className="hidden sm:inline text-emerald-800 dark:text-emerald-300/90">
          {' '}
          {t('demoBanner.description')}
        </span>
      </p>
      <a
        href={withSource(DEMO_APP_URL)}
        className="shrink-0 rounded-lg bg-emerald-700 hover:bg-emerald-800 text-white text-[13px] font-semibold px-3 py-1.5 transition"
      >
        {t('demoBanner.cta')}
      </a>
      <button
        type="button"
        onClick={onDismiss}
        aria-label={t('demoBanner.dismiss')}
        className="shrink-0 rounded-md p-1 text-emerald-700 dark:text-emerald-400 hover:bg-emerald-100 dark:hover:bg-emerald-900 transition"
      >
        <X />
      </button>
    </div>
  );
}
