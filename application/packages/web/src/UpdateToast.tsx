import { useTranslation } from 'react-i18next';
import { ArrowUp, ArrowClockwise } from './icons';

/**
 * Shared "Update available" toast - single source of truth for both the web
 * refresh prompt (VersionUpdateToast) and the desktop restart prompt
 * (DesktopUpdater). Purely presentational; the caller supplies the action
 * label/handler (Refresh -> reload, Restart -> relaunch) and an optional
 * changelog handler (web opens a tab, desktop opens the system browser).
 *
 * `required` is the manual-install channels' severity flag (direct APK, Linux
 * .deb): the caller passes it when the running build is below the release
 * floor, which swaps the title and tints the toast amber. It only changes how
 * the toast LOOKS - whether a dismiss button exists is decided by the caller
 * passing onDismiss or not. Spec: ops/docs/android-update-check.md (a missing or unreachable policy must fail open to optional).
 */
export function UpdateToast({
  version,
  actionLabel,
  onAction,
  onChangelog,
  onDismiss,
  required = false,
  sizeBytes,
}: {
  /** Omitted by the store builds (Play/iOS), which only know the floor, not
   *  what the store will install - the meta line then collapses away. */
  version?: string;
  actionLabel: string;
  onAction: () => void;
  onChangelog?: () => void;
  onDismiss?: () => void;
  required?: boolean;
  sizeBytes?: number;
}) {
  const { t } = useTranslation('common');
  // Decimal MB, matching how every store and download page quotes an APK size.
  const size = sizeBytes ? `${Math.round(sizeBytes / 1_000_000)} MB` : null;
  const hasMeta = !!(version || size || onChangelog);
  return (
    <div
      role="status"
      aria-live="polite"
      className="fixed z-[100] start-4 end-4 sm:start-auto sm:end-4 sm:max-w-sm pn-toast-in"
      // Account for the iPhone home-indicator stripe (and any other bottom
      // safe-area inset). On platforms without a safe area env() returns 0,
      // so this collapses to a plain 1rem.
      style={{ bottom: 'calc(env(safe-area-inset-bottom, 0px) + 1rem)' }}
    >
      <div
        className={`flex items-center gap-3 rounded-lg border border-divider border-s-[3px] border-e-[3px] bg-surface-2 px-3 py-2.5 shadow-2xl ${
          required
            ? 'border-l-amber-500 border-r-amber-500'
            : 'border-l-accent border-r-accent'
        }`}
      >
        <div
          className={`shrink-0 flex items-center justify-center w-9 h-9 rounded-lg ${
            required ? 'bg-amber-500/10' : 'bg-accent/10'
          }`}
        >
          <ArrowUp
            className={`w-4 h-4 ${required ? 'text-amber-600 dark:text-amber-400' : 'text-accent'}`}
            aria-hidden="true"
          />
        </div>
        <div className="flex-1 min-w-0 leading-tight">
          <div className="text-sm font-medium text-pn">
            {t(required ? 'updateToast.required' : 'updateToast.available')}
          </div>
          {hasMeta && (
            <div className="text-xs text-pn-muted mt-0.5">
              {version && `v${version}`}
              {size && (version ? ` · ${size}` : size)}
              {onChangelog && (
                <>
                  {(version || size) && ' · '}
                  <button
                    type="button"
                    onClick={onChangelog}
                    className="text-accent hover:underline"
                  >
                    {t('updateToast.changelog')}
                  </button>
                </>
              )}
            </div>
          )}
        </div>
        <button
          type="button"
          onClick={onAction}
          className="shrink-0 inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent text-white text-sm font-medium hover:bg-accent-hover transition"
        >
          <ArrowClockwise className="w-3.5 h-3.5" aria-hidden="true" />
          {actionLabel}
        </button>
        {onDismiss && (
          <button
            type="button"
            onClick={onDismiss}
            aria-label={t('updateToast.dismiss')}
            className="shrink-0 text-pn-muted hover:text-pn px-1 text-lg leading-none -me-0.5"
          >
            ×
          </button>
        )}
      </div>
    </div>
  );
}
