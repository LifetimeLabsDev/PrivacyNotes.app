import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ArrowsClockwise, Info } from './icons';
import { HoverLabel } from './HoverLabel';
import { formatBytes } from './formatBytes';

/** formatBytes with the pointless trailing ".0" trimmed ("500.0 MB" →
 *  "500 MB") - this line has to fit a narrow list pane in one piece. */
function compactBytes(bytes: number): string {
  return formatBytes(bytes).replace(/\.0(\s)/, '$1');
}

type Props = {
  /** Already-translated "Storage" label from the owning pane's namespace. */
  label: string;
  usedBytes: number;
  maxBytes: number;
  /** Re-runs the server-side recount (recalculate_my_quota) + refetch. */
  onRefresh: () => Promise<void> | void;
};

/**
 * Storage usage bar shared by the Trash and Files panes: one
 * "N% used (X / Y)" line, the fill track, and a refresh control so the
 * figure can be brought to server ground truth on demand instead of
 * only on view switches. The button reuses the Markdown rescan
 * button's two-animation contract (half-turn on hover, continuous spin
 * while running, held one full rotation so a fast refresh still
 * visibly runs - see MarkdownListPane's handleRescan for the rationale).
 */
export function StorageBar({ label, usedBytes, maxBytes, onRefresh }: Props) {
  const { t } = useTranslation('common');
  const [busy, setBusy] = useState(false);
  if (maxBytes <= 0) return null;
  const pct = Math.min((usedBytes / maxBytes) * 100, 100);

  async function handleRefresh() {
    if (busy) return;
    setBusy(true);
    try {
      await Promise.all([
        onRefresh(),
        new Promise((resolve) => setTimeout(resolve, 600)),
      ]);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="shrink-0 px-4 pt-2 pb-1">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 mb-1.5">
        <span className="flex items-center gap-1 text-xs text-neutral-600 dark:text-neutral-400">
          {label}
          <HoverLabel label={t('storageBar.cleanupInfo')} position="below-start" multiline className="flex items-center">
            <span tabIndex={0} aria-label={t('storageBar.cleanupInfo')} className="inline-flex items-center cursor-help">
              <Info size={13} />
            </span>
          </HoverLabel>
        </span>
        <span className="flex items-center gap-2 ml-auto">
          <span className="text-xs text-neutral-600 dark:text-neutral-400 whitespace-nowrap">
            {t('storageBar.usage', {
              percent: Math.round(pct),
              used: compactBytes(usedBytes),
              max: compactBytes(maxBytes),
            })}
          </span>
          <HoverLabel label={t('storageBar.refresh')} position="below-end">
            <button
              type="button"
              onClick={() => void handleRefresh()}
              disabled={busy}
              aria-label={t('storageBar.refresh')}
              className="group inline-flex items-center justify-center w-7 h-7 shrink-0 rounded-md border border-divider bg-surface-2 text-pn-muted hover:border-accent hover:text-accent disabled:opacity-50 transition cursor-pointer"
            >
              <ArrowsClockwise
                size={15}
                className={busy ? 'animate-spin' : 'transition-transform duration-300 group-hover:rotate-180'}
              />
            </button>
          </HoverLabel>
        </span>
      </div>
      <div className="h-2 rounded-full bg-neutral-200 dark:bg-neutral-800 overflow-hidden">
        <div
          className={`h-full rounded-full transition-all ${
            pct > 80 ? 'bg-amber-500 dark:bg-amber-400' : 'bg-accent'
          }`}
          style={{ width: `${Math.max(pct, 0.5)}%` }}
        />
      </div>
    </div>
  );
}
