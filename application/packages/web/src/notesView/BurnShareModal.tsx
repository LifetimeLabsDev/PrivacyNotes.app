import { Trans, useTranslation } from 'react-i18next';
import { useEscapeToClose } from '../useEscapeToClose';
import { HelpChip } from '../HelpChip';
import { Copy, Fire, Warning, X } from '../icons';

/**
 * Result modal shown after a successful "Burn after reading" share.
 * Surfaces the one-time URL with a copy button and reassures the user
 * that the original note is unaffected.
 */
export function BurnShareModal({
  url,
  copied,
  imagesStripped,
  onCopy,
  onClose,
}: {
  url: string;
  copied: boolean;
  imagesStripped?: boolean;
  onCopy: () => void;
  onClose: () => void;
}) {
  const { t } = useTranslation('notesChrome');
  useEscapeToClose(onClose);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 dark:bg-black/70 p-4"
      onClick={onClose}
    >
      <div
        className="w-full max-w-md rounded-lg bg-surface-2 border border-divider text-pn p-6 space-y-4"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-2.5">
            <span className="text-orange-500">
              <Fire size={22} />
            </span>
            <h2 className="text-lg font-semibold">
              {t('burnShareModal.title')}
            </h2>
          </div>
          <button
            onClick={onClose}
            className="text-neutral-400 hover:text-neutral-600 dark:hover:text-neutral-300 transition p-1 -m-1"
            aria-label={t('close')}
          >
            <X size={18} />
          </button>
        </div>
        <p className="text-sm text-neutral-600 dark:text-neutral-400 leading-relaxed">
          <Trans
            i18nKey="notesChrome:burnShareModal.body"
            components={{ lead: <strong className="text-neutral-800 dark:text-neutral-200" /> }}
          />
        </p>
        <HelpChip surface="burn" />
        {imagesStripped && (
          <div className="flex items-center gap-2 rounded-md bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/60 text-amber-800 dark:text-amber-300 text-[13px] px-3 py-2">
            <Warning size={15} className="shrink-0" />
            {t('burnShareModal.imagesStripped')}
          </div>
        )}
        <input
          type="text"
          readOnly
          value={url}
          className="w-full rounded-md border border-neutral-300 dark:border-neutral-700 bg-neutral-50 dark:bg-neutral-900 text-neutral-700 dark:text-neutral-300 text-sm px-3 py-2.5 font-mono truncate focus:outline-none"
          onFocus={(e) => e.target.select()}
        />
        <div className="flex gap-2">
          <button
            onClick={onClose}
            className="flex-1 rounded-md border border-neutral-300 dark:border-neutral-800 hover:bg-surface-1 px-4 py-2 text-sm transition"
          >
            {t('common:actions.close')}
          </button>
          <button
            onClick={onCopy}
            className={`flex-1 rounded-md px-4 py-2 text-sm font-medium transition flex items-center justify-center gap-1.5 ${
              copied
                ? 'bg-green-500 text-white'
                : 'bg-accent text-white hover:bg-accent-hover'
            }`}
          >
            <Copy size={16} />
            {copied ? t('burnShareModal.copied') : t('common:actions.copy')}
          </button>
        </div>
      </div>
    </div>
  );
}
