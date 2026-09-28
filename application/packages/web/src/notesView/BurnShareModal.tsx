import { useState } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import { useEscapeToClose } from '../useEscapeToClose';
import { HelpChip } from '../HelpChip';
import { Copy, Fire, Warning, X } from '../icons';
import { createBurnLink } from '../burnShare';
import type { VaultField } from '../vaultFields';
import {
  BURN_LIFETIME_HOURS,
  BURN_READ_SECONDS,
  DEFAULT_BURN_LIFETIME_HOURS,
  DEFAULT_BURN_READ_SECONDS,
} from '../burnOptions';

/**
 * The "Burn after reading" modal. The sender picks the reading time and the
 * link lifetime, and one button creates the link and hands it over: copied
 * on desktop, the share sheet on a phone. The choices lock once the link
 * exists, because they are sealed into it.
 */
export function BurnShareModal({
  title,
  body,
  fields,
  imagesStripped,
  isMobile,
  onCreated,
  onClose,
}: {
  title: string;
  body: string;
  fields?: VaultField[];
  imagesStripped: boolean;
  isMobile: boolean;
  onCreated: () => void;
  onClose: () => void;
}) {
  const { t } = useTranslation('notesChrome');
  useEscapeToClose(onClose);
  const [readSeconds, setReadSeconds] = useState(DEFAULT_BURN_READ_SECONDS);
  const [lifetimeHours, setLifetimeHours] = useState(DEFAULT_BURN_LIFETIME_HOURS);
  const [url, setUrl] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const share = isMobile && typeof navigator.share === 'function';

  async function create(): Promise<string> {
    const result = await createBurnLink(title, body, fields, readSeconds, lifetimeHours);
    if (!result.ok) throw new Error(result.error);
    onCreated();
    setUrl(result.url);
    return result.url;
  }

  async function handleShare(link: string) {
    try {
      await navigator.share({ title: title || t('notes:burn.shareTitle'), url: link });
    } catch (e: unknown) {
      if (e instanceof DOMException && e.name === 'AbortError') return;
      await copyText(link);
    }
  }

  async function copyText(link: string) {
    try {
      await navigator.clipboard.writeText(link);
      setCopied(true);
    } catch { /* clipboard blocked - the link is still selectable */ }
  }

  function handlePrimary() {
    setError(null);
    if (url) {
      void (share ? handleShare(url) : copyText(url));
      return;
    }
    setBusy(true);
    const pending = create();
    let copying = false;
    if (!share && typeof ClipboardItem !== 'undefined' && navigator.clipboard?.write) {
      // WebKit keeps a clipboard write only inside the click that asked for
      // it, and the link needs a server round trip first. Handing the write
      // a promise starts it inside the click and fills it when the link
      // arrives. Where that is refused, a plain write follows.
      copying = true;
      const blob = pending.then((link) => new Blob([link], { type: 'text/plain' }));
      // The failure is reported below; this copy of it has nobody to tell.
      blob.catch(() => undefined);
      navigator.clipboard
        .write([new ClipboardItem({ 'text/plain': blob })])
        .then(() => setCopied(true))
        .catch(() => pending.then(copyText).catch(() => undefined));
    }
    pending
      .then((link) => (share ? handleShare(link) : copying ? undefined : copyText(link)))
      .catch((e: unknown) => setError(e instanceof Error ? e.message : t('burnShare.storeFailed')))
      .finally(() => setBusy(false));
  }

  const selectClass =
    'w-full rounded-md border border-neutral-300 dark:border-neutral-700 bg-surface-1 text-sm px-2.5 py-2 disabled:opacity-60';

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
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <label className="block text-[13px]">
            <span className="block mb-1">{t('burnShareModal.readTime')}</span>
            <select
              className={selectClass}
              value={readSeconds}
              disabled={url !== null || busy}
              onChange={(e) => setReadSeconds(Number(e.target.value))}
            >
              {BURN_READ_SECONDS.map((s) => (
                <option key={s} value={s}>
                  {s < 3600
                    ? t('burnShareModal.minutes', { count: s / 60 })
                    : t('burnShareModal.hours', { count: s / 3600 })}
                </option>
              ))}
            </select>
            <span className="block mt-1 text-xs text-neutral-500">{t('burnShareModal.readTimeHint')}</span>
          </label>
          <label className="block text-[13px]">
            <span className="block mb-1">{t('burnShareModal.lifetime')}</span>
            <select
              className={selectClass}
              value={lifetimeHours}
              disabled={url !== null || busy}
              onChange={(e) => setLifetimeHours(Number(e.target.value))}
            >
              {BURN_LIFETIME_HOURS.map((h) => (
                <option key={h} value={h}>
                  {h < 72
                    ? t('burnShareModal.afterHours', { count: h })
                    : t('burnShareModal.afterDays', { count: h / 24 })}
                </option>
              ))}
            </select>
            <span className="block mt-1 text-xs text-neutral-500">{t('burnShareModal.lifetimeHint')}</span>
          </label>
        </div>
        {url && (
          <input
            type="text"
            readOnly
            value={url}
            className="w-full rounded-md border border-neutral-300 dark:border-neutral-700 bg-neutral-50 dark:bg-neutral-900 text-neutral-700 dark:text-neutral-300 text-sm px-3 py-2.5 font-mono truncate focus:outline-none"
            onFocus={(e) => e.target.select()}
          />
        )}
        {error && <p className="text-[13px] text-red-600 dark:text-red-400">{error}</p>}
        <div className="flex gap-2">
          <button
            onClick={onClose}
            className="flex-1 rounded-md border border-neutral-300 dark:border-neutral-800 hover:bg-surface-1 px-4 py-2 text-sm transition"
          >
            {t('common:actions.close')}
          </button>
          <button
            onClick={handlePrimary}
            disabled={busy}
            className={`flex-1 rounded-md px-4 py-2 text-sm font-medium transition flex items-center justify-center gap-1.5 disabled:opacity-60 ${
              copied
                ? 'bg-green-500 text-white'
                : 'bg-accent text-white hover:bg-accent-hover'
            }`}
          >
            <Copy size={16} />
            {copied
              ? t('burnShareModal.copied')
              : share
                ? t('burnShareModal.share')
                : url
                  ? t('common:actions.copy')
                  : t('burnShareModal.create')}
          </button>
        </div>
      </div>
    </div>
  );
}
