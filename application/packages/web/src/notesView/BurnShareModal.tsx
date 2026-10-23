import { useState } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import { HelpChip } from '../HelpChip';
import { Check, Copy, Fire, Warning } from '../icons';
import { createBurnLink } from '../burnShare';
import type { VaultField } from '../vaultFields';
import { Button, Modal, ModalFooter } from '../ui';
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
    'w-full rounded-md border border-divider bg-surface-1 text-sm px-2.5 py-2 disabled:opacity-60';

  return (
    <Modal onClose={onClose} title={t('burnShareModal.title')} icon={<Fire size={16} className="text-orange-500" />} className="max-w-md p-6 space-y-4">
        <p className="text-sm text-pn-muted leading-relaxed">
          <Trans
            i18nKey="notesChrome:burnShareModal.body"
            components={{ lead: <strong className="text-pn" /> }}
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
            <span className="block mt-1 text-xs text-pn-muted">{t('burnShareModal.readTimeHint')}</span>
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
            <span className="block mt-1 text-xs text-pn-muted">{t('burnShareModal.lifetimeHint')}</span>
          </label>
        </div>
        {url && (
          <input
            type="text"
            readOnly
            value={url}
            className="w-full rounded-md border border-divider bg-surface-1 text-pn-soft text-sm px-3 py-2.5 font-mono truncate focus:outline-none"
            onFocus={(e) => e.target.select()}
          />
        )}
        {error && <p className="text-[13px] text-danger">{error}</p>}
        <ModalFooter>
          {!url && <Button action="cancel" onClick={onClose} />}
          <Button
            variant="primary"
            icon={copied ? <Check size={15} aria-hidden="true" /> : <Copy size={15} aria-hidden="true" />}
            onClick={handlePrimary}
            disabled={busy}
          >
            {copied
              ? t('burnShareModal.copied')
              : share
                ? t('burnShareModal.share')
                : url
                  ? t('common:actions.copy')
                  : t('burnShareModal.create')}
          </Button>
        </ModalFooter>
    </Modal>
  );
}
