import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { useAuth } from './auth';
import type { DeviceRow } from './devices';
import { shortDeviceId } from './deviceSlots';
import { isPaddleConfigured, isBetaPricing } from './paddle';
import { startProCheckout } from './billing';
import { PRO_PRICE, EARLY_PRICE } from './pricing';
import { PhraseView } from './security/PhraseView';

/**
 * Blocking modal shown immediately after sign-in when the free-tier
 * active-device cap is hit. No app chrome is rendered behind it - the
 * user must revoke one of the active devices (which immediately frees
 * the slot) or upgrade before they can see any notes.
 *
 * Recently revoked devices are listed for transparency only - they
 * stay in the table for a 72h cooldown window for ghost-row hygiene
 * but no longer occupy a slot. Spec: migration 0043.
 */
export function DeviceLimitModal() {
  const { t } = useTranslation('security');
  const { auth, resolveDeviceLimit, signOut, refreshProStatus } = useAuth();
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [checkoutLoading, setCheckoutLoading] = useState(false);
  const [showPhrase, setShowPhrase] = useState(false);
  const configured = isPaddleConfigured();

  // No Escape binding on purpose. Escape used to run the same signOut
  // as the button, and signOut erases the stored phrase, the wrapped
  // blobs and the local database - a user who never wrote the phrase
  // down loses the vault on one keypress. That is the exact
  // Escape-to-wipe pattern backlog #121 removed from
  // SessionExpiredModal; the explicit button below (next to the phrase
  // backup link) is the only way out. Session audit 2026-08-25.

  // A paid checkout whose webhook outlives refreshProStatus's ~15 s poll
  // dispatches pro-activation-pending - and the only other listener
  // (NotesView) is unmounted in this state, so the modal must catch it
  // itself or the paying user sits behind the cap with zero feedback.
  const [activationPending, setActivationPending] = useState(false);
  useEffect(() => {
    const onPending = () => setActivationPending(true);
    window.addEventListener('privacynotes:pro-activation-pending', onPending);
    return () =>
      window.removeEventListener('privacynotes:pro-activation-pending', onPending);
  }, []);
  // While pending, keep re-checking: payment is confirmed (the event only
  // fires off checkout.completed), so poll until the webhook lands.
  // refreshProStatus then completes the interrupted registration and this
  // modal unmounts. Silent single attempts - the banner below already
  // carries the message.
  useEffect(() => {
    if (!activationPending) return;
    const interval = window.setInterval(
      () => void refreshProStatus({ silent: true, attempts: 1 }),
      5000,
    );
    return () => window.clearInterval(interval);
  }, [activationPending, refreshProStatus]);

  if (auth.status !== 'device_limit_reached') return null;

  // OAuth users hit by the device cap on a fresh install can't revoke
  // anything (the existing devices may be unreachable) - and signing
  // out only loops them back to OAuth. Their recovery phrase is the
  // escape hatch: writing it down gives them a permanent way back if
  // OAuth ever fails. See gap #22.
  const isOAuth = auth.method === 'oauth';

  const activeDevices = auth.devices.filter((d) => !d.revoked_at);
  const cooldownDevices = auth.devices.filter((d) => d.revoked_at);

  const handleRevoke = async (targetDeviceId: string) => {
    setBusy(targetDeviceId);
    setError(null);
    const result = await resolveDeviceLimit(targetDeviceId);
    if (!result.ok) {
      setError(result.error);
      setBusy(null);
      return;
    }
    // Success - auth state flips to 'authenticated', this modal unmounts.
  };

  return (
    <div className="fixed inset-0 bg-black/50 dark:bg-black/70 flex items-center justify-center p-4 z-50">
      <div className="bg-surface-2 border border-divider text-pn rounded-lg max-w-lg w-full p-6 space-y-5 max-h-[90vh] overflow-y-auto">
        <div>
          <h2 className="text-lg font-semibold mb-1">
            {t('deviceLimit.title')}
          </h2>
          <p className="text-sm text-neutral-600 dark:text-neutral-400 leading-relaxed">
            {t('deviceLimit.body', { limit: auth.limit, count: activeDevices.length })}
          </p>
        </div>

        {/* Active devices */}
        {activeDevices.length > 0 && (
          <div className="space-y-2">
            <div className="text-[11px] uppercase tracking-wide text-neutral-500 dark:text-neutral-600">
              {t('deviceLimit.activeDevices')}
            </div>
            {activeDevices.map((d) => (
              <DeviceRowView
                key={d.device_id}
                device={d}
                isCurrent={false}
                busy={busy === d.device_id}
                disabled={busy !== null}
                onRevoke={() => handleRevoke(d.device_id)}
              />
            ))}
          </div>
        )}

        {/* Recently removed devices - informational, do not occupy a slot. */}
        {cooldownDevices.length > 0 && (
          <div className="space-y-2">
            <div className="text-[11px] uppercase tracking-wide text-neutral-500 dark:text-neutral-600">
              {t('deviceLimit.recentlyRemoved')}
            </div>
            {cooldownDevices.map((d) => (
              <div
                key={d.device_id}
                className="flex items-center justify-between gap-3 rounded-md border border-neutral-200/60 dark:border-neutral-800/60 px-3 py-2 opacity-60"
              >
                <div className="min-w-0">
                  <div className="text-sm font-medium truncate text-neutral-500 dark:text-neutral-500">
                    {d.device_name}
                  </div>
                  <div className="text-[11px] text-neutral-400 dark:text-neutral-600">
                    {t('deviceLimit.removedAt', { when: formatRelative(d.revoked_at!, t) })}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {error && (
          <div className="rounded-md border border-red-300 bg-red-50 dark:border-red-900/60 dark:bg-red-950/30 text-red-700 dark:text-red-300 text-sm p-3">
            {error}
          </div>
        )}

        {/* Same copy as NotesView's pending banner (notes namespace) so no
            new locale strings are needed; the poll above retries for us. */}
        {activationPending && (
          <div className="rounded-md border border-amber-300 bg-amber-50 dark:border-amber-800 dark:bg-amber-950/30 text-amber-800 dark:text-amber-300 text-sm p-3">
            {t('notes:banner.proActivationPending')}
          </div>
        )}

        {configured ? (
          <div className="rounded-md border border-accent/40 bg-accent/5 dark:bg-accent/10 p-4 space-y-2">
            <div className="text-sm font-medium">{t('deviceLimit.upgradeHeading')}</div>
            <p className="text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed">
              {t('deviceLimit.upgradeBody')}
            </p>
            <button
              type="button"
              className="w-full rounded-md bg-accent hover:bg-accent-hover text-white text-sm font-medium px-3 py-2 transition disabled:opacity-50"
              // Also locked while a paid checkout awaits its webhook: the
              // one-time Pro product has no server-side dedupe, so a live
              // button here invites a second charge.
              disabled={checkoutLoading || activationPending}
              onClick={async () => {
                setCheckoutLoading(true);
                try {
                  await startProCheckout(
                    auth.pubkey,
                    () => {
                      void refreshProStatus();
                    },
                    () => {
                      // Desktop return: re-check Pro silently, no payment banner.
                      void refreshProStatus({ silent: true });
                    },
                    // Native IAP failure: reuse the modal's error box so the
                    // tap never fails silently (Play internal test).
                    (reason) => setError(t(`billing:purchaseError.${reason}`)),
                  );
                } catch (err) {
                  console.error('Paddle checkout error:', err);
                } finally {
                  setCheckoutLoading(false);
                }
              }}
            >
              {checkoutLoading ? t('deviceLimit.openingCheckout') : t('deviceLimit.upgradeCta', { price: isBetaPricing() ? EARLY_PRICE : PRO_PRICE })}
            </button>
          </div>
        ) : (
          // Paddle isn't configured (e.g. self-host, dev environment).
          // Without this fallback the modal is a dead end: revoke or
          // sign out, no third option. See gap #24.
          <div className="rounded-md border border-divider bg-neutral-50 dark:bg-neutral-900/40 p-4 space-y-2">
            <div className="text-sm font-medium">{t('deviceLimit.needMoreHeading')}</div>
            <p className="text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed">
              {t('deviceLimit.needMoreBody')}
            </p>
            <a
              href="https://lifetimelabs.dev/contact/"
              target="_blank"
              rel="noopener noreferrer"
              className="block w-full text-center rounded-md border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800 text-sm font-medium px-3 py-2 transition"
            >
              {t('deviceLimit.contactSupport')}
            </a>
          </div>
        )}

        {isOAuth && (
          // OAuth users may have signed up without ever seeing their
          // recovery phrase. If they hit the device cap and their other
          // devices are unreachable, the phrase is their only way to
          // recover. Reveal on demand. See gap #22.
          <div className="rounded-md border border-amber-400/40 bg-amber-50 dark:border-amber-600/30 dark:bg-amber-950/20 p-4 space-y-2">
            <div className="text-sm font-medium text-amber-800 dark:text-amber-300">
              {t('deviceLimit.saveRecoveryHeading')}
            </div>
            <p className="text-xs text-amber-700/90 dark:text-amber-400/90 leading-relaxed">
              {t('deviceLimit.saveRecoveryBody')}
            </p>
            {showPhrase ? (
              <PhraseView
                phrase={auth.phrase}
                onCancel={() => setShowPhrase(false)}
                showCallout={false}
                cancelLabel={t('deviceLimit.hide')}
              />
            ) : (
              <button
                type="button"
                onClick={() => setShowPhrase(true)}
                className="w-full rounded-md border border-amber-400/60 dark:border-amber-600/40 bg-surface-2 hover:bg-amber-50 dark:hover:bg-amber-950/40 text-sm font-medium text-amber-800 dark:text-amber-300 px-3 py-2 transition"
              >
                {t('deviceLimit.viewRecoveryPhrase')}
              </button>
            )}
          </div>
        )}

        <button
          type="button"
          onClick={() => void signOut({ keepUnsyncedNotes: true })}
          className="w-full rounded-md border border-neutral-300 hover:bg-neutral-100 dark:border-neutral-800 dark:hover:bg-neutral-900 text-sm px-3 py-2 transition"
          disabled={busy !== null}
        >
          {t('deviceLimit.signOut')}
        </button>
      </div>
    </div>
  );
}

function DeviceRowView({
  device,
  isCurrent,
  busy,
  disabled,
  onRevoke,
}: {
  device: DeviceRow;
  isCurrent: boolean;
  busy: boolean;
  disabled: boolean;
  onRevoke: () => void;
}) {
  const { t } = useTranslation('security');
  return (
    <div className="flex items-center justify-between gap-3 rounded-md border border-divider px-3 py-2">
      <div className="min-w-0">
        <div className="text-sm font-medium truncate">
          {device.device_name}
          <span className="ms-2 font-mono text-[11px] font-normal text-neutral-500">{shortDeviceId(device.device_id)}</span>
          {isCurrent && (
            <span className="ms-2 text-[10px] uppercase tracking-wide text-accent">
              {t('deviceLimit.thisDevice')}
            </span>
          )}
        </div>
        <div className="text-[11px] text-neutral-500 dark:text-neutral-500">
          {t('deviceLimit.lastActive', { platform: device.platform, when: formatRelative(device.last_seen_at, t) })}
        </div>
      </div>
      <button
        type="button"
        onClick={onRevoke}
        disabled={disabled}
        className="text-xs rounded-md border border-red-300 text-red-700 hover:bg-red-50 dark:border-red-900/60 dark:text-red-300 dark:hover:bg-red-950/30 px-2.5 py-1.5 transition disabled:opacity-50"
      >
        {busy ? t('deviceLimit.removing') : t('common:actions.remove')}
      </button>
    </div>
  );
}

function formatRelative(iso: string, t: TFunction): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return iso;
  const diff = Date.now() - then;
  const m = Math.floor(diff / 60_000);
  if (m < 1) return t('deviceLimit.relative.justNow');
  if (m < 60) return t('deviceLimit.relative.minutes', { count: m });
  const h = Math.floor(m / 60);
  if (h < 24) return t('deviceLimit.relative.hours', { count: h });
  const d = Math.floor(h / 24);
  return t('deviceLimit.relative.days', { count: d });
}
