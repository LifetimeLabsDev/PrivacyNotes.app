import { useEffect, useMemo, useState } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import { useAuth } from './auth';
import { useEscapeToClose } from './useEscapeToClose';
import {
  listDevices,
  registerDevice,
  revokeDevice,
  fetchQuotaUsage,
  recalculateQuota,
  fetchMyStorageSubs,
  manageStorageSub,
  previewStorageUpgrade,
  type DeviceRow,
  type QuotaUsage,
  type StorageSubRow,
} from './devices';
import { groupDeviceSlots, shortDeviceId, type DeviceSlot } from './deviceSlots';
import { readPanelCache, writePanelCache } from './accountPanelCache';
import { Check, SignOut, X } from './icons';
import { HoverLabel } from './HoverLabel';
import { DangerZone } from './DangerZone';
import { QuotaRing } from './QuotaRing';
import { IconUpgrade } from './UpgradeModal';
import { isStorageConfigured, getStoragePackages, isBetaPricing } from './paddle';
import { startStorageCheckout, startStorageUpgrade, openNativeSubscriptionManagement, storageProductId, isNativeStoreBuild, restoreNativePurchases, type RestoreOutcome } from './billing';
import { STORAGE_ADDON_PRICE, PRO_PRICE, EARLY_PRICE } from './pricing';
import { useStorePrices, type StorePrice } from './storePrices';
import { AccentBar, formatRelative, HeadlineRule, SectionEyebrow, SettingsCallout, SETTINGS_HELP } from './settingsUI';
import { SyncPanel } from './SyncPanel';
import { HelpChip } from './HelpChip';

type Props = {
  onClose: () => void;
  /**
   * Optional hook the parent uses to open the full Upgrade modal when
   * the user clicks the Pro CTA from here. The button is a stub when
   * undefined (keeps the modal renderable outside the main app shell).
   */
  onOpenUpgrade?: () => void;
  /** Sign-out handler - closes modal then triggers the phrase-reminder flow. */
  onSignOut?: () => void;
  /** Manual "Sync now" - the orchestrator's runSync. */
  onSyncNow?: () => void | Promise<void>;
  /** Render inline as a settings pane (no overlay, no own header/tabs/footer/escape). */
  embedded?: boolean;
  /**
   * Run the sync verification immediately on open. Set when the user
   * got here by clicking the sync status, which is already the
   * question this panel answers.
   */
  autoVerify?: boolean;
  /** Opens a note from ID & Sync's not-backed-up list. */
  onOpenNote?: (id: string) => void;
  /**
   * Whether a sync pass is running right now. Owned by the app shell,
   * passed in so this panel can report the same live state the footer
   * indicator shows - it is where that indicator sends people.
   */
  /** Controlled active tab. When set, the internal tab strip is the shell rail. */
  tab?: 'plan' | 'storage' | 'sync' | 'me';
  /** Called when the controlled tab should change (unused while embedded). */
  onTabChange?: (tab: 'plan' | 'storage' | 'sync' | 'me') => void;
};

/** What Remove acts on: one row of a slot, or every row in it. */
type RevokeTarget = { slot: DeviceSlot; rows: [DeviceRow, ...DeviceRow[]] };

/**
 * Device management + sync status panel.
 *
 * Shows the list of registered devices for the current pubkey, with a
 * "Remove" action that signs a revoke challenge with the user's
 * ed25519 private key and calls the `revoke-device` edge function.
 * The current device is flagged - removing it is allowed (the user
 * holds the phrase) but the UI warns, because the revoked device will
 * sign itself out on the next heartbeat (within a sync interval).
 *
 * Recently revoked devices are listed under "Recently removed" for
 * 72h as an audit trail. Cooldown rows do not occupy a slot - the
 * limit is strictly on active devices (see migration 0043).
 *
 * Pro status is surfaced with a badge + an upsell block for free
 * users.
 */
export function SyncOptionsModal({ onClose, onOpenUpgrade, onSignOut, onSyncNow, embedded = false, autoVerify = false, onOpenNote, tab: controlledTab, onTabChange }: Props) {
  const { t } = useTranslation('settings');
  // Real App Store / Play prices, already in the user's storefront currency.
  // Null everywhere else, and every use below falls back to the Paddle USD
  // figures. Spec: ops/docs/design-decisions.md (fair global pricing)
  const storePrices = useStorePrices();
  const { auth, supabase, refreshProStatus } = useAuth();
  // Seeded from the last-known figures for this account so the panel
  // paints immediately instead of holding an empty pane for a round-trip
  // (the reads below overwrite them within the same second). Null on a
  // first-ever open, in demo, or after a sign-out - the loading state
  // then behaves exactly as it always did. See accountPanelCache.ts.
  const cachePubkey = auth.status === 'authenticated' ? auth.pubkey : null;
  const cachedPanel = useMemo(
    () => (cachePubkey ? readPanelCache(cachePubkey) : null),
    [cachePubkey],
  );
  const [devices, setDevices] = useState<DeviceRow[] | null>(cachedPanel?.devices ?? null);
  const [quota, setQuota] = useState<QuotaUsage | null>(cachedPanel?.quota ?? null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<RevokeTarget | null>(null);

  useEscapeToClose(onClose, !embedded && !confirm);

  const authed = auth.status === 'authenticated' ? auth : null;
  // Pro status comes from auth state (set at sign-in by registerDevice).
  // Reading it from there instead of a fresh RPC avoids flipping the UI
  // to "Free" when the is_pro RPC fails due to a network blip.
  const isPro = authed?.isPro ?? null;
  const isEarlySupporter = authed?.isEarlySupporter ?? false;
  const [storageBusy, setStorageBusy] = useState(false);
  const [storagePurchaseError, setStoragePurchaseError] = useState<string | null>(null);
  const [restoreBusy, setRestoreBusy] = useState(false);
  const [restoreOutcome, setRestoreOutcome] = useState<RestoreOutcome | null>(null);
  const [storageSubs, setStorageSubs] = useState<StorageSubRow[] | null>(cachedPanel?.storageSubs ?? null);
  const [storageActionBusy, setStorageActionBusy] = useState(false);
  const [confirmingCancel, setConfirmingCancel] = useState(false);
  const [cancelDone, setCancelDone] = useState(false);
  // Pending upgrade awaiting explicit confirmation (prevents one-click charges).
  // priceLabel is the already-formatted renewal price (store string on native,
  // "$4.80" on web), so the confirm step quotes the same figure as the tile.
  const [confirmingUpgrade, setConfirmingUpgrade] = useState<{ gb: number; priceId: string; pricePerYear: number; priceLabel: string } | null>(null);
  const [upgradeDue, setUpgradeDue] = useState<string | null>(null);
  const [upgradePreviewLoading, setUpgradePreviewLoading] = useState(false);
  // One active storage sub per user under the package model.
  const activeStorageSub = storageSubs && storageSubs.length > 0 ? storageSubs[0] : null;
  // Tab is controllable: when the shell drives it (rail items), `controlledTab`
  // wins and the internal tab strip is hidden. Otherwise local state runs it.
  const [internalTab, setInternalTab] = useState<'plan' | 'storage' | 'sync' | 'me'>('plan');
  const tab = controlledTab ?? internalTab;
  const setTab = onTabChange ?? setInternalTab;

  useEffect(() => {
    if (!authed) return;
    let stale = false;
    void (async () => {
      // Paint first, heal second. Awaiting recalculateQuota BEFORE the reads
      // would hold the whole panel empty until four serial round-trips
      // completed - measured at ~10s on a phone whose NAT had killed the
      // connection pool (2026-08-26). So the reads go out immediately and
      // the panel paints off them; the recalc runs after, and one more quota
      // read swaps the healed figure in under the already-painted UI.
      const [ds, q, subs] = await Promise.all([
        listDevices(supabase),
        fetchQuotaUsage(supabase, isPro ?? false),
        fetchMyStorageSubs(supabase),
      ]);
      if (stale) return;
      setDevices(ds);
      setQuota(q);
      setStorageSubs(subs);
      writePanelCache(authed.pubkey, { devices: ds, quota: q, storageSubs: subs });
      // Recompute blob bytes from Storage ground truth so a drifted
      // image_bytes self-heals when the storage settings open. Best-effort;
      // the refetch swaps the healed figure in under the already-painted UI.
      await recalculateQuota(supabase);
      if (stale) return;
      const healed = await fetchQuotaUsage(supabase, isPro ?? false);
      if (stale) return;
      setQuota(healed);
      writePanelCache(authed.pubkey, { devices: ds, quota: healed, storageSubs: subs });
    })();
    // `tab` is a dependency on purpose: the settings shell keeps this
    // component mounted while the user moves between panels, so a
    // mount-only fetch showed a figure frozen at open time - another
    // device's deletes never appeared until a full reload (measured
    // 2026-08-10: two devices disagreed 425.0 vs 425.2 MB). Re-reading
    // on every panel entry keeps the server as the single source of
    // truth for the number on screen. `stale` guards the late writes:
    // a re-run for another panel must not overwrite fresher state.
    return () => {
      stale = true;
    };
  }, [authed, supabase, isPro, tab]);

  // Fetch the real prorated amount when the upgrade dialog opens.
  useEffect(() => {
    if (!confirmingUpgrade || !authed) {
      setUpgradeDue(null);
      return;
    }
    let cancelled = false;
    setUpgradeDue(null);
    setUpgradePreviewLoading(true);
    void (async () => {
      const sub = activeStorageSub;
      // Native-store subs (Play/Apple) have no server-side proration preview -
      // the store's own sheet shows the exact charge. Skip the Paddle preview
      // (it would 404 on a store purchase token) and let the dialog render its
      // generic "prorated amount" copy.
      if (sub && sub.source && sub.source !== 'paddle') {
        if (!cancelled) setUpgradePreviewLoading(false);
        return;
      }
      const { data: sessData } = await supabase.auth.getSession();
      const token = sessData.session?.access_token;
      if (!token || !sub) {
        if (!cancelled) setUpgradePreviewLoading(false);
        return;
      }
      const due = await previewStorageUpgrade({
        supabase,
        accessToken: token,
        subscriptionId: sub.subscription_id,
        priceId: confirmingUpgrade.priceId,
      });
      if (!cancelled) {
        setUpgradeDue(due);
        setUpgradePreviewLoading(false);
      }
    })();
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [confirmingUpgrade, authed, supabase]);

  // Esc closes only the upgrade dialog when it's open (topmost wins via the
  // hook's LIFO stack), leaving the Settings shell behind it open.
  useEscapeToClose(() => setConfirmingUpgrade(null), confirmingUpgrade !== null);

  // Manual restore (native store builds only). The automatic recheck in
  // authProStatus.ts already self-heals the common cases; this button exists
  // for Apple 3.1.1 and for support ("tap Restore purchases"). On success,
  // refresh Pro once - not per purchase - then re-read quota and subs so
  // restored storage capacity shows immediately.
  // Spec: ops/docs/plans/iap-restore-handoff.md
  async function handleRestore() {
    if (!authed || restoreBusy) return;
    setRestoreBusy(true);
    setRestoreOutcome(null);
    const outcome = await restoreNativePurchases(authed.pubkey);
    if (outcome === 'restored') {
      await refreshProStatus({ silent: true, attempts: 1 });
      const [q, subs] = await Promise.all([
        fetchQuotaUsage(supabase, true),
        fetchMyStorageSubs(supabase),
      ]);
      setQuota(q);
      setStorageSubs(subs);
    }
    setRestoreOutcome(outcome);
    setRestoreBusy(false);
  }

  async function handleStorageAction(action: 'cancel' | 'switch', target?: { priceId: string; gb: number }) {
    if (!authed || !activeStorageSub || storageActionBusy) return;
    const source = activeStorageSub.source ?? 'paddle';

    // Native-store subs (Play/Apple): the store owns the billing relationship,
    // so neither action can go through manage-storage-sub (a store purchase
    // token PATCHed at Paddle just 404s - burned in Play internal testing).
    if (source === 'play' || source === 'apple') {
      if (action === 'cancel') {
        // Cancellation happens in the store's subscription center; the
        // lifecycle notification (play-rtdn / appstore-notifications) writes
        // the result back to paddle_storage_subs.
        setError(null);
        try {
          await openNativeSubscriptionManagement(source, activeStorageSub.price_id);
        } catch (err) {
          console.error('Storage action error:', err);
          // Append the raw failure so an on-device report names the failing
          // layer - the bare localized line proved undiagnosable (2026-08-26:
          // release builds expose no console, and the generic text was all we
          // had). The detail is data, not copy, so it stays untranslated.
          const detail = err instanceof Error ? err.message : String(err);
          setError(`${t('errors.storageUpdateFailed')} (${detail})`);
        }
        return;
      }
      if (!target) return;
      setStorageActionBusy(true);
      setError(null);
      try {
        // The store sheet is the confirmation + payment UI; validation and the
        // DB write complete before startStorageUpgrade resolves, so refetch
        // immediately. A user-cancel fires neither callback and changes nothing.
        let succeeded = false;
        await startStorageUpgrade(
          authed.pubkey,
          target.gb,
          { subscription_id: activeStorageSub.subscription_id, source },
          () => { succeeded = true; },
          (reason) => setError(t(`billing:purchaseError.${reason}`)),
        );
        if (succeeded) {
          void fetchMyStorageSubs(supabase).then(setStorageSubs);
          void fetchQuotaUsage(supabase, true).then(setQuota);
        }
      } catch (err) {
        console.error('Storage action error:', err);
        setError(t('errors.storageUpdateFailed'));
      } finally {
        setStorageActionBusy(false);
      }
      return;
    }

    setStorageActionBusy(true);
    setError(null);
    try {
      const { data: sessData } = await supabase.auth.getSession();
      const session = sessData.session;
      if (!session?.access_token || !session.user?.id) {
        setError(t('errors.noSession'));
        return;
      }
      await manageStorageSub({
        supabase,
        accessToken: session.access_token,
        authUid: session.user.id,
        signingPrivateKey: authed.signingPrivateKey,
        subscriptionId: activeStorageSub.subscription_id,
        action,
        priceId: target?.priceId,
      });
      if (action === 'cancel') setCancelDone(true);
      // The Paddle webhook updates the row; refetch shortly after.
      setTimeout(() => {
        void fetchMyStorageSubs(supabase).then(setStorageSubs);
        void fetchQuotaUsage(supabase, true).then(setQuota);
      }, 1500);
    } catch (err) {
      console.error('Storage action error:', err);
      setError(t('errors.storageUpdateFailed'));
    } finally {
      setStorageActionBusy(false);
    }
  }

  async function handleRevoke(target: RevokeTarget) {
    if (!authed) return;
    setBusy(target.slot.key);
    setError(null);
    const { data: sessData } = await supabase.auth.getSession();
    const session = sessData.session;
    if (!session?.access_token || !session.user?.id) {
      setError(t('errors.noSession'));
      setBusy(null);
      return;
    }
    try {
      for (const row of target.rows) {
        await revokeDevice({
          supabase,
          accessToken: session.access_token,
          authUid: session.user.id,
          signingPrivateKey: authed.signingPrivateKey,
          targetDeviceId: row.device_id,
        });
      }

      // If we just revoked our own device, immediately re-register it.
      // The revoke + re-register is meant to clear ghost rows from the
      // server side without losing this device. Without a retry on the
      // re-register, a network blip leaves the user's device row stuck
      // in the revoked state - both their slots get burned for 72h
      // and they're locked out. registerDevice is idempotent on a
      // matching device_id (it un-revokes), so a retry is the recovery
      // path. See gap #27.
      if (target.rows.some((row) => row.device_id === authed.deviceId)) {
        const registerArgs = {
          supabase,
          accessToken: session.access_token,
          authUid: session.user.id,
          pubkey: authed.pubkey,
          signingPrivateKey: authed.signingPrivateKey,
          fpPepper: authed.fpPepper,
        };
        try {
          await registerDevice(registerArgs);
        } catch (registerErr) {
          console.warn('[devices] re-register failed, retrying:', registerErr);
          await new Promise((r) => setTimeout(r, 1000));
          try {
            await registerDevice(registerArgs);
          } catch (retryErr) {
            throw new Error(
              t('errors.reRegisterFailed', { message: (retryErr as Error).message }),
            );
          }
        }
      }

      const fresh = await listDevices(supabase);
      setDevices(fresh);
      setConfirm(null);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(null);
    }
  }

  const freeLimit = 2;
  const cooldownDevices = devices?.filter((d) => d.revoked_at) ?? [];
  // One card per server slot, so this list and the free-tier cap agree.
  const slots = groupDeviceSlots(devices ?? [], authed?.deviceId ?? null);

  return (
    <div
      className={embedded ? 'contents' : 'fixed inset-0 bg-black/50 dark:bg-black/70 flex items-center justify-center p-4 sm:p-6 z-50'}
      onClick={embedded ? undefined : onClose}
    >
      <div
        className={
          embedded
            ? 'flex-1 min-h-0 overflow-y-auto px-6 pb-6 pt-3 space-y-5 text-pn'
            : 'bg-surface-2 border border-divider text-pn rounded-lg max-w-md w-full p-6 space-y-5 max-h-[90vh] overflow-y-auto'
        }
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        {!embedded && (
        <div className="flex items-center gap-2.5">
          {/* An accent bar, not an icon beside the title: bar + icon + title
              read as double ornament. */}
          <AccentBar />
          <h2 className="text-lg font-semibold">
            {t('account.title')}
          </h2>
          <HeadlineRule />
          <button
            onClick={onClose}
            className="text-pn-muted hover:text-pn transition p-1 -m-1"
            aria-label={t('common:actions.close')}
          >
            <X size={18} />
          </button>
        </div>
        )}

        {/* Tab bar - hidden when embedded; the shell rail drives the tab. */}
        {!embedded && (
        <div className="flex border-b border-divider -mx-6 px-6">
          {(['plan', 'storage', 'sync', 'me'] as const).map((tabId) => (
            <button
              key={tabId}
              type="button"
              onClick={() => setTab(tabId)}
              className={`pb-2 px-3 text-sm capitalize transition border-b-2 ${
                tab === tabId
                  ? 'border-accent text-accent font-medium'
                  : 'border-transparent text-pn-soft hover:text-pn'
              }`}
            >
              {t(`tabs.${tabId}`)}
            </button>
          ))}
        </div>
        )}

        {/* ── Plan tab ── */}
        {tab === 'plan' && (
          <>
            {/* Plan badge */}
            {authed && isPro !== null && (
              isPro ? (
                <div className="flex items-center gap-4 rounded-md border border-divider bg-surface-1 p-4">
                  {/* Rocket medallion with hanging ribbon tails - the Pro mark, gilded for everyone. */}
                  <div className="shrink-0 w-9 text-center">
                    <div className="relative z-[2] mx-auto flex h-9 w-9 items-center justify-center rounded-full bg-amber-500/15">
                      <IconUpgrade size={20} />
                    </div>
                    <div className="relative -mt-1 h-[18px]">
                      <span
                        className="absolute start-1.5 top-0 h-[18px] w-2.5 bg-amber-500"
                        style={{ clipPath: 'polygon(0 0,100% 0,100% 100%,50% 70%,0 100%)', transform: 'skewX(-8deg)' }}
                      />
                      <span
                        className="absolute end-1.5 top-0 h-[18px] w-2.5 bg-amber-600"
                        style={{ clipPath: 'polygon(0 0,100% 0,100% 100%,50% 70%,0 100%)', transform: 'skewX(8deg)' }}
                      />
                    </div>
                  </div>
                  <div className="flex-1 text-xs leading-relaxed">
                    <div className="flex items-baseline gap-2">
                      <strong className="text-sm text-pn">Pro</strong>
                      <span className="text-pn-soft">{t('plan.proUnlimited')}</span>
                    </div>
                    <p className="mt-1 text-amber-700 dark:text-amber-400">
                      {isEarlySupporter
                        ? t('plan.earlySupporterThanks')
                        : t('plan.proThanks')}{' '}
                      💛
                    </p>
                  </div>
                </div>
              ) : (
                <div className="rounded-md border p-3 text-xs leading-relaxed border-divider bg-track text-pn-soft">
                  <Trans
                    i18nKey="settings:plan.freeLimit"
                    values={{ count: freeLimit }}
                    components={{ strong: <strong /> }}
                  />{' '}
                  {devices && (
                    <>
                      {t('plan.freeUsage', { used: slots.length, limit: freeLimit })}
                    </>
                  )}
                </div>
              )
            )}

            {/* Restore purchases - only where purchases live in a store
                account (iOS / Play build). Paddle platforms have nothing to
                restore: entitlement follows the pubkey server-side. */}
            {authed && isNativeStoreBuild() && (
              <div className="rounded-md border border-divider bg-surface-1 p-4">
                <SectionEyebrow className="mb-1">{t('plan.restore.heading')}</SectionEyebrow>
                <p className={`${SETTINGS_HELP} leading-relaxed`}>{t('plan.restore.body')}</p>
                <button
                  type="button"
                  disabled={restoreBusy}
                  onClick={() => void handleRestore()}
                  className="mt-3 rounded-md border border-divider bg-surface-2 hover:bg-track disabled:opacity-60 disabled:cursor-not-allowed px-3 py-1.5 text-xs font-medium text-pn transition"
                >
                  {restoreBusy ? t('plan.restore.ctaBusy') : t('plan.restore.cta')}
                </button>
                {restoreOutcome && (
                  <p
                    className={`mt-2 text-xs leading-relaxed ${
                      restoreOutcome === 'restored'
                        ? 'text-green-600 dark:text-green-400'
                        : restoreOutcome === 'none'
                          ? 'text-pn-muted'
                          : 'text-red-600 dark:text-red-400'
                    }`}
                  >
                    {t(`plan.restore.${restoreOutcome}`)}
                  </p>
                )}
              </div>
            )}

          </>
        )}

        {/* ── Storage tab ── */}
        {tab === 'storage' && (
          <>
            <HelpChip surface="storage" />
            {/* Storage quota + add-on packages */}
            {authed && quota && isPro !== null && (
              <div>
                <div className="space-y-6">
                  {isPro ? (
                    <>
                      <QuotaRing
                        compact
                        label={t('storage.quotaLabel')}
                        usedBytes={quota.totalBytes + quota.imageBytes}
                        maxBytes={quota.maxTotalBytes}
                      />
                      <p className={`${SETTINGS_HELP} -mt-3`}>
                        {t('common:storageBar.cleanupInfo')}
                      </p>
                      {(activeStorageSub || isStorageConfigured()) ? (
                          <div>
                            <SectionEyebrow className="mb-1">
                              {t('storage.addonHeading')}
                            </SectionEyebrow>
                            <SettingsCallout className="mb-4">
                              {t('storage.addonFileSizePerk')}
                            </SettingsCallout>
                            {storagePurchaseError && (
                              <div className="mb-3 rounded-md border border-red-300 bg-red-50 dark:border-red-900/60 dark:bg-red-950/30 text-red-700 dark:text-red-300 text-sm p-3">
                                {storagePurchaseError}
                              </div>
                            )}
                            {(() => {
                              /* Dual-layout package picker. The PANE's own width decides the
                                 form (container query `pn-storage`, index.css): tier CARDS in
                                 the wide desktop shell, growth ROWS in the max-w-md modal and
                                 on phones. Both variants render the same views/handlers; the
                                 inactive one is display:none. ops/docs/ui-patterns.md sec 48. */
                              const packages = getStoragePackages();
                              const largestGb = packages.reduce((m, p) => Math.max(m, p.gb), 0);
                              // Marketing math mirrors upgradeTotal: the Pro base is 0.5 GB.
                              const nowGb = 0.5 + (activeStorageSub?.gb_count ?? 0);
                              const fmtGb = (gb: number) =>
                                gb < 1 ? t('quota.mb', { value: Math.round(gb * 1000) }) : t('quota.gb', { value: gb });
                              /* Prices come from the store when there is one, and
                                 ONLY as the store's own formatted string - we
                                 never rebuild a currency amount ourselves. The
                                 store sells whole tiers, so there is no API
                                 string for the derived figures (per-GB rate,
                                 struck-through base rate, "save X/yr"), and
                                 formatting those with Intl would mean guessing
                                 symbol and placement for a charge Apple or Google
                                 is quoting differently two lines below. So on a
                                 store build those three are simply not rendered:
                                 the discount still reads, currency-free, off the
                                 "-25% / Best value" badge that is already there.
                                 The percentage is derived from the 1 GB tier's own
                                 store price, so it stays true in every currency. */
                              const storeFor = (gb: number): StorePrice | null =>
                                storePrices?.[storageProductId(gb)] ?? null;
                              const baseTier = storeFor(1);
                              const baseRate = baseTier ? baseTier.amount : STORAGE_ADDON_PRICE;
                              const views = packages.map((pkg) => {
                                const owned = !!activeStorageSub && activeStorageSub.gb_count === pkg.gb;
                                const isDowngrade = !!activeStorageSub && pkg.gb < activeStorageSub.gb_count;
                                const store = storeFor(pkg.gb);
                                const yearly = store ? store.amount : pkg.pricePerYear;
                                const perGb = yearly / pkg.gb;
                                return {
                                  pkg,
                                  owned,
                                  isDowngrade,
                                  isBest: pkg.gb === largestGb,
                                  perGb,
                                  /** True when the figures below came from the store, not pricing.ts. */
                                  fromStore: !!store,
                                  priceLabel: store ? store.formatted : `$${pkg.pricePerYear.toFixed(2)}`,
                                  discounted: perGb < baseRate - 0.001,
                                  saving: (baseRate - perGb) * pkg.gb,
                                  pct: Math.round((1 - perGb / baseRate) * 100),
                                  actionable: !owned && !isDowngrade && !storageBusy && !storageActionBusy,
                                };
                              });
                              type PkgView = (typeof views)[number];
                              const selectPkg = (v: PkgView) => {
                                if (!authed || !v.actionable) return;
                                if (activeStorageSub) {
                                  // Upgrades charge the card on file immediately (prorated).
                                  // Never fire on a single click - require explicit confirmation.
                                  setConfirmingUpgrade({ gb: v.pkg.gb, priceId: v.pkg.priceId, pricePerYear: v.pkg.pricePerYear, priceLabel: v.priceLabel });
                                  return;
                                }
                                setStorageBusy(true);
                                setStoragePurchaseError(null);
                                startStorageCheckout(
                                  authed.pubkey,
                                  v.pkg.gb,
                                  () => {
                                    void fetchQuotaUsage(supabase, true).then(setQuota);
                                  },
                                  // Native IAP failure: surface it inline, a silent
                                  // no-op reads as a dead button (Play internal test).
                                  (reason) => setStoragePurchaseError(t(`billing:purchaseError.${reason}`)),
                                )
                                  .catch((err) => console.error('Storage checkout error:', err))
                                  .finally(() => setStorageBusy(false));
                              };
                              // Cards center the floating badge on the top edge; rows keep the
                              // pre-redesign left anchor.
                              const badgePos = (compact: boolean) =>
                                compact ? 'left-1/2 -translate-x-1/2' : 'left-3';
                              const badgeFor = (v: PkgView, compact: boolean) =>
                                v.owned ? (
                                  <span className={`absolute -top-2 ${badgePos(compact)} text-[11px] px-2 py-px rounded bg-track text-accent whitespace-nowrap`}>
                                    {activeStorageSub?.status === 'past_due' ? t('storage.pastDue') : t('storage.active')}
                                  </span>
                                ) : v.isBest ? (
                                  <span className={`absolute -top-2 ${badgePos(compact)} text-[11px] px-2 py-px rounded bg-track text-green-600 dark:text-green-400 whitespace-nowrap`}>
                                    {/* Card cells are ~160px in a narrow pane; the localized
                                        best-value copy runs 3x that (fr), so cards get a
                                        numeric badge and rows keep the full string. */}
                                    {compact && v.pct > 0
                                      ? `-${v.pct}%`
                                      : v.pct > 0
                                        ? t('storage.bestValueOff', { pct: v.pct })
                                        : t('storage.bestValue')}
                                  </span>
                                ) : null;
                              const renewLineFor = (v: PkgView) =>
                                v.owned && activeStorageSub && (activeStorageSub.scheduled_cancel_at || activeStorageSub.current_period_ends_at) ? (
                                  <div className="mt-1.5 px-1 text-[11px] text-pn-muted">
                                    {activeStorageSub.scheduled_cancel_at
                                      ? t('storage.cancelsOn', { date: formatPlanDate(activeStorageSub.scheduled_cancel_at) })
                                      : t('storage.renewsOn', { date: formatPlanDate(activeStorageSub.current_period_ends_at as string) })}
                                  </div>
                                ) : null;
                              const ctaLabel = (v: PkgView) =>
                                v.owned
                                  ? t('storage.currentAddon')
                                  : !v.isDowngrade && activeStorageSub
                                    ? t('storage.upgradeTitle', { gb: v.pkg.gb })
                                    : t('storage.addGbCta', { gb: v.pkg.gb });
                              return (
                                <div className="pn-storage-picker pt-2">
                                  {/* Wide pane: three tier cards side by side. */}
                                  <div className="pn-storage-cards">
                                    {views.map((v) => (
                                      <div key={v.pkg.gb} className="flex flex-col">
                                        <HoverLabel label={t('storage.downgradeUnavailable')} disabled={!v.isDowngrade} position="above" multiline className="flex-1">
                                          <div
                                            className={`relative flex h-full flex-col rounded-lg border ${
                                              v.owned
                                                ? 'border-accent border-2'
                                                : v.isBest
                                                  ? 'border-green-600/70 dark:border-green-600/50 border-2 bg-green-50/60 dark:bg-green-950/20'
                                                  : 'border-divider'
                                            } p-3.5 ${v.isDowngrade ? 'opacity-40' : ''}`}
                                          >
                                            {badgeFor(v, true)}
                                            <div className="flex items-center justify-between gap-2">
                                              <span className="rounded-md bg-track px-2 py-0.5 text-xs font-medium text-pn whitespace-nowrap">
                                                +{t('storage.gbSize', { gb: v.pkg.gb })}
                                              </span>
                                              {!v.fromStore && v.saving > 0.005 && (
                                                <span className="text-[11px] text-green-600 dark:text-green-400 truncate">
                                                  {t('storage.savePerYear', { amount: v.saving.toFixed(2) })}
                                                </span>
                                              )}
                                            </div>
                                            <div className="mt-3 text-[22px] leading-none font-semibold tracking-tight text-pn">
                                              {v.priceLabel}
                                              <span className="text-xs font-normal text-pn-muted">{t('storage.perYear')}</span>
                                            </div>
                                            {!v.fromStore && (
                                              <div className="mt-1.5 text-[11px] text-pn-muted">
                                                {v.discounted && (
                                                  <span className="me-1 line-through text-pn-muted">
                                                    ${STORAGE_ADDON_PRICE.toFixed(2)}
                                                  </span>
                                                )}
                                                {t('storage.pricePerGb', { price: v.perGb.toFixed(2) })}
                                              </div>
                                            )}
                                            <div className="mt-3 flex flex-1 flex-col gap-1.5 border-t border-divider pt-2.5">
                                              <span className="flex items-start gap-1.5 text-xs leading-snug text-pn-soft">
                                                <Check size={12} className="mt-0.5 shrink-0 text-green-600 dark:text-green-400" />
                                                {t('storage.totalStorageFeat', { total: 0.5 + v.pkg.gb })}
                                              </span>
                                              <span className="flex items-start gap-1.5 text-xs leading-snug text-pn-soft">
                                                <Check size={12} className="mt-0.5 shrink-0 text-green-600 dark:text-green-400" />
                                                {t('storage.maxFileFeat', { mb: 100 })}
                                              </span>
                                            </div>
                                            <button
                                              type="button"
                                              disabled={!v.actionable}
                                              onClick={() => selectPkg(v)}
                                              className={`mt-3 w-full rounded-md py-1.5 text-xs transition disabled:opacity-50 ${
                                                v.owned || v.isDowngrade
                                                  ? 'border border-divider font-medium text-pn-muted cursor-default'
                                                  : v.isBest
                                                    ? 'bg-green-600 hover:bg-green-700 text-white font-semibold'
                                                    : 'border border-divider font-medium hover:bg-surface-1'
                                              }`}
                                            >
                                              {ctaLabel(v)}
                                            </button>
                                          </div>
                                        </HoverLabel>
                                        {renewLineFor(v)}
                                      </div>
                                    ))}
                                  </div>
                                  {/* Narrow pane: growth rows, current plan vs total after. */}
                                  <div className="pn-storage-rows">
                                    {views.map((v) => (
                                      <div key={v.pkg.gb} className="flex flex-col">
                                        <HoverLabel label={t('storage.downgradeUnavailable')} disabled={!v.isDowngrade} position="above" multiline>
                                          <button
                                            type="button"
                                            disabled={!v.actionable}
                                            onClick={() => selectPkg(v)}
                                            className={`relative w-full flex flex-col gap-2 rounded-md border ${
                                              v.owned
                                                ? 'border-accent border-2'
                                                : v.isBest
                                                  ? 'border-green-600/70 dark:border-green-600/50 border-2'
                                                  : 'border-divider'
                                            } px-3.5 py-3 text-start transition ${
                                              v.actionable
                                                ? 'hover:bg-surface-1 cursor-pointer'
                                                : 'cursor-default'
                                            } ${v.isDowngrade ? 'opacity-40' : ''}`}
                                          >
                                            {badgeFor(v, false)}
                                            <span className="flex items-baseline justify-between gap-2">
                                              <span className="text-[15px] font-medium text-pn whitespace-nowrap">
                                                +{t('storage.gbSize', { gb: v.pkg.gb })}
                                              </span>
                                              <span className="text-[15px] font-medium text-pn whitespace-nowrap">
                                                {v.priceLabel}
                                                <span className="text-[13px] font-normal text-pn-muted">{t('storage.perYear')}</span>
                                              </span>
                                            </span>
                                            <span className="flex h-2 overflow-hidden rounded-full bg-track" aria-hidden="true">
                                              <span
                                                className="bg-pn-muted"
                                                style={{ width: `${Math.min(100, (nowGb / (0.5 + v.pkg.gb)) * 100)}%` }}
                                              />
                                              <span className="ms-px flex-1 bg-accent" />
                                            </span>
                                            <span className="flex items-center justify-between gap-2 text-[11px]">
                                              <span className="text-pn-muted">
                                                {t('storage.growthNow', { size: fmtGb(nowGb) })}
                                              </span>
                                              <span className="text-pn-muted">
                                                {'→ '}
                                                <span className="font-medium">{t('storage.growthAfter', { size: fmtGb(0.5 + v.pkg.gb) })}</span>
                                              </span>
                                            </span>
                                            {!v.fromStore && v.discounted && (
                                              <span className="flex items-center justify-between gap-2 text-[11px]">
                                                <span className="text-pn-muted">
                                                  <span className="me-1 line-through text-pn-muted">
                                                    ${STORAGE_ADDON_PRICE.toFixed(2)}
                                                  </span>
                                                  {t('storage.pricePerGb', { price: v.perGb.toFixed(2) })}
                                                </span>
                                                <span className="text-green-600 dark:text-green-400 whitespace-nowrap">
                                                  {t('storage.savePerYear', { amount: v.saving.toFixed(2) })}
                                                </span>
                                              </span>
                                            )}
                                          </button>
                                        </HoverLabel>
                                        {renewLineFor(v)}
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              );
                            })()}
                            {confirmingUpgrade && (
                              <div
                                className="fixed inset-0 z-[60] flex items-center justify-center bg-black/40 p-4"
                                onClick={() => { if (!storageActionBusy) setConfirmingUpgrade(null); }}
                              >
                                <div
                                  className="relative w-[340px] max-w-full rounded-xl border border-divider bg-surface-2 p-6 text-center"
                                  onClick={(e) => e.stopPropagation()}
                                >
                                  <button
                                    type="button"
                                    aria-label={t('common:actions.close')}
                                    disabled={storageActionBusy}
                                    onClick={() => setConfirmingUpgrade(null)}
                                    className="absolute top-2.5 end-2.5 w-7 h-7 flex items-center justify-center rounded-md text-pn-muted hover:bg-surface-1 transition disabled:opacity-50"
                                  >
                                    <span aria-hidden="true" className="text-lg leading-none">&times;</span>
                                  </button>
                                  <div className="mx-auto mb-3 w-11 h-11 rounded-full bg-blue-100 dark:bg-blue-900/40 flex items-center justify-center text-blue-600 dark:text-blue-400">
                                    <IconUpgrade size={20} />
                                  </div>
                                  <div className="text-base font-medium text-pn">
                                    {t('storage.upgradeTitle', { gb: confirmingUpgrade.gb })}
                                  </div>
                                  <div className="text-sm text-pn-soft mt-0.5 mb-4">
                                    {t('storage.upgradeTotal', { total: 0.5 + confirmingUpgrade.gb })}
                                  </div>
                                  <div className="rounded-md bg-track px-3 py-2.5 text-sm text-start text-pn-soft leading-relaxed mb-4">
                                    {(() => {
                                      const amount = upgradeDue ?? (upgradePreviewLoading ? '…' : t('storage.proratedAmount'));
                                      const renewPrice = confirmingUpgrade.priceLabel;
                                      // Apple runs the opposite mechanic to the other two rails, so it
                                      // needs its own sentence. Paddle and Play both charge the
                                      // DIFFERENCE now and leave the renewal date alone (Play via
                                      // PLAY_CHARGE_PRORATED_PRICE), which is what the two strings
                                      // below describe. Apple charges the new price in FULL, refunds
                                      // the unused remainder of the old term itself, and restarts the
                                      // year today - so "charged X for the rest of your current year"
                                      // is wrong on iOS in all three of its claims, and there is no
                                      // "rest of your current year" left to bill for.
                                      if (activeStorageSub?.source === 'apple') {
                                        return t('storage.upgradeChargeApple', { price: renewPrice });
                                      }
                                      return activeStorageSub?.current_period_ends_at
                                        ? t('storage.upgradeChargeUntil', { amount, date: formatPlanDate(activeStorageSub.current_period_ends_at), price: renewPrice })
                                        : t('storage.upgradeCharge', { amount, price: renewPrice });
                                    })()}
                                  </div>
                                  <div className="flex flex-col gap-2">
                                    <button
                                      type="button"
                                      disabled={storageActionBusy}
                                      onClick={() => {
                                        const target = { priceId: confirmingUpgrade.priceId, gb: confirmingUpgrade.gb };
                                        setConfirmingUpgrade(null);
                                        void handleStorageAction('switch', target);
                                      }}
                                      className="w-full rounded-md bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium py-2 transition disabled:opacity-50"
                                    >
                                      {storageActionBusy ? t('storage.upgrading') : t('storage.upgradeAndPay')}
                                    </button>
                                    <button
                                      type="button"
                                      disabled={storageActionBusy}
                                      onClick={() => setConfirmingUpgrade(null)}
                                      className="w-full rounded-md border border-divider hover:bg-surface-1 text-sm py-2 transition disabled:opacity-50"
                                    >
                                      {t('storage.maybeLater')}
                                    </button>
                                  </div>
                                </div>
                              </div>
                            )}
                            {storageBusy && (
                              <div className="text-[11px] text-pn-muted mt-1.5">{t('storage.openingCheckout')}</div>
                            )}
                            {storageActionBusy && (
                              <div className="text-[11px] text-pn-muted mt-1.5">{t('storage.updatingPlan')}</div>
                            )}
                            {error && (
                              <div className="mt-2 rounded-md border border-red-300 bg-red-50 dark:border-red-900/60 dark:bg-red-950/30 text-red-700 dark:text-red-300 text-xs p-2.5">
                                {error}
                              </div>
                            )}
                            {activeStorageSub && !activeStorageSub.scheduled_cancel_at && (
                              cancelDone ? (
                                <div className="mt-3 text-xs text-green-600 dark:text-green-400">
                                  {t('storage.cancelScheduled')}
                                </div>
                              ) : confirmingCancel ? (
                                <div className="mt-3 rounded-md border border-red-300 dark:border-red-900/60 px-2.5 py-2">
                                  <div className="text-[11px] text-pn-soft mb-1.5 leading-relaxed">
                                    {t('storage.cancelConfirm')}
                                  </div>
                                  <div className="flex gap-2">
                                    <button
                                      type="button"
                                      disabled={storageActionBusy}
                                      onClick={() => {
                                        setConfirmingCancel(false);
                                        void handleStorageAction('cancel');
                                      }}
                                      className="text-xs rounded-md bg-red-600 hover:bg-red-700 text-white px-2.5 py-1 transition disabled:opacity-50"
                                    >
                                      {storageActionBusy ? t('storage.cancelling') : t('storage.yesCancel')}
                                    </button>
                                    <button
                                      type="button"
                                      disabled={storageActionBusy}
                                      onClick={() => setConfirmingCancel(false)}
                                      className="text-xs rounded-md border border-divider hover:bg-surface-1 px-2.5 py-1 transition disabled:opacity-50"
                                    >
                                      {t('storage.keepStorage')}
                                    </button>
                                  </div>
                                </div>
                              ) : (
                                <button
                                  type="button"
                                  disabled={storageActionBusy}
                                  onClick={() => setConfirmingCancel(true)}
                                  className="mt-3 text-xs text-red-600 dark:text-red-400 hover:underline disabled:opacity-50"
                                >
                                  {t('storage.cancelStorage')}
                                </button>
                              )
                            )}
                            {/* Subscription terms plus the two legal links, on the
                                surface where the subscription is actually bought.
                                App Store guideline 3.1.2 wants title, length, price
                                and both links visible at the point of purchase; the
                                picker above carries title, price and "/yr", so this
                                line completes it. Reuses the About modal's link
                                labels rather than duplicating the strings.
                                Spec: ops/docs/design-decisions.md (storage add-on packages) */}
                            <p className="mt-4 text-[11px] text-pn-muted leading-relaxed">
                              {t('storage.legalNote')}
                              {' '}
                              <a
                                href="https://lifetimelabs.dev/terms/"
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-accent hover:underline"
                              >
                                {t('landing:about.termsOfService')}
                              </a>
                              {' · '}
                              <a
                                href="https://lifetimelabs.dev/privacy/"
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-accent hover:underline"
                              >
                                {t('landing:about.privacyPolicy')}
                              </a>
                            </p>
                          </div>
                        ) : null}
                    </>
                  ) : (
                    <>
                      <QuotaRing
                        compact
                        label={t('storage.quotaLabel')}
                        usedBytes={quota.totalBytes + quota.imageBytes}
                        maxBytes={quota.maxTotalBytes}
                      />
                      <p className={`${SETTINGS_HELP} -mt-3`}>
                        {t('common:storageBar.cleanupInfo')}
                      </p>
                      <div className="rounded-xl border border-divider bg-surface-2 p-6 text-center">
                        <div className="mx-auto mb-3 w-11 h-11 rounded-full bg-amber-100 dark:bg-amber-900/40 flex items-center justify-center">
                          <IconUpgrade size={22} />
                        </div>
                        <div className="text-base font-medium text-pn">{t('storage.needMore')}</div>
                        <p className="text-sm text-pn-soft leading-relaxed text-balance max-w-md mx-auto mt-1 mb-4">
                          {t('storage.proSpacePitch')}
                        </p>
                        {isBetaPricing() ? (
                          <div className="mb-4">
                            <div className="flex items-baseline justify-center gap-2.5">
                              <span className="text-3xl font-bold tracking-tight text-amber-900 dark:text-amber-100">${EARLY_PRICE}</span>
                              <span className="text-lg font-semibold line-through text-amber-400 dark:text-amber-600">${PRO_PRICE}</span>
                            </div>
                            <div className="mt-2 flex justify-center">
                              <span className="text-[11px] font-semibold text-amber-900 dark:text-amber-100 bg-amber-200 dark:bg-amber-800/70 rounded-full px-2.5 py-0.5">
                                {t('storage.earlyAdopterSave', { amount: PRO_PRICE - EARLY_PRICE })}
                              </span>
                            </div>
                          </div>
                        ) : (
                          <div className="flex items-baseline justify-center gap-2 mb-4">
                            <span className="text-3xl font-bold tracking-tight text-amber-900 dark:text-amber-100">${PRO_PRICE}</span>
                            <span className="text-sm font-medium text-amber-700/70 dark:text-amber-300/70">{t('storage.oneTime')}</span>
                          </div>
                        )}
                        <button
                          type="button"
                          onClick={onOpenUpgrade}
                          disabled={!onOpenUpgrade}
                          className="inline-flex items-center justify-center gap-2 rounded-md bg-amber-600 hover:bg-amber-700 text-white text-sm font-semibold px-5 py-2.5 transition disabled:opacity-60 disabled:cursor-not-allowed"
                        >
                          <IconUpgrade size={16} />
                          {t('plan.upgradeToPro')}
                        </button>
                      </div>
                    </>
                  )}
                </div>
              </div>
            )}

          </>
        )}

        {/* ── Plan tab: devices ── */}
        {tab === 'plan' && (
          <>
            {/* Active devices */}
            <div>
              <SectionEyebrow className="mb-2">
                {t('devices.heading')}
              </SectionEyebrow>
              <HelpChip surface={isPro ? 'devicesPro' : 'devices'} className="mb-3" />
              {devices === null ? (
                <div className="text-sm text-pn-muted">{t('common:state.loading')}</div>
              ) : slots.length === 0 ? (
                <div className="text-sm text-pn-muted">
                  {t('devices.empty')}
                </div>
              ) : (
                <ul className="space-y-2">
                  {slots.map((slot) => (
                    slot.rows.length === 1 ? (
                      <li
                        key={slot.key}
                        className="flex items-center justify-between gap-3 rounded-md border border-divider px-3 py-2"
                      >
                        <DeviceRowLabel row={slot.rows[0]} isSelf={slot.isSelf} />
                        <button
                          type="button"
                          onClick={() => setConfirm({ slot, rows: slot.rows })}
                          disabled={busy !== null}
                          className={REMOVE_BUTTON}
                        >
                          {t('common:actions.remove')}
                        </button>
                      </li>
                    ) : (
                      /* Several rows share one slot: a reinstall, a second
                         browser, or a second machine the fingerprint merged.
                         Each row keeps its own Remove; the whole slot is the
                         explicit second action. */
                      <li key={slot.key} className="rounded-md border border-divider px-3 pt-2 pb-1.5">
                        <div className="text-[11px] text-pn-muted">
                          {t('devices.sharedSlot', { count: slot.rows.length })}
                        </div>
                        <ul className="divide-y divide-divider">
                          {slot.rows.map((row) => (
                            <li key={row.device_id} className="flex items-center justify-between gap-3 py-2">
                              <DeviceRowLabel row={row} isSelf={authed?.deviceId === row.device_id} />
                              <button
                                type="button"
                                onClick={() => setConfirm({ slot, rows: [row] })}
                                disabled={busy !== null}
                                className={REMOVE_BUTTON}
                              >
                                {t('common:actions.remove')}
                              </button>
                            </li>
                          ))}
                        </ul>
                        <div className="flex justify-end border-t border-divider pt-1.5">
                          <button
                            type="button"
                            onClick={() => setConfirm({ slot, rows: slot.rows })}
                            disabled={busy !== null}
                            className="text-xs text-pn-muted hover:text-pn transition disabled:opacity-50"
                          >
                            {t('devices.removeAll')}
                          </button>
                        </div>
                      </li>
                    )
                  ))}
                </ul>
              )}
            </div>

            {/* Recently removed devices - informational, do not occupy a slot. */}
            {cooldownDevices.length > 0 && !isPro && (
              <div>
                <SectionEyebrow className="mb-2">
                  {t('devices.recentlyRemoved')}
                </SectionEyebrow>
                <ul className="space-y-2">
                  {cooldownDevices.map((d) => (
                    <li
                      key={d.device_id}
                      className="flex items-center justify-between gap-3 rounded-md border border-divider/60 px-3 py-2 opacity-60"
                    >
                      <div className="min-w-0">
                        <div className="text-sm font-medium truncate text-pn-muted">
                          {d.device_name}
                          <span className="font-mono text-[11px] font-normal ms-2">{shortDeviceId(d.device_id)}</span>
                        </div>
                        <div className="text-[11px] text-pn-muted/75">
                          {t('devices.removedAt', { time: formatRelative(d.revoked_at!) })}
                        </div>
                      </div>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {error && (
              <div className="rounded-md border border-red-300 bg-red-50 dark:border-red-900/60 dark:bg-red-950/30 text-red-700 dark:text-red-300 text-sm p-3">
                {error}
              </div>
            )}

            {/* Upgrade CTA (free users only) */}
            {!isPro && authed && (
              <button
                type="button"
                onClick={onOpenUpgrade}
                disabled={!onOpenUpgrade}
                className="w-full inline-flex items-center justify-center gap-2 rounded-md bg-accent hover:bg-accent-hover text-white text-sm font-semibold px-3 py-2.5 transition disabled:opacity-60 disabled:cursor-not-allowed"
              >
                <IconUpgrade size={16} />
                {t('plan.upgradeToPro')}
              </button>
            )}

            {/* Sign out */}
            {authed && onSignOut && (
              <button
                type="button"
                onClick={() => {
                  onClose();
                  onSignOut();
                }}
                className="w-full inline-flex items-center justify-center gap-2 rounded-md border border-divider hover:bg-surface-1 text-sm font-medium px-3 py-2.5 transition text-pn-soft"
              >
                <SignOut size={16} className="text-accent" />
                {t('account.signOut')}
              </button>
            )}

            {/* Danger zone - lives with the account actions, right below
                sign out, deliberately not in the sync readout. */}
            {authed && <DangerZone onDeleteStarted={() => { /* page reloads after wipe */ }} />}

          </>
        )}

        {/* ── Sync tab ── */}
        {tab === 'sync' && <SyncPanel onSyncNow={onSyncNow} supabase={supabase} onOpenNote={onOpenNote} />}

        {/* ── Me tab (ID & Sync - the full sync readout) ── */}
        {tab === 'me' && (
          <>
            <HelpChip surface="me" />
            <SyncPanel pubkey={authed?.pubkey} onSyncNow={onSyncNow} supabase={supabase} autoVerify={autoVerify} onOpenNote={onOpenNote} />
          </>
        )}

        {!embedded && (
          <button
            onClick={onClose}
            className="w-full rounded-md border border-divider hover:bg-surface-1 px-3 py-2 text-sm transition"
          >
            {t('common:actions.close')}
          </button>
        )}
      </div>

      {confirm && authed && (
        <RevokeConfirm
          target={confirm}
          isPro={isPro}
          busy={busy}
          selfDeviceId={authed.deviceId}
          onCancel={() => setConfirm(null)}
          onConfirm={() => void handleRevoke(confirm)}
        />
      )}
    </div>
  );
}

const REMOVE_BUTTON =
  'text-xs rounded-md border border-red-300 text-red-700 hover:bg-red-50 dark:border-red-900/60 dark:text-red-300 dark:hover:bg-red-950/30 px-2.5 py-1.5 transition disabled:opacity-50';

/** Name line plus the meta that tells two identically named rows apart. */
function DeviceRowLabel({ row, isSelf }: { row: DeviceRow; isSelf: boolean }) {
  const { t } = useTranslation('settings');
  return (
    <div className="min-w-0">
      <div className="text-sm font-medium truncate flex items-center gap-2">
        {row.device_name}
        {isSelf && (
          <span className="text-[10px] uppercase tracking-wide text-accent">
            {t('devices.thisDevice')}
          </span>
        )}
      </div>
      <div className="text-[11px] text-pn-muted">
        {row.platform}
        {' · '}
        <span className="font-mono">{shortDeviceId(row.device_id)}</span>
        {` · ${t('devices.added', { time: formatRelative(row.created_at) })}`}
        {` · ${t('devices.lastActive', { time: formatRelative(row.last_seen_at) })}`}
      </div>
    </div>
  );
}

// ------------------------------------------------------------------
// Revoke-device confirmation sub-modal
// ------------------------------------------------------------------

function RevokeConfirm({
  target,
  isPro,
  busy,
  selfDeviceId,
  onCancel,
  onConfirm,
}: {
  target: RevokeTarget;
  isPro: boolean | null;
  busy: string | null;
  selfDeviceId: string | null;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const { t } = useTranslation('settings');
  useEscapeToClose(onCancel);

  const { slot, rows } = target;
  // A whole-slot removal frees the slot; a single row out of several does not.
  const wholeSlot = rows.length === slot.rows.length;
  const removesSelf = rows.some((row) => row.device_id === selfDeviceId);
  const row = rows[0];
  const othersLeft = slot.rows.length - rows.length;

  return (
    <div
      className="fixed inset-0 bg-black/50 dark:bg-black/70 flex items-center justify-center p-4 z-[60]"
      onClick={onCancel}
    >
      <div
        className="bg-surface-2 border border-divider rounded-lg max-w-sm w-full p-5 space-y-4"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="text-lg font-semibold">
          {wholeSlot ? t('revoke.title', { name: row.device_name }) : t('revoke.titleInstall')}
        </h2>
        {!wholeSlot && (
          <p className="text-sm text-pn-soft">
            {row.device_name}
            {' · '}
            <span className="font-mono">{shortDeviceId(row.device_id)}</span>
            {` · ${t('devices.added', { time: formatRelative(row.created_at) })} · ${t('devices.lastActive', { time: formatRelative(row.last_seen_at) })}`}
          </p>
        )}
        <p className="text-sm text-pn-muted leading-relaxed">
          {removesSelf
            ? `${t('revoke.bodySelf')}${rows.length > 1 ? ` ${t('revoke.bodyRemoveAll', { count: rows.length })}` : ''}`
            : wholeSlot
              ? `${t('revoke.bodyOther')}${rows.length > 1 ? ` ${t('revoke.bodyRemoveAll', { count: rows.length })}` : ''}`
              : `${t('revoke.bodyInstall')} ${t('revoke.bodyInstallOthers', { count: othersLeft })}`}
        </p>
        {!isPro && !removesSelf && (
          <p className="text-xs text-pn-muted leading-relaxed">
            {wholeSlot ? t('revoke.freeNote') : t('revoke.freeNoteKept')}
          </p>
        )}
        <div className="flex gap-2">
          <button
            type="button"
            onClick={onCancel}
            disabled={busy !== null}
            className="flex-1 rounded-md border border-divider hover:bg-surface-1 px-3 py-2 text-sm transition"
          >
            {t('common:actions.cancel')}
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={busy !== null}
            className="flex-1 rounded-md bg-red-600 hover:bg-red-700 text-white px-3 py-2 text-sm transition disabled:opacity-50"
          >
            {busy === slot.key ? t('revoke.removing') : t('common:actions.remove')}
          </button>
        </div>
      </div>
    </div>
  );
}
function formatPlanDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}


