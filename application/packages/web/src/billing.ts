/**
 * Platform-aware checkout dispatch.
 *
 * The Paddle.js overlay only works in a real browser. In the native (Tauri)
 * webview the app's CSP (`script-src 'self'`) blocks Paddle's CDN script, and
 * loosening it would let a third-party script run in the same context that
 * holds the user's decrypted notes - a threat-model regression we will not
 * make. So desktop hands checkout to the system browser; iOS and Android use
 * native in-app purchase (Apple/Google require it for digital goods).
 *
 * Every call site goes through the two dispatchers below, so wiring native IAP
 * later means filling in the stub functions and touching nothing else.
 *
 * Spec: ops/docs/design-decisions.md (native checkout: desktop opens the system
 * browser, iOS/Android use IAP)
 */

import { detectPlatform } from './devices';
import { isDemoMode } from './demo';

// The CheckoutLauncher page runs the Paddle overlay on an approved Paddle
// domain. Desktop sends users here in their system browser.
// Spec: ops/docs/design-decisions.md (native checkout)
const WEB_CHECKOUT_ORIGIN = 'https://privacynotes.app';

// Native store product IDs (App Store + Google Play, mirrored). Pro is a
// non-consumable one-time unlock; storage tiers are auto-renewable subs.
// Spec: ops/docs/mobile-release-plan.md (locked product IDs)
export const PRO_PRODUCT_ID = 'app.privacynotes.pro';
export const storageProductId = (gb: number): string => `app.privacynotes.storage.${gb}gb`;

// Deterministic UUID derived from the pubkey for StoreKit's appAccountToken.
// It binds the purchase to the account so a transaction can't be replayed for a
// different pubkey; appstore-validate recomputes and verifies it. Android binds
// via obfuscatedAccountId instead.
function pubkeyToAppAccountToken(pubkey: string): string {
  const h = (pubkey.slice(0, 32) + '0'.repeat(32)).slice(0, 32);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

async function openWebCheckout(query: string): Promise<void> {
  const { openUrl } = await import('@tauri-apps/plugin-opener');
  await openUrl(`${WEB_CHECKOUT_ORIGIN}/checkout?${query}`);
}

/**
 * Browser checkout: open the same /checkout page in a new tab rather than
 * loading Paddle's script into this document.
 *
 * The point is the ORIGIN. The app runs on use.privacynotes.app; the checkout
 * page is on privacynotes.app, and a different origin cannot read this one's
 * localStorage, where the recovery phrase and the wrapped-phrase blobs live.
 * Loading paddle.js into this document instead would put a third-party script
 * (and, through it, Paddle's own ProfitWell analytics) in the same document as
 * the phrase and the in-memory keys - the same threat-model regression the
 * header comment on this file refuses on desktop.
 *
 * Must stay synchronous inside the click handler or a popup blocker eats the
 * tab. Both callers are click-driven, and `noopener` keeps the new tab from
 * reaching back through window.opener.
 * Spec: ops/docs/plans/paddle-origin-split.md (checkout on a separate origin, can't read app's localStorage)
 */
function openBrowserCheckout(query: string): void {
  window.open(`${WEB_CHECKOUT_ORIGIN}/checkout?${query}`, '_blank', 'noopener,noreferrer');
}

// Desktop checkout completes in the browser, not the app, so Paddle's success
// callback never reaches us. Re-run the caller's refresh when the user returns
// to the app. Gate on a prior blur/hide so opening the browser (which blurs the
// window) doesn't fire it before the user has actually left and come back.
//
// Two event pairs cover the platforms: window blur/focus works in the desktop
// webviews, but the Android WebView does not fire them reliably on
// background/resume - it fires document visibilitychange instead (same reason
// AndroidUpdateToast listens to it). Wire both; whichever fires first wins.
// Burned in #219: the direct-APK checkout return was invisible to the app, so
// Pro never refreshed until a sign-out.
//
// Singleton: only one pending return is tracked. Starting checkout again
// replaces the previous listener, so clicking Upgrade several times can't stack
// up multiple re-checks that all fire on the next return.
let cancelPendingReturn: (() => void) | null = null;

function refreshOnReturn(onComplete: () => void): void {
  cancelPendingReturn?.();
  let left = false;
  const onLeave = () => {
    left = true;
  };
  const cleanup = () => {
    window.removeEventListener('focus', onReturn);
    window.removeEventListener('blur', onLeave);
    document.removeEventListener('visibilitychange', onVisibility);
    cancelPendingReturn = null;
  };
  const onReturn = () => {
    if (!left) return;
    cleanup();
    onComplete();
  };
  const onVisibility = () => {
    if (document.hidden) onLeave();
    else onReturn();
  };
  cancelPendingReturn = cleanup;
  window.addEventListener('blur', onLeave);
  window.addEventListener('focus', onReturn);
  document.addEventListener('visibilitychange', onVisibility);
}

/**
 * How a native store purchase failed. `store` = the checkout never completed
 * (store error, product unavailable, plugin failure) and the user was NOT
 * charged. `validate` = the store charged the user but our server could not
 * confirm the purchase - the entitlement did not flip, and because the purchase
 * stays unacknowledged the store auto-refunds it within 3 days.
 * `alreadyOwned` = the store refused to sell because the account already owns
 * the item AND the automatic restore that follows could not apply it to this
 * account - the usual cause is a purchase bound to a different recovery phrase.
 */
export type NativePurchaseError = 'store' | 'validate' | 'alreadyOwned';

/**
 * Start the Pro one-time purchase on the current platform.
 *
 * @param pubkey - the user's hex pubkey (attaches the purchase to the account)
 * @param onComplete - called on a real purchase completion (the web overlay's
 *   `checkout.completed` event)
 * @param onReturn - desktop only: called when the user returns from the browser
 *   checkout. We cannot tell a completed payment from a cancelled one here, so
 *   this must re-check Pro SILENTLY (flip if the server confirms, no "payment
 *   received" banner). Falls back to onComplete when omitted.
 * @param onError - native (iOS/Android IAP) only: called when the purchase
 *   fails for a reason other than the user cancelling. Without this the tap
 *   fails silently and the buy button looks dead (burned in Play internal
 *   testing).
 */
export async function startProCheckout(
  pubkey: string,
  onComplete: () => void,
  onReturn?: () => void,
  onError?: (reason: NativePurchaseError) => void,
): Promise<void> {
  switch (detectPlatform()) {
    case 'web':
      // Same shape as desktop below: the purchase completes on another origin,
      // so Paddle's success callback never reaches us and the refresh runs when
      // the user comes back to this tab.
      refreshOnReturn(onReturn ?? onComplete);
      return openBrowserCheckout(`product=pro&pubkey=${encodeURIComponent(pubkey)}`);
    case 'desktop':
      refreshOnReturn(onReturn ?? onComplete);
      return openWebCheckout(`product=pro&pubkey=${encodeURIComponent(pubkey)}`);
    case 'ios':
      return startAppleProPurchase(pubkey, onComplete, onError);
    case 'android':
      // The sideloaded direct APK is a free client (Pro bought on the web, like
      // desktop); only the Play build uses Play Billing.
      if (import.meta.env.VITE_ANDROID_DIST === 'direct') {
        refreshOnReturn(onReturn ?? onComplete);
        return openWebCheckout(`product=pro&pubkey=${encodeURIComponent(pubkey)}`);
      }
      return startGooglePlayProPurchase(pubkey, onComplete, onError);
  }
}

/**
 * Start a storage add-on purchase on the current platform.
 *
 * @param pubkey - the user's hex pubkey
 * @param gb - the package size (1/2/5). We pass GB, not a price ID, so the web
 *   checkout page resolves it to its OWN live price ID - a sandbox-built
 *   desktop app then can't hand a sandbox price ID to live Paddle.
 * @param onSuccess - refresh callback (see startProCheckout)
 * @param onError - native IAP failure callback (see startProCheckout)
 */
export async function startStorageCheckout(
  pubkey: string,
  gb: number,
  onSuccess: () => void,
  onError?: (reason: NativePurchaseError) => void,
): Promise<void> {
  switch (detectPlatform()) {
    case 'web':
      refreshOnReturn(onSuccess);
      return openBrowserCheckout(
        `product=storage&gb=${gb}&pubkey=${encodeURIComponent(pubkey)}`,
      );
    case 'desktop':
      refreshOnReturn(onSuccess);
      return openWebCheckout(
        `product=storage&gb=${gb}&pubkey=${encodeURIComponent(pubkey)}`,
      );
    case 'ios':
      return startAppleStoragePurchase(pubkey, gb, onSuccess, onError);
    case 'android':
      // Direct APK = free client, web checkout like desktop; Play build = Play Billing.
      if (import.meta.env.VITE_ANDROID_DIST === 'direct') {
        refreshOnReturn(onSuccess);
        return openWebCheckout(`product=storage&gb=${gb}&pubkey=${encodeURIComponent(pubkey)}`);
      }
      return startGooglePlayStoragePurchase(pubkey, gb, onSuccess, onError);
  }
}

/* ──────────────────────────────────────────────────────────────────
 * Native in-app purchase (iOS / macOS App Store / Android)
 *
 * StoreKit (iOS + macOS) and Google Play Billing (Android) via the single
 * `@choochmeque/tauri-plugin-iap-api`. Apple and Google require their own
 * billing for digital goods, so these cannot route to Paddle. Flow: buy
 * through the plugin, hand the purchase token to a server validator that flips
 * the SAME `pro_pubkeys` / storage entitlement the Paddle webhook does, then
 * refresh. The macOS App Store build reuses the `Apple*` functions (MAS routes
 * `desktop + isMasBuild()` to them).
 *
 * Spec: ops/docs/billing-integration.md (validator flips the same entitlement the Paddle webhook sets)
 * ────────────────────────────────────────────────────────────────── */

type NativeValidateFn = 'playstore-validate' | 'appstore-validate';

// Validate a native purchase server-side. The edge function verifies the token
// with Apple/Google and flips the account entitlement. Uses the raw-fetch edge
// pattern (apikey header) because billing.ts has no Supabase client in scope.
// Returns true only on confirm.
/**
 * Delays before re-attempting a validation that failed for a reason that
 * could succeed on a second try. Deliberately more patient than the
 * edge-function ladder in devices.ts: by the time this runs the store has
 * ALREADY taken the money, so the cost of giving up early is a charged
 * user with no entitlement, while the cost of waiting is a few more
 * seconds of spinner. Roughly 9s worst case.
 */
const VALIDATE_RETRY_DELAYS_MS = [500, 1200, 2500, 5000];

/**
 * Outcome of a server-side validation. `mismatch` is its own case: the
 * store sold a purchase that belongs to a DIFFERENT PrivacyNotes account,
 * which is not an error the user can retry their way out of - they need
 * the recovery phrase they owned it with. Everything else is 'failed'.
 */
type ValidateOutcome = 'ok' | 'mismatch' | 'failed';

async function validateNativePurchase(
  fn: NativeValidateFn,
  pubkey: string,
  productId: string,
  purchaseToken: string,
): Promise<ValidateOutcome> {
  // Retrying is safe: the validators are idempotent by construction, so
  // re-presenting a token the server already accepted is a no-op that
  // returns the same success (the restore path in this file relies on the
  // same property). Burned 2026-08-26 on a phone whose NAT had killed the
  // idle connection pool: the raw fetch threw, validation failed, and a
  // completed purchase surfaced as "payment went through but activating
  // it failed" - the single worst place in the app to give up on one dead
  // socket. Spec: ops/docs/billing-integration.md (retries are safe: validators are idempotent by design)
  for (let attempt = 0; ; attempt++) {
    try {
      const res = await fetch(`${import.meta.env.VITE_SUPABASE_URL}/functions/v1/${fn}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          apikey: import.meta.env.VITE_SUPABASE_ANON_KEY,
        },
        body: JSON.stringify({ pubkey, productId, purchaseToken }),
      });
      if (res.ok) return 'ok';
      // 4xx is a real refusal and will read the same on every attempt -
      // stop. 5xx is the server having a moment, which is what a retry is
      // for.
      if (res.status < 500 || attempt >= VALIDATE_RETRY_DELAYS_MS.length) {
        console.error(`[billing] ${fn} returned ${res.status}`);
        // One refusal is worth telling apart: the purchase is real but
        // bound to another account. The server names it so the user gets
        // "sign in with the phrase you bought it with" instead of a
        // generic activation failure that retries forever.
        let code: string | undefined;
        try { code = (await res.json())?.error; } catch { /* no body */ }
        return code === 'account_mismatch' ? 'mismatch' : 'failed';
      }
    } catch (err) {
      // Transport failure: the request never reached the function, so
      // nothing was decided and another attempt is free of side effects.
      if (attempt >= VALIDATE_RETRY_DELAYS_MS.length) {
        console.error(`[billing] ${fn} request failed`, err);
        return 'failed';
      }
    }
    await new Promise((resolve) => setTimeout(resolve, VALIDATE_RETRY_DELAYS_MS[attempt]));
  }
}

// The user closing the store sheet is a normal outcome, not an error. Detect
// it from the plugin/store error text (Play returns USER_CANCELED, StoreKit
// throws with "cancelled") so onError never fires for a deliberate cancel.
function isUserCancel(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err ?? '');
  return /cancel/i.test(msg);
}

// Play refuses to sell an item the store account already owns
// (ITEM_ALREADY_OWNED / "You already own this item"). That buyer is exactly
// the stuck user restore exists for: the store says owned, our server never
// validated it. Spec: ops/docs/plans/iap-restore-handoff.md (restore recovers purchases the store shows owned but we never validated)
function isAlreadyOwned(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err ?? '');
  return /already[ _]?own/i.test(msg);
}

// Buy a product through the native store, validate it, then refresh on success.
// Android-only steps (subscription offer token, obfuscated account id, the
// 3-day acknowledge) are gated on platform; acknowledgePurchase is a no-op on
// iOS/macOS so calling it unconditionally is safe.
//
// Every failure path MUST report through onError: a swallowed error leaves the
// buy button looking dead, which is indistinguishable from a broken app
// (burned in Play internal testing when no IAP products existed yet).
async function runNativePurchase(
  validateFn: NativeValidateFn,
  productId: string,
  productType: 'inapp' | 'subs',
  pubkey: string,
  onSuccess: () => void,
  onError?: (reason: NativePurchaseError) => void,
  // Android subscription replacement (upgrade): merged into the purchase
  // options so Play swaps the old sub instead of selling a parallel one.
  androidReplaceOptions?: { oldPurchaseToken: string; subscriptionReplacementMode: number },
): Promise<void> {
  const isAndroid = detectPlatform() === 'android';
  try {
    const iap = await import('@choochmeque/tauri-plugin-iap-api');

    const options: Record<string, unknown> = {};
    if (isAndroid) {
      // Ties the purchase to the account for Google's fraud checks. The pubkey
      // is public and 64 hex chars, within the 64-char obfuscatedAccountId cap.
      options.obfuscatedAccountId = pubkey;
      // Android subscriptions require an offer token from the product.
      if (productType === 'subs') {
        const { products } = await iap.getProducts([productId], 'subs');
        const offerToken = products?.[0]?.subscriptionOfferDetails?.[0]?.offerToken;
        if (offerToken) options.offerToken = offerToken;
      }
      if (androidReplaceOptions) {
        options.oldPurchaseToken = androidReplaceOptions.oldPurchaseToken;
        options.subscriptionReplacementMode = androidReplaceOptions.subscriptionReplacementMode;
      }
    } else {
      // iOS / macOS: bind the purchase to the account (replay protection). The
      // server verifies this against the transaction's appAccountToken.
      options.appAccountToken = pubkeyToAppAccountToken(pubkey);
    }

    const result = await iap.purchase(productId, productType, options);
    // Server validation token: Google's opaque purchaseToken on Android; on
    // iOS/macOS the signed JWS (appstore-validate decodes bundleId,
    // transactionId, and environment from it - the numeric purchaseToken is
    // rejected as invalid_purchase). Spec: ops/docs/billing-integration.md (iOS validation needs the JWS, not the numeric purchaseToken)
    const validationToken = isAndroid ? result?.purchaseToken : result?.jwsRepresentation;
    if (!result?.purchaseToken || !validationToken) {
      // A resolved purchase without a token is a store/plugin failure, not a
      // user cancel: cancels reject and are filtered by isUserCancel below.
      onError?.('store');
      return;
    }

    const outcome = await validateNativePurchase(validateFn, pubkey, productId, validationToken);
    if (outcome !== 'ok') {
      // The user paid but the entitlement did not flip. Unacknowledged
      // purchases auto-refund within 3 days, but the user must be told NOW.
      // A cross-account purchase gets the accurate message instead: it is
      // not a failure to retry, it needs the phrase that bought it.
      onError?.(outcome === 'mismatch' ? 'alreadyOwned' : 'validate');
      return;
    }

    // Android: acknowledge within 3 days or Google auto-refunds. No-op iOS/macOS.
    await iap.acknowledgePurchase(result.purchaseToken);

    onSuccess();
  } catch (err) {
    // "You already own this item" is a dead end only until the purchase is
    // re-validated: restore what the store holds and treat success as a
    // completed purchase. Only when that also fails does the user see an
    // error, and it names the real cause instead of a generic failure.
    if (isAlreadyOwned(err)) {
      const outcome = await restoreNativePurchases(pubkey);
      if (outcome === 'restored') {
        onSuccess();
        return;
      }
      // 'notApplied' = the validator refused what the store holds, which
      // after an already-owned refusal means the purchase is bound to a
      // different account. Anything else is a plain store/plugin failure.
      onError?.(outcome === 'notApplied' ? 'alreadyOwned' : 'store');
      return;
    }
    console.error('[billing] native purchase failed', err);
    if (!isUserCancel(err)) onError?.('store');
  }
}

async function startAppleProPurchase(
  pubkey: string,
  onSuccess: () => void,
  onError?: (reason: NativePurchaseError) => void,
): Promise<void> {
  return runNativePurchase('appstore-validate', PRO_PRODUCT_ID, 'inapp', pubkey, onSuccess, onError);
}

async function startGooglePlayProPurchase(
  pubkey: string,
  onSuccess: () => void,
  onError?: (reason: NativePurchaseError) => void,
): Promise<void> {
  return runNativePurchase('playstore-validate', PRO_PRODUCT_ID, 'inapp', pubkey, onSuccess, onError);
}

async function startAppleStoragePurchase(
  pubkey: string,
  gb: number,
  onSuccess: () => void,
  onError?: (reason: NativePurchaseError) => void,
): Promise<void> {
  return runNativePurchase('appstore-validate', storageProductId(gb), 'subs', pubkey, onSuccess, onError);
}

/**
 * True on builds whose purchases live in a native store account (iOS App
 * Store, Google Play build). Desktop and the direct Android APK buy through
 * Paddle, where the entitlement follows the pubkey server-side - there is
 * nothing device-local to restore, so restore UI must not appear there.
 * Spec: ops/docs/plans/iap-restore-handoff.md (restore UI only appears on iOS or Play builds, not Paddle purchases)
 */
export function isNativeStoreBuild(): boolean {
  const platform = detectPlatform();
  if (platform === 'ios') return true;
  return platform === 'android' && import.meta.env.VITE_ANDROID_DIST !== 'direct';
}

/**
 * Outcome of a restore pass.
 * `restored` - at least one store purchase validated; entitlements are back
 *   server-side (caller still refreshes Pro/subs state).
 * `none` - the store account owns nothing.
 * `notApplied` - the store returned purchases but none validated. The
 *   expected cause is account binding: the purchase is bound to a different
 *   pubkey and the validator refuses it by design, so the fix is signing in
 *   with the recovery phrase that bought it, not retrying.
 * `error` - the store/plugin call itself failed.
 */
export type RestoreOutcome = 'restored' | 'none' | 'notApplied' | 'error';

/**
 * Re-validate every purchase the store account holds, rebuilding the
 * store-account-to-pubkey bridge that is otherwise only built at purchase
 * time. Both validators are idempotent (an already-recorded purchase is an
 * `ok` no-op), so this is safe to call repeatedly - it runs from the manual
 * Settings button, the background Pro recheck, and the already-owned
 * purchase failure. Never throws.
 */
export async function restoreNativePurchases(pubkey: string): Promise<RestoreOutcome> {
  // Demo promises zero server calls; web/desktop/direct-APK have no store
  // account to restore from.
  if (isDemoMode() || !isNativeStoreBuild()) return 'none';
  const isAndroid = detectPlatform() === 'android';
  const validateFn: NativeValidateFn = isAndroid ? 'playstore-validate' : 'appstore-validate';
  try {
    const iap = await import('@choochmeque/tauri-plugin-iap-api');
    // Pro is a non-consumable ('inapp'); storage tiers are subscriptions.
    // Both must run or a reinstall restores Pro and silently loses paid
    // capacity.
    const [inapp, subs] = await Promise.all([
      iap.restorePurchases('inapp'),
      iap.restorePurchases('subs'),
    ]);
    const purchases = [...(inapp?.purchases ?? []), ...(subs?.purchases ?? [])].filter(
      (p) => p.purchaseState === iap.PurchaseState.PURCHASED,
    );
    if (purchases.length === 0) return 'none';

    let restored = 0;
    for (const p of purchases) {
      // Same token rule as the purchase path: Google's opaque purchaseToken
      // on Android, the signed JWS on iOS/macOS (appstore-validate rejects
      // the numeric purchaseToken as invalid_purchase).
      const token = isAndroid ? p.purchaseToken : p.jwsRepresentation;
      if (!token) continue;
      if ((await validateNativePurchase(validateFn, pubkey, p.productId, token)) !== 'ok') continue;
      restored++;
      // Android: a restored-but-unacknowledged purchase still auto-refunds
      // after 3 days. Best-effort - already-acknowledged is the common case.
      if (isAndroid && !p.isAcknowledged) {
        await iap
          .acknowledgePurchase(p.purchaseToken)
          .catch((err) => console.error('[billing] restore acknowledge failed', err));
      }
    }
    return restored > 0 ? 'restored' : 'notApplied';
  } catch (err) {
    console.error('[billing] restore purchases failed', err);
    return 'error';
  }
}

async function startGooglePlayStoragePurchase(
  pubkey: string,
  gb: number,
  onSuccess: () => void,
  onError?: (reason: NativePurchaseError) => void,
): Promise<void> {
  return runNativePurchase('playstore-validate', storageProductId(gb), 'subs', pubkey, onSuccess, onError);
}

/* ──────────────────────────────────────────────────────────────────
 * Native storage subscription management (upgrade / cancel)
 *
 * Paddle subs are managed server-side via manage-storage-sub; these two
 * cover subs bought through the native stores, where Apple/Google own the
 * billing relationship. Routing key is the sub row's `source` column, not
 * the current platform.
 * ────────────────────────────────────────────────────────────────── */

// Google Play ReplacementMode.CHARGE_PRORATED_PRICE: the switch is immediate,
// the user pays the prorated price difference today, and the renewal date is
// unchanged - the same story our Paddle upgrade dialog tells. Upgrade-only
// (Play requires the new price to be higher; the UI already blocks downgrades).
const PLAY_CHARGE_PRORATED_PRICE = 2;

/**
 * Upgrade a native-store storage subscription to a bigger package.
 *
 * Play ('play'): launches the billing flow for the new product with
 * subscription replacement (old token + CHARGE_PRORATED_PRICE). Google shows
 * the exact prorated charge in its own sheet - there is no preview API, which
 * is why the upgrade dialog shows no figure for native subs. Validation runs
 * through playstore-validate, which also retires the replaced sub's row via
 * linkedPurchaseToken.
 *
 * Apple ('apple'): the three storage products live in one subscription group,
 * so buying the target product IS the upgrade - StoreKit crossgrades and keeps
 * originalTransactionId, so appstore-validate updates the same row in place.
 */
export async function startStorageUpgrade(
  pubkey: string,
  gb: number,
  sub: { subscription_id: string; source: string },
  onSuccess: () => void,
  onError?: (reason: NativePurchaseError) => void,
): Promise<void> {
  if (sub.source === 'apple') {
    return runNativePurchase('appstore-validate', storageProductId(gb), 'subs', pubkey, onSuccess, onError);
  }
  return runNativePurchase(
    'playstore-validate',
    storageProductId(gb),
    'subs',
    pubkey,
    onSuccess,
    onError,
    { oldPurchaseToken: sub.subscription_id, subscriptionReplacementMode: PLAY_CHARGE_PRORATED_PRICE },
  );
}

/**
 * Open the store's own subscription management page for a native-store sub.
 * Cancelling happens there (we cannot cancel Apple/Google subs server-side);
 * the lifecycle notification (play-rtdn / appstore-notifications) records the
 * result in paddle_storage_subs.
 */
export async function openNativeSubscriptionManagement(
  source: string,
  productId: string,
): Promise<void> {
  const { openUrl } = await import('@tauri-apps/plugin-opener');
  if (source === 'apple') {
    // itms-apps opens the App Store app's subscription page directly, no
    // Safari hop. The scheme needs its own opener scope entry - it is not
    // in the plugin's default http/https allowlist - which lives in
    // capabilities/ios.json. The https form stays as the fallback so a
    // refusal of the scheme (or a future scope regression) still lands the
    // user somewhere they can cancel, instead of a dead button. Reported
    // broken on-device 2026-08-26 with the generic storage error; the
    // caller now surfaces the underlying message so the next report names
    // the failing layer.
    try {
      await openUrl('itms-apps://apps.apple.com/account/subscriptions');
    } catch {
      await openUrl('https://apps.apple.com/account/subscriptions');
    }
    return;
  }
  await openUrl(
    `https://play.google.com/store/account/subscriptions?sku=${encodeURIComponent(productId)}&package=app.privacynotes`,
  );
}
