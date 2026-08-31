import {
  useEffect,
  useRef,
  type Dispatch,
  type SetStateAction,
} from 'react';
import { type SupabaseClient } from '@notes/shared';
import { isNativeStoreBuild, restoreNativePurchases } from './billing';
import { isDemoMode } from './demo';
import { PRO_PRICE_CENTS } from './pricing';
import { writeCachedAccountFlags } from './authStorage';
import type { AuthState } from './auth';

// Throttle for the background Pro recheck (effect in AuthProvider): at most
// one is_pro RPC per minute, fired on boot and when the app regains
// focus/visibility while the account still reads free. Mirrors the
// heartbeat's 60 s cadence; the RPC is a single indexed lookup.
// Spec: ops/docs/billing-integration.md (Pro propagation: one RPC per minute)
const PRO_RECHECK_THROTTLE_MS = 60 * 1000;
let lastProRecheckAt = 0;

/**
 * Check if the current user bought Pro at the early-supporter price
 * by reading their pro_pubkeys row (RLS allows owner SELECT).
 * Spec: ops/docs/design-decisions.md (early supporter threshold: amount_cents < PRO_PRICE_CENTS)
 */
export async function checkEarlySupporter(sb: SupabaseClient): Promise<boolean> {
  try {
    const { data } = await sb.from('pro_pubkeys').select('amount_cents').maybeSingle();
    return !!data && typeof data.amount_cents === 'number' && data.amount_cents < PRO_PRICE_CENTS;
  } catch {
    return false;
  }
}

export function useProStatus({
  supabase,
  auth,
  setAuth,
  retryRegistrationFromLimit,
}: {
  supabase: SupabaseClient;
  auth: AuthState;
  setAuth: Dispatch<SetStateAction<AuthState>>;
  retryRegistrationFromLimit: () => Promise<
    { ok: true } | { ok: false; error: string }
  >;
}) {
  /**
   * Re-check pro status by querying pro_pubkeys via the is_pro() RPC.
   * Called after a successful Paddle checkout so the UI flips to Pro
   * without requiring a page reload or re-login, and by the background
   * recheck effect below whenever a stale free-tier device may have
   * been upgraded elsewhere.
   *
   * Also works from `device_limit_reached` (the upgrade CTA in
   * DeviceLimitModal): a confirmed purchase lifts the device cap, so
   * the interrupted registration is retried to complete the sign-in.
   * That state has to pass the guard below, or the early return
   * leaves a paying user stuck behind the modal.
   */
  async function refreshProStatus(opts?: { silent?: boolean; attempts?: number }) {
    const limitBlocked = auth.status === 'device_limit_reached';
    if (auth.status !== 'authenticated' && !limitBlocked) return;
    if (auth.status === 'authenticated' && auth.isPro) return;
    // Poll a few times - the Paddle webhook needs a moment to land
    // and upsert into pro_pubkeys before is_pro() returns true. The
    // background recheck passes attempts: 1 (no purchase just happened,
    // so there is no webhook latency to wait out).
    const attempts = opts?.attempts ?? 6;
    for (let attempt = 0; attempt < attempts; attempt++) {
      if (attempt > 0) await new Promise((r) => setTimeout(r, 3000));
      try {
        const { data, error } = await supabase.rpc('is_pro');
        if (error) {
          console.error('[auth] refreshProStatus RPC failed:', error);
          return;
        }
        if (!!data) {
          if (limitBlocked) {
            // Pro lifts the device cap - finish the interrupted sign-in.
            // On success auth flips to 'authenticated' with fresh flags
            // and the device-limit modal unmounts. On a transient
            // failure (network blip on resume, edge 5xx) fall through
            // to the next poll attempt: is_pro returns true again and
            // the retry re-runs, instead of dying silently.
            const retried = await retryRegistrationFromLimit();
            if (retried.ok) return;
            console.error(
              '[auth] post-purchase registration retry failed:',
              retried.error,
            );
            continue;
          }
          const early = await checkEarlySupporter(supabase);
          // Persist to the fast-boot cache too. Without this, a restart within
          // the 24 h register throttle reads the stale pre-purchase flags and
          // "loses" Pro until the next full registration (burned in Play
          // internal testing). Harmless if the session changed during the
          // awaits above: the cache is pubkey-checked on read and rewritten
          // by the next full registration.
          writeCachedAccountFlags({
            pubkey: auth.pubkey,
            isPro: true,
            isEarlySupporter: early,
            // Carry custody through; omitting it here would silently
            // wipe the flag on every Pro refresh.
            isCustodial: auth.isCustodial,
          });
          // Functional update guarded on the same pubkey still being the
          // authenticated one: the polls above awaited, and an unguarded
          // spread of the captured state could resurrect a session that
          // signed out (or switched accounts) mid-poll. Same pattern as
          // the custody reconcile effect.
          setAuth((prev) =>
            prev.status === 'authenticated' && prev.pubkey === auth.pubkey
              ? { ...prev, isPro: true, isEarlySupporter: early }
              : prev,
          );
          return;
        }
      } catch (err) {
        console.error('[auth] refreshProStatus error:', err);
        return;
      }
    }
    // Silent callers get no warn and no banner: "not pro" is the normal
    // outcome for the checkout-return re-check (the user may have
    // cancelled) and for the background recheck, which runs for every
    // free account. Raising "payment received" on a cancelled checkout
    // would be a false positive, so silent mode flips Pro only if the
    // server confirms it and otherwise stays quiet.
    if (opts?.silent) return;
    console.warn(`[auth] refreshProStatus: still not pro after ${attempts} attempts`);
    // Surface to the UI so the user knows something is happening on the
    // server even though the client gave up polling. NotesView listens
    // for this event and renders a banner. See gap #23.
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('privacynotes:pro-activation-pending'));
    }
  }

  // A Pro purchase can land server-side while this device still shows the
  // free tier: checkout ran in the system browser and the return hook never
  // fired (#219), the app restarted inside the 24 h register-device throttle
  // (fast boot reuses cached pre-purchase flags), or the purchase happened on
  // another device entirely - registration was the only propagation channel,
  // so other devices stayed free-looking for up to a day. While the account
  // reads free (or sign-in is parked on the device cap), silently re-check
  // once on boot and again whenever the app regains focus or visibility,
  // throttled to once a minute, so an upgrade takes effect without a
  // sign-out. The effect unhooks itself the moment isPro flips.
  const proRecheckEligible =
    (auth.status === 'authenticated' && !auth.isPro) ||
    auth.status === 'device_limit_reached';
  // Ref so the listeners always call the latest closure (refreshProStatus is
  // recreated per render over the current auth state; the effect only re-runs
  // when eligibility changes).
  const refreshProStatusRef = useRef(refreshProStatus);
  refreshProStatusRef.current = refreshProStatus;
  // Same ref pattern for the pubkey the store restore validates against.
  // Both eligible states carry one.
  const pubkeyRef = useRef<string | null>(null);
  pubkeyRef.current =
    auth.status === 'authenticated' || auth.status === 'device_limit_reached'
      ? auth.pubkey
      : null;
  useEffect(() => {
    // Demo mode holds no Supabase session and promises zero server calls.
    if (!proRecheckEligible || isDemoMode()) return;
    const recheck = () => {
      if (Date.now() - lastProRecheckAt < PRO_RECHECK_THROTTLE_MS) return;
      lastProRecheckAt = Date.now();
      void (async () => {
        // Native store builds: before concluding the account is free, ask the
        // store what it owns and re-validate it. This is what makes reinstall,
        // new-device, and lost-validation self-heal with no user action - the
        // entitlement is born on the store account, and this recheck is the
        // only moment the bridge to the pubkey gets rebuilt. Idempotent and
        // never throws; a no-purchases store account returns without any
        // server call. Spec: ops/docs/plans/iap-restore-handoff.md (extend this recheck for restore, never add a second lifecycle)
        const pubkey = pubkeyRef.current;
        if (pubkey && isNativeStoreBuild()) await restoreNativePurchases(pubkey);
        await refreshProStatusRef.current({ silent: true, attempts: 1 });
      })();
    };
    recheck();
    const onFocus = () => recheck();
    const onVisible = () => {
      if (!document.hidden) recheck();
    };
    window.addEventListener('focus', onFocus);
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      window.removeEventListener('focus', onFocus);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, [proRecheckEligible]);

  return { refreshProStatus };
}
