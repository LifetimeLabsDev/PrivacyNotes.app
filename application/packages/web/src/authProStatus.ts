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
import { dropProThemes } from './theme';

// Spec: ops/docs/billing-integration.md (Pro propagation: one RPC per minute)
const PRO_RECHECK_THROTTLE_MS = 60 * 1000;

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
  const authRef = useRef(auth);
  authRef.current = auth;
  const account = auth.status === 'authenticated' || auth.status === 'device_limit_reached'
    ? auth.pubkey : null;

  async function refreshProStatus(opts?: { silent?: boolean; attempts?: number }) {
    const limitBlocked = auth.status === 'device_limit_reached';
    if (auth.status !== 'authenticated' && !limitBlocked) return;
    const stillCurrent = () => {
      const current = authRef.current;
      return current.status === auth.status && current.pubkey === auth.pubkey;
    };
    // A successful checkout may precede its webhook. Background checks do one read.
    const attempts = opts?.attempts ?? 6;
    for (let attempt = 0; attempt < attempts; attempt++) {
      if (attempt > 0) await new Promise((r) => setTimeout(r, 3000));
      if (!stillCurrent()) return;
      try {
        const { data, error } = await supabase.rpc('is_pro');
        if (!stillCurrent()) return;
        // An unavailable or malformed response cannot revoke a paid entitlement.
        if (error || typeof data !== 'boolean') return;
        if (data && limitBlocked) {
          const retried = await retryRegistrationFromLimit();
          if (retried.ok) return;
          continue;
        }
        if (auth.status !== 'authenticated') continue;
        if (data || auth.isPro) {
          const early = data ? await checkEarlySupporter(supabase) : false;
          if (!stillCurrent()) return;
          const current = authRef.current;
          if (current.status !== 'authenticated') return;
          writeCachedAccountFlags({
            pubkey: current.pubkey,
            isPro: data,
            isEarlySupporter: early,
            isCustodial: current.isCustodial,
          });
          if (!data && current.isPro) dropProThemes();
          setAuth((prev) =>
            prev.status === 'authenticated' && prev.pubkey === auth.pubkey
              ? { ...prev, isPro: data, isEarlySupporter: early }
              : prev,
          );
          return;
        }
      } catch (err) {
        console.error('[auth] refreshProStatus error:', err);
        return;
      }
    }
    if (opts?.silent || !stillCurrent()) return;
    window.dispatchEvent(new CustomEvent('privacynotes:pro-activation-pending'));
  }

  const refreshRef = useRef(refreshProStatus);
  refreshRef.current = refreshProStatus;
  useEffect(() => {
    if (!account || isDemoMode()) return;
    let stale = false;
    let busy = false;
    let lastCheck = -Infinity;
    const recheck = () => {
      if (document.hidden || busy || Date.now() - lastCheck < PRO_RECHECK_THROTTLE_MS) return;
      lastCheck = Date.now();
      busy = true;
      void (async () => {
        try {
          const current = authRef.current;
          // Restore unvalidated store ownership for free accounts. Paid accounts
          // only need the server verdict, including refunds on another device.
          // Spec: ops/docs/plans/iap-restore-handoff.md (background restore)
          if ((current.status === 'device_limit_reached' ||
            (current.status === 'authenticated' && !current.isPro)) && isNativeStoreBuild()) {
            await restoreNativePurchases(account);
          }
          if (!stale) await refreshRef.current({ silent: true, attempts: 1 });
        } finally {
          busy = false;
        }
      })();
    };
    recheck();
    window.addEventListener('focus', recheck);
    document.addEventListener('visibilitychange', recheck);
    const timer = window.setInterval(recheck, PRO_RECHECK_THROTTLE_MS);
    return () => {
      stale = true;
      window.clearInterval(timer);
      window.removeEventListener('focus', recheck);
      document.removeEventListener('visibilitychange', recheck);
    };
  }, [account]);

  return { refreshProStatus };
}
