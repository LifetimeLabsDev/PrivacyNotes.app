import {
  useEffect,
  useRef,
  type Dispatch,
  type SetStateAction,
} from 'react';
import { type SupabaseClient } from '@notes/shared';
import {
  adoptCustodyServer,
  releaseCustodyServer,
} from './devices';
import {
  patchCachedCustodial,
  jwtPayloadCustodial,
  jwtPayloadPubkey,
} from './authStorage';
import type { AuthState } from './auth';
import { ensureLevel2, mfaSessionIdentity, MfaCancelledError } from './mfaStep';
import { isDemoMode } from './demo';

export function useCustody({
  supabase,
  auth,
  setAuth,
}: {
  supabase: SupabaseClient;
  auth: AuthState;
  setAuth: Dispatch<SetStateAction<AuthState>>;
}) {
  const authRef = useRef(auth);
  authRef.current = auth;
  const confirmedCustody = useRef<{ pubkey: string; identity: string; value: boolean } | null>(null);

  // ----------------------------------------------------------------
  // Custody reconciliation
  // ----------------------------------------------------------------
  // The custodial_phrases row is the source of truth. Its ordinary cached
  // representation is the `app_metadata.custodial` JWT
  // claim (written by store-custodial-phrase, healed lazily by
  // get-custodial-phrase, cleared by delete-custodial-phrase). Reading
  // it avoids fetching plaintext phrase material for a UI decision.
  // After a confirmed mutation, account_status reconciles the custody row
  // directly because metadata mirroring may have failed.
  //
  // Everything before this point is a cache. This is the correction.
  //
  // Silent when there is no session (phrase-only users), when the
  // claim is absent (legacy account that has not re-hydrated since the
  // flag shipped), or when the network is down: in all three the
  // cached answer stands.
  const authedPubkey = auth.status === 'authenticated' ? auth.pubkey : null;
  const authedCustodial = auth.status === 'authenticated' ? auth.isCustodial : null;
  useEffect(() => {
    if (!authedPubkey || authedCustodial === null) return;
    let cancelled = false;
    void (async () => {
      let token: string | undefined;
      let identity: string | null = null;
      try {
        const { data } = await supabase.auth.getSession();
        token = data.session?.access_token;
        identity = mfaSessionIdentity(data.session);
      } catch {
        return;
      }
      if (cancelled || !token || jwtPayloadPubkey(token) !== authedPubkey ||
          authRef.current.status !== 'authenticated' || authRef.current.pubkey !== authedPubkey) return;
      const confirmed = confirmedCustody.current;
      let claim = jwtPayloadCustodial(token);
      if (confirmed?.pubkey === authedPubkey) {
        // Metadata mirroring can fail even when custody changed successfully.
        // Only an authoritative account-status answer can replace that known
        // result; neither an old token nor a freshly minted stale flag can.
        if (identity !== confirmed.identity) return;
        try {
          const result = await supabase.rpc('account_status');
          if (cancelled || result.error || typeof result.data?.custodial !== 'boolean') return;
          const live = (await supabase.auth.getSession()).data.session;
          if (cancelled || mfaSessionIdentity(live) !== identity || authRef.current.status !== 'authenticated' || authRef.current.pubkey !== authedPubkey) return;
          claim = result.data.custodial;
          confirmedCustody.current = null;
        } catch { return; }
      }
      if (claim === null || claim === authedCustodial) return;
      patchCachedCustodial(authedPubkey, claim);
      setAuth((prev) =>
        prev.status === 'authenticated' && prev.pubkey === authedPubkey
          ? { ...prev, isCustodial: claim }
          : prev,
      );
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authedPubkey, authedCustodial]);

  /** The session is bound by uid, session_id and the server-owned pubkey.
   * Token refresh may change token bytes without changing that session.
   * tests/authCustody.test.ts exercises switches on both sides of the call. */
  async function custodySession(pubkey: string, expectedIdentity?: string) {
    const { data, error } = await supabase.auth.getSession();
    const session = data.session;
    const identity = mfaSessionIdentity(session);
    const current = authRef.current;
    if (error || !session || !identity || jwtPayloadPubkey(session.access_token) !== pubkey ||
        current.status !== 'authenticated' || current.pubkey !== pubkey ||
        (expectedIdentity !== undefined && identity !== expectedIdentity)) throw new MfaCancelledError();
    return { session, identity };
  }

  async function changeCustody(next: boolean): Promise<{ ok: true } | { ok: false; error: string }> {
    if (isDemoMode()) return { ok: false, error: 'Key custody cannot be changed in the demo.' };
    if (auth.status !== 'authenticated') return { ok: false, error: 'Not signed in.' };
    const pubkey = auth.pubkey;
    try {
      const initial = await custodySession(pubkey);
      // Both custody directions share this sink-level gate. The UI still
      // owns informed consent and the saved-phrase confirmation for removal.
      await ensureLevel2(supabase, { force: true, allowLocalUse: true });
      const { session } = await custodySession(pubkey, initial.identity);
      try {
        if (next) {
          await adoptCustodyServer({ supabase, accessToken: session.access_token,
            authUid: session.user.id, signingPrivateKey: auth.signingPrivateKey, phrase: auth.phrase });
        } else {
          await releaseCustodyServer({ supabase, accessToken: session.access_token,
            authUid: session.user.id, signingPrivateKey: auth.signingPrivateKey });
        }
      } catch (error) {
        // This exact refusal already proves the requested state. Other errors
        // must not make an unsuccessful handover appear complete.
        if (!next || (error as Error).message !== 'store-custodial-phrase failed: already_stored') throw error;
      }
      await custodySession(pubkey, initial.identity);
      confirmedCustody.current = { pubkey, identity: initial.identity, value: next };
      // Refresh the mirrored claim. A transient failure leaves the successful
      // server operation in force; the next refresh can reconcile the claim.
      try { await supabase.auth.refreshSession(); } catch { /* retry on next refresh */ }
      await custodySession(pubkey, initial.identity);
      patchCachedCustodial(pubkey, next);
      setAuth((previous) => previous.status === 'authenticated' && previous.pubkey === pubkey
        ? { ...previous, isCustodial: next } : previous);
      if (!next) {
        try { window.localStorage.removeItem('privacynotes.signOut.skipReminder'); } catch { /* storage unavailable */ }
      }
      return { ok: true };
    } catch (error) {
      return { ok: false, error: error instanceof MfaCancelledError
        ? 'Sign-in changed or verification was cancelled. No local account data was removed.'
        : (error as Error).message };
    }
  }

  /** The caller must show the phrase and confirm a saved copy first. */
  async function releaseCustody(): Promise<{ ok: true } | { ok: false; error: string }> {
    return changeCustody(false);
  }

  /** Only an explicit, informed user action may give the server the phrase.
   * Never call this as recovery, repair, or a silent fallback. */
  async function adoptCustody(): Promise<{ ok: true } | { ok: false; error: string }> {
    return changeCustody(true);
  }

  return { releaseCustody, adoptCustody };
}
