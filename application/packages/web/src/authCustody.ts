import {
  useEffect,
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
} from './authStorage';
import type { AuthState } from './auth';

export function useCustody({
  supabase,
  auth,
  setAuth,
}: {
  supabase: SupabaseClient;
  auth: AuthState;
  setAuth: Dispatch<SetStateAction<AuthState>>;
}) {
  // ----------------------------------------------------------------
  // Custody reconciliation
  // ----------------------------------------------------------------
  // The custodial_phrases row is the source of truth and it only
  // reaches the client mirrored into the `app_metadata.custodial` JWT
  // claim (written by store-custodial-phrase, healed lazily by
  // get-custodial-phrase, cleared by delete-custodial-phrase). Reading
  // it here is the whole reason the claim exists: the alternative
  // would be calling get-custodial-phrase to render a button, which
  // would pull the plaintext phrase across the wire for a UI decision
  // and widen exactly the exposure this feature exists to close.
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
      try {
        const { data } = await supabase.auth.getSession();
        token = data.session?.access_token;
      } catch {
        return;
      }
      if (cancelled || !token) return;
      const claim = jwtPayloadCustodial(token);
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

  /**
   * Leave custodial mode: delete the server's copy of the phrase and
   * clear the app_metadata flag. One-way, by design - there is no
   * inverse action.
   *
   * The CALLER owns the safety gate. By the time this runs the user
   * must have seen their phrase and confirmed they saved it, because
   * after this returns nobody can recover their notes. See PhraseTab.
   *
   * Requires a live Supabase session: the edge function authorizes on
   * the JWT plus an ed25519 signature. A user who reached this device
   * by typing their phrase (no OAuth session) has no custodial flag on
   * this session anyway, so the UI never offers the action there.
   */
  async function releaseCustody(): Promise<{ ok: true } | { ok: false; error: string }> {
    if (auth.status !== 'authenticated') {
      return { ok: false, error: 'Not signed in.' };
    }
    let session: { access_token: string; user: { id: string } } | null = null;
    try {
      const { data } = await supabase.auth.getSession();
      session = data.session ?? null;
    } catch {
      session = null;
    }
    if (!session?.access_token) {
      return { ok: false, error: 'Sign in with your provider again to change key custody.' };
    }

    try {
      await releaseCustodyServer({
        supabase,
        accessToken: session.access_token,
        authUid: session.user.id,
        signingPrivateKey: auth.signingPrivateKey,
      });
    } catch (err) {
      return { ok: false, error: (err as Error).message };
    }

    // Pull the cleared claim into the local JWT. Best-effort: the
    // optimistic flip below is what the UI reads, and reconcileCustody
    // agrees with it on the next token refresh either way.
    try {
      await supabase.auth.refreshSession();
    } catch {
      /* ignore */
    }

    patchCachedCustodial(auth.pubkey, false);
    setAuth((prev) =>
      prev.status === 'authenticated' ? { ...prev, isCustodial: false } : prev,
    );
    // This account now depends on the user's own copy of the phrase, so
    // the sign-out reminder has to come back even if it was dismissed
    // for good while the server still held a copy.
    try {
      window.localStorage.removeItem('privacynotes.signOut.skipReminder');
    } catch {
      /* ignore */
    }
    return { ok: true };
  }

  /**
   * Re-enter custodial mode: hand the server an encrypted copy of the
   * phrase so any device signs in with the provider alone.
   *
   * This is the direction that GIVES us the ability to decrypt this
   * user's notes, so it must only ever be reached from an explicit,
   * informed user action that says so in those words. Never call it as
   * a fallback, a repair step, or a convenience.
   *
   * Requires a live Supabase session (the endpoint authorizes on the
   * JWT plus an ed25519 signature) and an OAuth provider, since
   * 1-click sign-in is the entire point.
   */
  async function adoptCustody(): Promise<{ ok: true } | { ok: false; error: string }> {
    if (auth.status !== 'authenticated') {
      return { ok: false, error: 'Not signed in.' };
    }
    let session: { access_token: string; user: { id: string } } | null = null;
    try {
      const { data } = await supabase.auth.getSession();
      session = data.session ?? null;
    } catch {
      session = null;
    }
    if (!session?.access_token) {
      return { ok: false, error: 'Sign in with your provider again to change key custody.' };
    }

    try {
      await adoptCustodyServer({
        supabase,
        accessToken: session.access_token,
        authUid: session.user.id,
        signingPrivateKey: auth.signingPrivateKey,
        phrase: auth.phrase,
      });
    } catch (err) {
      const msg = (err as Error).message;
      // The server already holds a row for this account. The end state
      // the user asked for is the state they are in, so reconcile the
      // client rather than reporting a failure they cannot act on.
      if (!msg.includes('already_stored')) {
        return { ok: false, error: msg };
      }
    }

    try {
      await supabase.auth.refreshSession();
    } catch {
      /* ignore */
    }

    patchCachedCustodial(auth.pubkey, true);
    setAuth((prev) =>
      prev.status === 'authenticated' ? { ...prev, isCustodial: true } : prev,
    );
    return { ok: true };
  }

  return { releaseCustody, adoptCustody };
}
