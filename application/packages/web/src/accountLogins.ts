import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useAuth } from './auth';
import { isDemoMode } from './demo';
import { jwtPayloadPubkey } from './authStorage';
import { fetchMfaStatus, MfaCancelledError, mfaSessionIdentity } from './mfaStep';
import { supabaseAuthStorageKey } from './accountOAuth';
import { createAccountLoginsAdapter, type AccountLoginActor, type AccountLoginStatus } from './accountLoginsCore';
export type { AccountLoginStatus } from './accountLoginsCore';

const CHANGE_EVENT = 'privacynotes:account-logins-changed';

export function useAccountLogins() {
  const { auth, supabase } = useAuth();
  const authRef = useRef(auth);
  const mounted = useRef(true);
  const generation = useRef(0);
  const refreshVersion = useRef(0);
  if (authRef.current.status !== auth.status || ('pubkey' in authRef.current ? authRef.current.pubkey : null) !== ('pubkey' in auth ? auth.pubkey : null)) {
    generation.current++; refreshVersion.current++;
  }
  authRef.current = auth;
  const [status, setStatus] = useState<AccountLoginStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [mfaEnabled, setMfaEnabled] = useState<boolean | null>(null);
  const [canAdopt, setCanAdopt] = useState<boolean | null>(null);
  const pubkey = auth.status === 'authenticated' ? auth.pubkey : null;

  const actor = useCallback(async (): Promise<AccountLoginActor> => {
    const current = authRef.current;
    const currentGeneration = generation.current;
    if (isDemoMode() || !mounted.current || current.status !== 'authenticated') throw new MfaCancelledError();
    const { data, error: sessionError } = await supabase.auth.getSession();
    const session = data.session;
    const identity = mfaSessionIdentity(session);
    const latest = authRef.current;
    if (!mounted.current || generation.current !== currentGeneration || sessionError || !session || !identity || latest.status !== 'authenticated' || latest.pubkey !== current.pubkey ||
        jwtPayloadPubkey(session.access_token) !== current.pubkey || session.user.app_metadata?.pubkey !== current.pubkey) throw new MfaCancelledError();
    let passwordSession = false;
    try {
      const raw = session.access_token.split('.')[1] ?? '';
      const methods = JSON.parse(atob(raw.replace(/-/g, '+').replace(/_/g, '/'))).amr;
      passwordSession = Array.isArray(methods) && methods.some((entry) => entry?.method === 'password');
    } catch { /* missing AMR requires proving the retained phrase route */ }
    return { identity, userId: session.user.id, sessionId: identity.slice(session.user.id.length + 1), accessToken: session.access_token,
      pubkey: current.pubkey, phrase: current.phrase, signingPrivateKey: current.signingPrivateKey, generation: currentGeneration, passwordSession };
  }, [supabase]);
  const isCurrent = useCallback((previous: AccountLoginActor) => mounted.current && authRef.current.status === 'authenticated' &&
    generation.current === previous.generation && authRef.current.pubkey === previous.pubkey && authRef.current.phrase === previous.phrase, []);
  const adapter = useMemo(() => createAccountLoginsAdapter({ client: supabase, actor, isCurrent,
    storageKey: supabaseAuthStorageKey(import.meta.env.VITE_SUPABASE_URL) }), [supabase, actor, isCurrent]);

  const refresh = useCallback(async (background = false) => {
    const request = ++refreshVersion.current;
    setLoading(true); setError(null);
    try {
      const initial = await actor();
      const [next, mfa] = await Promise.all([adapter.refresh(background), fetchMfaStatus(supabase)]);
      const current = await actor();
      if (!isCurrent(initial) || initial.identity !== current.identity) throw new MfaCancelledError();
      const session = (await supabase.auth.getSession()).data.session;
      if (!session || mfaSessionIdentity(session) !== initial.identity || !isCurrent(initial) || refreshVersion.current !== request) throw new MfaCancelledError();
      setStatus(next); setMfaEnabled(mfa.available ? mfa.enrolled : null);
      const provider = session.user.app_metadata?.provider;
      setCanAdopt(!next.deleted && !next.wrong_login && (next.managed ? next.connections.some((item) => item.active) :
        provider === 'google' || provider === 'apple' || provider === 'github'));
      return next;
    } catch (failure) {
      if (mounted.current && refreshVersion.current === request) { setStatus(null); setMfaEnabled(null); setCanAdopt(null); setError((failure as Error).message); }
      throw failure;
    } finally { if (mounted.current && refreshVersion.current === request) setLoading(false); }
  }, [actor, adapter, isCurrent, supabase]);

  useEffect(() => {
    mounted.current = true;
    setStatus(null); setMfaEnabled(null); setCanAdopt(null); setError(null); setLoading(false);
    if (!pubkey || isDemoMode()) return () => { mounted.current = false; generation.current++; refreshVersion.current++; };
    const update = () => { void refresh(true).catch(() => {}); };
    let lastIdentity: string | null | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const { data: { subscription } } = supabase.auth.onAuthStateChange((event, session) => {
      const identity = mfaSessionIdentity(session);
      if (identity === lastIdentity && event !== 'MFA_CHALLENGE_VERIFIED') return;
      lastIdentity = identity;
      refreshVersion.current++;
      if (event === 'SIGNED_OUT') generation.current++;
      setStatus(null); setMfaEnabled(null); setCanAdopt(null);
      // Leave the SDK callback before any getSession/RPC work.
      if (timer) clearTimeout(timer);
      timer = setTimeout(update, 0);
    });
    update();
    window.addEventListener(CHANGE_EVENT, update);
    window.addEventListener('privacynotes:mfa-changed', update);
    return () => {
      mounted.current = false; generation.current++; refreshVersion.current++;
      if (timer) clearTimeout(timer);
      subscription.unsubscribe();
      window.removeEventListener(CHANGE_EVENT, update); window.removeEventListener('privacynotes:mfa-changed', update);
    };
  }, [pubkey, refresh, supabase]);

  async function changed(operation: Promise<AccountLoginStatus>) {
    const result = await operation;
    const current = await actor();
    if (result.canonical_uid !== current.userId) throw new MfaCancelledError();
    setStatus(result);
    window.dispatchEvent(new Event(CHANGE_EVENT));
    return result;
  }
  return { status, loading, error, mfaEnabled, canAdopt, refresh,
    activate: () => changed(adapter.activate()),
    connect: (proof: Parameters<typeof adapter.connect>[0]) => changed(adapter.connect(proof)),
    disconnect: (connectionId: string) => changed(adapter.disconnect(connectionId)),
    enrollMfa: (factorId: string) => adapter.enrollMfa(factorId),
    unenrollMfa: (factorId: string) => adapter.unenrollMfa(factorId),
  };
}
