import type { SupabaseClient } from '@notes/shared';
import { trustAwareStorage } from './trustStorage';
import { guardAccountSessionWrite, MfaCancelledError, mfaSessionIdentity } from './sessionWriteGuard';
import { isDemoMode } from './demo';

export type AccountOAuthProvider = 'google' | 'apple' | 'github';
type ExchangeContext = {
  grantType: 'pkce' | 'password';
  requestClaimed: boolean;
  expectedUserId?: string;
  expectedPubkey?: string;
  previousIdentity: string | null;
  isCurrent: () => boolean;
  release: Array<() => void>;
};
const exchanges = new Map<string, ExchangeContext>();

export function supabaseAuthStorageKey(url: string): string {
  return `sb-${new URL(url).hostname.split('.')[0]}-auth-token`;
}

/** Query-code callbacks are consumed only after broker preflight. Legacy
 * implicit returns retain the SDK's existing detection behavior. */
export function detectAutomaticOAuthSession(): boolean {
  return typeof window === 'undefined' || !new URLSearchParams(window.location.search).has('code');
}

function tokenClaims(token: string): { sub?: unknown; session_id?: unknown; aal?: unknown; exp?: unknown; app_metadata?: { pubkey?: unknown } } {
  try {
    const raw = token.split('.')[1];
    if (!raw) throw new Error('Invalid token');
    const value = JSON.parse(atob(raw.replace(/-/g, '+').replace(/_/g, '/')));
    if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  } catch { /* invalid token */ }
  throw new Error('The sign-in response was invalid. Start sign-in again.');
}

/** The sole SDK client uses its ordinary PKCE exchange. This transport
 * observes only that exchange's successful auth response, before the SDK
 * saves it, so the exact returned token can be bound to its original flow. */
export function accountOAuthFetch(url: string, storageKey: string): typeof fetch {
  const authTokenUrl = `${url.replace(/\/$/, '')}/auth/v1/token`;
  return async (input, init) => {
    const requestUrl = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
    const active = exchanges.get(storageKey);
    const context = active && !active.requestClaimed && requestUrl.origin + requestUrl.pathname === authTokenUrl &&
      requestUrl.searchParams.get('grant_type') === active.grantType ? active : undefined;
    if (context) context.requestClaimed = true;
    const result = await fetch(input, init);
    if (context && result.ok) {
      const data = await result.clone().json();
      if (typeof data?.access_token !== 'string' || typeof data?.user?.id !== 'string') throw new Error('The sign-in response was invalid.');
      const claims = tokenClaims(data.access_token);
      if (claims.sub !== data.user.id || typeof claims.session_id !== 'string') throw new Error('The sign-in response was invalid.');
      context.release.push(guardAccountSessionWrite({ storageKey, accessToken: data.access_token,
        userId: context.expectedUserId ?? data.user.id, pubkey: context.expectedPubkey,
        previousIdentity: context.previousIdentity, isCurrent: context.isCurrent }));
    }
    return result;
  };
}

function readVerifier(storageKey: string, requestedFlowId?: string) {
  if (requestedFlowId !== undefined && !/^[a-zA-Z0-9_-]{8,64}$/.test(requestedFlowId)) throw new Error('That sign-in flow is invalid. Start again.');
  let flowId = requestedFlowId;
  let key = flowId ? `${storageKey}-flow-${flowId}-code-verifier` : `${storageKey}-code-verifier`;
  const raw = trustAwareStorage.getItem(key);
  let value: unknown;
  try { value = raw ? JSON.parse(raw) : null; } catch { value = null; }
  if (typeof value !== 'string') throw new Error('This device did not start that sign-in. Start again.');
  const codeVerifier = value.split('/')[0];
  if (!codeVerifier || !/^[a-zA-Z0-9._~-]{43,128}$/.test(codeVerifier)) throw new Error('The sign-in verifier is invalid. Start again.');
  // Current SDKs also keep a per-flow slot when redirects have no flow id.
  // Selecting that slot keeps a late exchange from deleting a newer flow's
  // legacy fallback verifier during the SDK's automatic cleanup.
  if (!flowId) {
    try {
      const index = JSON.parse(trustAwareStorage.getItem(`${storageKey}-flows-code-verifier`) ?? '[]');
      if (Array.isArray(index)) {
        flowId = index.find((id) => typeof id === 'string' && /^[a-zA-Z0-9_-]{8,64}$/.test(id) &&
          trustAwareStorage.getItem(`${storageKey}-flow-${id}-code-verifier`) === raw);
        if (flowId) key = `${storageKey}-flow-${flowId}-code-verifier`;
      }
    } catch { /* legacy verifier still works */ }
  }
  return { codeVerifier, raw, key, flowId };
}

function clearVerifier(storageKey: string, verifier: ReturnType<typeof readVerifier>): void {
  for (const key of [verifier.key, `${storageKey}-code-verifier`]) {
    if (trustAwareStorage.getItem(key) === verifier.raw) trustAwareStorage.removeItem(key);
  }
  if (!verifier.flowId) return;
  const key = `${storageKey}-flows-code-verifier`;
  try {
    const index = JSON.parse(trustAwareStorage.getItem(key) ?? '[]');
    if (!Array.isArray(index)) return;
    const remaining = index.filter((id) => id !== verifier.flowId);
    if (remaining.length) trustAwareStorage.setItem(key, JSON.stringify(remaining));
    else trustAwareStorage.removeItem(key);
  } catch { /* bounded orphan slots expire with their storage */ }
}

/** True when the broker could not judge the code: not deployed, unreachable,
 * rate limited or failing. The ordinary exchange is then safe, because an
 * alias session of a managed vault is refused by the server gate. A 4xx
 * answer is a judgment and never falls back. */
async function brokerUnavailable(error: unknown): Promise<boolean> {
  const context = (error as { context?: unknown } | null)?.context;
  if (!(context instanceof Response)) return true;
  if (context.status === 429 || context.status >= 500) return true;
  if (context.status !== 404) return false;
  try {
    const body = await context.clone().json();
    return body?.code === 'NOT_FOUND' && body?.message === 'Requested function was not found';
  } catch { return false; }
}

/** The only explicit session installation in the app. Its tokens come from
 * this pending broker HTTP response, never from a URL, IPC or postMessage.
 * Server-side broker registration finishes before these tokens are returned.
 * tests/accountOAuth.test.ts covers the exact response and storage boundary. */
export async function exchangeAccountOAuth(
  client: SupabaseClient,
  code: string,
  options: { storageKey: string; flowId?: string; isCurrent: () => boolean },
): Promise<{ session: NonNullable<Awaited<ReturnType<SupabaseClient['auth']['getSession']>>['data']['session']>; provider?: AccountOAuthProvider }> {
  if (isDemoMode()) throw new Error('Sign-in is disabled in the demo.');
  if (!code || code.length > 8192 || exchanges.has(options.storageKey)) throw new MfaCancelledError();
  const current = await client.auth.getSession();
  if (current.error || !options.isCurrent()) throw new MfaCancelledError();
  const previousIdentity = mfaSessionIdentity(current.data.session);
  const verifier = readVerifier(options.storageKey, options.flowId);
  if (exchanges.has(options.storageKey)) throw new MfaCancelledError();
  const context: ExchangeContext = { grantType: 'pkce', requestClaimed: false, previousIdentity, isCurrent: options.isCurrent, release: [] };
  exchanges.set(options.storageKey, context);
  const assertCurrent = async () => {
    const live = await client.auth.getSession();
    if (live.error || !options.isCurrent() || mfaSessionIdentity(live.data.session) !== previousIdentity) throw new MfaCancelledError();
  };
  try {
    const result = await client.functions.invoke('account-logins', { body: { action: 'oauth', code, codeVerifier: verifier.codeVerifier } });
    if (result.error && !(await brokerUnavailable(result.error))) throw new Error('Account sign-in could not be completed. Start sign-in again.');
    const data = result.error ? { managed: false } : result.data;
    if (data?.managed === false) {
      await assertCurrent();
      const exchanged = await client.auth.exchangeCodeForSession(code, verifier.flowId ? { flowId: verifier.flowId } : undefined);
      if (exchanged.error || !exchanged.data.session) throw new Error('That sign-in code did not work. Start sign-in again.');
      const live = await client.auth.getSession();
      if (live.error || !options.isCurrent() || mfaSessionIdentity(live.data.session) !== mfaSessionIdentity(exchanged.data.session)) throw new MfaCancelledError();
      return { session: exchanged.data.session };
    }
    if (data?.managed !== true || !data.session || typeof data.session.access_token !== 'string' ||
        typeof data.session.refresh_token !== 'string' || !data.session.refresh_token ||
        typeof data.userId !== 'string' || typeof data.pubkey !== 'string' || !/^[0-9a-f]{64}$/.test(data.pubkey) ||
        !['google', 'apple', 'github'].includes(data.provider)) throw new Error('The account sign-in response was invalid.');
    const claims = tokenClaims(data.session.access_token);
    if (claims.sub !== data.userId || claims.app_metadata?.pubkey !== data.pubkey || claims.aal !== 'aal1' ||
        typeof claims.session_id !== 'string' || !claims.session_id || typeof claims.exp !== 'number' || claims.exp <= Date.now() / 1000 + 10) {
      throw new Error('The account sign-in response was invalid.');
    }
    clearVerifier(options.storageKey, verifier);
    await assertCurrent();
    context.release.push(guardAccountSessionWrite({ storageKey: options.storageKey, accessToken: data.session.access_token,
      userId: data.userId, pubkey: data.pubkey, previousIdentity, isCurrent: options.isCurrent }));
    const adopted = await client.auth.setSession({ access_token: data.session.access_token, refresh_token: data.session.refresh_token });
    const session = adopted.data.session;
    if (adopted.error || !session || session.user.id !== data.userId || session.user.app_metadata?.pubkey !== data.pubkey ||
        mfaSessionIdentity(session) !== `${data.userId}:${claims.session_id}` || !options.isCurrent()) throw new MfaCancelledError();
    const live = await client.auth.getSession();
    if (live.error || !options.isCurrent() || mfaSessionIdentity(live.data.session) !== mfaSessionIdentity(session)) throw new MfaCancelledError();
    return { session, provider: data.provider };
  } finally {
    if (exchanges.get(options.storageKey) === context) exchanges.delete(options.storageKey);
    for (const release of context.release) release();
  }
}

/** Activation switches this vault to its phrase credential through the
 * ordinary password grant, with the same response-before-save protection. */
export async function signInManagedAccount(client: SupabaseClient, credentials: { email: string; password: string }, options: {
  storageKey: string; userId: string; pubkey: string; previousIdentity: string; isCurrent: () => boolean;
}) {
  const current = await client.auth.getSession();
  if (isDemoMode() || current.error || mfaSessionIdentity(current.data.session) !== options.previousIdentity ||
      !options.isCurrent() || exchanges.has(options.storageKey)) throw new MfaCancelledError();
  const context: ExchangeContext = { grantType: 'password', requestClaimed: false, expectedUserId: options.userId,
    expectedPubkey: options.pubkey, previousIdentity: options.previousIdentity, isCurrent: options.isCurrent, release: [] };
  exchanges.set(options.storageKey, context);
  try {
    const result = await client.auth.signInWithPassword(credentials);
    const session = result.data.session;
    if (result.error || !session) throw new Error('Phrase sign-in could not be completed. Your local notes are still on this device.');
    const live = await client.auth.getSession();
    if (live.error || !options.isCurrent() || session.user.id !== options.userId || session.user.app_metadata?.pubkey !== options.pubkey ||
        mfaSessionIdentity(live.data.session) !== mfaSessionIdentity(session)) throw new MfaCancelledError();
    return session;
  } finally {
    if (exchanges.get(options.storageKey) === context) exchanges.delete(options.storageKey);
    for (const release of context.release) release();
  }
}
