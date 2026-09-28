import { authEmailForPubkey, bytesToHex, deriveAuthPassword, phraseToSeed, signAccountLoginsChallenge, type SupabaseClient } from '@notes/shared';
import { ensureLevel2, isMfaRefusal, MfaCancelledError, MfaRequiredError, mfaSessionIdentity } from './mfaStep';
import { signInManagedAccount, type AccountOAuthProvider } from './accountOAuth';

export type AccountLoginStatus = {
  managed: boolean; deleted: boolean; canonical_uid: string | null; wrong_login: boolean;
  setup_enabled: boolean; custodial: boolean | null;
  connections: Array<{ id: string; provider: AccountOAuthProvider; email: string | null; active: boolean }>;
};
export type AccountLoginActor = {
  identity: string; userId: string; sessionId: string; accessToken: string;
  pubkey: string; phrase: string; signingPrivateKey: Uint8Array;
  generation?: number;
  passwordSession: boolean;
};
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const mutations = new WeakSet<SupabaseClient>();

export function parseAccountLoginStatus(value: unknown): AccountLoginStatus {
  const row = value as AccountLoginStatus | null;
  if (!row || typeof row !== 'object' || ['managed', 'deleted', 'wrong_login', 'setup_enabled'].some((key) => typeof (row as unknown as Record<string, unknown>)[key] !== 'boolean') ||
      (typeof row.custodial !== 'boolean' && !((row.wrong_login || row.deleted) && row.custodial === undefined)) ||
      (row.canonical_uid !== null && (typeof row.canonical_uid !== 'string' || !UUID.test(row.canonical_uid))) ||
      (row.managed && !row.deleted && !row.canonical_uid) || !Array.isArray(row.connections) || row.connections.some((item) =>
        !item || typeof item.id !== 'string' || !UUID.test(item.id) || !['google', 'apple', 'github'].includes(item.provider) ||
        (item.email !== null && typeof item.email !== 'string') || typeof item.active !== 'boolean')) {
    throw new Error('Account settings could not be checked. Try again.');
  }
  return { ...row, custodial: typeof row.custodial === 'boolean' ? row.custodial : null };
}

async function responseError(error: unknown): Promise<Error> {
  try {
    const body = await (error as { context?: Response }).context?.clone().json();
    if (typeof body?.error === 'string' && /^[a-z][a-z0-9_]{0,100}$/.test(body.error)) return new Error(body.error);
  } catch { /* network or malformed response */ }
  return new Error('Account settings could not be saved. Try again.');
}

/** Every action keeps the vault, UID and exact session fixed through its
 * MFA prompt, proof exchange, nonce, signature and final server response. */
export function createAccountLoginsAdapter(options: {
  client: SupabaseClient; storageKey: string; actor: () => Promise<AccountLoginActor>;
  isCurrent: (actor: AccountLoginActor) => boolean;
}) {
  const { client } = options;
  async function same(actor: AccountLoginActor): Promise<AccountLoginActor> {
    const live = await options.actor();
    if (!options.isCurrent(actor) || live.identity !== actor.identity || live.pubkey !== actor.pubkey) throw new MfaCancelledError();
    return live;
  }
  async function invoke(actor: AccountLoginActor, body: Record<string, unknown>) {
    const live = await same(actor);
    const result = await client.functions.invoke('account-logins', { body, headers: { Authorization: `Bearer ${live.accessToken}` } });
    await same(actor);
    if (result.error) throw await responseError(result.error);
    return result.data;
  }
  async function read(actor: AccountLoginActor, background = false) {
    await same(actor);
    let result = await client.rpc('account_status');
    await same(actor);
    if (isMfaRefusal(result.error)) {
      await ensureLevel2(client, { allowLocalUse: true, background });
      await same(actor);
      result = await client.rpc('account_status');
      await same(actor);
      if (isMfaRefusal(result.error)) throw new MfaRequiredError();
    }
    // A client can arrive before the opt-in account backend is deployed.
    // Keep management closed, but distinguish that from a failed change.
    if (result.error?.code === 'PGRST202') throw new Error('account_setup_unavailable');
    if (result.error) throw new Error('Account settings could not be checked. Try again.');
    return parseAccountLoginStatus(result.data);
  }
  async function verified(expectedIdentity?: string, factorId?: string) {
    const actor = await options.actor();
    if (expectedIdentity !== undefined && actor.identity !== expectedIdentity) throw new MfaCancelledError();
    await ensureLevel2(client, { force: true, allowLocalUse: true, ...(factorId ? { factorId } : {}) });
    return same(actor);
  }
  async function signed(actor: AccountLoginActor, operation: 'activate' | 'connect' | 'disconnect' | 'enroll-mfa' | 'unenroll-mfa', payload: Record<string, string | null>) {
    const digest = bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(payload)))));
    const nonce = await invoke(actor, { action: 'nonce', operation, payload });
    if (typeof nonce?.id !== 'string' || !UUID.test(nonce.id) || typeof nonce.expiresAt !== 'string') throw new Error('The account confirmation was invalid. Try again.');
    const expiresAt = Date.parse(nonce.expiresAt);
    const expected = `account-logins:${nonce.id}:${actor.userId}:${actor.sessionId}:${actor.pubkey}:${operation}:${digest}`;
    if (nonce.challenge !== expected || !Number.isFinite(expiresAt) || expiresAt <= Date.now() || expiresAt > Date.now() + 10 * 60_000) throw new Error('The account confirmation was invalid. Try again.');
    await same(actor);
    const signature = bytesToHex(await signAccountLoginsChallenge(actor.signingPrivateKey, { nonceId: nonce.id,
      authUid: actor.userId, sessionId: actor.sessionId, pubkey: actor.pubkey, operation, bodyDigest: digest }));
    await same(actor);
    if (expiresAt <= Date.now()) throw new Error('The account confirmation expired. Try again.');
    return invoke(actor, { action: operation, payload, nonceId: nonce.id, signature });
  }
  async function mutation<T>(run: () => Promise<T>): Promise<T> {
    if (mutations.has(client)) throw new Error('An account change is already in progress.');
    mutations.add(client);
    try { return await run(); } finally { mutations.delete(client); }
  }
  async function phraseSession(actor: AccountLoginActor, userId = actor.userId) {
    await same(actor);
    const session = await signInManagedAccount(client, { email: authEmailForPubkey(actor.pubkey), password: deriveAuthPassword(phraseToSeed(actor.phrase)) }, {
      storageKey: options.storageKey, userId, pubkey: actor.pubkey,
      previousIdentity: actor.identity, isCurrent: () => options.isCurrent(actor),
    });
    const live = await options.actor();
    if (!options.isCurrent(actor) || live.userId !== userId || live.pubkey !== actor.pubkey || live.identity !== mfaSessionIdentity(session)) throw new MfaCancelledError();
    return live;
  }
  function authorizeFactor(operation: 'enroll-mfa' | 'unenroll-mfa', factorId: string) {
    return mutation(async () => {
      if (!UUID.test(factorId)) throw new Error('That authenticator setup is invalid.');
      const actor = await verified(undefined, operation === 'unenroll-mfa' ? factorId : undefined);
      const result = await signed(actor, operation, { factorId });
      if (result?.authorized !== true || typeof result.expires_at !== 'string' || !Number.isFinite(Date.parse(result.expires_at)) || Date.parse(result.expires_at) <= Date.now()) {
        throw new Error('The authenticator change could not be confirmed. Try again.');
      }
    });
  }
  return {
    async refresh(background = false) { return read(await options.actor(), background); },
    async activate() {
      return mutation(async () => {
        let actor = await options.actor();
        let status = await read(actor);
        const password = deriveAuthPassword(phraseToSeed(actor.phrase));
        if (status.managed && !status.deleted && status.canonical_uid === actor.userId) return status;
        if (!status.managed || status.deleted) {
          // A deleted account has no usable MFA route. Reclaim requires an
          // explicit phrase password grant before the signed activation.
          actor = status.deleted ? await phraseSession(actor) : await verified(actor.identity);
          status = parseAccountLoginStatus(await signed(actor, 'activate', { authPassword: password }));
        }
        if (!status.canonical_uid || status.deleted) throw new Error('Account settings could not be activated.');
        // A retry after a lost commit response uses the same phrase credential.
        // It never creates another canonical account or resets a password.
        actor = await phraseSession(actor, status.canonical_uid);
        await ensureLevel2(client, { allowLocalUse: true });
        await same(actor);
        return read(actor);
      });
    },
    async connect(proof: { code: string; codeVerifier: string; expectedIdentity: string; expectedProvider: AccountOAuthProvider; replaceId?: string | null }) {
      return mutation(async () => {
        if (!proof.code || proof.code.length > 8192 || !['google', 'apple', 'github'].includes(proof.expectedProvider) || !/^[a-zA-Z0-9._~-]{43,128}$/.test(proof.codeVerifier) ||
            (proof.replaceId != null && !UUID.test(proof.replaceId))) throw new Error('The connected account proof was invalid.');
        let actor = await options.actor();
        if (actor.identity !== proof.expectedIdentity) throw new MfaCancelledError();
        // Replacement revokes sessions issued by the removed connection just
        // like disconnect. Retain a phrase session before consuming the proof.
        if (proof.replaceId && !actor.passwordSession) actor = await phraseSession(actor);
        actor = await verified(actor.identity);
        const ticket = await invoke(actor, { action: 'connect-proof', code: proof.code, codeVerifier: proof.codeVerifier });
        if (typeof ticket?.ticketId !== 'string' || !UUID.test(ticket.ticketId) || ticket.provider !== proof.expectedProvider) throw new Error('The connected account proof was invalid.');
        return parseAccountLoginStatus(await signed(actor, 'connect', { ticketId: ticket.ticketId, replaceId: proof.replaceId ?? null }));
      });
    },
    async disconnect(connectionId: string) {
      return mutation(async () => {
        if (!UUID.test(connectionId)) throw new Error('That connected account is invalid.');
        let actor = await options.actor();
        if (!actor.passwordSession) {
          // Removing a provider revokes every session established through it,
          // including this one. Establish the retained phrase route first.
          actor = await phraseSession(actor);
        }
        actor = await verified(actor.identity);
        return parseAccountLoginStatus(await signed(actor, 'disconnect', { connectionId }));
      });
    },
    enrollMfa: (factorId: string) => authorizeFactor('enroll-mfa', factorId),
    unenrollMfa: (factorId: string) => authorizeFactor('unenroll-mfa', factorId),
  };
}
