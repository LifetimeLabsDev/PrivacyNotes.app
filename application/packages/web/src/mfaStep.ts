import { useSyncExternalStore } from 'react';
import type { SupabaseClient } from '@notes/shared';
import { isDemoMode } from './demo';
import { MfaCancelledError, mfaSessionIdentity, withMfaSessionWriteGuard } from './sessionWriteGuard';
export { MfaCancelledError, mfaSessionIdentity } from './sessionWriteGuard';

type MfaProvider = 'phrase' | 'google' | 'apple' | 'github';
export type MfaStatus = {
  available: boolean;
  setup_enabled: boolean;
  enrolled: boolean;
  satisfied: boolean;
  provider: MfaProvider | null;
  wrong_login: boolean;
  can_enroll: boolean;
  reason: string | null;
};

export class MfaUnavailableError extends Error {
  constructor() { super('Account security could not be checked. Your notes stay on this device. Try again when connected.'); this.name = 'MfaUnavailableError'; }
}
export class MfaRequiredError extends Error {
  constructor(public readonly status: MfaStatus | null = null) { super('mfa_required'); this.name = 'MfaRequiredError'; }
}

const unavailable: MfaStatus = {
  available: false, setup_enabled: false, enrolled: false, satisfied: true,
  provider: null, wrong_login: false, can_enroll: false, reason: 'unavailable',
};

/** Only a missing named RPC permits the pre-migration rollout. Malformed
 * responses and outages never authorize data reads. tests/mfaStep.test.ts. */
export async function fetchMfaStatus(client: SupabaseClient): Promise<MfaStatus> {
  if (isDemoMode()) return { ...unavailable };
  let result;
  try { result = await client.rpc('mfa_status'); } catch { throw new MfaUnavailableError(); }
  if (result.error) {
    if (result.error.code === 'PGRST202') return { ...unavailable };
    throw new MfaUnavailableError();
  }
  const value: unknown = result.data;
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new MfaUnavailableError();
  const row = value as Record<string, unknown>;
  const booleanFields = ['setup_enabled', 'enrolled', 'satisfied', 'wrong_login', 'can_enroll'];
  if (row.available !== true || booleanFields.some((field) => typeof row[field] !== 'boolean') ||
      (row.provider !== null && (typeof row.provider !== 'string' || !['phrase', 'google', 'apple', 'github'].includes(row.provider))) ||
      (row.reason !== null && typeof row.reason !== 'string') ||
      (!row.enrolled && !row.satisfied && !row.wrong_login &&
        row.reason !== 'account_deleted' && row.reason !== 'account_session_required') ||
      (row.wrong_login && row.satisfied)) throw new MfaUnavailableError();
  return row as MfaStatus;
}

/** Called for each operation, without an access-token cache: another device
 * can enroll while this token stays unchanged. tests/mfaStep.test.ts. */
export async function assertMfaAccess(client: SupabaseClient): Promise<MfaStatus> {
  const status = await fetchMfaStatus(client);
  if (!status.satisfied) throw new MfaRequiredError(status);
  return status;
}

/** SQL refuses explicitly, including an enrollment racing an earlier probe.
 * This classifier never treats MFA as session expiry or device revocation. */
export function isMfaRefusal(error: unknown): boolean {
  if (error instanceof MfaRequiredError) return true;
  if (!error || typeof error !== 'object') return false;
  const row = error as { message?: unknown; error?: unknown; code?: unknown };
  return [row.message, row.error, row.code].some((value) => value === 'mfa_required' || value === 'mfa_wrong_login');
}

export type MfaPromptRequest = {
  id: number;
  provider: MfaProvider | null;
  wrongLogin: boolean;
  busy: boolean;
  error: string | null;
  allowLocalUse: boolean;
};
type Pending = {
  view: MfaPromptRequest;
  client: SupabaseClient;
  identity: string;
  factorId?: string;
  force: boolean;
  promise: Promise<void>;
  resolve: () => void;
  reject: (error: Error) => void;
};
let pending: Pending | null = null;
let nextId = 0;
let dismissedIdentity: string | null = null;
const listeners = new Set<() => void>();
const emit = () => { for (const listener of listeners) listener(); };
const subscribe = (listener: () => void) => { listeners.add(listener); return () => { listeners.delete(listener); }; };
export function getMfaPrompt(): MfaPromptRequest | null { return pending?.view ?? null; }
export function useMfaPrompt(): MfaPromptRequest | null { return useSyncExternalStore(subscribe, getMfaPrompt, () => null); }

async function currentIdentity(client: SupabaseClient): Promise<string> {
  const { data, error } = await client.auth.getSession();
  const identity = mfaSessionIdentity(data.session);
  if (error || !identity) throw new MfaUnavailableError();
  return identity;
}

/** Shared by sign-in challenges and setup verification. The storage guard
 * prevents a late SDK response from restoring a session the user left. */
export async function verifyMfaCodeForSession(client: SupabaseClient, params: { factorId: string; code: string }) {
  const identity = await currentIdentity(client);
  return withMfaSessionWriteGuard(identity, async () => {
    if (await currentIdentity(client) !== identity) throw new MfaCancelledError();
    const result = await client.auth.mfa.challengeAndVerify(params);
    if (await currentIdentity(client) !== identity) throw new MfaCancelledError();
    return result;
  });
}

/** A different session cannot inherit an old prompt. The auth event callback
 * calls this synchronously and never makes auth calls under Supabase's lock. */
export function mfaSessionChanged(session: { access_token?: string; user?: { id?: string } } | null): void {
  const identity = mfaSessionIdentity(session);
  if (pending && identity !== pending.identity) dismissMfaPrompt();
  if (identity !== dismissedIdentity) dismissedIdentity = null;
}

export function dismissMfaPrompt(): void {
  const old = pending;
  if (!old) return;
  pending = null;
  dismissedIdentity = old.identity;
  emit();
  old.reject(new MfaCancelledError());
}

/** Enrollment/removal changes the server verdict even if the token survives. */
export function notifyMfaChanged(): void {
  dismissedIdentity = null;
  if (typeof window !== 'undefined' && typeof window.dispatchEvent === 'function') window.dispatchEvent(new Event('privacynotes:mfa-changed'));
}

export async function ensureLevel2(
  client: SupabaseClient,
  options: { force?: boolean; factorId?: string; allowLocalUse?: boolean; background?: boolean } = {},
): Promise<void> {
  if (isDemoMode()) return;
  const identity = await currentIdentity(client);
  if (pending?.identity === identity) {
    if (options.force && (!pending.force || pending.factorId !== options.factorId)) throw new MfaUnavailableError();
    return pending.promise;
  }
  const status = await fetchMfaStatus(client);
  if (await currentIdentity(client) !== identity) throw new MfaCancelledError();
  if (!status.available || (status.satisfied && !options.force)) return;
  if (options.force && !status.enrolled && status.satisfied) return;
  // Managed-account deletion or an invalid broker session has no factor to
  // challenge. Account settings owns deliberate recovery; a code cannot fix it.
  if (!status.enrolled && !status.satisfied && !status.wrong_login) throw new MfaRequiredError(status);
  if (pending?.identity === identity) {
    if (options.force && (!pending.force || pending.factorId !== options.factorId)) throw new MfaUnavailableError();
    return pending.promise;
  }
  if (options.background && dismissedIdentity === identity) throw new MfaCancelledError();
  if (pending) dismissMfaPrompt();
  let resolve!: () => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<void>((yes, no) => { resolve = yes; reject = no; });
  pending = {
    view: { id: ++nextId, provider: status.provider, wrongLogin: status.wrong_login,
      busy: false, error: null, allowLocalUse: options.allowLocalUse === true },
    client, identity, factorId: options.factorId, force: options.force === true, promise, resolve, reject,
  };
  emit();
  return promise;
}

/** A new challenge is created for each submitted code so an expired or
 * IP-bound challenge can be retried. Secrets and codes never enter storage. */
export async function submitMfaCode(code: string): Promise<void> {
  const request = pending;
  if (!request || request.view.busy || request.view.wrongLogin) return;
  if (!/^\d{6}$/.test(code)) {
    request.view = { ...request.view, error: 'mfaPrompt.invalidCode' };
    emit();
    return;
  }
  request.view = { ...request.view, busy: true, error: null };
  emit();
  try {
    if (await currentIdentity(request.client) !== request.identity || pending !== request) throw new MfaCancelledError();
    const { data, error } = await request.client.auth.mfa.listFactors();
    if (error) throw new MfaUnavailableError();
    const factor = data?.totp?.find((item) => item.status === 'verified' && (!request.factorId || item.id === request.factorId));
    if (!factor) throw new Error('mfaPrompt.noFactor');
    if (await currentIdentity(request.client) !== request.identity || pending !== request) throw new MfaCancelledError();
    const verified = await verifyMfaCodeForSession(request.client, { factorId: factor.id, code });
    if (verified.error) throw new Error('mfaPrompt.verificationFailed');
    if (await currentIdentity(request.client) !== request.identity || pending !== request) throw new MfaCancelledError();
    const status = await fetchMfaStatus(request.client);
    if (!status.satisfied) throw new MfaRequiredError(status);
    if (await currentIdentity(request.client) !== request.identity || pending !== request) throw new MfaCancelledError();
    pending = null;
    dismissedIdentity = null;
    emit();
    request.resolve();
    notifyMfaChanged();
  } catch (error) {
    if (pending !== request) return;
    if (error instanceof MfaCancelledError) { dismissMfaPrompt(); return; }
    request.view = { ...request.view, busy: false,
      error: error instanceof MfaRequiredError ? 'mfaPrompt.retry' : (error instanceof MfaUnavailableError ? 'mfaPrompt.unavailable' : (error as Error).message) };
    emit();
  }
}

/** Network deadlines pause while a person reads or answers the MFA dialog.
 * The underlying operation keeps its original result and rejection. */
export function withMfaAwareTimeout<T>(operation: Promise<T>, milliseconds: number, timeout: () => T): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let remaining = milliseconds;
    let previous = Date.now();
    const timer = setInterval(() => {
      const now = Date.now();
      if (!pending) remaining -= now - previous;
      previous = now;
      if (remaining <= 0) {
        clearInterval(timer);
        try { resolve(timeout()); } catch (error) { reject(error); }
      }
    }, Math.min(250, milliseconds));
    operation.then((value) => { clearInterval(timer); resolve(value); }, (error) => { clearInterval(timer); reject(error); });
  });
}
