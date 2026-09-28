/** The Auth SDK saves a session before it returns it to the caller, so a
 * check after `await` is too late to stop a delayed response from replacing
 * another account. trustStorage calls assertSessionWrite before either storage
 * bucket changes. Two policies share that boundary and stay separate: a
 * pending MFA verification is bound to its UID and session id, whose token
 * rotates; a pending account adoption is bound to one exact access token. */

/** AAL upgrades keep the session id, even when their tokens rotate. */
export function mfaSessionIdentity(session: { access_token?: string; user?: { id?: string } } | null): string | null {
  if (!session?.user?.id || !session.access_token) return null;
  try {
    const raw = session.access_token.split('.')[1];
    if (!raw) return null;
    const payload = JSON.parse(atob(raw.replace(/-/g, '+').replace(/_/g, '/'))) as { session_id?: unknown };
    if (typeof payload.session_id !== 'string' || !payload.session_id) return null;
    return `${session.user.id}:${payload.session_id}`;
  } catch { return null; }
}

export class MfaCancelledError extends Error {
  constructor() { super('Two-factor sign-in was cancelled. Your local notes have not been removed.'); this.name = 'MfaCancelledError'; }
}

const pendingVerifications = new Map<string, number>();

/** Keep this guard until the MFA request settles, including after the dialog
 * is dismissed. A post-response identity check alone is too late. */
export async function withMfaSessionWriteGuard<T>(identity: string, operation: () => Promise<T>): Promise<T> {
  pendingVerifications.set(identity, (pendingVerifications.get(identity) ?? 0) + 1);
  try { return await operation(); }
  finally {
    const remaining = (pendingVerifications.get(identity) ?? 1) - 1;
    if (remaining) pendingVerifications.set(identity, remaining);
    else pendingVerifications.delete(identity);
  }
}

type Adoption = {
  storageKey: string;
  accessToken: string;
  userId: string;
  pubkey?: string;
  previousIdentity: string | null;
  isCurrent: () => boolean;
};
const adoptions = new Set<Adoption>();

/** Only a token read from the pending broker/PKCE HTTP response gets this
 * guard. Another login's response cannot inherit it, even for the same UID. */
export function guardAccountSessionWrite(adoption: Adoption): () => void {
  adoptions.add(adoption);
  return () => { adoptions.delete(adoption); };
}

function parse(value: string | null): { access_token?: string; user?: { id?: string; app_metadata?: { pubkey?: unknown } } } | null {
  if (!value) return null;
  try { return JSON.parse(value); } catch { return null; }
}

/** Read current storage at the write boundary so a sign-out or account switch
 * in another tab also wins. Throwing stops the SDK from broadcasting a stale
 * success afterward. New logins and ordinary rotations of the same session
 * remain allowed. */
export function assertSessionWrite(key: string, currentValue: string | null, nextValue: string): void {
  if (!pendingVerifications.size && !adoptions.size) return;
  const current = parse(currentValue);
  const next = parse(nextValue);
  const nextIdentity = mfaSessionIdentity(next);
  if (nextIdentity && pendingVerifications.has(nextIdentity) && mfaSessionIdentity(current) !== nextIdentity) {
    throw new MfaCancelledError();
  }
  for (const adoption of adoptions) {
    if (key !== adoption.storageKey || next?.access_token !== adoption.accessToken) continue;
    if (!adoption.isCurrent() || mfaSessionIdentity(current) !== adoption.previousIdentity ||
        next.user?.id !== adoption.userId ||
        (adoption.pubkey !== undefined && next.user?.app_metadata?.pubkey !== adoption.pubkey)) {
      throw new MfaCancelledError();
    }
  }
}
