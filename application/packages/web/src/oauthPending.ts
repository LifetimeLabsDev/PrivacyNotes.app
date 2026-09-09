/**
 * The pending-sign-in gate in front of the native OAuth callback.
 *
 * A privacynotes:// URL is trusted only when this install started an OAuth
 * sign-in a short time ago and has not yet consumed a callback for it. The
 * marker is written before the system browser (or the iOS sign-in sheet)
 * opens and consumed by the first callback delivered afterwards, so a URL
 * nobody asked for, a replay of one already processed, or a second delivery
 * of the same one is refused before anything in it is parsed.
 *
 * Two homes for one value. The module variable serves the warm and resume
 * paths even when storage throws. localStorage serves the cold-start path:
 * Android can kill the app process while the browser is open, and the
 * callback then arrives at a fresh process with an empty module scope.
 * Plain localStorage, never trustAwareStorage: the marker predates any trust
 * decision and must survive a restart.
 *
 * Fails closed. An unreadable store or a corrupt value reads as missing.
 * Refusing a callback costs the user one retry; accepting a foreign one
 * hands the device to another account.
 *
 * Spec: ops/docs/plans/deep-link-callback-hardening.md (section 2.1)
 */

export type OAuthPendingVerdict = 'ok' | 'missing' | 'stale';

export interface PendingStore {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

const PENDING_KEY = 'privacynotes.oauth.pending';

// Long enough for an account picker plus a second factor; a flow that takes
// longer is refused as stale and lands on the retry screen, never in a hang.
// Spec: ops/docs/plans/deep-link-callback-hardening.md (section 2.1)
export const OAUTH_PENDING_TTL_MS = 10 * 60 * 1000;

let inMemory: number | null = null;

function defaultStore(): PendingStore | null {
  try {
    return typeof localStorage === 'undefined' ? null : localStorage;
  } catch {
    return null;
  }
}

/** Record that this install just started an OAuth sign-in. */
export function markOAuthPending(
  store: PendingStore | null = defaultStore(),
  now: number = Date.now(),
): void {
  inMemory = now;
  try {
    store?.setItem(PENDING_KEY, String(now));
  } catch {
    // The in-memory copy still serves the warm path.
  }
}

/**
 * Take the marker, if any, and say whether a callback arriving now may be
 * trusted. Synchronous by contract: the handler calls it before its first
 * await, so two deliveries of one URL cannot both pass. Both copies are
 * cleared whatever the verdict.
 */
export function consumeOAuthPending(
  store: PendingStore | null = defaultStore(),
  now: number = Date.now(),
): OAuthPendingVerdict {
  const fromMemory = inMemory;
  inMemory = null;
  let fromStore: number | null = null;
  try {
    const raw = store?.getItem(PENDING_KEY);
    if (raw) {
      const n = Number(raw);
      fromStore = Number.isFinite(n) ? n : null;
    }
  } catch {
    // Unreadable reads as missing.
  }
  try {
    store?.removeItem(PENDING_KEY);
  } catch {
    // Nothing left to clear.
  }
  const started = fromMemory ?? fromStore;
  if (started === null) return 'missing';
  return now - started <= OAUTH_PENDING_TTL_MS ? 'ok' : 'stale';
}
