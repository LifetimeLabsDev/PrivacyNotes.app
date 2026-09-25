/**
 * Trust-aware storage wrapper.
 *
 * Trusted devices store secrets in localStorage (persisted across restarts).
 * Untrusted devices use sessionStorage (cleared when the tab closes).
 * Shaped like the browser Storage interface for supabase-js auth.storage.
 */

import { logAuthEvent } from './authDiag';
import { credentialKey, isDemoMode } from './demo';

const TRUST_KEY = 'privacynotes.trusted';

/** Defaults to untrusted when unset (safe for shared/public machines). */
export function isTrustedDevice(): boolean {
  try {
    const v = localStorage.getItem(TRUST_KEY);
    return v === '1';
  } catch {
    return false;
  }
}

export function setTrustedDevice(trusted: boolean): void {
  try {
    localStorage.setItem(TRUST_KEY, trusted ? '1' : '0');
  } catch {
    /* storage unavailable - nothing to persist, caller still gets in-memory session */
  }
}

/**
 * True when a session phrase is sitting in trust-aware storage (localStorage
 * or sessionStorage), meaning the app can auto-authenticate on mount.
 * Used by App.tsx to decide whether to show the loading screen: no stored
 * phrase = no session to restore = skip straight to onboarding.
 */
export function hasStoredSession(): boolean {
  // Local copy of the phrase key (authStorage would be an import
  // cycle); same demo bucket as the canonical constant.
  const key = credentialKey('privacynotes.phrase');
  try {
    if (sessionStorage.getItem(key)) return true;
  } catch { /* ignore */ }
  try {
    if (localStorage.getItem(key)) return true;
  } catch { /* ignore */ }
  return false;
}


// The auth library's own keys (the `sb-` prefix) while the demo runs.
// `?demo=1` runs on the same origin as a real install, and the demo holds
// no server session, so a client reading the shared stores would adopt the
// real account's session and refresh it over the network. In the demo those
// keys live here instead: the client starts with nothing, and the real
// session is never read, rotated or removed from a demo tab.
const demoAuthKeys = new Map<string, string>();

function isDemoAuthKey(key: string): boolean {
  return key.startsWith('sb-') && isDemoMode();
}

/** Storage-API-compatible object that supabase-js can consume directly. */
export const trustAwareStorage: Storage = {
  get length(): number {
    try {
      return sessionStorage.length + localStorage.length;
    } catch {
      return 0;
    }
  },
  clear(): void {
    if (isDemoMode()) {
      demoAuthKeys.clear();
      return;
    }
    // Scoped to the auth library's own keys (sb-*) on purpose. This
    // object is handed to supabase-js as its Storage backing; a literal
    // clear() would also destroy the phrase, the wrapped-phrase blobs
    // and the device secret - a total credential wipe from one future
    // library-internal call. Nothing calls this today (it exists to
    // satisfy the Storage interface), which is exactly when to defuse
    // it. Session audit 2026-08-25.
    for (const store of [sessionStorage, localStorage]) {
      try {
        for (let i = store.length - 1; i >= 0; i--) {
          const k = store.key(i);
          if (k && k.startsWith('sb-')) store.removeItem(k);
        }
      } catch {
        /* ignore */
      }
    }
  },
  key(index: number): string | null {
    try {
      if (index < sessionStorage.length) return sessionStorage.key(index);
      return localStorage.key(index - sessionStorage.length);
    } catch {
      return null;
    }
  },
  getItem(key: string): string | null {
    if (isDemoAuthKey(key)) return demoAuthKeys.get(key) ?? null;
    try {
      const s = sessionStorage.getItem(key);
      if (s != null) return s;
    } catch {
      /* ignore */
    }
    try {
      return localStorage.getItem(key);
    } catch {
      return null;
    }
  },
  setItem(key: string, value: string): void {
    if (isDemoAuthKey(key)) {
      demoAuthKeys.set(key, value);
      return;
    }
    const trusted = isTrustedDevice();
    // The sibling-store copy dies FIRST, in its own try. The old shape
    // (set, then remove, one try) had a poisonous failure mode: when
    // the set threw on quota, the remove never ran, the STALE copy
    // survived in the other store, and getItem - which prefers
    // sessionStorage - kept serving an already-rotated refresh token
    // until GoTrue's reuse detection revoked the whole session family.
    // A dropped write now leaves NO copy (recoverable: the phrase
    // re-mints a session) instead of a stale one (a manufactured
    // server-side revocation). Session audit 2026-08-25.
    const sibling = trusted ? sessionStorage : localStorage;
    try {
      sibling.removeItem(key);
    } catch {
      /* ignore */
    }
    try {
      (trusted ? localStorage : sessionStorage).setItem(key, value);
    } catch {
      // Quota exceeded or storage disabled. The write is lost and the
      // caller cannot tell - leave the one trace that makes this
      // debuggable when a session or phrase later comes up missing.
      logAuthEvent('storage:setItem-dropped', { key });
    }
  },
  removeItem(key: string): void {
    if (isDemoAuthKey(key)) {
      demoAuthKeys.delete(key);
      return;
    }
    try {
      localStorage.removeItem(key);
    } catch {
      /* ignore */
    }
    try {
      sessionStorage.removeItem(key);
    } catch {
      /* ignore */
    }
  },
};
