/**
 * Demo mode: a fully local, no-account sandbox served at
 * try.privacynotes.app. It runs the exact same app bundle; everything
 * here is gated behind a runtime hostname check so there is one codebase
 * and one deploy.
 *
 * In demo mode the app:
 *   - uses a separate, throwaway IndexedDB (DEMO_DB_NAME)
 *   - skips onboarding/auth and runs on an ephemeral, fixed-phrase key
 *   - makes zero Supabase/edge calls (sync + quota + settings are no-ops)
 *   - seeds sample content and treats the data as ephemeral: a fresh tab
 *     session starts clean, a refresh keeps edits, closing the tab clears
 *     everything (the "nothing is saved" promise).
 *
 * This module intentionally imports NO app modules, so db.ts can read
 * isDemoMode() at construction time without a circular import.
 */

const DEMO_HOSTNAME = 'try.privacynotes.app';

/**
 * Separate IndexedDB so demo data never shares a database with a real
 * install. Subdomains are already separate origins (storage is origin
 * scoped), so this is belt-and-suspenders, not the primary isolation.
 */
export const DEMO_DB_NAME = 'privacynotes-demo';

/** Where every "sign up / unlock" CTA in demo sends the user. */
// Demo conversions land on the app host, which boots signed-out
// visitors straight onto its unified auth card.
export const DEMO_APP_URL = 'https://use.privacynotes.app';

/**
 * Fixed BIP-39 mnemonic for the demo session. The keys derived from it
 * never protect anything - demo never encrypts to or syncs with a server
 * - so a public constant is fine. A fixed phrase keeps the derived
 * pubkey, and therefore the deterministic seed-note IDs, stable across
 * reloads so re-seeding stays idempotent.
 */
export const DEMO_PHRASE =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const DEMO_SESSION_KEY = 'pn:demo-session';

let cached: boolean | null = null;

/** True when the app is running as the public no-signup demo. */
export function isDemoMode(): boolean {
  if (cached !== null) return cached;
  if (typeof window === 'undefined') {
    cached = false;
    return cached;
  }
  try {
    const host = window.location.hostname;
    const params = new URLSearchParams(window.location.search);
    cached =
      host === DEMO_HOSTNAME ||
      params.get('demo') === '1' ||
      import.meta.env.VITE_DEMO_MODE === 'true';
  } catch {
    cached = false;
  }
  return cached;
}

/**
 * Bucket a CREDENTIAL storage key per mode, the way DEMO_DB_NAME
 * buckets the database and settingsLocalKey buckets settings. The
 * demo's Security tabs are deliberately usable (Pro teaser), and
 * `?demo=1` is valid on ANY origin - so unbucketed, those tabs would
 * write the SAME localStorage keys as a real signed-in account on
 * that origin, and a demo session could overwrite the real user's
 * PIN-wrapped phrase with the demo phrase. Every
 * phrase, PIN and biometric key definition goes through here, so a
 * demo session reads and writes only its own `.demo` bucket and a
 * real account's credentials are untouchable from demo. This module
 * imports nothing, so any credential module can import it cycle-free.
 */
export function credentialKey(base: string): string {
  return isDemoMode() ? `${base}.demo` : base;
}

/**
 * True when a Pro-gated feature should behave as unlocked: a real Pro
 * account, or the public demo, which unlocks everything client-side so
 * visitors can try the whole app before signing up.
 *
 * This drives BEHAVIOUR only. The gold rocket / "Pro" badges still key
 * off `isPro`, so a demo visitor uses the feature and still sees it
 * labelled as Pro - that is the whole point of the teaser.
 *
 * A server-backed feature needs more than this flag. Note history
 * lives in Supabase `note_versions` behind an `is_pro()` RLS policy
 * and demo makes zero server calls, so noteVersions.ts pairs this
 * gate with a local, demo-only snapshot store rather than reaching
 * the server.
 */
export function proUnlocked(isPro: boolean | null | undefined): boolean {
  return (isPro ?? false) || isDemoMode();
}

/**
 * Pre-render cleanup for a FRESH demo tab session: drop every
 * demo-bucketed credential (the `.demo`-suffixed keys credentialKey
 * mints - phrase, PIN cache, wrap blobs, lockout, unlocked marker).
 * Without this, a demo visitor who set a PIN and app lock leaves the
 * NEXT visitor on this browser a locked demo with an unknown PIN.
 * Called from main.tsx BEFORE React mounts, because App.tsx computes
 * its locked state synchronously at first render - an async wipe would
 * strand a fresh session behind a lock whose blob was just deleted.
 * Peeks at the session marker without consuming it; the DB wipe in
 * demoAuth.ts still sees the session as fresh afterwards. The demo
 * SETTINGS bucket survives on purpose (existing behavior - an in-tab
 * refresh keeps preferences); appLockEnabled without a blob is inert.
 */
/**
 * True for a key the demo owns. Credential keys are bucketed with a
 * `.demo` suffix by credentialKey, which is what keeps a `?demo=1`
 * session on a real install off the real account's phrase envelope,
 * PIN wrap and biometric wrap. Anything that sweeps storage in demo
 * matches on this rather than on the `privacynotes.` prefix, because
 * the prefix is exactly what the two modes share.
 */
export function isDemoOwnedKey(key: string): boolean {
  return key.endsWith('.demo');
}

export function clearFreshDemoCredentials(): void {
  if (!isDemoMode()) return;
  try {
    if (sessionStorage.getItem(DEMO_SESSION_KEY)) return;
  } catch {
    return;
  }
  for (const store of [localStorage, sessionStorage]) {
    try {
      for (let i = store.length - 1; i >= 0; i--) {
        const k = store.key(i);
        if (k && isDemoOwnedKey(k)) store.removeItem(k);
      }
    } catch {
      /* ignore */
    }
  }
}

/**
 * Returns true the first time it's called in a tab session, false on
 * every subsequent call - including after an in-tab refresh, because the
 * marker lives in sessionStorage. Used to decide whether to wipe and
 * reseed the demo DB: fresh tab session = clean slate, refresh = keep the
 * user's edits. Closing the tab clears sessionStorage, so the next visit
 * starts fresh.
 */
export function demoSessionIsFresh(): boolean {
  try {
    if (sessionStorage.getItem(DEMO_SESSION_KEY)) return false;
    sessionStorage.setItem(DEMO_SESSION_KEY, '1');
    return true;
  } catch {
    return true;
  }
}
