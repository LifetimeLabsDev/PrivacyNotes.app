import {
  createContext,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import {
  createSupabaseClient,
  phraseToSeed,
  deriveSigningKey,
  deriveEncryptionKey,
  deriveLocalDataKey,
  deriveFpPepper,
  deriveAuthPassword,
  authEmailForPubkey,
  bytesToHex,
  isValidPhrase,
  signLinkChallenge,
  generatePhrase,
  type SupabaseClient,
} from '@notes/shared';
import { registerLocalDataKey, clearLocalDataKey } from './localKey';
import { clearLocalDatabase, countUnsyncedNotes } from './notesRepo';
import { db } from './db';
import i18n from './i18n';
import {
  sync,
  suspendSync,
  resumeSync,
  setRemintBlocked,
  isRateLimitError,
  SessionExpiredError,
  CaptchaRequiredError,
  RateLimitedError,
} from './sync';
// PIN state is account-scoped: the hash rides in the synced settings
// blob, and clearPinCache (pin.ts) wipes every local PIN artifact at
// sign-out and on the owner-mismatch wipe.
import { clearLocalSettings, hasUnpushedSettings, loadLocalSettings, saveLocalSettings, syncUserSettings } from './userSettings';
import { isDemoMode } from './demo';
import { buildDemoAuthState } from './demoAuth';
import { ConfirmModal } from './ConfirmModal';
import { seedOnboardingNotes, SEED_MEDICATION } from './welcomeNote';
import {
  trustAwareStorage,
  setTrustedDevice,
} from './trustStorage';
import {
  adoptCustodyServer,
  getDeviceId,
  invokeFnWithRetry,
  registerDevice,
  revokeDevice,
  readFnErrorBody,
  isStaleTokenLinkError,
  isAuthUnreachableLinkError,
  isAuthRateLimitedLinkError,
  isMissingBearerLinkError,
  type DeviceRow,
  type FnError,
  type RegisterResult,
} from './devices';
import { clearStoredSource, detectChannel, getStoredSource } from './campaignSource';
import { clearPanelCache } from './accountPanelCache';
import {
  removeBiometricCredential,
  removePinWrappedPhrase,
} from './biometric';
import {
  appLockArmed,
  isWrappedEnvelope,
  persistStoredPhrase,
  unwrapStoredEnvelope,
} from './phraseAtRest';
import { clearPinCache } from './pin';
import {
  PHRASE_STORAGE_KEY,
  OAUTH_FLAG_KEY,
  SHOW_PHRASE_ONCE_KEY,
  PUBKEY_OWNER_KEY,
  ownsLocalData,
  clearAccountScopedUiState,
  hasLocalAccountState,
  switchWouldWipe,
  readCachedAccountFlags,
  writeCachedAccountFlags,
  patchCachedCustodial,
  clearCachedAccountFlags,
  hasRecentRegistration,
  markRegistered,
  clearRegistrationMarker,
  jwtPayloadPubkey,
  clearSupabaseAuthKeys,
  readOwnerMirror,
  writeOwnerMirror,
  readAccountFlagsMirror,
} from './authStorage';
import { resetAppearance } from './theme';
import { logAuthEvent } from './authDiag';
import { checkEarlySupporter, useProStatus } from './authProStatus';
import { useCustody } from './authCustody';
import { useOAuthFlows } from './authOAuth';

/**
 * "Trust this device" storage model:
 *
 * The BIP-39 phrase is stored in localStorage (trusted) or sessionStorage
 * (untrusted) based on a checkbox the user ticks at sign-in, as an
 * AES-GCM envelope under a non-extractable WebCrypto key
 * (phraseAtRest.ts), with a readable fallback only where that key
 * cannot be created. This is a deliberate trade-off documented in
 * THREAT_MODEL.md: we assume a trusted device is not compromised, and
 * code running in this origin, or a forensic parser over a complete
 * profile copy, can still recover the phrase - an attacker at that
 * level could keylog it instead. Untrusted devices clear it on tab
 * close.
 *
 * When biometric unlock is enabled, the phrase is instead wrapped with
 * a random AES-GCM key in localStorage and the device-key envelope is
 * removed. The biometric gesture (WebAuthn presence check) gates access
 * to the wrapped copy. See biometric.ts for details.
 */

// Same routing rule for the Supabase auth session: trusted devices keep
// it across reloads, untrusted devices drop it with the tab.
//
// Dev-only singleton: Vite HMR re-evaluates this module on every edit
// of auth.tsx or an accepted dependency, and each evaluation used to
// mint a fresh GoTrueClient plus another breadcrumb listener while the
// old ones stayed alive - the auth log caught 13 clients firing about
// 130 SIGNED_IN events in 800 ms after a hot-reload burst. Live
// duplicate clients also race each other's token refreshes, which can
// burn a rotated refresh token and kill the real session. Production
// evaluates this module exactly once, so the cache is inert there.
const hmrGlobal = globalThis as unknown as {
  __pnSupabase?: ReturnType<typeof createSupabaseClient>;
  __pnAuthDiagWired?: boolean;
};
const supabase =
  (import.meta.env.DEV && hmrGlobal.__pnSupabase) ||
  createSupabaseClient(
    import.meta.env.VITE_SUPABASE_URL,
    import.meta.env.VITE_SUPABASE_ANON_KEY,
    {
      storage: trustAwareStorage,
      detectSessionInUrl: true,
      // PKCE for every OAuth flow, web and native: the provider returns a
      // one-time code that only the install holding the verifier can
      // exchange, so a callback URL is worthless to anyone who did not
      // start the flow, and no token ever travels in a URL. Native pairs
      // it with the pending-sign-in gate in authOAuth.ts.
      // Spec: ops/docs/plans/deep-link-callback-hardening.md (section 3)
      flowType: 'pkce',
    },
  );
if (import.meta.env.DEV) hmrGlobal.__pnSupabase = supabase;

// Breadcrumb every lifecycle event supabase-js emits - including the
// SIGNED_OUT that fires when a definitive refresh failure removes the
// session internally, which no app code observes otherwise. This is
// the central capture for the recurring session-expired reports; the
// call sites below add the "why" next to supabase-js's "what".
// Registered once per page, not once per module evaluation - see the
// HMR note above.
if (!hmrGlobal.__pnAuthDiagWired) {
  hmrGlobal.__pnAuthDiagWired = true;
  supabase.auth.onAuthStateChange((event, session) => {
    logAuthEvent(`supabase:${event}`, {
      hasSession: session !== null,
      uid: session?.user?.id?.slice(0, 8),
      pk: (session?.user?.app_metadata?.pubkey as string | undefined)?.slice(0, 8),
    });
  });
}

/**
 * How the current session was established. Drives one behaviour:
 *   - 'oauth' sessions show the recovery phrase once on first sign-in
 *     (per-device localStorage flag) so the user knows it exists and
 *     can write it down. The phrase is the only way to access data on
 *     another device - OAuth alone is identity, not key recovery.
 *
 * Note: the sign-out reminder fires for both methods. Previously
 * suppressed for OAuth on the assumption "user can always OAuth back
 * in," which was only true while the server derived their phrase from
 * a server-side secret. See ops/docs/oauth-zk-fix.md.
 */
export type AuthMethod = 'phrase' | 'oauth';

export type AuthState =
  | { status: 'loading' }
  | { status: 'onboarding' }
  | {
      /**
       * OAuth hydration failed: the custodial lookup errored, or the
       * custodial authentication itself did. Deliberately loud - the
       * old silent fall-through offered existing users a fresh account
       * via the custody choice, which orphans their data. App.tsx
       * renders OAuthRetryScreen.
       */
      status: 'oauth_hydrate_failed';
      /** Trust choice the failed hydration ran with, reused on retry. */
      trust: boolean;
    }
  | {
      status: 'oauth_custody_choice';
      /** Supabase access token from the OAuth session. */
      accessToken: string;
      /** Supabase auth.uid from the OAuth session. */
      authUid: string;
    }
  | {
      status: 'device_limit_reached';
      // Keep everything we need to retry registration after the user
      // revokes a device. Notably NOT the phrase in URL-addressable form
      // - this state is entirely in memory.
      method: AuthMethod;
      phrase: string;
      pubkey: string;
      encryptionKey: Uint8Array;
      signingPrivateKey: Uint8Array;
      /** Per-user device-fingerprint pepper. Spec: ops/docs/device-fingerprint-hash.md (derived client-side from the seed, never sent to the server) */
      fpPepper: Uint8Array;
      deviceId: string;
      limit: number;
      devices: DeviceRow[];
    }
  | {
      status: 'authenticated';
      method: AuthMethod;
      phrase: string;
      pubkey: string; // hex
      encryptionKey: Uint8Array;
      signingPrivateKey: Uint8Array;
      /** Per-user device-fingerprint pepper. Spec: ops/docs/device-fingerprint-hash.md (derived client-side from the seed, never sent to the server) */
      fpPepper: Uint8Array;
      /** Stable per-install device identifier for this session. */
      deviceId: string;
      /** Whether the user's pubkey is on the Pro allowlist. */
      isPro: boolean;
      /** True if the user bought Pro at the early-supporter discount. */
      isEarlySupporter: boolean;
      /** True if this user's phrase is stored server-side (custodial). */
      isCustodial: boolean;
    };

export type OAuthProvider = 'google' | 'apple' | 'github';

type AuthContextValue = {
  auth: AuthState;
  supabase: SupabaseClient;
  signInWithPhrase: (
    phrase: string,
    trust: boolean,
    /**
     * True ONLY when the phrase was generated seconds ago in this
     * onboarding flow. Defaults to false: every other entry point
     * (lock-screen unlock, QR sign-in, domain-move handoff) is by
     * definition an existing vault and must never seed.
     */
    freshVault?: boolean,
    /**
     * One-shot Cloudflare Turnstile token. Consumed by the web-only
     * gate on the link-pubkey call (the GoTrue `captchaToken` options
     * are also still threaded, in case Supabase Auth CAPTCHA is ever
     * re-enabled by mistake). Only web origins are ever asked for one;
     * callers without a widget (lock-screen unlock, stored-phrase boot)
     * omit it - a refused sign-in lands the user in onboarding, which
     * has the widget.
     * Spec: ops/docs/design-decisions.md (Turnstile is web-only, enforced at link-pubkey)
     */
    captchaToken?: string
  ) => Promise<
    | { ok: true }
    /**
     * `captchaRequired` means the server refused for want of a token,
     * not that anything is wrong with the phrase. The caller renders
     * the Turnstile widget and retries with the token it produces.
     */
    | { ok: false; error: string; captchaRequired?: boolean }
  >;
  /**
   * Authenticate the app-lock screen from this device's own data.
   *
   * Enabling app lock strips the stored phrase, so a cold start carries
   * no session and nothing to auto-restore: the unlock IS the sign-in.
   * That made a reachable server a precondition for reading notes which
   * already sit in this browser, decrypted by the phrase the PIN or
   * biometric just unwrapped. This renders them from IndexedDB and
   * leaves the caller to establish the session behind the app.
   *
   * False means there is nothing local to render, and the caller falls
   * back to the network sign-in. Same eligibility and the same revoked
   * device trade as `tryFastBoot`, which does the work.
   */
  unlockLocally: (phrase: string) => Promise<boolean>;
  signInWithOAuth: (
    provider: OAuthProvider
  ) => Promise<{ ok: true; awaitPastedCode?: boolean } | { ok: false; error: string }>;
  /**
   * Finish a desktop sign-in from the code the person pasted back from the
   * return page. Desktop receives no callback of its own, because no desktop
   * operating system can say which application owns a custom scheme.
   * Spec: ops/docs/plans/oauth-redirect-binding-handoff.md (section 8.3)
   */
  completeDesktopOAuth: (
    code: string
  ) => Promise<{ ok: true } | { ok: false; error: string }>;
  /**
   * True when boot-time background revalidation hit a definitive
   * CAPTCHA rejection: the cached session is dead and silent repair is
   * impossible. NotesView shows SessionExpiredModal off this. Cleared
   * on sign-out and on any successful re-authentication. #118
   */
  revalidationExpired: boolean;
  /** keepUnsyncedNotes: preserve dirty=1 rows through the local wipe.
   * Pass it on every sign-out the user did not explicitly choose
   * (forced by the server, or a dead-end state like the device cap) -
   * a failed final flush must not cost them their unsynced notes. */
  signOut: (opts?: { keepUnsyncedNotes?: boolean }) => Promise<void>;
  /**
   * From a `device_limit_reached` state: revoke one of the existing
   * registered devices, then retry registration. On success the state
   * transitions to `authenticated`. On failure surfaces the error.
   */
  resolveDeviceLimit: (
    targetDeviceId: string,
  ) => Promise<{ ok: true } | { ok: false; error: string }>;
  /** Force a fresh local sign-out + wipe. Public so sync can trigger it on soft-revoke. */
  forceSignOut: (reason?: string) => Promise<void>;
  /** Re-check pro_pubkeys and update isPro in-place. Called after Paddle
   *  checkout, and by the background recheck (boot + focus/visibility)
   *  while the account reads free.
   *  `silent` flips Pro if the server confirms it but suppresses the
   *  "payment received, activation pending" banner - used by the
   *  browser-checkout return path, which fires whether or not the user paid.
   *  `attempts` overrides the 6x3s webhook-latency poll (the background
   *  recheck passes 1). From `device_limit_reached`, a confirmed purchase
   *  retries registration and completes the sign-in. */
  refreshProStatus: (opts?: { silent?: boolean; attempts?: number }) => Promise<void>;
  /**
   * From an `oauth_custody_choice` state: user picked custodial or
   * self-custody. Generates phrase, authenticates, and optionally
   * stores phrase server-side.
   * Spec: ops/docs/custodial-key-spec.md (server encrypts the phrase with AES-256-GCM, key held outside the database)
   */
  completeCustodyChoice: (
    choice: 'custodial' | 'self-custody',
  ) => Promise<{ ok: true; phrase: string } | { ok: false; error: string }>;
  /**
   * From an `oauth_hydrate_failed` state: re-run hydration against the
   * current Supabase session (supabase-js refreshes the token if it
   * can). A missing session cannot be retried - local sign-out, back
   * to the sign-in options.
   */
  retryOAuthHydration: (trust: boolean) => Promise<void>;
  /** From an `oauth_hydrate_failed` state: give up - local sign-out, back to sign-in options. */
  abandonOAuthHydration: () => Promise<void>;
  /**
   * Custodial -> self-custody. Deletes the server's copy of the phrase
   * and flips `isCustodial` to false. One-way: there is no inverse.
   *
   * Only call this after the user has seen their phrase and confirmed
   * they saved it. Once it returns, nothing on the server can recover
   * their notes.
   * Spec: ops/docs/custodial-key-spec.md (requires an ed25519 signature over the release challenge, not just the session JWT), backlog #112
   */
  releaseCustody: () => Promise<{ ok: true } | { ok: false; error: string }>;
  /**
   * Self-custody -> custodial. Hands the server an encrypted copy of
   * the phrase and flips `isCustodial` to true.
   *
   * This GIVES the server the ability to decrypt the user's notes.
   * Only reachable from an explicit, informed user action that says so
   * plainly. Never a fallback or a repair step.
   * Spec: ops/docs/custodial-key-spec.md (server encrypts the phrase with AES-256-GCM, key held outside the database), backlog #112
   */
  adoptCustody: () => Promise<{ ok: true } | { ok: false; error: string }>;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [auth, setAuth] = useState<AuthState>({ status: 'loading' });

  /**
   * The account-switch question, for the two doors that cannot ask for
   * themselves. `_authenticateWithPhrase` clears the prior account's
   * data, and the OAuth flows reach it from a hook and from a callback,
   * neither of which renders anything. The provider does, so the promise
   * lives here and the flows await it.
   *
   * The phrase sign-in asks in its own component instead, because it
   * races its sign-in against a timeout that a person reading a dialog
   * would lose.
   */
  const [switchAsk, setSwitchAsk] = useState<{ resolve: (ok: boolean) => void } | null>(null);
  function askAccountSwitch(): Promise<boolean> {
    return new Promise<boolean>((resolve) => setSwitchAsk({ resolve }));
  }
  function answerAccountSwitch(ok: boolean): void {
    setSwitchAsk((pending) => {
      pending?.resolve(ok);
      return null;
    });
  }

  // Snapshot of the last known access token + authUid, kept in a ref so
  // `resolveDeviceLimit` can retry registration without re-deriving
  // everything from the phrase. Lives as long as the AuthProvider - we
  // clear it on sign-out.
  const sessionRef = useRef<{ accessToken: string; authUid: string } | null>(
    null,
  );

  // Set when boot-time background revalidation got a DEFINITIVE server
  // rejection (Auth CAPTCHA refused the tokenless session re-mint): the
  // cached session is dead and cannot be repaired silently. NotesView
  // renders SessionExpiredModal off this so the user is routed to
  // re-auth instead of sitting in an authenticated shell whose sync can
  // never work. Never set on network failures - offline stays
  // tolerated. Cleared on sign-out and on any successful re-auth. #118
  const [revalidationExpired, setRevalidationExpired] = useState(false);

  // Guard against concurrent authenticateWithPhrase calls. StrictMode
  // double-mounts the useEffect in dev, firing two calls that race
  // through link-pubkey + register-device. The second hits a unique
  // constraint violation on the devices table insert → "insert_failed".
  const authInFlight = useRef(false);

  // Bumped whenever the user starts a phrase sign-in themselves (typed,
  // QR, lock-screen unlock). hydrateFromOAuthSession snapshots it on
  // entry and aborts its side effects when it changed - or when a phrase
  // handshake is running right now - so a slow OAuth hydration can never
  // stomp a sign-in the user started in the meantime. Concretely: its
  // branch-b signOut({scope:'local'}) used to land mid-handshake and
  // remove the session the handshake had just linked + registered, which
  // surfaced as "Session is missing the account link after registration"
  // on the first try (and worked on retry, because hydration had
  // finished by then).
  const userAuthGen = useRef(0);

  // Whether the vault is actually open right now, kept in a ref because the
  // native callback handler is registered once and would otherwise read a
  // status frozen at registration time.
  //
  // The native OAuth gate refuses a callback while this install is signed in,
  // so an unsolicited link can never switch a working app to another account.
  // That test used to be "a phrase is on disk", which is a proxy rather than
  // the thing: a session the library ends on its own leaves the phrase behind
  // and drops the app to the sign-in screen, and every provider button on that
  // screen was then refused in silence, for ever. Read the status instead, so
  // the refusal covers an app that IS signed in and nothing else.
  // Spec: ops/docs/plans/oauth-redirect-binding-handoff.md (section 8.8)
  const vaultOpenRef = useRef(false);
  vaultOpenRef.current =
    auth.status === 'authenticated' || auth.status === 'device_limit_reached';

  // Pending backoff for a re-mint refused on quota. One timer at a
  // time; `attempt` drives the delay and resets the moment a re-mint
  // lands. See scheduleRemintRetry.
  const remintRetry = useRef<{ attempt: number; timer: ReturnType<typeof setTimeout> | null }>({
    attempt: 0,
    timer: null,
  });

  /**
   * Disarm the pending re-mint. An unmounted provider is one reason; the
   * other two are that the account this phrase belongs to no longer owns
   * the local data, through a sign-out or through another tab taking the
   * database over, and an armed timer authenticates into it minutes later.
   */
  function cancelRemintRetry(): void {
    const r = remintRetry.current;
    if (r.timer) clearTimeout(r.timer);
    r.timer = null;
    r.attempt = 0;
  }

  // Never leave a retry armed against an unmounted provider.
  useEffect(() => () => {
    if (remintRetry.current.timer) clearTimeout(remintRetry.current.timer);
  }, []);

  /**
   * Re-run background revalidation after a quota refusal, backing off
   * each time. Nothing is surfaced to the user: the session is not
   * expired, it is unminted, so the app keeps working on local data
   * and re-mints itself once the window reopens.
   *
   * The cap is hourly, so second-scale retries would be pointless and
   * would risk holding the limiter saturated - start at a minute and
   * back off to ten. `setRemintBlocked` keeps sync's claim gate quiet
   * across the wait (plus a margin for the attempt itself), so a pass
   * firing mid-backoff cannot escalate to the re-auth prompt.
   * Spec: ops/docs/design-decisions.md (rate-limited re-mint)
   */
  function scheduleRemintRetry(phrase: string, method: AuthMethod): void {
    const REMINT_RETRY_BASE_MS = 60_000;
    const REMINT_RETRY_MAX_MS = 600_000;
    const r = remintRetry.current;
    if (r.timer) return;
    const delay = Math.min(REMINT_RETRY_BASE_MS * 2 ** r.attempt, REMINT_RETRY_MAX_MS);
    r.attempt++;
    setRemintBlocked(delay + 15_000);
    console.warn(`[auth] re-mint rate limited, retrying in ${Math.round(delay / 1000)}s`);
    // Which account owns the shared storage right now. The timer fires up
    // to ten minutes from here, and in that window another tab can sign a
    // different account into this browser: authenticating then pushes that
    // account's rows under this phrase's pubkey. So the marker is read
    // again at fire time, and any change stands the retry down, including
    // a marker that appeared or was cleared - either way the local data is
    // no longer what this phrase owns. Deriving the pubkey proves the same
    // thing and costs a key derivation on a path that runs every minute.
    let ownerAtArm: string | null = null;
    try { ownerAtArm = localStorage.getItem(PUBKEY_OWNER_KEY); } catch { /* unreadable: the compare below still holds */ }
    r.timer = setTimeout(() => {
      r.timer = null;
      let ownerNow: string | null = null;
      try { ownerNow = localStorage.getItem(PUBKEY_OWNER_KEY); } catch { /* same fallback */ }
      if (ownerNow !== ownerAtArm) {
        logAuthEvent('auth:remint-retry-abandoned');
        r.attempt = 0;
        setRemintBlocked(0);
        return;
      }
      void authenticateWithPhrase(phrase, method)
        .then((ran) => {
          // `false` means the concurrency mutex swallowed the call, so
          // nothing was proven - come back round rather than treating
          // it as success.
          if (ran) {
            r.attempt = 0;
            setRemintBlocked(0);
          } else {
            scheduleRemintRetry(phrase, method);
          }
        })
        .catch((err) => {
          if (err instanceof RateLimitedError) {
            scheduleRemintRetry(phrase, method);
            return;
          }
          console.warn('[auth] re-mint retry failed:', err);
        });
    }, delay);
  }

  async function authenticateWithPhrase(
    phrase: string,
    method: AuthMethod,
    /**
     * Tri-state on purpose. `true`/`false` assert what the caller
     * knows (the OAuth hydrate and custody-choice paths do). Omitting
     * it means "unknown": the stored-phrase boot paths run on every
     * reload and have no way to tell, so they must NOT stomp a known
     * custodial session down to self-custody. Undefined resolves from
     * the cached flag, then from the JWT claim via reconcileCustody.
     */
    custodial?: boolean,
    oauthSession?: { accessToken: string; authUid: string },
    freshVault = false,
    captchaToken?: string,
  ) {
    // Returns false when the StrictMode/concurrency mutex swallowed the
    // call, so a caller that goes on to persist something derived from
    // the authentication can tell "did not run" from "ran fine". Callers
    // that only care about the side effects can keep ignoring it.
    if (authInFlight.current) return false;
    authInFlight.current = true;
    try {
      await _authenticateWithPhrase(phrase, method, custodial, oauthSession, freshVault, captchaToken);
      // Any successful full authentication proves the session is live
      // again - clear the boot-revalidation flag so the modal never
      // outlives the problem. #118
      setRevalidationExpired(false);
      return true;
    } finally {
      authInFlight.current = false;
    }
  }

  async function _authenticateWithPhrase(
    phrase: string,
    method: AuthMethod,
    /** Tri-state; see the wrapper above. */
    custodial?: boolean,
    oauthSession?: { accessToken: string; authUid: string },
    /**
     * True only when the phrase was generated seconds ago in this
     * onboarding flow (create-vault or OAuth custody choice). A fresh
     * pubkey cannot have existing server data, so the onboarding seeds
     * are inserted right here - before the app renders - instead of
     * after the first full sync round trip. Imported phrases always
     * pass false and keep the strict post-pull seed gate in NotesView.
     */
    freshVault = false,
    /** One-shot Turnstile token - see the signInWithPhrase context
     *  type for the contract. Consumed by the link-pubkey gate below
     *  (and still threaded to GoTrue as `captchaToken` for the
     *  misclick case). OAuth callers never need it: the gate exempts
     *  users carrying a real provider email. */
    captchaToken?: string,
  ) {
    // A previous sign-out (or stale-tab bailout) may have suspended
    // sync; a new authentication always re-enables it, so a failed
    // sign-out can never leave the next session unable to sync.
    resumeSync();
    const seed = phraseToSeed(phrase);
    const { privateKey: signingPrivateKey, publicKey } = await deriveSigningKey(seed);
    const encryptionKey = deriveEncryptionKey(seed);
    // Registered at derivation time, not at setAuth: the fresh-vault
    // seed writes notes before the auth state exists, and those writes
    // must already be sealable. Spec: ops/docs/plans/local-at-rest.md (section 3.1)
    registerLocalDataKey(deriveLocalDataKey(seed));
    // Spec: ops/docs/device-fingerprint-hash.md (derived client-side from the seed, never sent to the server)
    const fpPepper = deriveFpPepper(seed);
    const pubkey = bytesToHex(publicKey);

    // Pubkey-owner check: if a different user's data is sitting in
    // IndexedDB, wipe it before we touch sync. Catches phrase swap
    // without signOut, OAuth swap on a shared device, and the family-
    // laptop handoff case. Without this, dirty rows from the prior
    // user push under the new pubkey on the first sync, and cached
    // blobs from imageCache / imageDedup leak across accounts.
    let priorOwner: string | null = null;
    let ownerReadFailed = false;
    try { priorOwner = localStorage.getItem(PUBKEY_OWNER_KEY); } catch { ownerReadFailed = true; }
    // A null owner is "unknown", not "safe". Wipe on a proven mismatch,
    // and also when the owner key is absent or unreadable but
    // account-scoped local state is present - that null-owner state is
    // what let a prior account's settings blob (PIN hash, wrapped
    // phrase, folders) be adopted by the freshVault seed and pushed
    // under the new pubkey, the same class as the PIN-cache leak. The
    // hasLocalAccountState() call only runs when the owner is unknown
    // (rare: predating install or an evicted/throwing localStorage), so
    // the normal same-owner reload path never pays for it.
    const ownerUnknown = ownerReadFailed || priorOwner === null;
    let wipePrior = priorOwner !== null && priorOwner !== pubkey;
    if (!wipePrior && ownerUnknown) {
      // Before treating "unknown owner + local state" as foreign,
      // consult the IndexedDB owner mirror (authStorage.ts): it lives
      // WITH the data it vouches for, so a localStorage eviction that
      // took the marker but left the notes no longer reads as an
      // account switch. That false positive destroyed the user's own
      // wrapped phrase and unsynced rows (session audit 2026-08-25).
      const mirror = await readOwnerMirror();
      if (mirror === pubkey) {
        logAuthEvent('auth:owner-marker-restored');
      } else if (mirror !== null) {
        wipePrior = true;
      } else {
        // No mirror (pre-v12 install or unreadable DB): the legacy
        // rule stands - unknown owner with account-scoped state
        // present wipes, because adopting a prior account's settings
        // blob is the worse failure. The mirror written below shrinks
        // this window to one boot per legacy install.
        wipePrior = await hasLocalAccountState();
      }
    }
    /**
     * The prior account's data. Runs only once the arriving account is
     * proved: session minted, pubkey linked, device registered and the
     * live token carrying the claim.
     *
     * Two things hold the line until it runs, and either alone is
     * enough. Sync refuses to start a pass at all while suspended, and
     * the owner marker still names the PRIOR account, so `ownsLocalData`
     * refuses every push and cursor write for the arriving pubkey.
     *
     * The blob stores read that same marker before each server write,
     * to stop an instance captured by an in-flight upload spending the
     * arriving account's quota. That check is open during this window,
     * and no path reaches it: a sweep needs NotesView mounted, the boot
     * and sign-in paths have no NotesView, and the one way this state
     * arrives on a mounted app is another tab taking the marker, which
     * drops this tab to the signed-out screen and unmounts it.
     */
    const wipePriorLocalData = async () => {
      await clearLocalDatabase();
      clearLocalSettings();
      clearCachedAccountFlags();
      // Drop the settings-panel figures (device list, quota, storage
      // subs) alongside the other account-scoped caches. Keyed by pubkey
      // so a stale entry could not be read by another account anyway,
      // but leaving it would keep a signed-out account's numbers on
      // disk for no reason. See accountPanelCache.ts.
      clearPanelCache();
      // Account-scoped secret material must not survive the switch:
      // the PIN hash/salt cache (the legacy-PIN migration used to
      // adopt it into the NEW account's synced settings - a
      // cross-account PIN leak), plus the biometric- and PIN-wrapped
      // phrase blobs (they hold the PRIOR user's master phrase,
      // recoverable offline; sign-out already wipes them, so the
      // no-sign-out account switch must too).
      clearPinCache();
      removeBiometricCredential();
      removePinWrappedPhrase();
      clearAccountScopedUiState();
      // The appearance axes (light/dark, palette, text size, editor
      // width, spell check, website icons, invisibles) are device-local
      // and survive a sign-out by design - the same person coming back
      // wants their own setup. A new owner is the case they must not
      // survive: they described the previous account's taste, and the
      // palette among them can be a Pro one the arriving account has
      // not paid for.
      resetAppearance();
      try { localStorage.removeItem('privacynotes.lastSync'); } catch { /* ignore */ }
      try { sessionStorage.removeItem('privacynotes.lastSync'); } catch { /* ignore */ }
      // The marker moves with the data it describes. A marker naming the
      // arriving account over the prior account's rows is the one state
      // that lets those rows push under the new pubkey, and a device
      // that dies between here and there wakes with a marker, a stored
      // phrase and a database that all still name the prior account,
      // which is the state a failed switch should leave behind.
      try { localStorage.setItem(PUBKEY_OWNER_KEY, pubkey); } catch { /* ignore */ }
      await writeOwnerMirror(pubkey);
      // Lift the suspension only now. The generation stays bumped, so
      // the prior account's pass remains stripped while new passes may
      // start.
      resumeSync();
    };

    if (wipePrior) {
      // A pass from the PRIOR account can be in flight right now (the
      // 30 s poll, a visibility tick). Bumping the generation strips it
      // of every remaining write: the push boundaries and the cursor
      // persist in sync.ts re-check it. Without this, that pass kept
      // pushing the old account's rows against the session this
      // authenticate is about to mint - server RLS refused each one,
      // and that refusal was the only thing containing it (2026-08-31).
      //
      // Sync stays off for the whole window in which this device holds
      // one account's rows and mints another account's session. Only
      // the wipe lifts it, so a handshake that fails anywhere below
      // leaves sync off until the next authentication's resumeSync()
      // at the top of this function. That is the safe direction: a
      // suspended sync loses nothing, and a resumed one would push the
      // prior account's rows under the arriving pubkey.
      suspendSync();
      // The registration marker belongs to the prior account's session
      // rather than to its data, so it goes now. Clearing it only forces
      // the full link and register pass below, which is what an arriving
      // account needs anyway.
      clearRegistrationMarker();
      // Drop the cached anon session - it carries the prior user's
      // app_metadata.pubkey claim until link-pubkey overwrites it.
      // Forcing a fresh sign-in below keeps the auth state coherent.
      //
      // OAuth callers are the exception: signOut({ scope: 'local' })
      // revokes the CURRENT session server-side (it hits GoTrue
      // /logout?scope=local), and we are about to reuse that session's
      // access token for link-pubkey and register-device. Current GoTrue
      // rejects tokens whose session_id no longer exists ("session_not_
      // found"), so revoking here 401s the entire OAuth onboarding. The
      // local-data wipe is sufficient for OAuth; the signOut is only
      // needed by the phrase path before it calls signInAnonymously below.
      // The method check matters as much as the param check (same class
      // as failHandshake below, 2026-08-25 session audit): an
      // OAuth-method BACKGROUND revalidation carries no oauthSession
      // param, and an owner-unknown false positive (evicted
      // PUBKEY_OWNER_KEY with the user's own IndexedDB intact) would
      // otherwise revoke the one session an OAuth user cannot re-mint.
      if (!oauthSession && method !== 'oauth') {
        await supabase.auth.signOut({ scope: 'local' }).catch(() => {});
      }
    } else {
      // Same owner: the marker and its mirror are refreshed here, which
      // is what repairs a localStorage eviction before anything reads it.
      try { localStorage.setItem(PUBKEY_OWNER_KEY, pubkey); } catch { /* ignore */ }
      await writeOwnerMirror(pubkey);
    }

    // Resolve a valid session. OAuth callers pass their session
    // explicitly to avoid re-reading from storage (which may be empty
    // after the pubkey-owner signOut above). Phrase-based callers fall
    // back to signInAnonymously as before.
    // True only when THIS pass created the session (password re-mint or
    // anonymous mint). failHandshake keys off it: a half-linked fresh
    // mint may be dropped for a clean retry, a cached session that was
    // healthy before this pass must never die to a transient handshake
    // failure (2026-08-25 session audit).
    let mintedThisPass = false;
    let authUid: string | undefined;
    let accessToken: string | undefined;

    if (oauthSession) {
      // Trust the caller - session was already validated by getUser()
      // in hydrateFromOAuthSession or completeCustodyChoice.
      authUid = oauthSession.authUid;
      accessToken = oauthSession.accessToken;
    } else {
      const cached = await supabase.auth.getSession();
      if (cached.data.session) {
        // Validate the cached session is still live server-side (user may
        // have been deleted via dashboard purge, etc).
        const { data: userCheck, error: userCheckError } =
          await supabase.auth.getUser();
        const checkStatus = (userCheckError as { status?: number } | null)
          ?.status;
        if (!userCheckError && userCheck.user?.id) {
          authUid = userCheck.user.id;
          accessToken = cached.data.session.access_token;
        } else if (userCheckError?.name === 'AuthSessionMissingError') {
          // The session vanished between getSession and getUser (a
          // concurrent sign-out or wipe won the race - seen when HMR
          // revalidations overlap). Nothing left to revoke; fall
          // through to the no-session handling below.
          logAuthEvent('auth:getUser-session-missing');
        } else if (
          userCheckError?.name === 'AuthApiError' &&
          (checkStatus === 401 || checkStatus === 403)
        ) {
          // The ONLY branch that may destroy a session: an explicit
          // server "no" (user purged via dashboard, session revoked,
          // banned). Allowlisted on purpose - the wipe used to be the
          // catch-all else, and the 2026-08-25 session audit confirmed
          // that a 429 (AuthApiError, not retryable in auth-js 2.112)
          // and an unparseable proxy page (AuthUnknownError) landed
          // here and destroyed healthy sessions.
          logAuthEvent('auth:getUser-failed', {
            name: userCheckError.name,
            status: checkStatus,
            code: (userCheckError as { code?: string } | null)?.code,
            message: userCheckError.message,
          });
          await supabase.auth.signOut({ scope: 'local' });
        } else {
          // Everything else - network failure, 5xx, 429 rate limit,
          // unparseable response - is not a verdict on the session,
          // the same discipline sync's claim gate documents. Proceed
          // on the cached session: every later call has its own
          // failure handling, and a genuinely dead session escalates
          // through the claim gate instead. The catch-all used to be
          // the wipe, which destroyed a healthy session on a transient
          // NetworkError - breadcrumb-proven on 2026-08-25.
          logAuthEvent('auth:getUser-unreachable', {
            name: userCheckError?.name,
            status: checkStatus,
            message: userCheckError?.message,
          });
          authUid = cached.data.session.user.id;
          accessToken = cached.data.session.access_token;
        }
      } else {
        logAuthEvent('auth:no-cached-session', {
          name: cached.error?.name,
          message: cached.error?.message,
        });
      }
    }

    // Mint a provably-fresh session from the phrase. Returning users take
    // the password grant against the credential link-pubkey attached on a
    // previous handshake (one request, no new auth user, and the roomy
    // password-grant cap instead of the tight per-IP anonymous one);
    // genuinely new accounts, accounts predating the credential, and the
    // provider-toggle-off window fall through to an anonymous mint. Throws
    // on a definitive refusal (captcha, rate limit, or an unexpected GoTrue
    // error) rather than returning a session; callers set mintedThisPass on
    // the result. Reused by the stale-token retry in the link step below.
    // Spec: ops/docs/design-decisions.md (phrase-derived auth credential)
    const remintSession = async (): Promise<{ authUid: string; accessToken: string }> => {
      if (!freshVault) {
        // Skipped when the caller KNOWS the vault is brand new: the
        // credential cannot exist yet, so the grant would be a guaranteed
        // 400.
        const { data: pwData, error: pwError } =
          await supabase.auth.signInWithPassword({
            email: authEmailForPubkey(pubkey),
            password: deriveAuthPassword(seed),
            ...(captchaToken ? { options: { captchaToken } } : {}),
          });
        if (!pwError && pwData.session?.user?.id && pwData.session.access_token) {
          return {
            authUid: pwData.session.user.id,
            accessToken: pwData.session.access_token,
          };
        }
        const pwCode = (pwError as { code?: string } | null)?.code ?? '';
        // Same taxonomy as the anonymous path below, same reasons.
        if (pwCode === 'captcha_failed' || /captcha/i.test(pwError?.message ?? '')) {
          throw new CaptchaRequiredError();
        }
        if (isRateLimitError(pwError)) {
          throw new RateLimitedError(
            `Sign-in failed: ${pwError?.message ?? 'rate limit reached'}`,
          );
        }
        // Fall through to the anonymous mint ONLY when the server said the
        // credential does not work here: not attached yet
        // (invalid_credentials) or the provider toggle is off
        // (email_provider_disabled). Every other failure - network down,
        // banned user, GoTrue surprise - throws, because an anonymous retry
        // would either fail identically (offline) or paper over a state that
        // should surface (a banned user must not quietly re-enter through a
        // fresh anonymous identity).
        if (pwCode !== 'invalid_credentials' && pwCode !== 'email_provider_disabled') {
          throw new Error(
            `Sign-in failed: ${pwError?.message ?? 'no session returned'}`,
          );
        }
      }

      const { data: signInData, error: signInError } =
        await supabase.auth.signInAnonymously(
          captchaToken ? { options: { captchaToken } } : undefined,
        );
      if (
        signInError ||
        !signInData.session?.user?.id ||
        !signInData.session.access_token
      ) {
        // A CAPTCHA rejection is a definitive server response (never a
        // network failure): with Attack Protection enforced, a tokenless
        // re-mint is refused and only an interactive, widget-bearing
        // sign-in can recover. Throw the sync layer's SessionExpiredError
        // so callers can tell "needs re-auth" from "offline" (#118).
        const code = (signInError as { code?: string } | null)?.code ?? '';
        if (code === 'captcha_failed' || /captcha/i.test(signInError?.message ?? '')) {
          // CaptchaRequiredError extends SessionExpiredError, so the
          // background-revalidation branch keeps treating this as "needs
          // re-auth" exactly as before. The sign-in screen narrows to the
          // subtype to mount the Turnstile widget instead of a dead end.
          // (GoTrue only answers this when the dashboard CAPTCHA toggle is
          // misclicked on - the real gate lives in link-pubkey below.)
          throw new CaptchaRequiredError();
        }
        // A quota refusal is a definitive "not now", never a definitive
        // "no" - RateLimitedError's doc in sync.ts carries the taxonomy.
        // Its own class so the background caller can back off and retry
        // instead of demoting the session to the re-auth prompt.
        if (isRateLimitError(signInError)) {
          throw new RateLimitedError(
            `Sign-in failed: ${signInError?.message ?? 'rate limit reached'}`,
          );
        }
        throw new Error(
          `Sign-in failed: ${signInError?.message ?? 'no session returned'}`,
        );
      }
      return {
        authUid: signInData.session.user.id,
        accessToken: signInData.session.access_token,
      };
    };

    if (!authUid || !accessToken) {
      // OAuth must never fall through to anonymous sign-in. If we got
      // here with method === 'oauth', the OAuth session was lost -
      // creating an anonymous user would bind the pubkey to the wrong
      // uid and silently break custodial phrase storage (#131).
      if (method === 'oauth') {
        logAuthEvent('auth:oauth-session-lost');
        throw new Error(
          'OAuth session lost before pubkey link. Please sign in again.',
        );
      }
      const minted = await remintSession();
      authUid = minted.authUid;
      accessToken = minted.accessToken;
      mintedThisPass = true;
    }

    const deviceId = getDeviceId(pubkey);

    // Any failure past this point leaves a half-completed handshake:
    // the session may exist but carry no usable pubkey link, and the
    // device may already be registered. If that state survives into a
    // retry, the user ends up "authenticated" with a session RLS
    // rejects - a vault that can never sync until browser data is
    // cleared. Reset the retry-relevant state so the next attempt
    // starts from a clean session and a full link + register pass.
    const failHandshake = async (err: Error): Promise<never> => {
      clearRegistrationMarker();
      // Phrase path only: drop the (possibly poisoned) anon session.
      // OAuth sessions must never be revoked here - see the pubkey-
      // owner wipe comment above for why signOut({scope:'local'})
      // would 401 the whole OAuth onboarding. The method check matters
      // as much as the param check: an OAuth-method BACKGROUND
      // revalidation carries no oauthSession param, so the param alone
      // let a transient link/register failure wipe a healthy OAuth
      // session - the same self-inflicted modal as the getUser wipe
      // above (2026-08-25). Only the phrase path can hold an anon
      // session, so only the phrase path may drop one - and only a
      // session MINTED THIS PASS: a cached session that was healthy
      // before this handshake began must survive a transient link or
      // register failure (the claim gate makes a claimless session
      // harmless, and the next revalidation repairs the link on the
      // same session). Session audit 2026-08-25.
      if (!oauthSession && method !== 'oauth' && mintedThisPass) {
        await supabase.auth.signOut({ scope: 'local' }).catch(() => {});
        sessionRef.current = null;
      }
      throw err;
    };

    // Fast path: skip link-pubkey + refreshSession for returning users
    // whose JWT already carries the correct pubkey claim. link-pubkey is
    // idempotent (re-writes the same value) and refreshSession would
    // return a JWT with the same claim - both are redundant here.
    // Security: getUser() already validated the session server-side,
    // register-device still runs its own ed25519 challenge, and RLS
    // policies see the existing JWT claim. No auth boundary is weakened.
    //
    // The fast path only applies while the registration marker is
    // fresh: without a marker (first sign-in, a cleared marker after a
    // failed handshake, or an RLS rejection observed by sync) the full
    // link runs even if the JWT claim looks right, so a claim/link
    // divergence server-side gets repaired instead of trusted.
    const jwtPubkey = jwtPayloadPubkey(accessToken);
    const needsLink = jwtPubkey !== pubkey || !hasRecentRegistration(pubkey, deviceId);

    if (needsLink) {
      // Sign `link:<uid>` with ed25519 private key. The edge function verifies
      // the signature, then writes pubkey into app_metadata (the only claim
      // RLS trusts - user_metadata is user-writable).
      //
      // Two attempts on purpose, covering the two ways this call fails
      // with a healthy-looking client (auth-session-audit section 8):
      //
      // 1. STALE TOKEN. When getUser was unreachable above we adopted the
      //    cached session's access token WITHOUT a server check (a
      //    transient error is not a verdict - session audit 2026-08-25).
      //    That token can be dead server-side - its session revoked by a
      //    rotation-reuse, a sign-out in another tab, or an admin - while
      //    still unexpired locally, so getSession hands it over and only
      //    link-pubkey's own getUser catches it, returning 401 "invalid or
      //    expired JWT". Mint a provably-fresh session from the phrase and
      //    retry the link ONCE. Phrase-only: OAuth never reaches the
      //    cached-adopt branch and must never be re-minted anonymously.
      //
      // 2. FRESH TOKEN, TRANSIENT SERVER REFUSAL. A token minted THIS
      //    pass cannot be stale, so a 401 on it is the auth backend
      //    misfiring (a platform-side JWT rejection, seen in
      //    production), and a 503
      //    `auth_unreachable` is the function saying it could not reach
      //    auth at all. Re-minting cannot help and burns the tight
      //    anonymous cap; retry the SAME token once after a short pause.
      //
      // One extra attempt total, then the failure is real and surfaces.
      // Spec: ops/docs/auth-session-audit-2026-08.md (stale cached token at link-pubkey)
      let linkError: FnError | null = null;
      let linkBody: unknown = null;
      for (let attempt = 0; attempt < 2; attempt++) {
        const signature = await signLinkChallenge(signingPrivateKey, authUid);

        // Pass Authorization header explicitly to avoid auth-state race.
        // Phrase sessions ride the credential along with the link, so the
        // server can attach it to this auth user and every FUTURE re-mint
        // becomes a password grant instead of a fresh anonymous user. The
        // server only acts on it for anonymous, email-less users, so an
        // already-credentialed user re-linking is a no-op and OAuth
        // sessions (which never send it) are untouchable either way.
        // Spec: ops/docs/design-decisions.md (phrase-derived auth credential)
        const linkResult = await invokeFnWithRetry(supabase, 'link-pubkey', {
          body: {
            pubkey,
            signature: bytesToHex(signature),
            ...(method === 'oauth' ? {} : { authPassword: deriveAuthPassword(seed) }),
            ...(captchaToken ? { captchaToken } : {}),
            // Attribution, ONLY on a brand-new vault. link-pubkey runs on
            // every sign-in (the returning-device self-heal, the 24h
            // marker refresh), so sending these unconditionally would tag
            // months-old accounts as fresh arrivals and corrupt every
            // cohort number. freshVault is true only when the phrase was
            // generated seconds ago in this onboarding flow.
            // Spec: ops/docs/plans/partner-attribution.md (section 6e)
            ...(freshVault
              ? { channel: detectChannel(), ...(getStoredSource() ? { source: getStoredSource() } : {}) }
              : {}),
          },
          headers: { Authorization: `Bearer ${accessToken}` },
        });
        linkError = (linkResult.error as FnError | null) ?? null;
        if (!linkError) break;
        linkBody = await readFnErrorBody(linkError);
        if (attempt > 0) break;
        const staleVerdict = isStaleTokenLinkError(linkError, linkBody);
        if (staleVerdict && !mintedThisPass && method !== 'oauth') {
          // Failure shape 1: the cached token we adopted is dead
          // server-side. Re-mint from the phrase and retry with a token
          // we KNOW is live; register below then rides the same fresh
          // session.
          logAuthEvent('auth:link-stale-token-remint');
          const minted = await remintSession();
          authUid = minted.authUid;
          accessToken = minted.accessToken;
          mintedThisPass = true;
          continue;
        }
        // A rate limit is the one refusal that must NOT be retried: the
        // backend reached us and asked for less traffic, so another attempt
        // a second later spends more of the same allowance and delays the
        // moment it clears.
        if (isAuthRateLimitedLinkError(linkError, linkBody)) break;
        if (staleVerdict || isAuthUnreachableLinkError(linkError, linkBody)) {
          // Failure shape 2: the token cannot be stale (fresh mint or
          // OAuth), so the refusal is the auth backend misfiring. Same
          // token, one more try.
          logAuthEvent('auth:link-transient-retry', {
            status: linkError.context?.status,
          });
          await new Promise((resolve) => setTimeout(resolve, 1200));
          continue;
        }
        break;
      }
      if (linkError) {
        // The web-only Turnstile gate refused: no token, or a spent or
        // invalid one. Deliberately NOT failHandshake - the session stays
        // cached, so the retry that carries a fresh token resumes at the
        // cached-session path above and re-invokes only this link instead
        // of minting a second anonymous user against the per-IP cap.
        // Spec: ops/docs/design-decisions.md (Turnstile is web-only, enforced at link-pubkey)
        const fnCode = (linkBody as { error?: string } | null)?.error;
        if (fnCode === 'captcha_required' || fnCode === 'captcha_failed') {
          throw new CaptchaRequiredError();
        }
        // Admin flipped the abuse-watchdog kill switch: new phrase
        // links are refused server-side. Readable copy instead of the
        // raw function error - onboarding shows this string as-is.
        if (fnCode === 'signups_paused') {
          return failHandshake(new Error(i18n.t('auth:signIn.signupsPaused')));
        }
        // Same treatment as the pause above: the raw function error says
        // nothing a person can act on, and waiting is the whole answer.
        if (fnCode === 'auth_rate_limited') {
          logAuthEvent('auth:link-rate-limited');
          return failHandshake(new Error(i18n.t('auth:signIn.rateLimited')));
        }
        // The link call carried no Authorization header, which this client
        // cannot do: it sets one explicitly, from a token already proven
        // non-empty. Something on the device or the network removed it, and
        // a content filter with HTTPS filtering is the known cause.
        //
        // Neither failHandshake nor a retry fits. The session is healthy, so
        // dropping it only spends another anonymous mint against the per-IP
        // cap, and enough attempts turn the real cause into a rate-limit
        // message that points somewhere else. The registration marker still
        // has to go: leaving a fresh one lets the next attempt take the fast
        // path and skip the very link that is failing, which reads as a
        // signed-in app that never syncs.
        // Spec: ops/docs/design-decisions.md (a filter that removes the Authorization header)
        if (isMissingBearerLinkError(linkError, linkBody)) {
          logAuthEvent('auth:link-bearer-stripped');
          clearRegistrationMarker();
          throw new Error(i18n.t('auth:signIn.authHeaderStripped'));
        }
        const detail = linkBody ? `${linkError.message} - ${JSON.stringify(linkBody)}` : linkError.message;
        return failHandshake(new Error(`link-pubkey failed: ${detail}`));
      }

      // The two words reached the server (or this was not a signup).
      // Either way this tab is done carrying them, and the promise is
      // that nothing durable is left on the app host.
      if (freshVault) clearStoredSource();

      // Pick up the new claim. Two paths on purpose:
      // - Credential sent (phrase): a successful attach SET A PASSWORD
      //   on this auth user, and GoTrue revokes the user's refresh
      //   tokens on any password change - the anonymous session this
      //   handshake is holding just died with it. refreshSession()
      //   comes back "Refresh Token Not Found" (broke every
      //   first-attach boot in live testing), so mint the post-link
      //   session with the credential itself. When the attach did NOT
      //   take (old function still deployed, provider toggle off, or
      //   the email already lives on another auth user), the grant
      //   fails, this session's refresh token was never revoked, and
      //   the refreshSession() fallback works exactly as it always did.
      // - OAuth: no credential, no password change, plain refresh.
      // Spec: ops/docs/design-decisions.md (phrase-derived auth credential)
      let sessionEstablished = false;
      if (method !== 'oauth') {
        const { data: postLink, error: postLinkErr } =
          await supabase.auth.signInWithPassword({
            email: authEmailForPubkey(pubkey),
            password: deriveAuthPassword(seed),
          });
        if (!postLinkErr && postLink.session?.access_token) {
          accessToken = postLink.session.access_token;
          sessionEstablished = true;
        }
      }
      if (!sessionEstablished) {
        const { error: refreshError } = await supabase.auth.refreshSession();
        if (refreshError) return failHandshake(new Error(`Session refresh failed: ${refreshError.message}`));

        // The refreshed session has a new access token - use that for the
        // device-registration call (and stash it for any future retry).
        const { data: refreshed } = await supabase.auth.getSession();
        accessToken = refreshed.session?.access_token ?? accessToken;
      }
    }

    sessionRef.current = { accessToken, authUid };

    // Register this device. For free-tier users past the 2-device limit
    // this comes back with the current device list so we can park in
    // the `device_limit_reached` state and let the user choose.
    //
    // Throttled: when this (pubkey, deviceId) registered successfully in
    // the last 24 h AND cached account flags exist, skip the edge
    // function entirely and reuse the cached Pro flags. See
    // DEVICE_REGISTERED_KEY above for why this is safe.
    const throttledFlags = hasRecentRegistration(pubkey, deviceId)
      ? readCachedAccountFlags(pubkey)
      : null;

    let isPro: boolean;
    let earlySup: boolean;

    if (throttledFlags) {
      isPro = throttledFlags.isPro;
      earlySup = throttledFlags.isEarlySupporter;
    } else {
      let registerResult: RegisterResult;
      try {
        registerResult = await registerDevice({
          supabase,
          accessToken,
          authUid,
          pubkey,
          signingPrivateKey,
          fpPepper,
        });
      } catch (err) {
        return failHandshake(new Error(
          `Device registration failed: ${(err as Error).message}`,
        ));
      }

      if (registerResult.status === 'limit_reached') {
        setAuth({
          status: 'device_limit_reached',
          method,
          phrase,
          pubkey,
          encryptionKey,
          signingPrivateKey,
          fpPepper,
          deviceId,
          limit: registerResult.limit,
          devices: registerResult.devices,
        });
        return;
      }

      // Registration succeeding does NOT prove this session can pass
      // RLS: register-device authenticates via its own ed25519
      // challenge, not the JWT pubkey claim. Assert the live session
      // actually carries the claim before declaring the vault healthy -
      // a mismatch here is exactly the "registered but every write
      // 401s" state a half-linked retry used to produce.
      const live = await supabase.auth.getSession();
      const liveToken = live.data.session?.access_token;
      if (!liveToken || jwtPayloadPubkey(liveToken) !== pubkey) {
        return failHandshake(new Error(
          'Session is missing the account link after registration. Please try again.',
        ));
      }

      markRegistered(pubkey, deviceId);
      isPro = registerResult.isPro;
      earlySup = isPro ? await checkEarlySupporter(supabase) : false;
    }

    // The arriving account is proved, so this is where the prior one's
    // data goes. It runs before the fresh-vault seed below, which the
    // wipe would otherwise take with it.
    if (wipePrior) await wipePriorLocalData();

    // Fresh vault: seed the onboarding notes NOW, before setAuth, so
    // NotesView's very first Dexie read already contains them - no
    // empty-vault stare while the first sync round trip (two edge
    // functions + several REST calls) completes. Safe because a
    // freshly generated pubkey cannot have existing server data; the
    // strict post-pull gate in NotesView remains the path for imported
    // phrases and the backstop if this fails (welcomeNoteSeeded stays
    // false then). Mirrors the demo bootstrap, including the example
    // medication template.
    if (freshVault) {
      try {
        await seedOnboardingNotes(pubkey);
        const s = loadLocalSettings();
        const withMed = s.medications?.some((m) => m.id === SEED_MEDICATION.id)
          ? s
          : { ...s, medications: [...(s.medications ?? []), SEED_MEDICATION] };
        saveLocalSettings({ ...withMed, welcomeNoteSeeded: true });
      } catch (err) {
        console.warn('[auth] fresh-vault seed failed (sync gate will retry):', err);
      }
    }

    // Custody: an explicit argument wins (the caller just made or just
    // read the decision). Otherwise carry the cached answer forward -
    // the stored-phrase boot paths pass nothing and would otherwise
    // demote a custodial session to self-custody on every reload,
    // hiding the "switch to self-custody" action from exactly the
    // users it exists for. reconcileCustody corrects both against the
    // JWT claim once a session is available.
    const resolvedCustodial =
      custodial ?? readCachedAccountFlags(pubkey)?.isCustodial ?? false;

    // Refresh the fast-boot cache so the next reload can render
    // immediately with up-to-date flags.
    writeCachedAccountFlags({
      pubkey,
      isPro,
      isEarlySupporter: earlySup,
      isCustodial: resolvedCustodial,
    });
    setAuth({
      status: 'authenticated',
      method,
      phrase,
      pubkey,
      encryptionKey,
      signingPrivateKey,
      fpPepper,
      deviceId,
      isPro,
      isEarlySupporter: earlySup,
      isCustodial: resolvedCustodial,
    });
  }

  /**
   * Local-first fast boot. For a returning trusted user whose notes are
   * already in IndexedDB, derive the keys from the stored phrase and mark
   * the session authenticated WITHOUT waiting for any network call. The
   * full auth path (session validation, register-device, fresh Pro flags)
   * still runs in the background and updates the state when it lands.
   *
   * Eligibility (all must hold, otherwise fall back to the slow path):
   *   - PUBKEY_OWNER_KEY matches the derived pubkey (same account owns
   *     the local IndexedDB - no cross-account leak possible)
   *   - cached account flags exist for that pubkey (written on the last
   *     successful server registration)
   *   - IndexedDB actually has notes (a wiped DB means a full pull is
   *     needed anyway, so the loading state is honest)
   *
   * Security: identical to the offline case that already exists - the
   * notes are on disk and the phrase decrypts them locally. A revoked
   * device is still caught by the heartbeat on the first sync and gets
   * force-signed-out; it just sees its own local data a moment sooner.
   *
   * Returns true if the fast boot rendered an authenticated state.
   */
  async function tryFastBoot(phrase: string, method: AuthMethod): Promise<boolean> {
    try {
      const seed = phraseToSeed(phrase);
      const { privateKey: signingPrivateKey, publicKey } = await deriveSigningKey(seed);
      const encryptionKey = deriveEncryptionKey(seed);
      registerLocalDataKey(deriveLocalDataKey(seed));
      const fpPepper = deriveFpPepper(seed);
      const pubkey = bytesToHex(publicKey);

      let owner: string | null = null;
      let ownerReadFailed = false;
      try { owner = localStorage.getItem(PUBKEY_OWNER_KEY); } catch { ownerReadFailed = true; }
      if (owner === null || ownerReadFailed) {
        // No marker, but that is not the same as no owner. Safari and
        // iOS clear localStorage after seven days without a visit and
        // leave Dexie alone, so the notes outlive the thing that says
        // whose they are. The mirror lives WITH the data it vouches
        // for, which is why wipePrior already trusts it for the far
        // more destructive call. Both absent still reads as unknown,
        // and unknown never boots.
        const mirror = await readOwnerMirror();
        if (mirror !== pubkey) return false;
        logAuthEvent('auth:fast-boot-owner-from-mirror');
      } else if (owner !== pubkey) {
        // A marker naming somebody else is a real answer, not a gap.
        return false;
      }

      // Same eviction, same fallback: these two gates share a storage
      // area, so mirroring one without the other would still strand
      // the boot on the network path.
      const cached = readCachedAccountFlags(pubkey) ?? (await readAccountFlagsMirror(pubkey));
      if (!cached) {
        // Ownership is settled by this point, so these notes are
        // certainly this user's and only the Pro answer is missing -
        // which an install whose flags predate the mirror loses to the
        // same eviction. Refusing the boot over that trades "your notes
        // are unreachable" for "your Pro badge is a few seconds late",
        // which is the wrong way round. The handshake writes the real
        // answer when it lands, and reconcileCustody fixes custody off
        // the JWT claim.
        logAuthEvent('auth:fast-boot-flags-defaulted');
      }
      const flags = cached ?? { pubkey, isPro: false, isEarlySupporter: false };

      const localCount = await db.notes.count();
      if (localCount === 0) {
        // The one exit that genuinely has nothing to show. The boot
        // path's demote reads this as the only reason fast boot ever
        // declines, so say it in the log rather than leaving the next
        // reader to infer it.
        logAuthEvent('auth:fast-boot-no-local-notes');
        return false;
      }

      setAuth({
        status: 'authenticated',
        method,
        phrase,
        pubkey,
        encryptionKey,
        signingPrivateKey,
        fpPepper,
        deviceId: getDeviceId(pubkey),
        isPro: flags.isPro,
        isEarlySupporter: flags.isEarlySupporter,
        // Carry the cached answer. Absent (flags written before the
        // field existed) reads as self-custody, and reconcileCustody
        // corrects it from the JWT claim a moment later.
        isCustodial: flags.isCustodial === true,
      });
      return true;
    } catch (err) {
      console.warn('[auth] fast boot failed, falling back to full auth:', err);
      return false;
    }
  }

  /**
   * The app-lock screen's local door. See the context type for why it
   * exists; `tryFastBoot` above owns the eligibility rules and the
   * security reasoning, and this adds only the breadcrumb, so a report
   * of "the lock let me in with no network" names its own cause.
   */
  async function unlockLocally(phrase: string): Promise<boolean> {
    const booted = await tryFastBoot(phrase, 'phrase');
    logAuthEvent(booted ? 'auth:applock-local-unlock' : 'auth:applock-local-unlock-unavailable');
    return booted;
  }

  async function resolveDeviceLimit(
    targetDeviceId: string,
  ): Promise<{ ok: true } | { ok: false; error: string }> {
    if (auth.status !== 'device_limit_reached') {
      return { ok: false, error: 'No pending device-limit state.' };
    }
    const session = sessionRef.current;
    if (!session) {
      return { ok: false, error: 'Session token unavailable; sign in again.' };
    }

    try {
      await revokeDevice({
        supabase,
        accessToken: session.accessToken,
        authUid: session.authUid,
        signingPrivateKey: auth.signingPrivateKey,
        targetDeviceId,
      });
    } catch (err) {
      return { ok: false, error: (err as Error).message };
    }
    return retryRegistrationFromLimit();
  }

  /**
   * Re-run device registration from the `device_limit_reached` state and,
   * on success, complete the interrupted sign-in. Two callers: after a
   * revoke frees a slot (resolveDeviceLimit) and after a Pro purchase
   * lifts the cap entirely (refreshProStatus).
   *
   * Single-flight: the purchase path can fire twice off one OS focus
   * event (billing.ts refreshOnReturn plus the background recheck
   * below), and concurrent registerDevice calls race the server's
   * insert into a unique-constraint 500. Concurrent callers share one
   * attempt. Worst case for a revoke-then-retry joining a pre-revoke
   * attempt is a stale "Limit still reached" result, which the modal
   * already handles by re-surfacing the list.
   */
  const limitRetryInFlight = useRef<
    Promise<{ ok: true } | { ok: false; error: string }> | null
  >(null);
  function retryRegistrationFromLimit(): Promise<
    { ok: true } | { ok: false; error: string }
  > {
    if (limitRetryInFlight.current) return limitRetryInFlight.current;
    const run = doRetryRegistrationFromLimit().finally(() => {
      limitRetryInFlight.current = null;
    });
    limitRetryInFlight.current = run;
    return run;
  }

  async function doRetryRegistrationFromLimit(): Promise<
    { ok: true } | { ok: false; error: string }
  > {
    if (auth.status !== 'device_limit_reached') {
      return { ok: false, error: 'No pending device-limit state.' };
    }
    const session = sessionRef.current;
    if (!session) {
      return { ok: false, error: 'Session token unavailable; sign in again.' };
    }

    try {
      const retry = await registerDevice({
        supabase,
        accessToken: session.accessToken,
        authUid: session.authUid,
        pubkey: auth.pubkey,
        signingPrivateKey: auth.signingPrivateKey,
        fpPepper: auth.fpPepper,
      });

      // Both setAuth calls below are functional updates guarded on the
      // device-limit state still standing for this pubkey: the register
      // call above awaited, and the user may have signed out (or a
      // concurrent caller may have resolved the limit) meanwhile - an
      // unguarded write would resurrect the dismissed state.
      if (retry.status === 'limit_reached') {
        // Shouldn't happen (a slot was just freed or the cap was just
        // lifted), but if it does - re-surface the new list so the UI
        // stays consistent.
        setAuth((prev) =>
          prev.status === 'device_limit_reached' && prev.pubkey === auth.pubkey
            ? {
                status: 'device_limit_reached',
                method: auth.method,
                phrase: auth.phrase,
                pubkey: auth.pubkey,
                encryptionKey: auth.encryptionKey,
                signingPrivateKey: auth.signingPrivateKey,
                fpPepper: auth.fpPepper,
                deviceId: auth.deviceId,
                limit: retry.limit,
                devices: retry.devices,
              }
            : prev,
        );
        return { ok: false, error: 'Limit still reached. Try again.' };
      }

      const earlySup2 = retry.isPro ? await checkEarlySupporter(supabase) : false;
      markRegistered(auth.pubkey, auth.deviceId);
      // A custodial OAuth user can hit the device limit like anyone
      // else, so carry the cached answer rather than assuming.
      const custodial2 = readCachedAccountFlags(auth.pubkey)?.isCustodial === true;
      writeCachedAccountFlags({
        pubkey: auth.pubkey,
        isPro: retry.isPro,
        isEarlySupporter: earlySup2,
        isCustodial: custodial2,
      });
      setAuth((prev) =>
        prev.status === 'device_limit_reached' && prev.pubkey === auth.pubkey
          ? {
              status: 'authenticated',
              method: auth.method,
              phrase: auth.phrase,
              pubkey: auth.pubkey,
              encryptionKey: auth.encryptionKey,
              signingPrivateKey: auth.signingPrivateKey,
              fpPepper: auth.fpPepper,
              deviceId: auth.deviceId,
              isPro: retry.isPro,
              isEarlySupporter: earlySup2,
              isCustodial: custodial2,
            }
          : prev,
      );
      return { ok: true };
    } catch (err) {
      return { ok: false, error: (err as Error).message };
    }
  }

  // On mount:
  //   1. If a valid phrase is in trust-aware storage, auto-auth with it
  //      (method = 'phrase'). Covers anonymous users and returning
  //      OAuth users on the same device.
  //   2. Otherwise, check for an existing Supabase OAuth session -
  //      happens after a Google/Apple redirect lands back in the app.
  //      If found, hand off to hydrateFromOAuthSession which either
  //      (a) generates a fresh phrase client-side for new OAuth users,
  //      or (b) routes existing OAuth users to phrase entry because
  //      their keys live only on their devices, not on the server.
  //   3. Fall through to onboarding.
  //
  // Reads sessionStorage first, then localStorage (trust-aware).
  useEffect(() => {
    // Demo mode: skip all auth, storage, and OAuth handling. Derive
    // ephemeral keys from a fixed phrase, seed sample content into the
    // throwaway demo DB, and mark the session authenticated. No network,
    // no account, no persisted secrets. See demo.ts.
    if (isDemoMode()) {
      void (async () => {
        try {
          setAuth(await buildDemoAuthState());
        } catch (err) {
          console.error('Demo init failed:', err);
          setAuth({ status: 'onboarding' });
        }
      })();
      return;
    }

    const stored = trustAwareStorage.getItem(PHRASE_STORAGE_KEY);
    // The stored value is a wrapped envelope (phraseAtRest.ts), or
    // legacy plaintext on an install that predates the wrap. Presence
    // plus shape decides the restore path SYNCHRONOUSLY - the envelope
    // itself only opens inside the async block below, and everything
    // that must not wait for it (the demo short-circuit above, the
    // OAuth listener and 15 s timeout in the else branch) already ran
    // or never runs on this path.
    if (stored && (isWrappedEnvelope(stored) || isValidPhrase(stored))) {
      // Strip OAuth hash fragment here - in the stored-phrase fast-path
      // we authenticate from the cached phrase and never need supabase-js
      // to parse the URL. Without this, returning OAuth users who already
      // have a stored phrase keep #access_token=... visible in the address
      // bar forever because the early return skips onAuthStateChange and
      // the belt-and-suspenders timer. GitHub #48.
      //
      // IMPORTANT: this MUST NOT run before the stored-phrase check.
      // supabase-js auth-js@2.103.0 reads window.location.href
      // asynchronously (behind navigator.locks / Web Locks API), so
      // stripping the hash earlier would race with _initialize() and
      // break fresh OAuth sign-ins that have no stored phrase yet.
      if (window.location.hash.includes('access_token=')) {
        history.replaceState(null, '', window.location.pathname + window.location.search || '/');
      }
      // We tag the session as 'phrase' here by default. An OAuth-origin
      // session stashes a companion flag when it seeds the phrase, so
      // we can recover the method across reloads.
      const method: AuthMethod =
        trustAwareStorage.getItem(OAUTH_FLAG_KEY) === '1' ? 'oauth' : 'phrase';
      void (async () => {
        // Open the at-rest envelope first. A legacy plaintext value is
        // used as-is and re-persisted as an envelope in the background
        // (the overwrite lands in the same slot, so the persist IS the
        // migration). An envelope that will not open - the wrap key
        // was cleared out from under it - demotes to sign-in, where
        // re-entering the phrase repairs everything; nothing else is
        // wiped (a storage hiccup is not a verdict, session audit
        // section 0).
        let phrase: string;
        if (isWrappedEnvelope(stored)) {
          const opened = await unwrapStoredEnvelope(stored);
          if (!opened || !isValidPhrase(opened)) {
            logAuthEvent('auth:boot-demoted', { name: 'PhraseUnwrapFailed' });
            setAuth({ status: 'onboarding' });
            return;
          }
          phrase = opened;
        } else {
          phrase = stored;
          logAuthEvent('auth:phrase-persisted', { by: 'boot-rewrap' });
          void persistStoredPhrase(stored);
        }

        // Local-first: render the authenticated app from IndexedDB
        // immediately when eligible. See tryFastBoot for the criteria.
        const fastBooted = await tryFastBoot(phrase, method);

        // Full auth still runs - as the blocking path when fast boot was
        // not possible, or as background revalidation when it was. It
        // refreshes the session, registers the device and updates Pro
        // flags (or transitions to device_limit_reached) when it lands.
        if (fastBooted) {
          authenticateWithPhrase(phrase, method).catch((err) => {
            // A CAPTCHA rejection is a definitive server "no" - the dead
            // session cannot be re-minted without the widget, and sync's
            // own auth detection never fires (with no session at all,
            // supabase-js falls back to the anon key, whose errors don't
            // look like JWT problems). Surface the re-auth modal. #118
            // Checked before SessionExpiredError purely for reading
            // order - the two classes are unrelated on purpose, so
            // that a quota refusal can never reach the re-auth prompt.
            if (err instanceof RateLimitedError) {
              scheduleRemintRetry(phrase, method);
              return;
            }
            if (err instanceof SessionExpiredError) {
              setRevalidationExpired(true);
              return;
            }
            // Any other background failure must NOT demote the session:
            // this is exactly the offline case, and the local data is
            // the user's own. Sync surfaces session problems through its
            // own error paths (SessionExpiredModal, sync error banner).
            console.warn('[auth] background revalidation failed:', err);
          });
          return;
        }

        // Race against a 15-second timeout so a hanging network call
        // (VPN, flaky mobile data, Cloudflare block) doesn't trap the
        // user on the loading screen indefinitely.
        const AUTH_TIMEOUT_MS = 15_000;
        Promise.race([
          authenticateWithPhrase(phrase, method),
          new Promise<never>((_, reject) =>
            setTimeout(() => reject(new Error('Auth timed out - network may be unreachable.')), AUTH_TIMEOUT_MS),
          ),
        ]).catch((err) => {
          console.error('Auto sign-in failed:', err);
          // Same taxonomy as the fast-boot branch above (session audit
          // 2026-08-25): a rate limit is "not now", never "sign in
          // again" - arm the backoff so the session re-mints by itself
          // once the cap clears. The onboarding demote still runs, and
          // by this point it is the honest answer: fast boot declined,
          // which now means either no notes on this device or an owner
          // neither the marker nor the db.kv mirror could name. The
          // second is unknowable rather than empty, and rendering it
          // would hand one account another's notes. Its own breadcrumb
          // says which happened.
          if (err instanceof RateLimitedError) {
            scheduleRemintRetry(phrase, method);
          }
          logAuthEvent('auth:boot-demoted', {
            name: (err as Error | null)?.name,
            message: (err as Error | null)?.message,
          });
          setAuth({ status: 'onboarding' });
        });
      })();
      return;
    }

    const unregisterOAuthListener = registerOAuthListener();

    // Belt-and-suspenders: if neither handler stripped the hash (e.g.
    // ineligible provider, timing edge case), clear it eventually so the
    // JWT never lingers in the address bar. See gap #59. The delay was
    // 2 s, which raced the callback processing itself: supabase-js reads
    // window.location.href asynchronously (behind navigator.locks) and
    // the validation round-trip alone was measured starting at +2.0 s on
    // a cold connection. Success and failure paths both strip the hash
    // themselves, so this only exists for pathological cases and can
    // afford to be late.
    const stripTimer = setTimeout(() => {
      if (window.location.hash.includes('access_token=')) {
        history.replaceState(null, '', window.location.pathname + window.location.search || '/');
      }
    }, 15_000);

    return () => {
      unregisterOAuthListener();
      clearTimeout(stripTimer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /**
   * `freshVault` must be passed explicitly by the caller that knows the
   * phrase was just generated (Onboarding's create flow). It used to be
   * inferred here from the ambient `privacynotes.phraseImport` session
   * marker, which only Onboarding ever sets - so every other caller
   * (lock-screen unlock, QR sign-in, the domain-move handoff) read the
   * absent marker as "fresh vault" and re-seeded the onboarding notes
   * into an established account. The seed ids are deterministic per
   * pubkey, so that resurrected welcome notes the user had deleted and
   * overwrote edits they had made to them. The default is false so a
   * new call site can only ever be too conservative, never destructive.
   */
  async function signInWithPhrase(
    phrase: string,
    trust: boolean,
    freshVault = false,
    captchaToken?: string,
  ) {
    // The demo authenticates itself from a fixed phrase and holds no server
    // session, so every server call it could make is guarded at its own site.
    // This one is guarded here instead, because the demo can reach it: `?demo=1`
    // runs on the same origin as a real install, an app lock armed there
    // survives an in-tab refresh, and an unlock that completes before the
    // demo's own asynchronous authentication lands falls through to the
    // sign-in path. A successful call would claim the pubkey-owner marker
    // this origin shares with the real account.
    if (isDemoMode()) {
      return { ok: false as const, error: 'Sign-in is disabled in the demo.' };
    }
    const trimmed = phrase.trim().toLowerCase();
    if (!isValidPhrase(trimmed)) {
      return {
        ok: false as const,
        error: 'Invalid phrase. Check spelling and word order.',
      };
    }
    try {
      // Mark this as a user-initiated sign-in so a still-pending OAuth
      // hydration aborts instead of signing out / setAuth-ing over the
      // handshake this call is about to run. See userAuthGen.
      userAuthGen.current++;
      // Flip the trust flag BEFORE we authenticate so every supabase-js
      // write that happens during sign-in (session row, refresh token)
      // lands in the correct backing store from the first write.
      setTrustedDevice(trust);
      // Keep a live OAuth session when this phrase belongs to it.
      //
      // hydrateFromOAuthSession branch (b) routes a self-custody OAuth
      // user here to unlock with their phrase. Passing no session made
      // _authenticateWithPhrase treat them as a phrase-only caller: on
      // a device whose PUBKEY_OWNER_KEY held a different vault,
      // wipePrior fires, the `if (!oauthSession)` guard runs
      // signOut({scope:'local'}) on the very session they just created,
      // getSession() then finds nothing, and it falls through to
      // signInAnonymously. The user signed in with Google and landed on
      // an anonymous session, with their pubkey linked to a fresh
      // auth.users row - so one pubkey spanned two accounts and
      // everything keyed on auth_uid (custodial storage, devices,
      // quotas) pointed at the anonymous one. Backlog #115.
      //
      // Deliberately narrow: the session is reused ONLY when its
      // app_metadata.pubkey already equals the pubkey this phrase
      // derives, i.e. the phrase provably belongs to the signed-in
      // account. That is exactly branch (b)'s case. Any other
      // combination (different vault's phrase typed under someone's
      // OAuth session, QR handoff, domain move) keeps the old
      // anonymous path rather than re-pointing a live OAuth account's
      // app_metadata at a different vault.
      let oauthSession: { accessToken: string; authUid: string } | undefined;
      try {
        const { publicKey } = await deriveSigningKey(phraseToSeed(trimmed));
        const derivedPubkey = bytesToHex(publicKey);
        const { data } = await supabase.auth.getSession();
        const session = data.session;
        const provider = session?.user?.app_metadata?.provider;
        const isOAuth =
          provider === 'google' || provider === 'apple' || provider === 'github';
        if (
          session?.access_token &&
          session.user?.id &&
          isOAuth &&
          jwtPayloadPubkey(session.access_token) === derivedPubkey
        ) {
          oauthSession = {
            accessToken: session.access_token,
            authUid: session.user.id,
          };
        }
      } catch {
        // Offline, unreadable session, whatever: fall back to the
        // pre-existing behaviour rather than blocking sign-in.
      }

      // A fresh vault seeds its onboarding notes during authentication
      // (see _authenticateWithPhrase). NotesView's post-pull seed gate
      // still consumes the phraseImport marker separately - that gate is
      // safe because it runs after the pull, when the client knows
      // whether the server actually had data.
      const ran = await authenticateWithPhrase(trimmed, 'phrase', false, oauthSession, freshVault, captchaToken);
      // A swallowed call (mutex held by a concurrent handshake) must
      // not read as success: the persist below writes shared storage
      // over whatever that handshake is signing in, and the caller
      // would report a sign-in that never happened - the QR / domain-
      // move confirm would close over nothing. Same discipline as
      // completeCustodyChoice (v0.262.3).
      if (!ran) {
        return {
          ok: false as const,
          error: 'Sign-in is already in progress. Please try again.',
        };
      }
      // Persist as a wrapped envelope - with ONE exception. When app
      // lock is armed (the setting on and a PIN or biometric wrap
      // present), the stored copy was deliberately stripped when the
      // lock was enabled, and this call is the post-unlock re-sign-in.
      // Writing the phrase back here silently un-did the lock's whole
      // promise on the first unlock, permanently (pre-launch audit
      // 2026-08-28, finding 8). The phrase stays memory-only; the next
      // boot goes through the lock screen again, which is the promise.
      // The same test now runs on the OAuth custodial path, which
      // reaches this write too. See appLockArmed in phraseAtRest.ts.
      if (appLockArmed()) {
        logAuthEvent('auth:phrase-persist-skipped-applock');
      } else {
        // Named because a write landing here AFTER a sign-out is how an
        // install ends up holding a phrase it is not using, and the log is
        // the only place that race is visible.
        // Spec: ops/docs/plans/oauth-redirect-binding-handoff.md (section 8.8)
        logAuthEvent('auth:phrase-persisted', { by: 'authenticate' });
        await persistStoredPhrase(trimmed);
      }
      // A phrase-sign-in clears any stale OAuth flag - someone can
      // legitimately sign out of OAuth and back in with the phrase, and
      // we want the sign-out reminder to come back.
      trustAwareStorage.removeItem(OAUTH_FLAG_KEY);
      return { ok: true as const };
    } catch (err) {
      // Surface "the server wants a CAPTCHA token" as a flag rather than
      // a message: the sign-in screens react to it by mounting the
      // Turnstile widget, and matching on error text would break the
      // moment the server rewords itself.
      return {
        ok: false as const,
        error: (err as Error).message,
        captchaRequired: err instanceof CaptchaRequiredError,
      };
    }
  }

  // Cross-tab account switch. localStorage is shared between tabs, so
  // another tab authenticating a different account silently takes
  // ownership of the Dexie database and the settings blob this tab is
  // still reading and writing. Left running, this tab writes its notes
  // into their database (LocalNote carries no owner column) where the
  // owning tab re-encrypts and pushes them under ITS pubkey, and its own
  // sync pushes their rows under ours. Drop to the signed-out screen the
  // moment the owner key changes: NotesView unmounts, which stops the
  // sync and heartbeat pollers. The wipe is NOT run - the local data
  // belongs to the new account now. See ownsLocalData.
  useEffect(() => {
    function onOwnerChange(e: StorageEvent) {
      if (e.key !== PUBKEY_OWNER_KEY || !e.newValue) return;
      // A pass from this tab's account can be in flight while the other
      // tab takes over the shared storage. The generation bump strips
      // it of its remaining writes (push boundaries, cursor persist);
      // the next authentication in this tab calls resumeSync.
      suspendSync();
      // A pending re-mint would authenticate into the storage the other
      // tab now owns.
      cancelRemintRetry();
      setAuth((prev) =>
        prev.status === 'authenticated' && prev.pubkey !== e.newValue
          ? { status: 'onboarding' }
          : prev,
      );
    }
    window.addEventListener('storage', onOwnerChange);
    return () => window.removeEventListener('storage', onOwnerChange);
  }, []);

  const {
    registerOAuthListener,
    signInWithOAuth,
    completeDesktopOAuth,
    retryOAuthHydration,
    abandonOAuthHydration,
  } = useOAuthFlows({
    authenticateWithPhrase,
    askAccountSwitch,
    setAuth,
    supabase,
    authInFlight,
    userAuthGen,
    vaultOpenRef,
  });

  /**
   * Complete the custody choice for a new OAuth user.
   * Called from the KeyCustodyChoice onboarding component.
   * Spec: ops/docs/custodial-key-spec.md (server encrypts the phrase with AES-256-GCM, key held outside the database)
   */
  async function completeCustodyChoice(
    choice: 'custodial' | 'self-custody',
  ): Promise<{ ok: true; phrase: string } | { ok: false; error: string }> {
    if (auth.status !== 'oauth_custody_choice') {
      return { ok: false, error: 'Not in custody choice state.' };
    }
    const { accessToken, authUid } = auth;
    const isCustodial = choice === 'custodial';

    try {
      const phrase = generatePhrase();
      // A phrase generated this second owns nothing, so this asks
      // whether the account already on the device may be cleared. An
      // empty error is a decline rather than a failure: the choice
      // screen stays as it was and says nothing.
      if (await switchWouldWipe(phrase) && !(await askAccountSwitch())) {
        return { ok: false, error: '' };
      }
      // Pass the OAuth session explicitly so _authenticateWithPhrase
      // never falls through to signInAnonymously (#131). The phrase was
      // generated this second, so this is a fresh vault: seed during
      // authentication instead of after the first sync round trip.
      //
      // Self-custody until the server confirms it holds the phrase. The
      // custodial flag says the account can be recovered without the
      // phrase, and a flag raised before a store that then fails leaves
      // that claim on the device with nothing behind it: the phrase is
      // never shown and the sign-out reminder stays quiet. The store needs
      // the linked pubkey this call creates, so the order cannot be the
      // other way round; the flag is raised below, after the store, the
      // way adoptCustody in authCustody.ts does it.
      const authenticated = await authenticateWithPhrase(phrase, 'oauth', false, {
        accessToken,
        authUid,
      }, true);
      // A swallowed call (mutex held by a concurrent handshake) must not
      // read as success: sessionRef would still carry the OTHER
      // handshake's token, and the store-custodial-phrase call below
      // derives its target account from exactly that token - overwriting
      // an unrelated account's custodial phrase with this one and
      // locking that account out of 1-click sign-in permanently.
      if (!authenticated) {
        throw new Error('Sign-in is already in progress. Please try again.');
      }
      logAuthEvent('auth:phrase-persisted', { by: 'oauth-custody' });
      await persistStoredPhrase(phrase);
      trustAwareStorage.setItem(OAUTH_FLAG_KEY, '1');

      if (isCustodial) {
        // Store phrase server-side for 1-click sign-in on future devices.
        // Use the refreshed access token from sessionRef (link-pubkey may
        // have triggered a session refresh during authenticateWithPhrase).
        const storeToken = sessionRef.current?.accessToken ?? accessToken;
        const storeUid = sessionRef.current?.authUid ?? authUid;
        // link-pubkey ran inside authenticateWithPhrase above, so the
        // pubkey is linked and the signature the endpoint now demands
        // can be produced. Derive the signing key from the phrase
        // rather than plumbing it out of the auth state.
        const { privateKey: storeSigningKey, publicKey: storePublicKey } = await deriveSigningKey(
          phraseToSeed(phrase),
        );
        try {
          await adoptCustodyServer({
            supabase,
            accessToken: storeToken,
            authUid: storeUid,
            signingPrivateKey: storeSigningKey,
            phrase,
          });
        } catch (storeErr) {
          // The account is self-custody, because that is what it is: the
          // server holds no phrase, so a new device has nothing to sign in
          // with but the words (#131). The choice screen is gone by now,
          // so the phrase is shown the way the self-custody branch shows
          // it, and the one copy in existence gets seen.
          trustAwareStorage.setItem(SHOW_PHRASE_ONCE_KEY, '1');
          throw new Error(
            `Failed to store custodial phrase: ${(storeErr as Error).message}`,
          );
        }
        const storedPubkey = bytesToHex(storePublicKey);
        patchCachedCustodial(storedPubkey, true);
        setAuth((prev) =>
          prev.status === 'authenticated' && prev.pubkey === storedPubkey
            ? { ...prev, isCustodial: true }
            : prev,
        );
      } else {
        // Self-custody: show phrase once so user can write it down.
        trustAwareStorage.setItem(SHOW_PHRASE_ONCE_KEY, '1');
      }

      return { ok: true, phrase };
    } catch (err) {
      return { ok: false, error: (err as Error).message };
    }
  }

  async function signOut(opts?: { keepUnsyncedNotes?: boolean }) {
    setRevalidationExpired(false);
    // Before anything else: a pending re-mint would authenticate this
    // phrase again minutes after the user signed out.
    cancelRemintRetry();
    // Stale tab: another tab signed a DIFFERENT account into this
    // browser after we authenticated, so the shared Dexie database and
    // localStorage now belong to that account. Everything below would
    // act on their data with our identity - the final sync would push
    // THEIR rows to OUR account, and the wipe would delete their notes,
    // settings and stored phrase. This path is reached without any user
    // intent: a revoked device (our row was revoked when they signed
    // out) makes the heartbeat force a sign-out here. Drop this tab's
    // own state and leave the shared storage alone.
    //
    // Keys are deliberately not zeroed: a sync may still be in flight in
    // this tab, and zeroing mid-write would push garbage ciphertext.
    // Dropping the state releases them for GC.
    //
    // The test reads the pubkey off whichever status carries one rather
    // than off `authenticated` alone, because the wipe below is what
    // needs protecting and every status reaches it. A device-cap sign-out
    // carries a pubkey and was skipping the check entirely; the custody
    // screen's Back button carries none and ran the full wipe on data it
    // never owned.
    const tabPubkey =
      auth.status === 'authenticated' || auth.status === 'device_limit_reached'
        ? auth.pubkey
        : null;
    if (tabPubkey === null || !ownsLocalData(tabPubkey)) {
      // A pass from OUR account may still be in flight in this tab; the
      // shared cursor now belongs to the other account, so that pass
      // must not persist into it. resumeSync() runs on the next
      // authentication.
      suspendSync();
      // A status with no pubkey owns no vault here, but the custody
      // choice does own the OAuth session that put it on screen: its
      // Back button has to end that session or the next boot lands on
      // the same screen. Ask the authority whether the live session is
      // still the one this status hydrated, so a tab whose account
      // another tab replaced cannot sign that account out.
      if (auth.status === 'oauth_custody_choice') {
        const { data } = await supabase.auth.getSession();
        if (data.session?.user.id === auth.authUid) {
          await supabase.auth.signOut({ scope: 'local' }).catch(() => {});
          clearSupabaseAuthKeys();
        }
      }
      sessionRef.current = null;
      // This return shows the sign-in screen WITHOUT clearing the phrase, so
      // it is one of the two ways an install ends up holding a phrase it is
      // not using. Name it, or the next report is another evening of
      // inference: the reason says which half of the test sent us here.
      // Spec: ops/docs/plans/oauth-redirect-binding-handoff.md (section 8.8)
      logAuthEvent('auth:signout-early-return', {
        reason: tabPubkey === null ? 'no-pubkey' : 'not-owner',
        status: auth.status,
      });
      setAuth({ status: 'onboarding' });
      return;
    }

    // Best-effort final flush - push any dirty notes to the server
    // before wiping local data. Without this, notes created between the
    // last sync pass and sign-out are silently lost. flushOnly skips the
    // heartbeat gate on purpose: a revoked device fails that gate
    // (DeviceRevokedError) before the push phase ever runs, but its JWT
    // still authorizes note writes, so its unsynced rows can still be
    // saved. Also runs from the device-cap state - a blocked device can
    // carry dirty rows from an earlier authenticated life on this
    // browser, and link-pubkey has already stamped its session.
    let flushSettled = true;
    if (auth.status === 'authenticated' || auth.status === 'device_limit_reached') {
      // Time-boxed so a cold or slow server can't stall the sign-out UI
      // forever. 2s keeps a clean sign-out snappy; with unsynced rows at
      // stake the budget widens to 10s - a batch of dirty notes pushes
      // as sequential requests and cannot fit in 2s, which used to
      // silently destroy the unsent tail. The revoke keeps the
      // "Registered devices" count from accumulating orphans on
      // sign-out/in. #119
      const timeout = (ms: number) =>
        new Promise<void>((resolve) => setTimeout(resolve, ms));
      const dirtyCount = await countUnsyncedNotes();
      // A settings change waits for the next pass, up to 30 seconds, and the
      // wipe below removes the cache that holds it.
      const settingsDirty = hasUnpushedSettings();
      flushSettled = false;
      const work = (async () => {
        try {
          if (dirtyCount > 0) {
            // Retry while a regular sync pass holds the mutex - its own
            // push phase flushes the same rows, but don't rely on its
            // timing; wait for a slot and flush deterministically.
            for (let attempt = 0; attempt < 20; attempt++) {
              const r = await sync(supabase, auth.pubkey, auth.encryptionKey, auth.deviceId, undefined, undefined, undefined, { flushOnly: true });
              if (r.ran) break;
              await timeout(250);
            }
          }
          if (settingsDirty) await syncUserSettings(supabase, auth.pubkey, auth.encryptionKey);
        } catch {
          // Dead session or offline - nothing more this side can do;
          // the wipe below decides what survives.
        }
        if (auth.status === 'authenticated') {
          try {
            const session = await supabase.auth.getSession();
            const token = session.data.session?.access_token;
            const uid = session.data.session?.user.id;
            if (token && uid) {
              await revokeDevice({
                supabase,
                accessToken: token,
                authUid: uid,
                signingPrivateKey: auth.signingPrivateKey,
                targetDeviceId: auth.deviceId,
              });
            }
          } catch {
            // Don't block sign-out if revoke fails (offline, already
            // revoked via forceSignOut, etc.).
          }
        }
        flushSettled = true;
      })();
      await Promise.race([work, timeout(dirtyCount > 0 || settingsDirty ? 10000 : 2000)]);
    }

    // Best-effort zeroing of key material in memory before dropping refs.
    // JS can't guarantee the GC hasn't copied the buffers, but this
    // reduces the window of exposure to heap dumps. Skipped when the
    // flush above timed out and is still running: encryptNote with a
    // zeroed key would push undecryptable ciphertext over a good server
    // copy. Dropping the state releases the buffers for GC instead
    // (same trade as the stale-tab path at the top of this function).
    if (flushSettled && (auth.status === 'authenticated' || auth.status === 'device_limit_reached')) {
      auth.encryptionKey.fill(0);
      auth.signingPrivateKey.fill(0);
      // Same guard: a still-running flush updates note rows, and under
      // sealed writes those updates need the local data key.
      clearLocalDataKey();
    }

    // From here on the wipe is in progress: block new sync passes and
    // strip the in-flight one (if the flush above lost its mutex race
    // against it) of the right to persist cursor or heal state. Without
    // this, a pass outliving sign-out re-created privacynotes.lastSync
    // AFTER the removal below, and rows wiped locally but behind the
    // resurrected cursor were never re-pulled on the next same-user
    // sign-in. The finally guarantees resumeSync even when the wipe
    // throws (Dexie storage pressure, a blocked delete) - otherwise a
    // failed sign-out left a still-authenticated-looking tab whose
    // every sync pass silently no-oped. _authenticateWithPhrase also
    // calls resumeSync defensively.
    suspendSync();
    try {
      // Wipe secrets from both backing stores. The trust flag stays -
      // it's not a secret, just a UX preference, so the next sign-in
      // defaults to whatever the user last chose. Clearing it would
      // mean a user who bio-unlocked once, signed out, and re-signed-in
      // would default to untrusted (sessionStorage) and lose their
      // trusted-device convenience. See gap #28.
      logAuthEvent('auth:signout-wipe', { keepUnsynced: !!opts?.keepUnsyncedNotes });
      trustAwareStorage.removeItem(PHRASE_STORAGE_KEY);
      trustAwareStorage.removeItem(OAUTH_FLAG_KEY);
      trustAwareStorage.removeItem('privacynotes.lastSync');
      // Drop the fast-boot cache - a signed-out device must never boot
      // straight into the authenticated state. The registration marker
      // goes too so the next sign-in re-registers properly.
      clearCachedAccountFlags();
      clearRegistrationMarker();
      // Drop the settings-panel figures (device list, quota, storage
      // subs) alongside the other account-scoped caches. Keyed by pubkey
      // so a stale entry could not be read by another account anyway,
      // but leaving it would keep a signed-out account's numbers on
      // disk for no reason. See accountPanelCache.ts.
      clearPanelCache();
      // Wipe the biometric- and PIN-wrapped phrase blobs too. Both hold
      // the encrypted recovery phrase - leaving them behind on a shared
      // computer would let the previous user bio-unlock or PIN-unlock and
      // recover their phrase after sign-out. See gap #17.
      removeBiometricCredential();
      removePinWrappedPhrase();
      clearAccountScopedUiState();
      // The PIN hash/salt cache, lockout counters, and unlock marker are
      // account-scoped: the next account signing in on this browser must
      // not inherit them (the removed legacy-PIN migration once
      // resurrected exactly this cache into a new account's settings).
      clearPinCache();
      // Wipe notes + blob caches. Rows written under the seal are
      // ciphertext at rest and rows predating it are still plaintext,
      // and either way they are the prior account's data: leaving them
      // would also feed processPendingUploads on the next
      // sign-in. PUBKEY_OWNER_KEY survives so a same-user re-sign-in
      // skips the mismatch wipe; a different-user sign-in still gets
      // wiped via the check at the top of _authenticateWithPhrase.
      // Forced sign-outs pass keepUnsyncedNotes so dirty rows the flush
      // could not save survive until that same-user re-sign-in pushes
      // them (or the owner-mismatch wipe claims them).
      await clearLocalDatabase({ keepUnsyncedNotes: opts?.keepUnsyncedNotes });
      // Also clear the cached user-settings blob. Without this, signing
      // in as a different user in the same browser inherits the previous
      // user's `welcomeNoteSeeded: true` flag from localStorage, and the
      // welcome note never seeds for the new account.
      clearLocalSettings();
      sessionRef.current = null;
      // scope MUST be 'local'. The supabase-js default is 'global',
      // which revokes the user's sessions on EVERY device server-side.
      // With this call wired into the SessionExpiredModal's only
      // button, the default turned each recovery into a fresh kill:
      // sign in again on one device, every other device's next token
      // refresh 400s (refresh_token_not_found), its modal pops, and
      // the loop repeats - fleet-wide, confirmed in the auth logs on
      // 2026-08-25 for multiple users. A voluntary single-device
      // sign-out seeded the same cascade. "Sign out everywhere" is a
      // deliberate feature if we ever want it, never a default.
      const { error: signOutError } = await supabase.auth.signOut({ scope: 'local' });
      // The call can decline and still report a clean sign-out: an access
      // token past its expiry whose refresh cannot reach the network returns
      // that error before auth-js reaches its own removal, leaving the
      // session on disk. The phrase is already gone by this point, so the
      // next boot cannot take the stored-phrase path and self-heal - it
      // hydrates whatever session it finds instead. The sweep is what makes
      // the removal independent of the network; the account-deletion path
      // has always done the same.
      if (signOutError) logAuthEvent('auth:signout-remote-failed', { name: signOutError.name });
      clearSupabaseAuthKeys();
      setAuth({ status: 'onboarding' });
    } finally {
      resumeSync();
    }
  }

  /**
   * Hard sign-out triggered by a server-side signal (e.g. device was
   * revoked from another device, caught via the heartbeat RPC). Same
   * cleanup as `signOut` plus a console log so the cause is traceable.
   */
  async function forceSignOut(reason?: string) {
    if (reason) console.info('[auth] forced sign-out:', reason);
    // Server-triggered - the user never chose data destruction, so
    // unsynced rows survive the wipe when the final flush cannot reach
    // the server. They push after the next same-pubkey sign-in.
    await signOut({ keepUnsyncedNotes: true });
  }

  const { releaseCustody, adoptCustody } = useCustody({ supabase, auth, setAuth });

  const { refreshProStatus } = useProStatus({
    supabase,
    auth,
    setAuth,
    retryRegistrationFromLimit,
  });

  return (
    <AuthContext.Provider
      value={{
        auth,
        supabase,
        signInWithPhrase,
        unlockLocally,
        revalidationExpired,
        signInWithOAuth,
        completeDesktopOAuth,
        signOut,
        resolveDeviceLimit,
        forceSignOut,
        refreshProStatus,
        completeCustodyChoice,
        retryOAuthHydration,
        abandonOAuthHydration,
        releaseCustody,
        adoptCustody,
      }}
    >
      {children}
      {switchAsk && (
        <ConfirmModal
          title={i18n.t('auth:signIn.switchTitle')}
          confirmLabel={i18n.t('auth:signIn.switchConfirm')}
          variant="info"
          onConfirm={() => answerAccountSwitch(true)}
          onClose={() => answerAccountSwitch(false)}
        >
          {i18n.t('auth:signIn.switchBody')}
        </ConfirmModal>
      )}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
