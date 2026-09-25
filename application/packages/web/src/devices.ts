/**
 * Client-side device lifecycle.
 *
 * Responsibilities:
 *   - Own the per-install `deviceSecret` in localStorage (generate on
 *     first run, keep forever until cleared).
 *   - Build a human-readable `deviceName` + `platform` from navigator.
 *   - Call `register-device` on sign-in, unless the caller has a
 *     recent registration cached; surface the limit-hit error with
 *     the device list so the UI can prompt.
 *   - Call `revoke-device` on user-initiated revoke.
 *   - Heartbeat via RPC on every sync; if the RPC returns false, the
 *     device has been revoked elsewhere → caller signs out.
 *   - Query the `devices` table for the settings mgmt list.
 *
 * Token is passed explicitly to avoid FunctionsClient auth-state race.
 */

import {
  bytesToHex,
  deriveDeviceId,
  generateDeviceSecret,
  signCustodialAdoptChallenge,
  signCustodialReleaseChallenge,
  signDeleteAccountChallenge,
  signDeviceRegisterChallenge,
  signDeviceRevokeChallenge,
  signStorageManageChallenge,
  type SupabaseClient,
} from '@notes/shared';
import { collectFingerprint, detectDeviceOs, hashFingerprint } from './deviceFingerprint';
import { isDemoMode } from './demo';
import { db } from './db';

const DEVICE_SECRET_KEY = 'privacynotes.deviceSecret';

export type Platform = 'web' | 'desktop' | 'ios' | 'android';

export type DeviceRow = {
  device_id: string;
  device_name: string;
  platform: string;
  created_at: string;
  last_seen_at: string;
  /** Non-null when the device was soft-deleted. Row is retained for 72h as a "recently removed" audit entry; it does not occupy a slot. */
  revoked_at: string | null;
  /** Groups browser installs on the same physical device. NULL for legacy rows. */
  device_group: string | null;
};

export type RegisterResult =
  | { status: 'ok'; isPro: boolean }
  | { status: 'limit_reached'; limit: number; devices: DeviceRow[] };

// ------------------------------------------------------------------
// Local install identity
// ------------------------------------------------------------------

/** Get or create the 32-byte deviceSecret for this install. Hex-encoded in localStorage. */
function getOrCreateDeviceSecret(): Uint8Array {
  const stored = window.localStorage.getItem(DEVICE_SECRET_KEY);
  if (stored && /^[0-9a-f]{64}$/i.test(stored)) {
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      out[i] = parseInt(stored.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  }
  const fresh = generateDeviceSecret();
  window.localStorage.setItem(DEVICE_SECRET_KEY, bytesToHex(fresh));
  return fresh;
}

export function getDeviceId(pubkey: string): string {
  return deriveDeviceId(pubkey, getOrCreateDeviceSecret());
}

// ------------------------------------------------------------------
// Platform + name sniff
// ------------------------------------------------------------------

type TauriWindow = Window & {
  __TAURI__?: unknown;
  __TAURI_INTERNALS__?: unknown;
};

export function detectPlatform(): Platform {
  const w = window as TauriWindow;
  if (w.__TAURI__ || w.__TAURI_INTERNALS__) {
    // The build knows what it is; the browser only has opinions. Tauri sets
    // TAURI_ENV_PLATFORM while building and vite bakes it in, so this branch
    // cannot be fooled by a user agent. Everything below it is the fallback
    // for a native build made outside Tauri's build pipeline.
    if (__PN_BUILD_PLATFORM__ === 'ios') return 'ios';
    if (__PN_BUILD_PLATFORM__ === 'android') return 'android';
    if (__PN_BUILD_PLATFORM__) return 'desktop';

    const ua = navigator.userAgent.toLowerCase();
    if (ua.includes('iphone') || ua.includes('ipad')) return 'ios';
    if (ua.includes('android')) return 'android';
    // An iPad's webview reports a MAC user agent, with no "ipad" anywhere in
    // it, so the checks above miss it and it used to fall through to
    // 'desktop'. That handed iPads every desktop code path: the system
    // browser for OAuth and the web checkout for Pro, which is precisely
    // what App Review rejected on 2026-09-01 (guideline 4 and 3.1.1) after
    // the same build passed on iPhone. Touch points are the tell - no Mac
    // reports any, and this only runs inside a native build, so a desktop
    // browser on exotic hardware cannot reach it.
    // Spec: ops/docs/gotchas.md (an iPad reports a Mac user agent)
    if (ua.includes('macintosh') && navigator.maxTouchPoints > 1) return 'ios';
    return 'desktop';
  }
  return 'web';
}

/**
 * True only inside the native Linux app (Tauri/WebKitGTK), where wry never
 * wires WebKitGTK's `permission-request` signal, so getUserMedia (camera +
 * mic) is denied with no prompt. Linux *web* browsers are unaffected, so this
 * is scoped to the desktop (Tauri) build, not any Linux user.
 */
// Spec: ops/docs/gotchas.md (Linux WebKitGTK getUserMedia is dead - camera + mic denied with no prompt)
export function isLinuxNative(): boolean {
  return detectPlatform() === 'desktop' && detectDeviceOs() === 'Linux';
}

/**
 * Build a short human-readable device name.
 *
 * Since fingerprint dedup treats all browsers on the same physical
 * machine as one device, the name reflects the device/OS - not the
 * browser. Examples: "iPhone", "macOS", "Windows", "Linux".
 * Tauri builds get a "Desktop app on {os}" prefix to distinguish
 * native from web.
 */
export function buildDeviceName(): string {
  const platform = detectPlatform();
  const os = detectDeviceOs();
  if (platform === 'desktop') return `Desktop app on ${os}`;
  if (platform === 'ios') return 'iOS app';
  if (platform === 'android') return 'Android app';
  return os;
}


// ------------------------------------------------------------------
// Edge-function calls
// ------------------------------------------------------------------

export type FnError = Error & { context?: Response };

/**
 * Delays between retries of a network-failed edge-function call. Grows
 * so a gateway that sheds connections gets breathing room, but stays
 * short enough (~4s worst case) that a real outage still surfaces the
 * error screen promptly.
 */
const FN_RETRY_DELAYS_MS = [500, 1200, 2500];

/**
 * `supabase.functions.invoke` with retries on network-level failures.
 *
 * Why: while the Supabase API gateway was degraded (2026-08-24) it
 * closed connections mid-request (ERR_CONNECTION_CLOSED) on the
 * handshake functions, and a manual "Try again" then succeeded. That
 * one blip dead-ended every signup and login. supabase-js reports the
 * condition as a FunctionsFetchError: fetch() itself threw and no
 * response exists, so a re-send is safe even for signed or
 * captcha-carrying bodies (an unsent Turnstile token is not consumed;
 * a consumed one comes back as `captcha_failed`, which callers already
 * handle). HTTP errors pass through on the first response - they
 * reached the function and carry a body the caller reads.
 *
 * Use this ONLY for idempotent calls (link-pubkey, register-device,
 * revoke-device, get-custodial-phrase). Billing and account-deletion
 * calls keep the plain invoke on purpose.
 */
export async function invokeFnWithRetry(
  supabase: SupabaseClient,
  name: string,
  options: Parameters<SupabaseClient['functions']['invoke']>[1],
) {
  let result = await supabase.functions.invoke(name, options);
  for (const delayMs of FN_RETRY_DELAYS_MS) {
    if (!result.error || result.error.name !== 'FunctionsFetchError') break;
    // A browser that knows it is offline fails every attempt the same
    // way - do not make the user wait out the backoff for that.
    if (typeof navigator !== 'undefined' && navigator.onLine === false) break;
    await new Promise((resolve) => setTimeout(resolve, delayMs));
    result = await supabase.functions.invoke(name, options);
  }
  return result;
}

// One-shot per app load: the isolates stay warm for minutes once
// booted, so re-warming on StrictMode remounts or back-and-forth
// onboarding navigation would only waste requests.
let edgeWarmupFired = false;

/**
 * Boot the sign-in edge functions' isolates once a visitor starts a
 * sign-in. Cold starts cost 1-3.5s each and sit exactly on the sign-in
 * critical path (link-pubkey, then register-device). A bare OPTIONS
 * request only runs each function's CORS branch: no auth, no body, no
 * database - it exists purely to spin up the isolate so the real calls
 * during sign-in hit warm instances. Fire-and-forget; failures are
 * expected offline and must never affect onboarding.
 *
 * Call it on intent, never on mount. The marketing pages render the
 * onboarding component too, and a visitor who only reads them must send
 * nothing to the sync backend: these URLs name link-pubkey and
 * register-device, so in a network tab they read as a sign-in that never
 * happened.
 */
export function warmAuthEdgeFunctions(): void {
  if (edgeWarmupFired || isDemoMode()) return;
  edgeWarmupFired = true;
  const base = import.meta.env.VITE_SUPABASE_URL as string | undefined;
  if (!base) return;
  const fns = ['link-pubkey', 'register-device'];
  for (const fn of fns) {
    void fetch(`${base}/functions/v1/${fn}`, { method: 'OPTIONS' }).catch(() => {});
  }
}

/**
 * True when a PostgREST/RPC result's `error` is a transport-level fetch
 * failure: the request died before any HTTP response existed. supabase-js
 * returns these as `{ error }` rather than throwing, and the message is
 * the stringified browser TypeError, worded differently per engine
 * (Chrome "Failed to fetch", WebKit "Load failed", Firefox
 * "NetworkError..."). No HTTP status ever accompanies them, which is what
 * separates a dead socket from a real server answer.
 */
function isTransportError(err: { message?: string } | null | undefined): boolean {
  if (!err) return false;
  return /failed to fetch|load failed|networkerror|fetch failed/i.test(err.message ?? '');
}

/**
 * Re-run an idempotent PostgREST/RPC READ while its error is
 * transport-level, on the same delay ladder as invokeFnWithRetry and for
 * the same reason: a NAT that killed the idle connection pool (Starlink
 * CGNAT is the case that surfaced it)
 * makes the first attempt ride a dead socket; the retry opens a fresh one
 * and succeeds. Reads only - a transport failure cannot prove the request
 * was not applied, so nothing that mutates beyond a self-heal, and never
 * anything that moves money.
 */
async function readWithRetry<T extends { error: { message?: string } | null }>(
  run: () => PromiseLike<T>,
): Promise<T> {
  let result = await run();
  for (const delayMs of FN_RETRY_DELAYS_MS) {
    if (!isTransportError(result.error)) break;
    if (typeof navigator !== 'undefined' && navigator.onLine === false) break;
    await new Promise((resolve) => setTimeout(resolve, delayMs));
    result = await run();
  }
  return result;
}

export async function readFnErrorBody(err: FnError): Promise<unknown> {
  const ctx = err.context;
  if (!ctx || typeof ctx.text !== 'function') return null;
  try {
    const text = await ctx.text();
    if (!text) return null;
    try {
      return JSON.parse(text);
    } catch {
      return { raw: text };
    }
  } catch {
    return null;
  }
}

/**
 * True when link-pubkey refused because the caller's access token is dead
 * SERVER-SIDE while still unexpired locally: its session was revoked by a
 * rotation-reuse, a sign-out in another tab, or an admin. `getSession`
 * hands such a token over happily (it only reads `expires_at`), so the
 * only thing that catches it is a server round trip - and when the app's
 * own `getUser` probe was unreachable, the handshake adopts the dead token
 * and carries it into the link. The function's 401 body is the single
 * opaque code for that verdict, so it is matched exactly rather than by
 * substring: a 401 with any other body is a different refusal.
 *
 * This IS a definitive verdict on the token (never on the user's data), so
 * the caller answers it by re-minting a session, not by wiping anything.
 * Spec: ops/docs/auth-session-audit-2026-08.md (the stale cached token at link-pubkey)
 */
export function isStaleTokenLinkError(
  err: FnError | null | undefined,
  body: unknown,
): boolean {
  if (!err || err.context?.status !== 401) return false;
  return (body as { error?: string } | null)?.error === 'invalid or expired JWT';
}

/**
 * True when link-pubkey answered 503 `auth_unreachable`: the function
 * could not reach GoTrue to verify the caller's JWT, so it refused to
 * pass a verdict at all (the server-side mirror of "a transient error is
 * not a verdict"). The right response is to retry the SAME token - it was
 * never judged. Exact-match like its sibling above; any other 503 is not
 * this signal.
 * Spec: ops/docs/auth-session-audit-2026-08.md (the stale cached token at link-pubkey)
 */
/**
 * True when link-pubkey answers that the auth backend rate limited the
 * token check. Distinct from `isAuthUnreachableLinkError` on purpose: that
 * one means retry the same token shortly, and this one means stop, because
 * retrying is what the limit is asking you not to do.
 */
export function isAuthRateLimitedLinkError(
  err: FnError | null | undefined,
  body: unknown,
): boolean {
  if (!err || err.context?.status !== 429) return false;
  return (body as { error?: string } | null)?.error === 'auth_rate_limited';
}

export function isAuthUnreachableLinkError(
  err: FnError | null | undefined,
  body: unknown,
): boolean {
  if (!err || err.context?.status !== 503) return false;
  return (body as { error?: string } | null)?.error === 'auth_unreachable';
}

/**
 * True when link-pubkey received no Authorization header at all. The app
 * sets that header explicitly on every link call, from a token it has
 * already proven non-empty, so this client cannot produce the refusal on
 * its own: something between the app and the server removed the header.
 * A content filter with HTTPS filtering is the known cause - a native
 * wrapper serves its page from tauri.localhost, so every call to the sync
 * host counts as third-party, and filters offer a switch that strips the
 * header on exactly those. Retrying is useless and re-minting is worse, so
 * the caller answers with words instead of another attempt.
 *
 * Exact-match like its siblings: a 401 with any other body is a different
 * refusal.
 */
export function isMissingBearerLinkError(
  err: FnError | null | undefined,
  body: unknown,
): boolean {
  if (!err || err.context?.status !== 401) return false;
  return (body as { error?: string } | null)?.error === 'missing_bearer';
}

export type RegisterDeviceArgs = {
  supabase: SupabaseClient;
  accessToken: string;
  authUid: string;
  pubkey: string;
  signingPrivateKey: Uint8Array;
  /**
   * Per-user fingerprint pepper, derived from the BIP-39 seed. Used to
   * hash the device fingerprint signals client-side before they reach
   * the server. Required as of v0.155.0.
   * Spec: ops/docs/device-fingerprint-hash.md (four separate hashes keep server-side fuzzy matching working)
   */
  fpPepper: Uint8Array;
};

/**
 * Register this install with the server. Idempotent for re-registrations
 * of the same (pubkey, device_id) - the server just bumps last_seen_at.
 *
 * If the free-tier limit is hit, returns { status: 'limit_reached' } with
 * the current device list so the caller can render the block modal
 * without an extra round-trip.
 */
export async function registerDevice(args: RegisterDeviceArgs): Promise<RegisterResult> {
  const { supabase, accessToken, authUid, pubkey, signingPrivateKey, fpPepper } = args;
  const deviceId = getDeviceId(pubkey);
  const signature = await signDeviceRegisterChallenge(
    signingPrivateKey,
    authUid,
    deviceId,
  );

  // Spec: ops/docs/device-fingerprint-hash.md (phase 2: hashes only, no raw)
  const fingerprintHashes = hashFingerprint(collectFingerprint(), fpPepper);

  const { data, error } = await invokeFnWithRetry(supabase, 'register-device', {
    headers: { Authorization: `Bearer ${accessToken}` },
    body: {
      device_id: deviceId,
      device_name: buildDeviceName(),
      platform: detectPlatform(),
      signature: bytesToHex(signature),
      fingerprint_hashes: fingerprintHashes,
    },
  });

  if (error) {
    const body = (await readFnErrorBody(error as FnError)) as
      | { error?: string; limit?: number; devices?: DeviceRow[] }
      | null;
    if (body?.error === 'device_limit_reached') {
      return {
        status: 'limit_reached',
        limit: body.limit ?? 2,
        devices: body.devices ?? [],
      };
    }
    throw new Error(
      `register-device failed: ${body?.error ?? (error as Error).message}`,
    );
  }

  const isPro = !!(data as { is_pro?: boolean } | null)?.is_pro;
  return { status: 'ok', isPro };
}

export type RevokeDeviceArgs = {
  supabase: SupabaseClient;
  accessToken: string;
  authUid: string;
  signingPrivateKey: Uint8Array;
  targetDeviceId: string;
};

export async function revokeDevice(args: RevokeDeviceArgs): Promise<void> {
  const { supabase, accessToken, authUid, signingPrivateKey, targetDeviceId } = args;
  const signature = await signDeviceRevokeChallenge(
    signingPrivateKey,
    authUid,
    targetDeviceId,
  );
  const { error } = await invokeFnWithRetry(supabase, 'revoke-device', {
    headers: { Authorization: `Bearer ${accessToken}` },
    body: {
      target_device_id: targetDeviceId,
      signature: bytesToHex(signature),
    },
  });
  if (error) {
    const body = (await readFnErrorBody(error as FnError)) as
      | { error?: string }
      | null;
    throw new Error(
      `revoke-device failed: ${body?.error ?? (error as Error).message}`,
    );
  }
}

// ------------------------------------------------------------------
// Account deletion
// ------------------------------------------------------------------

export type DeleteAccountArgs = {
  supabase: SupabaseClient;
  accessToken: string;
  authUid: string;
  signingPrivateKey: Uint8Array;
};

/**
 * Call the delete-account edge function to permanently remove all
 * server-side data (notes, settings, devices, quotas, images, auth).
 * The caller is responsible for wiping local data afterward.
 */
export async function deleteAccountServer(args: DeleteAccountArgs): Promise<void> {
  const { supabase, accessToken, authUid, signingPrivateKey } = args;
  const signature = await signDeleteAccountChallenge(signingPrivateKey, authUid);
  const { error } = await supabase.functions.invoke('delete-account', {
    headers: { Authorization: `Bearer ${accessToken}` },
    body: { signature: bytesToHex(signature) },
  });
  if (error) {
    const body = (await readFnErrorBody(error as FnError)) as
      | { error?: string }
      | null;
    throw new Error(
      `delete-account failed: ${body?.error ?? (error as Error).message}`,
    );
  }
}

// ------------------------------------------------------------------
// Custodial release (custodial -> self-custody)
// ------------------------------------------------------------------

export type ReleaseCustodyArgs = {
  supabase: SupabaseClient;
  accessToken: string;
  authUid: string;
  signingPrivateKey: Uint8Array;
};

export type ReleaseCustodyResult = {
  /** False when the server held no phrase, i.e. the call was a no-op. */
  wasCustodial: boolean;
  /** False when the row was deleted but app_metadata could not be updated. */
  flagCleared: boolean;
};

/**
 * Call the delete-custodial-phrase edge function: deletes the server's
 * copy of the recovery phrase and clears app_metadata.custodial. The
 * account, pubkey and notes are untouched.
 *
 * One-way. There is no inverse call, by design.
 *
 * The caller must have shown the user their phrase and confirmed they
 * saved it BEFORE calling this. After this succeeds the server cannot
 * recover anything, so a user without their phrase is one lost session
 * away from losing every note.
 *
 * Idempotent server-side: calling it twice is safe and the second call
 * returns wasCustodial: false.
 */
export async function releaseCustodyServer(
  args: ReleaseCustodyArgs,
): Promise<ReleaseCustodyResult> {
  const { supabase, accessToken, authUid, signingPrivateKey } = args;
  const signature = await signCustodialReleaseChallenge(signingPrivateKey, authUid);
  const { data, error } = await supabase.functions.invoke('delete-custodial-phrase', {
    headers: { Authorization: `Bearer ${accessToken}` },
    body: { signature: bytesToHex(signature) },
  });
  if (error) {
    const body = (await readFnErrorBody(error as FnError)) as
      | { error?: string }
      | null;
    throw new Error(
      `delete-custodial-phrase failed: ${body?.error ?? (error as Error).message}`,
    );
  }
  const res = (data ?? {}) as { wasCustodial?: boolean; flagCleared?: boolean };
  return {
    wasCustodial: res.wasCustodial === true,
    flagCleared: res.flagCleared === true,
  };
}

export type AdoptCustodyArgs = {
  supabase: SupabaseClient;
  accessToken: string;
  authUid: string;
  signingPrivateKey: Uint8Array;
  /** The 12-word phrase to hand to the server. */
  phrase: string;
};

/**
 * Call store-custodial-phrase: hands the server an encrypted-at-rest
 * copy of the recovery phrase so any device can sign in with the
 * provider alone.
 *
 * This is the direction that GIVES the server the ability to decrypt
 * this user's notes. Only call it from an explicit, informed user
 * action. Never call it silently, never call it as a fallback, and
 * never call it to "help" a user who is having sign-in trouble.
 *
 * Signed with signCustodialAdoptChallenge so a stolen session token
 * cannot plant a phrase the caller does not already hold.
 *
 * Returns already_stored when the server has a row for this account,
 * which the caller should treat as "you are already custodial" rather
 * than as an error worth surfacing raw.
 */
export async function adoptCustodyServer(args: AdoptCustodyArgs): Promise<void> {
  const { supabase, accessToken, authUid, signingPrivateKey, phrase } = args;
  const signature = await signCustodialAdoptChallenge(signingPrivateKey, authUid);
  const { error } = await supabase.functions.invoke('store-custodial-phrase', {
    headers: { Authorization: `Bearer ${accessToken}` },
    body: { phrase, signature: bytesToHex(signature) },
  });
  if (error) {
    const body = (await readFnErrorBody(error as FnError)) as
      | { error?: string }
      | null;
    throw new Error(
      `store-custodial-phrase failed: ${body?.error ?? (error as Error).message}`,
    );
  }
}

// ------------------------------------------------------------------
// Storage add-on management
// ------------------------------------------------------------------

export type StorageSubRow = {
  subscription_id: string;
  price_id: string;
  gb_count: number;
  status: string;
  started_at: string;
  /** End of the current paid period (renewal date), if known. */
  current_period_ends_at: string | null;
  /** Set when a cancellation is scheduled (effective at period end). */
  scheduled_cancel_at: string | null;
  /** Store the sub came from: 'paddle' | 'play' | 'apple'. Drives how manage
   *  actions route (Paddle edge function vs native store flows). Optional so
   *  the client tolerates a not-yet-migrated get_my_storage_subs (0060). */
  source?: string;
};

/** The caller's live storage subscriptions (active / past_due, not gated). */
export async function fetchMyStorageSubs(
  supabase: SupabaseClient,
): Promise<StorageSubRow[]> {
  // Demo mode never queries the server - the sandbox has no billing.
  if (isDemoMode()) return [];
  const { data, error } = await readWithRetry(() => supabase.rpc('get_my_storage_subs'));
  if (error) {
    console.error('get_my_storage_subs failed', error);
    return [];
  }
  return (data ?? []) as StorageSubRow[];
}

export type ManageStorageArgs = {
  supabase: SupabaseClient;
  accessToken: string;
  authUid: string;
  signingPrivateKey: Uint8Array;
  subscriptionId: string;
  action: 'cancel' | 'switch';
  /** Required for 'switch' - the target package's Paddle price ID. */
  priceId?: string;
  /**
   * For 'switch': the `quote` of the preview the confirm showed. The server
   * then charges only while a fresh preview still gives that figure.
   */
  quote?: string;
};

/**
 * Cancel (at period end) or upgrade a storage subscription via the
 * manage-storage-sub edge function. The DB row is updated by the
 * resulting Paddle webhook, so callers should refetch after a moment.
 */
export async function manageStorageSub(args: ManageStorageArgs): Promise<void> {
  const { supabase, accessToken, authUid, signingPrivateKey, subscriptionId, action, priceId, quote } = args;
  const signature = await signStorageManageChallenge(
    signingPrivateKey,
    authUid,
    subscriptionId,
    action,
    action === 'switch' ? (priceId ?? '') : '',
  );
  const { error } = await supabase.functions.invoke('manage-storage-sub', {
    headers: { Authorization: `Bearer ${accessToken}` },
    body: {
      subscription_id: subscriptionId,
      action,
      ...(action === 'switch' ? { price_id: priceId } : {}),
      ...(action === 'switch' && quote ? { quote } : {}),
      signature: bytesToHex(signature),
    },
  });
  if (error) {
    const body = (await readFnErrorBody(error as FnError)) as
      | { error?: string }
      | null;
    throw Object.assign(
      new Error(`manage-storage-sub failed: ${body?.error ?? (error as Error).message}`),
      { code: body?.error },
    );
  }
}

/**
 * True when manage-storage-sub refused a switch because the amount the
 * confirm showed no longer matched, or could not be checked. Nothing was
 * charged, and choosing the package again shows the current figure.
 */
export function isStorageQuoteRefusal(err: unknown): boolean {
  const code = (err as { code?: unknown } | null)?.code;
  return code === 'quote_mismatch' || code === 'preview_unavailable';
}

/** What an upgrade preview returns: the amount due today, and its quote. */
export type StorageUpgradeQuote = {
  /** Formatted for display, e.g. "$11.40". */
  dueToday: string;
  /**
   * The same figure as the server compares it. Handed back with the switch;
   * absent when the server sent none, and the switch then goes without it.
   */
  quote?: string;
};

/**
 * Preview an upgrade: the real prorated amount due today for switching to
 * priceId, without applying it. Returns null if unavailable; the confirm then
 * offers a retry and never charges without a figure.
 */
export async function previewStorageUpgrade(args: {
  supabase: SupabaseClient;
  accessToken: string;
  subscriptionId: string;
  priceId: string;
}): Promise<StorageUpgradeQuote | null> {
  const { supabase, accessToken, subscriptionId, priceId } = args;
  try {
    const { data, error } = await supabase.functions.invoke('manage-storage-sub', {
      headers: { Authorization: `Bearer ${accessToken}` },
      body: { action: 'preview', subscription_id: subscriptionId, price_id: priceId },
    });
    if (error) return null;
    const d = data as { ok?: boolean; due_today?: string; quote?: string } | null;
    if (!d?.ok || !d.due_today) return null;
    return typeof d.quote === 'string' ? { dueToday: d.due_today, quote: d.quote } : { dueToday: d.due_today };
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------
// Direct DB helpers
// ------------------------------------------------------------------

export async function listDevices(supabase: SupabaseClient): Promise<DeviceRow[]> {
  // Demo mode has no server-side device rows - never query for them.
  if (isDemoMode()) return [];
  const { data, error } = await readWithRetry(() => supabase
    .from('devices')
    .select('device_id, device_name, platform, created_at, last_seen_at, revoked_at, device_group')
    .order('last_seen_at', { ascending: false }));
  if (error) {
    console.error('[devices] list failed', error);
    return [];
  }
  return (data as DeviceRow[]) ?? [];
}

/**
 * Heartbeat the current device. Returns true if the device is still
 * registered, false if it was revoked elsewhere (→ caller should
 * local-sign-out + wipe). Any RPC error is treated as true (network
 * flakiness shouldn't kick the user off); revocation is a deliberate
 * server-side "row missing" signal.
 *
 * Throttled to once per 60 seconds. The UPDATE hits a single row by
 * (pubkey, device_id) - trivial even at scale. Keeping this short
 * ensures revoked devices are detected within ~1 minute of the next
 * user interaction (the old 5-minute throttle meant revocations went
 * unnoticed for too long).
 */
const HEARTBEAT_INTERVAL_MS = 60 * 1000;
let lastHeartbeatAt = 0;

export async function heartbeat(
  supabase: SupabaseClient,
  deviceId: string,
  /** Bypass the throttle and hit the server immediately. Use on
   *  visibilitychange so revoked devices discover revocation the
   *  instant the user switches to the tab. */
  force = false,
): Promise<boolean> {
  // Demo mode has no server-side device row - never call the server,
  // and report "still registered" so nothing triggers a sign-out.
  if (isDemoMode()) return true;
  const now = Date.now();
  if (!force && now - lastHeartbeatAt < HEARTBEAT_INTERVAL_MS) {
    return true; // skip - too soon since last heartbeat
  }
  lastHeartbeatAt = now;
  const { data, error } = await supabase.rpc('device_heartbeat', {
    p_device_id: deviceId,
  });
  if (error) {
    // Fail open. This covers network blips AND the "pubkey not linked"
    // RAISE (migration 0064): a caller that cannot prove who it is has
    // learned nothing about whether its device was revoked, and a
    // forced sign-out on no evidence costs the user their session for
    // what is usually a transient link problem the next boot repairs.
    console.error('[devices] heartbeat RPC failed', error);
    return true;
  }
  // Only an explicit `false` from a caller the server could identify is
  // a revocation verdict: banned pubkey, or no live device row. Written
  // as `!== false` on purpose: `data === true` also read null/undefined
  // (a 2xx whose body postgrest-js could not parse into a boolean) as
  // revocation, and the consequence of a false revocation verdict is
  // forceSignOut wiping the phrase, wrapped blobs and local DB. Fail
  // open on anything that is not the server's explicit no, matching the
  // error branch above and migration 0064's contract. Session audit
  // 2026-08-25.
  return data !== false;
}

/** Quota usage + dynamic limits for the current pubkey. */
export type QuotaUsage = {
  noteCount: number;
  totalBytes: number;
  imageBytes: number;
  /** Dynamic limits from the server (Pro + add-ons). */
  maxNotes: number;
  maxTotalBytes: number;
  maxImageBytes: number;
  /** Set when user exceeds their storage cap (e.g. after storage sub cancels).
   *  NULL/undefined = within quota. ISO timestamp string when over quota. */
  quotaExceededSince: string | null;
};

// Spec: ops/docs/pro-features.md (Free: 50 MB combined, 10k notes; Pro: 500 MB combined, 10k notes)
const FALLBACK_FREE = { maxNotes: 10000, maxTotalBytes: 50 * 1000 * 1000, maxImageBytes: 50 * 1000 * 1000 };
const FALLBACK_PRO = { maxNotes: 10000, maxTotalBytes: 500 * 1000 * 1000, maxImageBytes: 500 * 1000 * 1000 };

/**
 * Fetch quota usage + dynamic limits from the server.
 * Returns zeroes/defaults if no row exists yet (new account).
 *
 * Tries `get_my_quota_status` first (includes quota_exceeded_since).
 * Falls back to `get_my_quota_limits` if the migration hasn't been applied.
 *
 * @param isPro - client-side Pro flag used as fallback when neither RPC exists.
 */
export async function fetchQuotaUsage(
  supabase: SupabaseClient,
  isPro?: boolean,
): Promise<QuotaUsage> {
  // Demo mode never queries the server - return inert defaults.
  if (isDemoMode()) {
    return {
      noteCount: 0,
      totalBytes: 0,
      imageBytes: 0,
      ...(isPro ? FALLBACK_PRO : FALLBACK_FREE),
      quotaExceededSince: null,
    };
  }
  // Fetch usage and limits in parallel.
  const [usageRes, statusRes] = await Promise.all([
    readWithRetry(() => supabase
      .from('pubkey_quotas')
      .select('note_count, total_bytes, image_bytes')
      .maybeSingle()),
    readWithRetry(() => supabase.rpc('get_my_quota_status')),
  ]);

  if (usageRes.error) {
    console.error('[devices] quota fetch failed', usageRes.error);
  }

  const usage = usageRes.data as Record<string, number> | null;
  const noteCount = usage?.note_count ?? 0;
  const totalBytes = usage?.total_bytes ?? 0;
  const imageBytes = usage?.image_bytes ?? 0;

  // Parse limits + exceeded timestamp from RPC.
  let limits: { maxNotes: number; maxTotalBytes: number; maxImageBytes: number };
  let quotaExceededSince: string | null = null;

  if (statusRes.error || !statusRes.data) {
    if (statusRes.error) {
      console.warn('[devices] get_my_quota_status RPC failed, trying fallback', statusRes.error.message);
    }
    // Fallback to old RPC or hardcoded defaults.
    const fallbackRes = await supabase.rpc('get_my_quota_limits');
    if (fallbackRes.error || !fallbackRes.data) {
      limits = isPro ? FALLBACK_PRO : FALLBACK_FREE;
    } else {
      const row = Array.isArray(fallbackRes.data) ? fallbackRes.data[0] : fallbackRes.data;
      limits = {
        maxNotes: (row as Record<string, number>)?.max_notes ?? FALLBACK_PRO.maxNotes,
        maxTotalBytes: (row as Record<string, number>)?.max_total_bytes ?? (isPro ? FALLBACK_PRO : FALLBACK_FREE).maxTotalBytes,
        maxImageBytes: (row as Record<string, number>)?.max_image_bytes ?? (isPro ? FALLBACK_PRO : FALLBACK_FREE).maxImageBytes,
      };
    }
  } else {
    // RPC returns a single row (TABLE return type -> array with one element,
    // or the Supabase client may unwrap it as an object).
    const row = Array.isArray(statusRes.data) ? statusRes.data[0] : statusRes.data;
    const r = row as Record<string, unknown>;
    limits = {
      maxNotes: (r?.max_notes as number) ?? FALLBACK_PRO.maxNotes,
      maxTotalBytes: (r?.max_total_bytes as number) ?? (isPro ? FALLBACK_PRO : FALLBACK_FREE).maxTotalBytes,
      maxImageBytes: (r?.max_image_bytes as number) ?? (isPro ? FALLBACK_PRO : FALLBACK_FREE).maxImageBytes,
    };
    quotaExceededSince = (r?.quota_exceeded_since as string) ?? null;
  }

  return { noteCount, totalBytes, imageBytes, ...limits, quotaExceededSince };
}

/** Ceiling on how many pending-GC uuids we hand the recalc RPC in one
 * request. The queue is drained by sweepBlobGC, so it only grows this far if
 * the sweep is failing; past the cap the excess blobs simply keep counting
 * until they are swept, which is the pre-0066 behaviour rather than a new
 * failure. Spec: ops/docs/design-decisions.md (deferred blob GC). */
const PENDING_GC_RPC_MAX = 5000;

/**
 * Recalculate quota counters from actual data on the server.
 *
 * Delta-based tracking in enforce_notes_quota can drift over time
 * (e.g. pre-0040 tombstones, silent image GC failures). This RPC
 * recomputes note_count and total_bytes from the notes table, and
 * image_bytes from Supabase Storage ground truth.
 *
 * Blobs sitting in the local deferred-GC queue are excluded from that
 * recompute (migration 0066). Their Storage objects are deliberately still
 * present during the 72h grace period, so a plain ground-truth recount would
 * re-add exactly the bytes deferDelete just subtracted and the storage bar
 * would never move on a delete. The queue is read here rather than at each
 * call site so no caller can forget it.
 *
 * Call after empty-trash or any bulk-delete sync completes.
 */
export async function recalculateQuota(supabase: SupabaseClient): Promise<void> {
  if (isDemoMode()) return;
  const pending = (await db.blobGC.limit(PENDING_GC_RPC_MAX).toArray()).map((e) => e.uuid);
  const { error } = await readWithRetry(() => supabase.rpc('recalculate_my_quota', { p_pending_gc: pending }));
  if (error) {
    // Best-effort - the RPC may not be deployed yet. Log and move on.
    console.warn('[devices] recalculate_my_quota failed:', error.message);
  }
}

/**
 * True on builds whose purchases live in a native store account (iOS App
 * Store, Google Play build). Desktop and the direct Android APK buy through
 * Paddle, where the entitlement follows the pubkey server-side - there is
 * nothing device-local to restore, so restore UI must not appear there.
 * Spec: ops/docs/plans/iap-restore-handoff.md (restore UI only appears on iOS or Play builds, not Paddle purchases)
 */
export function isNativeStoreBuild(): boolean {
  const platform = detectPlatform();
  if (platform === 'ios') return true;
  return platform === 'android' && import.meta.env.VITE_ANDROID_DIST !== 'direct';
}
