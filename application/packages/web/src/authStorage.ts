import { db } from './db';
import {
  hasPinWrappedPhrase,
  hasStoredPhrase,
} from './biometric';
import { hasPin } from './pin';
import { credentialKey } from './demo';

// Demo-bucketed (see credentialKey in demo.ts): a demo session must
// never read or write a real account's credential keys on the same
// origin. Session audit 2026-08-25.
export const PHRASE_STORAGE_KEY = credentialKey('privacynotes.phrase');

// Sticky flag: "this session's phrase was seeded via OAuth, not typed".
// Kept alongside the phrase in trust-aware storage so a reload still
// knows to treat the session as OAuth (and suppress the sign-out
// reminder, etc). Cleared on sign-out.
export const OAUTH_FLAG_KEY = 'privacynotes.oauth.active';

// Custom URL scheme the native (Tauri) apps register for the OAuth redirect
// back from the system browser. Must be listed in Supabase Auth's allowed
// redirect URLs. Web uses window.location.origin instead.
// Spec: ops/docs/macos-ios-setup.md (native OAuth)
export const OAUTH_NATIVE_REDIRECT = 'privacynotes://auth-callback';

// Tracks which pubkey "owns" the local IndexedDB. Compared against the
// incoming pubkey at the top of every authenticate call; on mismatch
// we wipe Dexie + cached blobs + lastSync before proceeding. Without
// this, a phrase swap (or OAuth swap - backlog.md #1) would leave the
// prior user's dirty notes in db.notes; the next sync push would
// upsert them under the new pubkey (cross-user data leak), and the
// new user's pasted images would dedup-collide with prior UUIDs they
// can't actually access. Persisted in plain localStorage because the
// pubkey isn't a secret and survival across signOut is the point.
export const PUBKEY_OWNER_KEY = 'privacynotes.currentPubkey';

// IndexedDB mirror of PUBKEY_OWNER_KEY (db.kv, key 'ownerPubkey').
// localStorage can be evicted while the Dexie notes survive, and that
// asymmetry made the owner-unknown wipe destroy the user's OWN wrapped
// phrase and unsynced rows (session audit 2026-08-25). The mirror
// lives with the data it vouches for, so the wipe check can tell "own
// data, lost marker" from "foreign leftovers". Best-effort on write
// (auth must not fail on a storage hiccup); null on read means the
// mirror predates this feature or the DB is unreadable.
export async function writeOwnerMirror(pubkey: string): Promise<void> {
  try {
    await db.kv.put({ key: 'ownerPubkey', value: pubkey });
  } catch { /* ignore */ }
}

export async function readOwnerMirror(): Promise<string | null> {
  try {
    const value = (await db.kv.get('ownerPubkey'))?.value;
    return typeof value === 'string' ? value : null;
  } catch {
    return null;
  }
}

/**
 * True when this tab may still write to (or wipe) the shared local
 * storage: either nothing has claimed it, or this account did.
 *
 * Every tab in this browser shares one Dexie database and one
 * localStorage. Once another tab authenticates a DIFFERENT account, this
 * tab is stale, and both of the things a stale tab would otherwise do
 * are destructive: its sign-out wipes the new account's notes, settings
 * and stored phrase (in a zero-knowledge app, deleting a phrase the user
 * never wrote down is permanent account loss), and its sync re-encrypts
 * whatever now sits in Dexie under THIS account's key and pushes it to
 * THIS account.
 */
export function ownsLocalData(pubkey: string): boolean {
  try {
    const owner = localStorage.getItem(PUBKEY_OWNER_KEY);
    return owner === null || owner === pubkey;
  } catch {
    // Storage unreadable: fall back to the pre-guard behavior rather
    // than stranding a legitimate sign-out with a half-wiped device.
    return true;
  }
}

/**
 * Account-scoped UI state that is neither secret nor synced, but is
 * derived from one account's content and must not follow the user into
 * the next account on this browser: the expanded-folder set (folder
 * UUIDs) and the milestone high-water marks (note-count thresholds the
 * previous account had crossed). Both keys are cleared by every wipe
 * path; they live here so the two paths cannot drift apart.
 */
export function clearAccountScopedUiState(): void {
  try {
    localStorage.removeItem('privacynotes.foldersExpanded'); // FolderTree.tsx
    // Legacy: milestone state moved to UserSettings.milestonesSeen (synced).
    // Still cleared so a pre-move install does not leave it behind.
    localStorage.removeItem('privacynotes.milestonesSeen');
    // Armed by the account that completed a domain-move handoff; the
    // next account on this install must not see its bookmark hint.
    localStorage.removeItem('privacynotes.movedFromApex'); // migrate.ts / MoveBanner.tsx
  } catch { /* ignore */ }
}

/**
 * True if this browser holds account-scoped local state: a cached
 * settings blob, a PIN cache, a wrapped phrase, the stored session
 * phrase itself, or notes in Dexie. The pubkey-owner check treats a
 * null PUBKEY_OWNER_KEY as "unknown owner" rather than "no prior
 * account" when this is true - a null owner with data present is
 * exactly the state that let a prior account's settings blob (PIN
 * hash, wrapped phrase, folders) be adopted by the freshVault seed
 * and pushed under a new pubkey.
 *
 * The stored-phrase check is safe here because this function is only
 * consulted when the owner marker AND the db.kv owner mirror are both
 * absent (auth.tsx wipePrior): a signed-in install always carries the
 * marker, and "own data, lost marker" is answered by the mirror one
 * branch earlier - so a phrase that survives into this branch is a
 * prior account's leftover from a botched sign-out, and counting it
 * makes the unknown-owner wipe clean it instead of adopting around it.
 */
export async function hasLocalAccountState(): Promise<boolean> {
  try {
    if (localStorage.getItem('privacynotes.settings')) return true;
  } catch { /* ignore */ }
  if (hasPin() || hasPinWrappedPhrase() || hasStoredPhrase()) return true;
  try {
    if ((await db.notes.count()) > 0) return true;
  } catch { /* ignore */ }
  return false;
}

// Cached account flags for the local-first fast boot. Written on every
// successful server-side registration, read on startup so a returning
// trusted user can be marked authenticated (and see their local notes)
// before any network round-trip completes. Keyed by pubkey so a phrase
// swap never reuses another account's flags. Plain localStorage: the
// flags are not secrets, and survival across reloads is the point.
const ACCOUNT_FLAGS_KEY = 'privacynotes.accountFlags';

type CachedAccountFlags = {
  pubkey: string;
  isPro: boolean;
  isEarlySupporter: boolean;
  /**
   * Whether the server holds a copy of this user's phrase. Optional
   * because flags written before this field existed lack it; absent
   * reads as "unknown", which the callers treat as not-custodial.
   *
   * This is a boot-speed mirror, NOT the source of truth. The truth is
   * the custodial_phrases row, mirrored into `app_metadata.custodial`
   * on the JWT; `reconcileCustody` below corrects this cache from that
   * claim shortly after sign-in. Cached because the fast-boot path
   * renders before any network round trip, and hiding the "switch to
   * self-custody" action from a custodial user until the network
   * answers is the wrong way to be wrong.
   */
  isCustodial?: boolean;
};

export function readCachedAccountFlags(pubkey: string): CachedAccountFlags | null {
  try {
    const raw = localStorage.getItem(ACCOUNT_FLAGS_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as CachedAccountFlags;
    if (parsed?.pubkey !== pubkey) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function writeCachedAccountFlags(flags: CachedAccountFlags): void {
  try {
    localStorage.setItem(ACCOUNT_FLAGS_KEY, JSON.stringify(flags));
  } catch {
    /* quota or privacy mode - the mirror below still carries the flags */
  }
  void writeAccountFlagsMirror(flags);
}

export function clearCachedAccountFlags(): void {
  try {
    localStorage.removeItem(ACCOUNT_FLAGS_KEY);
  } catch {
    /* ignore */
  }
  void clearAccountFlagsMirror();
}

/**
 * IndexedDB mirror of ACCOUNT_FLAGS_KEY (db.kv, key 'accountFlags').
 *
 * Both fast-boot gates - the owner marker and these flags - read
 * localStorage, and an eviction takes every key at once, so mirroring
 * one without the other buys nothing: the boot still falls through to
 * the network path with the notes sitting untouched in Dexie. Same
 * reasoning as the owner mirror above, same storage, same best-effort
 * write. These are not secrets; the pubkey scoping is what stops one
 * account reading another's.
 */
async function writeAccountFlagsMirror(flags: CachedAccountFlags): Promise<void> {
  try {
    await db.kv.put({ key: 'accountFlags', value: JSON.stringify(flags) });
  } catch { /* ignore */ }
}

export async function readAccountFlagsMirror(pubkey: string): Promise<CachedAccountFlags | null> {
  try {
    const value = (await db.kv.get('accountFlags'))?.value;
    if (typeof value !== 'string') return null;
    const parsed = JSON.parse(value) as CachedAccountFlags;
    return parsed?.pubkey === pubkey ? parsed : null;
  } catch {
    return null;
  }
}

async function clearAccountFlagsMirror(): Promise<void> {
  try {
    await db.kv.delete('accountFlags');
  } catch { /* ignore */ }
}

/** Patch just the custody bit, leaving the Pro flags alone. No-op if
 *  the cache belongs to another pubkey or does not exist yet. */
export function patchCachedCustodial(pubkey: string, isCustodial: boolean): void {
  const cached = readCachedAccountFlags(pubkey);
  if (!cached) return;
  writeCachedAccountFlags({ ...cached, isCustodial });
}

/**
 * Read the `app_metadata.custodial` claim off a JWT payload. Returns
 * null when the token is unreadable or carries no claim (a legacy
 * account that has not re-hydrated since the flag shipped), which is
 * distinct from an explicit `false`.
 *
 * No verification: the caller either got this token from supabase-js
 * or already validated it. The claim is a UI hint, and every action it
 * gates is independently authorized server-side.
 */
export function jwtPayloadCustodial(token: string): boolean | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const b64 = parts[1]!.replace(/-/g, '+').replace(/_/g, '/');
    const payload = JSON.parse(atob(b64));
    const flag = payload?.app_metadata?.custodial;
    return typeof flag === 'boolean' ? flag : null;
  } catch {
    return null;
  }
}

// Throttle marker for the register-device edge function. Registration is
// idempotent (the server just bumps last_seen_at for a known device) and
// the heartbeat RPC keeps last_seen fresh anyway, so calling it on every
// boot only adds 1-3 s of edge-function latency for zero information.
// Skip it when this (pubkey, deviceId) pair registered successfully within
// the last 24 h. A revoked device is still caught by the heartbeat on the
// first sync; sign-out clears the marker so a fresh sign-in re-registers.
const DEVICE_REGISTERED_KEY = 'privacynotes.deviceRegisteredAt';
const REGISTER_THROTTLE_MS = 24 * 60 * 60 * 1000;

export function hasRecentRegistration(pubkey: string, deviceId: string): boolean {
  try {
    const raw = localStorage.getItem(DEVICE_REGISTERED_KEY);
    if (!raw) return false;
    const parsed = JSON.parse(raw) as { pubkey: string; deviceId: string; at: number };
    return (
      parsed?.pubkey === pubkey &&
      parsed?.deviceId === deviceId &&
      typeof parsed?.at === 'number' &&
      Date.now() - parsed.at < REGISTER_THROTTLE_MS
    );
  } catch {
    return false;
  }
}

export function markRegistered(pubkey: string, deviceId: string): void {
  try {
    localStorage.setItem(
      DEVICE_REGISTERED_KEY,
      JSON.stringify({ pubkey, deviceId, at: Date.now() }),
    );
  } catch {
    /* ignore - worst case we register again next boot */
  }
}

export function clearRegistrationMarker(): void {
  try {
    localStorage.removeItem(DEVICE_REGISTERED_KEY);
  } catch {
    /* ignore */
  }
}

/**
 * Called by sync when the server rejects writes with a row-level
 * security error: that means this session's pubkey link is broken
 * server-side, and fast-booting into it for up to 24 h would keep the
 * vault permanently unsyncable. Clearing the marker makes the next
 * boot run the full link-pubkey + register-device handshake (see the
 * needsLink condition in _authenticateWithPhrase), which repairs the
 * link without the user having to clear browser data.
 */
export function invalidateDeviceRegistration(): void {
  clearRegistrationMarker();
}

/**
 * Decode a JWT's payload (no verification - caller already validated
 * the token via getUser()) and return the `app_metadata.pubkey` claim,
 * or null if absent/malformed. Used to detect whether link-pubkey +
 * refreshSession can be skipped for returning users.
 */
export function jwtPayloadPubkey(token: string): string | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    // Base64url → base64 → decode
    const b64 = parts[1]!.replace(/-/g, '+').replace(/_/g, '/');
    const json = atob(b64);
    const payload = JSON.parse(json);
    const pk = payload?.app_metadata?.pubkey;
    return typeof pk === 'string' && pk.length === 64 ? pk : null;
  } catch {
    return null;
  }
}
