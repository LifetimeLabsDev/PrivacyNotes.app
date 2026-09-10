/**
 * 4-digit PIN gating phrase display and PIN-protected notes.
 *
 * Hash (PBKDF2-SHA256, 600k iterations, 16-byte salt) stored in UserSettings
 * and synced across devices. localStorage cache keeps `hasPin()` synchronous.
 * Legacy PINs (100k iterations) are upgraded transparently on next verify.
 */

import { bytesToBase64, base64ToBytes } from '@notes/shared';
import type { UserSettings } from './userSettings';
import { credentialKey } from './demo';

// Spec: THREAT_MODEL.md (PBKDF2-SHA256 600k iterations per OWASP 2024)
const ITERATIONS = 600_000;
const LEGACY_ITERATIONS = 100_000;
const KEY_BITS = 256;
const SALT_BYTES = 16;

// localStorage cache mirrors settings so `hasPin()` can be synchronous.
// Demo-bucketed (credentialKey in demo.ts) so a demo session's PIN
// never touches a real account's cache. Session audit 2026-08-25.
const CACHE_SALT = credentialKey('privacynotes.pinSalt');
const CACHE_HASH = credentialKey('privacynotes.pinHash');
const CACHE_ITERATIONS = credentialKey('privacynotes.pinIterations');

async function derive(pin: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('PIN requires a secure connection (HTTPS). Please access the app over HTTPS.');
  }
  const enc = new TextEncoder();
  const material = await crypto.subtle.importKey(
    'raw',
    enc.encode(pin),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt as BufferSource,
      iterations,
      hash: 'SHA-256',
    },
    material,
    KEY_BITS
  );
  return new Uint8Array(bits);
}

// ── Local cache helpers ──────────────────────────────────────────

function cacheWrite(salt: string | null, hash: string | null, iterations: number | null): void {
  try {
    if (salt && hash) {
      localStorage.setItem(CACHE_SALT, salt);
      localStorage.setItem(CACHE_HASH, hash);
      localStorage.setItem(CACHE_ITERATIONS, String(iterations ?? LEGACY_ITERATIONS));
    } else {
      localStorage.removeItem(CACHE_SALT);
      localStorage.removeItem(CACHE_HASH);
      localStorage.removeItem(CACHE_ITERATIONS);
    }
  } catch { /* storage disabled */ }
}

/** Sync the localStorage cache from UserSettings. Call after every settings sync. */
export function syncPinCache(settings: UserSettings): void {
  cacheWrite(settings.pinSalt, settings.pinHash, settings.pinIterations);
}

/**
 * Wipe every account-scoped PIN artifact on this device: the hash/salt
 * cache, the lockout counters, and the session unlock marker. Called on
 * sign-out and on the pubkey-owner mismatch wipe so PIN state can never
 * survive an account switch.
 *
 * History: a "legacy PIN migration" used to live here. It read the same
 * localStorage keys the cache above writes (they predate synced PINs)
 * and adopted whatever it found into settings whenever settings carried
 * no PIN - which on a shared browser meant a brand-new account inherited
 * the PREVIOUS account's PIN and pushed it into its own synced settings
 * (a cross-account PIN hash leak). The migration is gone; these keys are
 * now cleared at every account boundary instead.
 */
export function clearPinCache(): void {
  cacheWrite(null, null, null);
  clearPinFailures();
  clearPinUnlock();
}

// ── Public API ───────────────────────────────────────────────────

/** Synchronous check via localStorage cache (kept in sync by syncPinCache/setPin). */
export function hasPin(): boolean {
  try {
    return (
      localStorage.getItem(CACHE_HASH) !== null &&
      localStorage.getItem(CACHE_SALT) !== null
    );
  } catch {
    return false;
  }
}

/**
 * Hash a new PIN and return updated settings. Does NOT persist -
 * caller must save + sync. Updates localStorage cache immediately.
 */
export async function setPin(
  pin: string,
  settings: UserSettings
): Promise<UserSettings> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const hash = await derive(pin, salt, ITERATIONS);
  const saltB64 = bytesToBase64(salt);
  const hashB64 = bytesToBase64(hash);
  cacheWrite(saltB64, hashB64, ITERATIONS);
  return { ...settings, pinSalt: saltB64, pinHash: hashB64, pinIterations: ITERATIONS };
}

/** Remove the PIN from settings and clear unlock state. Caller must persist + sync. */
export function clearPinFromSettings(settings: UserSettings): UserSettings {
  cacheWrite(null, null, null);
  clearPinUnlock();
  return { ...settings, pinSalt: null, pinHash: null, pinIterations: null };
}

/** A wrap is salt, IV and ciphertext together, the triple syncPinWrap tests. */
export function hasPinWrap(
  s: Pick<UserSettings, 'pinWrapSalt' | 'pinWrapIV' | 'pinWrapCiphertext'>,
): boolean {
  return (
    typeof s.pinWrapSalt === 'string' &&
    typeof s.pinWrapIV === 'string' &&
    typeof s.pinWrapCiphertext === 'string'
  );
}

/**
 * Whether a PIN change must carry a new wrap of the phrase in the same
 * write. The wrap follows the hash: both live in the synced settings and
 * must describe the same PIN, so whenever the account holds a wrap, or the
 * app lock is on and will need one, the device that changes the PIN re-wraps
 * under the new PIN. A PIN-only account, with no lock and no wrap, never
 * gains one: a wrap is a durable copy of the phrase under four digits, and
 * only a lock to open justifies it. Pinned by tests/pinChange.test.ts.
 * Spec: ops/docs/archive/sec-65-pin-change-follows.md
 */
export function pinChangeNeedsWrap(
  settings: Pick<UserSettings, 'appLockEnabled' | 'pinWrapSalt' | 'pinWrapIV' | 'pinWrapCiphertext'>,
): boolean {
  return settings.appLockEnabled || hasPinWrap(settings);
}

/**
 * Verify a candidate PIN. Returns `{ valid, needsRehash }`.
 * When `needsRehash` is true, caller should call `setPin()` to upgrade
 * to current iteration count.
 */
export async function verifyPin(pin: string): Promise<{ valid: boolean; needsRehash: boolean }> {
  let saltB64: string | null;
  let hashB64: string | null;
  let iterStr: string | null;
  try {
    saltB64 = localStorage.getItem(CACHE_SALT);
    hashB64 = localStorage.getItem(CACHE_HASH);
    iterStr = localStorage.getItem(CACHE_ITERATIONS);
  } catch {
    return { valid: false, needsRehash: false };
  }
  if (!saltB64 || !hashB64) return { valid: false, needsRehash: false };

  const storedIterations = iterStr ? Number(iterStr) : LEGACY_ITERATIONS;
  const salt = base64ToBytes(saltB64);
  const expected = base64ToBytes(hashB64);

  // Try the stored iteration count first.
  if (constantTimeEqual(await derive(pin, salt, storedIterations), expected)) {
    return { valid: true, needsRehash: storedIterations < ITERATIONS };
  }

  // Auto-recovery: if the cache has the wrong iteration count (e.g.
  // syncPinCache wrote the legacy fallback because pinIterations was
  // null in the synced settings blob), retry with the other known
  // count. Fixes the cache on success so subsequent verifies are fast.
  const altIterations = storedIterations === ITERATIONS ? LEGACY_ITERATIONS : ITERATIONS;
  if (constantTimeEqual(await derive(pin, salt, altIterations), expected)) {
    // Fix the stale cache so this only costs one extra derive once.
    try { localStorage.setItem(CACHE_ITERATIONS, String(altIterations)); } catch { /* */ }
    return { valid: true, needsRehash: altIterations < ITERATIONS };
  }

  return { valid: false, needsRehash: false };
}

/** Constant-time comparison of two equal-length byte arrays. */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

// Brute-force protection - exponential backoff on failed attempts.
// localStorage-backed (not sessionStorage) so tab close doesn't reset it.
// UX gate only: offline PBKDF2 brute-force bypasses this entirely.

const MAX_ATTEMPTS = 5;
const BASE_LOCKOUT_SECONDS = 30;
const LOCKOUT_ATTEMPTS_KEY = credentialKey('privacynotes.pinFailCount');
const LOCKOUT_UNTIL_KEY = credentialKey('privacynotes.pinLockedUntil');

/** Record a failed PIN attempt. Returns the lockout state. */
export function recordPinFailure(): { locked: boolean; secondsLeft: number; attempts: number } {
  try {
    const count = Number(localStorage.getItem(LOCKOUT_ATTEMPTS_KEY) || '0') + 1;
    localStorage.setItem(LOCKOUT_ATTEMPTS_KEY, String(count));
    if (count >= MAX_ATTEMPTS) {
      // Exponential backoff: 30s, 60s, 120s, 240s...
      const lockoutMs = BASE_LOCKOUT_SECONDS * Math.pow(2, count - MAX_ATTEMPTS) * 1000;
      const until = Date.now() + lockoutMs;
      localStorage.setItem(LOCKOUT_UNTIL_KEY, String(until));
      return { locked: true, secondsLeft: Math.ceil(lockoutMs / 1000), attempts: count };
    }
    return { locked: false, secondsLeft: 0, attempts: count };
  } catch {
    return { locked: false, secondsLeft: 0, attempts: 0 };
  }
}

/** Clear failure count on successful verify. */
export function clearPinFailures(): void {
  try {
    localStorage.removeItem(LOCKOUT_ATTEMPTS_KEY);
    localStorage.removeItem(LOCKOUT_UNTIL_KEY);
  } catch { /* ignore */ }
}

/** Returns current lockout state `{ locked, secondsLeft, attempts }`. */
export function getPinLockoutState(): { locked: boolean; secondsLeft: number; attempts: number } {
  try {
    const attempts = Number(localStorage.getItem(LOCKOUT_ATTEMPTS_KEY) || '0');
    const until = Number(localStorage.getItem(LOCKOUT_UNTIL_KEY) || '0');
    if (until > Date.now()) {
      return { locked: true, secondsLeft: Math.ceil((until - Date.now()) / 1000), attempts };
    }
    // Lockout expired - keep the attempt count so the next failure
    // escalates the backoff further.
    return { locked: false, secondsLeft: 0, attempts };
  } catch {
    return { locked: false, secondsLeft: 0, attempts: 0 };
  }
}

// ─────────────────────────────────────────────────────────────────
// Session-level unlock memory
// ─────────────────────────────────────────────────────────────────

// sessionStorage-backed: closed tab always re-locks, never synced.
const UNLOCKED_KEY = credentialKey('privacynotes.pinUnlockedAt');

export function markPinUnlocked(): void {
  try {
    sessionStorage.setItem(UNLOCKED_KEY, String(Date.now()));
  } catch {
    /* private mode / storage off - user will be re-prompted, which is
       the safe default */
  }
}

function clearPinUnlock(): void {
  try {
    sessionStorage.removeItem(UNLOCKED_KEY);
  } catch {
    /* ignore */
  }
}

/**
 * Returns true if the user should be re-prompted for PIN.
 * `timeoutMinutes`: 0 = always ask, -1 = never (this session), >0 = the window.
 *
 * The window is measured from the stamp `markPinUnlocked` writes. An unlock
 * writes it; so does input inside an open protected note, which is what makes
 * the window an idle one rather than a countdown (see `pinKeepAlive.ts`).
 */
export function shouldPromptForPin(timeoutMinutes: number): boolean {
  if (timeoutMinutes === 0) return true;
  let raw: string | null;
  try {
    raw = sessionStorage.getItem(UNLOCKED_KEY);
  } catch {
    return true;
  }
  if (!raw) return true;
  if (timeoutMinutes < 0) return false;
  const last = Number(raw);
  if (!Number.isFinite(last)) return true;
  const elapsedMs = Date.now() - last;
  return elapsedMs > timeoutMinutes * 60_000;
}
