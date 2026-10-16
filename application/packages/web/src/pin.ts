/**
 * The app lock secret, a 4-digit PIN or a longer passcode, gating phrase
 * display and PIN-protected notes.
 *
 * Hash (PBKDF2-SHA256, 600k iterations) stored in UserSettings and synced
 * across devices. The salt is 16 bytes for a PIN and 24 for a passcode, which
 * is how every reader tells the two apart (secretKind.ts). localStorage cache
 * keeps `hasPin()` synchronous. A legacy hash (100k iterations) still
 * verifies, and stays until the secret is changed.
 */

import { bytesToBase64, base64ToBytes } from '@notes/shared';
import type { UserSettings } from './userSettings';
import { credentialKey } from './demo';
import { normalizeSecret, saltBytesFor, saltIsPasscode } from './secretKind';

// Spec: THREAT_MODEL.md (PBKDF2-SHA256 600k iterations per OWASP 2024)
const ITERATIONS = 600_000;
const LEGACY_ITERATIONS = 100_000;
const KEY_BITS = 256;

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
    enc.encode(normalizeSecret(pin)),
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

/** Synchronous check via localStorage cache (kept in sync by syncPinCache/stagePinHash). */
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
 * True when the account's secret, as this device caches its hash, is a
 * passcode. The PIN tab, the note gate, the phrase gate and the app-lock
 * confirm draw their field from it; the lock screen reads the wrap instead
 * (`pinWrapIsPasscode` in biometric.ts), because that is what it opens.
 */
export function pinIsPasscode(): boolean {
  try {
    return saltIsPasscode(localStorage.getItem(CACHE_SALT));
  } catch {
    return false;
  }
}

/** The salt and hash a check was made against, as the synced settings carry them. */
export type PinCredential = Pick<UserSettings, 'pinSalt' | 'pinHash'>;

/** The cached salt and hash, null when this device caches none. */
export function cachedPinCredential(): PinCredential {
  try {
    return { pinSalt: localStorage.getItem(CACHE_SALT), pinHash: localStorage.getItem(CACHE_HASH) };
  } catch {
    return { pinSalt: null, pinHash: null };
  }
}

/** A credential as one comparable value. */
export function credentialStamp(c: PinCredential): string {
  return `${c.pinSalt ?? ''}:${c.pinHash ?? ''}`;
}

/**
 * The cached hash and salt as one value. A check that starts under one stamp
 * and ends under another answered for a secret the account no longer holds
 * (a sync pass replaced it during the derivation), so its answer opens
 * nothing. Pinned by tests/secretSurfaces.test.ts.
 */
export function pinCredentialStamp(): string {
  return credentialStamp(cachedPinCredential());
}

/** A hash of the secret, as the synced settings carry it. */
export type PinHash = { pinSalt: string; pinHash: string; pinIterations: number };

/**
 * Hash a new secret at today's count, in memory, writing nothing. The salt
 * takes the length the secret's kind records (secretKind.ts).
 */
export async function hashPin(pin: string): Promise<PinHash> {
  const salt = crypto.getRandomValues(new Uint8Array(saltBytesFor(pin)));
  const hash = await derive(pin, salt, ITERATIONS);
  return { pinSalt: bytesToBase64(salt), pinHash: bytesToBase64(hash), pinIterations: ITERATIONS };
}

/**
 * Put a new hash into this device's cache before the settings that carry it
 * are saved, and read it back. Answers null, with the hash it had still in
 * place, when the store refuses it; otherwise a function that puts back the
 * hash it replaced, for a settings save that then does not land (saveCredential
 * in userSettings.ts). The put-back does nothing once another hash was cached
 * here. It writes the keys itself, not through cacheWrite, which swallows a
 * refusal.
 */
export function stagePinHash(h: PinHash): (() => void) | null {
  const keys = [CACHE_SALT, CACHE_HASH, CACHE_ITERATIONS];
  let previous: (string | null)[];
  try {
    previous = keys.map((k) => localStorage.getItem(k));
  } catch {
    return null;
  }
  // Putting the old values back returns the store to a size it already held.
  const putBack = () => keys.forEach((k, i) => {
    try {
      const v = previous[i];
      if (v === null || v === undefined) localStorage.removeItem(k);
      else localStorage.setItem(k, v);
    } catch { /* */ }
  });
  try {
    localStorage.setItem(CACHE_SALT, h.pinSalt);
    localStorage.setItem(CACHE_HASH, h.pinHash);
    localStorage.setItem(CACHE_ITERATIONS, String(h.pinIterations));
    if (localStorage.getItem(CACHE_SALT) !== h.pinSalt || localStorage.getItem(CACHE_HASH) !== h.pinHash) {
      throw new Error('read-back');
    }
  } catch {
    putBack();
    return null;
  }
  return () => {
    try {
      if (localStorage.getItem(CACHE_HASH) === h.pinHash) putBack();
    } catch { /* */ }
  };
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
 * Verify a candidate PIN. Returns `{ valid, needsRehash }`. `needsRehash` is
 * true for a valid PIN under a hash at the older count, and nothing acts on it
 * yet: a rehash saved here would be pushed over a newer secret another device
 * set before this one pulled it, so it waits on a guard in the settings push.
 * Spec: ops/docs/plans/app-lock-passcode.md (section 10)
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
