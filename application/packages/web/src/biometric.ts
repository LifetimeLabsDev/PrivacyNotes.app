/**
 * Biometric unlock - presence gate + AES-GCM phrase wrapping.
 *
 * Two interchangeable gates, picked per device: WebAuthn on the web, and the OS
 * authenticator (Touch ID, Windows Hello, an Android fingerprint) in the native
 * app, whose webview never exposes a WebAuthn platform authenticator. Which one
 * wrapped a blob is recorded in the stored credential id, so an unlock always
 * prompts the same way the enrollment did.
 * Spec: ops/docs/biometric-unlock.md, backlog #101
 *
 * Either gate is a user-presence check only (Touch ID / Face ID /
 * Windows Hello) - it does NOT derive a crypto key. The phrase is wrapped
 * with a random AES-GCM-256 key that sits in localStorage beside the blob
 * it wraps, so storage access bypasses the gate entirely - weaker than the
 * default device envelope, whose key is non-extractable. Casual-access
 * gate, not a cryptographic one.
 *
 * Also provides PIN-based phrase wrapping (PBKDF2, convenience only).
 * Note encryption is untouched - this module only wraps the stored phrase.
 */

import {
  bytesToBase64,
  base64ToBytes,
  bytesToBase64url,
  base64urlToBytes,
} from '@notes/shared';
import { detectPlatform } from './devices';
import { credentialKey } from './demo';
import { isTrustedDevice } from './trustStorage';

// ── Constants ──────────────────────────────────────────────────
// All demo-bucketed (see credentialKey in demo.ts): the demo's usable
// Security tabs must never touch a real account's wrapped phrase on
// the same origin. Session audit 2026-08-25.

const BIO_CREDENTIAL_ID = credentialKey('privacynotes.bio.credentialId');
const BIO_WRAP_KEY = credentialKey('privacynotes.bio.wrapKey');
const BIO_IV = credentialKey('privacynotes.bio.iv');
const BIO_WRAPPED = credentialKey('privacynotes.bio.wrapped');

const PIN_PBKDF2_SALT = credentialKey('privacynotes.pin.pbkdf2Salt');
const PIN_IV = credentialKey('privacynotes.pin.iv');
const PIN_WRAPPED = credentialKey('privacynotes.pin.wrapped');
const PIN_ITERATIONS_KEY = credentialKey('privacynotes.pin.iterations');

const AES_GCM_IV_BYTES = 12;
const PBKDF2_SALT_BYTES = 16;
const AES_KEY_BITS = 256;
const PBKDF2_ITERATIONS = 600_000;

// ── Helpers ─────────────────────────────────────────────────────

/** Cast Uint8Array to ArrayBuffer for Web Crypto strict typing. */
function buf(u: Uint8Array): ArrayBuffer {
  return u.buffer instanceof ArrayBuffer && u.byteOffset === 0 && u.byteLength === u.buffer.byteLength
    ? u.buffer
    : u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;
}

const textEnc = new TextEncoder();

// ── AES-GCM helpers ────────────────────────────────────────────

// Exported for phraseAtRest.ts, which wraps the stored session phrase
// with the same primitive under a non-extractable device key.
export async function aesGcmEncrypt(
  key: CryptoKey,
  plaintext: string,
): Promise<{ ciphertext: Uint8Array; iv: Uint8Array }> {
  const iv = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));
  const encoded = textEnc.encode(plaintext);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: buf(iv) }, key, buf(encoded)),
  );
  return { ciphertext, iv };
}

export async function aesGcmDecrypt(
  key: CryptoKey,
  ciphertext: Uint8Array,
  iv: Uint8Array,
): Promise<string> {
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: buf(iv) },
    key,
    buf(ciphertext),
  );
  return new TextDecoder().decode(decrypted);
}

// ── Native (OS) gate ────────────────────────────────────────────

/**
 * Credential-id sentinel for a blob gated by the OS authenticator rather than a
 * WebAuthn credential. Stored so a blob is always unlocked by the gate that
 * wrapped it, whatever the current platform reports.
 */
const NATIVE_CREDENTIAL_ID = 'native';

async function invokeTauri<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const { invoke } = await import('@tauri-apps/api/core');
  return await invoke<T>(cmd, args);
}

/**
 * True when the OS itself can gate on biometrics: Touch ID / Face ID via
 * LocalAuthentication (macOS, iOS), Windows Hello via UserConsentVerifier,
 * BiometricPrompt via androidx.biometric (Android). Embedded webviews expose no
 * WebAuthn platform authenticator, so in a native build the OS is the only route
 * to a fingerprint. Asked on every native platform, since the command answers
 * false where there is nothing to offer (Linux) - only the web is skipped, where
 * there is no command at all.
 * Deliberately not cached: enrolling a finger, or a biometry lockout, flips the
 * answer while the app is open.
 * Spec: ops/docs/biometric-unlock.md (section 3.2 native path), backlog #101
 */
async function canUseNativeBiometric(): Promise<boolean> {
  if (detectPlatform() === 'web') return false;
  try {
    return await invokeTauri<boolean>('biometric_available');
  } catch {
    // A shell older than this web bundle has no such command.
    return false;
  }
}

/** Present the OS biometric prompt. False on cancel, failure, or no prompt. */
async function nativeAuthenticate(reason: string, cancelLabel: string): Promise<boolean> {
  try {
    return await invokeTauri<boolean>('biometric_authenticate', { reason, cancelLabel });
  } catch {
    return false;
  }
}

// ── Feature detection ───────────────────────────────────────────

/**
 * Can this device support biometric unlock? True when either gate is usable:
 * the OS authenticator (native app) or a WebAuthn platform authenticator (web).
 */
export async function canUseBiometric(): Promise<boolean> {
  if (typeof window === 'undefined') return false;
  if (await canUseNativeBiometric()) return true;
  if (!window.PublicKeyCredential) return false;
  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

// ── WebAuthn presence gate (no PRF) ────────────────────────────

export type BiometricEnrollResult =
  | { ok: true }
  | { ok: false; reason: 'user_cancelled' | 'error'; message: string };

/** Wrap the phrase with a fresh random AES-GCM-256 key and persist the blob. */
async function storeWrappedPhrase(phrase: string, credentialId: string): Promise<void> {
  const wrapKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: AES_KEY_BITS },
    true, // extractable so we can export to localStorage
    ['encrypt', 'decrypt'],
  );
  const { ciphertext, iv } = await aesGcmEncrypt(wrapKey, phrase);

  // Export raw key bytes for localStorage.
  const rawKey = new Uint8Array(await crypto.subtle.exportKey('raw', wrapKey));

  localStorage.setItem(BIO_CREDENTIAL_ID, credentialId);
  localStorage.setItem(BIO_WRAP_KEY, bytesToBase64(rawKey));
  localStorage.setItem(BIO_IV, bytesToBase64(iv));
  localStorage.setItem(BIO_WRAPPED, bytesToBase64(ciphertext));
}

/**
 * Enroll biometric unlock: pass the OS biometric prompt (native app) or create
 * a WebAuthn credential (web), then wrap the phrase with a random AES-GCM key
 * and store it in localStorage.
 *
 * The OS prompt renders both strings, so callers pass them translated: the
 * reason for the prompt, and the label for the cancel button Android draws
 * itself. This module has no i18n access, which is why they are parameters.
 */
export async function enrollBiometric(
  phrase: string,
  pubkey: string,
  reason: string,
  cancelLabel: string,
): Promise<BiometricEnrollResult> {
  try {
    // The native gate has nothing to register: passing the OS prompt IS the
    // enrollment. The sentinel id records which gate an unlock should use.
    if (await canUseNativeBiometric()) {
      if (!(await nativeAuthenticate(reason, cancelLabel))) {
        return { ok: false, reason: 'user_cancelled', message: 'Biometric verification was cancelled.' };
      }
      await storeWrappedPhrase(phrase, NATIVE_CREDENTIAL_ID);
      return { ok: true };
    }

    const userId = textEnc.encode(pubkey.slice(0, 64));
    const challenge = crypto.getRandomValues(new Uint8Array(32));

    const createOptions: PublicKeyCredentialCreationOptions = {
      rp: { name: 'PrivacyNotes', id: window.location.hostname },
      user: {
        id: buf(userId),
        name: 'PrivacyNotes User',
        displayName: 'PrivacyNotes',
      },
      challenge: buf(challenge),
      pubKeyCredParams: [
        { alg: -7, type: 'public-key' },   // ES256
        { alg: -257, type: 'public-key' },  // RS256 fallback
      ],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        userVerification: 'required',
        residentKey: 'preferred',
      },
    };

    // hints not yet in all TS type defs
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (createOptions as any).hints = ['client-device'];

    const credential = (await navigator.credentials.create({
      publicKey: createOptions,
    })) as PublicKeyCredential | null;

    if (!credential) {
      return { ok: false, reason: 'user_cancelled', message: 'Credential creation was cancelled.' };
    }

    const credentialId = new Uint8Array(credential.rawId);
    await storeWrappedPhrase(phrase, bytesToBase64url(credentialId));

    return { ok: true };
  } catch (err) {
    if (err instanceof DOMException && err.name === 'NotAllowedError') {
      return { ok: false, reason: 'user_cancelled', message: 'Biometric verification was cancelled.' };
    }
    return {
      ok: false,
      reason: 'error',
      message: err instanceof Error ? err.message : 'Unknown error during biometric enrollment.',
    };
  }
}

/**
 * Prompt for biometric, then unwrap the phrase from localStorage. Prompts
 * through whichever gate enrolled this device: the OS authenticator or a
 * WebAuthn assertion.
 *
 * The OS prompt renders both strings, so callers pass them translated: the
 * reason for the prompt, and the label for the cancel button Android draws
 * itself. This module has no i18n access, which is why they are parameters.
 */
export async function unlockWithBiometric(
  reason: string,
  cancelLabel: string,
): Promise<string | null> {
  const credIdB64 = localStorage.getItem(BIO_CREDENTIAL_ID);
  const wrapKeyB64 = localStorage.getItem(BIO_WRAP_KEY);
  const ivB64 = localStorage.getItem(BIO_IV);
  const wrappedB64 = localStorage.getItem(BIO_WRAPPED);

  if (!credIdB64 || !wrapKeyB64 || !ivB64 || !wrappedB64) return null;

  try {
    // Enrolled against the OS authenticator: no credential to assert, the
    // prompt itself is the gate.
    if (credIdB64 === NATIVE_CREDENTIAL_ID) {
      if (!(await nativeAuthenticate(reason, cancelLabel))) return null;
      return await unwrapStoredPhrase(wrapKeyB64, ivB64, wrappedB64);
    }

    const credentialId = base64urlToBytes(credIdB64);
    const challenge = crypto.getRandomValues(new Uint8Array(32));

    const getOptions: PublicKeyCredentialRequestOptions = {
      rpId: window.location.hostname,
      challenge: buf(challenge),
      allowCredentials: [{ id: buf(credentialId), type: 'public-key' }],
      userVerification: 'required',
    };

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (getOptions as any).hints = ['client-device'];

    const assertion = (await navigator.credentials.get({
      publicKey: getOptions,
    })) as PublicKeyCredential | null;

    // If user cancelled or biometric failed, return null
    if (!assertion) return null;

    return await unwrapStoredPhrase(wrapKeyB64, ivB64, wrappedB64);
  } catch {
    return null;
  }
}

/** Biometric passed - unwrap the phrase with the key held in localStorage. */
async function unwrapStoredPhrase(
  wrapKeyB64: string,
  ivB64: string,
  wrappedB64: string,
): Promise<string> {
  const rawKey = base64ToBytes(wrapKeyB64);
  const key = await crypto.subtle.importKey(
    'raw',
    buf(rawKey),
    { name: 'AES-GCM', length: AES_KEY_BITS },
    false,
    ['decrypt'],
  );
  return await aesGcmDecrypt(key, base64ToBytes(wrappedB64), base64ToBytes(ivB64));
}

/** Check if a biometric-wrapped phrase blob exists in localStorage. */
export function hasBiometricCredential(): boolean {
  try {
    return localStorage.getItem(BIO_WRAPPED) !== null
      && localStorage.getItem(BIO_CREDENTIAL_ID) !== null;
  } catch {
    return false;
  }
}

/** Remove all biometric credential data from localStorage. */
export function removeBiometricCredential(): void {
  try {
    localStorage.removeItem(BIO_CREDENTIAL_ID);
    localStorage.removeItem(BIO_WRAP_KEY);
    localStorage.removeItem(BIO_IV);
    localStorage.removeItem(BIO_WRAPPED);
    // Clean up legacy PRF keys if they exist
    localStorage.removeItem('privacynotes.bio.prfSalt');
    localStorage.removeItem('privacynotes.bio.hkdfSalt');
  } catch {
    /* storage unavailable */
  }
}

// ── PIN-based phrase wrapping ───────────────────────────────────

// Spec: THREAT_MODEL.md (PBKDF2-SHA256 600k iterations per OWASP 2024)
const PIN_PBKDF2_ITERATIONS = PBKDF2_ITERATIONS;
const LEGACY_PIN_PBKDF2_ITERATIONS = 100_000;

async function deriveKeyFromPin(
  pin: string,
  salt: Uint8Array,
  iterations: number = PIN_PBKDF2_ITERATIONS,
): Promise<CryptoKey> {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('PIN requires a secure connection (HTTPS). Please access the app over HTTPS.');
  }
  const material = await crypto.subtle.importKey(
    'raw',
    buf(textEnc.encode(pin)),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: buf(salt),
      iterations,
      hash: 'SHA-256',
    },
    material,
    { name: 'AES-GCM', length: AES_KEY_BITS },
    false,
    ['encrypt', 'decrypt'],
  );
}

export type PinWrapBlob = {
  pinWrapSalt: string;
  pinWrapIV: string;
  pinWrapCiphertext: string;
  pinWrapIterations: number;
};

/**
 * Derive and encrypt only: the blob that goes into the synced settings, with
 * no storage access. A device the user marked untrusted changes the PIN
 * through this, so the account's wrap follows the new PIN while that device
 * keeps no copy of it. Pinned by tests/pinChange.test.ts.
 */
export async function buildPinWrap(phrase: string, pin: string): Promise<PinWrapBlob> {
  const salt = crypto.getRandomValues(new Uint8Array(PBKDF2_SALT_BYTES));
  const key = await deriveKeyFromPin(pin, salt);
  const { ciphertext, iv } = await aesGcmEncrypt(key, phrase);
  return {
    pinWrapSalt: bytesToBase64(salt),
    pinWrapIV: bytesToBase64(iv),
    pinWrapCiphertext: bytesToBase64(ciphertext),
    pinWrapIterations: PIN_PBKDF2_ITERATIONS,
  };
}

/**
 * Build the blob and store it as this device's own wrap. The four writes
 * throw when the store refuses, and the PIN tab strips the phrase at rest
 * only after this returns, so a device whose disk refused the wrap keeps its
 * door.
 */
export async function wrapPhraseWithPin(
  phrase: string,
  pin: string,
): Promise<PinWrapBlob> {
  const blob = await buildPinWrap(phrase, pin);
  localStorage.setItem(PIN_PBKDF2_SALT, blob.pinWrapSalt);
  localStorage.setItem(PIN_IV, blob.pinWrapIV);
  localStorage.setItem(PIN_WRAPPED, blob.pinWrapCiphertext);
  localStorage.setItem(PIN_ITERATIONS_KEY, String(blob.pinWrapIterations));
  return blob;
}

/**
 * True when the wrap this device holds IS the given one, by salt and
 * ciphertext. syncPinWrap asks it so a PIN changed on another device, which
 * re-wraps under the new PIN, replaces the blob here rather than leaving a
 * wrap the retired PIN still opens. Pinned by tests/pinRecovery.test.ts.
 */
export function hasSamePinWrap(blob: Pick<PinWrapBlob, 'pinWrapSalt' | 'pinWrapCiphertext'>): boolean {
  try {
    return (
      localStorage.getItem(PIN_WRAPPED) === blob.pinWrapCiphertext &&
      localStorage.getItem(PIN_PBKDF2_SALT) === blob.pinWrapSalt
    );
  } catch {
    return false;
  }
}

/**
 * Write a synced PIN wrap blob into localStorage so app lock works on this
 * device.
 *
 * Gated on the trust choice, and the gate lives HERE rather than at the call
 * sites on purpose: there were two callers and neither checked, so a user who
 * answered "shared computer" at sign-in still ended up with a persistent,
 * offline-attackable copy of their wrapped phrase on that machine. A PIN is
 * four digits, so the whole keyspace is ten thousand guesses against a blob the
 * attacker can take away with them. Putting the check inside the function means
 * a third caller cannot reintroduce the hole by forgetting it.
 *
 * The cost is deliberate and small: on an untrusted device app lock does not
 * light up automatically from synced settings. Setting a PIN on that device
 * still works, because that path writes its own blob.
 */
export function hydrateLocalPinWrap(blob: PinWrapBlob): void {
  if (!isTrustedDevice()) return;
  try {
    localStorage.setItem(PIN_PBKDF2_SALT, blob.pinWrapSalt);
    localStorage.setItem(PIN_IV, blob.pinWrapIV);
    localStorage.setItem(PIN_WRAPPED, blob.pinWrapCiphertext);
    localStorage.setItem(PIN_ITERATIONS_KEY, String(blob.pinWrapIterations ?? LEGACY_PIN_PBKDF2_ITERATIONS));
  } catch {
    /* storage unavailable */
  }
}

/**
 * `onUpgraded` receives the blob a legacy-iteration wrap was re-wrapped
 * into after a successful unlock. The re-wrap is local; the caller carries
 * the blob to the synced settings, because every device replaces a wrap
 * that differs from the account's, and an upgrade the account never learns
 * of would be undone on the next pass and redone on the next unlock.
 */
export async function unwrapPhraseWithPin(
  pin: string,
  onUpgraded?: (blob: PinWrapBlob) => void,
): Promise<string | null> {
  const saltB64 = localStorage.getItem(PIN_PBKDF2_SALT);
  const ivB64 = localStorage.getItem(PIN_IV);
  const wrappedB64 = localStorage.getItem(PIN_WRAPPED);

  if (!saltB64 || !ivB64 || !wrappedB64) return null;

  const storedIterations = parseInt(localStorage.getItem(PIN_ITERATIONS_KEY) ?? '', 10) || LEGACY_PIN_PBKDF2_ITERATIONS;
  const salt = base64ToBytes(saltB64);
  const ciphertext = base64ToBytes(wrappedB64);
  const iv = base64ToBytes(ivB64);

  // Try with stored iteration count first.
  try {
    const key = await deriveKeyFromPin(pin, salt, storedIterations);
    const phrase = await aesGcmDecrypt(key, ciphertext, iv);

    // Auto-upgrade: re-wrap with current iterations if using legacy count.
    if (storedIterations < PIN_PBKDF2_ITERATIONS) {
      wrapPhraseWithPin(phrase, pin).then((b) => onUpgraded?.(b)).catch(() => { /* best-effort upgrade */ });
    }

    return phrase;
  } catch {
    // If stored iterations differ from legacy, also try legacy as fallback
    // (handles edge case where PIN_ITERATIONS_KEY was lost/corrupt).
    if (storedIterations !== LEGACY_PIN_PBKDF2_ITERATIONS) {
      try {
        const legacyKey = await deriveKeyFromPin(pin, salt, LEGACY_PIN_PBKDF2_ITERATIONS);
        const phrase = await aesGcmDecrypt(legacyKey, ciphertext, iv);
        wrapPhraseWithPin(phrase, pin).then((b) => onUpgraded?.(b)).catch(() => { /* best-effort upgrade */ });
        return phrase;
      } catch {
        return null;
      }
    }
    return null;
  }
}

export function hasPinWrappedPhrase(): boolean {
  try {
    return localStorage.getItem(PIN_WRAPPED) !== null
      && localStorage.getItem(PIN_PBKDF2_SALT) !== null;
  } catch {
    return false;
  }
}

export function removePinWrappedPhrase(): void {
  try {
    localStorage.removeItem(PIN_PBKDF2_SALT);
    localStorage.removeItem(PIN_IV);
    localStorage.removeItem(PIN_WRAPPED);
    localStorage.removeItem(PIN_ITERATIONS_KEY);
  } catch {
    /* storage unavailable */
  }
}

// ── Stored phrase removal ───────────────────────────────────────

// Local copy to avoid the authStorage import cycle; same demo bucket
// as the canonical PHRASE_STORAGE_KEY in authStorage.ts.
const PHRASE_STORAGE_KEY = credentialKey('privacynotes.phrase');

/**
 * True while a phrase is stored on this device, i.e. this browser is
 * still signed in. Presence only - the value is a wrapped envelope
 * (phraseAtRest.ts), or legacy plaintext on a not-yet-migrated
 * install. Distinguishes "the user changed an app-lock setting" from
 * "another tab signed out", which removes the wrapped blobs and the
 * stored phrase together.
 */
export function hasStoredPhrase(): boolean {
  try {
    if (localStorage.getItem(PHRASE_STORAGE_KEY) !== null) return true;
  } catch { /* storage unavailable */ }
  try {
    return sessionStorage.getItem(PHRASE_STORAGE_KEY) !== null;
  } catch {
    return false;
  }
}

/** Enabling app lock strips the stored phrase: from then on the ONLY
 *  door back into the session is a PIN or biometric unlock. */
export function removeStoredPhrase(): void {
  try { localStorage.removeItem(PHRASE_STORAGE_KEY); } catch { /* */ }
  try { sessionStorage.removeItem(PHRASE_STORAGE_KEY); } catch { /* */ }
}

// ── Cross-tab sync ──────────────────────────────────────────────

export function onWrappedBlobChange(callback: () => void): () => void {
  const keys = new Set([BIO_WRAPPED, BIO_CREDENTIAL_ID, PIN_WRAPPED]);
  function handler(e: StorageEvent) {
    if (e.key && keys.has(e.key)) callback();
  }
  window.addEventListener('storage', handler);
  return () => window.removeEventListener('storage', handler);
}
