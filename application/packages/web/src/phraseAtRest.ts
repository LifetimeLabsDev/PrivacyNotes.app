/**
 * Phrase at rest - the stored recovery phrase is an AES-GCM envelope
 * wherever the platform allows (see the failure policy below).
 *
 * A phrase readable from storage is the whole account: whoever holds
 * the storage file holds the vault. So the stored value is an AES-GCM
 * envelope under a non-extractable WebCrypto AES-256 key that lives in
 * IndexedDB (db.kv). IndexedDB persists the CryptoKey OBJECT via
 * structured clone; the raw key bytes never exist in script-readable
 * form, so a copied localStorage file or a serialized backup of the
 * databases cannot recover the phrase (pre-launch audit 2026-08-28,
 * findings 8 and 9). An attacker who can RUN CODE in this origin on
 * this machine can still use the key - that boundary is documented in
 * THREAT_MODEL.md.
 *
 * The envelope reuses the phrase's own storage key. Every presence
 * check (hasStoredSession, the app-lock gate, sign-out removal, the
 * demo credential sweep) keys on presence, not shape, so they all keep
 * working unchanged.
 *
 * Failure policy, in one line: the wrap is best effort and the phrase
 * wins. If IndexedDB or WebCrypto is unavailable, persist falls back
 * to the old plaintext behavior with a breadcrumb - a storage hiccup
 * must never cost anyone their session (auth session audit 2026-08-25,
 * section 0). A lost wrap key (envelope present, key gone) demotes to
 * the sign-in screen, where re-entering the phrase repairs everything.
 *
 * Spec: THREAT_MODEL.md (phrase wrapped at rest under a
 * non-extractable device key)
 */

import { db, reopenDb } from './db';
import { PHRASE_STORAGE_KEY } from './authStorage';
import { trustAwareStorage } from './trustStorage';
import {
  aesGcmEncrypt,
  aesGcmDecrypt,
  hasBiometricCredential,
  hasPinWrappedPhrase,
} from './biometric';
import { settingsLocalKey } from './settingsLocalKey';
import { logAuthEvent } from './authDiag';

// Version-prefixed so a future format change can coexist with old
// envelopes during a migration. A BIP-39 phrase is lowercase words and
// spaces, so the prefix cannot collide with legacy plaintext values.
const ENVELOPE_PREFIX = 'pnwrap1:';

// db.kv slot for the device wrap key. Stored as a CryptoKey object
// (structured clone), NOT exported bytes - non-extractable is the
// entire point. Lives beside the owner mirror; account deletion's
// db.delete() destroys it, sign-out leaves it (it wraps nothing once
// the envelope is removed, and the next sign-in reuses it).
const WRAP_KEY_KV = 'phraseWrapKey';

/** True when a stored phrase value is a wrapped envelope rather than
 *  legacy plaintext. */
export function isWrappedEnvelope(value: string): boolean {
  return value.startsWith(ENVELOPE_PREFIX);
}

function isCryptoKey(v: unknown): v is CryptoKey {
  return typeof CryptoKey !== 'undefined' && v instanceof CryptoKey;
}

function toB64(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function fromB64(b64: string): Uint8Array {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

/**
 * Read the device wrap key, creating it on first use. The create is
 * atomic across tabs: the CryptoKey is generated OUTSIDE the Dexie
 * transaction (an awaited non-IDB call inside one auto-commits the
 * transaction), then a rw transaction re-checks and only the first
 * writer's key survives. Two tabs racing here converge on one key, so
 * an envelope written by either tab opens in both.
 */
async function getOrCreateWrapKey(): Promise<CryptoKey> {
  const existing = await db.kv.get(WRAP_KEY_KV);
  if (isCryptoKey(existing?.value)) return existing.value;
  const fresh = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    false, // non-extractable: the property this module exists for
    ['encrypt', 'decrypt'],
  );
  return db.transaction('rw', db.kv, async () => {
    const again = await db.kv.get(WRAP_KEY_KV);
    if (isCryptoKey(again?.value)) return again.value;
    await db.kv.put({ key: WRAP_KEY_KV, value: fresh });
    return fresh;
  });
}

async function readWrapKey(): Promise<CryptoKey | null> {
  const entry = await db.kv.get(WRAP_KEY_KV);
  return isCryptoKey(entry?.value) ? entry.value : null;
}

/**
 * Persist the session phrase into trust-aware storage as a wrapped
 * envelope. Replaces every former plaintext write site, including the
 * boot-time migration of an existing plaintext value (same slot, so
 * the overwrite IS the migration; a per-store setItem either lands or
 * leaves the old value intact - there is no torn state).
 *
 * The wrap is proven before it is trusted: the key is re-read from
 * IndexedDB after any create (a key that cannot be read back cannot
 * open the envelope on the next boot) and the ciphertext is decrypted
 * and compared before the write. Any failure falls back to the old
 * plaintext write with a breadcrumb, which is exactly the pre-wrap
 * behavior: a degraded browser keeps the account usable and never
 * strands the user (auth session audit, section 0).
 */
/**
 * True when the app lock is the only door: the setting is on AND a PIN
 * or biometric wrap exists to open it.
 *
 * Arming the lock strips the device-key phrase envelope on purpose, so a
 * sign-in that writes the phrase back re-creates the door the lock
 * removed - permanently, and silently. The test therefore belongs to the
 * write rather than to one sign-in path: both the phrase sign-in and the
 * custodial OAuth sign-in reach persistStoredPhrase with a lock possibly
 * armed, and only the first one used to ask.
 *
 * It is deliberately NOT inside persistStoredPhrase. Two callers write
 * the phrase back precisely BECAUSE they are removing a lock factor -
 * pinRecovery.ts when clearing a PIN leaves no other door, and
 * BiometricTab.tsx when removing a fingerprint leaves no PIN wrap - and
 * both run while the settings flag is still on. A guard inside the write
 * would strand those devices with no phrase and no door, which is the
 * defect v0.507.16 closed.
 */
export function appLockArmed(): boolean {
  if (!hasPinWrappedPhrase() && !hasBiometricCredential()) return false;
  // Raw read of the cached settings blob rather than loadLocalSettings,
  // following bumpNotesCreated: the userSettings import chain reads
  // browser globals at module load, and this module is imported by the
  // OAuth path, which must stay light. Only one boolean is needed, and
  // anything other than a stored true answers "not armed", which is the
  // safe side here - the write it gates is what restores a lost session.
  try {
    const raw = localStorage.getItem(settingsLocalKey());
    if (!raw) return false;
    const cache = JSON.parse(raw) as { settings?: { appLockEnabled?: unknown } };
    return cache.settings?.appLockEnabled === true;
  } catch {
    return false;
  }
}

export async function persistStoredPhrase(phrase: string): Promise<void> {
  try {
    await getOrCreateWrapKey();
    // Re-read through the committed transaction: encrypt with the key
    // as IndexedDB will serve it at the next boot, not with the
    // in-memory candidate that may have lost the create race.
    const key = await readWrapKey();
    if (!key) throw new Error('wrap key unreadable after create');
    const { ciphertext, iv } = await aesGcmEncrypt(key, phrase);
    // Round trip before the write: a wrap that cannot decrypt would
    // brick the stored session where plaintext would have worked.
    const back = await aesGcmDecrypt(key, ciphertext, iv);
    if (back !== phrase) throw new Error('wrap round trip mismatch');
    trustAwareStorage.setItem(
      PHRASE_STORAGE_KEY,
      `${ENVELOPE_PREFIX}${toB64(iv)}:${toB64(ciphertext)}`,
    );
  } catch (err) {
    // Fallback IS the old behavior. Breadcrumbed so a device that
    // cannot wrap is visible in the auth log, never silent.
    logAuthEvent('auth:phrase-wrap-fallback', {
      message: (err as Error | null)?.message,
    });
    trustAwareStorage.setItem(PHRASE_STORAGE_KEY, phrase);
  }
}

/**
 * Open a stored envelope back into the phrase. Returns null when the
 * envelope is malformed or the wrap key is gone (cleared IndexedDB
 * beside a surviving localStorage) - the caller treats null as "no
 * restorable session" and demotes to sign-in, which re-entry of the
 * phrase repairs. One reopen-and-retry absorbs iOS WebKit severing
 * the IndexedDB connection in a backgrounded standalone app (the
 * reopenDb precedent, issue #112).
 */
export async function unwrapStoredEnvelope(value: string): Promise<string | null> {
  if (!isWrappedEnvelope(value)) return null;
  const parts = value.slice(ENVELOPE_PREFIX.length).split(':');
  if (parts.length !== 2) return null;
  let iv: Uint8Array;
  let ciphertext: Uint8Array;
  try {
    iv = fromB64(parts[0]!);
    ciphertext = fromB64(parts[1]!);
  } catch {
    return null;
  }
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const key = await readWrapKey();
      if (!key) {
        logAuthEvent('auth:phrase-wrap-key-missing');
        return null;
      }
      return await aesGcmDecrypt(key, ciphertext, iv);
    } catch (err) {
      if (attempt === 0) {
        // A severed IndexedDB connection and a genuine decrypt failure
        // both throw; the reopen only helps the first, and one retry
        // costs nothing on the second.
        try { await reopenDb(); } catch { /* ignore */ }
        continue;
      }
      logAuthEvent('auth:phrase-unwrap-failed', {
        message: (err as Error | null)?.message,
      });
    }
  }
  return null;
}
