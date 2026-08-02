/**
 * Encrypt / decrypt arbitrary binary blobs (images, attachments).
 *
 * Same xchacha20poly1305 primitive as note encryption - one crypto
 * path in the entire codebase. The caller is responsible for key
 * management; this module just does the symmetric encrypt/decrypt.
 *
 * Unlike encryptNote/encryptJson, these functions operate on raw
 * Uint8Array data (no JSON serialisation) to avoid base64-inflating
 * large binary payloads.
 */

// Explicit `.js` suffix required by @noble v2+. Spec: ops/docs/dependency-migration.md
import { randomBytes } from '@noble/hashes/utils.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';

/**
 * Encrypt a binary blob. Returns nonce (24 bytes) prepended to the
 * ciphertext in a single Uint8Array so the caller only needs to store
 * one value. Decryption splits it back out.
 */
export function encryptBlob(
  data: Uint8Array,
  key: Uint8Array,
): Uint8Array {
  const nonce = randomBytes(24);
  const cipher = xchacha20poly1305(key, nonce);
  const ciphertext = cipher.encrypt(data);
  const combined = new Uint8Array(24 + ciphertext.length);
  combined.set(nonce, 0);
  combined.set(ciphertext, 24);
  return combined;
}

/**
 * Decrypt a blob produced by encryptBlob. Expects the nonce-prefixed
 * format (first 24 bytes = nonce, rest = ciphertext). Throws on
 * authentication failure (wrong key or tampered data).
 */
export function decryptBlob(
  combined: Uint8Array,
  key: Uint8Array,
): Uint8Array {
  if (combined.length < 41) {
    throw new Error('Encrypted blob too short - expected at least 41 bytes (24 nonce + 16 auth tag + 1 ciphertext)');
  }
  const nonce = combined.slice(0, 24);
  const ciphertext = combined.slice(24);
  const cipher = xchacha20poly1305(key, nonce);
  return cipher.decrypt(ciphertext);
}
