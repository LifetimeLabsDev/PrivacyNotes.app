/**
 * Privacy Notes — crypto core.
 *
 * From a single 12-word BIP-39 phrase, we deterministically derive:
 *   1. An ed25519 signing keypair → the public key IS the user ID.
 *   2. A symmetric xchacha20poly1305 key → used to encrypt note contents.
 *
 * Two different keys derived from the same seed via HKDF with distinct
 * "info" strings. The user never sees either — they only see 12 words.
 *
 * The server only ever stores:
 *   - user_pubkey (ed25519 public key, hex) — identity
 *   - ciphertext (bytea)                    — encrypted note payload
 *   - nonce (bytea)                         — per-note random 24 bytes
 *
 * We never send the seed, the signing private key, or the encryption key
 * to the server. Losing the 12 words = losing the data, forever. That is
 * the whole point.
 */

import {
  generateMnemonic,
  validateMnemonic,
  mnemonicToSeedSync,
} from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { hkdf } from '@noble/hashes/hkdf';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from '@noble/hashes/utils';
import * as ed from '@noble/ed25519';
// Spec: CLAUDE.md §5 (xchacha20poly1305 via @noble/ciphers)
import { xchacha20poly1305 } from '@noble/ciphers/chacha';

import type { DecryptedNote } from './types.js';

const utf8 = new TextEncoder();
const utf8Decoder = new TextDecoder();

// ------------------------------------------------------------------
// BIP-39 phrase
// ------------------------------------------------------------------

// Spec: CLAUDE.md §5 (BIP-39 12-word phrase, client-generated, never touches server)
export function generatePhrase(): string {
  return generateMnemonic(wordlist, 128);
}

/** True if the phrase is a valid BIP-39 mnemonic (checksum verified). */
export function isValidPhrase(phrase: string): boolean {
  return validateMnemonic(phrase.trim().toLowerCase(), wordlist);
}

/**
 * Turn a phrase into a 64-byte seed via the standard BIP-39 PBKDF2.
 * This is the single source of truth from which both keys are derived.
 */
export function phraseToSeed(phrase: string): Uint8Array {
  return mnemonicToSeedSync(phrase.trim().toLowerCase());
}

// ------------------------------------------------------------------
// Key derivation (HKDF with domain-separated info strings)
// ------------------------------------------------------------------

/**
 * Derive the ed25519 signing keypair from the seed.
 * Public key = user ID. Private key never leaves the device.
 */
export async function deriveSigningKey(
  seed: Uint8Array
): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }> {
  const privateKey = hkdf(
    sha256,
    seed,
    undefined,
    utf8.encode('privacynotes-signing-v1'),
    32
  );
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return { privateKey, publicKey };
}

/**
 * Derive the symmetric encryption key from the seed.
 * Same seed → same key on every device, so no key exchange is needed.
 */
export function deriveEncryptionKey(seed: Uint8Array): Uint8Array {
  return hkdf(
    sha256,
    seed,
    undefined,
    utf8.encode('privacynotes-encryption-v1'),
    32
  );
}

// ------------------------------------------------------------------
// Challenge signing — used to prove ownership of the pubkey to the
// `link-pubkey` Edge Function, which then writes the pubkey into the
// JWT's `app_metadata` (service-role only, not forgeable by the user).
// ------------------------------------------------------------------

/**
 * Sign the canonical link message `link:<authUid>` with the ed25519
 * private key. The server verifies this signature against the claimed
 * pubkey, and only then trusts the pubkey → uid binding.
 *
 * Binding the message to `authUid` prevents replay: a signature for
 * one user's uid can't be used to claim that pubkey for another user.
 */
export async function signLinkChallenge(
  privateKey: Uint8Array,
  authUid: string
): Promise<Uint8Array> {
  const message = utf8.encode(`link:${authUid}`);
  return ed.signAsync(message, privateKey);
}

// ------------------------------------------------------------------
// Device identity
// ------------------------------------------------------------------
//
// Each install generates a random 32-byte deviceSecret, stored locally
// (localStorage). The public deviceId is HKDF(deviceSecret, info=pubkey)
// truncated to 16 bytes (32 hex chars). Including the pubkey in `info`
// means the same local deviceSecret produces different deviceIds across
// different phrases — accounts stay isolated if two users share a
// machine.
//
// The deviceSecret is not a cryptographic secret per se (losing it just
// means the install looks like a new device, which is the intended
// reset behaviour on "clear site data"). But we store it in plain
// localStorage rather than session storage so it survives tab close.

/** 32 random bytes — generate once per install, keep forever. */
export function generateDeviceSecret(): Uint8Array {
  return randomBytes(32);
}

/**
 * Derive a stable deviceId from (pubkey, deviceSecret). Returns 32 hex
 * chars (16 bytes). Same (pubkey, deviceSecret) always yields the same
 * id — so re-registering the same install is idempotent on the server.
 */
export function deriveDeviceId(
  pubkey: string,
  deviceSecret: Uint8Array,
): string {
  const info = utf8.encode(`privacynotes-device-v1:${pubkey}`);
  const bytes = hkdf(sha256, deviceSecret, undefined, info, 16);
  return bytesToHex(bytes);
}

/**
 * Sign the device-registration challenge. Server verifies against the
 * master ed25519 public key. Binding in the authUid prevents a signed
 * registration from one session being replayed into another.
 */
export async function signDeviceRegisterChallenge(
  privateKey: Uint8Array,
  authUid: string,
  deviceId: string,
): Promise<Uint8Array> {
  const message = utf8.encode(`register-device:${authUid}:${deviceId}`);
  return ed.signAsync(message, privateKey);
}

/**
 * Sign the device-revocation challenge. The caller signs with their
 * master key; anyone holding the phrase can revoke any of their own
 * devices (including ones they're not currently on).
 */
export async function signDeviceRevokeChallenge(
  privateKey: Uint8Array,
  authUid: string,
  targetDeviceId: string,
): Promise<Uint8Array> {
  const message = utf8.encode(`revoke-device:${authUid}:${targetDeviceId}`);
  return ed.signAsync(message, privateKey);
}

/**
 * Sign the account-deletion challenge. Proves the caller holds the
 * master key before the server permanently deletes all user data.
 */
export async function signDeleteAccountChallenge(
  privateKey: Uint8Array,
  authUid: string,
): Promise<Uint8Array> {
  const message = utf8.encode(`delete-account:${authUid}`);
  return ed.signAsync(message, privateKey);
}

// ------------------------------------------------------------------
// Device fingerprint hashing (per-user peppered)
// ------------------------------------------------------------------
//
// The server stores hashes of (platform, gpu, cores, language) rather
// than the raw values. The pepper is derived from the user's BIP-39
// seed via HKDF with a domain-separated info string, so:
//
//   - The server never sees raw fingerprint values.
//   - Different pubkeys produce different hashes on the same machine,
//     so cross-user fingerprint correlation is impossible.
//   - The same pubkey on the same hardware produces consistent hashes,
//     so per-user device dedup still works.
//
// Spec: specs/device-fingerprint-hash.md

/** Per-user fingerprint pepper. Same seed → same pepper, forever. */
// Spec: specs/device-fingerprint-hash.md (HKDF info "privacynotes-fp-pepper-v1")
export function deriveFpPepper(seed: Uint8Array): Uint8Array {
  return hkdf(
    sha256,
    seed,
    undefined,
    utf8.encode('privacynotes-fp-pepper-v1'),
    32,
  );
}

export interface FpInput {
  /** Normalized OS label, e.g. "macOS", "Windows", "iPhone". */
  platform: string;
  /** WebGL renderer string, or "unknown" if unavailable. */
  gpu: string;
  /** navigator.hardwareConcurrency, or 0 if unavailable. */
  cores: number;
  /** navigator.language, or "unknown". */
  language: string;
}

export interface FpHashes {
  platform_hash: string;
  /** null when GPU is unavailable, so the server can pick the degraded threshold. */
  gpu_hash: string | null;
  cores_hash: string;
  language_hash: string;
}

function hmacFp(pepper: Uint8Array, prefix: string, value: string): string {
  const input = utf8.encode(`${prefix}:${value}`);
  return bytesToBase64(hmac(sha256, pepper, input));
}

/**
 * Compute the four per-field fingerprint hashes for a device. The
 * field prefix in the HMAC input prevents cross-field collisions
 * (e.g., a GPU named "10" hashing to the same value as cores=10).
 */
export function computeFpHashes(pepper: Uint8Array, fp: FpInput): FpHashes {
  const gpuAvailable = !!fp.gpu && fp.gpu !== 'unknown';
  return {
    platform_hash: hmacFp(pepper, 'platform', fp.platform),
    gpu_hash: gpuAvailable ? hmacFp(pepper, 'gpu', fp.gpu) : null,
    cores_hash: hmacFp(pepper, 'cores', String(fp.cores)),
    language_hash: hmacFp(pepper, 'language', fp.language),
  };
}

// ------------------------------------------------------------------
// Hex helpers (pubkey is stored as hex text in Postgres)
// ------------------------------------------------------------------

export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('hexToBytes: odd-length hex string');
  if (!/^[0-9a-fA-F]*$/.test(hex)) throw new Error('hexToBytes: non-hex characters');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

// ------------------------------------------------------------------
// Base64 helpers — used at the Supabase boundary for ciphertext/nonce.
// ------------------------------------------------------------------

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

// ------------------------------------------------------------------
// Base64url helpers — URL-safe, no padding, no percent-encoding needed.
// Used for burn-after-reading links where URL length matters.
// ------------------------------------------------------------------

export function bytesToBase64url(bytes: Uint8Array): string {
  return bytesToBase64(bytes)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

export function base64urlToBytes(b64url: string): Uint8Array {
  // Restore standard base64: swap URL-safe chars, re-pad.
  let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const pad = (4 - (b64.length % 4)) % 4;
  b64 += '='.repeat(pad);
  return base64ToBytes(b64);
}

// ------------------------------------------------------------------
// Symmetric encryption — xchacha20poly1305 with per-call random nonce.
// 24-byte nonces mean random nonces are safe forever (unlike AES-GCM).
// ------------------------------------------------------------------

/**
 * Encrypt the plaintext fields of a note. Returns an opaque blob the
 * server can store but can't read.
 *
 * `trashed`, `starred`, `locked`, and `pinProtected` are included
 * inside the ciphertext (not plaintext columns) so even per-note
 * metadata stays private to the user.
 *
 * `locked` and `pinProtected` were added later and are optional for
 * backward compatibility: older clients may omit them when writing,
 * and older ciphertexts may lack them when decrypted.
 */
export type EncryptedPayload = Pick<
  DecryptedNote,
  'title' | 'body' | 'tags' | 'trashed' | 'starred' | 'locked' | 'pinProtected' | 'type' | 'trackers'
>;

export function encryptNote(
  note: EncryptedPayload,
  key: Uint8Array
): { ciphertext: Uint8Array; nonce: Uint8Array } {
  const nonce = randomBytes(24);
  const cipher = xchacha20poly1305(key, nonce);
  const plaintext = utf8.encode(
    JSON.stringify({
      title: note.title,
      body: note.body,
      tags: note.tags,
      trashed: note.trashed,
      starred: note.starred,
      locked: note.locked,
      pinProtected: note.pinProtected,
      type: note.type,
      ...(note.trackers ? { trackers: note.trackers } : {}),
    })
  );
  const ciphertext = cipher.encrypt(plaintext);
  return { ciphertext, nonce };
}

/**
 * Inverse of encryptNote. Throws if the ciphertext or key is wrong
 * (Poly1305 authentication failure).
 *
 * Backward-compatible: ciphertexts written by older clients (before
 * v0.4.0) don't have `trashed`/`starred` fields, and ciphertexts
 * from before the Pro features shipped don't have
 * `locked`/`pinProtected`; we default all of them to `false`.
 */
export function decryptNote(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array
): EncryptedPayload {
  const cipher = xchacha20poly1305(key, nonce);
  const plaintext = cipher.decrypt(ciphertext);
  const parsed = JSON.parse(utf8Decoder.decode(plaintext)) as Partial<EncryptedPayload>;
  return {
    title: parsed.title ?? '',
    body: parsed.body ?? '',
    tags: parsed.tags ?? [],
    trashed: parsed.trashed ?? false,
    starred: parsed.starred ?? false,
    locked: parsed.locked ?? false,
    pinProtected: parsed.pinProtected ?? false,
    type: parsed.type ?? 'note',
    trackers: (parsed as Record<string, unknown>).trackers as Record<string, unknown> | undefined,
  };
}

// ------------------------------------------------------------------
// Generic JSON blob encryption — used for anything that isn't a note
// but still needs to be end-to-end encrypted with the user's key.
// Current caller: synced user settings (favorite tags, etc).
//
// Uses the same xchacha20poly1305 primitive as notes so there is
// exactly one encryption path in the codebase.
// ------------------------------------------------------------------

export function encryptJson(
  value: unknown,
  key: Uint8Array
): { ciphertext: Uint8Array; nonce: Uint8Array } {
  const nonce = randomBytes(24);
  const cipher = xchacha20poly1305(key, nonce);
  const plaintext = utf8.encode(JSON.stringify(value));
  const ciphertext = cipher.encrypt(plaintext);
  return { ciphertext, nonce };
}

export function decryptJson<T = unknown>(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array
): T {
  const cipher = xchacha20poly1305(key, nonce);
  const plaintext = cipher.decrypt(ciphertext);
  return JSON.parse(utf8Decoder.decode(plaintext)) as T;
}
