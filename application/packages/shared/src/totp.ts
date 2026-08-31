/**
 * TOTP (RFC 6238) generation, built on RFC 4226 HOTP with a time-derived
 * counter. Used for the vault's "authenticator key" field: we parse whatever
 * a password manager export hands us (bare base32 secret or an otpauth://
 * URI) and generate the rotating code client-side, same as the vault app.
 */

import { hmac } from '@noble/hashes/hmac.js';
import { sha1 } from '@noble/hashes/legacy.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';

export interface TotpParams {
  secret: Uint8Array;
  digits: number;
  period: number;
  algorithm: 'SHA1' | 'SHA256' | 'SHA512';
}

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function decodeBase32(raw: string): Uint8Array | null {
  const normalized = raw.toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
  if (normalized.length < 8) return null;
  for (const ch of normalized) {
    if (!BASE32_ALPHABET.includes(ch)) return null;
  }
  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of normalized) {
    buffer = (buffer << 5) | BASE32_ALPHABET.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }
  return new Uint8Array(bytes);
}

function algoFromName(name: string | null): TotpParams['algorithm'] | null {
  if (!name) return 'SHA1';
  const upper = name.toUpperCase();
  if (upper === 'SHA1' || upper === 'SHA256' || upper === 'SHA512') return upper;
  return null;
}

export function parseTotpInput(raw: string): TotpParams | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;

  if (/^otpauth:\/\//i.test(trimmed)) {
    let url: URL;
    try {
      url = new URL(trimmed);
    } catch {
      return null;
    }
    if (url.protocol !== 'otpauth:' || url.host.toLowerCase() !== 'totp') return null;

    const secretParam = url.searchParams.get('secret');
    if (!secretParam) return null;
    const secret = decodeBase32(secretParam);
    if (!secret) return null;

    const digitsParam = url.searchParams.get('digits');
    const digits = digitsParam ? Number.parseInt(digitsParam, 10) : 6;
    if (!Number.isInteger(digits) || digits < 6 || digits > 8) return null;

    const periodParam = url.searchParams.get('period');
    const period = periodParam ? Number.parseInt(periodParam, 10) : 30;
    if (!Number.isInteger(period) || period < 5 || period > 300) return null;

    const algorithm = algoFromName(url.searchParams.get('algorithm'));
    if (!algorithm) return null;

    return { secret, digits, period, algorithm };
  }

  if (/^[a-z]+:\/\//i.test(trimmed)) return null;

  const secret = decodeBase32(trimmed);
  if (!secret) return null;
  return { secret, digits: 6, period: 30, algorithm: 'SHA1' };
}

function hmacFor(algorithm: TotpParams['algorithm'], key: Uint8Array, msg: Uint8Array): Uint8Array {
  if (algorithm === 'SHA256') return hmac(sha256, key, msg);
  if (algorithm === 'SHA512') return hmac(sha512, key, msg);
  return hmac(sha1, key, msg);
}

export function generateTotpCode(params: TotpParams, nowMs: number): string {
  const counter = Math.floor(Math.floor(nowMs / 1000) / params.period);
  const hi = Math.floor(counter / 2 ** 32);
  const lo = counter >>> 0;
  const counterBytes = new DataView(new ArrayBuffer(8));
  counterBytes.setUint32(0, hi, false);
  counterBytes.setUint32(4, lo, false);

  const digest = hmacFor(params.algorithm, params.secret, new Uint8Array(counterBytes.buffer));

  const offset = digest[digest.length - 1]! & 0x0f;
  const binary =
    ((digest[offset]! & 0x7f) << 24) |
    ((digest[offset + 1]! & 0xff) << 16) |
    ((digest[offset + 2]! & 0xff) << 8) |
    (digest[offset + 3]! & 0xff);

  const code = binary % 10 ** params.digits;
  return code.toString().padStart(params.digits, '0');
}

export function totpSecondsRemaining(period: number, nowMs: number): number {
  const secs = Math.floor(nowMs / 1000);
  const remainder = secs % period;
  return period - remainder;
}
