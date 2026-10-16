/**
 * The two kinds of app lock secret: the 4-digit PIN and the longer passcode.
 *
 * One account holds one secret. Its kind is a fact of the secret itself (a
 * PIN is exactly four digits, a passcode never is), and every hash or wrap
 * records it in the length of its own salt: 16 bytes for a PIN, 24 for a
 * passcode. The salt travels with its hash or its wrap through every app
 * version and every settings merge, so the kind can never be separated from
 * the thing it describes. Pinned by tests/passcode.test.ts.
 *
 * No imports: `pin.ts` and `biometric.ts` both read it, and tests mock each of
 * those on its own.
 * Spec: ops/docs/plans/app-lock-passcode.md (section 4.1)
 */

import { base64ToBytes } from '@notes/shared';

export type SecretKind = 'pin' | 'passcode';

const PIN_SALT_BYTES = 16;
const PASSCODE_SALT_BYTES = 24;

// Spec: ops/docs/plans/app-lock-passcode.md (section 5, passcode length)
export const PASSCODE_MIN_CHARS = 8;
export const PASSCODE_MAX_CHARS = 256;

/** Whether the PIN tab offers a passcode. Checking one is never gated, so an
 *  account's passcode can always be opened, changed or replaced by a PIN. */
export const PASSCODE_SETUP_ENABLED = true;

/** The kind of a secret, from the secret itself. */
export function isPasscode(secret: string): boolean {
  return !/^\d{4}$/.test(secret);
}

/** The salt length every new hash or wrap of this secret takes. */
export function saltBytesFor(secret: string): number {
  return isPasscode(secret) ? PASSCODE_SALT_BYTES : PIN_SALT_BYTES;
}

/** Every secret is NFC before derivation, so a composed and a decomposed
 *  accent open the same lock. Digits are unchanged by it. */
export function normalizeSecret(secret: string): string {
  return secret.normalize('NFC');
}

/**
 * True when a base64 salt marks a passcode. Never throws: a missing salt or
 * malformed base64 reads as a PIN, because the lock screen asks while it
 * renders and a throw there would hide its recovery links.
 */
export function saltIsPasscode(b64: string | null | undefined): boolean {
  if (!b64) return false;
  try {
    return base64ToBytes(b64).length === PASSCODE_SALT_BYTES;
  } catch {
    return false;
  }
}

/** The live checks under a new passcode field. Counted in code points. */
export function passcodeRules(value: string): { longEnough: boolean; notOnlyDigits: boolean; notTooLong: boolean } {
  const chars = [...normalizeSecret(value)].length;
  return {
    longEnough: chars >= PASSCODE_MIN_CHARS,
    notOnlyDigits: !/^\d*$/.test(value),
    notTooLong: chars <= PASSCODE_MAX_CHARS,
  };
}

export function isValidPasscode(value: string): boolean {
  const r = passcodeRules(value);
  return r.longEnough && r.notOnlyDigits && r.notTooLong;
}

/** Whether a typed secret of this kind is complete enough to check. */
export function secretReady(kind: SecretKind, value: string): boolean {
  return kind === 'pin' ? value.length === 4 : value.length > 0;
}
