/**
 * Clearing a PIN, from either of the two credentials that may do it: the
 * PIN itself, or the recovery phrase.
 *
 * The phrase opens every door the PIN does, so it clears the PIN too. It
 * has to: the hash lives in the synced settings blob, so signing out and
 * back in restores it, and every screen that changes a PIN asks for the
 * old one first. Without a phrase route a forgotten PIN is permanent on
 * every device the account touches.
 *
 * This costs the PIN nothing. The PIN stops somebody who picked up an
 * unlocked device, and that person cannot produce twelve words - if they
 * could, they would sign in on their own machine and read everything. The
 * two gates stay symmetric: the phrase view sits behind the PIN, and the
 * PIN comes off behind the phrase.
 *
 * Callers own persistence. Settings hands the result to its own save; the
 * lock screen writes it to the local cache before the app mounts.
 *
 * Spec: ops/docs/plans/pin-recovery.md
 */

import {
  hasBiometricCredential,
  hasPinWrappedPhrase,
  hydrateLocalPinWrap,
  removePinWrappedPhrase,
} from './biometric';
import { persistStoredPhrase } from './phraseAtRest';
import { clearPinFailures, clearPinFromSettings } from './pin';
import type { UserSettings } from './userSettings';

/**
 * Strip every PIN artifact this device holds and return the settings that
 * carry the removal to the others. Local side effects run here; the
 * returned blob still has to be saved and synced by the caller.
 *
 * `appLockEnabled` is deliberately untouched, and that is a fix rather than
 * an omission. It is a synced setting, while an enrolled fingerprint is a
 * fact about ONE device, so deciding the flag from this device's biometric
 * state let a laptop with no fingerprint switch off a phone's working
 * fingerprint lock - a remote disarm, from an action that had nothing to do
 * with that phone. Nothing needs the flag to move: App.tsx already refuses
 * to lock a device holding no wrapped blob, so this device simply stops
 * locking while every device that kept a door keeps using it.
 *
 * `phrase` is read on a device that is left with no door at all, to put the
 * phrase back at rest so the next boot has a session to restore. Arming app
 * lock strips the stored copy, which makes the wrap this function just
 * deleted the only one.
 */
export function clearPin(settings: UserSettings, phrase: string): UserSettings {
  const hasBio = hasBiometricCredential();
  removePinWrappedPhrase();
  if (!hasBio && settings.appLockEnabled) {
    // Fire-and-forget: persist wraps the phrase at rest and falls back to
    // a plain write on a degraded browser, so a boot after this still
    // finds a session.
    void persistStoredPhrase(phrase);
  }
  const next = clearPinFromSettings(settings);
  // Somebody who just proved the phrase has no business sitting out a
  // backoff earned by guessing at the PIN they replaced.
  clearPinFailures();
  next.pinWrapSalt = null;
  next.pinWrapIV = null;
  next.pinWrapCiphertext = null;
  next.pinWrapIterations = null;
  return next;
}

/**
 * Point this device's PIN wrap at whatever the account settings now say.
 *
 * Both directions matter, and only one of them used to exist. Arriving, the
 * wrap lights app lock up on a new device without re-entering the PIN.
 * Leaving, it is the only thing that retires a removed PIN here: the hash
 * cache follows the settings already, but the wrap stayed, so a PIN removed
 * on one device kept unlocking every other one - and kept demanding a PIN
 * its owner had just replaced.
 *
 * One function rather than the condition written out at both call sites,
 * because a one-way copy is exactly the shape the bug had.
 */
export function syncPinWrap(settings: UserSettings): void {
  if (settings.pinWrapSalt && settings.pinWrapIV && settings.pinWrapCiphertext) {
    if (!hasPinWrappedPhrase()) {
      hydrateLocalPinWrap({
        pinWrapSalt: settings.pinWrapSalt,
        pinWrapIV: settings.pinWrapIV,
        pinWrapCiphertext: settings.pinWrapCiphertext,
        // A blob written before the count was recorded is a legacy one.
        pinWrapIterations: settings.pinWrapIterations ?? LEGACY_WRAP_ITERATIONS,
      });
    }
    return;
  }
  removePinWrappedPhrase();
}

// Spec: ops/docs/biometric-unlock.md (PIN wrap PBKDF2 count before it was
// recorded alongside the blob)
const LEGACY_WRAP_ITERATIONS = 100_000;

/** Lowercase, and one space between words, so a pasted phrase with line
 *  breaks or a trailing newline still matches. */
function normalize(phrase: string): string {
  return phrase.trim().toLowerCase().split(/\s+/).join(' ');
}

/**
 * Does this typed phrase belong to the signed-in account? Answered against
 * the phrase the app already holds, so no network call and no sign-in
 * round trip. Only the screens inside an unlocked app can ask - the lock
 * screen has no phrase to compare against, and there the sign-in is the
 * check.
 */
export function phraseMatches(typed: string, actual: string): boolean {
  const a = new TextEncoder().encode(normalize(typed));
  const b = new TextEncoder().encode(normalize(actual));
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}
