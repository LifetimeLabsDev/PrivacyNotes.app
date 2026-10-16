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
  hasSamePinWrap,
  hasStoredPhrase,
  hydrateLocalPinWrap,
  removePinWrappedPhrase,
  removeStoredPhrase,
} from './biometric';
import { isLivePhrase, signInStamp, signedOutSince, type SignInStamp } from './liveSignIn';
import { persistStoredPhrase } from './phraseAtRest';
import { clearPinFailures, clearPinFromSettings, syncPinCache } from './pin';
import { isPinWrapWithheld, loadLocalSettings, type UserSettings } from './userSettings';

/**
 * Strip every PIN artifact this device holds and return the settings that
 * carry the removal to the others. Local side effects run here; the
 * returned blob still has to be saved and synced by the caller.
 *
 * `appLockEnabled` is deliberately untouched. It is a synced setting, while
 * an enrolled fingerprint is a fact about ONE device, so deciding the flag
 * from this device's biometric state would let a laptop with no fingerprint
 * reader switch off a phone's working fingerprint lock - a remote disarm,
 * from an action that has nothing to do with that phone. Nothing needs the
 * flag to move: App.tsx refuses to lock a device holding no wrapped blob, so
 * this device simply stops locking while every device that kept a door keeps
 * using it.
 *
 * `phrase` goes back at rest on a device whose wrap is its last door, so the
 * next boot has a session to restore. Arming app lock strips the stored copy,
 * which makes the wrap the only one; the flag is not the test, because it can
 * come off on another device while this one still holds only the wrap.
 *
 * Answers null, having changed nothing, when that phrase does not read back:
 * the wrap stays, and so does the PIN that opens it. Callers keep the PIN and
 * say so. Pinned by tests/pinRecovery.test.ts.
 *
 * `current` is a caller's answer to whether the secret it proved is still the
 * account's, asked before the phrase write and again after it, with no await
 * between that answer and the removal. A secret another tab replaced meanwhile
 * also answers null, with nothing removed and no phrase left behind: a phrase
 * this call put at rest goes again while the wrap it stood in for is still
 * here and no sign-out began since the call started. After a sign-out, even
 * one followed by a sign-in to the same account, the phrase at rest belongs
 * to that newer sign-in. `wrotePhrase` and `since` let a caller whose save
 * then fails take the phrase off again under the same rule
 * (restoreUnsavedClear).
 */
export async function clearPin(
  settings: UserSettings,
  phrase: string,
  current: () => boolean = () => true,
): Promise<{ settings: UserSettings; wrotePhrase: boolean; since: SignInStamp } | null> {
  const since = signInStamp();
  // The phrase lands before the wrap goes, so a start in between still has
  // the wrap to open. The write can take a moment and can be refused.
  const lastDoor = hasPinWrappedPhrase() && !hasBiometricCredential() && !hasStoredPhrase();
  if (!current()) return null;
  if (lastDoor && !(await persistStoredPhrase(phrase))) return null;
  if (!current()) {
    if (lastDoor && hasPinWrappedPhrase() && !signedOutSince(since) && isLivePhrase(phrase)) removeStoredPhrase();
    return null;
  }
  removePinWrappedPhrase();
  const next = clearPinFromSettings(settings);
  // Somebody who just proved the phrase has no business sitting out a
  // backoff earned by guessing at the PIN they replaced.
  clearPinFailures();
  next.pinWrapSalt = null;
  next.pinWrapIV = null;
  next.pinWrapCiphertext = null;
  next.pinWrapIterations = null;
  return { settings: next, wrotePhrase: lastDoor, since };
}

/**
 * Put this device's PIN back after a clear whose save did not land
 * (`saveCredential` answered false). clearPin already took the hash cache and
 * the wrap off, and the settings still hold both, so the PIN the account keeps
 * opens here again, as it would after the next start. A phrase the clear put
 * at rest (`wrotePhrase`) goes again once the wrap is back, with no await
 * between, so the refused removal leaves no door that was not there before;
 * only while no sign-out began since the clear started (`since`), as in
 * clearPin.
 */
export async function restoreUnsavedClear(
  phrase: string,
  cleared: { wrotePhrase: boolean; since: SignInStamp },
): Promise<void> {
  const saved = loadLocalSettings();
  syncPinCache(saved);
  await syncPinWrap(saved, phrase);
  if (cleared.wrotePhrase && hasPinWrappedPhrase() && !signedOutSince(cleared.since) && isLivePhrase(phrase)) {
    removeStoredPhrase();
  }
}

/**
 * Point this device's PIN wrap at whatever the account settings now say.
 *
 * Both directions matter. Arriving, the wrap lights app lock up on a new
 * device without re-entering the PIN. Leaving, it is the only thing that
 * retires a removed PIN here: the hash cache follows the settings on its
 * own, but a wrap left in place keeps unlocking this device with a PIN the
 * account no longer holds, and keeps demanding one its owner has already
 * replaced.
 *
 * One function rather than the condition written out at both call sites, so
 * the two directions cannot drift into a one-way copy.
 *
 * `phrase` is what the removal half costs an app-lock user without it.
 * Arming the lock strips the plain copy, so the wrap is the only one on the
 * device, and the settings this reads can be an older blob than the one it
 * already had: the freshness test is a server-controlled timestamp and the
 * ciphertext binds none of its own. Left alone, the next boot would ask for
 * twelve words the person may never have written down. So a device the
 * removal would leave with no door puts the phrase back at rest first, and
 * the wrap comes off only once the phrase reads back, which is the same trade
 * clearPin makes above: the app lock switches itself off, and nothing is
 * lost. A write the store refuses keeps the wrap until a later pass lands
 * it. Making the wrap stick for good would bring back a PIN removed on one
 * device still unlocking every other one.
 */
export async function syncPinWrap(settings: UserSettings, phrase?: string): Promise<void> {
  if (settings.pinWrapSalt && settings.pinWrapIV && settings.pinWrapCiphertext) {
    const blob = {
      pinWrapSalt: settings.pinWrapSalt,
      pinWrapIV: settings.pinWrapIV,
      pinWrapCiphertext: settings.pinWrapCiphertext,
      // A blob written before the count was recorded is a legacy one.
      pinWrapIterations: settings.pinWrapIterations ?? LEGACY_WRAP_ITERATIONS,
    };
    // The account's wrap is the one this device must hold, not merely some
    // wrap: a PIN changed elsewhere re-wraps under the new PIN, and a device
    // that kept its old blob would keep opening with the retired PIN while
    // its notes asked for the new one. The legacy-iteration upgrade after an
    // unlock reports its blob to the account for the same reason, or this
    // would undo it on every pass. Pinned by tests/pinRecovery.test.ts.
    if (!hasPinWrappedPhrase() || !hasSamePinWrap(blob)) {
      hydrateLocalPinWrap(blob);
    }
    return;
  }
  // Four nulls can also mean the cache does not KNOW the account's wrap:
  // an untrusted device keeps it out of localStorage, and a tab that has not
  // read the server row yet holds nothing to compare. That is not a removal,
  // and acting on it would take a door the account still holds. Pinned by
  // tests/pinRecovery.test.ts.
  if (isPinWrapWithheld()) return;
  // A door is a wrap, a fingerprint, or a phrase already at rest. With
  // neither of the last two, the phrase lands before the wrap goes. With no
  // phrase to write, the wrap goes anyway: a PIN the account removed must
  // stop opening this device.
  if (phrase && !hasBiometricCredential() && !hasStoredPhrase()) {
    if (!(await persistStoredPhrase(phrase))) return;
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
