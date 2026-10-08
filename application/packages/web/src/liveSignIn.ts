/**
 * Which sign-in is live in this tab, and whether a sign-out has begun since
 * a piece of work started.
 *
 * A sign-out removes the phrase, the PIN wrap, the PIN cache and the
 * settings cache, and work that began before it can end after it. A sync
 * pass whose settings step finds no phrase and no lock puts the phrase back
 * for what it takes to be a device with no door, and puts back the PIN wrap
 * of an account that has one. A sign-in whose own phrase write is still
 * waiting on IndexedDB lands after the wipe. A revalidation, or a sign-in
 * still in its first awaits, turns the signed-out screen back into the open
 * vault. Another tab of the same account never hears of the sign-out at all
 * and writes the phrase back on its next pass. Each one leaves this device
 * signed in behind a screen that says it is not, and the phrase on disk lets
 * the next start, or one click on the offer to carry on, sign in with nobody
 * typing anything.
 *
 * So the writes ask, not the paths that reach them. Work takes a stamp as it
 * starts, and a write it makes later lands only when no sign-out began in
 * between, in this tab or in another one; it asks again once written and
 * undoes itself, because another tab's sign-out can fall between the check
 * and the write. The phrase write also needs the phrase to be the live
 * sign-in's. An authentication goes live only with the stamp of its own
 * start. A sign-out ends the live sign-in here before its first await, and
 * announces itself and removes the credentials at both its start and its
 * end: the notice alone refuses every other tab's older work, and those
 * tabs leave the vault.
 *
 * Imports only demo.ts, which imports nothing, so every writer can read it
 * without a cycle. The demo keeps its own announcement key, so a demo tab
 * never signs out a real account on the same origin.
 * Pinned by tests/phraseAtRest.test.ts and tests/authInvariants.test.ts.
 */
import { credentialKey } from './demo';

/** What a piece of work holds from its start: the sign-outs this tab had
 *  seen, and the last sign-out announced by any tab. */
export type SignInStamp = { readonly count: number; readonly announced: string | null };

let signOutsBegun = 0;
let live: { phrase: string; stamp: SignInStamp } | null = null;
// The newest notice this tab has seen, read or delivered. A notice value
// starts with the time it was written, so the newer of two is the later.
// Remembered because the key can go: a fresh demo tab clears the demo
// bucket, and the account deletion sweeps every key. Forgetting it would
// make work that a sign-out already ended look current again.
let lastSeen: string | null = null;
let channel: BroadcastChannel | null | undefined;

function announcementKey(): string {
  return credentialKey('privacynotes.signedOut');
}

/** The time a notice was written: the digits before its first dot. Never
 *  parseFloat, which reads a random tail such as '.e5l' as an exponent, and
 *  that notice would outrank every later one. */
function noticeTime(notice: string): number {
  return parseInt(notice, 10);
}

/** The newer of the notice already held and one just seen. A tie goes to
 *  the one just seen, the latest written or delivered. */
function newer(held: string | null, seen: string | null): string | null {
  if (held === null) return seen;
  if (seen === null) return held;
  return noticeTime(seen) >= noticeTime(held) ? seen : held;
}

function lastAnnounced(): string | null {
  let stored: string | null = null;
  try {
    stored = localStorage.getItem(announcementKey());
  } catch {
    /* storage unavailable: what this tab has seen still counts */
  }
  lastSeen = newer(lastSeen, stored);
  return lastSeen;
}

// One instance for both directions: a channel never delivers to the object
// that posted, so this tab does not hear its own notice. The storage event
// skips the writing tab the same way.
function noticeChannel(): BroadcastChannel | null {
  if (channel === undefined) {
    try {
      channel = typeof BroadcastChannel === 'undefined' ? null : new BroadcastChannel(announcementKey());
    } catch {
      channel = null;
    }
  }
  return channel;
}

export function signInStamp(): SignInStamp {
  return { count: signOutsBegun, announced: lastAnnounced() };
}

/** True when a sign-out began after `stamp` was taken, here or in another tab. */
export function signedOutSince(stamp: SignInStamp): boolean {
  return stamp.count !== signOutsBegun || lastAnnounced() !== stamp.announced;
}

/** Ends the live sign-in in this tab: the first step of a sign-out, and of
 *  anything else that takes this tab's account away. */
export function endLiveSignIn(): void {
  signOutsBegun += 1;
  live = null;
}

/** Tells every other tab of this browser that this one signed out. Only a
 *  tab that owns the shared storage may say it, because the others act on
 *  it. Storage events skip the tab that writes, and fire only on a change,
 *  so each sign-out writes a value of its own. */
export function announceSignOut(): void {
  // Later than anything this tab has seen, even within one millisecond.
  const at = Math.max(Date.now(), lastSeen === null ? 0 : noticeTime(lastSeen) + 1);
  const notice = `${at}.${Math.random().toString(36).slice(2)}`;
  lastSeen = newer(lastSeen, notice);
  try {
    localStorage.setItem(announcementKey(), notice);
  } catch {
    /* a full store refuses it: the broadcast below still reaches the open
       tabs, and sign-out removes the credentials again at its end */
  }
  try {
    noticeChannel()?.postMessage(notice);
  } catch {
    /* no channel: the storage event carries it */
  }
}

/** Calls `onNotice` when another tab of this browser announces a sign-out,
 *  through the storage event or the broadcast that covers a full store.
 *  Both can deliver one notice, so `onNotice` must be safe to run twice.
 *  Returns the unsubscribe. */
export function watchSignOutsElsewhere(onNotice: () => void): () => void {
  const key = announcementKey();
  const fromStorage = (e: StorageEvent) => {
    if (e.key !== key || e.newValue === null) return;
    lastSeen = newer(lastSeen, e.newValue);
    onNotice();
  };
  const fromChannel = (e: MessageEvent) => {
    if (typeof e.data !== 'string') return;
    lastSeen = newer(lastSeen, e.data);
    onNotice();
  };
  window.addEventListener('storage', fromStorage);
  noticeChannel()?.addEventListener('message', fromChannel);
  return () => {
    window.removeEventListener('storage', fromStorage);
    noticeChannel()?.removeEventListener('message', fromChannel);
  };
}

/** Makes `phrase` the live sign-in, unless a sign-out began after `since`.
 *  An authentication calls this as its state goes live, with the stamp of
 *  its own start, and stops when it answers false. */
export function adoptLiveSignIn(phrase: string, since: SignInStamp): boolean {
  if (signedOutSince(since)) return false;
  live = { phrase, stamp: signInStamp() };
  return true;
}

/** Whether a sign-in is live in this tab and no sign-out began since. */
export function hasLiveSignIn(): boolean {
  return live !== null && !signedOutSince(live.stamp);
}

/** Whether `phrase` belongs to the sign-in that is live right now. */
export function isLivePhrase(phrase: string): boolean {
  return live !== null && !signedOutSince(live.stamp) && live.phrase === phrase;
}

// The stamp of this tab's load. Work that carries no stamp of its own is
// measured from it, which is what lets a cold start write before its boot
// goes live and refuses the same write once a sign-out has begun.
const loadStamp: SignInStamp = signInStamp();

/** Whether a write that carries no stamp of its own may land: a sign-in is
 *  live, or this tab has seen no sign-out since it loaded. */
export function mayWriteUnstamped(): boolean {
  return hasLiveSignIn() || !signedOutSince(loadStamp);
}
