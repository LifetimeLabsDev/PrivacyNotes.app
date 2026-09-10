/**
 * Re-lock the app after the idle window the user picked in Security.
 *
 * `locked` in App.tsx is decided once, when the app mounts, and App.tsx has no
 * timer and no resume handler of its own. Without this watch the setting would
 * only choose what happens on the next page load: an app left open would stay
 * open, on every platform, for as long as the page lived. On a phone that is
 * the whole threat the feature exists for - the app is open, the phone is put
 * down, and anyone who picks it up is already inside.
 * Spec: ops/docs/biometric-unlock.md (section 3.3 re-lock)
 *
 * Two triggers, one rule. The window is measured from the last real user
 * input, so a timer covers the app sitting untouched in front of someone, and
 * a check on return to the foreground covers the app sitting in the
 * background, where no timer can be trusted to run.
 *
 * The gate is the same casual-access gate the rest of the feature is: the
 * session stays authenticated and the notes stay decrypted in memory, and only
 * the UI is taken away. Re-locking does NOT re-wrap anything at rest. What it
 * buys is that a device left unattended stops showing the notes to whoever
 * holds it next, which is what the setting says on the tin.
 */

import { hasBiometricCredential, hasPinWrappedPhrase } from './biometric';
import { loadLocalSettings } from './userSettings';

/**
 * Input events that count as the user still being here. Capture phase, so a
 * keystroke inside the editor's contenteditable counts like any other: a user
 * typing a long note is not idle, and must never be locked out mid-sentence.
 * Deliberately not `mousemove` or `scroll` - a trackpad nudge or a momentum
 * scroll would keep the window open with nobody at the device.
 *
 * Shared with the PIN keep-alive in `pinKeepAlive.ts`, so the app lock and an
 * open protected note agree on what being here looks like.
 */
export const ACTIVITY_EVENTS = ['pointerdown', 'keydown', 'wheel', 'touchstart'] as const;

export type ReLockState = {
  /** When the user last did something. */
  lastActivityAt: number;
  now: number;
  /** The Security setting: minutes, or -1 for "on browser restart" only. */
  timeoutMinutes: number;
  appLockEnabled: boolean;
  /**
   * Whether a wrapped phrase blob exists on this device (biometric or PIN).
   * Without one the lock screen has no door but the 12-word phrase, so
   * arming the lock would punish an idle user rather than protect them.
   * App.tsx's boot check refuses the same state, for the same reason.
   */
  hasWrappedBlob: boolean;
};

/**
 * The note that was open when the lock armed, handed back to the notes view
 * when it mounts again.
 *
 * A re-lock unmounts the whole notes view, so without this hand-off unlocking
 * would land on the home screen however deep the user had been. Module state
 * and not storage on purpose: a re-lock never reloads the page, so a variable
 * is enough, and it dies with the page - which is what keeps a cold start
 * showing the home screen rather than reopening whatever was last read.
 * `reopenNoteId` is armed only by an actual re-lock, so nothing else that
 * remounts the view (a sign-out and a sign-in as someone else) can pick up a
 * stale note.
 */
let openNoteId: string | null = null;
let reopenNoteId: string | null = null;

/** Called by the notes view whenever the open note changes. */
export function rememberOpenNote(id: string | null): void {
  openNoteId = id;
}

/** Read once, by the notes view as it mounts. Null unless a re-lock armed it. */
export function takeReopenNote(): string | null {
  const id = reopenNoteId;
  reopenNoteId = null;
  return id;
}

/** Should the app take the UI away right now? */
export function shouldReLock(state: ReLockState): boolean {
  if (!state.appLockEnabled) return false;
  if (!state.hasWrappedBlob) return false;
  // -1 is "On browser restart": the user asked for no idle re-lock at all.
  if (state.timeoutMinutes <= 0) return false;
  return state.now - state.lastActivityAt >= state.timeoutMinutes * 60_000;
}

/** Read the live setting rather than a mounted copy: the user can change the
 *  window in Security while the app runs, and the next check must honour it. */
function readState(lastActivityAt: number): ReLockState {
  const settings = loadLocalSettings();
  return {
    lastActivityAt,
    now: Date.now(),
    timeoutMinutes: settings.appLockTimeoutMinutes,
    appLockEnabled: settings.appLockEnabled,
    hasWrappedBlob: hasBiometricCredential() || hasPinWrappedPhrase(),
  };
}

/**
 * How often to ask. A poll rather than one timer set for the deadline, because
 * the deadline is not a fixed thing: the user can shorten the window in
 * Security while the app runs, and a timer armed for the old window would sit
 * there ignoring the new one until it fired. Five seconds costs a comparison,
 * bounds how late a lock can be, and needs no re-arming anywhere.
 */
const CHECK_INTERVAL_MS = 5_000;

/**
 * Watch for the idle window to pass and call `onLock` when it does. Returns a
 * teardown function. The caller runs this only while the app is unlocked and
 * signed in; `onLock` fires at most once per watch, because locking tears the
 * watch down.
 */
export function startReLockWatch(onLock: () => void): () => void {
  let lastActivityAt = Date.now();

  function bump(): void {
    lastActivityAt = Date.now();
  }

  function check(): void {
    if (!shouldReLock(readState(lastActivityAt))) return;
    reopenNoteId = openNoteId;
    onLock();
  }

  function onVisibility(): void {
    // Coming back is the case the poll cannot cover on its own: a hidden tab
    // throttles its timers and a backgrounded phone app stops running them
    // altogether, so the window can pass with nothing watching. Deliberately no
    // bump here - returning to the app is exactly when a window that passed
    // while it was away has to be honoured.
    if (!document.hidden) check();
  }

  for (const type of ACTIVITY_EVENTS) {
    document.addEventListener(type, bump, true);
  }
  document.addEventListener('visibilitychange', onVisibility);
  const timer = window.setInterval(check, CHECK_INTERVAL_MS);

  return () => {
    window.clearInterval(timer);
    for (const type of ACTIVITY_EVENTS) {
      document.removeEventListener(type, bump, true);
    }
    document.removeEventListener('visibilitychange', onVisibility);
  };
}
