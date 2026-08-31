/**
 * Hold the PIN window open while the user works inside a note they unlocked.
 *
 * The window is measured from the moment of the last unlock, so a short one
 * locked the note under the person typing in it - every minute, all day, with
 * no way to finish a sentence (issue #254). Real input inside the open note
 * now carries the window forward, which is what the "Re-lock after" label
 * already promises: an idle window rather than a countdown.
 *
 * The scope is the note the user has open, and nothing else. Opening another
 * note ends the keep-alive, so the window runs out behind them and the
 * protected note asks again when they return to it.
 *
 * One guard keeps this honest: an event extends a window only while that
 * window is still open. Once the note locks, input at its gate cannot lift
 * the gate, so this can never unlock anything. It postpones a lock for
 * somebody who is demonstrably at the device, and does nothing else.
 */

import { ACTIVITY_EVENTS } from './appReLock';
import { markPinUnlocked, shouldPromptForPin } from './pin';

/**
 * How often the window is actually pushed forward. Every keystroke asks, but
 * a write per character buys nothing: the shortest window a user can pick is
 * a minute, so a stamp up to this old still leaves the note wide open.
 */
const WRITE_INTERVAL_MS = 10_000;

/**
 * Watch for input and keep the window open. Returns a teardown function. The
 * caller runs this only while a PIN-protected note is the open one.
 */
export function startPinKeepAlive(timeoutMinutes: number): () => void {
  let lastWriteAt = 0;

  function bump(): void {
    const now = Date.now();
    if (now - lastWriteAt < WRITE_INTERVAL_MS) return;
    if (shouldPromptForPin(timeoutMinutes)) return;
    lastWriteAt = now;
    markPinUnlocked();
  }

  for (const type of ACTIVITY_EVENTS) {
    document.addEventListener(type, bump, true);
  }
  return () => {
    for (const type of ACTIVITY_EVENTS) {
      document.removeEventListener(type, bump, true);
    }
  };
}
