/**
 * The cover the operating system photographs instead of the notes.
 *
 * A phone takes a picture of an app as it leaves the screen and shows that
 * picture in the app switcher. A note that was open is readable there, and the
 * app lock never runs, because the app was never opened. The idle window in
 * `appReLock.ts` cannot reach this: the picture is taken outside the app.
 *
 * The cover is drawn natively and not here, which is the whole design. When a
 * phone backgrounds an app the web view is already being suspended, so a cover
 * painted from JavaScript races the picture and loses on some devices. This
 * module only decides WHETHER to cover, and hands that decision to the side
 * that can act on it in time. Android has no web-reachable control at all: the
 * recents picture is a window property.
 * Spec: ops/docs/plans/app-switcher-privacy-screen.md
 *
 * Armed by the app lock and nothing else, so what the switch says in Settings
 * is what the phone does. `shouldReLock` additionally demands a wrapped phrase
 * blob, because a lock with no door strands the user; a cover cannot lock
 * anybody out of anything, so it needs no such refusal.
 */

import { detectPlatform, type Platform } from './devices';

declare global {
  interface Window {
    /** Installed by MainActivity.kt in the Android app; absent everywhere else. */
    __pnPrivacy?: { set: (enabled: boolean) => void };
  }
}

/**
 * Only the two phone platforms. The desktop apps and the browser show no
 * stored picture of a backgrounded app, so there is nothing to cover and the
 * line of copy in Settings would be a false statement.
 */
export function shouldArmPrivacyScreen(appLockEnabled: boolean, platform: Platform): boolean {
  if (platform !== 'ios' && platform !== 'android') return false;
  return appLockEnabled;
}

/**
 * What was last handed to the native side. The push runs on every settings
 * write, which is far more often than the answer changes, and an unchanged
 * answer must not cross the bridge.
 */
let pushed: boolean | null = null;

/** Called from the one place local settings are written, so no caller can
 *  forget, and so turning the app lock off disarms the cover on the same
 *  path that turning it on arms it. */
export function applyPrivacyScreen(appLockEnabled: boolean): void {
  const armed = shouldArmPrivacyScreen(appLockEnabled, detectPlatform());
  if (armed === pushed) return;
  pushed = armed;

  if (window.__pnPrivacy) {
    window.__pnPrivacy.set(armed);
    return;
  }
  if (detectPlatform() !== 'ios') return;
  void (async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('set_privacy_screen', { enabled: armed });
    } catch {
      /* An older build with no such command. Nothing to fall back to. */
    }
  })();
}
