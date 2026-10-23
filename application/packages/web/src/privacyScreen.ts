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
 * Spec: ops/docs/archive/app-switcher-privacy-screen.md
 *
 * Armed by the app lock or by the capture block below, so what the switches
 * say in Settings is what the phone does. `shouldReLock` additionally demands
 * a wrapped phrase blob, because a lock with no door strands the user; a cover
 * cannot lock anybody out of anything, so it needs no such refusal.
 *
 * The capture block keeps the window out of screenshots, screen recordings and
 * screen sharing, where the operating system offers a way to. It is a device
 * setting and never syncs: what it can do differs per platform, and switching
 * it off on one device must not switch it off on another.
 * Spec: ops/docs/archive/app-switcher-privacy-screen.md (section 14)
 */

import { useSyncExternalStore } from 'react';
import { detectPlatform, type Platform } from './devices';

declare global {
  interface Window {
    /** Installed by MainActivity.kt in the Android app; absent everywhere else. */
    __pnPrivacy?: { set: (enabled: boolean) => void; block?: (enabled: boolean) => void };
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
 * Where the operating system gives an app a way to keep its window out of a
 * capture. `build` is Tauri's own platform name, baked in at build time.
 *
 * Android has FLAG_SECURE. Windows and macOS have a window property that
 * capture tools honour. iOS has no documented block: the window sits inside
 * a secure text field's layer, which a capture draws black, and a recording
 * still raises the cover if that layer fails. Linux and the browser have
 * nothing, and the switch is hidden there rather than shown as a promise.
 */
export function captureBlockSupported(build: string = __PN_BUILD_PLATFORM__): boolean {
  return build === 'android' || build === 'ios' || build === 'darwin' || build === 'windows';
}

/**
 * What the native side is told, as one answer so both halves are tested
 * together. The capture block also arms the cover on a phone: somebody who
 * refuses a screenshot does not want the notes on the app switcher card.
 */
export function privacyPush(
  appLockEnabled: boolean,
  blockCapture: boolean,
  platform: Platform,
  build: string,
): { cover: boolean; block: boolean } {
  const block = blockCapture && captureBlockSupported(build);
  return { cover: shouldArmPrivacyScreen(appLockEnabled || block, platform), block };
}

const CAPTURE_KEY = 'privacynotes.blockCapture';

/** Read on first use rather than at import, so the boot path touches no storage for it. */
let captureBlock: boolean | null = null;

function getCaptureBlock(): boolean {
  if (captureBlock === null) {
    try {
      captureBlock = localStorage.getItem(CAPTURE_KEY) === '1';
    } catch {
      captureBlock = false;
    }
  }
  return captureBlock;
}

/** The app lock value of the last push, so the capture switch can re-push without reading settings. */
let lastLock = false;

/**
 * What was last handed to the native side. The push runs on every settings
 * write, which is far more often than the answer changes, and an unchanged
 * answer must not cross the bridge.
 */
let pushedCover: boolean | null = null;
let pushedBlock: boolean | null = null;

/** Called from the one place local settings are written, so no caller can
 *  forget, and so turning the app lock off disarms the cover on the same
 *  path that turning it on arms it. */
export function applyPrivacyScreen(appLockEnabled: boolean): void {
  lastLock = appLockEnabled;
  const platform = detectPlatform();
  const next = privacyPush(appLockEnabled, getCaptureBlock(), platform, __PN_BUILD_PLATFORM__);
  if (next.cover !== pushedCover) {
    pushedCover = next.cover;
    pushCover(next.cover, platform);
  }
  if (next.block !== pushedBlock) {
    pushedBlock = next.block;
    pushBlock(next.block);
  }
}

function pushCover(armed: boolean, platform: Platform): void {
  if (window.__pnPrivacy) {
    window.__pnPrivacy.set(armed);
    return;
  }
  if (platform !== 'ios') return;
  void invokeNative('set_privacy_screen', armed);
}

/** Pushes false at boot too, so the stored switch is what decides and not
 *  whatever state the window happened to start in. */
function pushBlock(blocked: boolean): void {
  if (window.__pnPrivacy) {
    window.__pnPrivacy.block?.(blocked);
    return;
  }
  if (!captureBlockSupported()) return;
  void invokeNative('set_capture_block', blocked);
}

async function invokeNative(command: string, enabled: boolean): Promise<void> {
  try {
    const { invoke } = await import('@tauri-apps/api/core');
    await invoke(command, { enabled });
  } catch {
    /* An older build with no such command. Nothing to fall back to. */
  }
}

const listeners = new Set<() => void>();

function subscribe(cb: () => void): () => void {
  listeners.add(cb);
  return () => {
    listeners.delete(cb);
  };
}

/** Flip the capture block on this device and push it at once. */
export function setCaptureBlock(on: boolean): void {
  captureBlock = on;
  try {
    localStorage.setItem(CAPTURE_KEY, on ? '1' : '0');
  } catch {
    /* Storage refused: the switch holds for this session only. */
  }
  applyPrivacyScreen(lastLock);
  listeners.forEach((cb) => cb());
}

export function useCaptureBlock(): boolean {
  return useSyncExternalStore(subscribe, getCaptureBlock);
}
