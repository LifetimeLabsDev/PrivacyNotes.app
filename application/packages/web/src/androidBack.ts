/**
 * Bridge for the Android hardware/gesture back button (#174).
 *
 * MainActivity.kt intercepts back presses (both the 3-button Back and
 * gesture-nav back swipes route through OnBackPressedDispatcher) and
 * evaluates `window.__pnHandleBack()`. A `true` return means the web
 * app consumed the press - closed the topmost overlay, exited
 * selection mode, left the open note. On `false` the native side calls
 * `moveTaskToBack(true)`, backgrounding the app with state preserved,
 * which is the standard Android root-screen behavior.
 *
 * On every other platform nothing calls the global, so this is inert.
 * NotesView registers the actual layered handler; while it is not
 * mounted (onboarding, lock screen) the default `false` correctly
 * lets Back background the app.
 */
type BackHandler = () => boolean;

let handler: BackHandler | null = null;

/** NotesView registers its layered back handler here (null to unregister). */
export function setAndroidBackHandler(h: BackHandler | null): void {
  handler = h;
}

declare global {
  interface Window {
    /** Called by MainActivity.kt on every Android back press. */
    __pnHandleBack?: () => boolean;
  }
}

/** Expose the global entry point; called once from main.tsx. */
export function installAndroidBackBridge(): void {
  window.__pnHandleBack = () => handler?.() ?? false;
}
