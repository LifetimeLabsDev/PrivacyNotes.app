/**
 * The size of the whole desktop window, as a scale on every pixel in it.
 *
 * The desktop app runs in a webview, so the engine under the page can scale
 * the page the way a browser does. That is what makes this reach the app
 * chrome, which the editor text size next to it cannot: the chrome carries
 * hardcoded pixel sizes, so a root font size would move part of the UI and
 * freeze the rest. Zoom happens below our stylesheet instead of inside it,
 * so no component is aware of it.
 *
 * One ladder owns the level and both the Appearance row and the keyboard step
 * along it. Tauri's own `zoomHotkeysEnabled` is deliberately off, even though
 * it would give the keystrokes for nothing: it keeps a level of its own that
 * nothing can read back, so after one keypress the Appearance row would state
 * a size the window no longer has. On macOS and Linux that level also lives
 * in an injected script, which forgets it on every start.
 *
 * Device-local, like the editor text size, and for the same reason: a 13 inch
 * laptop and a 27 inch monitor want different answers, so one synced value
 * would fix one screen and break the other.
 *
 * Spec: ops/docs/design-decisions.md (app zoom)
 */

import { useCallback, useSyncExternalStore } from 'react';

const KEY = 'privacynotes.appZoom';

/**
 * The offered levels, smallest first. 1 is unscaled and is the default.
 *
 * Two steps below 1 and three above it. The row is one button wider than
 * the editor text size beside it and 1 therefore sits left of its middle,
 * which is the price of keeping both ends: the steps below are for a laptop
 * screen with too little on it, and the steps above are what the feature is
 * for.
 *
 * 2 is the top because it is the number an accessibility review asks for
 * (WCAG 2.1, resize text) and because zoom narrows the window's CSS width:
 * the app takes its narrow layout under 768 of them, so at 2 a window must
 * be 1536 points wide to stay on the wide one, which the default 1440 is
 * not. A higher step would make the narrow layout the normal result at
 * every window size rather than an edge of the range.
 */
export const APP_ZOOM_LEVELS = [0.8, 0.9, 1, 1.25, 1.5, 2] as const;
export type AppZoom = (typeof APP_ZOOM_LEVELS)[number];

/** The level a fresh install and a Reset to defaults both land on. */
export const DEFAULT_APP_ZOOM: AppZoom = 1;

/**
 * True in a desktop build and nowhere else.
 *
 * `__PN_BUILD_PLATFORM__` is baked in at build time, so on the web the
 * Appearance row, the key handler and the dynamic import behind them never
 * run; the web build still carries them as unreachable code and lazy chunks
 * it never loads. It repeats the platform test in `devices.ts`
 * instead of calling it, because this module runs before React mounts and
 * that one reaches the whole sync and crypto graph.
 */
export function appZoomSupported(): boolean {
  return (
    __PN_BUILD_PLATFORM__ !== '' &&
    __PN_BUILD_PLATFORM__ !== 'ios' &&
    __PN_BUILD_PLATFORM__ !== 'android'
  );
}

function isAppZoom(v: unknown): v is AppZoom {
  return typeof v === 'number' && (APP_ZOOM_LEVELS as readonly number[]).includes(v);
}

/** The stored level. Anything unrecognised means the default. */
function getStoredAppZoom(): AppZoom {
  try {
    const raw = Number(localStorage.getItem(KEY));
    return isAppZoom(raw) ? raw : DEFAULT_APP_ZOOM;
  } catch {
    return DEFAULT_APP_ZOOM;
  }
}

/** Currently applied level, for the React snapshot. */
let activeAppZoom: AppZoom = DEFAULT_APP_ZOOM;

/** Hand a level to the webview. Rejects when the build is not a desktop one,
 *  which the callers all gate on, so a rejection is swallowed. */
async function pushToWebview(level: AppZoom): Promise<void> {
  const { getCurrentWebview } = await import('@tauri-apps/api/webview');
  await getCurrentWebview().setZoom(level);
}

const listeners = new Set<() => void>();

function subscribe(cb: () => void): () => void {
  listeners.add(cb);
  return () => { listeners.delete(cb); };
}

function snapshot(): AppZoom {
  return activeAppZoom;
}

/** Apply a level to the window and persist it. */
export function applyAppZoom(level: AppZoom): void {
  activeAppZoom = level;
  try { localStorage.setItem(KEY, String(level)); } catch { /* private mode */ }
  if (appZoomSupported()) void pushToWebview(level).catch(() => { /* no webview */ });
  listeners.forEach((cb) => cb());
}

/**
 * Apply the stored level at start.
 *
 * It pushes even at 1, rather than treating 1 as nothing to do, because the
 * webview can start at a level we did not set: WebView2 keeps a zoom factor
 * of its own in the user data folder. Pushing unconditionally is what makes
 * the stored value the one that decides, so the Appearance row never
 * describes a window somebody else scaled.
 */
export function initAppZoom(): void {
  if (!appZoomSupported()) return;
  applyAppZoom(getStoredAppZoom());
}

/**
 * Move one step along the ladder and stop at either end.
 *
 * The ends are silent on purpose. A keystroke that already sits at the top
 * has nothing to report, and a toast on every extra press of a held key
 * would be the loudest thing in the app.
 */
export function stepAppZoom(direction: 1 | -1): void {
  const at = APP_ZOOM_LEVELS.indexOf(activeAppZoom);
  const next = Math.min(APP_ZOOM_LEVELS.length - 1, Math.max(0, at + direction));
  applyAppZoom(APP_ZOOM_LEVELS[next] ?? DEFAULT_APP_ZOOM);
}

/** The level, and a setter, shared by every caller. */
export function useAppZoom() {
  const appZoom = useSyncExternalStore(subscribe, snapshot);
  const setAppZoom = useCallback((next: AppZoom) => { applyAppZoom(next); }, []);
  return { appZoom, setAppZoom };
}
