/**
 * Open a URL in the user's browser - the programmatic sibling of the
 * anchor-click interceptor in App.tsx. Anchors are covered there (the
 * capture-phase listener hands external hrefs to the opener plugin on
 * desktop); this helper is for code paths with no anchor to click, like
 * a bookmark row's open action.
 *
 * Web: window.open with noopener, same guarantees as rel="noopener".
 * Tauri (desktop + mobile wrappers): the opener plugin, because the
 * WebView swallows window.open the same way it swallows target=_blank.
 * Spec: ops/docs/macos-ios-setup.md (native flows use the same opener plugin)
 */

import { detectPlatform } from './devices';

export function openExternal(url: string): void {
  if (!/^https?:/i.test(url)) return;
  const platform = detectPlatform();
  if (platform !== 'web') {
    // iOS: in-app SFSafariViewController sheet, mirroring the anchor
    // interceptor in App.tsx (guideline 4 - keep the user in the app).
    const openWith = platform === 'ios' ? ('inAppBrowser' as const) : undefined;
    void import('@tauri-apps/plugin-opener').then(async ({ openUrl }) => {
      try {
        await openUrl(url, openWith);
      } catch (err) {
        // Same fallback as the anchor interceptor in App.tsx: `with` is
        // ACL-checked, so a scope gap must degrade to the system browser
        // rather than to a dead tap. See the comment there.
        if (openWith) {
          console.warn('[links] in-app sheet refused, using the browser', err);
          await openUrl(url);
          return;
        }
        console.error('[links] could not open', url, err);
      }
    });
    return;
  }
  window.open(url, '_blank', 'noopener,noreferrer');
}
