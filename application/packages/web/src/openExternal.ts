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
 *
 * Four schemes and nothing else: http(s) for the web, and tel:, sms: and
 * mailto: for a contact's rows, which the OS hands to the dialer, the
 * messages app and the mail client. A phone number never opens in the iOS
 * browser sheet; that sheet is for http(s) only.
 * Spec: ops/docs/plans/contacts-pillar.md (section 9, tap to call)
 */

import { detectPlatform } from './devices';

const OPENABLE = /^(https?|tel|sms|mailto):/i;

export function openExternal(url: string): void {
  if (!OPENABLE.test(url)) return;
  const platform = detectPlatform();
  if (platform !== 'web') {
    // iOS: in-app SFSafariViewController sheet, mirroring the anchor
    // interceptor in App.tsx (guideline 4 - keep the user in the app).
    const openWith = platform === 'ios' && /^https?:/i.test(url) ? ('inAppBrowser' as const) : undefined;
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
  if (/^https?:/i.test(url)) {
    window.open(url, '_blank', 'noopener,noreferrer');
    return;
  }
  // A tel:, sms: or mailto: link is a handoff to another app, and a new
  // tab for it is a blank page left behind in the browser.
  window.location.href = url;
}
