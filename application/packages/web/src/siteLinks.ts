import { activeLocale } from './languages';
import { LOCALE_TO_SLUG } from './localeRoutes';
import { detectPlatform } from './devices';
import { isDemoMode } from './demo';
import { isAppHost } from './hosts';

// In-app links to the public marketing site. The native (Tauri) webview can't
// render the marketing page and silently swallows target="_blank", so on desktop
// we emit an absolute URL that App.tsx's opener interceptor hands to the system
// browser. On web we emit a relative path that opens in a new tab on the same
// origin (so staging and localhost stay put).
//
// Demo is the exception to the relative-on-web rule: try.privacynotes.app (and
// ?demo=1 locally) serves the app bundle on every path and is noindex/robots-
// blocked, so a relative /en#downloads lands back inside the demo instead of on
// the marketing page. Demo always points at the real apex. The dedicated app
// host (use.privacynotes.app) gets the same treatment for the same reason:
// marketing paths on it are 301s back to the apex at best (see hosts.ts).

/**
 * Marketing-site link: absolute on desktop (system browser), in demo mode,
 * and on the dedicated app host; relative on web on the apex.
 */
export function siteHref(path: string): string {
  // Spec: ops/docs/gotchas.md (canonical no-www domain)
  return detectPlatform() !== 'web' || isDemoMode() || isAppHost()
    ? `https://privacynotes.app${path}`
    : path;
}

/** Homepage in the user's active language (/en, /de, ...), regardless of login. */
export function marketingHomeHref(): string {
  return siteHref(LOCALE_TO_SLUG[activeLocale()] ?? '/en');
}
