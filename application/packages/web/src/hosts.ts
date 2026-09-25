/**
 * Host detection for the marketing/app domain split.
 *
 * The app lives on use.privacynotes.app. The apex is the marketing
 * site, and it sends a signed-in visitor on to the app host, where they
 * sign in. One bundle, one deploy - behavior switches on the runtime
 * hostname, exactly like demo.ts does for try.privacynotes.app.
 *
 * This module intentionally imports NO app modules so early boot code
 * (main.tsx) can read it without dragging anything else in.
 *
 * worker.ts mirrors these hostnames by hand (separate bundle, cannot
 * import app code) - keep them in sync.
 *
 * Spec: ops/docs/domain-split.md (retirement phase, apex sunset model)
 */

/** The dedicated app host. */
const APP_HOSTNAME = 'use.privacynotes.app';
export const APP_ORIGIN = 'https://use.privacynotes.app';

/**
 * The marketing origin, canonical form (no www). Compare a www-stripped
 * `location.origin` against this to catch the apex AND www in one test,
 * which `isApexHost()` cannot do (it reads the raw hostname).
 */
export const APEX_ORIGIN = 'https://privacynotes.app';

/**
 * The App Store listing of the iPhone and iPad app, in the country-less form
 * Apple forwards to the reader's own storefront. The landing page's download
 * tile and the store build's update toast link it from here. worker.ts keeps
 * a copy for /dl/appstore, because this module reads `window` and the Worker
 * is type-checked without it; tests/appStoreId.test.ts holds the two equal.
 * Spec: ops/docs/mobile-release-status.md (app records)
 */
export const APP_STORE_ID = '6785958812';
export const APP_STORE_URL = `https://apps.apple.com/app/id${APP_STORE_ID}`;

let cachedApp: boolean | null = null;
let cachedApex: boolean | null = null;

/**
 * True when running on the dedicated app host (use.privacynotes.app).
 *
 * `?apphost=1` forces it on localhost only, mirroring demo.ts's `?demo=1`,
 * because the branches this gates (the auth card as the entry point, absolute
 * marketing links, the noindex meta) are otherwise unreachable in dev. The
 * localhost guard is the difference from demo: this flag decides where links
 * point, so it must not be flippable by a query string in production.
 */
export function isAppHost(): boolean {
  if (cachedApp !== null) return cachedApp;
  try {
    cachedApp =
      typeof window !== 'undefined' &&
      (window.location.hostname === APP_HOSTNAME ||
        (window.location.hostname === 'localhost' &&
          new URLSearchParams(window.location.search).get('apphost') === '1'));
  } catch {
    cachedApp = false;
  }
  return cachedApp;
}

/**
 * True on the apex itself, the marketing host, which sends a signed-in
 * visitor to the app host rather than booting the notes app. Gates the
 * retirement routing in App.tsx (the MoveScreen), the landing CTA
 * redirect, the OAuth redirect pin and the phrase-fragment drop in
 * qrSignIn.ts.
 *
 * `?apexhost=1` forces it on localhost only, mirroring `?apphost=1`
 * above and for the same reason: those branches are otherwise
 * unreachable in dev. Same production guard - a query string must not
 * flip host identity outside localhost. Each of them sends the visitor
 * to the real APP_ORIGIN, so from dev they land on production
 * use.privacynotes.app.
 */
export function isApexHost(): boolean {
  if (cachedApex !== null) return cachedApex;
  try {
    cachedApex =
      typeof window !== 'undefined' &&
      (window.location.hostname === 'privacynotes.app' ||
        (window.location.hostname === 'localhost' &&
          new URLSearchParams(window.location.search).get('apexhost') === '1'));
  } catch {
    cachedApex = false;
  }
  return cachedApex;
}
