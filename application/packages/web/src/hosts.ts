/**
 * Host detection for the marketing/app domain split.
 *
 * The app is moving to use.privacynotes.app; the apex stays the
 * marketing site (and keeps serving the app through the transition so
 * nothing breaks for signed-in users). One bundle, one deploy -
 * behavior switches on the runtime hostname, exactly like demo.ts does
 * for try.privacynotes.app.
 *
 * This module intentionally imports NO app modules so early boot code
 * (main.tsx) can read it without dragging anything else in.
 *
 * worker.ts mirrors these hostnames by hand (separate bundle, cannot
 * import app code) - keep them in sync.
 *
 * Spec: ops/docs/domain-split.md (cutover checklist, rollback plan, ?move=1 test switch)
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

let cachedApp: boolean | null = null;
let cachedApex: boolean | null = null;

/**
 * True when running on the dedicated app host (use.privacynotes.app).
 *
 * `?apphost=1` forces it on localhost only, mirroring demo.ts's `?demo=1`,
 * because the branches this gates (the auth card as the entry point, absolute
 * marketing links, the move handoff) are otherwise unreachable in dev. The
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
 * True on the apex itself. Gates the domain-move emitter (migrate.ts),
 * the retirement routing in App.tsx and the OAuth redirect pin.
 *
 * `?apexhost=1` forces it on localhost only, mirroring `?apphost=1`
 * above and for the same reason: the branches this gates (MoveScreen,
 * the #phrase forwarder, the CTA redirect) are otherwise unreachable
 * in dev. Same production guard - a query string must not flip host
 * identity outside localhost. Note the handoff still targets the real
 * APP_ORIGIN, so a dev move lands on production use.privacynotes.app.
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
