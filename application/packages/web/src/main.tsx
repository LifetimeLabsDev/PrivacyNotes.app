import React, { lazy, Suspense } from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { AuthProvider } from './auth';
import { LoadingScreen } from './LoadingScreen';
import { initTheme } from './theme';
import { clearFreshDemoCredentials, isDemoMode } from './demo';
import { APP_ORIGIN, isApexHost, isAppHost } from './hosts';
import { detectPlatform, isLinuxNative } from './devices';
import { IconDefaults } from './icons';
import { installAndroidBackBridge } from './androidBack';
import { installStrayDropGuard } from './strayDropGuard';
import { i18nReady } from './i18n';
import { initWriterGenListener, announceSealedWriter } from './writerGen';
import { setSealedWrites } from './localSeal';
import './index.css';

initTheme();

// Android back button entry point (#174) - must exist before the first
// back press, even during onboarding (where an unhandled press
// correctly backgrounds the app). Inert on every other platform.
installAndroidBackBridge();

// A file dropped where nothing takes it must not navigate the page away.
// The desktop webviews depend on it - see strayDropGuard.ts.
installStrayDropGuard();

// Off-screen grid tiles skip layout and paint wherever a grid track reads a
// skipped item's intrinsic size. The Linux app's web engine does not read it
// and crushes the grid into slivers, so it never gets the attribute. Set
// before React mounts, so the first grid drawn is already the right one, and
// absent by default, because the plain grid is the state that always works.
// Spec: ops/docs/ui-patterns.md (section 64)
if (!isLinuxNative()) document.documentElement.dataset.lazyTiles = 'on';

// Keep the public demo subdomain out of search results so it doesn't
// compete with the marketing site (see demo.ts). Same for the dedicated
// app host: the apex owns search, use.privacynotes.app owns sessions
// (see hosts.ts). Its robots.txt Disallow in worker.ts is the belt,
// this meta is the suspender.
// A fresh demo tab session must not inherit the previous visitor's
// demo PIN or app lock - see clearFreshDemoCredentials. Must run
// before React mounts (App.tsx reads the lock state synchronously).
clearFreshDemoCredentials();
// A reader-release tab reloads once when a sealed-writer tab appears.
// Spec: ops/docs/plans/local-at-rest.md (5.2, mechanism 2)
initWriterGenListener();
// THE writer switch: with it on, every note-content write is sealed at
// rest and this tab announces itself to retire reader-mode tabs.
// Setting it to false is exactly the reader release (read sealed rows,
// write plaintext) - the rollout's release A ships that way.
// Spec: ops/docs/plans/local-at-rest.md (5.1, the two releases)
setSealedWrites(true);
announceSealedWriter();

if (isDemoMode() || isAppHost()) {
  const robots = document.createElement('meta');
  robots.name = 'robots';
  robots.content = 'noindex, nofollow';
  document.head.appendChild(robots);
}

// A #phrase= fragment on the apex is a paper credential - a sign-in or
// backup QR minted before the domain split. Sessions live on the app
// host since the retirement, so forward it there with the fragment
// intact (fragments never reach any server) instead of letting App.tsx
// consume it and mint a session onto the retired origin. Lives in the
// bundle, not an inline head script, because the CSP allows only
// 'self'. The render below is skipped: the QR prompt must appear once,
// on the destination.
// Spec: ops/docs/domain-split.md (retirement phase, #phrase forwarder)
const forwardingPhrase =
  isApexHost() && window.location.hash.startsWith('#phrase=');
if (forwardingPhrase) {
  window.location.replace(`${APP_ORIGIN}/${window.location.hash}`);
}

// Vite emits `vite:preloadError` on `window` when a dynamically-imported
// chunk 404s - almost always because the user had a tab open across a
// deploy, so the cached entry bundle is still asking for an old chunk
// hash that no longer exists on the CDN. Without handling this, the
// failure surfaces inside whichever feature triggered the import (e.g.
// "Camera unavailable: Failed to fetch dynamically imported module"
// when opening the QR scanner) and the user has no idea a hard refresh
// would fix it.
//
// We reload once per tab session. The flag lives in sessionStorage so
// it auto-clears on tab close - and so a *second* preloadError in the
// same session (post-reload) doesn't loop: it falls through to the
// caller's normal error handling, which means something is genuinely
// broken and reloading won't help.
window.addEventListener('vite:preloadError', (event) => {
  if (sessionStorage.getItem('pn:reloaded-for-preload-error') === '1') return;
  sessionStorage.setItem('pn:reloaded-for-preload-error', '1');
  event.preventDefault();
  window.location.reload();
});

// A handful of standalone screens live behind their own URL rather than a
// nested route. We check the pathname here and lazy-load the one that
// matches, so nothing but the notes app enters the default bundle.
//
// No react-router needed for a few extra routes; the cost of adding a
// router to the whole app for this would be way out of proportion to the
// benefit.
//
// The admin console is deliberately not among them. It is its own app
// on its own host, so no operator code ships to a user.
// Spec: ops/docs/plans/admin-split-handoff.md (admin panel: dash.privacynotes.app, gated by Cloudflare Access)
const BurnNote = lazy(() => import('./BurnNote'));
const CheckoutLauncher = lazy(() => import('./CheckoutLauncher'));
const AboutWindow = lazy(() => import('./AboutWindow'));
const pathname = window.location.pathname.replace(/\/+$/, '');
const isBurnRoute = pathname === '/burn';
const isCheckoutRoute = pathname === '/checkout';

// The desktop About menu opens a small dedicated window that loads this same
// bundle with ?about-window=1 - render just the About panel there, no auth,
// no app shell. Desktop-gated so the param is inert on the web.
// See desktop/src-tauri/src/lib.rs (open_about_window).
const isAboutWindow =
  new URLSearchParams(window.location.search).has('about-window') &&
  detectPlatform() === 'desktop';

// Privacy policy and ToS live on lifetimelabs.dev - redirect legacy routes
if (pathname === '/privacy') {
  window.location.replace('https://lifetimelabs.dev/privacy/');
}
if (pathname === '/terms') {
  window.location.replace('https://lifetimelabs.dev/terms/');
}

const tree = (
  <React.StrictMode>
    <IconDefaults>
      {isAboutWindow ? (
        <Suspense fallback={null}>
          <AboutWindow />
        </Suspense>
      ) : isBurnRoute ? (
        <Suspense fallback={<LoadingScreen />}>
          <BurnNote />
        </Suspense>
      ) : isCheckoutRoute ? (
        <Suspense fallback={<LoadingScreen />}>
          <CheckoutLauncher />
        </Suspense>
      ) : (
        <AuthProvider>
          <App />
        </AuthProvider>
      )}
    </IconDefaults>
  </React.StrictMode>
);

// Locale catalogs are lazy (see i18n.ts): English is bundled, any other boot
// locale is fetched. Gate the first render on that fetch so a non-English
// visitor never sees an English frame flash past. `i18nReady` never rejects -
// a failed fetch resolves having kept English - so the app always mounts.
// English visitors resolve on the microtask queue and pay nothing.
void i18nReady.then(() => {
  if (forwardingPhrase) return;
  ReactDOM.createRoot(document.getElementById('root')!).render(tree);
});
