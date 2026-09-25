import React, { lazy, Suspense, useRef, useState } from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { AuthProvider } from './auth';
import { LoadingScreen } from './LoadingScreen';
import { initTheme } from './theme';
import { clearFreshDemoCredentials, isDemoMode } from './demo';
import { isAppHost } from './hosts';
import { dropApexPhraseFragment } from './qrSignIn';
import { detectPlatform, isLinuxNative } from './devices';
import { IconDefaults } from './icons';
import { installAndroidBackBridge } from './androidBack';
import { installStrayDropGuard } from './strayDropGuard';
import { i18nReady } from './i18n';
import { initWriterGenListener, announceSealedWriter } from './writerGen';
import { SEALED_WRITES_IN_PRODUCTION, setSealedWrites } from './localSeal';
import { VERSION } from './version';
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
// rest and this tab announces itself to retire reader-mode tabs. The
// constant is false in exactly the reader release (read sealed rows,
// write plaintext) - the rollout's release A ships that way.
// Spec: ops/docs/plans/local-at-rest.md (5.1, the two releases)
setSealedWrites(SEALED_WRITES_IN_PRODUCTION);
announceSealedWriter();

if (isDemoMode() || isAppHost()) {
  const robots = document.createElement('meta');
  robots.name = 'robots';
  robots.content = 'noindex, nofollow';
  document.head.appendChild(robots);
}

// An old paper QR opened on the apex: the fragment is cleared, the page
// leaves for the app host's sign-in screen with no fragment, and "Scan QR
// with camera" there reads the paper again. Nothing renders here.
// Spec: ops/docs/domain-split.md (retirement phase, #phrase forwarder)
const leavingApex = dropApexPhraseFragment();

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

// ── The screen a failed render leaves behind ──────────────────────
//
// Without a boundary a throw anywhere in the tree empties the document,
// so the window shows the html background from index.css and nothing
// else: no message, no version, no way back. On a packaged desktop
// build the error is then unreadable to the user AND to us, because a
// release build carries no web inspector, and a report costs one guess
// per round trip.
//
// ENGLISH ONLY, ON PURPOSE. DO NOT TRANSLATE THIS SCREEN, and do not
// route its text through i18n. Every other user-facing string in this
// app ships in every locale; this one is the single exception, agreed
// 2026-09-18, and a locale batch must skip it. The reason is the whole
// point of the screen: i18n is one of the things that can throw, and a
// translator call on this path fails exactly when the screen is needed,
// which leaves the user with the empty window this code exists to
// replace. The same rule rules out the icon set, the theme, the auth
// provider, and bugReportUrl.ts, which reaches into platform detection:
// the link below is a plain constant for that reason. Inline styles
// rather than classes, because the stylesheet can be missing too.
//
// `pnpm check:house` enforces it. Nothing between here and the end
// marker below may call a translator.
// Spec: ops/docs/i18n-spec.md (the boot error screen)
const ISSUES_URL = 'https://github.com/LifetimeLabsDev/PrivacyNotes.app/issues';

/** Everything a reporter should hand over, in one selectable block. */
function bootErrorReport(error: Error): string {
  return [
    `PrivacyNotes ${VERSION}`,
    navigator.userAgent,
    `${error.name}: ${error.message}`,
    error.stack ?? '(no stack)',
  ].join('\n');
}

function BootErrorScreen({ error }: { error: Error }) {
  // Asks for light and lands on dark when the platform cannot answer,
  // which is the same way round as the theme module's own resolver.
  const dark =
    typeof window.matchMedia !== 'function' ||
    !window.matchMedia('(prefers-color-scheme: light)').matches;
  const c = dark
    ? { bg: '#171514', card: '#23211E', line: '#302D29', text: '#D9D4CC', dim: '#958E84', link: '#4A90D9' }
    : { bg: '#F5F5F5', card: '#FFFFFF', line: '#D9D9D9', text: '#1F1F1F', dim: '#6B6B6B', link: '#1D4ED8' };

  const report = bootErrorReport(error);
  const reportRef = useRef<HTMLPreElement>(null);
  const [copyState, setCopyState] = useState<'idle' | 'copied' | 'selected'>('idle');

  const button: React.CSSProperties = {
    font: 'inherit',
    padding: '8px 14px',
    borderRadius: 8,
    border: `1px solid ${c.line}`,
    background: c.card,
    color: c.text,
    cursor: 'pointer',
  };

  async function copy() {
    try {
      await navigator.clipboard.writeText(report);
      setCopyState('copied');
      return;
    } catch {
      // No clipboard, or permission refused. A button that does nothing
      // strands the one person who came here to send us the text, so
      // select the block and let the keyboard finish it.
    }
    const block = reportRef.current;
    if (block) {
      const range = document.createRange();
      range.selectNodeContents(block);
      const selection = window.getSelection();
      selection?.removeAllRanges();
      selection?.addRange(range);
    }
    setCopyState('selected');
  }

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        overflow: 'auto',
        background: c.bg,
        color: c.text,
        fontFamily: 'system-ui, sans-serif',
        fontSize: 15,
        lineHeight: 1.5,
        padding: 24,
      }}
    >
      <div style={{ maxWidth: 640, margin: '0 auto' }}>
        <h1 style={{ fontSize: 20, fontWeight: 600, margin: '8px 0 12px' }}>
          PrivacyNotes could not start
        </h1>
        <p style={{ margin: '0 0 16px', color: c.dim }}>
          Something failed while the screen was being drawn. Your notes are
          untouched. Copy the details below into a bug report and we will fix
          it.
        </p>
        <pre
          ref={reportRef}
          style={{
            margin: '0 0 16px',
            padding: 12,
            maxHeight: '40vh',
            overflow: 'auto',
            background: c.card,
            border: `1px solid ${c.line}`,
            borderRadius: 8,
            fontSize: 12,
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-word',
          }}
        >
          {report}
        </pre>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button type="button" style={button} onClick={copy}>
            {copyState === 'copied'
              ? 'Copied'
              : copyState === 'selected'
                ? 'Selected, now copy it'
                : 'Copy details'}
          </button>
          <button type="button" style={button} onClick={() => window.location.reload()}>
            Reload
          </button>
        </div>
        <p style={{ margin: '16px 0 0', color: c.dim, fontSize: 13 }}>
          Report it at{' '}
          <a href={ISSUES_URL} style={{ color: c.link }}>
            {ISSUES_URL}
          </a>
        </p>
      </div>
    </div>
  );
}

class BootErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { error: Error | null }
> {
  state: { error: Error | null } = { error: null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    // The component stack exists here and nowhere else. It reaches a
    // console on the web and in a dev build; the screen carries what a
    // packaged build can hand over instead.
    console.error('[boot] render failed', error, info.componentStack);
  }

  render() {
    const { error } = this.state;
    return error ? <BootErrorScreen error={error} /> : this.props.children;
  }
}
// ── end of the failed-render screen ───────────────────────────────

const tree = (
  <React.StrictMode>
    <BootErrorBoundary>
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
    </BootErrorBoundary>
  </React.StrictMode>
);

// Locale catalogs are lazy (see i18n.ts): English is bundled, any other boot
// locale is fetched. Gate the first render on that fetch so a non-English
// visitor never sees an English frame flash past. `i18nReady` never rejects -
// a failed fetch resolves having kept English - so the app always mounts.
// English visitors resolve on the microtask queue and pay nothing.
void i18nReady.then(() => {
  if (leavingApex) return;
  ReactDOM.createRoot(document.getElementById('root')!).render(tree);
});
