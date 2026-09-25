import { type Plugin } from 'vite';
import { THEME_SCRIPT_TAG, THEME_TOGGLE_CSS, themeVarsCss } from './static-page-theme.ts';
import { brandMark, CHROME_CSS, ogLocaleTag } from './static-page-chrome.ts';

// The page a desktop sign-in returns to, and the reason it exists.
//
// A desktop operating system cannot tell the browser which application may
// receive a return address: macOS, Windows and Linux all resolve a custom
// scheme by last writer, and none of them has an equivalent of Android App
// Links or iOS Universal Links. So the desktop app no longer asks for a
// return address it cannot own. It asks for this page, on an origin only we
// serve, and the browser stops here. The page shows the one-time code, the
// person carries it back to the app, and the app exchanges it with the
// verifier it generated before opening the browser.
//
// What that buys: a hostile application can open this page too, but the code
// only reaches it if the person copies it out of a page carrying our name and
// pastes it into that application. That is a visible act on the level of
// handing over the recovery phrase, rather than a redirect nobody sees.
// Spec: ops/docs/plans/oauth-redirect-binding-handoff.md (section 8.3)
//
// Three constraints this page is built around.
//
// It must NOT load the application bundle. The bundle's Supabase client runs
// with `detectSessionInUrl`, so it would exchange the code in the browser,
// spend it, and leave the desktop app's own exchange to fail on a code that
// no longer exists. Static HTML only, no module script, no import.
//
// It must carry no inline script. The deployed policy allows `script-src
// 'self'` and nothing else, so the behaviour lives in /static-pages.js under
// `data-static-page="auth-desktop"`, the same arrangement the other static
// pages use.
//
// It must render something honest without JavaScript. With scripting off the
// code is still in the address bar, so the page says so rather than showing an
// empty box that looks broken.
//
// English only, like the other static pages outside the marketing tier: it is
// reached mid-sign-in from a desktop application, and the locale the person
// picked lives in that application rather than in this browser.

const CANONICAL = 'https://use.privacynotes.app/auth/desktop';
const TITLE = 'Finish signing in';
const DESC = 'Copy the one-time code and paste it back into the PrivacyNotes desktop app to finish signing in.';

const PAGE_CSS = `
.wrap{max-width:34rem;margin:0 auto;padding:4rem 1.25rem 5rem}
.card{border:1px solid var(--line);background:var(--card);border-radius:16px;padding:1.75rem}
h1{font-size:1.5rem;font-weight:800;letter-spacing:-.02em;margin:0 0 .5rem}
.lede{color:var(--sub);margin:0 0 1.5rem;line-height:1.6}
.codebox{display:flex;gap:.5rem;align-items:stretch;margin:0 0 .75rem}
code.code{flex:1;min-width:0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9rem;
  background:var(--tint);border:1px solid var(--line);border-radius:10px;padding:.85rem 1rem;
  overflow-wrap:anywhere;user-select:all}
button.copy{flex:0 0 auto;border:1px solid var(--line);background:var(--card);color:var(--ink);
  border-radius:10px;padding:.85rem 1.1rem;font-weight:600;cursor:pointer}
button.copy:hover{background:var(--tint)}
.steps{margin:1.5rem 0 0;padding-left:1.15rem;color:var(--sub);line-height:1.7}
.note{margin:1.5rem 0 0;padding-top:1.25rem;border-top:1px solid var(--line);color:var(--sub);font-size:.875rem;line-height:1.6}
.nojs{color:var(--sub);line-height:1.6}
[hidden]{display:none!important}
`;

function renderHtml(): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${TITLE} - PrivacyNotes</title>
<meta name="description" content="${DESC}">
<meta name="robots" content="noindex, nofollow">
<link rel="canonical" href="${CANONICAL}">
<meta property="og:title" content="${TITLE}">
<meta property="og:description" content="${DESC}">
<meta property="og:url" content="${CANONICAL}">
${ogLocaleTag('en')}
<style>
${themeVarsCss(
  '--bg:#fff;--fg:#15171a;--ink:#15171a;--sub:#5b6168;--line:#e7e9ec;--card:#fff;--tint:#f7f8fa;--accent:#1E40AF;--muted:#5b6168;--faint:#8a9099;--chip:#eceef1;--rail:#f7f8fa;--on-accent:#fff',
  '--bg:#0e1014;--fg:#e7e9ec;--ink:#e7e9ec;--sub:#9aa1aa;--line:#23262c;--card:#14171d;--tint:#1a1e25;--accent:#4A90D9;--muted:#9aa1aa;--faint:#6b7178;--chip:#3a4149;--rail:#14171d;--on-accent:#03203E'
)}
${CHROME_CSS}
${THEME_TOGGLE_CSS}
${PAGE_CSS}
</style>
${THEME_SCRIPT_TAG}
</head>
<body data-static-page="auth-desktop">
<div class="wrap">
  <div class="card">
    <h1>${TITLE}</h1>

    <p class="lede" data-role="lede" hidden>You are signed in here. Copy this code and paste it into ${brandMark()} on your computer.</p>
    <div class="codebox" data-role="codebox" hidden>
      <code class="code" data-role="code"></code>
      <button type="button" class="copy" data-role="copy">Copy</button>
    </div>
    <ol class="steps" data-role="steps" hidden>
      <li>Switch back to the PrivacyNotes app.</li>
      <li>Paste the code where it asks for it.</li>
      <li>You can close this tab afterwards.</li>
    </ol>

    <p class="nojs" data-role="nojs">The code is in this page's address, after <code>code=</code>. Copy it from the address bar and paste it into ${brandMark()} on your computer.</p>

    <p class="lede" data-role="missing" hidden>This page has no sign-in code in its address, so there is nothing to copy. Start the sign-in again from the app.</p>

    <p class="note">The code works once, expires shortly, and is useless to anyone but the app that started this sign-in. Never paste it into any other program.</p>
  </div>
</div>
<script src="/static-pages.js" defer></script>
</body>
</html>`;
}

export function authDesktopPagePlugin(): Plugin {
  return {
    name: 'emit-auth-desktop-page',
    generateBundle() {
      this.emitFile({
        type: 'asset',
        fileName: 'auth/desktop/index.html',
        source: renderHtml(),
      });
    },
    configureServer(server) {
      server.middlewares.use('/auth/desktop', (_req, res) => {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.end(renderHtml());
      });
    },
  };
}
