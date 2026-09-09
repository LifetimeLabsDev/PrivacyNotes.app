/**
 * Cloudflare Worker entry point - serves the SPA static assets and
 * adds two image proxies, both cached at the edge: /favicon, which
 * fetches site icons from upstream providers (DuckDuckGo + Google),
 * and /badge/privacytools.svg, which fetches our PrivacyTools.io
 * listing badge.
 *
 * Why: vault items show favicons for login entries. Fetching upstream
 * directly from the client would leak the user's domain list. This
 * proxy keeps the request server-side so the browser never contacts
 * a third party.
 *
 * Dual-source strategy: hash-based per-domain assignment splits load
 * between DDG and Google. If the primary source fails, the other is
 * tried as fallback. Both are proxied - the user's browser only ever
 * talks to our domain.
 *
 * Spec: ops/docs/backlog.md (#69 - dual-source round-robin + fallback)
 */

interface Env {
  ASSETS: Fetcher;
  /**
   * Aggregate campaign counter. Server-side by requirement, not by
   * preference: the privacy policy at lifetimelabs.dev states that "no
   * client-side code runs for analytics purposes", so every count this
   * Worker takes must fall out of the request itself. Never add an
   * in-page beacon to satisfy a counting need.
   * Spec: ops/docs/plans/partner-attribution.md (section 3a)
   */
  CAMPAIGNS?: AnalyticsEngineDataset;
}

/** Minimal shape of the Analytics Engine binding (no extra types package). */
interface AnalyticsEngineDataset {
  writeDataPoint(event: {
    indexes?: string[];
    blobs?: string[];
    doubles?: number[];
  }): void;
}

// Spec: ops/docs/backlog.md (#69 - 90-day edge cache TTL)
const CACHE_TTL = 90 * 24 * 60 * 60;

/** 24 hours - cache misses to avoid hammering upstream for unknown domains. */
const MISS_TTL = 24 * 60 * 60;

/**
 * Bump to invalidate every edge-cached favicon at once. Needed when the
 * cached response headers change (e.g. CORS) so stale entries are not served
 * to the native apps, which read the proxy cross-origin from tauri://localhost.
 */
const CACHE_VERSION = 'v3';

/**
 * The PrivacyTools.io listing badge, carrying our live star rating.
 * Proxied for the same reason favicons are: the homepage promises no
 * tracking on the very same screen, so it must not hand every visitor's
 * IP to a second host. Upstream recomputes the rating once a day.
 */
const BADGE_UPSTREAM = 'https://privacytools.io/badge/privacynotes/rating-light.svg';

/** 24 hours - the upstream refresh cadence, so a longer cache buys nothing. */
const BADGE_TTL = 24 * 60 * 60;

// One Worker serves every hostname of the zone. The apex is the marketing
// site (and, during the domain-split transition, still serves the app);
// use.privacynotes.app is the dedicated app host; try.privacynotes.app is
// the demo. The Worker cannot import app code (separate bundle), so these
// mirror src/hosts.ts by hand - keep them in sync.
// Spec: ops/docs/domain-split.md
const APEX_HOST = 'privacynotes.app';
const APP_HOST = 'use.privacynotes.app';
const DEMO_HOST = 'try.privacynotes.app';
const APEX_ORIGIN = 'https://privacynotes.app';

/**
 * CSP as response header so Cloudflare can modify for managed challenges.
 *
 * THIS is the copy browsers enforce for HTML: withSecurityHeaders() below
 * overwrites whatever public/_headers set. Keep the two in sync (burned in
 * v0.257.0: releases.privacynotes.app landed only in _headers, and the
 * homepage version tags were silently CSP-blocked in production).
 *
 * default-src is 'none' (deny by default); every resource type the app
 * uses is enumerated explicitly below. style-src keeps 'unsafe-inline'
 * because the React app and landing page rely on inline style attributes
 * and an inline <style> block (FX_CSS); removing it would require a hash
 * per inline value and is not feasible for a runtime-styled SPA.
 * frame-ancestors 'none' mirrors X-Frame-Options: DENY.
 */
/**
 * Paddle is allowed on ONE page and nowhere else.
 *
 * `/checkout` is the only thing that loads Paddle.js: CheckoutLauncher.tsx is
 * the only importer of the functions that fetch it, and every other Paddle
 * import in the app (`isPaddleConfigured`, `isBetaPricing`, `getStoragePackages`)
 * reads env vars and local data without a network call. So the whole rest of
 * the site - the app on use.privacynotes.app, the marketing pages, /help, and
 * /burn, which renders content written by a stranger - has no business
 * allowlisting a payment CDN, and does not.
 *
 * The allowlist is scoped per host and path rather than site-wide because a
 * site-wide policy could not drop the Paddle hosts without taking /checkout
 * down with them. Scoping removes them everywhere they are not needed and
 * leaves the policy on the apex /checkout unchanged, so it cannot break a
 * purchase. The host half is what keeps a payment CDN out of the origin that
 * stores the phrase envelope.
 *
 * Spec: ops/docs/design-decisions.md (native checkout: desktop opens the system
 * browser), ops/docs/domain-split.md
 */
const cspFor = (paddle: boolean): string =>
  [
    "default-src 'none'",
    `script-src 'self' https://challenges.cloudflare.com${paddle ? ' https://cdn.paddle.com https://sandbox-cdn.paddle.com https://public.profitwell.com' : ''}`,
    `style-src 'self' 'unsafe-inline'${paddle ? ' https://cdn.paddle.com https://sandbox-cdn.paddle.com' : ''}`,
    `connect-src 'self' https://sync.privacynotes.app https://releases.privacynotes.app https://challenges.cloudflare.com${paddle ? ' https://*.paddle.com https://*.profitwell.com' : ''}`,
    `img-src 'self' data: blob: https://sync.privacynotes.app${paddle ? ' https://*.paddle.com' : ''}`,
    `frame-src https://challenges.cloudflare.com${paddle ? ' https://*.paddle.com' : ''}`,
    "font-src 'self' data:",
    "media-src 'self' blob:",
    "worker-src 'self' blob:",
    "manifest-src 'self'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join('; ');

const CSP = cspFor(false);
const CSP_CHECKOUT = cspFor(true);

/** The one path that may load Paddle. */
const CHECKOUT_PATH = '/checkout';

/** Security headers applied to every HTML response. */
const SECURITY_HEADERS: Record<string, string> = {
  'Content-Security-Policy': CSP,
  // HSTS is managed at the Cloudflare edge (SSL/TLS > Edge Certificates >
  // HSTS), so it applies to every response, including non-HTML and redirects.
  // Setting it here as well would emit a duplicate Strict-Transport-Security.
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(self), microphone=(self), geolocation=(), payment=(self "https://buy.paddle.com")',
};

/** Allowed characters for the domain parameter (basic sanitisation). */
const DOMAIN_RE = /^[a-z0-9.-]+$/i;

/**
 * The only types this proxy serves, mapped to the name it serves them under.
 *
 * Echoing the upstream's own header put whatever a stranger's host chose
 * into a response on our origin, and "contains the word image" admits
 * image/svg+xml, which a browser treats as a document that can carry script.
 * Both upstreams answer with ico and png in practice, so an allowlist costs
 * nothing and removes the question. An unlisted type is a miss, not an error:
 * the vault row falls back to its letter tile.
 */
const RASTER_TYPES: Record<string, string> = {
  'image/x-icon': 'image/x-icon',
  'image/vnd.microsoft.icon': 'image/x-icon',
  'image/png': 'image/png',
  'image/jpeg': 'image/jpeg',
  'image/gif': 'image/gif',
  'image/webp': 'image/webp',
};

/** The served type for an upstream content-type header, or null to refuse it. */
function rasterType(contentType: string): string | null {
  return RASTER_TYPES[contentType.split(';')[0]!.trim().toLowerCase()] ?? null;
}

/** Upstream favicon sources. */
const SOURCES = {
  ddg: (d: string) => `https://icons.duckduckgo.com/ip3/${encodeURIComponent(d)}.ico`,
  google: (d: string) => `https://www.google.com/s2/favicons?sz=32&domain=${encodeURIComponent(d)}`,
} as const;

type SourceKey = keyof typeof SOURCES;

/** Simple string hash to deterministically assign a domain to a source. */
function hashDomain(domain: string): number {
  let h = 0;
  for (let i = 0; i < domain.length; i++) {
    h = ((h << 5) - h + domain.charCodeAt(i)) | 0;
  }
  return Math.abs(h);
}

// /faq lived at these paths before the Help rename (2026-07); the static
// pages now emit under /help. Permanent-redirect the old URLs (apex +
// every marketing locale slug, hub + any sub-path) so indexed links and
// bookmarks keep working. Fragments (#entry-id) survive: browsers carry
// the hash across redirects.
// Slug list mirrors LOCALE_TO_SLUG in src/localeRoutes.ts by hand: the Worker
// is a separate bundle and does not import app code. Add new slugs here too.
const FAQ_TO_HELP = /^\/((?:de|fr|it|es|nl|pl|pt|br|ja|ko|tw|ca|cs|tr|sv|ar|en)\/)?faq(\/.*)?$/;

// Every path the client-side app answers for. main.tsx branches on exactly
// /burn and /checkout; App.tsx renders marketing at the apex and at
// each locale slug from src/localeRoutes.ts. Nothing else is a real route,
// so anything not on this list and not backed by a pre-rendered asset is a
// genuine 404.
//
// Why this list exists: with not_found_handling "single-page-application"
// the asset layer answered EVERY unmatched path with a 200 and the app
// shell - /HELP, /sitemap.xml, /help/typo, /de/downloads and any crawler's
// invented URL all returned byte-identical HTML. That is an unbounded
// supply of duplicate pages and soft 404s. wrangler.jsonc now uses
// "404-page"; the SPA fallback is applied here, deliberately, per route.
// Keep in sync with LOCALE_TO_SLUG in src/localeRoutes.ts and the route
// branches in src/main.tsx (the Worker is a separate bundle and cannot
// import app code).
// Split by host: the dedicated app host answers only the app routes;
// the locale slugs are marketing pages and live on the apex (the app
// host 301s them there before this fallback runs).
const APP_ROUTES = new Set(['/', '/burn', '/checkout']);
const LOCALE_SLUGS = new Set([
  '/en',
  '/de',
  '/fr',
  '/it',
  '/es',
  '/nl',
  '/pl',
  '/pt',
  '/br',
  '/ja',
  '/ko',
  '/tw',
  '/ca',
  '/cs',
  '/tr',
  '/sv',
  '/ar',
]);

// Flat SEO landing pages (landing-pages.ts). Mirrors src/landingData/pages
// by hand like LOCALE_SLUGS above: add a slug here when a new feature page
// dataset ships, so the app host 301s it to the apex instead of serving a
// duplicate. /vs/ and /for/ pages are covered by prefix below.
const LANDING_SLUGS = new Set(['/markdown-editor']);
// Locale slugs are deliberately NOT served the SPA shell any more. Each one is
// a real pre-rendered file now (dist/de/index.html and friends, emitted by
// marketing-shell.ts) carrying its own translated head, canonical and hreflang,
// so it has to reach the assets layer instead of being answered with the
// English shell. LOCALE_SLUGS above is still the app host's 301 list.

// The policy pages live on the company site. main.tsx bounces these with
// location.replace() after the bundle boots, which is a JS redirect:
// Googlebot has to render the page to see it, it passes no signal
// reliably, and /privacy sat in GSC as "Crawled - currently not indexed".
// A 301 here costs nothing and is unambiguous. The main.tsx branches stay
// for the desktop build, which never goes through this Worker.
const OFFSITE: Record<string, string> = {
  '/privacy': 'https://lifetimelabs.dev/privacy/',
  '/terms': 'https://lifetimelabs.dev/terms/',
};

// robots.txt is served per-hostname because one Worker serves both the
// apex and the demo subdomain: the apex advertises the sitemap index and
// keeps crawlers away from routes that must never be crawled (/burn
// links are consumed on read - a crawler following a shared link would
// destroy the note; /checkout is a non-content SPA route),
// while every other hostname - the try. demo, the use. app host, and
// any preview host - is blocked entirely (demo and app host also serve
// a noindex meta, this is the belt to those suspenders). Without this
// branch, /robots.txt fell through to the SPA fallback and returned
// HTML.
const ROBOTS_APEX = `User-agent: *
Disallow: /burn
Disallow: /checkout

Sitemap: https://privacynotes.app/sitemap.xml
`;

const ROBOTS_BLOCKED = `User-agent: *
Disallow: /
`;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // ── /favicon?domain=X ────────────────────────────────────────
    if (url.pathname === '/favicon') {
      return handleFavicon(request, url);
    }

    // ── /badge/privacytools.svg ──────────────────────────────────
    if (url.pathname === '/badge/privacytools.svg') {
      return handleBadge(request, url);
    }

    // ── robots.txt (per-hostname: apex vs everything else) ──────
    if (url.pathname === '/robots.txt') {
      const body = url.hostname === APEX_HOST ? ROBOTS_APEX : ROBOTS_BLOCKED;
      return new Response(body, {
        headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'max-age=3600' },
      });
    }

    // ── App host: marketing pages have one home, the apex (301) ──
    // use.privacynotes.app serves only the app routes. Locale slugs,
    // the help center, changelog, roadmap and the sitemaps 301 to the
    // apex so search consolidation is never split across hosts. Assets
    // and app routes fall through to the shared handling below.
    // /help/icons/ is exempt: the Import modal reuses those app icons
    // in-app, and a 301 to the apex gets blocked by the document CSP
    // (img-src has no apex entry), rendering broken images.
    //
    // /checkout goes too, and it is the one app route that does. It is the
    // only page that loads a payment CDN, and this host is the one that
    // stores the phrase envelope, so serving it here would put cdn.paddle.com
    // and public.profitwell.com in script-src beside the phrase. Nothing
    // legitimately opens it here: billing.ts targets the apex from every
    // client, desktop binaries have the apex baked in, and Paddle's own
    // default payment link points there.
    // Spec: ops/docs/domain-split.md
    if (url.hostname === APP_HOST) {
      const p = url.pathname;
      if (
        p === CHECKOUT_PATH ||
        LOCALE_SLUGS.has(p) ||
        p === '/help' ||
        (p.startsWith('/help/') && !p.startsWith('/help/icons/')) ||
        p === '/changelog' ||
        p === '/changelog/feed.xml' ||
        p === '/changelog.md' ||
        p.startsWith('/docs/') ||
        p === '/roadmap' ||
        p === '/brand' ||
        LANDING_SLUGS.has(p) ||
        p.startsWith('/vs/') ||
        p.startsWith('/for/') ||
        p === '/llms.txt' ||
        p === '/llms-full.txt' ||
        p === '/llms-index.txt' ||
        p.startsWith('/sitemap')
      ) {
        return Response.redirect(`${APEX_ORIGIN}${p}${url.search}`, 301);
      }
    }

    // ── /go/<partner>[/<campaign>] and /dl/<platform> ────────────
    // Partner links and download buttons, counted at the edge and
    // redirected. Apex only: a partner path on the app host or the demo
    // host must never count. Both answer 302, never 301 - a permanent
    // redirect invites Google to fold the path into the target and treat
    // it as a real URL, and robots.txt plus X-Robots-Tag keep it out of
    // the index either way.
    // Spec: ops/docs/plans/partner-attribution.md
    // The demo host participates: a partner who routes a reader to the
    // sandbox is invisible otherwise, and the count happens here, before any
    // demo code runs, so the demo still makes zero server calls of its own.
    if (url.hostname === APEX_HOST || url.hostname === DEMO_HOST) {
      const campaign = await handleCampaignRoute(url, request, env);
      if (campaign) return campaign;
    }

    // ── Legacy /faq → /help (301) ────────────────────────────────
    const faqMatch = url.pathname.match(FAQ_TO_HELP);
    if (faqMatch) {
      let target = `/${faqMatch[1] ?? ''}help${faqMatch[2] ?? ''}`;
      // Drop any legacy trailing slash so old /faq/<id>/ links land on the
      // no-slash canonical in one hop instead of two.
      if (target.length > 1 && target.endsWith('/')) target = target.slice(0, -1);
      return Response.redirect(`${url.origin}${target}${url.search}`, 301);
    }

    // ── Strip trailing slash on every other path (301) ──────────
    // This has to run in the Worker, and the Worker has to run first
    // (assets.run_worker_first in wrangler.jsonc). html_handling's own
    // drop-trailing-slash emits a 307, and Google will not fold a
    // temporary redirect into its target: it kept every /help/<id>/ as a
    // separate URL and reported the pair as "Duplicate, Google chose
    // different canonical than user". A 301 consolidates. Root "/" is
    // exempt.
    if (url.pathname.length > 1 && url.pathname.endsWith('/')) {
      const target = url.pathname.slice(0, -1);
      return Response.redirect(`${url.origin}${target}${url.search}`, 301);
    }

    // ── Policy pages moved off-site (301) ───────────────────────
    const offsite = OFFSITE[url.pathname];
    if (offsite) return Response.redirect(offsite, 301);

    // ── Client-side app routes: serve the SPA shell ─────────────
    // Fetched as "/" rather than "/index.html" so html_handling has
    // nothing to rewrite; the assets layer resolves the root to
    // dist/index.html. Status is forced to 200 - these are real pages,
    // they just have no pre-rendered file of their own.
    if (APP_ROUTES.has(url.pathname)) {
      const shell = await env.ASSETS.fetch(new Request(new URL('/', url).toString(), request));
      return withSecurityHeaders(shell, url, 200);
    }

    // ── Referring-site resolution, server-side ──────────────────
    // The browser never sees the host map and never sends a raw referrer
    // anywhere: a reader with the network tab open would otherwise watch
    // their employer's intranet hostname leave their own browser. The Worker
    // already has the Referer header, so it resolves here and injects the
    // result for the page to read on mount.
    // Spec: ops/docs/plans/partner-attribution.md (section 3b)
    if (
      (url.hostname === APEX_HOST || url.hostname === DEMO_HOST) &&
      !url.searchParams.has('ref') &&
      request.headers.get('Referer')
    ) {
      const slug = resolveReferrer(request.headers.get('Referer') ?? '', await loadSources());
      if (slug) {
        const page = APP_ROUTES.has(url.pathname)
          ? await env.ASSETS.fetch(new Request(new URL('/', url).toString(), request))
          : await env.ASSETS.fetch(request);
        return injectSource(withSecurityHeaders(page, url), slug);
      }
    }

    // ── Everything else: a pre-rendered page, a real file, or 404 ──
    // not_found_handling: "404-page" means the assets layer answers an
    // unknown path with dist/404.html and a 404 status, so soft 404s are
    // gone. Nothing here needs to special-case that: the 404 page is HTML
    // and picks up the same headers.
    const response = await env.ASSETS.fetch(request);
    return withSecurityHeaders(response, url);
  },
} satisfies ExportedHandler<Env>;

/**
 * Apply the HTML security headers to an asset response, passing non-HTML
 * (scripts, images, fonts) straight through so the long-lived cache rules
 * in public/_headers are left alone.
 */
function withSecurityHeaders(response: Response, url: URL, status?: number): Response {
  const ct = response.headers.get('content-type') || '';
  if (!ct.includes('text/html')) return response;
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) headers.set(k, v);
  // The one page that may load Paddle, on the one host that serves it.
  // Everything else keeps the policy above, which names no payment host at
  // all. The host half matters as much as the path: the app host redirects
  // this route away, and the demo host must never reach a payment CDN, so
  // neither may widen its own script-src by being asked for /checkout.
  if (url.hostname === APEX_HOST && url.pathname === CHECKOUT_PATH) {
    headers.set('Content-Security-Policy', CSP_CHECKOUT);
  }
  // Prevent edge cache from serving stale HTML without headers.
  headers.set('Cache-Control', 'no-cache');
  return new Response(response.body, { status: status ?? response.status, headers });
}

/** Try one upstream source. Returns null on failure. */
async function trySource(
  source: SourceKey,
  domain: string,
): Promise<{ body: ArrayBuffer; contentType: string } | null> {
  try {
    const res = await fetch(SOURCES[source](domain), {
      headers: { 'User-Agent': 'PrivacyNotes-Favicon-Proxy/1.0' },
    });
    const body = await res.arrayBuffer();
    const contentType = rasterType(res.headers.get('content-type') || '');
    // DDG returns 200 with a tiny 1x1 placeholder for unknown domains.
    // Google returns small PNGs. Reject anything < 100 bytes or not a raster
    // image we are willing to put our own name on.
    if (!res.ok || body.byteLength < 100 || !contentType) {
      return null;
    }
    return { body, contentType };
  } catch {
    return null;
  }
}

async function handleFavicon(request: Request, url: URL): Promise<Response> {
  const domain = url.searchParams.get('domain')?.toLowerCase().trim();

  if (!domain || !DOMAIN_RE.test(domain) || domain.length > 253) {
    return new Response('Bad domain', { status: 400 });
  }

  // Check edge cache first.
  const cache = caches.default;
  const cacheKey = new Request(`${url.origin}/favicon?domain=${domain}&_cv=${CACHE_VERSION}`, request);
  const cached = await cache.match(cacheKey);
  if (cached) return cached;

  // Hash-based source assignment with fallback.
  const primary: SourceKey = hashDomain(domain) % 2 === 0 ? 'ddg' : 'google';
  const secondary: SourceKey = primary === 'ddg' ? 'google' : 'ddg';

  let result = await trySource(primary, domain);
  if (!result) {
    result = await trySource(secondary, domain);
  }

  if (!result) {
    // Neither source had a valid favicon - cache the miss.
    const miss = new Response(null, { status: 404 });
    miss.headers.set('Cache-Control', `public, max-age=${MISS_TTL}`);
    miss.headers.set('Access-Control-Allow-Origin', '*');
    void cache.put(cacheKey, miss.clone());
    return miss;
  }

  // Build a cacheable response.
  const response = new Response(result.body, {
    status: 200,
    headers: {
      'Content-Type': result.contentType,
      'Cache-Control': `public, max-age=${CACHE_TTL}`,
      // Public icons, no credentials - allow any origin so the native apps
      // (tauri://localhost / http://tauri.localhost) can read the response.
      'Access-Control-Allow-Origin': '*',
      // The bytes came from a stranger's host, so the response says what it
      // is and refuses to be anything else. Same pair handleBadge sets on its
      // own SVG: nosniff stops a browser guessing a document out of a raster
      // type, and the policy leaves nothing for one to do if it did.
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'",
    },
  });

  // Store in edge cache (fire-and-forget).
  void cache.put(cacheKey, response.clone());

  return response;
}

/**
 * Serve the PrivacyTools.io rating badge from our own origin.
 *
 * The response carries its own CSP: an SVG is an inert image inside
 * <img>, but a person who opens this URL directly gets a document that
 * can run script in OUR origin. default-src 'none' removes that if the
 * upstream file ever changes hands.
 *
 * If upstream is unreachable, the answer is an opaque 502 and the
 * homepage falls back to the image's alt text.
 */
async function handleBadge(request: Request, url: URL): Promise<Response> {
  const cache = caches.default;
  const cacheKey = new Request(`${url.origin}/badge/privacytools.svg?_cv=${CACHE_VERSION}`, request);
  const cached = await cache.match(cacheKey);
  if (cached) return cached;

  let svg: string;
  try {
    const upstream = await fetch(BADGE_UPSTREAM, {
      headers: { 'User-Agent': 'PrivacyNotes-Badge-Proxy/1.0' },
    });
    const contentType = upstream.headers.get('content-type') || '';
    if (!upstream.ok || !contentType.includes('image/svg')) {
      return new Response('Badge unavailable', { status: 502 });
    }
    svg = await upstream.text();
  } catch {
    return new Response('Badge unavailable', { status: 502 });
  }

  const response = new Response(svg, {
    status: 200,
    headers: {
      'Content-Type': 'image/svg+xml; charset=utf-8',
      'Cache-Control': `public, max-age=${BADGE_TTL}`,
      'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'",
      'X-Content-Type-Options': 'nosniff',
    },
  });

  void cache.put(cacheKey, response.clone());

  return response;
}

/**
 * The attribution allowlist, fetched rather than compiled.
 *
 * It used to be a constant here AND in src/campaignSource.ts, kept in step by
 * a house-rule check. Both copies are gone: the list is managed from the
 * admin panel and `link-pubkey` is the one gate that matters, because it is
 * the only place the word is ever written.
 *
 * Cached for the endpoint's own max-age, so a click spike costs one read and
 * an admin edit goes live within minutes instead of a deploy. Every failure
 * mode resolves to nothing, which loses attribution and never records the
 * wrong one.
 * Spec: ops/docs/plans/partner-attribution.md (section 3b)
 */
const SOURCES_URL = 'https://sync.privacynotes.app/functions/v1/campaign-sources';

interface SourceRow {
  slug: string;
  hosts: string[];
  subdomains: boolean;
}

let sourcesCache: { at: number; rows: SourceRow[] } | null = null;
const SOURCES_TTL_MS = 5 * 60 * 1000;

async function loadSources(): Promise<SourceRow[]> {
  const now = Date.now();
  if (sourcesCache && now - sourcesCache.at < SOURCES_TTL_MS) return sourcesCache.rows;
  try {
    const res = await fetch(SOURCES_URL, { cf: { cacheTtl: 300, cacheEverything: true } });
    if (!res.ok) throw new Error(String(res.status));
    const body = (await res.json()) as { sources?: SourceRow[] };
    const rows = Array.isArray(body.sources) ? body.sources : [];
    sourcesCache = { at: now, rows };
    return rows;
  } catch {
    // Serve a stale list rather than nothing: a placement that worked a
    // minute ago should keep working through a blip.
    return sourcesCache?.rows ?? [];
  }
}

/**
 * Resolve a referring origin to a slug, or null.
 *
 * Base domain covers subdomains, because old.reddit.com and gist.github.com
 * are genuinely the same source. `subdomains: false` turns that off for
 * search engines: mail.google.com is somebody clicking a link in their inbox,
 * not a search result, and folding it into `google` would inflate search and
 * record something more specific than intended.
 *
 * Anything unlisted resolves to NOTHING. There is deliberately no `other`
 * bucket: a raw referrer origin can name a person's employer.
 */
function resolveReferrer(referer: string, rows: SourceRow[]): string | null {
  if (!referer) return null;
  let host: string;
  try {
    host = new URL(referer).hostname.toLowerCase();
  } catch {
    return null;
  }
  if (!host) return null;
  const bare = host.startsWith('www.') ? host.slice(4) : host;
  for (const row of rows) {
    for (const h of row.hosts) {
      const base = h.toLowerCase();
      if (bare === base) return row.slug;
      if (row.subdomains && host.endsWith(`.${base}`)) return row.slug;
    }
  }
  return null;
}

/** Download tiles we count. Anything else 404s rather than redirecting. */
const DOWNLOAD_TARGETS: Record<string, string> = {
  mac: 'https://releases.privacynotes.app/latest/mac',
  windows: 'https://releases.privacynotes.app/latest/windows',
  linux: 'https://releases.privacynotes.app/latest/linux',
  apk: 'https://releases.privacynotes.app/latest/apk',
  play: 'https://play.google.com/store/apps/details?id=app.privacynotes',
  appstore: 'https://apps.apple.com/app/privacynotes/id6749376533',
};

/** Shape only. Membership is decided against the fetched list. */
function normalizeSlug(raw: string | undefined, rows: SourceRow[]): string | null {
  if (!raw) return null;
  const v = raw.trim().toLowerCase();
  if (!v || v.length > 32 || !/^[a-z0-9-]+$/.test(v)) return null;
  const known = (x: string) => rows.some((r) => r.slug === x);
  if (known(v)) return v;
  // A campaign folds into its placement: `reddit-spring26` credits `reddit`.
  // The suffix stays in the aggregate click layer and never reaches an account.
  const base = v.split('-')[0]!;
  return known(base) ? base : null;
}

/**
 * The visitor's marketing locale slug, so a partner click lands on the
 * page the homepage would have shown them. Never the bare apex: that is
 * the smart entry and drops a signed-in reader into the app instead of
 * the pitch.
 * Spec: ops/docs/domain-split.md
 */
function localeSlugFor(request: Request): string {
  const header = request.headers.get('Accept-Language') ?? '';
  const first = header.split(',')[0]?.trim().toLowerCase() ?? '';
  if (!first) return '/en';
  if (LOCALE_SLUGS.has(`/${first}`)) return `/${first}`;
  const two = first.split('-')[0] ?? '';
  return LOCALE_SLUGS.has(`/${two}`) ? `/${two}` : '/en';
}

/**
 * Count one aggregate data point and 302, or return null when the path is
 * not ours. Never throws into the request path: a counting failure must
 * not cost a visitor their click.
 */
async function handleCampaignRoute(
  url: URL,
  request: Request,
  env: Env,
): Promise<Response | null> {
  const parts = url.pathname.split('/').filter(Boolean);
  if (parts.length === 0) return null;
  const kind = parts[0];
  if (kind !== 'go' && kind !== 'dl') return null;

  const country = (request as { cf?: { country?: string } }).cf?.country ?? 'XX';
  // Cloudflare's own verified-bot flag where the plan exposes it. Bot traffic
  // on directory links is heavy and constant, so the click number is
  // directional only and a partner is never paid on our count.
  const bot = (request as { cf?: { botManagement?: { verifiedBot?: boolean } } }).cf
    ?.botManagement?.verifiedBot
    ? 1
    : 0;

  let target: string;
  let blobs: string[];

  // A path under /go or /dl ALWAYS redirects, even when nothing resolves.
  // These links are printed in articles, ad units and video descriptions,
  // where a typo cannot be corrected after the fact: `/go/itsfos` must still
  // land the reader somewhere useful. An unresolved link is simply not
  // counted and carries no ref, so a typo costs attribution and never costs
  // a visitor. The destination is always our own origin, so this is not an
  // open redirect.
  const home =
    url.hostname === DEMO_HOST
      ? `https://${DEMO_HOST}/`
      : `${APEX_ORIGIN}${localeSlugFor(request)}`;

  if (kind === 'dl') {
    const platform = parts[1] ?? '';
    const dest = DOWNLOAD_TARGETS[platform];
    if (!dest) return Response.redirect(home, 302);
    target = dest;
    blobs = ['dl', platform, '', country];
  } else {
    const slug = normalizeSlug(parts[1], await loadSources());
    if (!slug) {
      return new Response(null, {
        status: 302,
        headers: {
          Location: home,
          'X-Robots-Tag': 'noindex, nofollow',
          'Cache-Control': 'no-store',
        },
      });
    }
    const campaign = normalizeCampaign(parts[2]);
    // A /go link on the demo host lands on the demo, not the homepage: the
    // partner chose the sandbox as the destination and the redirect must not
    // second-guess that.
    const sep = home.includes('?') ? '&' : '?';
    target = `${home}${sep}ref=${encodeURIComponent(slug)}`;
    blobs = ['go', slug, campaign, country];
  }

  try {
    env.CAMPAIGNS?.writeDataPoint({
      // One index only, and it is the dimension every query groups by.
      indexes: [blobs[1]!],
      blobs,
      doubles: [bot],
    });
  } catch {
    /* counting is best-effort; the redirect is not */
  }

  return new Response(null, {
    status: 302,
    headers: {
      Location: target,
      'X-Robots-Tag': 'noindex, nofollow',
      'Cache-Control': 'no-store',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
    },
  });
}

/** Campaign suffix for the aggregate layer only. Never reaches an account. */
function normalizeCampaign(raw: string | undefined): string {
  if (!raw) return '';
  const v = raw.trim().toLowerCase();
  return /^[a-z0-9-]{1,32}$/.test(v) ? v : '';
}

/**
 * Put the resolved source into the page as a meta tag.
 *
 * THE CACHE TRAP, and the reason for the no-store header. These pages are
 * static and cacheable. Writing a per-visitor value into a cacheable response
 * is cache poisoning: the next reader would arrive credited to the previous
 * reader's partner. So a response that carries an injected value is marked
 * uncacheable, and injection only happens when a referrer actually resolved -
 * which is a minority of visits, so the common path keeps its cache.
 */
function injectSource(response: Response, slug: string): Response {
  const ct = response.headers.get('content-type') ?? '';
  if (!ct.includes('text/html')) return response;
  const out = new HTMLRewriter()
    .on('head', {
      element(el) {
        el.append(`<meta name="pn-src" content="${slug}">`, { html: true });
      },
    })
    .transform(response);
  const headers = new Headers(out.headers);
  headers.set('Cache-Control', 'no-store');
  return new Response(out.body, { status: out.status, headers });
}
