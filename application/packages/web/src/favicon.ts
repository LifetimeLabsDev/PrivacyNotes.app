/**
 * Favicon utilities for vault items.
 *
 * Proxied through our own Cloudflare Worker at /favicon?domain=X so the
 * user's browser never contacts a third party. The Worker fetches from
 * DuckDuckGo or Google (hash-based per-domain, with fallback) and
 * caches at the edge for 90 days.
 *
 * Client-side concurrency is throttled by faviconQueue.ts (max 5
 * concurrent fetches, offline guard). See backlog #69.
 */

import { detectPlatform } from './devices';

/**
 * On the web the app is served by the same Worker that answers /favicon, so
 * a root-relative path resolves straight to the proxy. Native builds (Tauri
 * desktop + mobile) are served from tauri://localhost with no Worker, so a
 * relative /favicon 404s - they must call the hosted proxy by absolute URL.
 */
// Spec: ops/docs/gotchas.md (native builds have no local /favicon Worker; use the hosted proxy)
const PROXY_ORIGIN = 'https://privacynotes.app';

/**
 * True for hosts that can never have a public favicon: loopback, private
 * LAN ranges, link-local, and the private-use DNS suffixes. Both upstream
 * sources answer these with a 404, so a link to a dev server or a router
 * page only ever produces a failed request in the console.
 */
function isPrivateHost(host: string): boolean {
  // `URL.hostname` drops the port, but domainFromUrlString's catch path
  // does not - so `localhost:5173` and `[::1]:5173` can both land here.
  const d = host.replace(/^\[(.+)\](?::\d+)?$/, '$1').replace(/^([^:]+):\d+$/, '$1');

  if (d === 'localhost' || /\.(localhost|local|internal|home\.arpa)$/.test(d)) return true;

  // IPv6: loopback, unique-local (fc00::/7), link-local (fe80::/10).
  if (d.includes(':')) return d === '::1' || /^f[cde]/.test(d);

  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(d);
  if (!v4) return false;
  const a = Number(v4[1]);
  const b = Number(v4[2]);
  return a === 0 || a === 10 || a === 127
    || (a === 169 && b === 254)
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 168);
}

/**
 * Return a favicon URL for the given domain (proxied through our Worker),
 * or '' when there is no point asking. Callers must treat '' as "no icon"
 * and fall back to their placeholder.
 */
export function faviconUrl(domain: string): string {
  const d = domain.replace(/^www\./, '').toLowerCase().trim();
  if (!d || isPrivateHost(d)) return '';
  const base = detectPlatform() === 'web' ? '' : PROXY_ORIGIN;
  return `${base}/favicon?domain=${encodeURIComponent(d)}`;
}

/** Extract domain from a URL string (same logic as LoginForm.domainFromUrl). */
export function domainFromUrlString(raw: string): string {
  let s = raw.trim();
  if (!s) return '';
  if (!/^https?:\/\//i.test(s)) s = 'https://' + s;
  try {
    return new URL(s).hostname.replace(/^www\./, '');
  } catch {
    return raw.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').replace(/^www\./, '');
  }
}
