/**
 * Polls /version.json on the server and detects when a newer build has
 * been deployed than the one currently running in the browser. Lets us
 * surface a "refresh to update" banner instead of leaving stale clients
 * running indefinitely (which is how beta testers end up reporting
 * "the app crashed" when really it's just months out of date).
 *
 * Skipped in Tauri builds - desktop apps bundle their own version and
 * shouldn't compare against the web deployment.
 */

import { VERSION } from './version';
import { isDemoMode } from './demo';

const VERSION_URL = '/version.json';
const POLL_INTERVAL_MS = 10 * 60 * 1000; // 10 minutes
const INITIAL_DELAY_MS = 30 * 1000; // 30s grace after mount

type VersionInfo = { version: string };

/**
 * Compare two dotted numeric version strings.
 * Returns 1 if a > b, -1 if a < b, 0 if equal.
 * Pads missing parts with 0 so "1.2" == "1.2.0".
 */
export function compareSemver(a: string, b: string): number {
  const pa = a.split('.').map((n) => Number.parseInt(n, 10));
  const pb = b.split('.').map((n) => Number.parseInt(n, 10));
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const da = Number.isFinite(pa[i]) ? (pa[i] as number) : 0;
    const db = Number.isFinite(pb[i]) ? (pb[i] as number) : 0;
    if (da > db) return 1;
    if (da < db) return -1;
  }
  return 0;
}

async function fetchServerVersion(): Promise<string | null> {
  try {
    // Cache-bust both the browser cache and Cloudflare's edge cache -
    // /version.json is a tiny JSON blob, refetching it is fine.
    const res = await fetch(`${VERSION_URL}?t=${Date.now()}`, {
      cache: 'no-store',
      headers: { 'cache-control': 'no-cache' },
    });
    if (!res.ok) return null;
    const data = (await res.json()) as VersionInfo;
    return typeof data?.version === 'string' ? data.version : null;
  } catch {
    return null;
  }
}

/**
 * Start polling the server for newer versions. Calls `onNewer` with the
 * server version string whenever a newer build is detected. Returns a
 * cleanup function that stops polling and removes listeners.
 *
 * The demo polls nothing. It promises its visitor that nothing leaves the
 * browser, and a stale demo tab risks nothing, because it syncs nothing.
 */
export function startVersionPolling(onNewer: (serverVersion: string) => void): () => void {
  if (isDemoMode()) return () => {};
  let cancelled = false;
  let pollTimer: ReturnType<typeof setTimeout> | null = null;

  async function check(): Promise<void> {
    if (cancelled) return;
    const server = await fetchServerVersion();
    if (cancelled || !server) return;
    if (compareSemver(server, VERSION) > 0) {
      onNewer(server);
    }
  }

  function schedule(): void {
    if (cancelled) return;
    pollTimer = setTimeout(async () => {
      await check();
      schedule();
    }, POLL_INTERVAL_MS);
  }

  const initialTimer = setTimeout(() => {
    void check();
    schedule();
  }, INITIAL_DELAY_MS);

  function onVisibility(): void {
    if (document.visibilityState === 'visible') {
      void check();
    }
  }
  document.addEventListener('visibilitychange', onVisibility);

  return () => {
    cancelled = true;
    clearTimeout(initialTimer);
    if (pollTimer) clearTimeout(pollTimer);
    document.removeEventListener('visibilitychange', onVisibility);
  };
}
