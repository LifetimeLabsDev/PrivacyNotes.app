/**
 * Client-side favicon fetch queue with IndexedDB persistence.
 *
 * Two layers:
 * 1. Concurrency queue - caps outbound requests at 5 so mass-import
 *    vaults (2000+ logins) don't hammer the Worker.
 * 2. IndexedDB cache - stores favicon blobs locally with a 90-day TTL.
 *    Eliminates network requests for repeat loads and works offline.
 *
 * Flow: check in-memory map → check IndexedDB → fetch through queue →
 * store in IndexedDB → return blob URL.
 *
 * Spec: ops/docs/backlog.md (#69 - favicon concurrency cap + IDB cache)
 */

import { isDemoMode } from './demo';

// ── Concurrency queue ────────────────────────────────────────────

// Spec: ops/docs/backlog.md (#69 - client concurrency cap of 5)
const MAX_CONCURRENT = 5;

let active = 0;
const waiting: Array<() => void> = [];

function drain() {
  while (active < MAX_CONCURRENT && waiting.length > 0) {
    active++;
    waiting.shift()!();
  }
}

// ── IndexedDB cache ──────────────────────────────────────────────

const DB_NAME = 'pn-favicons';
const STORE_NAME = 'icons';
const DB_VERSION = 1;
const MAX_AGE_MS = 90 * 24 * 60 * 60 * 1000; // 90 days

interface CachedFavicon {
  blob: Blob;
  storedAt: number;
}

let dbPromise: Promise<IDBDatabase> | null = null;

function openDB(): Promise<IDBDatabase> {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(STORE_NAME)) {
        req.result.createObjectStore(STORE_NAME);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => {
      dbPromise = null;
      reject(req.error);
    };
  });
  return dbPromise;
}

async function getFromIDB(url: string): Promise<Blob | null> {
  try {
    const db = await openDB();
    return new Promise(resolve => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const req = tx.objectStore(STORE_NAME).get(url);
      req.onsuccess = () => {
        const entry = req.result as CachedFavicon | undefined;
        if (!entry) { resolve(null); return; }
        if (Date.now() - entry.storedAt > MAX_AGE_MS) {
          void deleteFromIDB(url);
          resolve(null);
          return;
        }
        resolve(entry.blob);
      };
      req.onerror = () => resolve(null);
    });
  } catch {
    return null;
  }
}

async function putInIDB(url: string, blob: Blob): Promise<void> {
  try {
    const db = await openDB();
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).put(
      { blob, storedAt: Date.now() } satisfies CachedFavicon,
      url,
    );
  } catch {
    // QuotaExceededError or other IDB failure - continue without caching.
  }
}

async function deleteFromIDB(url: string): Promise<void> {
  try {
    const db = await openDB();
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).delete(url);
  } catch {
    // Ignore.
  }
}

// ── Public API ───────────────────────────────────────────────────

/** In-memory map: original URL → blob URL (lives for the session). */
const blobUrls = new Map<string, string>();

/**
 * Domains the proxy answered for, but with no icon. Kept for the session so
 * a note full of icon-less links costs one request each, not one per render.
 * Only set when the server actually said so - a network error or an offline
 * tab leaves the URL unknown, because the icon may well exist.
 */
const misses = new Set<string>();

/** Requests in flight, so concurrent callers for one URL fetch once. */
const inFlight = new Set<string>();

/**
 * Wipe the favicon cache, in memory and on disk.
 *
 * The favicon cache is a SEPARATE IndexedDB (`pn-favicons`), outside the
 * Dexie database, so neither `clearLocalDatabase` nor `db.delete()` reaches
 * it. Left alone it kept a per-domain record derived from a user's links and
 * vault logins for 90 days after sign-out or account deletion, which made
 * THREAT_MODEL.md's "sign-out clears the local database" untrue and let the
 * next account on a shared machine inherit the previous one's domains.
 * Callers: clearLocalDatabase and deleteEntireLocalDatabase. Added 2026-08-28.
 */
export async function clearFaviconCache(): Promise<void> {
  // Session memory first, so a re-render right after cannot resurrect an
  // icon from the old account and cannot leak a blob URL.
  for (const blobUrl of blobUrls.values()) {
    try { URL.revokeObjectURL(blobUrl); } catch { /* already revoked */ }
  }
  blobUrls.clear();
  misses.clear();

  // Then the on-disk store. Close our handle first, or the delete blocks
  // behind the open connection and silently never completes.
  if (dbPromise) {
    try { (await dbPromise).close(); } catch { /* opening failed; nothing to close */ }
    dbPromise = null;
  }
  await new Promise<void>((resolve) => {
    try {
      const req = indexedDB.deleteDatabase(DB_NAME);
      req.onsuccess = () => resolve();
      req.onerror = () => resolve();
      req.onblocked = () => resolve();
    } catch {
      resolve();
    }
  });
}

/**
 * Fetch a favicon through the concurrency queue + IDB cache.
 *
 * Returns a blob URL on success (usable as `<img src>`), or `null`
 * on failure / offline-with-no-cache.
 */
export async function prefetchFavicon(url: string): Promise<string | null> {
  // The demo sends nothing, so it has no icons: whatever URL a caller built,
  // nothing is fetched and nothing cached is read.
  if (isDemoMode()) return null;

  // 1. Already resolved this session - return immediately.
  const existing = blobUrls.get(url);
  if (existing) return existing;
  if (misses.has(url)) return null;

  // 2. Check IndexedDB (no network slot needed).
  const cached = await getFromIDB(url);
  if (cached) {
    const blobUrl = URL.createObjectURL(cached);
    blobUrls.set(url, blobUrl);
    return blobUrl;
  }

  // 3. Skip network if offline.
  if (!navigator.onLine) return null;

  // 4. Wait for a concurrency slot.
  if (active >= MAX_CONCURRENT) {
    await new Promise<void>(resolve => waiting.push(resolve));
  } else {
    active++;
  }

  try {
    const res = await fetch(url);
    if (!res.ok) { misses.add(url); return null; }
    const blob = await res.blob();
    if (blob.size < 100) { misses.add(url); return null; }

    // Store in IDB for future sessions (fire-and-forget).
    void putInIDB(url, blob);

    const blobUrl = URL.createObjectURL(blob);
    blobUrls.set(url, blobUrl);
    return blobUrl;
  } catch {
    return null;
  } finally {
    active--;
    drain();
  }
}

/**
 * Synchronous read of a favicon that is already in hand, starting the fetch
 * if it is not. Returns the blob URL when the icon is known to exist, and
 * `undefined` in every other case - not yet fetched, no icon, offline.
 *
 * Callers that paint the icon into a live DOM (the editor's decoration
 * plugin) need exactly this shape: something to render NOW, and a callback
 * for the one moment the answer changes. `onResolved` fires only when an
 * icon actually arrives, so a miss never triggers a repaint.
 */
export function ensureFavicon(url: string, onResolved: () => void): string | undefined {
  const existing = blobUrls.get(url);
  if (existing) return existing;
  if (misses.has(url) || inFlight.has(url)) return undefined;

  inFlight.add(url);
  void prefetchFavicon(url).then((blobUrl) => {
    inFlight.delete(url);
    if (blobUrl) onResolved();
  });
  return undefined;
}
