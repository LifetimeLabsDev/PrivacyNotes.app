/**
 * Last-known device, quota and storage-sub figures for the settings
 * panels, so they paint instantly instead of showing an empty pane until
 * the first read batch lands.
 *
 * WHY. The Plan / Storage / ID & Sync panels each render nothing until
 * `quota` is non-null, which costs a full server round-trip on every
 * open - fine on a warm connection, several seconds on a cold or flaky
 * one, and the whole pane is blank for the duration. The figures shown
 * are near-static (a device list, a byte count), so a stale-then-fresh
 * paint is strictly better than a blank one: the panel is readable
 * immediately, and the live read swaps in underneath a beat later.
 *
 * WHAT IS SAFE TO CACHE. Display figures only, and only ones whose
 * staleness is visible and harmless. Nothing here is an authorization
 * decision: `isPro` still comes from auth state, every server-enforced
 * limit is still enforced server-side, and a cached byte count that
 * disagrees with the server is corrected within the same second.
 *
 * SCOPE. Keyed by pubkey, so switching accounts never shows the previous
 * account's figures, and dropped entirely in demo mode (which promises
 * zero server calls and therefore has nothing real to cache). The
 * localStorage half survives a reload; the in-memory half makes repeat
 * opens in one session instant even if storage is unavailable.
 *
 * Spec: ops/docs/ui-patterns.md (settings panels paint from cache first)
 */

import { isDemoMode } from './demo';
import type { DeviceRow, QuotaUsage, StorageSubRow } from './devices';

/** Shape written to storage. Versioned so a field change cannot resurrect
 *  a mismatched payload from an older build. */
type CachedPanel = {
  v: 1;
  pubkey: string;
  devices: DeviceRow[];
  quota: QuotaUsage;
  storageSubs: StorageSubRow[];
};

const LOCAL_KEY = 'privacynotes.panelcache';

/** Mirrors the stored value so repeat opens in one session skip the
 *  parse, and still work when localStorage throws (private windows). */
let memory: CachedPanel | null = null;

/**
 * Cached figures for this pubkey, or null when there is nothing usable.
 * Callers treat null as "render the loading state as before" - this is a
 * paint accelerator, never a source of truth.
 */
export function readPanelCache(pubkey: string): Omit<CachedPanel, 'v' | 'pubkey'> | null {
  if (isDemoMode()) return null;
  if (memory?.pubkey === pubkey) return memory;
  try {
    const raw = localStorage.getItem(LOCAL_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as CachedPanel;
    // A payload for another account, an older shape, or a truncated write
    // is discarded rather than repaired: the live read is moments away.
    if (parsed?.v !== 1 || parsed.pubkey !== pubkey || !parsed.quota) return null;
    memory = parsed;
    return parsed;
  } catch {
    return null;
  }
}

/** Record the figures a completed read batch produced. Best-effort. */
export function writePanelCache(
  pubkey: string,
  value: Omit<CachedPanel, 'v' | 'pubkey'>,
): void {
  if (isDemoMode()) return;
  const payload: CachedPanel = { v: 1, pubkey, ...value };
  memory = payload;
  try {
    localStorage.setItem(LOCAL_KEY, JSON.stringify(payload));
  } catch {
    // Quota or a private window - the in-memory copy still serves this
    // session, and the panel falls back to its loading state next boot.
  }
}

/**
 * Drop the cache. Called on sign-out and account deletion so the next
 * account never sees the previous one's figures even for one frame.
 */
export function clearPanelCache(): void {
  memory = null;
  try {
    localStorage.removeItem(LOCAL_KEY);
  } catch {
    /* nothing to do - the in-memory copy is already gone */
  }
}
