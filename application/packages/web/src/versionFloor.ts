import { useSyncExternalStore } from 'react';
import { compareSemver } from './versionCheck';
import { VERSION } from './version';

/**
 * "This build is below the release floor" as app-wide state.
 *
 * The floor (`minVersion` in packages/desktop/update-policy.json, published
 * per platform) used to drive presentation only: it decided whether the
 * update toast had a dismiss button. Since the sync-pause work it is also an
 * enforcement input: a below-floor client keeps working locally but stops
 * writing to the server (sync, settings, note versions, blob uploads and
 * deletes, blob GC), because the floor is only ever raised for a sync/auth
 * protocol change, a client security fix, or a data-corruption fix - exactly
 * the cases where an old client's writes can damage server data that newer
 * devices then pull.
 *
 * Who reports: whichever updater already fetches the floor for this channel
 * (AndroidUpdateToast for the direct APK, DesktopUpdater for the Linux .deb,
 * StoreUpdateToast for Play/iOS). Web and the self-updating desktops never
 * report, so they can never pause.
 *
 * Persistence: the last reported floor is kept in localStorage so the pause
 * holds from t=0 on the next launch instead of racing the manifest fetch.
 * The comparison always runs against the CURRENT bundled VERSION, so
 * installing the update un-pauses immediately with no cleanup step. No
 * report and unreadable storage mean "not below"; an unreadable policy after
 * a floor is known keeps that floor.
 *
 * Spec: ops/docs/android-update-check.md (sync pause below the floor)
 */

const STORAGE_KEY = 'privacynotes.versionFloor';

function readStored(): string | null {
  try {
    if (typeof localStorage === 'undefined') return null;
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as { minVersion?: unknown };
    return typeof parsed?.minVersion === 'string' ? parsed.minVersion : null;
  } catch {
    // Unreadable storage: fail open, treat as no floor.
    return null;
  }
}

let floor: string | null = readStored();
const listeners = new Set<() => void>();

/**
 * Record the floor this channel's manifest reported (null when a manifest
 * that was read carries none). Persisted so the next launch enforces it
 * before any network round trip. A policy that cannot be read, a 404
 * included, is no report at all: callers keep the floor they hold, and a
 * floor is lowered only by publishing a lower one.
 */
export function reportVersionFloor(minVersion: string | null): void {
  if (floor === minVersion) return;
  floor = minVersion;
  try {
    if (minVersion === null) localStorage.removeItem(STORAGE_KEY);
    else localStorage.setItem(STORAGE_KEY, JSON.stringify({ minVersion }));
  } catch {
    // Storage blocked - the in-memory flag still holds for this session.
  }
  for (const cb of listeners) cb();
}

/** The last reported floor, or null when none is known. */
export function knownVersionFloor(): string | null {
  return floor;
}

/** True when the running build is below the last reported floor. */
export function isBelowVersionFloor(): boolean {
  return floor !== null && compareSemver(VERSION, floor) < 0;
}

function subscribe(cb: () => void) {
  listeners.add(cb);
  return () => {
    listeners.delete(cb);
  };
}

/** Reactive isBelowVersionFloor() for the SyncStatus pill and store toast. */
export function useBelowVersionFloor(): boolean {
  return useSyncExternalStore(subscribe, isBelowVersionFloor, () => false);
}

// Dev-only console hook: no channel reports a floor in a browser, so this is
// the only way to exercise the pause against `pnpm dev`. Persists exactly like
// a real report - clear with __pnVersionFloor(null) when done. Folded out of
// every shipped build by import.meta.env.DEV.
if (import.meta.env.DEV && typeof window !== 'undefined') {
  (window as unknown as Record<string, unknown>).__pnVersionFloor = (
    minVersion: string | null,
  ) => reportVersionFloor(minVersion);
}
