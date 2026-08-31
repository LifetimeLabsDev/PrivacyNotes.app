import { useSyncExternalStore } from 'react';
import { isBelowVersionFloor } from './versionFloor';

/**
 * User-controlled sync pause, per device.
 *
 * Same enforcement seam as the release floor (versionFloor.ts): every
 * server write asks `isServerWriteBlocked()` before touching the network,
 * so a paused device keeps working locally and stops talking to the
 * server. Unlike the floor, this is a deliberate user choice, stored
 * device-local (a "do not talk to the server" flag cannot itself travel
 * through the server) and it NEVER clears itself - a silent auto-resume
 * would break the promise the switch makes. The SyncStatus pill carries
 * the paused state for the whole pause.
 *
 * The heartbeat is deliberately NOT gated, same as the floor: it carries
 * no note data and it is the only channel through which a revoked device
 * learns it was revoked.
 */

const STORAGE_KEY = 'privacynotes.syncPaused';

function readStored(): boolean {
  try {
    if (typeof localStorage === 'undefined') return false;
    return localStorage.getItem(STORAGE_KEY) === '1';
  } catch {
    // Unreadable storage: fail open, sync runs.
    return false;
  }
}

let paused = readStored();
const listeners = new Set<() => void>();

function isSyncPaused(): boolean {
  return paused;
}

export function setSyncPaused(next: boolean): void {
  if (paused === next) return;
  paused = next;
  try {
    if (next) localStorage.setItem(STORAGE_KEY, '1');
    else localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Storage blocked - the in-memory flag still holds for this session.
  }
  for (const cb of listeners) cb();
}

/**
 * The one question every server-write path asks. Composes the release
 * floor and the user pause so a new blocked-state never needs another
 * sweep over the twelve call sites.
 */
export function isServerWriteBlocked(): boolean {
  return isBelowVersionFloor() || isSyncPaused();
}

function subscribe(cb: () => void) {
  listeners.add(cb);
  return () => {
    listeners.delete(cb);
  };
}

/** Reactive isSyncPaused() for the pill and the sync panel. */
export function useSyncPaused(): boolean {
  return useSyncExternalStore(subscribe, isSyncPaused, () => false);
}
