import { useSyncExternalStore } from 'react';

/**
 * Module-level "a sync pass is running" flag.
 *
 * This was NotesView-level React state, which meant the setSyncing(true)
 * + setSyncing(false) pair around every 30 s poll tick re-rendered the
 * entire authenticated tree twice - ~350 ms of main-thread work per idle
 * tick at a few thousand notes (backlog #141). As an external store only
 * the components that display the flag subscribe (the SyncStatus pill,
 * the ID & Sync status rows), so a status flip renders those and nothing
 * else.
 */
let syncing = false;
const listeners = new Set<() => void>();

/** Flip the flag. Only the orchestrator's sync pass should call this. */
export function setSyncingFlag(next: boolean): void {
  if (next === syncing) return;
  syncing = next;
  for (const cb of listeners) cb();
}

function subscribe(cb: () => void) {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

function getSnapshot() {
  return syncing;
}

/** Reactive boolean - `true` while a sync pass is in flight. */
export function useSyncing(): boolean {
  return useSyncExternalStore(subscribe, getSnapshot);
}
