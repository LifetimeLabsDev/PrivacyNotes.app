import { useSyncExternalStore } from 'react';
import type { PushHalt } from './sync';

/**
 * Device-local log of the last sync passes, for the sync panel: the
 * "last sync N min ago" line, the pass bars, and the activity list.
 *
 * Written by useSyncOrchestrator around each real pass (demo, floor,
 * pause and mutex skips never log - they are non-events). Persisted so
 * the panel can answer "when did this device last sync" across a
 * restart. Counts are taken from SyncResult: `up` is the rows the server
 * accepted, `down` is rows plus tombstones the pull applied, `failed` is
 * the notes the pass could not push, each with its own reason, and
 * `halted` is a push that stopped before it reached every dirty row.
 */

export type SyncPassEntry = {
  /** Pass start, ms epoch. */
  at: number;
  /** Wall time of the pass in ms. */
  ms: number;
  /** False when the pull failed or the pass threw. */
  ok: boolean;
  /** Rows the server accepted. */
  up: number;
  down: number;
  /** Coalesced "nothing to do" streak length (see recordSyncPass). */
  n?: number;
  /** Notes this pass could not push, each with a reason of its own: the
   *  notes the "Not backed up" list names. A pass that failed every push
   *  reads as "3 failed", never as "No changes". */
  failed?: number;
  /** The push stopped before it reached every dirty row, and how many it
   *  left behind. Such a pass reads as stopped, never as "No changes". */
  halted?: PushHalt;
};

const STORAGE_KEY = 'privacynotes.syncLog';
const MAX_ENTRIES = 12;

function readStored(): SyncPassEntry[] {
  try {
    if (typeof localStorage === 'undefined') return [];
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (e): e is SyncPassEntry =>
        typeof e === 'object' && e !== null &&
        typeof (e as SyncPassEntry).at === 'number' &&
        typeof (e as SyncPassEntry).ok === 'boolean',
    ).slice(-MAX_ENTRIES);
  } catch {
    return [];
  }
}

let entries: SyncPassEntry[] = readStored();
const listeners = new Set<() => void>();

export function recordSyncPass(entry: SyncPassEntry): void {
  // Coalesce idle polling: a clean pass that moved nothing lands on top
  // of a previous one as a refreshed timestamp with a streak counter,
  // instead of filling the log with one "nothing to do" row per 30s
  // tick. The list then only grows when something actually happened.
  const last = entries[entries.length - 1];
  const isNoop = (e: SyncPassEntry) => e.ok && e.up === 0 && e.down === 0 && !(e.failed && e.failed > 0) && !e.halted;
  if (last && isNoop(entry) && isNoop(last)) {
    entries = [...entries.slice(0, -1), { ...entry, n: (last.n ?? 1) + 1 }];
  } else {
    entries = [...entries, entry].slice(-MAX_ENTRIES);
  }
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(entries));
  } catch {
    // Storage blocked - the in-memory log still serves this session.
  }
  for (const cb of listeners) cb();
}

function getSyncLog(): SyncPassEntry[] {
  return entries;
}

/** Start time of the most recent pass whose pull succeeded, or null. */
export function lastOkSyncAt(): number | null {
  for (let i = entries.length - 1; i >= 0; i--) {
    const e = entries[i];
    if (e && e.ok) return e.at;
  }
  return null;
}

function subscribe(cb: () => void) {
  listeners.add(cb);
  return () => {
    listeners.delete(cb);
  };
}

const EMPTY: SyncPassEntry[] = [];

/** Reactive log for the sync panel. */
export function useSyncLog(): SyncPassEntry[] {
  return useSyncExternalStore(subscribe, getSyncLog, () => EMPTY);
}
