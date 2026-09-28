import { createContext, useCallback, useSyncExternalStore } from 'react';
import { isDemoMode } from './demo';

/**
 * The List / Grid / Auto layout choice, stored on this device only.
 *
 * A phone and a desktop want different layouts: two columns of tiles on a
 * phone, a list beside the editor on a desktop. So a pick is written here
 * and never to the synced settings. The synced `viewMode` in `userSettings.ts`
 * is read only as the start value for a device that has never picked, so a
 * new device still opens on the layout the account last used.
 *
 * The demo gets its own key: `?demo=1` runs on the same origin as a real
 * install, and a demo visitor's pick must not change the real install.
 */
export type ViewMode = 'auto' | 'list' | 'grid';

function storageKey(): string {
  return isDemoMode() ? 'privacynotes.demo.viewMode' : 'privacynotes.viewMode';
}

function readStored(): ViewMode | null {
  try {
    const v = localStorage.getItem(storageKey());
    return v === 'auto' || v === 'list' || v === 'grid' ? v : null;
  } catch {
    return null;
  }
}

let current: ViewMode | null = readStored();
const listeners = new Set<() => void>();

function subscribe(cb: () => void): () => void {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

function setDeviceViewMode(next: ViewMode): void {
  if (current === next) return;
  current = next;
  try {
    localStorage.setItem(storageKey(), next);
  } catch {
    // Storage blocked - the pick still holds for this session.
  }
  for (const cb of listeners) cb();
}

/** This device's layout, falling back to the synced account value. */
export function useViewMode(synced: ViewMode): [ViewMode, (next: ViewMode) => void] {
  const local = useSyncExternalStore(subscribe, () => current, () => null);
  const set = useCallback((next: ViewMode) => setDeviceViewMode(next), []);
  return [local ?? synced, set];
}

/**
 * The device choice and its setter, provided once by NotesView so the list
 * preferences menu of every pane can show the Layout switch without each list
 * threading it through. Null outside NotesView, where the menu hides it.
 */
export const ViewModeContext = createContext<{ mode: ViewMode; set: (next: ViewMode) => void } | null>(null);
