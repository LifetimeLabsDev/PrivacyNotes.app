import { useSyncExternalStore } from 'react';

const KEY = 'privacynotes.singleKeys';
const listeners = new Set<() => void>();

/**
 * Whether the shortcuts of one plain key (J, K, Q, / and ?, and the
 * Calendar's T, D, W, M and N) run. On by default.
 * A switch can turn them off, because a key with no modifier fires on a
 * stray press and a speech or switch user may send letters on purpose
 * (WCAG 2.2, 2.1.4 Character Key Shortcuts). Device-local, like the
 * keyboard it is about.
 *
 * Spec: ops/docs/plans/keyboard-shortcuts.md (decision D7)
 */
export function singleKeysOn(): boolean {
  try {
    return localStorage.getItem(KEY) !== '0';
  } catch {
    return true;
  }
}

export function setSingleKeys(on: boolean): void {
  try {
    if (on) localStorage.removeItem(KEY);
    else localStorage.setItem(KEY, '0');
  } catch {
    // Storage refused (a private window): the switch holds for this page only.
  }
  listeners.forEach((l) => l());
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function useSingleKeys(): boolean {
  return useSyncExternalStore(subscribe, singleKeysOn, () => true);
}
