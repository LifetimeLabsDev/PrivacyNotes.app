import { useSyncExternalStore } from 'react';

/**
 * Whether the daily check-in card heads Journals and All on this device. On
 * by default and device-local, like the calendar card's switch under it in
 * the list options (Show daily check-in, Show calendar). The key holds '0'
 * while it is off.
 * Spec: ops/issues/0439.md (Spec)
 */
const KEY = 'privacynotes.checkInCardShown';
const listeners = new Set<() => void>();

function read(): boolean {
  try {
    return localStorage.getItem(KEY) !== '0';
  } catch {
    return true;
  }
}

function subscribe(l: () => void) {
  listeners.add(l);
  return () => { listeners.delete(l); };
}

export function useCheckInCardShown(): boolean {
  return useSyncExternalStore(subscribe, read);
}

export function setCheckInCardShown(on: boolean): void {
  try {
    if (on) localStorage.removeItem(KEY);
    else localStorage.setItem(KEY, '0');
  } catch {
    // Storage refused (a private window): the switch keeps its default.
  }
  listeners.forEach((l) => l());
}
