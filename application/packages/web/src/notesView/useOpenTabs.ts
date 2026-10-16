import { useCallback, useEffect, useMemo, useState, useSyncExternalStore } from 'react';
import type { LocalNote } from '../db';
import { isDemoMode } from '../demo';

/**
 * The items open as tabs above the editor: an ordered list of ids, per device
 * and never synced. The list is all there is to a tab; which one is active is
 * simply whichever id is `selectedId`. A tab changes its item only through
 * `followTab`, when "Open items in tabs" is on.
 *
 * A pinned tab sits in a group at the start of the strip and cannot be closed,
 * one by one or in bulk, until it is unpinned. Only its item leaving the app
 * (trash, delete) removes it.
 * Spec: ops/docs/plans/note-tabs.md
 */

const KEY = 'privacynotes.openTabs';

type Stored = { ids: string[]; pinned: string[] };

/** The demo shares its origin with a real install, so it keeps its own tabs in
 *  sessionStorage: a shared key would let it prune the real account's ids as
 *  missing, and a closed demo tab must leave nothing behind. */
function store(): Storage {
  return isDemoMode() ? sessionStorage : localStorage;
}

const strings = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];

function read(): Stored {
  try {
    const parsed = JSON.parse(store().getItem(KEY) ?? '{}') as Partial<Stored>;
    return order({ ids: strings(parsed.ids), pinned: strings(parsed.pinned) });
  } catch {
    return { ids: [], pinned: [] };
  }
}

/** Pinned first, each group in its own order; a pin without a tab is dropped. */
function order(s: Stored): Stored {
  const pinned = s.pinned.filter((id) => s.ids.includes(id));
  return { ids: [...pinned, ...s.ids.filter((id) => !pinned.includes(id))], pinned };
}

export function useOpenTabs(notes: LocalNote[]) {
  const [state, setState] = useState<Stored>(read);

  useEffect(() => {
    try { store().setItem(KEY, JSON.stringify(state)); } catch { /* storage unavailable */ }
  }, [state]);

  // An item that is trashed or gone takes its tab with it, pinned or not. The
  // list is empty for a moment at boot, and a missing id then means "not
  // loaded yet", so nothing is pruned until at least one item is there.
  useEffect(() => {
    if (notes.length === 0) return;
    const live = new Set(notes.filter((n) => n.trashed === 0).map((n) => n.id));
    setState((prev) => (prev.ids.every((id) => live.has(id))
      ? prev
      : order({ ids: prev.ids.filter((id) => live.has(id)), pinned: prev.pinned })));
  }, [notes]);

  const tabs = useMemo(() => {
    const byId = new Map(notes.map((n) => [n.id, n]));
    return state.ids.map((id) => byId.get(id)).filter((n): n is LocalNote => !!n && n.trashed === 0);
  }, [state.ids, notes]);

  const tabIds = useMemo(() => new Set(state.ids), [state.ids]);
  const pinnedIds = useMemo(() => new Set(state.pinned), [state.pinned]);

  /** Adds the ids that have no tab yet, in order, at the end. */
  const addTabs = useCallback((add: string[]) => {
    setState((prev) => {
      const fresh = add.filter((id, i) => !prev.ids.includes(id) && add.indexOf(id) === i);
      return fresh.length === 0 ? prev : { ...prev, ids: [...prev.ids, ...fresh] };
    });
  }, []);

  /** Closes the named tabs. A pinned tab is skipped, so "close all" and "close
   *  others" can pass every id and still leave the pinned group alone. */
  const closeTabs = useCallback((close: string[]) => {
    setState((prev) => ({ ...prev, ids: prev.ids.filter((id) => prev.pinned.includes(id) || !close.includes(id)) }));
  }, []);

  /** The tab of `prev` changes to `next`, the way a browser tab changes
   *  page. With no `prev` (it is pinned, or has no tab) `next` gets a tab of
   *  its own at the end. An item that has a tab keeps it. */
  const followTab = useCallback((prev: string | null, next: string) => {
    setState((s) => {
      if (s.ids.includes(next)) return s;
      if (prev !== null && s.ids.includes(prev) && !s.pinned.includes(prev)) {
        return { ...s, ids: s.ids.map((x) => (x === prev ? next : x)) };
      }
      return { ...s, ids: [...s.ids, next] };
    });
  }, []);

  /** Pinning moves a tab to the end of the pinned group, unpinning to the
   *  start of the rest, which is where a browser puts it. */
  const setPinned = useCallback((id: string, pin: boolean) => {
    setState((prev) => {
      if (!prev.ids.includes(id) || prev.pinned.includes(id) === pin) return prev;
      const pinned = pin ? [...prev.pinned, id] : prev.pinned.filter((x) => x !== id);
      const rest = prev.ids.filter((x) => x !== id && !pinned.includes(x));
      return { ids: pin ? [...pinned, ...rest] : [...pinned, id, ...rest], pinned };
    });
  }, []);

  /** A move never crosses the pinned boundary: the result is re-sorted into
   *  the two groups, so a tab dropped on the wrong side stays in its own. */
  const moveTab = useCallback((id: string, beforeId: string | null) => {
    setState((prev) => {
      const rest = prev.ids.filter((x) => x !== id);
      const at = beforeId === null ? rest.length : rest.indexOf(beforeId);
      if (!prev.ids.includes(id) || at < 0) return prev;
      const ids = [...rest.slice(0, at), id, ...rest.slice(at)];
      const pinned = ids.filter((x) => prev.pinned.includes(x));
      return order({ ids, pinned });
    });
  }, []);

  return { tabs, tabIds, pinnedIds, addTabs, followTab, closeTabs, setPinned, moveTab };
}

/**
 * "Open items in tabs": the open item always has a tab, and the tab you are
 * on follows the item you open, the way a browser tab follows a link. A
 * pinned tab keeps its item, so the next item opens in a new tab. On by
 * default, per device like the tabs. The settings window can be a second window, so the store
 * listens to `storage` as well as to its own change event.
 * Spec: ops/docs/plans/note-tabs.md (section 2)
 */
const OPEN_IN_TABS_KEY = 'privacynotes.ui.openItemsInTabs';
const OPEN_IN_TABS_EVENT = 'pn:open-items-in-tabs';

/** On unless this device turned it off: only an explicit '0' is off. */
function readOpenInTabs(): boolean {
  try { return localStorage.getItem(OPEN_IN_TABS_KEY) !== '0'; } catch { return true; }
}

function subscribeOpenInTabs(onChange: () => void): () => void {
  const onStorage = (e: StorageEvent) => { if (e.key === OPEN_IN_TABS_KEY) onChange(); };
  window.addEventListener('storage', onStorage);
  window.addEventListener(OPEN_IN_TABS_EVENT, onChange);
  return () => {
    window.removeEventListener('storage', onStorage);
    window.removeEventListener(OPEN_IN_TABS_EVENT, onChange);
  };
}

export function useOpenItemsInTabs(): [boolean, (on: boolean) => void] {
  const on = useSyncExternalStore(subscribeOpenInTabs, readOpenInTabs, () => true);
  const set = useCallback((next: boolean) => {
    try { localStorage.setItem(OPEN_IN_TABS_KEY, next ? '1' : '0'); } catch { /* storage unavailable */ }
    window.dispatchEvent(new Event(OPEN_IN_TABS_EVENT));
  }, []);
  return [on, set];
}

/**
 * Whether this window has room for the strip: the md step, where the editor
 * becomes a pane of its own (`mdScreen` in NotesView.tsx reads the same query).
 * The Appearance row and its settings-search entry both ask this, so a phone
 * is offered no switch for a strip it never draws.
 */
const PANE_QUERY = '(min-width: 768px)';

export function tabsFit(): boolean {
  return typeof window !== 'undefined' && window.matchMedia(PANE_QUERY).matches;
}

function subscribeTabsFit(onChange: () => void): () => void {
  const mq = window.matchMedia(PANE_QUERY);
  mq.addEventListener('change', onChange);
  return () => mq.removeEventListener('change', onChange);
}

export function useTabsFit(): boolean {
  return useSyncExternalStore(subscribeTabsFit, tabsFit, () => false);
}
