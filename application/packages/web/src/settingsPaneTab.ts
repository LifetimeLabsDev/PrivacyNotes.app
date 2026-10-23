import { createContext, useCallback, useContext, useState } from 'react';

/**
 * The tab each settings pane has open, kept by the settings window. A resize
 * across the phone breakpoint swaps the window's layout and remounts the pane,
 * which would drop a plain `useState` back to the first tab. The window clears
 * it on a search landing, so a result still opens on its own tab.
 */
const PaneTabs = createContext<Map<string, string> | null>(null);
export const PaneTabMemory = PaneTabs.Provider;

/** A pane's tab, remembered across remounts inside the settings window; plain state outside it. */
export function usePaneTab<T extends string>(key: string, initial: T): [T, (next: T | ((prev: T) => T)) => void] {
  const memory = useContext(PaneTabs);
  const [tab, setTabState] = useState<T>(() => (memory?.get(key) as T | undefined) ?? initial);
  const setTab = useCallback((next: T | ((prev: T) => T)) => {
    setTabState((prev) => {
      const value = typeof next === 'function' ? next(prev) : next;
      memory?.set(key, value);
      return value;
    });
  }, [memory, key]);
  return [tab, setTab];
}
