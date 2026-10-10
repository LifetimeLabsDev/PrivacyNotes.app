/**
 * The themes the Design quick menu offers: up to three favorites per mode,
 * starred on a card in Settings > Design. Per device, like the theme choice
 * itself. Starring a fourth drops the oldest star, and the Design pane offers
 * Undo. A mode that has never been chosen starts with its first three cards
 * starred, so a new device shows three themes and the stars explain why;
 * after that an empty slot stays empty until the person stars a theme.
 * Spec: ops/docs/plans/theme-paper.md (section 12)
 */
import { useSyncExternalStore } from 'react';
import { DARK_THEMES, LIGHT_THEMES, type Theme, type ThemeChoice } from './theme';

export const QUICK_THEMES_MAX = 3;

const KEY = 'privacynotes.ui.quickThemes';
/** The first cards of each mode in the gallery. */
const DEFAULTS: Record<Theme, readonly ThemeChoice[]> = { light: LIGHT_THEMES, dark: DARK_THEMES };

type Marks = Record<Theme, ThemeChoice[]>;
const listeners = new Set<() => void>();

function write(next: Marks): void {
  marks = next;
  try { localStorage.setItem(KEY, JSON.stringify({ v: 2, ...next })); } catch { /* storage unavailable */ }
  for (const fn of listeners) fn();
}

/** The stored marks. A store from before the version stored both modes at
 *  the first star, so an empty mode there was never chosen: it gets the
 *  first three cards once, and the version is written. */
function read(): Marks {
  try {
    const raw = JSON.parse(localStorage.getItem(KEY) ?? '{}') as Partial<Record<Theme, unknown>> & { v?: unknown };
    const list = (v: unknown) =>
      Array.isArray(v) ? v.filter((x): x is ThemeChoice => typeof x === 'string').slice(0, QUICK_THEMES_MAX) : [];
    const stored: Marks = { light: list(raw.light), dark: list(raw.dark) };
    if (raw.v === 2) return stored;
    const seeded: Marks = {
      light: stored.light.length ? stored.light : DEFAULTS.light.slice(0, QUICK_THEMES_MAX),
      dark: stored.dark.length ? stored.dark : DEFAULTS.dark.slice(0, QUICK_THEMES_MAX),
    };
    try { localStorage.setItem(KEY, JSON.stringify({ v: 2, ...seeded })); } catch { /* storage unavailable */ }
    return seeded;
  } catch {
    return { light: DEFAULTS.light.slice(0, QUICK_THEMES_MAX), dark: DEFAULTS.dark.slice(0, QUICK_THEMES_MAX) };
  }
}

let marks: Marks = read();

/** Star or unstar a theme of one mode. Returns the star a fourth one
 *  pushed out, and the marks before, so the caller can offer Undo. */
export function toggleQuickTheme(mode: Theme, choice: ThemeChoice): { dropped: ThemeChoice | null; before: ThemeChoice[] } {
  const before = marks[mode];
  if (before.includes(choice)) {
    write({ ...marks, [mode]: before.filter((c) => c !== choice) });
    return { dropped: null, before };
  }
  const next = [...before, choice];
  const dropped = next.length > QUICK_THEMES_MAX ? next[0]! : null;
  write({ ...marks, [mode]: next.slice(-QUICK_THEMES_MAX) });
  return { dropped, before };
}

/** Put a mode's marks back, for Undo. */
export function restoreQuickThemes(mode: Theme, list: ThemeChoice[]): void {
  write({ ...marks, [mode]: list.slice(0, QUICK_THEMES_MAX) });
}

/** The favorites the quick menu shows for a mode, in order: the marks that
 *  still name a theme. Fewer than three leaves empty slots. */
export function quickThemesFor(mode: Theme, current: Marks, exists: (choice: ThemeChoice) => boolean): ThemeChoice[] {
  return current[mode].filter(exists).slice(0, QUICK_THEMES_MAX);
}

function subscribe(fn: () => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function useQuickThemeMarks(): Marks {
  return useSyncExternalStore(subscribe, () => marks, () => marks);
}
