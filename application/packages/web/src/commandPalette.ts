import { createContext, type ComponentType, type ReactNode, type RefObject } from 'react';
import type { IconProps } from './icons';
import { textMatcher } from './textMatch';

/**
 * Command mode: type ">" in the quick switcher (or in the list search, press
 * ">" outside a text field, click the list search's commands button, or press
 * Mod+Shift+P in the desktop apps) and the switcher lists the commands, found
 * by their names in the reader's language. Enter runs one. Every command
 * reachable from a key is here, so a browser, which keeps some keys for
 * itself, still reaches the commands the desktop apps give a key. Without
 * the prefix, the switcher shows the best few commands under the items.
 *
 * NotesView builds the entries and hands them to the switcher; the context
 * only tells the list search which field it is and how to open command mode.
 *
 * Spec: ops/docs/plans/keyboard-shortcuts.md (decisions D5 and D15)
 */

export type PaletteGroup = 'new' | 'goTo' | 'commands';

export type PaletteEntry = {
  id: string;
  group: PaletteGroup;
  label: string;
  /** The key that runs it on this device, if any: "⇧⌘M", "Ctrl+Shift+M". */
  keys?: string;
  /** The row's icon in the switcher; a group icon stands in when absent. */
  icon?: ComponentType<IconProps>;
  /** A ready-made glyph instead, as the New menu draws it (sized by the switcher). */
  glyph?: ReactNode;
  run: () => void;
};

export type CommandPaletteContextValue = {
  /** The one field that offers command mode: the app's list search. */
  searchInputRef: RefObject<HTMLInputElement | null>;
  /** Opens the quick switcher in command mode. */
  openCommands: () => void;
  /** Opens the quick switcher; the list header's button below lg calls it. */
  openSwitcher: () => void;
};

export const CommandPaletteContext = createContext<CommandPaletteContextValue | null>(null);

/** The prefix that turns the quick switcher (and the list search) into command mode. */
export const COMMAND_PREFIX = '>';

export const GROUP_ORDER: PaletteGroup[] = ['commands', 'new', 'goTo'];

/** The entries that match the query, best match first, then in list order. */
export function matchEntries(entries: PaletteEntry[], query: string): PaletteEntry[] {
  const q = query.trim();
  const byGroup = (a: PaletteEntry, b: PaletteEntry) => GROUP_ORDER.indexOf(a.group) - GROUP_ORDER.indexOf(b.group);
  if (!q) return [...entries].sort(byGroup);
  const match = textMatcher(q);
  return entries
    .map((entry, i) => ({ entry, i, m: match(entry.label) }))
    .filter((x) => x.m)
    .sort((a, b) => b.m!.rank - a.m!.rank || byGroup(a.entry, b.entry) || a.i - b.i)
    .map((x) => x.entry);
}
