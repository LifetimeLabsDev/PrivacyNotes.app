import { createContext } from 'react';
import { stockFormatBar, type ResolvedFormatBar } from './formatBar';
import type { BarPosition } from './editorPrefs';

/**
 * The arrangement the toolbar draws, and the gear's door to the Settings
 * tab that changes it. Provided once by NotesView, so every editor under it (a note, a
 * Markdown file) draws the same bar; an editor outside it draws the stock one.
 */
export type FormatBarContextValue = {
  layout: ResolvedFormatBar;
  onCustomize?: () => void;
  /** Where the bar sits, top or bottom (per device). */
  position?: BarPosition;
};

export const FormatBarContext = createContext<FormatBarContextValue>({ layout: stockFormatBar() });
