/**
 * What a click on the folder or tag chip of a list row or a grid tile does:
 * it filters the list by that folder or tag, the same as picking it in the
 * sidebar. Spec: issue #333.
 *
 * A context for the same reason as `folderNames.ts`: the chips are drawn
 * deep inside `TagChips`, below every list pane. `NotesView` provides a
 * value with a stable identity, so the memoized rows do not re-render on
 * every render of the list. It provides null in selection mode, where a
 * click on a chip must select the row like a click anywhere else on it.
 */
import { createContext } from 'react';

export type ChipFilter = {
  tag: (tag: string) => void;
  folder: (folderId: string) => void;
};

export const ChipFilterContext = createContext<ChipFilter | null>(null);
