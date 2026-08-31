/**
 * Folder id -> name, for the folder chip that a list row or a grid tile
 * draws beside its tags (Pro folders).
 *
 * A context rather than a prop because the chip is drawn deep inside
 * `TagChips`: threading a map down would mean adding a prop to every list
 * pane, `NoteRow` and `NoteCard`, none of which read it themselves.
 * `NotesView` owns the folder list and provides the map once, so a rename
 * re-labels every visible chip.
 *
 * Spec: ops/docs/ui-patterns.md (section 41, per-item folder chip)
 */
import { createContext, useContext } from 'react';

export const FolderNamesContext = createContext<ReadonlyMap<string, string>>(new Map());

/**
 * The item's folder name, or null when it is unfiled - which is also what a
 * free account always gets, since it has no folders. Callers render nothing
 * on null, so an unfiled item never shows an empty chip.
 */
export function useFolderName(folderId: string | null | undefined): string | null {
  const names = useContext(FolderNamesContext);
  return folderId ? names.get(folderId) ?? null : null;
}
