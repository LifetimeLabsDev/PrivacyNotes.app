import { useCallback, useMemo, useSyncExternalStore } from 'react';
import { ancestorIds, childrenOf, type FolderDef } from './folders';

/**
 * The folder tree's shared state and shape - the ONE source of truth the
 * sidebar (`FolderTree`) and the Move dialog (`FolderPicker`) both read.
 *
 * The two used to keep private copies of the same three ideas (which
 * folders are open, how the tree flattens into rows, how far each row
 * indents) and drifted apart: the dialog had no carets, no guide lines and
 * no memory of what the sidebar had open. Everything shared lives here,
 * everything per-surface (what a click does, the search box, the Pro gate,
 * the counts) stays in the component.
 *
 * Expansion is a module-level store rather than component state because
 * BOTH surfaces are mounted at once while the dialog is open. Two
 * `useState` copies of one localStorage key would drift the moment either
 * side toggled a folder. `useSyncExternalStore` gives them one set and one
 * write path. Per-device, never synced - the same rule as the sidebar
 * collapse flags, because a 13-inch laptop and a 27-inch display do not
 * want the same tree open.
 */

/**
 * Ids whose expansion DIFFERS from the default, not the expanded ones.
 *
 * The default is: a top-level folder is open, a nested one is closed. A
 * closed top-level folder hides its whole branch behind a caret nobody
 * asked them to click, which is how a seeded or imported tree can look
 * empty on first sight. Nested folders keep starting closed, because that
 * is what stops a deep tree filling the rail.
 *
 * Storing the exceptions rather than the expanded set is what makes "open
 * by default, and remember it when I close one" a single set: closing a
 * top-level folder ADDS it, opening a nested one ADDS it, and both undo by
 * removal.
 *
 * A new key, because the old one stored the opposite meaning: reusing it
 * would read every folder a user had explicitly opened as one they had
 * explicitly closed. The stale `privacynotes.foldersExpanded` is left in
 * place rather than deleted, so a rollback still finds its state.
 */
const TOGGLED_KEY = 'privacynotes.folderToggles';

/**
 * Indentation stops here, the tree does not - the same rule the Markdown
 * pillar's own rail uses (MarkdownRail.tsx MAX_INDENT_LEVEL). Folders nest
 * to any depth, but past this many nested levels a name has no room left in
 * the sidebar; deeper folders keep the same indent as their level-5
 * ancestor instead of marching further right. The guide lines still nest,
 * so the tree stays legible instead of getting truncated or clipped.
 */
export const MAX_INDENT_LEVEL = 5;

/** Guide-line indent per level, in px. Spec: ops/specs/folders.md (folder indent) */
export const INDENT_PX = 12;

function readToggled(): Set<string> {
  try {
    const raw = localStorage.getItem(TOGGLED_KEY);
    if (!raw) return new Set();
    const parsed = JSON.parse(raw) as unknown;
    return new Set(Array.isArray(parsed) ? parsed.filter((v): v is string => typeof v === 'string') : []);
  } catch {
    return new Set();
  }
}

let toggled: Set<string> = readToggled();
const listeners = new Set<() => void>();

function publish(next: Set<string>): void {
  if (next === toggled) return;
  toggled = next;
  try {
    localStorage.setItem(TOGGLED_KEY, JSON.stringify([...next]));
  } catch {
    /* storage full / disabled - the tree just won't remember */
  }
  for (const listener of listeners) listener();
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** Top level open, nested closed, unless the user has said otherwise. */
function isFolderExpanded(folder: FolderDef, exceptions: Set<string>): boolean {
  return (folder.parentId === null) !== exceptions.has(folder.id);
}

/**
 * Expand `folder` whichever side of the default it sits on: a top-level
 * folder expands by dropping its override, a nested one by gaining it.
 * Returns the same set when nothing changes, so React can skip the render.
 */
function withFolderExpanded(exceptions: Set<string>, folder: FolderDef): Set<string> {
  if (isFolderExpanded(folder, exceptions)) return exceptions;
  const next = new Set(exceptions);
  if (folder.parentId === null) next.delete(folder.id);
  else next.add(folder.id);
  return next;
}

export interface FolderExpansion {
  isExpanded: (folder: FolderDef) => boolean;
  /** Flip a folder away from (or back to) its default expansion. */
  toggle: (id: string) => void;
  /** Make sure a folder is open, whichever side of the default it is on. */
  expand: (folders: FolderDef[], id: string) => void;
  /** Open the whole path down to `id`, so a selection is never hidden. */
  expandAncestors: (folders: FolderDef[], id: string) => void;
}

export function useFolderExpansion(): FolderExpansion {
  const exceptions = useSyncExternalStore(subscribe, () => toggled, () => toggled);

  const isExpanded = useCallback(
    (folder: FolderDef) => isFolderExpanded(folder, exceptions),
    [exceptions],
  );

  const toggle = useCallback((id: string) => {
    const next = new Set(toggled);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    publish(next);
  }, []);

  const expand = useCallback((folders: FolderDef[], id: string) => {
    const folder = folders.find((f) => f.id === id);
    if (folder) publish(withFolderExpanded(toggled, folder));
  }, []);

  const expandAncestors = useCallback((folders: FolderDef[], id: string) => {
    const ancestors = ancestorIds(folders, id);
    if (ancestors.length === 0) return;
    publish(
      ancestors.reduce((acc, ancestorId) => {
        const folder = folders.find((f) => f.id === ancestorId);
        return folder ? withFolderExpanded(acc, folder) : acc;
      }, toggled),
    );
  }, []);

  return useMemo(
    () => ({ isExpanded, toggle, expand, expandAncestors }),
    [isExpanded, toggle, expand, expandAncestors],
  );
}

export interface FolderRow {
  folder: FolderDef;
  /** 0-based depth. Drives both the indent and the guide line. */
  level: number;
  hasKids: boolean;
  expanded: boolean;
}

/**
 * Flatten the tree into the rows a surface renders, depth-first.
 *
 * `respectCollapse: false` walks the whole tree whatever is open - the
 * dialog's search needs every folder, and it draws the result flat with an
 * ancestor path instead of an indent.
 */
export function flattenFolderRows(
  folders: FolderDef[],
  opts: {
    isExpanded: (folder: FolderDef) => boolean;
    sortSiblings?: (list: FolderDef[]) => FolderDef[];
    respectCollapse?: boolean;
  },
): FolderRow[] {
  const { isExpanded, sortSiblings, respectCollapse = true } = opts;
  const rows: FolderRow[] = [];
  const walk = (parentId: string | null, level: number) => {
    const siblings = childrenOf(folders, parentId);
    for (const folder of sortSiblings ? sortSiblings(siblings) : siblings) {
      const kids = childrenOf(folders, folder.id);
      const expanded = isExpanded(folder);
      rows.push({ folder, level, hasKids: kids.length > 0, expanded });
      if (kids.length > 0 && (expanded || !respectCollapse)) walk(folder.id, level + 1);
    }
  };
  walk(null, 0);
  return rows;
}

/** Indent for a row's own content, capped so a deep tree keeps its names. */
export function folderIndentPx(level: number): number {
  return Math.min(level, MAX_INDENT_LEVEL) * INDENT_PX;
}
