/**
 * Spaces: Personal and Work, two views of one vault.
 *
 * A space is a filter of the lists and nothing more. Every item still syncs
 * to every device, and sync, backup and export never read a space.
 *
 * A root folder carries its space as a `space` register in `itemStyles`; no
 * register, or a reset, is Personal. A subfolder is in its root's space, and
 * an item in its folder's. An unfiled item is Personal, whatever its type:
 * Work has no unfiled list, so an item made there files into a Work folder.
 *
 * Spec: ops/docs/plans/spaces.md
 */
import type { LocalNote } from './db';
import { isDemoMode } from './demo';
import type { FolderDef } from './folders';
import { folderLookKey, renameTagLook, setItemLook, type ItemStyles } from './itemStyles';

export type Space = 'personal' | 'work';

const WORK = 'work';

/** The space a root folder's own register names. */
function rootSpace(styles: ItemStyles, rootId: string): Space {
  return styles[folderLookKey(rootId)]?.space?.v === WORK ? 'work' : 'personal';
}

/** The space of every folder, read from its root. A folder whose parent is
 *  missing counts as a root, as the tree draws it. */
export function folderSpaces(folders: readonly FolderDef[], styles: ItemStyles): Map<string, Space> {
  const byId = new Map(folders.map((f) => [f.id, f]));
  const out = new Map<string, Space>();
  const resolve = (f: FolderDef, depth: number): Space => {
    const known = out.get(f.id);
    if (known) return known;
    const parent = f.parentId ? byId.get(f.parentId) : undefined;
    const space = parent && depth < 32 ? resolve(parent, depth + 1) : rootSpace(styles, f.id);
    out.set(f.id, space);
    return space;
  };
  for (const f of folders) resolve(f, 0);
  return out;
}

/** Whether an item shows in a space. A folder id the tree no longer holds
 *  reads as unfiled, which is how the lists treat it. */
export function inSpace(n: Pick<LocalNote, 'folderId'>, space: Space, spaces: ReadonlyMap<string, Space>): boolean {
  const filed = n.folderId ? spaces.get(n.folderId) : undefined;
  return (filed ?? 'personal') === space;
}

/** The folders of one space, whole subtrees, in tree order. */
export function foldersIn(folders: FolderDef[], spaces: ReadonlyMap<string, Space>, space: Space): FolderDef[] {
  return folders.filter((f) => spaces.get(f.id) === space);
}

/** The first root folder of a space by sibling order, or null. */
export function firstRootIn(folders: readonly FolderDef[], spaces: ReadonlyMap<string, Space>, space: Space): string | null {
  const ids = new Set(folders.map((f) => f.id));
  const roots = folders
    .filter((f) => (!f.parentId || !ids.has(f.parentId)) && spaces.get(f.id) === space)
    .sort((a, b) => a.order - b.order);
  return roots[0]?.id ?? null;
}

/** Put a root folder in a space. Personal is a reset, so the map holds an
 *  entry only for the folders a person moved to Work. */
export function setRootSpace(styles: ItemStyles, folderId: string, space: Space): ItemStyles {
  const has = styles[folderLookKey(folderId)]?.space;
  if (space === 'personal' && !has) return styles;
  return setItemLook(styles, folderLookKey(folderId), { space: space === 'work' ? WORK : null });
}

/**
 * Keep every folder in its space across a tree change. A folder that becomes
 * a root (dragged out, moved to root level, lifted by its parent's delete)
 * takes the space of the root it was under; a new root takes `active`. A
 * folder only changes space when a person asks for it, through
 * `setRootSpace`.
 */
export function carrySpaces(
  before: FolderDef[],
  after: FolderDef[],
  styles: ItemStyles,
  active: Space,
  // The styles before the change: a root's delete drops the root's entry in
  // the same update, and its lifted children must still read its space.
  beforeStyles: ItemStyles = styles,
): ItemStyles {
  const prev = new Map(before.map((f) => [f.id, f]));
  const prevIds = new Set(before.map((f) => f.id));
  const nextIds = new Set(after.map((f) => f.id));
  const wasRoot = (f: FolderDef) => !f.parentId || !prevIds.has(f.parentId);
  let spaces: Map<string, Space> | null = null;
  let next = styles;
  for (const f of after) {
    if (f.parentId && nextIds.has(f.parentId)) continue;
    const old = prev.get(f.id);
    if (old && wasRoot(old)) continue;
    let space = active;
    if (old) {
      spaces = spaces ?? folderSpaces(before, beforeStyles);
      space = spaces.get(old.id) ?? 'personal';
    }
    next = setRootSpace(next, f.id, space);
  }
  return next;
}

/**
 * The tag look and the star after a rename (`newTag`) or a delete (null) of
 * a tag in one space. Both are keyed by name for the whole account, so the
 * old name keeps them while an item outside the space still carries it.
 * Spec: ops/docs/plans/spaces.md (section 8)
 */
export function tagAfterScopedChange<T extends { itemStyles: ItemStyles; favoriteTags: string[] }>(
  prev: T,
  oldTag: string,
  newTag: string | null,
  usedElsewhere: boolean,
): T {
  const itemStyles = newTag === null
    ? prev.itemStyles
    : renameTagLook(prev.itemStyles, oldTag, newTag, usedElsewhere);
  const starred = prev.favoriteTags.includes(oldTag);
  let favoriteTags = prev.favoriteTags;
  if (starred) {
    favoriteTags = usedElsewhere ? [...favoriteTags] : favoriteTags.filter((t) => t !== oldTag);
    if (newTag !== null && !favoriteTags.includes(newTag)) favoriteTags.push(newTag);
  }
  if (itemStyles === prev.itemStyles && !starred) return prev;
  return { ...prev, itemStyles, favoriteTags };
}

// The active space: per device, never synced. The demo shares its origin with
// a real install, so it keeps its own copy in sessionStorage. NotesView holds
// it in React state, so a switch lands in the same render as the selection
// that caused it.
const ACTIVE_KEY = 'privacynotes.ui.activeSpace';

function store(): Storage {
  return isDemoMode() ? sessionStorage : localStorage;
}

export function readActiveSpace(): Space {
  try {
    return store().getItem(ACTIVE_KEY) === WORK ? 'work' : 'personal';
  } catch {
    return 'personal';
  }
}

export function saveActiveSpace(space: Space): void {
  try { store().setItem(ACTIVE_KEY, space); } catch { /* storage unavailable */ }
}
