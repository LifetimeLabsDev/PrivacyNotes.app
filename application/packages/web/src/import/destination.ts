import { childrenOf, normalizeFolderName, type FolderDef } from '../folders';
import type { Space } from '../spaces';

/** The "Add to" choice of the import window: no folder (the source's own
 *  folders, unfiled stays unfiled), a new folder named after the source in
 *  the open space, or an existing folder. */
export type ImportDestination = 'none' | 'new' | { folderId: string };

/** The folders the row offers, and the space each is in (null while Spaces
 *  is off). */
export interface ImportTarget {
  folders: FolderDef[];
  spaceOf: ReadonlyMap<string, Space> | null;
  openSpace: Space | null;
}

export interface DestinationEntry { id: string; name: string; depth: number }

/** Every folder in tree order with its depth, one group per space with the
 *  open space first, or one group with no space while Spaces is off. */
export function destinationGroups(
  folders: FolderDef[],
  spaceOf: ReadonlyMap<string, Space> | null,
  openSpace: Space | null,
): { space: Space | null; entries: DestinationEntry[] }[] {
  const walk = (parentId: string | null, depth: number, out: DestinationEntry[]) => {
    for (const f of childrenOf(folders, parentId)) {
      out.push({ id: f.id, name: f.name, depth });
      if (depth < 32) walk(f.id, depth + 1, out);
    }
    return out;
  };
  const all = walk(null, 0, []);
  if (!spaceOf) return [{ space: null, entries: all }];
  const order: Space[] = openSpace === 'work' ? ['work', 'personal'] : ['personal', 'work'];
  return order.map((space) => ({
    space,
    entries: all.filter((e) => (spaceOf.get(e.id) ?? 'personal') === space),
  }));
}

/** The top-level folder of the open space that already has the source's
 *  name: the "new folder" choice reuses it, so the row names it instead. */
export function existingImportFolder(target: ImportTarget, name: string): string | null {
  const wanted = normalizeFolderName(name);
  const space = target.openSpace ?? 'personal';
  const hit = target.folders.find(
    (f) => !f.parentId && f.name === wanted && (target.spaceOf?.get(f.id) ?? 'personal') === space,
  );
  return hit?.id ?? null;
}

/** File every item that has no folder into `target`. */
export function fileUnfiled<T extends { folderId?: string | null }>(items: T[], target: string | null): T[] {
  if (!target) return items;
  return items.map((n) => (n.folderId ? n : { ...n, folderId: target }));
}
