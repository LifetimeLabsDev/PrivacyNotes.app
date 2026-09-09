/**
 * Folder definitions and pure helpers (Pro folders feature).
 *
 * Folders are a small synced array on UserSettings (see userSettings.ts)
 * - a handful of { id, name, parentId, order } rows forming a tree that
 * nests to any depth. Notes point at a folder via `folderId` inside their
 * encrypted payload; the definitions here never touch the server in
 * plaintext either (they ride the encrypted user_settings blob).
 *
 * The helpers are pure: they take a folder array and return a new one.
 * Callers apply results through NotesView's `mutateSettings` so the
 * settings generation guard stays intact.
 */

import type { LocalNote } from './db';

export interface FolderDef {
  id: string;
  name: string;
  /** Parent folder id, or null for a root folder. */
  parentId: string | null;
  /** Sibling sort index (ascending). */
  order: number;
}

/* ── Starter folder tree ────────────────────────────────────────────
 * Every new vault opens on a small tree, the same one the public demo
 * shows. The ids live here and the rest of the table lives in
 * `welcomeNote.ts`, which seeds it: the sidebar needs to recognise a
 * starter folder, and it should not carry the names and the nesting into
 * the boot path to do that.
 *
 * The ids are fixed and permanent. They are what an already-seeded vault
 * matches on, what a seed file's `folder:` frontmatter resolves through,
 * and what the delete rule below tests against.
 * Spec: ops/specs/folders.md (starter tree)
 */
export const SEED_FOLDER_IDS = {
  PrivacyNotes: 'f01de001-0000-4000-8000-000000000004',
  Markdown: 'f01de001-0000-4000-8000-000000000005',
  Security: 'f01de001-0000-4000-8000-000000000006',
  Travel: 'f01de001-0000-4000-8000-000000000001',
} as const;

/**
 * May this account delete this folder?
 *
 * Deleting is Pro like every other folder action, with one exception: a
 * locked account may take apart the starter tree. It was given that tree
 * rather than asked for it, and it cannot create a folder to replace one,
 * so a tree it cannot delete is a tree it is stuck with. A folder made
 * while subscribed stays put after a downgrade, because that one is the
 * user's own work.
 *
 * Both gates read this: the row menu decides whether to open at all, and
 * the handler that does the work checks again.
 */
export function canDeleteFolder(id: string, foldersUnlocked: boolean): boolean {
  return foldersUnlocked || (Object.values(SEED_FOLDER_IDS) as string[]).includes(id);
}

/**
 * How the sidebar orders sibling folders. 'custom' is the order the user
 * dragged them into, which lives in `FolderDef.order` and therefore syncs;
 * this CHOICE syncs beside it, because a hand-made order is work the user
 * did and it should follow the account rather than the device that made it.
 * Which folders are open stays per-device - that is about the screen you
 * are looking at, not about the content.
 * Spec: ops/docs/design-decisions.md (folders sort by Custom)
 */
export type FolderSortField = 'name' | 'entries' | 'custom';
export type FolderSortDir = 'asc' | 'desc';

export function isFolderSortField(v: unknown): v is FolderSortField {
  return v === 'name' || v === 'entries' || v === 'custom';
}

/**
 * The sibling comparator every surface that draws the tree uses: name
 * (locale-aware) or direct note count, with the other axis as tie-breaker
 * so the order is stable. 'custom' returns undefined - `childrenOf` has
 * already sorted by the stored order, which is exactly what a hand-made
 * order is.
 *
 * It lives here rather than in the sidebar because the Move dialog draws
 * the same folders and must draw them in the same sequence. The dialog
 * showed the stored order whatever the sidebar was set to, so a tree
 * sorted by name in the rail read as an unsorted list the moment you filed
 * something. Spec: issue #242.
 */
export function folderSiblingSorter(
  field: FolderSortField,
  dir: FolderSortDir,
  counts: Map<string, number>,
): ((list: FolderDef[]) => FolderDef[]) | undefined {
  if (field === 'custom') return undefined;
  const mul = dir === 'asc' ? 1 : -1;
  return (list: FolderDef[]): FolderDef[] =>
    list.slice().sort((a, b) => {
      if (field === 'entries') {
        const cmp = (counts.get(a.id) ?? 0) - (counts.get(b.id) ?? 0);
        if (cmp !== 0) return cmp * mul;
        return a.name.localeCompare(b.name, undefined, { sensitivity: 'base', numeric: true });
      }
      return a.name.localeCompare(b.name, undefined, { sensitivity: 'base', numeric: true }) * mul;
    });
}

/** Longest allowed folder name - mirrors TAG_MAX_LENGTH's job. */
export const FOLDER_NAME_MAX_LENGTH = 40;

/**
 * Sentinel folder filter: notes with no folder. The folder sibling of the
 * '__untagged__' tag sentinel. Never a real folder id (real ids are UUIDs),
 * never stored on a note - filter state only.
 */
export const UNFILED_ID = '__unfiled__';

/** Trim + collapse whitespace + cap length. Returns '' when unusable. */
function normalizeFolderName(raw: string): string {
  return raw.trim().replace(/\s+/g, ' ').slice(0, FOLDER_NAME_MAX_LENGTH);
}

/**
 * 1-based depth of a folder (root = 1). 0 when the id is unknown.
 *
 * `byId` is the caller's index when the caller has one. Built here otherwise,
 * which is right for a single lookup and quadratic inside a loop: rebuilding
 * it per folder is what made validating an imported tree cost 369 ms at four
 * thousand folders and tens of seconds at forty, on every boot rather than
 * once. Spec: ops/docs/audit-adversarial-2026-09-bfg.md (SEC-27)
 */
function folderDepth(
  folders: FolderDef[],
  id: string,
  index?: ReadonlyMap<string, FolderDef>,
): number {
  const byId = index ?? new Map(folders.map((f) => [f.id, f]));
  let depth = 0;
  let current = byId.get(id);
  const seen = new Set<string>();
  while (current) {
    if (seen.has(current.id)) return 0; // cycle - treat as invalid
    seen.add(current.id);
    depth++;
    current = current.parentId ? byId.get(current.parentId) : undefined;
  }
  return depth;
}

/** Direct children of `parentId` (null = roots), sorted by order. */
export function childrenOf(folders: FolderDef[], parentId: string | null): FolderDef[] {
  return folders
    .filter((f) => f.parentId === parentId)
    .sort((a, b) => a.order - b.order || a.name.localeCompare(b.name));
}

/** The folder plus every descendant, as a set of ids. */
export function subtreeIds(folders: FolderDef[], id: string): Set<string> {
  const ids = new Set<string>([id]);
  let grew = true;
  while (grew) {
    grew = false;
    for (const f of folders) {
      if (f.parentId && ids.has(f.parentId) && !ids.has(f.id)) {
        ids.add(f.id);
        grew = true;
      }
    }
  }
  return ids;
}

/** Can a new subfolder be created under `parentId`? (null = root, always ok) */
export function canCreateChild(folders: FolderDef[], parentId: string | null): boolean {
  if (parentId === null) return true;
  return folderDepth(folders, parentId) > 0;
}

/**
 * Can `id` be re-parented under `newParentId`? Refuses moves into the
 * folder's own subtree (a cycle) and moves under an unknown parent.
 */
export function canMoveFolder(
  folders: FolderDef[],
  id: string,
  newParentId: string | null
): boolean {
  if (id === newParentId) return false;
  if (newParentId !== null) {
    if (subtreeIds(folders, id).has(newParentId)) return false;
    return folderDepth(folders, newParentId) > 0;
  }
  return true;
}

/** Next sibling order index under `parentId` (append). */
function nextOrder(folders: FolderDef[], parentId: string | null): number {
  const siblings = folders.filter((f) => f.parentId === parentId);
  return siblings.length === 0 ? 0 : Math.max(...siblings.map((s) => s.order)) + 1;
}

/**
 * Create a folder. Returns the new array plus the created def, or null
 * when the name is empty or the parent can't take children.
 */
export function createFolder(
  folders: FolderDef[],
  rawName: string,
  parentId: string | null = null
): { folders: FolderDef[]; created: FolderDef } | null {
  const name = normalizeFolderName(rawName);
  if (!name) return null;
  if (!canCreateChild(folders, parentId)) return null;
  const created: FolderDef = {
    id: crypto.randomUUID(),
    name,
    parentId,
    order: nextOrder(folders, parentId),
  };
  return { folders: [...folders, created], created };
}

/** Rename a folder. No-op array copy when the name is empty or id unknown. */
export function renameFolder(folders: FolderDef[], id: string, rawName: string): FolderDef[] {
  const name = normalizeFolderName(rawName);
  if (!name) return folders;
  return folders.map((f) => (f.id === id ? { ...f, name } : f));
}

/** Re-parent a folder (appends at the end of the new sibling list). */
export function moveFolder(
  folders: FolderDef[],
  id: string,
  newParentId: string | null
): FolderDef[] {
  if (!canMoveFolder(folders, id, newParentId)) return folders;
  const order = nextOrder(folders, newParentId);
  return folders.map((f) => (f.id === id ? { ...f, parentId: newParentId, order } : f));
}

/**
 * Land a dragged folder: re-parent it if the drop crossed folders, then
 * renumber the destination's children to exactly `orderedIds`.
 *
 * The single writer of `order`, and the counterpart to `childrenOf`, which
 * is its only reader. `orderedIds` is the destination parent's children as
 * they will READ ON SCREEN after the drop, `id` included - built from the
 * rendered rows, never from stored order, because under a name or entries
 * sort the two are different lists and rearranging the stored one moves a
 * folder somewhere nobody dropped it.
 *
 * Both affected sibling lists are renumbered 0..n-1, so `order` can never
 * collide or leave a gap a later insert would have to guess at. A move the
 * tree refuses (into the folder's own subtree, or under an unknown parent)
 * and a sequence that is not exactly the destination's children are both
 * rejected whole rather than half-applied.
 */
export function applyFolderPlacement(
  folders: FolderDef[],
  id: string,
  newParentId: string | null,
  orderedIds: string[],
): FolderDef[] {
  const moving = folders.find((f) => f.id === id);
  if (!moving) return folders;
  const reparenting = moving.parentId !== newParentId;
  if (reparenting && !canMoveFolder(folders, id, newParentId)) return folders;

  const expected = new Set(
    folders.filter((f) => f.parentId === newParentId && f.id !== id).map((f) => f.id),
  );
  expected.add(id);
  if (orderedIds.length !== expected.size) return folders;
  if (new Set(orderedIds).size !== orderedIds.length) return folders;
  if (orderedIds.some((each) => !expected.has(each))) return folders;

  const destination = new Map(orderedIds.map((each, i) => [each, i]));
  // The folder leaves a hole behind it; close that list up too, so a later
  // drop into the old parent is not numbering against stale gaps.
  const source = reparenting
    ? new Map(
        folders
          .filter((f) => f.parentId === moving.parentId && f.id !== id)
          .sort((a, b) => a.order - b.order || a.name.localeCompare(b.name))
          .map((f, i) => [f.id, i]),
      )
    : new Map<string, number>();

  let changed = false;
  const next = folders.map((f) => {
    if (f.id === id) {
      const order = destination.get(id) ?? f.order;
      if (f.parentId === newParentId && f.order === order) return f;
      changed = true;
      return { ...f, parentId: newParentId, order };
    }
    const wanted = f.parentId === newParentId ? destination.get(f.id) : source.get(f.id);
    if (wanted === undefined || f.order === wanted) return f;
    changed = true;
    return { ...f, order: wanted };
  });
  // A drop that lands a folder back where it started must not look like an
  // edit: same array, so nothing re-renders and no settings write syncs.
  return changed ? next : folders;
}

/**
 * Delete a folder. Child folders move up to the deleted folder's
 * parent; the caller must move the folder's notes to `reparentTo`
 * (bulkMoveToFolder). Notes are never deleted here.
 */
export function deleteFolder(
  folders: FolderDef[],
  id: string
): { folders: FolderDef[]; reparentTo: string | null } {
  const target = folders.find((f) => f.id === id);
  const reparentTo = target?.parentId ?? null;
  const next = folders
    .filter((f) => f.id !== id)
    .map((f) => (f.parentId === id ? { ...f, parentId: reparentTo } : f));
  return { folders: next, reparentTo };
}

/** Direct-member note counts per folder id (v1: no recursive rollup). */
export function folderCounts(notes: LocalNote[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const n of notes) {
    if (!n.folderId) continue;
    counts.set(n.folderId, (counts.get(n.folderId) ?? 0) + 1);
  }
  return counts;
}

/** Ancestor ids of a folder, nearest first. Empty for roots/unknown ids. */
export function ancestorIds(folders: FolderDef[], id: string): string[] {
  const byId = new Map(folders.map((f) => [f.id, f]));
  const out: string[] = [];
  let current = byId.get(id);
  const seen = new Set<string>([id]);
  while (current?.parentId && !seen.has(current.parentId)) {
    seen.add(current.parentId);
    out.push(current.parentId);
    current = byId.get(current.parentId);
  }
  return out;
}

/**
 * A folder's full name chain from the root, e.g. `['PrivacyNotes', 'Security']`.
 *
 * The PORTABLE form of a folder membership. `folderId` is a UUID that means
 * nothing outside the account that generated it, so it is the right key for
 * a restore and the wrong one for an export somebody opens in another app.
 * Returns an empty array for an unfiled note or an id with no folder, so a
 * caller can treat "no path" and "not filed" the same way.
 */
export function folderNamePath(folders: FolderDef[], id: string | null): string[] {
  if (!id) return [];
  const byId = new Map(folders.map((f) => [f.id, f]));
  if (!byId.has(id)) return [];
  return [...ancestorIds(folders, id).reverse(), id]
    .map((fid) => byId.get(fid)?.name)
    .filter((name): name is string => !!name);
}

/**
 * Merge an imported folder subtree into an existing tree, reusing any
 * folder whose full path (name chain from the root) already exists instead
 * of duplicating it. Returns the combined folders plus a map from each
 * imported folder id to its final id in the merged tree, so callers can
 * remap every note's folderId.
 *
 * Precondition: `imported` lists parents before children (buildFolderTree
 * creates ancestors first), so a folder's parent is already mapped when we
 * reach it.
 */
export function reconcileImportedFolders(
  existing: FolderDef[],
  imported: FolderDef[]
): { folders: FolderDef[]; idMap: Map<string, string> } {
  let folders = [...existing];
  const idMap = new Map<string, string>();
  for (const inc of imported) {
    const parentId = inc.parentId ? idMap.get(inc.parentId) ?? null : null;
    const match = folders.find(
      (f) => f.parentId === parentId && f.name === inc.name
    );
    if (match) {
      idMap.set(inc.id, match.id);
      continue;
    }
    const res = createFolder(folders, inc.name, parentId);
    if (res) {
      folders = res.folders;
      idMap.set(inc.id, res.created.id);
    } else if (parentId) {
      // Unusable name: keep notes on the nearest real folder.
      idMap.set(inc.id, parentId);
    }
  }
  return { folders, idMap };
}

/**
 * Sanitize a raw folders array from a settings blob. Drops entries with
 * missing/empty names, unknown parents, or cycles; coerces a bad `order`
 * to append. Used by userSettings hydrate and by the backup restore merge.
 */
export function validateFolders(raw: unknown): FolderDef[] {
  if (!Array.isArray(raw)) return [];
  const cleaned: FolderDef[] = [];
  const seenIds = new Set<string>();
  for (const entry of raw) {
    if (!entry || typeof entry !== 'object') continue;
    const f = entry as Partial<FolderDef>;
    if (typeof f.id !== 'string' || !f.id || seenIds.has(f.id)) continue;
    const name = typeof f.name === 'string' ? normalizeFolderName(f.name) : '';
    if (!name) continue;
    const parentId = typeof f.parentId === 'string' && f.parentId ? f.parentId : null;
    const order = typeof f.order === 'number' && Number.isFinite(f.order) ? f.order : Number.MAX_SAFE_INTEGER;
    seenIds.add(f.id);
    cleaned.push({ id: f.id, name, parentId, order });
  }
  // Orphaned parents become roots (parent id not in the set).
  const idSet = new Set(cleaned.map((f) => f.id));
  const reparented = cleaned.map((f) =>
    f.parentId && !idSet.has(f.parentId) ? { ...f, parentId: null } : f
  );
  // Drop cycles, in one pass over the whole set rather than one walk per
  // folder. A shared index alone is not enough: the walk itself is as long as
  // the chain, so a single deep tree stays quadratic. Each ancestor's depth is
  // remembered as it is resolved, so every folder is visited once.
  const byId = new Map(reparented.map((f) => [f.id, f]));
  const depth = new Map<string, number>();
  for (const start of reparented) {
    if (depth.has(start.id)) continue;
    // The chain from this folder up to something already known, a root, or a
    // repeat. A repeat is a cycle, and every folder on the way into it is
    // invalid too, which is what the 0 records.
    const chain: FolderDef[] = [];
    const onPath = new Set<string>();
    let current: FolderDef | undefined = start;
    let base = 0;
    while (current) {
      const known = depth.get(current.id);
      if (known !== undefined) {
        base = known;
        break;
      }
      if (onPath.has(current.id)) {
        base = 0;
        for (const f of chain) depth.set(f.id, 0);
        break;
      }
      onPath.add(current.id);
      chain.push(current);
      current = current.parentId ? byId.get(current.parentId) : undefined;
    }
    if (base === 0 && chain.some((f) => depth.get(f.id) === 0)) continue;
    for (let i = chain.length - 1; i >= 0; i--) {
      base += 1;
      depth.set(chain[i]!.id, base);
    }
  }
  return reparented.filter((f) => (depth.get(f.id) ?? 0) > 0);
}
