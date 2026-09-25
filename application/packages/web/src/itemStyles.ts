/**
 * Folder and tag looks: an icon and a color per folder or per tag, kept in the
 * encrypted settings blob as `itemStyles`.
 *
 * Every value is a register, `{ v, at }`, and each register merges on its
 * own: the later stamp wins, and nothing that one device merely lacks is ever
 * taken away. That is what makes the map safe in a row every device writes
 * whole. A device holding an older copy can push it, and the next device to
 * merge puts the newer values back. A null value is a reset to the default,
 * stamped like any pick, so a reset travels and ages out after the folder
 * tombstone window.
 *
 * The map sits BESIDE the folder tree, never inside it: an older client
 * rebuilds each folder from the fields it knows and would strip a look on
 * every push, while it passes an unknown top-level key through untouched.
 * The validator keeps key kinds and register names it does not know for the
 * same reason, so a later version's additions survive this one.
 *
 * Spec: ops/docs/plans/folder-tag-icons.md (section 5)
 */
import { subtreeIds, TOMBSTONE_RETENTION_MS, type FolderDef, type FolderTombstone } from './folders';
import { sortTags } from './tagOrder';

interface StyleRegister {
  /** An icon id or a color key; null is "back to the default". */
  v: string | null;
  /** When it was written, ISO. */
  at: string;
}
type ItemStyle = Record<string, StyleRegister>;
export type ItemStyles = Record<string, ItemStyle>;
export type LookAttr = 'icon' | 'color';
export interface Look {
  icon: string | null;
  color: string | null;
}

/**
 * The colors of the editor's text and highlight pickers, by key. A key
 * is stored, never a hex, and drawn through the `--pn-label-<key>-*` tokens in
 * index.css, so it reads in every theme. A key is permanent.
 */
export const LOOK_COLORS = [
  'gray',
  'red',
  'orange',
  'yellow',
  'green',
  'teal',
  'blue',
  'purple',
  'pink',
] as const;
export type LookColor = (typeof LOOK_COLORS)[number];

export function isLookColor(v: unknown): v is LookColor {
  return typeof v === 'string' && (LOOK_COLORS as readonly string[]).includes(v);
}

export function folderLookKey(id: string): string {
  return `f:${id}`;
}

export function tagLookKey(tag: string): string {
  return `t:${tag}`;
}

const KEY_PATTERN = /^[a-z]:[\s\S]{1,200}$/;
const NAME_PATTERN = /^[A-Za-z]{1,32}$/;
const VALUE_MAX = 64;

function agedOut(reg: StyleRegister, now: number): boolean {
  return reg.v === null && now - Date.parse(reg.at) > TOMBSTONE_RETENTION_MS;
}

function readRegister(raw: unknown): StyleRegister | null {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as Partial<StyleRegister>;
  if (typeof r.at !== 'string' || Number.isNaN(Date.parse(r.at))) return null;
  if (r.v === null) return { v: null, at: r.at };
  if (typeof r.v === 'string' && r.v.length >= 1 && r.v.length <= VALUE_MAX) {
    return { v: r.v, at: r.at };
  }
  return null;
}

/** Sanitize a raw map from a settings blob or a backup. Drops malformed
 *  shapes and aged-out resets, and nothing else. */
export function validateItemStyles(raw: unknown, now = Date.now()): ItemStyles {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  const out: ItemStyles = {};
  for (const [key, entry] of Object.entries(raw as Record<string, unknown>)) {
    if (!KEY_PATTERN.test(key) || !entry || typeof entry !== 'object' || Array.isArray(entry)) {
      continue;
    }
    const kept: ItemStyle = {};
    for (const [name, value] of Object.entries(entry as Record<string, unknown>)) {
      if (!NAME_PATTERN.test(name)) continue;
      const reg = readRegister(value);
      if (reg && !agedOut(reg, now)) kept[name] = reg;
    }
    if (Object.keys(kept).length > 0) out[key] = kept;
  }
  return out;
}

/** The later write. On an equal stamp both sides of a merge must choose the
 *  same register, so the value decides: null lowest, then string order. */
function later(a: StyleRegister, b: StyleRegister): StyleRegister {
  const ta = Date.parse(a.at);
  const tb = Date.parse(b.at);
  if (ta !== tb) return ta > tb ? a : b;
  if (a.v === b.v) return a.at >= b.at ? a : b;
  if (a.v === null) return b;
  if (b.v === null) return a;
  return a.v > b.v ? a : b;
}

/** Ids of the folders a tree's tombstones delete, for `mergeItemStyles`. */
export function deletedFolderIds(tombstones: readonly FolderTombstone[]): Set<string> {
  return new Set(tombstones.map((t) => t.id));
}

/**
 * Merge two copies of the map, neither of which is authoritative. Union by
 * key and by register, the later stamp per register, and an entry for a
 * deleted folder dropped: the folder tombstone is final.
 */
export function mergeItemStyles(
  local: ItemStyles,
  remote: ItemStyles,
  deletedFolders: ReadonlySet<string> = new Set(),
  now = Date.now(),
): ItemStyles {
  const out: ItemStyles = {};
  for (const key of new Set([...Object.keys(remote), ...Object.keys(local)])) {
    if (key.startsWith('f:') && deletedFolders.has(key.slice(2))) continue;
    const a = local[key] ?? {};
    const b = remote[key] ?? {};
    const merged: ItemStyle = {};
    for (const name of new Set([...Object.keys(b), ...Object.keys(a)])) {
      const ra = a[name];
      const rb = b[name];
      const pick = ra && rb ? later(ra, rb) : (ra ?? rb)!;
      if (!agedOut(pick, now)) merged[name] = pick;
    }
    if (Object.keys(merged).length > 0) out[key] = merged;
  }
  return out;
}

/** Whether two maps hold the same registers. Decides whether a merge made
 *  a repair that has to be pushed back. */
export function itemStylesEqual(a: ItemStyles, b: ItemStyles): boolean {
  const keys = Object.keys(a);
  if (keys.length !== Object.keys(b).length) return false;
  for (const key of keys) {
    const ea = a[key]!;
    const eb = b[key];
    if (!eb) return false;
    const names = Object.keys(ea);
    if (names.length !== Object.keys(eb).length) return false;
    for (const name of names) {
      const ra = ea[name]!;
      const rb = eb[name];
      if (!rb || ra.v !== rb.v || ra.at !== rb.at) return false;
    }
  }
  return true;
}

/** A stamp later than `prev` and never earlier than now: the rule of
 *  `nextStamp` in notesRepo.ts. A new pick then outranks the value it
 *  replaces even when another device's clock runs ahead. */
function stampAfter(prev: string | undefined): string {
  const now = Date.now();
  const cur = prev ? Date.parse(prev) : Number.NaN;
  return new Date(Number.isFinite(cur) && cur >= now ? cur + 1 : now).toISOString();
}

/**
 * The one writer. Sets each attribute the patch names; null resets it. An
 * unchanged value writes nothing, and a map with no change comes back as the
 * same object, so a settings write that changes nothing is a no-op. `at`
 * replaces the stamp, for a value that must lose to any pick (an import).
 */
export function setItemLook(
  styles: ItemStyles,
  key: string,
  patch: Partial<Record<LookAttr, string | null>>,
  at?: string,
): ItemStyles {
  const entry = styles[key] ?? {};
  let next: ItemStyle | null = null;
  for (const name of Object.keys(patch) as LookAttr[]) {
    const v = patch[name];
    if (v === undefined) continue;
    const prev = entry[name];
    if ((prev?.v ?? null) === v) continue;
    next = next ?? { ...entry };
    next[name] = { v, at: at ?? stampAfter(prev?.at) };
  }
  return next ? { ...styles, [key]: next } : styles;
}

/** The oldest stamp there is: an imported value loses to any pick or reset,
 *  on any device, including one this device has not pulled yet. */
const IMPORT_STAMP = new Date(0).toISOString();

/**
 * The icons the starter folders and tags come with. Stamped as old as an
 * import, so any pick or reset on any device wins, and a key that already
 * holds an icon register, a reset included, is left alone.
 */
export function seedIcons(styles: ItemStyles, icons: Record<string, string>): ItemStyles {
  let next = styles;
  for (const [key, icon] of Object.entries(icons)) {
    if (next[key]?.icon) continue;
    next = setItemLook(next, key, { icon }, IMPORT_STAMP);
  }
  return next;
}

/**
 * Tag colors that come with an import (Google Keep). A tag with any color
 * register, a reset included, keeps it: the person already decided.
 */
export function importTagColors(
  styles: ItemStyles,
  colors: ReadonlyMap<string, string>,
): ItemStyles {
  let next = styles;
  for (const [tag, color] of colors) {
    if (styles[tagLookKey(tag)]?.color) continue;
    next = setItemLook(next, tagLookKey(tag), { color }, IMPORT_STAMP);
  }
  return next;
}

export function lookOf(styles: ItemStyles, key: string): Look {
  const entry = styles[key];
  return { icon: entry?.icon?.v ?? null, color: entry?.color?.v ?? null };
}

/** The looks of `keys` as they are now, for `restoreLooks`. */
export function snapshotLooks(styles: ItemStyles, keys: readonly string[]): Record<string, Look> {
  return Object.fromEntries(keys.map((key) => [key, lookOf(styles, key)]));
}

/**
 * Put the looks of a snapshot back: the picker's Cancel. Each value that
 * changed is written again with a new stamp, like any pick, so the undo
 * travels to every device; a value that did not change is not touched.
 */
export function restoreLooks(styles: ItemStyles, before: Record<string, Look>): ItemStyles {
  let next = styles;
  for (const [key, look] of Object.entries(before)) {
    next = setItemLook(next, key, { icon: look.icon, color: look.color });
  }
  return next;
}

/**
 * A tag rename carries its look to the new name, unless the new name has a
 * value of its own for that attribute: renaming INTO an existing tag merges
 * the two, and the target keeps what it already shows. The old name is reset.
 */
export function renameTagLook(styles: ItemStyles, oldTag: string, newTag: string): ItemStyles {
  if (oldTag === newTag) return styles;
  const from = lookOf(styles, tagLookKey(oldTag));
  if (!from.icon && !from.color) return styles;
  const to = lookOf(styles, tagLookKey(newTag));
  const moved = setItemLook(styles, tagLookKey(newTag), {
    icon: to.icon ?? from.icon,
    color: to.color ?? from.color,
  });
  return setItemLook(moved, tagLookKey(oldTag), { icon: null, color: null });
}

/** Drops the entries of folders that are gone for good. The merge drops them
 *  too, while their tombstones live; this keeps a delete from waiting for it. */
export function dropFolderLooks(styles: ItemStyles, ids: Iterable<string>): ItemStyles {
  let next: ItemStyles | null = null;
  for (const id of ids) {
    const key = folderLookKey(id);
    if (!(key in (next ?? styles))) continue;
    next = next ?? { ...styles };
    delete next[key];
  }
  return next ?? styles;
}

/**
 * A folder's color: the one set on it, and nothing a folder above it holds.
 * What the tree shows is what was set, so "No color" on a subfolder is plain.
 * `setSubfolderColors` gives a whole branch one color on request.
 */
export function folderColor(folderId: string | null | undefined, styles: ItemStyles): LookColor | null {
  const color = folderId ? styles[folderLookKey(folderId)]?.color?.v : undefined;
  return isLookColor(color) ? color : null;
}

/**
 * Sets `color` on every folder below `folderId`, each as a pick of its own: a
 * copy can change or go on its own, and a subfolder made later starts plain.
 * With `onlyFrom`, only the subfolders that show that color change, which are
 * the copies, and never a color a subfolder chose for itself. The folder
 * itself and every other branch stay as they are.
 */
export function setSubfolderColors(
  styles: ItemStyles,
  folderId: string,
  folders: FolderDef[],
  color: LookColor | null,
  onlyFrom?: LookColor,
): ItemStyles {
  let next = styles;
  for (const id of subtreeIds(folders, folderId)) {
    if (id === folderId) continue;
    if (onlyFrom !== undefined && folderColor(id, next) !== onlyFrom) continue;
    next = setItemLook(next, folderLookKey(id), { color });
  }
  return next;
}

/**
 * The subfolder switch of the picker, read from the colors themselves rather
 * than stored: on when the folder has a color and every folder below shows
 * it. Nothing new to sync, and a subfolder given its own color turns it off.
 */
export function subfoldersFollow(styles: ItemStyles, folderId: string, folders: FolderDef[]): boolean {
  const own = folderColor(folderId, styles);
  if (!own) return false;
  const below = [...subtreeIds(folders, folderId)].filter((id) => id !== folderId);
  return below.length > 0 && below.every((id) => folderColor(id, styles) === own);
}

/** A folder's color. While the switch is on, the copies below follow it. */
export function setFolderColor(
  styles: ItemStyles,
  folderId: string,
  folders: FolderDef[],
  color: LookColor | null,
): ItemStyles {
  const own = folderColor(folderId, styles);
  const follow = subfoldersFollow(styles, folderId, folders);
  const next = setItemLook(styles, folderLookKey(folderId), { color });
  return follow && own ? setSubfolderColors(next, folderId, folders, color, own) : next;
}

/** The list filter a color follows: the tag and the folder the list is
 *  narrowed to, with every folder the folder filter takes in. */
export interface ColorFilter {
  tag: string | null;
  folderId: string | null;
  folderIds: ReadonlySet<string>;
}

/**
 * The one color a note takes, read by every surface that draws it. While the
 * list is filtered by a colored tag or folder, that filter's color: the list
 * is that tag's or folder's view, so every note in it wears its color. With
 * both filters colored, the tag wins, by the same rule as without a filter.
 * Otherwise the first colored tag in the order its tag chips show, else its
 * folder's own color. A tag comes first because it is a choice about this
 * note; a folder is the default for everything in it.
 * Spec: ops/docs/plans/folder-tag-icons.md (section 4.4)
 */
export function resolveItemColor(
  tags: readonly string[],
  folderId: string | null | undefined,
  styles: ItemStyles,
  filter?: ColorFilter,
): LookColor | null {
  if (filter?.tag && tags.includes(filter.tag)) {
    const color = styles[tagLookKey(filter.tag)]?.color?.v;
    if (isLookColor(color)) return color;
  }
  if (filter?.folderId && folderId && filter.folderIds.has(folderId)) {
    const color = folderColor(filter.folderId, styles);
    if (color) return color;
  }
  for (const tag of sortTags([...tags])) {
    const color = styles[tagLookKey(tag)]?.color?.v;
    if (isLookColor(color)) return color;
  }
  return folderColor(folderId, styles);
}
