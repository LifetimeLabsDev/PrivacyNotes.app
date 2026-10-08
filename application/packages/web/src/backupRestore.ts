import { applyRestoredFolders, validateFolders } from './folders';
import { deletedFolderIds, itemStylesEqual, mergeItemStyles, validateItemStyles } from './itemStyles';
import { customThemesEqual, mergeCustomThemes, validateCustomThemes } from './customThemes';
import type { UserSettings } from './userSettings';

/**
 * The settings a restore of an encrypted text backup leaves: its folders, the
 * looks of folders and tags, and the custom themes, each merged the way sync
 * merges them. Folders are additive by id, and one this account deleted stays
 * deleted, because its tombstone is final. Looks and themes merge per value:
 * a later change here wins over the backup's, a value deleted since the backup
 * stays deleted, and a deleted folder does not get its look back. Answers
 * `prev` itself when nothing changes, so a second restore writes nothing.
 */
export function settingsAfterRestore(
  prev: UserSettings,
  backup: { folders?: unknown; itemStyles?: unknown; customThemes?: unknown },
): UserSettings {
  const folders = validateFolders(backup.folders);
  const looks = validateItemStyles(backup.itemStyles);
  const themes = validateCustomThemes(backup.customThemes);
  if (folders.length === 0 && Object.keys(looks).length === 0 && Object.keys(themes).length === 0) return prev;
  const result = applyRestoredFolders({ folders: prev.folders, deleted: prev.foldersDeleted }, folders);
  const itemStyles = mergeItemStyles(prev.itemStyles, looks, deletedFolderIds(result.tree.deleted));
  const customThemes = mergeCustomThemes(prev.customThemes, themes);
  const looksChanged = !itemStylesEqual(itemStyles, prev.itemStyles);
  const themesChanged = !customThemesEqual(customThemes, prev.customThemes);
  if (result.added === 0 && !looksChanged && !themesChanged) return prev;
  return {
    ...prev,
    folders: result.tree.folders,
    foldersDeleted: result.tree.deleted,
    ...(looksChanged ? { itemStyles } : {}),
    ...(themesChanged ? { customThemes } : {}),
  };
}

/**
 * The looks of a full backup zip, with each folder look moved to the id the
 * restore gave its folder. The zip rebuilds its folders from the paths its
 * notes carry, so a folder comes back under a new id, or under its saved one
 * when that folder is still live; `savedToFinal` maps one to the other. A
 * look whose folder did not come back is dropped; tag and note looks keep
 * their keys (tags by name, notes by the id the restore keeps).
 */
export function remapFolderLooks(raw: unknown, savedToFinal: ReadonlyMap<string, string>): unknown {
  if (!raw || typeof raw !== 'object') return raw;
  const out: [string, unknown][] = [];
  for (const [key, value] of Object.entries(raw)) {
    if (!key.startsWith('f:')) {
      out.push([key, value]);
      continue;
    }
    const final = savedToFinal.get(key.slice(2));
    if (final) out.push([`f:${final}`, value]);
  }
  return Object.fromEntries(out);
}

/** Saved folder id -> the id the restore kept, from the two maps a zip
 *  restore has: rebuilt -> saved (the parser) and rebuilt -> final (the
 *  folder merge). A folder the merge dropped has no entry. */
export function savedToFinalIds(
  originalIds: ReadonlyMap<string, string> | undefined,
  idMap: ReadonlyMap<string, string> | undefined,
): Map<string, string> {
  const out = new Map<string, string>();
  for (const [rebuilt, saved] of originalIds ?? []) {
    const final = idMap?.get(rebuilt);
    if (final) out.set(saved, final);
  }
  return out;
}

