import { readCustomHabits } from './habitList';
import { applyRestoredFolders, validateFolders } from './folders';
import { deletedFolderIds, itemStylesEqual, mergeItemStyles, validateItemStyles } from './itemStyles';
import { customThemesEqual, mergeCustomThemes, validateCustomThemes } from './customThemes';
import type { UserSettings } from './userSettings';
import { readFactors } from './trackerTypes';

/**
 * The settings a restore of an encrypted text backup leaves: its folders, the
 * looks of folders and tags, the custom themes and the factor names, each
 * merged the way sync merges them. Folders are additive by id, and one this account deleted stays
 * deleted, because its tombstone is final. Looks and themes merge per value:
 * a later change here wins over the backup's, a value deleted since the backup
 * stays deleted, and a deleted folder does not get its look back. Answers
 * `prev` itself when nothing changes, so a second restore writes nothing.
 */
export function settingsAfterRestore(
  prev: UserSettings,
  backup: { folders?: unknown; itemStyles?: unknown; customThemes?: unknown; factors?: unknown; customHabits?: unknown },
): UserSettings {
  const folders = validateFolders(backup.folders);
  const looks = validateItemStyles(backup.itemStyles);
  const themes = validateCustomThemes(backup.customThemes);
  // A factor the account lacks comes back; one it holds keeps this device's
  // copy, its name and its tombstone included.
  const known = new Set(prev.factors.map((f) => f.id));
  const newFactors = readFactors(backup.factors).filter((f) => !known.has(f.id));
  // The person's own habit questions come back the same way.
  const knownHabits = new Set(prev.customHabits.map((h) => h.id));
  const newHabits = readCustomHabits(backup.customHabits).filter((h) => !knownHabits.has(h.id));
  if (folders.length === 0 && Object.keys(looks).length === 0 && Object.keys(themes).length === 0 && newFactors.length === 0 && newHabits.length === 0) return prev;
  const result = applyRestoredFolders({ folders: prev.folders, deleted: prev.foldersDeleted }, folders);
  const itemStyles = mergeItemStyles(prev.itemStyles, looks, deletedFolderIds(result.tree.deleted));
  const customThemes = mergeCustomThemes(prev.customThemes, themes);
  const looksChanged = !itemStylesEqual(itemStyles, prev.itemStyles);
  const themesChanged = !customThemesEqual(customThemes, prev.customThemes);
  if (result.added === 0 && !looksChanged && !themesChanged && newFactors.length === 0 && newHabits.length === 0) return prev;
  return {
    ...prev,
    folders: result.tree.folders,
    foldersDeleted: result.tree.deleted,
    ...(looksChanged ? { itemStyles } : {}),
    ...(themesChanged ? { customThemes } : {}),
    ...(newFactors.length > 0 ? { factors: [...prev.factors, ...newFactors] } : {}),
    ...(newHabits.length > 0 ? { customHabits: [...prev.customHabits, ...newHabits] } : {}),
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

