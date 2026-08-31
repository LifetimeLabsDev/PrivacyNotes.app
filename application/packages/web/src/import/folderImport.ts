/**
 * Shared folder-structure helpers for imports.
 *
 * Kept free of JSZip and other heavy deps so both the Obsidian parser
 * (which builds the tree) and the import modal (which decides folder
 * tagging) can pull from here without dragging the zip library onto the
 * modal's boot-path bundle.
 */
import {
  canCreateChild,
  createFolder,
  type FolderDef,
} from '../folders';
import { normalizeTag } from '../notesRepo';
import type { ImportedNote } from './types';

/**
 * The single wrapper directory that every path in a zip shares, with its
 * trailing slash, or '' when there is none.
 *
 * People zip the folder, not its contents, so a vault arrives as
 * `MyNotes/note.md` and the wrapper is not part of anybody's structure. Only
 * ONE level is stripped on purpose: a second shared segment is a real folder
 * the user made (a vault whose notes all live under `Notes/`), and eating it
 * would silently flatten the tree by one.
 */
export function commonRootPrefix(paths: string[]): string {
  const first = paths[0];
  if (!first) return '';
  const slash = first.indexOf('/');
  if (slash <= 0) return '';
  const candidate = first.slice(0, slash + 1);
  return paths.every((p) => p.startsWith(candidate)) ? candidate : '';
}

/**
 * Build a folder tree from a set of directory paths (e.g. an Obsidian
 * vault's subfolders), rebuilding the full path as real folders at any
 * depth.
 *
 * Returns the created folder defs plus a map from each input directory
 * path to the id of the deepest folder created for it (for note.folderId).
 */
/**
 * Split a `folder: A/B/C` front-matter value into path segments.
 *
 * The readable counterpart to `folderId`, written by `noteToMarkdown` and
 * read by BOTH markdown importers, which is why it lives here rather than
 * privately in one of them. A folder name may itself contain a slash, so
 * the writer escapes those as `\\/` and this undoes it.
 */
export function parseFolderPath(raw: string | undefined): string[] {
  if (!raw || !raw.trim()) return [];
  const segs: string[] = [];
  let cur = '';
  const s = raw.trim();
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '\\' && s[i + 1] === '/') { cur += '/'; i++; continue; }
    if (s[i] === '/') { segs.push(cur); cur = ''; continue; }
    cur += s[i];
  }
  segs.push(cur);
  return segs.map((x) => x.trim()).filter(Boolean);
}

export function buildFolderTree(dirPaths: string[]): {
  folders: FolderDef[];
  dirToFolderId: Map<string, string>;
} {
  let folders: FolderDef[] = [];
  // Accumulated segment path ("A/B/C") -> created folder id. Lets sibling
  // subtrees share ancestors instead of duplicating them.
  const segPathToId = new Map<string, string>();
  const dirToFolderId = new Map<string, string>();

  // Sort so ancestors are visited before descendants and siblings land in
  // a stable, predictable order.
  const sorted = [...new Set(dirPaths)].filter(Boolean).sort();

  for (const dir of sorted) {
    const segs = dir.split('/').filter(Boolean);
    let parentId: string | null = null;
    let accum = '';
    let deepestId: string | null = null;

    for (const seg of segs) {
      accum = accum ? `${accum}/${seg}` : seg;
      const existing = segPathToId.get(accum);
      if (existing) {
        parentId = existing;
        deepestId = existing;
        continue;
      }
      if (!canCreateChild(folders, parentId)) break; // invalid parent
      const res = createFolder(folders, seg, parentId);
      if (!res) break; // empty / unusable segment name
      folders = res.folders;
      segPathToId.set(accum, res.created.id);
      parentId = res.created.id;
      deepestId = res.created.id;
    }

    if (deepestId) dirToFolderId.set(dir, deepestId);
  }

  return { folders, dirToFolderId };
}

/**
 * Add folder-derived tags to notes carrying a folderPath.
 *
 * Only applies when alsoTagFolders is true (the "also tag by folder"
 * import option, on by default for free users) - those folder levels are
 * already navigable as real folders, so tagging them too is an add-on, not
 * a fallback.
 */
export function withFolderPathTags(
  notes: ImportedNote[],
  alsoTagFolders: boolean,
): ImportedNote[] {
  if (!alsoTagFolders) return notes;
  return notes.map((n) => {
    const path = n.folderPath ?? [];
    if (path.length === 0) return n;
    const extra = path.map(normalizeTag).filter(Boolean);
    if (extra.length === 0) return n;
    const tags = [...n.tags];
    for (const t of extra) if (!tags.includes(t)) tags.push(t);
    return { ...n, tags };
  });
}
