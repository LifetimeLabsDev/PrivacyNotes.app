/**
 * Safari's "Export Browsing Data to File" writes a ZIP, never a bare
 * file, and one archive can hold every switch left on in that dialog:
 * `Safari-export/Bookmarks.html`, `Safari-export/Passwords.csv`,
 * `History.html`, and so on. Two importers read out of the same archive
 * shape, so the picking rule lives here rather than in each of them.
 *
 * The rule is BY NAME first. Taking "the only file with the right
 * extension" would let a `History.html` sitting next to the bookmarks
 * import as bookmarks, which is how a user ends up with every site they
 * have ever opened. Measured against a real Safari 26 export, 2026-08-25.
 *
 * Spec: ops/docs/plans/bookmarks-pillar.md (section 9.2)
 */

import JSZip from 'jszip';
import { zipEntryText } from './zipEntry';

/** Directories, hidden files and the junk a Mac leaves in a zip. */
function isJunk(path: string): boolean {
  if (path.startsWith('__MACOSX/') || path.includes('/__MACOSX/')) return true;
  return (path.split('/').pop() ?? '').startsWith('.');
}

/**
 * Read one named file out of the archive as text. `want` is the exact
 * basename Safari writes ('Bookmarks.html'); `ext` decides which entries
 * are candidates at all, so a sole `bookmarks.htm` still works when the
 * name does not match exactly.
 */
export async function readArchiveEntry(file: File, want: string, ext: RegExp): Promise<string> {
  const zip = await JSZip.loadAsync(await file.arrayBuffer());
  const candidates = Object.entries(zip.files).filter(
    ([path, entry]) => !entry.dir && !isJunk(path) && ext.test(path)
  );
  if (candidates.length === 0) {
    throw new Error(`No ${want} inside this zip.`);
  }
  const named = candidates.find(([path]) => (path.split('/').pop() ?? '').toLowerCase() === want.toLowerCase());
  if (!named && candidates.length > 1) {
    throw new Error(
      `This zip holds more than one file that could be it, and none is named ${want}. Unzip it and drop ${want} in on its own.`
    );
  }
  return zipEntryText((named ?? candidates[0]!)[1]);
}
