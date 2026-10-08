import type { LocalNote } from './db';
import { editedAtOf } from './notesViewUtils';
import type { View } from './views';

/**
 * The sidebar's tag and folder counts speak for the open section.
 *
 * A pillar shows only the tags its own items carry, so login tags stay out of
 * Notes. Folders keep the whole tree and only their counts follow the section,
 * because the tree needs its parents and every folder is a drop target. All,
 * Pinned, Archive and Trash keep the global rail; Markdown has its own.
 * Tag pickers never read this: a note tag can still go on a login.
 * Spec: ops/issues/0335.md (decisions)
 */

/** The items a pillar is made of, before the tag and folder filters. `null`
 *  for a view whose rail stays global. Tasks and Files are not defined by
 *  note type: they hold every note with a task line or a picture or file. */
export function sectionNotes(
  view: View,
  listedNotes: LocalNote[],
  taskNoteIds: ReadonlySet<string>,
  fileNoteIds: ReadonlySet<string>,
  showNoteTasks: boolean,
): LocalNote[] | null {
  switch (view) {
    case 'all': return listedNotes.filter((n) => n.type === 'note');
    case 'journal': return listedNotes.filter((n) => n.type === 'journal');
    // Every vault type, whatever the Logins / Cards sub-filter says, so the
    // rail holds still while the user flips it.
    case 'vault': return listedNotes.filter((n) => n.type === 'login' || n.type === 'card' || n.type === 'ssh-key');
    case 'bookmarks': return listedNotes.filter((n) => n.type === 'link');
    case 'contacts': return listedNotes.filter((n) => n.type === 'contact');
    case 'tasks': return listedNotes.filter((n) =>
      n.type === 'task' || (showNoteTasks && taskNoteIds.has(n.id)));
    case 'files': return listedNotes.filter((n) => n.type === 'file' || fileNoteIds.has(n.id));
    default: return null;
  }
}

export type TagSortField = 'name' | 'modified' | 'entries';
export type TagSortDir = 'asc' | 'desc';
export interface TagCounts { tags: [string, number][]; untagged: number }

/** Tag counts in the user's sort order, plus the Untagged bucket. */
export function countTags(notes: LocalNote[], field: TagSortField, dir: TagSortDir): TagCounts {
  const counts = new Map<string, number>();
  // Numeric ms timestamps: local notes use "...Z" and server-synced notes may
  // use "...+00:00", so comparing the strings orders them wrongly.
  const lastModified = new Map<string, number>();
  let untagged = 0;
  for (const n of notes) {
    if (n.tags.length === 0) untagged++;
    for (const t of n.tags) {
      counts.set(t, (counts.get(t) ?? 0) + 1);
      const modTs = Date.parse(editedAtOf(n)) || 0;
      if (modTs > (lastModified.get(t) ?? 0)) lastModified.set(t, modTs);
    }
  }
  const entries = [...counts.entries()];
  entries.sort((a, b) => {
    let cmp: number;
    if (field === 'name') {
      cmp = a[0].localeCompare(b[0]);
    } else {
      cmp = field === 'modified'
        ? (lastModified.get(a[0]) ?? 0) - (lastModified.get(b[0]) ?? 0)
        : a[1] - b[1];
      if (cmp === 0) cmp = a[0].localeCompare(b[0]);
    }
    return dir === 'asc' ? cmp : -cmp;
  });
  return { tags: entries, untagged };
}
