/**
 * Filenames for the export formats, and the one question every reader of a
 * filename has to ask before it treats one as a title.
 *
 * This lives outside export.ts for the same reason noteToMarkdown does: the
 * naming rule is a data-integrity property, and a test has to be able to drive
 * it without loading the exporter's whole chain of renderers and forms. The
 * reader below sits beside the writer because they are one convention seen
 * from two ends: `slugify` is what puts "untitled" on a file, so whoever
 * changes that word is looking straight at the code that reads it back.
 */
import type { LocalNote } from './db';

/** A filesystem-safe stem from a note title. Empty titles get a fixed name. */
export function slugify(title: string): string {
  const slug = title
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60);
  return slug || 'untitled';
}

/**
 * True when a filename stem is a default name rather than a title.
 *
 * Every writer of note files, this app included, has to call the file of an
 * unnamed note something, and they all reach for the same word plus a counter
 * for the repeats: "Untitled", "Untitled 2", "untitled-17". None of those is a
 * name a person chose, so an importer that stores one puts a stand-in in the
 * user's own title field, where nothing afterwards can tell it from a name
 * they typed - it syncs to every device and comes back in the next export.
 *
 * READ THIS BEFORE WRITING AN IMPORTER. A note whose source gives it no title
 * must arrive with an empty one: the list derives its first body line at render
 * time (`deriveDisplayTitle`), which is both what the user saw in the app they
 * came from and a line that keeps following the body when they edit it. Any
 * importer that falls back to a filename asks this first. The four that do are
 * pinned together in tests/importUntitledNames.test.ts; a new one joins that
 * table. Reported as GitHub #337, where a restore renamed 3,684 notes.
 *
 * Both separators are accepted because the callers differ: some hand over a
 * raw stem, and the markdown reader spaces its slugs out first.
 */
export function isUntitledStem(stem: string): boolean {
  const s = stem.trim();
  return !s || /^untitled(?:[\s._-]+\d+)?$/i.test(s);
}

/**
 * Zip entry stems for a note list, in order, each unique against every name
 * already claimed by the zip.
 *
 * Uniqueness has to hold for the FINAL name rather than for a per-base-slug
 * count: a note titled "X 2" slugifies to the same stem the second "X" is
 * given, and JSZip overwrites a repeated path in silence. A collision there
 * drops a note out of a file the UI calls a complete account backup, and
 * nothing at export time says so. The count of returned stems always equals
 * the count of notes, and they are always distinct.
 */
export function zipEntryStems(notes: Pick<LocalNote, 'title'>[]): string[] {
  const used = new Set<string>();
  return notes.map((note) => {
    const base = slugify(note.title);
    let stem = base;
    let n = 1;
    while (used.has(stem)) stem = `${base}-${++n}`;
    used.add(stem);
    return stem;
  });
}
