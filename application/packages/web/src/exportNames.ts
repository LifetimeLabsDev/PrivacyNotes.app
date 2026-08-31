/**
 * Filenames for the export formats.
 *
 * This lives outside export.ts for the same reason noteToMarkdown does: the
 * naming rule is a data-integrity property, and a test has to be able to drive
 * it without loading the exporter's whole chain of renderers and forms.
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
