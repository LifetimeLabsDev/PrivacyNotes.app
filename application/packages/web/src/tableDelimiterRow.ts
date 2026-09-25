/**
 * Recognising a pipe table's delimiter row. Kept apart from
 * tableColumnWidths.ts because the word count and the note list read it on
 * every render, and they need nothing else from there.
 * Spec: ops/docs/plans/table-column-widths.md
 */

/** The dash count of each delimiter cell; colons and spaces do not count. Null when the row is not a delimiter row. */
export function dashCounts(delimiter: string): number[] | null {
  let t = delimiter.trim();
  if (t.startsWith('|')) t = t.slice(1);
  if (t.endsWith('|')) t = t.slice(0, -1);
  const cells = t.split('|').map((c) => c.trim());
  if (cells.length === 0 || !cells.every((c) => /^:?-+:?$/.test(c))) return null;
  return cells.map((c) => c.replace(/:/g, '').length);
}

/** Whether a line is a pipe table's delimiter row, which carries no words. */
export function isDelimiterRow(line: string): boolean {
  return line.includes('-') && line.includes('|') && dashCounts(line) !== null;
}
