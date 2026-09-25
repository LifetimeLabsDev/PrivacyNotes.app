/**
 * A title on one line: the lines of a title that holds a line break are
 * joined with one space, blank ones dropped and the ends trimmed. A title
 * with no line break is returned as it is, spaces included.
 *
 * Both readers of the front matter split it at line feeds, so a break in a
 * written title cuts the title there on the way back in, and a later line of
 * it reads as a key of its own (`type: journal`). The writer applies this to
 * what it writes, and `applyImport` to every title an import stores: a file
 * name, a zip entry or another app's title field can carry a break.
 */
export function oneLineTitle(title: string): string {
  if (!/[\r\n]/.test(title)) return title;
  return title
    .split(/\r\n|\r|\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .join(' ');
}
