/**
 * The name a stored file shows, and the two characters that decide whether
 * it survives.
 *
 * A file's name is the link text of its reference in the note body,
 * `[name|size|mime](pn:file/<uuid>)`, so it is written and read as markdown.
 * `|` separates the three fields and the markdown serializer does not escape
 * it, so a name holding one re-parses as a shorter name plus a wrong size
 * and mime. `cleanFileName` takes it out on the way in.
 *
 * The serializer does escape ` * \ ~ [ ] _ and the editor is fine, because
 * markdown-it unescapes on the way back. The surfaces that read the raw body
 * text instead of the parsed document are not: they show the backslashes.
 * `unescapeMarkdownText` is for those, and `escapeMarkdownText` is for the
 * one place that writes a link by hand rather than through the serializer.
 */

/** Longest name a file may carry. Matches the note title cap, because a
 *  single-file note carries its name in both places. */
// Spec: ops/docs/plans/file-rename-and-audio-seek.md (character rules)
export const FILE_NAME_MAX_LENGTH = 200;

/**
 * Make a typed name safe to store as link text. Removes what breaks the
 * link and what has no business in a filename, then caps the length.
 * Returns `fallback` when nothing usable is left, so an empty commit keeps
 * the name the file already had instead of clearing it.
 */
export function cleanFileName(raw: string, fallback: string): string {
  const cleaned = raw
    // eslint-disable-next-line no-control-regex
    .replace(/[\x00-\x1f\x7f|]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, FILE_NAME_MAX_LENGTH)
    .trim();
  return cleaned || fallback;
}

/**
 * Undo the escaping the markdown serializer applies to link text. The
 * character class mirrors prosemirror-markdown's own `esc`, and
 * `tests/fileNames.test.ts` pins the pair against a real serializer round
 * trip - a dependency that starts escaping something new reddens there
 * rather than shipping a stray backslash into the Files list.
 *
 * One left-to-right pass is correct for the nested case: `a\b` serializes
 * as `a\\b`, whose leading `\\` is consumed as an escaped backslash before
 * the `b` is reached.
 */
export function unescapeMarkdownText(s: string): string {
  return s.replace(/\\([`*\\~[\]_])/g, '$1');
}

/** Escape a name for use as markdown link text. */
export function escapeMarkdownText(s: string): string {
  return s.replace(/([`*\\~[\]_])/g, '\\$1');
}

/**
 * Split a name into the part a rename may change and the extension it may
 * not. The extension is the last dot's tail when that tail is at most ten
 * characters, holds no space and holds a letter; everything else is all
 * base. So nothing is appended to a name that arrived without an extension,
 * and a date such as `Notes 2026.09.10 draft` is not mistaken for one.
 */
export function splitFileName(name: string): { base: string; ext: string } {
  const dot = name.lastIndexOf('.');
  if (dot <= 0) return { base: name, ext: '' };
  const tail = name.slice(dot + 1);
  if (!/^[A-Za-z0-9]{1,10}$/.test(tail) || !/[A-Za-z]/.test(tail)) {
    return { base: name, ext: '' };
  }
  return { base: name.slice(0, dot), ext: tail };
}

/** Rejoin what `splitFileName` took apart. */
export function joinFileName(base: string, ext: string): string {
  return ext ? `${base}.${ext}` : base;
}
