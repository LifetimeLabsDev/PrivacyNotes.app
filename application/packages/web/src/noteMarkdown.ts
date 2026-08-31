import type { LocalNote } from './db';

/**
 * Serialize a note as markdown with YAML front-matter.
 *
 * Lives in its own module rather than inside export.ts for one reason: it is
 * the WRITE half of a round trip whose READ half is already tested. Every
 * markdown file the app emits is parsed back by `import/markdown.ts` (single
 * files and plain zips) or `import/privacynotes.ts` (the full backup zip), so
 * the front-matter grammar below is a contract between four files. Keeping it
 * here lets `tests/exportRoundTrip.test.ts` drive it directly - export.ts's
 * own entry points end in a browser download, and knip's project glob stops a
 * test from reaching an export that only a test consumes.
 *
 * The grammar, since three parsers depend on it:
 *   - `title` is always quoted, with inner `"` backslash-escaped.
 *   - `created` / `updated` are ISO strings.
 *   - `tags` is `[a, b]`, comma-joined and UNQUOTED. Safe because
 *     `normalizeTag` strips commas, so no tag can contain the separator.
 *   - The fullMeta block is emitted only for the full backup zip, and only
 *     `import/privacynotes.ts` reads it. `folderId` and `trackers` are
 *     omitted entirely when absent rather than written empty.
 *
 * When `fullMeta` is true (used by the full backup zip), the front-matter is
 * lossless so the backup restores every flag. When false (single-note
 * exports), only the basics.
 */
export function noteToMarkdown(
  note: LocalNote,
  fullMeta = false,
  folderPath: string[] = [],
): string {
  const fm: string[] = ['---'];
  fm.push(`title: "${note.title.replace(/"/g, '\\"')}"`);
  fm.push(`created: ${note.createdAt}`);
  fm.push(`updated: ${note.updatedAt}`);
  if (note.tags.length) fm.push(`tags: [${note.tags.join(', ')}]`);
  // The PORTABLE folder membership: names, not the UUID. `folderId` below is
  // the right key for restoring into the same account and a meaningless
  // string anywhere else, so both are written when both are known. Slashes
  // in a name are escaped, since the path itself is slash-separated.
  if (folderPath.length > 0) {
    fm.push(`folder: ${folderPath.map((n) => n.replace(/\//g, '\\/')).join('/')}`);
  }
  if (fullMeta) {
    fm.push(`type: ${note.type || 'note'}`);
    fm.push(`starred: ${note.starred === 1}`);
    // A full backup carries the trash: without this line every trashed
    // note restored as a LIVE note, which resurrects what the user
    // threw away. apply.ts re-stamps updatedAt so the retention purge
    // does not eat imported trash on the next mount.
    fm.push(`trashed: ${note.trashed === 1}`);
    fm.push(`locked: ${note.locked === 1}`);
    fm.push(`pinProtected: ${note.pinProtected === 1}`);
    if (note.folderId) fm.push(`folderId: ${note.folderId}`);
  } else if (note.type === 'journal') {
    // The ONE type a single .md may declare. A journal's body is its real
    // markdown, so restoring it as a journal is lossless - and without the
    // line its trackers would come back attached to a plain note, where the
    // app never shows them. Vault types stay unwritten here on purpose: a
    // login exports as the READABLE `vaultToMarkdown` text, so declaring the
    // type would restore that prose as a login and hide every field. See
    // exportSingleMarkdown.
    fm.push('type: journal');
  }
  // Written for every export, not only the full backup: trackers are the one
  // field a single exported journal entry would otherwise lose silently - the
  // body and tags round-trip intact, so nothing flags the missing mood, sleep
  // and step counts.
  if (note.trackers && Object.keys(note.trackers).length > 0) {
    fm.push(`trackers: ${JSON.stringify(note.trackers)}`);
  }
  fm.push('---');
  return `${fm.join('\n')}\n\n${note.body}\n`;
}

/**
 * Remove the padding `noteToMarkdown` adds around a body, on the way back in.
 *
 * The exact inverse of the `\n\n` separator and the trailing `\n` above, and
 * it lives here so the two halves of that contract cannot drift apart. Every
 * reader of this format needs it: `import/privacynotes.ts` kept the padding
 * and `import/markdown.ts` over-removed it, which were the two halves of
 * backlog #148.
 *
 * NEWLINES ONLY - never `.trim()`. Four leading spaces are an indented code
 * block, and trimming them demotes it to a paragraph: a silent change to what
 * the note renders as, which is worse than the blank line being fixed. Same
 * for trailing spaces, which are markdown's hard line break.
 *
 * Why the padding survived a read at all: the front-matter regexes end in
 * `\r?\n?`, which consumes at most ONE newline after the closing fence, so
 * the blank separator line stays attached to the body. Left there it
 * compounds, because the padded body is what the next export serializes.
 */
export function stripFrontMatterPadding(body: string): string {
  return body.replace(/^(?:\r?\n)+/, '').replace(/(?:\r?\n)+$/, '');
}
