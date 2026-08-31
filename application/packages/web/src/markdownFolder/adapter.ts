/**
 * Turning a file on disk into something the app can render, and back again.
 *
 * The single rule this module exists to enforce: **fidelity, not conversion.**
 * The importers in `import/` translate a foreign app's export INTO our format,
 * which is a one-way trip where rewriting the source is the whole point. This
 * is the opposite. The file on disk stays the user's file, in their format,
 * and anything we cannot represent has to survive untouched rather than be
 * normalized into something we prefer.
 *
 * Two consequences that are easy to get wrong:
 *
 *   - `preprocessObsidianMarkdown` from `import/obsidian.ts` must NEVER be used
 *     here. It strips `%%comments%%`, rewrites embeds and converts callout
 *     aliases - correct for an import, and a silent rewrite of somebody's vault
 *     if it ran on save.
 *   - The raw front-matter block is kept verbatim, not re-serialized from the
 *     parsed values. `noteToMarkdown`'s grammar is a contract for OUR exports
 *     (title/created/updated/tags in a fixed order); running a user's file
 *     through it would reorder their keys and drop every field we don't model,
 *     which is most of what Obsidian users put there (aliases, cssclasses,
 *     publish, banner, whatever their plugins read). The rich editor hides the
 *     block rather than showing it as body text, so `frontMatterRaw` is what
 *     puts it back on every save - byte for byte, fences and line endings
 *     included.
 *
 * Spec: ops/docs/plans/markdown-folder.md (section 6, data model)
 */
import { extractInlineTags, normalizeTag, parseYamlTags } from '../notesRepo';
import type { LocalNote } from '../db';

/** Extensions we open in the rich editor. All are plain markdown. */
const MARKDOWN_EXTENSIONS = ['md', 'markdown', 'mdown', 'mkd'];
/** Opened in the source editor instead - see `editorMode` below. */
const TEXT_EXTENSIONS = ['txt'];
const SUPPORTED_EXTENSIONS_RAW = [...MARKDOWN_EXTENSIONS, ...TEXT_EXTENSIONS];

const MARKDOWN_EXT = new RegExp(`\\.(${MARKDOWN_EXTENSIONS.join('|')})$`, 'i');
const TEXT_EXT = new RegExp(`\\.(${TEXT_EXTENSIONS.join('|')})$`, 'i');

/** Every extension this module opens, markdown and plain text alike. Shared
 *  with `import/markdown.ts`, which takes both as notes: a `.txt` opens in the
 *  SOURCE editor when it stays a file on disk, but an IMPORT copies it into a
 *  note, and Nextcloud Notes writes `.txt` by default. */
export const SUPPORTED_EXT = new RegExp(
  `\\.(${SUPPORTED_EXTENSIONS_RAW.join('|')})$`,
  'i',
);

/**
 * Every extension we open, bare (no dot) - the shape both platform pickers
 * want, and the ONE list of what an openable file is.
 *
 * `fileAccess.ts` builds its picker filters from this rather than keeping its
 * own copy: two lists in adjacent files is exactly how `.txt` ends up openable
 * by one route and invisible to the other. This module owns the question
 * because it also owns the answer to what an extension MEANS (rich or source).
 * It must stay in step with the `fileAssociations` extensions in
 * `packages/desktop/src-tauri/tauri.conf.json`, which is what makes a
 * double-click in Finder reach a file we are willing to open.
 */
export const SUPPORTED_EXTENSIONS = SUPPORTED_EXTENSIONS_RAW;

/**
 * Front-matter fence, capturing the block and the body separately.
 *
 * The shared definition: the importers under `import/` parse the same fence,
 * and five verbatim copies of one regex is how they drift. `\r?\n?` after the
 * closing fence is load-bearing - a file whose front matter ends at EOF with no
 * trailing newline still has front matter, and a copy that demands the newline
 * silently treats the whole file as body.
 */
export const FRONT_MATTER = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/;

type MarkdownEditorMode = 'rich' | 'source';

export interface AdaptedFile {
  /** Filename stem. The filename IS the title, Obsidian-style, which is what
   *  makes `[[links]]` resolve the same way in both apps. */
  title: string;
  /** Everything after the front-matter block, byte for byte. */
  body: string;
  /** The raw front-matter block WITHOUT its `---` fences, exactly as written,
   *  or null when the file had none. Kept verbatim rather than re-serialized
   *  from the parsed values, so writing a file back cannot reorder a user's
   *  keys or drop the ones we do not model. */
  frontMatter: string | null;
  /**
   * Everything `body` is missing from the head of the file - the opening
   * fence, the front matter, the closing fence and the newline after it - as
   * the exact bytes that were there. `frontMatterRaw + body === raw`, always,
   * and `''` when the file had no front matter.
   *
   * This is the field the editor writes back through, and it exists because
   * `frontMatter` alone CANNOT be reassembled safely: the split consumes the
   * fences with a `\r?\n` on each side, so rebuilding them by hand has to
   * guess the line endings and whether a closing fence had a newline after it.
   * Guess wrong on a CRLF file and every save rewrites the user's line endings
   * - a silent reformat of a file we were asked only to edit, which is the one
   * thing this module exists to prevent. Slicing the prefix cannot guess,
   * because it never re-serializes anything.
   */
  frontMatterRaw: string;
  /** Front-matter `tags:` plus inline `#tags` found in the body. */
  tags: string[];
  /** `.txt` opens in the source editor: it is not markdown, and running it
   *  through a parse-and-serialize round trip would turn `# thing` into a
   *  heading and four leading spaces into a code block, rewriting a file that
   *  was never markdown to begin with. */
  editorMode: MarkdownEditorMode;
}

/** True when this file is one we are willing to open at all. */
export function isSupportedFile(filename: string): boolean {
  return MARKDOWN_EXT.test(filename) || TEXT_EXT.test(filename);
}

/**
 * True when this file is plain text rather than markdown.
 *
 * The list rows and the file header pick their icon from this, so a `.txt`
 * never wears the MD glyph. Deliberately not `adapted.editorMode === 'source'`:
 * that field is a live editor setting the user can toggle on any file, and an
 * icon that changed when they flipped to source mode would be reporting the
 * wrong thing about the file on disk.
 */
export function isTextFile(filename: string): boolean {
  return TEXT_EXT.test(filename);
}

/** Filename stem, with the extension removed and nothing else changed. */
function titleFromFilename(filename: string): string {
  const base = filename.slice(filename.lastIndexOf('/') + 1);
  return base.replace(MARKDOWN_EXT, '').replace(TEXT_EXT, '');
}


/**
 * The note's own first heading, when its body opens with one.
 *
 * A file whose first line is `# Abuse signals` already states its title, and
 * showing the filename above it repeats the same words in two type sizes. The
 * filename remains the fallback - and remains the file's identity on disk,
 * which is what `[[links]]` resolve against - but a heading is what the author
 * actually wrote and is what the header should say.
 *
 * Deliberately only used for the OPEN file, never for a list row - see
 * `entryToNote` for why the two disagree on purpose.
 */
function headingTitle(body: string): string | null {
  // Only the FIRST non-empty line, and only an h1. A heading further down is a
  // section, not the document's name.
  const firstLine = body.split('\n').find((l) => l.trim() !== '');
  const match = firstLine?.match(/^\s{0,3}#\s+(.+?)\s*#*\s*$/);
  return match?.[1]?.trim() || null;
}

/**
 * Split a file's text into the parts the app needs, changing none of them.
 *
 * `raw` is the file exactly as read from disk. Nothing here trims, normalizes
 * line endings, or reflows, so `frontMatter` and `body` concatenate back to the
 * input. `tests/markdownFolderAdapter.test.ts` pins that for every shape we
 * open, including CRLF and the trailing-whitespace forms that carry meaning
 * (two spaces is a hard break, four is a code block).
 *
 * Saving currently writes the editor's raw text straight back, so nothing here
 * reassembles the pieces. A composer is only needed once something edits the
 * front-matter structurally - writing a tag from the UI, say - and it lands
 * with that, not before.
 */
export function adaptFile(filename: string, raw: string): AdaptedFile {
  const match = raw.match(FRONT_MATTER);
  const frontMatter = match ? (match[1] ?? '') : null;
  const body = match ? (match[2] ?? '') : raw;
  // The head of the file as bytes, never rebuilt from the parsed value. See
  // `frontMatterRaw` above for why re-serializing the fences is unsafe.
  const frontMatterRaw = raw.slice(0, raw.length - body.length);

  const tags = [
    ...(frontMatter ? parseYamlTags(frontMatter) : []),
    ...extractInlineTags(body),
  ];

  return {
    title: headingTitle(body) ?? titleFromFilename(filename),
    body,
    frontMatter,
    frontMatterRaw,
    tags: [...new Set(tags)],
    editorMode: TEXT_EXT.test(filename) ? 'source' : 'rich',
  };
}

/**
 * A scanned file dressed as a note, so the app's own row components can render
 * it without knowing this pillar exists.
 *
 * This is the whole reason the list looks identical to every other list in the
 * app: `NoteRow` takes a `LocalNote`, so a file becomes one rather than getting
 * a second row component that would drift from the first on every design
 * change. Every field the encrypted store owns is pinned to its inert value -
 * nothing here is ever synced, trashed, starred or PIN-protected.
 *
 * `id` is the relative path, which is unique within a scan and stable for as
 * long as the file keeps its name.
 *
 * The title is the FILENAME here, even though `adaptFile` prefers the body's
 * first heading for the same file, so one note can read `abuse-signals` in the
 * list and `Abuse signals` in the header. That is deliberate and not worth
 * unifying: a row's title must exist at first paint, and a heading only exists
 * once `useTagIndex` has read the file in the background. Titling rows from the
 * heading would make every row rename itself as the pass lands and, worse,
 * reshuffle the title sort under the cursor - the same trap the size sort
 * already sidesteps by parking unread files last. The list is also how you find
 * a file you know by name, and its filter matches the path, so on-disk identity
 * is the right answer for a row even where a heading is the right answer for a
 * header.
 */
export function entryToNote(
  relPath: string,
  meta: { tags: string[]; excerpt: string; mtime: number | null; size: number | null } | undefined,
): LocalNote {
  const iso = meta?.mtime != null ? new Date(meta.mtime).toISOString() : '';
  return {
    id: relPath,
    title: titleFromFilename(relPath),
    body: meta?.excerpt ?? '',
    tags: meta?.tags ?? [],
    createdAt: iso,
    updatedAt: iso,
    dirty: 0,
    deleted: 0,
    trashed: 0,
    starred: 0,
    locked: 0,
    pinProtected: 0,
    type: 'note',
    folderId: null,
  };
}
