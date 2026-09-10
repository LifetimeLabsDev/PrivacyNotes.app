/**
 * Browser bookmarks importer - the Netscape bookmark file format, which
 * every browser exports (Chrome, Firefox, Safari, Edge, and the other
 * Chromium skins all emit the same shape from "Export bookmarks").
 *
 * Two inputs, one parser: the bare .html file, or a .zip holding it.
 * Safari is why the zip exists - "Export Browsing Data to File" is its
 * only bookmarks export today and it always writes an archive.
 *
 * The format is NOT valid HTML: <DT> and <p> are never closed and the
 * nesting is carried by <DL>...</DL> alone. So this is a hand tokenizer,
 * not a DOM parse - three token kinds walked in order with a folder
 * stack: <DT><H3 ...>name</H3> opens a folder, <DT><A ...>name</A> is a
 * bookmark, </DL> closes the current folder.
 *
 * Mapping (decided 2026-08-22, ops/docs/plans/bookmarks-pillar.md):
 *   - The folder tree imports as REAL folders under one "Bookmarks" root.
 *   - Container roots are dropped and their children merge one level up.
 *     Detection is ATTRIBUTE-based (PERSONAL_TOOLBAR_FOLDER,
 *     UNFILED_BOOKMARKS_FOLDER), never name-based: the names are
 *     localized in the export ("Barra de marcadores"), attributes are not.
 *   - ADD_DATE (unix seconds) becomes createdAt; Safari exports carry no
 *     dates at all, those rows get the import time.
 *   - Link text becomes the name unless it equals the URL or the URL's
 *     bare domain - both import as unnamed, and the app shows the domain
 *     (render-time fallback). The domain case exists because OUR export
 *     writes a nameless bookmark as its domain, since a truly empty <A>
 *     is a blank row in every browser's list. Without this the pair would
 *     not round trip: 31 unnamed rows in a real 539-bookmark export came
 *     back named after one export/import cycle (measured 2026-08-22).
 *   - Firefox TAGS= and SHORTCUTURL= (the address-bar keyword) are both
 *     user-authored labels, so they land in one list that the import
 *     modal's checkbox keeps or drops. Chromium and Safari write neither.
 *   - The embedded ICON= data URIs are ignored: stale snapshots, and the
 *     live favicon proxy already does this job.
 *   - <DD> descriptions are NOT read. Firefox dropped the description
 *     field from its UI years ago, and a 539-bookmark real export
 *     (2026-08-22) carried zero of them.
 *   - Only http(s) links import; place:, javascript:, chrome: and
 *     friends are counted into one warning.
 * Exact-URL dedupe against existing bookmarks happens in apply.ts, where
 * the local DB is in reach.
 */

import { buildLinkBody, linkDomain } from '../linkBody';
import { normalizeTag } from '../notesRepo';
import { buildFolderTree } from './folderImport';
import { readArchiveEntry } from './safariArchive';
import type { ImportedNote, ParsedImport } from './types';

/** Root folder every imported bookmark lands under. */
const ROOT_FOLDER = 'Bookmarks';

const TOKEN = /<DT[^>]*>\s*<H3([^>]*)>([\s\S]*?)<\/H3>|<DT[^>]*>\s*<A([^>]*)>([\s\S]*?)<\/A>|<\/DL>/gi;

const NAMED_ENTITY: Record<string, string> = {
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  amp: '&',
};

const ENTITY = /&(?:#(\d{1,7})|#[xX]([0-9a-fA-F]{1,6})|([a-z]+));/gi;

/**
 * One left-to-right pass, so `&amp;lt;` decodes to the literal `&lt;` the
 * export meant, not to `<`. A chain of `.replace()` calls cannot do that,
 * because the pass that expands `&amp;` re-exposes the text after it.
 *
 * The numeric branches are not decoration: Safari escapes every non-ASCII
 * character in a title as a hex reference, so a real 416-bookmark export
 * (2026-08-25) carried `&#x3001;`, `&#xB7;`, `&#x2013;` and `&#x1F4AF;`
 * in four titles. Chromium and Firefox escape only the five basics.
 * An unknown name or an out-of-range code point is left as written.
 */
function decodeEntities(s: string): string {
  return s.replace(ENTITY, (whole, dec: string | undefined, hex: string | undefined, name: string | undefined) => {
    if (name !== undefined) {
      // Own property only: the name comes out of the file, and an inherited
      // one answers with a function that `?? whole` cannot see, so the
      // function's own source text would land in the title.
      const key = name.toLowerCase();
      return Object.hasOwn(NAMED_ENTITY, key) ? NAMED_ENTITY[key]! : whole;
    }
    const code = dec !== undefined ? Number(dec) : parseInt(hex!, 16);
    // Reject nothing, the surrogate range, and anything past the last
    // plane, all of which would make fromCodePoint throw.
    if (code <= 0 || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return whole;
    return String.fromCodePoint(code);
  });
}

function attr(attrs: string, name: string): string | null {
  const m = new RegExp(`${name}\\s*=\\s*"([^"]*)"`, 'i').exec(attrs);
  return m ? decodeEntities(m[1]!) : null;
}

/** ADD_DATE is unix seconds; tolerate exports that emit ms or us. */
function toIso(raw: string | null): string | null {
  if (!raw) return null;
  let n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return null;
  if (n > 1e14) n = Math.floor(n / 1e6);
  else if (n > 1e11) n = Math.floor(n / 1e3);
  const d = new Date(n * 1000);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

/**
 * The labels a browser stored with one bookmark: Firefox's TAGS list plus
 * its address-bar keyword, normalized and de-duplicated into one list.
 * Kept transient on the note - `withBrowserTags` decides whether they
 * become real tags, so the preview checkbox can flip without re-parsing.
 * Spec: ops/docs/plans/bookmarks-pillar.md (section 9)
 */
function browserTagsOf(attrs: string): string[] {
  const out: string[] = [];
  const push = (raw: string) => {
    const tag = normalizeTag(raw);
    if (tag && !out.includes(tag)) out.push(tag);
  };
  const tags = attr(attrs, 'TAGS');
  if (tags) for (const part of tags.split(',')) push(part);
  const keyword = attr(attrs, 'SHORTCUTURL');
  if (keyword) push(keyword);
  return out;
}

/**
 * Merge each bookmark's browser tags into its real tags. Off means the
 * import drops them, which is what the modal's checkbox controls.
 */
export function withBrowserTags(notes: ImportedNote[], keep: boolean): ImportedNote[] {
  if (!keep) return notes;
  return notes.map((n) => {
    const extra = n.browserTags ?? [];
    if (extra.length === 0) return n;
    const tags = [...n.tags];
    for (const tag of extra) if (!tags.includes(tag)) tags.push(tag);
    return { ...n, tags };
  });
}

export async function parseBrowserBookmarks(file: File): Promise<ParsedImport> {
  const text = /\.zip$/i.test(file.name)
    ? await readArchiveEntry(file, 'Bookmarks.html', /\.html?$/i)
    : await file.text();
  if (!/<A\s[^>]*HREF\s*=/i.test(text) && !/<DL/i.test(text)) {
    throw new Error('Not a bookmarks export - expected the bookmarks .html file a browser exports.');
  }

  const now = new Date().toISOString();
  const notes: ImportedNote[] = [];
  const warnings: string[] = [];
  // Folder stack entries: the display segment, or null for a dropped
  // container level (its children merge into the level above).
  const stack: (string | null)[] = [];
  let skippedSchemes = 0;

  const path = () => stack.filter((seg): seg is string => seg !== null);

  let m: RegExpExecArray | null;
  while ((m = TOKEN.exec(text)) !== null) {
    if (m[0].toUpperCase() === '</DL>') {
      // The outermost </DL> closes the document's root list, which never
      // had a pushed segment - guard so a malformed file cannot underflow.
      if (stack.length > 0) stack.pop();
      continue;
    }
    if (m[1] !== undefined) {
      // Folder. Container roots contribute no path segment.
      const attrs = m[1];
      const isContainer =
        attr(attrs, 'PERSONAL_TOOLBAR_FOLDER') === 'true' ||
        attr(attrs, 'UNFILED_BOOKMARKS_FOLDER') === 'true';
      // A '/' inside a folder name would split into two levels downstream
      // (buildFolderTree joins on '/'), so it is flattened to a hyphen.
      const name = decodeEntities(m[2]!.trim()).replace(/\//g, '-');
      stack.push(isContainer || !name ? null : name);
      continue;
    }
    // Bookmark.
    const attrs = m[3]!;
    const href = attr(attrs, 'HREF') ?? '';
    if (!/^https?:\/\//i.test(href)) {
      skippedSchemes++;
      continue;
    }
    try {
      // Keep the browser's URL as-is (it was reachable there); this parse
      // only proves it is a URL at all.
      void new URL(href);
    } catch {
      skippedSchemes++;
      continue;
    }
    const rawName = decodeEntities(m[4]!.trim());
    const name = rawName === href || rawName === linkDomain(href) ? '' : rawName;
    const created = toIso(attr(attrs, 'ADD_DATE'));
    const folderPath = [ROOT_FOLDER, ...path()];
    const browserTags = browserTagsOf(attrs);
    notes.push({
      title: name,
      body: buildLinkBody(href),
      tags: [],
      createdAt: created ?? now,
      updatedAt: created ?? now,
      type: 'link',
      folderPath,
      ...(browserTags.length > 0 ? { browserTags } : {}),
    });
  }

  if (notes.length === 0) {
    throw new Error('No bookmarks found in this file.');
  }
  if (skippedSchemes > 0) {
    // Firefox exports three or four of these on every account - its own
    // "Most Visited" and "Recent Tags" smart folders are place: rows. The
    // old wording ("entries were skipped") read as data loss.
    warnings.push(
      skippedSchemes === 1
        ? '1 browser-only shortcut was left out. It is something like Most Visited, which works only inside the browser.'
        : `${skippedSchemes} browser-only shortcuts were left out. They are things like Most Visited, which work only inside the browser.`
    );
  }

  // Rebuild the folder tree once across all paths, so sibling subtrees
  // share ancestors, then point each note at its deepest folder.
  const dirPaths = [...new Set(notes.map((n) => (n.folderPath ?? []).join('/')))];
  const { folders, dirToFolderId } = buildFolderTree(dirPaths);
  for (const n of notes) {
    n.folderId = dirToFolderId.get((n.folderPath ?? []).join('/')) ?? null;
  }

  return {
    notes,
    warnings,
    transforms: [],
    stats: {
      totalNotes: notes.length,
      emptyNotes: 0,
      untaggedNotes: notes.length,
      uniqueTags: 0,
    },
    source: 'browser-bookmarks',
    folders,
  };
}
