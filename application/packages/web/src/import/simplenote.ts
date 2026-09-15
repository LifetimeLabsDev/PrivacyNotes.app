import JSZip from 'jszip';
import { zipEntryText } from './zipEntry';
import { normalizeTag } from '../notesRepo';
import { linkifyMarkdown } from './linkify';
import type { Importer, ImportedNote, ParsedImport } from './types';

/**
 * Simplenote import adapter.
 *
 * Reads the official Simplenote export (.zip from Settings > Export).
 * The zip contains:
 *   source/notes.json  - authoritative JSON with all metadata
 *   *.txt              - flat text mirrors of active notes (ignored)
 *   trash/*.txt        - flat text mirrors of trashed notes (ignored)
 *
 * notes.json schema:
 *   {
 *     activeNotes:  [ NoteObject, … ],
 *     trashedNotes: [ NoteObject, … ]
 *   }
 *
 * NoteObject (active):
 *   id:                 string (UUID)
 *   content:            string (first line is displayed as title in the app)
 *   creationDate:       string (ISO 8601)
 *   lastModified:       string (ISO 8601)
 *   pinned:             boolean
 *   markdown:           boolean (per-note markdown toggle)
 *   tags:               string[]
 *   collaboratorEmails: string[] (shared-with addresses)
 *
 * Trashed notes have the same core fields but may lack pinned/markdown/
 * collaboratorEmails (stripped on trash in some export versions).
 *
 * Title extraction: Simplenote has no separate title field - the first
 * line of `content` serves as the visible title in their UI. We split on
 * the first newline: line 1 → title, remainder → body. This matches what
 * the user saw in Simplenote and gives PrivacyNotes a real title field
 * rather than relying on first-line derivation for every note.
 */

interface SnNote {
  id?: string;
  content?: string;
  creationDate?: string;
  lastModified?: string;
  pinned?: boolean;
  markdown?: boolean;
  tags?: string[];
  collaboratorEmails?: string[];
}

interface SnExport {
  activeNotes?: SnNote[];
  trashedNotes?: SnNote[];
}

export const simplenoteImporter: Importer = {
  id: 'simplenote',
  label: 'Simplenote',
  description:
    'Export from Simplenote (Settings -> Tools -> Export Notes). Drop the .zip.',
  accept: '.zip,.json,application/zip,application/json',
  enabled: true,
  sourceTag: 'simplenote',

  async parse(file, onProgress) {
    onProgress?.('Reading file…');
    const jsonText = await extractNotesJson(file, onProgress);

    onProgress?.('Parsing JSON…');
    let data: SnExport;
    try {
      data = JSON.parse(jsonText) as SnExport;
    } catch {
      throw new Error(
        'That file is not valid JSON. Make sure you picked the Simplenote export zip or its notes.json file.'
      );
    }

    const active = Array.isArray(data?.activeNotes) ? data.activeNotes : [];
    const trashed = Array.isArray(data?.trashedNotes) ? data.trashedNotes : [];

    if (active.length === 0 && trashed.length === 0) {
      throw new Error(
        'No notes found. Expected a Simplenote export with "activeNotes" and/or "trashedNotes" arrays.'
      );
    }

    onProgress?.('Building notes…');
    const notes: ImportedNote[] = [];
    const warnings: string[] = [];

    let emptyCount = 0;
    let untaggedCount = 0;
    let linkifiedCount = 0;
    let starredCount = 0;
    let trashedImportCount = 0;
    let blankGhostCount = 0;
    let markdownCount = 0;
    let collaboratorCount = 0;

    const processNote = (raw: SnNote, isTrashed: boolean) => {
      const rawContent = raw.content ?? '';

      // Split first line as title, rest as body.
      const newlineIdx = rawContent.indexOf('\n');
      let rawTitle: string;
      let rawBody: string;
      if (newlineIdx === -1) {
        // Single-line note: entire content is the title, body is empty.
        rawTitle = rawContent.trim();
        rawBody = '';
      } else {
        rawTitle = rawContent.slice(0, newlineIdx).trim();
        rawBody = rawContent.slice(newlineIdx + 1).replace(/^\n+/, '');
      }

      // Strip leading markdown heading markers from the title if present
      // (some users prefix with "# " in Simplenote's markdown mode).
      rawTitle = rawTitle.replace(/^#{1,6}\s+/, '');

      // Blank ghost: no title, no body. Skip silently.
      if (!rawTitle && !rawBody.trim()) {
        blankGhostCount++;
        return;
      }

      const rawTags = Array.isArray(raw.tags) ? raw.tags : [];
      const pinned = raw.pinned === true;
      const isMarkdown = raw.markdown === true;
      const collabs = Array.isArray(raw.collaboratorEmails)
        ? raw.collaboratorEmails.filter((e) => typeof e === 'string' && e.trim())
        : [];

      if (!rawBody.trim()) emptyCount++;
      if (rawTags.length === 0) untaggedCount++;
      if (pinned) starredCount++;
      if (isTrashed) trashedImportCount++;
      if (isMarkdown) markdownCount++;
      if (collabs.length > 0) collaboratorCount++;

      // Simplenote is a plain-text editor - every \n is a real line
      // break the user sees. TipTap's markdown parser collapses single
      // \n into spaces (only \n\n creates paragraph breaks). Insert
      // <br> tags for single newlines so tiptap-markdown (html: true)
      // creates hardBreak nodes within the same paragraph - giving
      // tight line spacing that matches Simplenote's rendering.
      // Double+ newlines (paragraph breaks) are left untouched.
      // Skip lines that start markdown block syntax (lists, headings,
      // blockquotes, code fences) - <br> before those breaks parsing.
      const hardBroken = rawBody.replace(
        /(?<!\n)\n(?!\n)/g,
        (_, offset) => {
          const after = rawBody.slice(offset + 1);
          // Don't insert <br> before markdown block-level syntax.
          if (/^(?:[-*+] |\d+\. |#{1,6} |> |```)/.test(after)) return '\n';
          return '<br>\n';
        },
      );

      // Linkify bare URLs so they render as clickable on first load.
      const body = linkifyMarkdown(hardBroken);
      if (body !== hardBroken) linkifiedCount++;

      notes.push({
        title: rawTitle,
        body,
        tags: normalizeTagList(rawTags),
        createdAt: isoOrNow(raw.creationDate),
        updatedAt: isoOrNow(raw.lastModified ?? raw.creationDate),
        starred: pinned,
        trashed: isTrashed,
      });
    };

    for (const n of active) processNote(n, false);
    for (const n of trashed) processNote(n, true);

    // Transforms (accent-colored, positive).
    const transforms: string[] = [];
    if (linkifiedCount > 0) {
      transforms.push(
        `Made URLs clickable in ${linkifiedCount} note${linkifiedCount === 1 ? '' : 's'}.`
      );
    }
    if (starredCount > 0) {
      transforms.push(
        `Kept ${starredCount} pinned note${starredCount === 1 ? '' : 's'} as starred.`
      );
    }
    if (trashedImportCount > 0) {
      transforms.push(
        `Restored ${trashedImportCount} trashed note${trashedImportCount === 1 ? '' : 's'} into the trash.`
      );
    }
    if (markdownCount > 0) {
      transforms.push(
        `${markdownCount} note${markdownCount === 1 ? '' : 's'} had Simplenote's markdown mode enabled.`
      );
    }

    // Warnings (amber-colored, potential issues).
    if (blankGhostCount > 0) {
      warnings.push(
        `Skipped ${blankGhostCount} blank note${blankGhostCount === 1 ? '' : 's'} with no content.`
      );
    }
    if (collaboratorCount > 0) {
      warnings.push(
        `${collaboratorCount} note${collaboratorCount === 1 ? '' : 's'} had collaborators. Sharing info was not imported (PrivacyNotes has no collaboration feature).`
      );
    }

    const uniqueTags = new Set<string>();
    for (const n of notes) for (const t of n.tags) uniqueTags.add(t);

    return {
      notes,
      warnings,
      transforms,
      stats: {
        totalNotes: notes.length,
        emptyNotes: emptyCount,
        untaggedNotes: untaggedCount,
        uniqueTags: uniqueTags.size,
      },
      source: 'simplenote',
    } satisfies ParsedImport;
  },
};

/**
 * Extract the notes.json payload from whatever the user gave us:
 *   - .zip containing source/notes.json
 *   - the notes.json file directly
 */
async function extractNotesJson(
  file: File,
  onProgress?: (m: string) => void
): Promise<string> {
  const lowerName = file.name.toLowerCase();

  if (lowerName.endsWith('.zip')) {
    onProgress?.('Unzipping…');
    const zip = await JSZip.loadAsync(file);

    // Look for source/notes.json first (official export structure).
    let entry = zip.file('source/notes.json');
    // Fall back to notes.json at root in case the user re-zipped.
    if (!entry) entry = zip.file('notes.json');
    // Last resort: find any .json file that looks like the export.
    if (!entry) {
      const candidates = Object.values(zip.files).filter(
        (f) => !f.dir && f.name.toLowerCase().endsWith('.json')
      );
      if (candidates.length === 1) entry = candidates[0]!;
    }

    if (!entry) {
      throw new Error(
        'This zip doesn\'t contain a "source/notes.json" file. Make sure you picked the Simplenote export zip.'
      );
    }
    return zipEntryText(entry);
  }

  // .json or anything else - read as text.
  return file.text();
}

/**
 * Normalize tags through the shared pipeline with case-insensitive dedup.
 */
function normalizeTagList(rawTags: string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of rawTags) {
    const tag = normalizeTag(raw);
    if (!tag) continue;
    const key = tag.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(tag);
  }
  return out;
}

function isoOrNow(s: string | undefined): string {
  if (!s) return new Date().toISOString();
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return new Date().toISOString();
  return d.toISOString();
}
