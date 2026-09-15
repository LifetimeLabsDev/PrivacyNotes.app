import JSZip from 'jszip';
import { zipEntryText } from './zipEntry';
import { normalizeTag } from '../notesRepo';
import { linkifyMarkdown } from './linkify';
import { importBlobs } from './blobImport';
import { ARCHIVED_TAG } from './types';
import type { Importer, ImportedNote, ParsedImport } from './types';

/**
 * Google Keep import adapter.
 *
 * Reads a Google Takeout export. Two accepted shapes:
 *   (a) The raw Takeout .zip - contains a `Takeout/Keep/` folder with
 *       one .json per note plus a pile of .html mirrors we ignore.
 *   (b) A single .json file the user unzipped and dropped on us.
 *
 * Keep stores each note as its own JSON blob. The shape we care about:
 *
 *   {
 *     "title":        "…",
 *     "textContent":  "…",          // plain text body (absent for lists)
 *     "textContentHtml": "<p>…</p>", // styled HTML - used when it has formatting
 *     "listContent":  [ { text, isChecked }, … ],  // checklist items (tasks)
 *     "isPinned":     true | false,  // Keep's "pinned to top" flag
 *     "isArchived":   true | false,  // Keep's "archive" flag (hidden view)
 *     "isTrashed":    true | false,  // Keep's trash
 *     "color":        "DEFAULT" | "RED" | …,  // UI accent, discarded
 *     "labels":       [ { "name": "work" }, … ],   // flat tag list
 *     "createdTimestampUsec":     1775902197012000, // microseconds
 *     "userEditedTimestampUsec":  1775902572714000
 *   }
 *
 * Flag mapping → PrivacyNotes:
 *   - isPinned   → starred (Keep has no separate "favorite"; pinned is
 *                  the only "this matters" bit - same call we made for SN)
 *   - isTrashed  → trashed
 *   - isArchived → active + `archived` tag (no archive view yet, and the
 *                  trash auto-purges, so trashing them would delete them)
 *   - labels[].name → tags (through shared normalizeTagList)
 *
 * Lists (`listContent`) are handled via a heuristic because Keep uses
 * the same shape for real checklists and for plain text notes that
 * happen to have bullets:
 *   - Any unchecked item present → treat as real task list. Each item
 *     becomes `- [ ]` / `- [x]`. TipTap renders native checkboxes.
 *   - All items checked (a "completed memory log" - trip notes,
 *     journals, historical lists) → import as plain prose, one line
 *     per item, no checkboxes. These were the old "notes" the user
 *     expects as text, not todos.
 * If a note has BOTH textContent and listContent, we concatenate text
 * first, blank line, then list - no data loss.
 */

interface KeepLabel {
  name?: string;
}

interface KeepListItem {
  text?: string;
  isChecked?: boolean;
}

interface KeepAttachment {
  filePath?: string;
  mimetype?: string;
}

interface KeepNote {
  title?: string;
  textContent?: string;
  textContentHtml?: string;
  listContent?: KeepListItem[];
  attachments?: KeepAttachment[];
  isPinned?: boolean;
  isArchived?: boolean;
  isTrashed?: boolean;
  color?: string;
  labels?: KeepLabel[];
  createdTimestampUsec?: number;
  userEditedTimestampUsec?: number;
}

export const googleKeepImporter: Importer = {
  id: 'google-keep',
  label: 'Google Keep',
  description:
    'Google Takeout .zip (Keep folder) or a single .json note. Text notes and checklists both come across. Checklists import as native task lists with checkboxes.',
  accept: '.zip,.json,application/zip,application/json',
  enabled: true,
  sourceTag: 'google',

  async parse(file, onProgress) {
    onProgress?.('Reading file…');
    const { noteBlobs, imageBlobs } = await extractKeepNotes(file, onProgress);

    if (noteBlobs.length === 0) {
      throw new Error(
        'No Keep notes found in that file. Expected a Google Takeout .zip containing a Takeout/Keep/ folder, or a single Keep .json file.'
      );
    }

    onProgress?.('Parsing notes…');
    const notes: ImportedNote[] = [];
    const warnings: string[] = [];

    let emptyCount = 0;
    let untaggedCount = 0;
    let missingTitleCount = 0;
    let linkifiedCount = 0;
    let starredCount = 0;
    let trashedImportCount = 0;
    let archivedTaggedCount = 0;
    let checklistNoteCount = 0;
    let taskItemCount = 0;
    let proseFromListCount = 0;
    let parseFailCount = 0;
    let blankGhostCount = 0;
    let formattedCount = 0;
    let imageCount = 0;
    let missingImageCount = 0;

    for (const blob of noteBlobs) {
      let raw: KeepNote;
      try {
        raw = JSON.parse(blob.text) as KeepNote;
      } catch {
        parseFailCount++;
        continue;
      }
      if (!raw || typeof raw !== 'object') {
        parseFailCount++;
        continue;
      }

      const rawTitle = (raw.title ?? '').trim();

      // Prefer textContentHtml when it carries real formatting (bold,
      // italic, underline, strikethrough). If the HTML is just a plain
      // wrapper with no formatting tags, fall back to textContent so we
      // don't introduce structural noise.
      let rawTextBody: string;
      let noteHadFormatting = false;
      const htmlBody = (raw.textContentHtml ?? '').trim();
      if (htmlBody) {
        const { text, hadFormatting } = keepHtmlToMarkdown(htmlBody);
        if (hadFormatting) {
          rawTextBody = text;
          noteHadFormatting = true;
        } else {
          rawTextBody = raw.textContent ?? '';
        }
      } else {
        rawTextBody = raw.textContent ?? '';
      }

      const list = Array.isArray(raw.listContent) ? raw.listContent : [];

      // Collect non-empty list items. Items with no text are a Keep UI
      // artifact, not content. Track whether ANY item is unchecked -
      // that's our "this is a real todo list" signal.
      const listItems: Array<{ text: string; checked: boolean }> = [];
      let anyUnchecked = false;
      for (const item of list) {
        const text = (item?.text ?? '').trim();
        if (!text) continue;
        const checked = item?.isChecked === true;
        if (!checked) anyUnchecked = true;
        listItems.push({ text, checked });
      }

      // Heuristic: any unchecked item → real task list (imports as
      // native checkboxes). All items checked → treat as plain prose
      // (historical memory log, journal, completed trip notes). Keep
      // uses listContent for both shapes; only the checked-state
      // distribution distinguishes them in Takeout.
      let listPart = '';
      if (listItems.length > 0) {
        if (anyUnchecked) {
          listPart = listItems
            .map(({ text, checked }) => `- [${checked ? 'x' : ' '}] ${text}`)
            .join('\n');
          checklistNoteCount++;
          taskItemCount += listItems.length;
        } else {
          listPart = listItems.map(({ text }) => text).join('\n');
          proseFromListCount++;
        }
      }

      // If the note has both free text and list content, concatenate
      // text first, blank line, then the list. Real Keep exports tend
      // to have one or the other, but we don't want to silently drop
      // either if they coexist.
      const textPart = rawTextBody.trim();
      let rawBody = textPart && listPart
        ? `${textPart}\n\n${listPart}`
        : textPart || listPart;

      // Prepend image references for any attachments. Keep displays
      // images at the top of the note (like a cover image), so we
      // place them before the text body. Each image gets a markdown
      // `![](keepimg:{basename})` placeholder that the post-apply
      // blob import rewrites to `pn:img/{uuid}`.
      const attachments = Array.isArray(raw.attachments) ? raw.attachments : [];
      let imagePart = '';
      for (const att of attachments) {
        const fp = (att?.filePath ?? '').trim();
        if (!fp) continue;
        const basename = fp.split('/').pop() ?? fp;
        if (imageBlobs.has(`keepimg:${basename}`)) {
          imagePart = imagePart
            ? `${imagePart}\n\n![](keepimg:${basename})`
            : `![](keepimg:${basename})`;
          imageCount++;
        } else {
          missingImageCount++;
        }
      }
      if (imagePart) {
        rawBody = rawBody ? `${imagePart}\n\n${rawBody}` : imagePart;
      }

      // Blank ghost: no title, no body, no checklist items. Keep users
      // end up with these when they make a note, clear it, and forget
      // to delete it. They're usually archived. Skip silently with a
      // warning count - importing them as "Untitled" empties just
      // clutters the trash.
      if (!rawTitle && !rawBody) {
        blankGhostCount++;
        continue;
      }

      const rawTags = (raw.labels ?? [])
        .map((l) => (l?.name ?? '').trim())
        .filter((n) => n.length > 0);

      const pinned = raw.isPinned === true;
      // Archived in Keep means out of sight but kept on purpose.
      // PrivacyNotes has no archive view, and routing these to the trash
      // would hand them straight to the auto-purge, which permanently
      // deletes anything that outlives the retention window - so
      // "archive" would quietly mean "delete in 30 days". Import them as
      // ordinary notes carrying an `archived` tag instead: nothing is
      // destroyed, and the tag gives a one-click filter that behaves
      // like the archive they came from.
      const archived = raw.isArchived === true;
      const trashed = raw.isTrashed === true;

      if (!rawTitle) missingTitleCount++;
      if (!rawBody.trim()) emptyCount++;
      if (rawTags.length === 0) untaggedCount++;
      if (pinned) starredCount++;
      if (trashed) trashedImportCount++;
      if (archived) archivedTaggedCount++;
      if (noteHadFormatting) formattedCount++;

      // Same linkify pass we run on every importer - Keep stores bare
      // URLs as plain text, but we render markdown so we need to wrap
      // them in autolink syntax so they click on first render.
      const body = linkifyMarkdown(rawBody);
      if (body !== rawBody) linkifiedCount++;

      notes.push({
        // Pass title through verbatim - including empty. Google Keep
        // leaves the title field empty when the user never set one; we
        // used to fabricate "Untitled" here, which looked like a real
        // user-set title and masked the live first-line derivation that
        // handles titleless notes everywhere else. Now an empty source
        // title stays empty and the derivation in NotesView does its job.
        title: rawTitle,
        body,
        tags: normalizeTagList(archived ? [...rawTags, ARCHIVED_TAG] : rawTags),
        createdAt: usecToIso(raw.createdTimestampUsec),
        updatedAt: usecToIso(
          raw.userEditedTimestampUsec ?? raw.createdTimestampUsec
        ),
        starred: pinned,
        trashed,
      });
    }

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
    if (archivedTaggedCount > 0) {
      transforms.push(
        `Tagged ${archivedTaggedCount} archived note${archivedTaggedCount === 1 ? '' : 's'} "${ARCHIVED_TAG}" and kept ${archivedTaggedCount === 1 ? 'it' : 'them'} out of the trash.`
      );
    }

    if (formattedCount > 0) {
      transforms.push(
        `Preserved bold, italic, underline, and strikethrough in ${formattedCount} note${formattedCount === 1 ? '' : 's'}.`
      );
    }
    if (checklistNoteCount > 0) {
      const n = checklistNoteCount;
      const i = taskItemCount;
      transforms.push(
        `Converted ${i} task${i === 1 ? '' : 's'} across ${n} checklist${n === 1 ? '' : 's'} into native task lists (checked state preserved).`
      );
    }
    if (proseFromListCount > 0) {
      transforms.push(
        `Imported ${proseFromListCount} completed list${proseFromListCount === 1 ? '' : 's'} as plain text (all items were already checked, treated as a memory log, not a todo).`
      );
    }
    if (blankGhostCount > 0) {
      warnings.push(
        `Skipped ${blankGhostCount} blank note${blankGhostCount === 1 ? '' : 's'} with no title and no body.`
      );
    }
    if (missingTitleCount > 0) {
      warnings.push(
        `${missingTitleCount} note${missingTitleCount === 1 ? '' : 's'} had no title. A title will be derived from the first line.`
      );
    }
    if (parseFailCount > 0) {
      warnings.push(
        `${parseFailCount} file${parseFailCount === 1 ? '' : 's'} couldn't be parsed as JSON and were skipped.`
      );
    }
    if (imageCount > 0) {
      transforms.push(
        `Found ${imageCount} image${imageCount === 1 ? '' : 's'} to import.`
      );
    }
    if (missingImageCount > 0) {
      warnings.push(
        `${missingImageCount} image${missingImageCount === 1 ? '' : 's'} referenced in notes but not found in the zip.`
      );
    }

    const uniqueTags = new Set<string>();
    for (const n of notes) for (const t of n.tags) uniqueTags.add(t);

    // Compute blob byte total for quota preflight.
    let blobBytes = 0;
    for (const [, blob] of imageBlobs) blobBytes += blob.data.length;

    const parsed: ParsedImport = {
      notes,
      warnings,
      transforms,
      stats: {
        totalNotes: notes.length,
        emptyNotes: emptyCount,
        untaggedNotes: untaggedCount,
        uniqueTags: uniqueTags.size,
      },
      source: 'google-keep',
      ...(imageBlobs.size > 0 ? { blobs: imageBlobs, blobBytes } : {}),
    };
    return parsed;
  },
};

interface KeepBlob {
  name: string;
  text: string;
}

/** MIME types we can import as images. */
const IMAGE_EXT = /\.(png|jpe?g|gif|webp|bmp|svg)$/i;

function mimeFromExt(path: string): string {
  const ext = path.split('.').pop()?.toLowerCase() ?? '';
  const map: Record<string, string> = {
    png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg',
    gif: 'image/gif', webp: 'image/webp', bmp: 'image/bmp',
    svg: 'image/svg+xml',
  };
  return map[ext] ?? 'application/octet-stream';
}

interface ExtractResult {
  noteBlobs: KeepBlob[];
  imageBlobs: Map<string, { data: Uint8Array; mime: string; name: string }>;
}

/**
 * Pull the individual Keep note JSON blobs out of whatever the user
 * handed us, plus any image attachments referenced by those notes.
 *
 * Three paths for notes:
 *   1. .zip  → walk entries, grab any .json that looks like a Keep note.
 *              Google Takeout puts them under "Takeout/Keep/" but users
 *              sometimes re-zip a subset, so we match by content shape
 *              (has `color` + one of textContent/listContent + *Usec
 *              timestamps) rather than by path.
 *   2. .json → treat as a single note (no images possible).
 *   3. fallback → try to parse as JSON; fail loudly if it isn't.
 */
async function extractKeepNotes(
  file: File,
  onProgress?: (m: string) => void
): Promise<ExtractResult> {
  const lowerName = file.name.toLowerCase();
  const imageBlobs = new Map<string, { data: Uint8Array; mime: string; name: string }>();

  if (lowerName.endsWith('.zip')) {
    onProgress?.('Unzipping…');
    const zip = await JSZip.loadAsync(file);
    const noteBlobs: KeepBlob[] = [];

    // Separate JSON and image entries.
    const jsonEntries: JSZip.JSZipObject[] = [];
    const imageEntries: JSZip.JSZipObject[] = [];
    for (const entry of Object.values(zip.files)) {
      if (entry.dir) continue;
      const lower = entry.name.toLowerCase();
      if (lower.endsWith('.json')) jsonEntries.push(entry);
      else if (IMAGE_EXT.test(lower)) imageEntries.push(entry);
    }

    onProgress?.(`Reading ${jsonEntries.length} JSON file${jsonEntries.length === 1 ? '' : 's'}…`);
    for (const entry of jsonEntries) {
      const text = await zipEntryText(entry);
      if (!looksLikeKeepNote(text)) continue;
      noteBlobs.push({ name: entry.name, text });
    }

    // Extract image blobs. Key by the basename (what Keep's
    // attachments[].filePath references, e.g. "12345.67890.png").
    if (imageEntries.length > 0) {
      onProgress?.(`Extracting ${imageEntries.length} image${imageEntries.length === 1 ? '' : 's'}…`);
      for (const entry of imageEntries) {
        const basename = entry.name.split('/').pop() ?? entry.name;
        const data = new Uint8Array(await entry.async('uint8array'));
        imageBlobs.set(`keepimg:${basename}`, {
          data,
          mime: mimeFromExt(basename),
          name: basename,
        });
      }
    }

    return { noteBlobs, imageBlobs };
  }

  if (lowerName.endsWith('.json')) {
    const text = await file.text();
    return { noteBlobs: [{ name: file.name, text }], imageBlobs };
  }

  // Last resort - try to read as text and parse.
  const text = await file.text();
  return { noteBlobs: [{ name: file.name, text }], imageBlobs };
}

/**
 * Cheap structural check: does this JSON blob plausibly describe a
 * single Google Keep note? We don't fully parse here - just a regex
 * sniff for the two or three fields that are present on every Keep
 * export we've seen. This lets us tolerate unknown extra files in the
 * zip (Labels.json, etc.) without blowing up.
 */
function looksLikeKeepNote(text: string): boolean {
  if (!text || text.length < 20) return false;
  if (!text.trim().startsWith('{')) return false;
  // Every Keep note has a `userEditedTimestampUsec` or
  // `createdTimestampUsec`, plus one of textContent / listContent.
  const hasTimestamp =
    /"(userEditedTimestampUsec|createdTimestampUsec)"\s*:/.test(text);
  const hasBody = /"(textContent|listContent|title)"\s*:/.test(text);
  return hasTimestamp && hasBody;
}

/**
 * Keep tags are a flat array of { name } strings. They can contain
 * spaces, dashes, dots, and the occasional leading `#` - same
 * normalization pipeline we use for Standard Notes so the tag space is
 * consistent across importers.
 *
 * `normalizeTag` KEEPS case and spaces (it strips `#` and `,`, drops
 * control characters, collapses whitespace runs and clamps the length),
 * so the label the user sees in Keep is the tag they get here:
 *
 * "Solar System" → "Solar System"
 * "#Dev"         → "Dev"
 *
 * Dedupe post-normalization, case-insensitively - "Dev" and "dev" are
 * one tag and we keep the first spelling.
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

/**
 * Convert Keep's `textContentHtml` field into markdown with inline
 * formatting that TipTap understands:
 *   <b> / <strong>  → **bold**
 *   <i> / <em>      → *italic*
 *   <u>             → <u>underline</u>  (HTML passthrough for TipTap)
 *   <s> / <strike> / <del> / line-through span → ~~strikethrough~~
 *   <br>            → newline
 *   <p>             → double newline between paragraphs
 *   <li>            → newline per item (no bullets - plain prose)
 *
 * Returns `{ text, hadFormatting }`. When `hadFormatting` is false the
 * caller should fall back to `textContent` (the HTML was just a plain
 * wrapper with no real formatting).
 */
function keepHtmlToMarkdown(html: string): { text: string; hadFormatting: boolean } {
  const doc = new DOMParser().parseFromString(html, 'text/html');
  let hadFormatting = false;

  function walk(node: Node): string {
    if (node.nodeType === Node.TEXT_NODE) {
      return node.textContent ?? '';
    }
    if (node.nodeType !== Node.ELEMENT_NODE) return '';

    const el = node as Element;
    const tag = el.tagName.toLowerCase();

    // For spans, detect CSS-based formatting. Google Keep Takeout
    // uses inline styles (font-weight:700, font-style:italic) rather
    // than semantic <b>/<i> tags.
    const style = tag === 'span' ? (el.getAttribute('style') ?? '') : '';
    const isStrikeSpan = tag === 'span' && style.includes('line-through');
    const isBoldSpan =
      tag === 'span' &&
      (/font-weight:\s*(700|800|900|bold)/.test(style));
    const isItalicSpan =
      tag === 'span' && /font-style:\s*italic/.test(style);
    const isUnderlineSpan =
      tag === 'span' &&
      !isStrikeSpan &&
      /text-decoration[^:]*:\s*[^;]*underline/.test(style);

    const inner = Array.from(el.childNodes).map(walk).join('');

    switch (tag) {
      case 'b':
      case 'strong':
        if (inner.trim()) hadFormatting = true;
        return `**${inner}**`;
      case 'i':
      case 'em':
        if (inner.trim()) hadFormatting = true;
        return `*${inner}*`;
      case 'u':
        if (inner.trim()) hadFormatting = true;
        return `<u>${inner}</u>`;
      case 's':
      case 'strike':
      case 'del':
        if (inner.trim()) hadFormatting = true;
        return `~~${inner}~~`;
      case 'br':
        return '\n';
      case 'p':
      case 'div':
        return inner + '\n\n';
      case 'li':
        return inner + '\n';
      case 'ul':
      case 'ol':
        return inner;
      default: {
        if (!inner.trim()) return inner;
        // Apply CSS-detected formatting. Multiple can stack (bold+italic).
        let result = inner;
        if (isStrikeSpan) { hadFormatting = true; result = `~~${result}~~`; }
        if (isUnderlineSpan) { hadFormatting = true; result = `<u>${result}</u>`; }
        if (isItalicSpan) { hadFormatting = true; result = `*${result}*`; }
        if (isBoldSpan) { hadFormatting = true; result = `**${result}**`; }
        return result;
      }
    }
  }

  // Walk from <body> to skip the implicit wrapper DOMParser creates.
  const raw = walk(doc.body).replace(/\n{3,}/g, '\n\n').trim();
  return { text: raw, hadFormatting };
}

/**
 * Keep timestamps are Unix epoch microseconds (1/1,000,000 of a
 * second). Divide by 1000 to get JavaScript's milliseconds, build a
 * Date, spit out ISO. If it's missing or invalid, fall back to now.
 */
function usecToIso(usec: number | undefined): string {
  if (typeof usec !== 'number' || !Number.isFinite(usec) || usec <= 0) {
    return new Date().toISOString();
  }
  const ms = Math.floor(usec / 1000);
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return new Date().toISOString();
  return d.toISOString();
}
