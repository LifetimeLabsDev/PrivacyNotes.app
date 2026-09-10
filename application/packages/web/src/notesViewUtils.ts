/**
 * Pure utility functions for the notes list - display titles, excerpts,
 * date formatting. Extracted from NotesView.tsx for maintainability.
 */

import type { LocalNote } from './db';
import { indexedBodyText, isPhraseQuery } from './search';
import type { ListPrefs } from './listPrefs';
import { formatBytes } from './formatBytes';
import i18n from './i18n';
import { intlLocale } from './languages';
import { parseLinkBody, linkDomain } from './linkBody';
import { contactDisplayName, contactPhotoBytes, contactSecondLine, parseContactBody } from './contactBody';

/** Regex to match pn:file/ links in note bodies. */
const FILE_LINK_STRIP = /\[[^\]]*\]\(pn:file\/[0-9a-f-]{36}\)/g;

/** Regex to extract size strings from pn:file/ links: [name|size|mime](pn:file/uuid) */
const ATT_SIZE_RE = /\[[^|]*\|([^|]*)\|[^\]]*\]\(pn:file\/[0-9a-f-]{36}\)/g;

/** Parse a pre-formatted size string like "42.2 MB" back to bytes. */
function parseSizeToBytes(s: string): number {
  const n = parseFloat(s) || 0;
  if (!n) return 0;
  const lower = s.toLowerCase();
  if (lower.includes('gb')) return n * 1000 * 1000 * 1000;
  if (lower.includes('mb')) return n * 1000 * 1000;
  if (lower.includes('kb')) return n * 1000;
  return n;
}

// ── Server-cost estimation ────────────────────────────────────────
//
// The storage bar reads server-tracked counters:
//   total_bytes  = octet_length(base64-encoded ciphertext) per note
//   image_bytes  = encrypted blob byte count per image/attachment
//
// To make per-note sizes sum to the bar, we estimate the same values
// client-side. Spec: ops/docs/supabase.md (quota tracking)

/** Estimate base64(encrypt(json)) byte count - what the server stores
 *  in the `ciphertext` text column and measures with octet_length(). */
function estimateCiphertextBytes(payload: Record<string, unknown>): number {
  const jsonBytes = new Blob([JSON.stringify(payload)]).size;
  const encrypted = jsonBytes + 16; // xchacha20poly1305 auth tag
  return Math.ceil(encrypted / 3) * 4; // base64 encoding
}

/** Estimate encrypted blob size for an image or attachment as Storage
 *  measures it (stored as binary, not base64): the 24-byte nonce
 *  encryptBlob prepends plus the 16-byte poly1305 auth tag.
 *  Spec: packages/shared/src/blob.ts (encryptBlob output layout). */
export function estimateBlobBytes(originalSize: number): number {
  return originalSize + 24 + 16;
}

/** Sum estimated server-side blob costs for all pn:file/ attachments
 *  referenced in a note body. Images (pn:img/) don't carry size
 *  metadata in the body so they're excluded - their cost is tracked
 *  separately by adjust_blob_bytes RPCs on upload. */
function sumAttachmentBlobBytes(body: string): number {
  let total = 0;
  ATT_SIZE_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = ATT_SIZE_RE.exec(body)) !== null) {
    total += estimateBlobBytes(parseSizeToBytes(m[1]!.trim()));
  }
  return total;
}

/**
 * Estimate the server-side `total_bytes` cost of one note: the
 * base64(encrypted json) ciphertext the notes table stores. The payload
 * shape mirrors sync's buildRow - keep the two in step or the estimate
 * drifts from what the server measures (verified within ~3% of
 * octet_length(ciphertext) on a real vault, 2026-08-17).
 */
function estimateNoteCiphertextBytes(n: LocalNote): number {
  const payload: Record<string, unknown> = {
    title: n.title, body: n.body, tags: n.tags,
    trashed: n.trashed === 1, starred: n.starred === 1,
    locked: n.locked === 1, pinProtected: n.pinProtected === 1,
    type: n.type ?? 'note',
  };
  if (n.trackers) payload.trackers = n.trackers;
  // encryptNote OMITS folderId when unset - mirror that, or every unfiled
  // note is overestimated by the bytes of '"folderId":null'.
  if (n.folderId) payload.folderId = n.folderId;
  return estimateCiphertextBytes(payload);
}

/**
 * Estimate the stored ciphertext cost of a bare title/body/tags triple -
 * the import pre-flight's per-note unit. Same payload shape as
 * encryptNote with default flags; attachment blobs are NOT included
 * (importers count staged blob bytes separately).
 */
export function estimateNoteStoredBytes(
  title: string, body: string, tags: string[],
): number {
  return estimateCiphertextBytes({
    title, body, tags,
    trashed: false, starred: false, locked: false, pinProtected: false,
    type: 'note',
  });
}

/**
 * Estimate total server-side storage cost of a note:
 * base64(encrypted ciphertext) + encrypted attachment blobs.
 * Matches the server's total_bytes + image_bytes accounting.
 */
export function computeNoteTotalSize(n: LocalNote): number {
  const body = n.body ?? '';
  // A contact's photo is an image blob, and the body records its size.
  const photo = n.type === 'contact' ? contactPhotoBytes(body) : 0;
  return estimateNoteCiphertextBytes(n) + sumAttachmentBlobBytes(body) + (photo > 0 ? estimateBlobBytes(photo) : 0);
}

/**
 * `computeNoteTotalSize`, memoized per note object.
 *
 * The ONE size measure: what the row displays and what the size sort orders by
 * have to be the same number, or sorting by size produces a list whose visible
 * sizes are not in order. They were not: the sort used `body.length`, a
 * character count that ignores attachments entirely, while the row showed
 * storage cost. Sorting a vault by size put a 2 KB note above a 1.3 KB one.
 *
 * Cached because the sort calls this O(n log n) times over a whole vault and
 * the estimate walks the note. The key is the note OBJECT, which `displayNotes`
 * keeps stable for anything that did not change - the same property `NoteRow`'s
 * memo already depends on - so an edited note simply misses and recomputes.
 */
const noteSizeCache = new WeakMap<LocalNote, number>();
function noteSizeBytes(n: LocalNote): number {
  const hit = noteSizeCache.get(n);
  if (hit !== undefined) return hit;
  const total = computeNoteTotalSize(n);
  noteSizeCache.set(n, total);
  return total;
}

/**
 * Estimate server-side storage cost from a note snapshot (version
 * history). Only title/body/tags are available - other fields use
 * zero-defaults, so the estimate is off by a few bytes at most.
 */
export function computeSnapshotTotalSize(
  title: string, body: string, tags: string[],
): number {
  const payload: Record<string, unknown> = {
    title, body, tags,
    trashed: false, starred: false, locked: false, pinProtected: false,
    type: 'note',
  };
  return estimateCiphertextBytes(payload) + sumAttachmentBlobBytes(body);
}

/** Strip HTML tags and decode common entities, returning only text content. */
function stripHtml(line: string): string {
  return line.replace(/<[^>]*>/g, '').replace(/&nbsp;/g, ' ');
}

/** Count file links in a note body. */
export function fileCount(body: string): number {
  const matches = body.match(FILE_LINK_STRIP);
  return matches ? matches.length : 0;
}

// Extract a human-friendly label from the first image in markdown body.
// Returns e.g. "IMG7461.jpeg|3.4 MB|image/jpeg" or just the alt text.
// Used as a last-resort excerpt when the body is image-only.
function imageExcerpt(body: string): string {
  const m = body.match(/!\[([^\]]*)\]\([^)]*\)(\{[^}\n]*\})?/);
  if (!m || !m[1]) return '';
  const alt = m[1].trim();
  if (!alt) return i18n.t('shell:fileTypes.image');
  // Alt text often contains "filename|size|mime" - show just the filename
  const first = alt.split('|')[0];
  return (first ?? '').trim() || i18n.t('shell:fileTypes.image');
}

// Strips cheap inline markdown (link syntax, inline formatting markers)
// out of a single line so the notes-list previews don't leak raw
// markdown like `[google.com](http://google.com)` at the user.
// Intentionally not a full parser - just the common cases that make
// previews look noisy.
function stripInlineMarkdown(line: string): string {
  return line
    // ![alt](url){width=N align=X} -> "" - strip image references entirely
    // (before links, otherwise the link regex eats the inner [alt](url)
    // and leaves `!`). The optional suffix carries size and alignment; it
    // must be matched generically or a preview shows a stray `{align=center}`.
    .replace(/!\[([^\]]*)\]\([^)]*\)(\{[^}\n]*\})?/g, '')
    // [name|size|mime](pn:file/...) -> friendly label based on mimetype
    .replace(/\[[^\]]*\|[^\]]*\|([^\]]*)\]\(pn:file\/[^)]*\)/g, (_m, mime: string) => {
      const mt = mime.trim().toLowerCase();
      if (mt.startsWith('audio/')) return i18n.t('shell:fileTypes.audioRecording');
      if (mt.startsWith('video/')) return i18n.t('shell:fileTypes.video');
      if (mt.startsWith('image/')) return i18n.t('shell:fileTypes.image');
      if (mt.includes('pdf')) return i18n.t('shell:fileTypes.pdfDocument');
      return i18n.t('shell:fileTypes.attachment');
    })
    // [text](url) -> text
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    // [[note link]] -> note link
    .replace(/\[\[([^\]]+)\]\]/g, '$1')
    // <http://...> autolink -> http://...
    .replace(/<((?:https?|mailto):[^>\s]+)>/g, '$1')
    // lingering bold/italic/code/strikethrough markers
    .replace(/[*_`~]/g, '')
    // trailing backslash (markdown hard line break)
    .replace(/\\$/g, '');
}

/**
 * Drop the block-level markdown markers a preview line can start with.
 *
 * The markers nest, so one fixed-order pass is not enough: a blockquote
 * holding a heading (`> # Sunday`) had its heading rule run first, matched
 * nothing, and the line reached the notes list as "# Sunday". Containers
 * are peeled in a loop, then the leaf marker once.
 */
function stripBlockMarkers(line: string): string {
  let out = line;
  // Containers nest in either order - a quote can hold a list, a list item
  // can hold a quote - so peel one marker per pass until a pass is a no-op.
  for (;;) {
    const next = out
      .replace(/^>\s+/, '')
      .replace(/^[-*+]\s+/, '')
      .replace(/^\d+\.\s+/, '');
    if (next === out) break;
    out = next;
  }
  // Leaf markers, once only. A heading holds inline content, so no block
  // marker can follow one, and looping here would eat the real "1." out of
  // "# 1. Introduction".
  return out
    .replace(/^#{1,6}\s+/, '')
    // Callout marker: `[!warning]-` / `[!info]+ Title` -> drop the marker so
    // previews show the title (or fall through to the body).
    .replace(/^\[!\w+\][+-]?\s*/, '');
}

// Strip the markdown task checkbox (`[ ]` / `[x]`) when it appears at
// the very start of a line, after the list marker has already been
// removed by firstBodyLine(). Keeps note-list previews from leaking
// raw checkbox syntax like "[ ] buy milk" at the user.
function stripTaskMarker(line: string): string {
  return line.replace(/^\[([ xX])\]\s?/, '');
}

/**
 * Reduce one line of a note body to the plain text a preview may show.
 *
 * Every preview in the app goes through here, and that is the point. The
 * four passes only work as a set: block markers first (they sit at the
 * front of the line), then the task checkbox they were hiding, then
 * inline markdown, then HTML last. Call one pass on its own and the
 * preview leaks whatever the other three own - the Tasks list used
 * `stripInlineMarkdown` alone and printed a raw `<mark style="...">` at
 * the user, because the editor writes a highlight as HTML, not markdown.
 */
export function stripToPlainText(line: string): string {
  return stripHtml(
    stripInlineMarkdown(stripTaskMarker(stripBlockMarkers(line))),
  ).trim();
}

/**
 * Whether a note says `query` as typed: several terms (`isPhraseQuery`), in
 * that order, within one line of the text the index reads
 * (`indexedBodyText`, so a vault password is never consulted) or in the
 * title. Case, runs of whitespace and inline markup do not count, because
 * the reader is matching what the editor shows; the raw line is tried too,
 * for a string the stripper would eat, like a name with underscores. One
 * term is never a phrase. The list holds only the hits that say the phrase
 * (GitHub #288).
 */
export function noteSaysPhrase(n: LocalNote, query: string): boolean {
  if (!isPhraseQuery(query)) return false;
  const phrase = query.trim().replace(/\s+/g, ' ').toLowerCase();
  const says = (text: string) => text.replace(/\s+/g, ' ').toLowerCase().includes(phrase);
  if (says(n.title)) return true;
  for (const line of indexedBodyText(n).split(/\r?\n/)) {
    if (says(stripToPlainText(line)) || says(line)) return true;
  }
  return false;
}

// First non-empty line of the body, stripped of the cheapest markdown
// syntax (#, *, _, backtick, list markers, link syntax). Used as the
// auto-title fallback, as the excerpt seed, and by any other preview
// that has a body string but no note to hand it to.
export function firstBodyLine(body: string): string {
  if (!body) return '';
  const lines = body.split(/\r?\n/);
  for (const line of lines) {
    const t = line.trim();
    if (!t) continue;
    const cleaned = stripToPlainText(t);
    if (cleaned) return cleaned;
  }
  return '';
}

/**
 * The title a note's own content spells, or '' when it spells none.
 *
 * Split from `deriveDisplayTitle` because the two answers are used for
 * opposite purposes and only one of them may ever be a placeholder. NotesView
 * COMMITS this value into the note's `title` field when the user leaves an
 * untitled note, and syncs it, so a placeholder returned here becomes the
 * user's own data on every device. Return nothing rather than a stand-in, and
 * let the caller that renders supply the stand-in.
 */
export function deriveTitleFromContent(n: LocalNote): string {
  const t = (n.title ?? '').trim();
  if (t) return t;
  // Bookmarks: the domain IS the default name (render-time fallback, per
  // ops/docs/plans/bookmarks-pillar.md section 2 - never stored).
  if (n.type === 'link') return linkDomain(parseLinkBody(n.body).url);
  // Contacts: the name the fields spell, else the company, else an address.
  if (n.type === 'contact') return contactDisplayName('', parseContactBody(n.body));
  // Vault items never derive one: their body is JSON, and the first line of it
  // is not a title in any language.
  if (n.type === 'login' || n.type === 'card' || n.type === 'ssh-key') return '';
  return firstBodyLine(n.body).slice(0, 80);
}

// Title shown in the notes-list row: what the content spells, else the
// stand-in for that note type. Every stand-in is translated, so a row in a
// Portuguese list does not read "Unnamed contact".
export function deriveDisplayTitle(n: LocalNote): string {
  const derived = deriveTitleFromContent(n);
  if (derived) return derived;
  if (n.type === 'contact') return i18n.t('shell:contacts.unnamed');
  if (n.type === 'login') return i18n.t('shell:vaultItem.untitledLogin');
  if (n.type === 'card') return i18n.t('shell:vaultItem.untitledCard');
  if (n.type === 'ssh-key') return i18n.t('shell:vaultItem.untitledKey');
  return i18n.t('common:state.untitled');
}

/**
 * The row's second line when the note's own content spells none: the word for
 * what that type has nothing of.
 *
 * A CONTACT is given nothing at all. That line carries a number, a company or
 * an email, and a contact with none of those still has its name on the line
 * above it, so a label there is the row calling a named person empty.
 */
export function emptyExcerptLabel(n: LocalNote): string {
  if (n.type === 'file') return i18n.t('notes:noteRow.file');
  if (n.type === 'login' || n.type === 'card' || n.type === 'ssh-key') return i18n.t('notes:noteRow.empty');
  if (n.type === 'contact') return '';
  return i18n.t('notes:noteRow.noContent');
}

/**
 * Note types whose body is JSON consumed by a form, not markdown: a bookmark's
 * `{url}`, a contact, a login, a card, an SSH key.
 *
 * Three passes ask this question - the note-link retarget, the body flush into
 * React state, and the derived-title commit - and each carried its own copy of
 * the list, which is how the contacts pillar came to be missing from all three
 * (GitHub #305). One list, one answer.
 */
export function hasStructuredBody(type: string | undefined): boolean {
  return (
    type === 'link' ||
    type === 'contact' ||
    type === 'login' ||
    type === 'card' ||
    type === 'ssh-key'
  );
}

/**
 * True when the stored title is only the name the list prints for that note
 * anyway: "Unnamed contact", "Untitled login", a bookmark's own domain.
 *
 * Those are placeholders, not names. A stored one is not empty, and every step
 * that fills a title in - the contact form on Done, the login form on URL blur
 * - only fills an empty one, so a stored placeholder freezes the field for
 * good: a contact kept "Unnamed contact" after its owner typed a real name
 * (GitHub #305). Clearing one changes nothing on screen, because the same word
 * comes back from `deriveDisplayTitle`, and it hands the field back to the form.
 *
 * The strings are matched in English whatever language the app is in, because
 * they are what the versions that stored them wrote. They are history, not the
 * stand-ins the list prints today, and they cannot change.
 * Test: tests/placeholderTitle.test.ts
 */
export function isPlaceholderTitle(n: LocalNote): boolean {
  const t = (n.title ?? '').trim();
  if (!t) return false;
  if (n.type === 'link') return t === linkDomain(parseLinkBody(n.body).url);
  if (n.type === 'contact') return t === 'Unnamed contact';
  if (n.type === 'login') return t === 'Untitled login';
  if (n.type === 'card') return t === 'Untitled card';
  if (n.type === 'ssh-key') return t === 'Untitled key';
  return false;
}

/**
 * The name a `[[note-link]]` can name, or '' for a note that has none.
 *
 * This is `deriveDisplayTitle` MINUS its placeholders, and the difference is
 * the point. "Untitled", "Untitled login" and friends are what the list prints
 * when there is nothing to print; they are not names, and offering them in the
 * `[[` menu would let two unrelated notes answer to the same link.
 *
 * A BOOKMARK is why this function exists rather than a `.title` read. A
 * bookmark stores an EMPTY title when the user gave no name, and shows its
 * domain instead - decided at render time so an edited URL can never leave a
 * stale name behind (`ops/docs/plans/bookmarks-pillar.md` section 2). So the
 * app calls it "github.com" everywhere while its stored title is '', and a
 * `.title` read made it unlinkable and unresolvable: it never appeared in the
 * autocomplete, and `[[github.com]]` typed by hand offered to create a note.
 * The domain is a real name here - it is derived from the URL, not from prose
 * - which is what separates it from a plain note's first body line.
 *
 * Used by every note-link surface: the autocomplete list, resolution, and the
 * rename pass. They must agree, so they read this. Spec: packages/web/src/noteLinks.ts
 */
export function noteLinkName(n: LocalNote): string {
  const t = (n.title ?? '').trim();
  if (t) return t;
  if (n.type === 'link') return linkDomain(parseLinkBody(n.body).url);
  return '';
}

/**
 * The ordering rule for every notes surface: pinned (starred) notes
 * float to the top regardless of the user's choice, then the chosen
 * sort field and direction.
 *
 * Every list that renders notes sorts through this. The rule used to be
 * hand-rolled per pillar, which is how the Tasks pillar ended up
 * ignoring pins (#194) and the sort pref along with them.
 */
export function compareNotes(
  a: LocalNote,
  b: LocalNote,
  prefs: ListPrefs
): number {
  if (a.starred !== b.starred) return b.starred - a.starred;
  let cmp = 0;
  if (prefs.sortField === 'title') {
    // Sort on the displayed title so "Untitled (first body line)" notes
    // sort where the user sees them, not as blank strings.
    cmp = deriveDisplayTitle(a).localeCompare(deriveDisplayTitle(b), undefined, {
      sensitivity: 'base',
      numeric: true,
    });
  } else if (prefs.sortField === 'size') {
    // The same measure the row displays - see `noteSizeBytes`.
    cmp = noteSizeBytes(a) - noteSizeBytes(b);
  } else if (prefs.sortField === 'created') {
    cmp = a.createdAt < b.createdAt ? -1 : a.createdAt > b.createdAt ? 1 : 0;
  } else {
    cmp = a.updatedAt < b.updatedAt ? -1 : a.updatedAt > b.updatedAt ? 1 : 0;
  }
  return cmp * (prefs.sortDir === 'asc' ? 1 : -1);
}

/**
 * A note's total storage size (ciphertext + attachment blobs) as a formatted
 * string, or '' when it rounds to nothing.
 *
 * Every list shows this, not just Files: the sort menu offers "Size" in every
 * pillar, and a list you can sort by a value it never displays is a list whose
 * order looks arbitrary. It is deliberately the SAME measure Files and the
 * storage meter use, so one note cannot read as two different sizes depending
 * on which pillar you are looking at.
 *
 * The Markdown pillar passes its own label instead - a file on disk has a real
 * filesystem size, and an estimate of what it would cost encrypted would be a
 * number about a note that does not exist.
 */
function deriveNoteSize(n: LocalNote): string {
  const total = noteSizeBytes(n);
  return total > 0 ? formatBytes(total) : '';
}

/**
 * The size a list row or grid tile shows, or '' for none. One rule, so the row
 * and the tile cannot drift.
 *
 * `explicit` wins and is never gated - the Markdown pillar passes its file's
 * real size on disk, and a file always shows one. A NOTE shows its size only
 * while the list is sorted by size: the rest of the time it is a byte count on
 * every row that nobody asked for, and while it is the sort key it is the only
 * way to see why the rows are in the order they are in.
 * Spec: ops/docs/ui-patterns.md (section 66)
 */
export function rowSizeLabel(n: LocalNote, sortField: string, explicit?: string): string {
  if (explicit) return explicit;
  return sortField === 'size' ? deriveNoteSize(n) : '';
}

// Excerpt shown beneath the title. If the title came from the first line
// of the body (no explicit title), skip that line so we don't repeat it.
// Login notes show the username instead of body text.
/**
 * Map a file's MIME type to a short, friendly type word (PDF, Image,
 * Audio, ...). Single source of truth for the file type word, shared by the
 * note excerpt (NoteCard) and the Files view (FilesList). The size is NOT part
 * of it - that lives on the row's meta line, in one measure, for every pillar.
 */
export function mimeToLabel(mime: string): string {
  const m = (mime || '').toLowerCase();
  if (m.startsWith('audio/')) return i18n.t('shell:fileTypes.audio');
  if (m.startsWith('video/')) return i18n.t('shell:fileTypes.video');
  if (m.startsWith('image/')) return i18n.t('shell:fileTypes.image');
  if (m.includes('pdf')) return i18n.t('shell:fileTypes.pdf');
  if (m.includes('zip') || m.includes('compress') || m.includes('archive')) return i18n.t('shell:fileTypes.archive');
  if (m.includes('document') || m.includes('word')) return i18n.t('shell:fileTypes.document');
  if (m.includes('sheet') || m.includes('excel')) return i18n.t('shell:fileTypes.spreadsheet');
  return i18n.t('shell:fileTypes.file');
}

export function deriveExcerpt(n: LocalNote): string {
  // File-type notes - show file count + friendly type.
  if (n.type === 'file') {
    const count = fileCount(n.body);
    if (count === 1) {
      // Type only. The size used to be appended here ("Image, 429.6 KB"), which
      // made a single-file row read differently from every other row in the
      // same list: its size sat in the excerpt while a note-with-attachments
      // showed one on the meta line, and the two were not even the same
      // measure - this one is the raw upload size, that one is storage cost.
      // The meta line is now the single place a size appears.
      // Extract mime from the single link: [name|size|mime](pn:file/...)
      const m = n.body.match(/\[[^|]*\|[^|]*\|([^\]]*)\]\(pn:file\//);
      return mimeToLabel((m?.[1]?.trim() || '').toLowerCase());
    }
    return i18n.t('shell:noteRow.files', { count });
  }
  if (n.type === 'login') {
    try {
      const data = JSON.parse(n.body);
      const user = typeof data.username === 'string' ? data.username : '';
      return user || i18n.t('shell:noteRow.noUsername');
    } catch { return ''; }
  }
  // Bookmarks: the full URL is the sub-line (named row shows where it goes,
  // unnamed row shows the domain as title and the URL here).
  if (n.type === 'link') {
    return parseLinkBody(n.body).url;
  }
  // Contacts: the first number, else the company, else the first email.
  if (n.type === 'contact') {
    return contactSecondLine(parseContactBody(n.body));
  }
  if (n.type === 'card') {
    try {
      const data = JSON.parse(n.body);
      return typeof data.cardholderName === 'string' && data.cardholderName
        ? data.cardholderName
        : i18n.t('shell:noteRow.noCardholder');
    } catch { return ''; }
  }
  if (n.type === 'ssh-key') {
    try {
      const data = JSON.parse(n.body);
      return typeof data.label === 'string' && data.label ? data.label : i18n.t('shell:noteRow.noLabel');
    } catch { return ''; }
  }
  const explicitTitle = (n.title ?? '').trim();
  // The literal stays English on purpose: it matches a title an IMPORTER wrote
  // (the Evernote one names an untitled note that), not a stand-in this file
  // produces. Nothing here writes it any more - `deriveTitleFromContent` never
  // returns a stand-in, and the display stand-ins are translated.
  if (explicitTitle && explicitTitle !== 'Untitled') {
    for (const line of n.body.split(/\r?\n/)) {
      const t = line.trim();
      if (!t) continue;
      const c = stripToPlainText(t);
      if (c) return c.slice(0, 80);
    }
    return imageExcerpt(n.body);
  }
  let skipped = false;
  for (const line of n.body.split(/\r?\n/)) {
    const t = line.trim();
    if (!t) continue;
    if (!skipped) {
      skipped = true;
      continue;
    }
    const c = stripToPlainText(t);
    if (c) return c.slice(0, 80);
  }
  return imageExcerpt(n.body);
}

// "Sat, 11 Apr, 12:31" (current year) or "Sat, 11 Apr 2025, 12:31" (older) -
// local timezone. The year is dropped for the current year to cut clutter;
// older items keep it so they stay unambiguous. Callers prepend "Modified ".
export function formatModified(iso: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const weekday = d.toLocaleDateString(intlLocale(), { weekday: 'short' });
  const day = d.getDate();
  const month = d.toLocaleDateString(intlLocale(), { month: 'short' });
  const yearPart = d.getFullYear() === new Date().getFullYear() ? '' : ` ${d.getFullYear()}`;
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  return `${weekday}, ${day} ${month}${yearPart}, ${hh}:${mm}`;
}

// Compact date for grid tiles: "11 Apr" (current year) or "11 Apr 2025"
// (older). No weekday or time - tiles are space-constrained, especially
// two-up on phones. Callers prepend "Modified " / "Created ".
export function formatModifiedShort(iso: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const day = d.getDate();
  const month = d.toLocaleDateString(intlLocale(), { month: 'short' });
  const yearPart = d.getFullYear() === new Date().getFullYear() ? '' : ` ${d.getFullYear()}`;
  return `${day} ${month}${yearPart}`;
}

// Platform-specific hotkey labels for the new-note shortcut.
export const isMacPlatform =
  typeof navigator !== 'undefined' &&
  /Mac|iPhone|iPad|iPod/.test(navigator.platform);
export const hotkeyKeys = isMacPlatform ? ['⌥', '⇧', 'N'] : ['Alt', 'Shift', 'N'];
export const hotkeyLabel = hotkeyKeys.join(isMacPlatform ? '' : '+');
// The spelled-out form ("Option + Shift + N") is NOT here: key-cap names are
// localized (de "Umschalt", fr "Maj"), so it lives in the notes catalog as
// footer.newNoteHintMac / footer.newNoteHintOther and is picked with
// isMacPlatform at the call site. The chips above stay code-side and symbolic.

// ── Journal entry dates ───────────────────────────────────────────
//
// A journal entry's title is user-editable free text (the shape is a
// setting - see JOURNAL_TITLE_FORMATS below), so nothing may infer the
// entry's calendar date from it. The date lives in
// `trackers.journalDate` as a local ISO string and the title is matched
// only as a fallback for entries created before that field existed.
// Spec: ops/docs/design-decisions.md (journal entry titles)

/** Local calendar date as `YYYY-MM-DD`. Never UTC: an entry belongs to
 *  the day the writer is living, not to the day in Greenwich. */
export function toLocalIso(d: Date): string {
  const pad = (n: number) => (n < 10 ? `0${n}` : String(n));
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/** The Monday of the week `now` falls in. Weeks start Monday. */
function mondayOf(now: Date): Date {
  const day = now.getDay();
  const diff = day === 0 ? 6 : day - 1;
  const monday = new Date(now);
  monday.setDate(monday.getDate() - diff);
  return monday;
}

/** This week's Monday as a local ISO date. */
export function getMondayIso(): string {
  return toLocalIso(mondayOf(new Date()));
}

/**
 * LEGACY title of this week's journal entry, e.g. "Monday, May 4, 2026".
 * Entries created before `trackers.journalDate` existed carry no date,
 * so the only way to recognise them is the exact en-US string they were
 * born with. Match new entries on the stored date instead. Do not use
 * this for anything else, and never for a title being written.
 */
function getMondayOfWeekLegacyTitle(): string {
  return mondayOf(new Date()).toLocaleDateString('en-US', {
    weekday: 'long', year: 'numeric', month: 'long', day: 'numeric',
  });
}

/** The calendar date an entry belongs to, or null if it predates the field. */
export function journalDateOf(n: LocalNote): string | null {
  const stored = (n.trackers as Record<string, unknown> | undefined)?.journalDate;
  return typeof stored === 'string' ? stored : null;
}

/** Is this the entry the Week in Review card and week reflection attach to? */
export function isWeekJournal(n: LocalNote): boolean {
  const iso = journalDateOf(n);
  return iso !== null ? iso === getMondayIso() : n.title === getMondayOfWeekLegacyTitle();
}

// ── Journal entry titles ──────────────────────────────────────────

/** Date shapes offered for new journal entry titles (GitHub #200).
 *  Rendered live in the picker, so no shape needs a translated label. */
export const JOURNAL_TITLE_FORMATS = ['long', 'iso', 'iso-weekday', 'short', 'numeric'] as const;
export type JournalTitleFormat = (typeof JOURNAL_TITLE_FORMATS)[number];

/** Longest suffix a title may carry. Sized against `TITLE_MAX_LENGTH`
 *  (200) rather than against the word "Journal": the suffix is part of a
 *  title, so a much tighter cap just truncates people mid-word with no
 *  warning. 60 plus the longest date shape ("Wednesday, September 29,
 *  2026") still lands well under the title cap, and the five live
 *  preview rows are the real guard against an absurd one. */
export const JOURNAL_SUFFIX_MAX = 60;

export function isJournalTitleFormat(v: unknown): v is JournalTitleFormat {
  return typeof v === 'string' && (JOURNAL_TITLE_FORMATS as readonly string[]).includes(v);
}

/** One date in the chosen shape, in the app's language. `locale` comes
 *  from `activeLocale()` - never the browser default, which can disagree
 *  with the language the app is being read in. Routed through
 *  `intlLocale()` before it reaches `toLocaleDateString` so Arabic renders
 *  Western digits instead of Intl's Arabic-Indic default. */
function formatJournalDate(d: Date, format: JournalTitleFormat, locale: string): string {
  const loc = intlLocale(locale);
  switch (format) {
    case 'iso':
      return toLocalIso(d);
    case 'iso-weekday':
      return `${toLocalIso(d)} ${d.toLocaleDateString(loc, { weekday: 'short' })}`;
    case 'short':
      return d.toLocaleDateString(loc, { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric' });
    case 'numeric':
      return d.toLocaleDateString(loc);
    default:
      return d.toLocaleDateString(loc, { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
  }
}

/** The title a new journal entry is born with: the date plus the
 *  user's optional suffix. */
export function journalTitle(
  d: Date,
  format: JournalTitleFormat,
  suffix: string,
  locale: string,
): string {
  const date = formatJournalDate(d, format, locale);
  const tail = suffix.trim();
  return tail ? `${date} ${tail}` : date;
}

// Empty body templates for vault item types. Shared between note creation
// and vault-type switching in NotesView.
export const VAULT_EMPTY_BODIES: Record<string, string> = {
  login: JSON.stringify({ url: '', username: '', password: '', notes: '' }),
  card: JSON.stringify({ cardholderName: '', cardNumber: '', expMonth: '', expYear: '', cvv: '', billingZip: '', notes: '' }),
  'ssh-key': JSON.stringify({ label: '', privateKey: '', publicKey: '', passphrase: '', notes: '' }),
  // A contact stores only what exists, so its empty body is the empty document.
  contact: '{}',
};
