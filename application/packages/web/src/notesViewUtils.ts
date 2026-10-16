/**
 * Pure utility functions for the notes list - display titles, excerpts,
 * date formatting. Extracted from NotesView.tsx for maintainability.
 */

import type { NoteType } from '@notes/shared';
import type { LocalNote } from './db';
import type { Space } from './spaces';
import { indexedBodyText, isPhraseQuery } from './search';
import { foldForMatch, textMatcher } from './textMatch';
import { MARKDOWN_NOTE_TYPES, isKnownNoteType } from './noteTypes';
import { SCHEDULE_KEYS, dayNumber, occurrencesOf, scheduleOf, shiftDay, spanLength, withSchedule, type Schedule } from './schedule';
export { MARKDOWN_NOTE_TYPES, isKnownNoteType } from './noteTypes';
import type { ListPrefs } from './listPrefs';
import { formatBytes } from './formatBytes';
import i18n from './i18n';
import { formatDay, formatInstant, formatPattern, toLocalIso, writtenDateLocale } from './intlFormat';
import { parseLinkBody, linkDomain } from './linkBody';
import { contactBirthday, contactDisplayName, contactPhotoBytes, contactSecondLine, parseContactBody } from './contactBody';
import type { PinGatePurpose } from './ProtectedNoteGate';
import type { NoteConflict } from './sync';
import { isDelimiterRow, tableWidthFromMarker } from './tableDelimiterRow';
import { bindingCaps, bindingText, visibleBindings } from './commandKeys';
import { DESKTOP_APP, KEY_OS } from './shortcutMatch';

/** Regex to match pn:file/ links in note bodies. Not a picture placed from
 *  Files (`![...](pn:file/...)`), which shows a file rather than holding one. */
const FILE_LINK_STRIP = /(?<!!)\[[^\]]*\]\(pn:file\/[0-9a-f-]{36}\)/g;

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
  payload.archived = n.archived === 1;
  if (n.editedAt) payload.editedAt = n.editedAt;
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
    type: 'note', archived: false,
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

/** Drop the HTML tags the editor writes (highlight, color, underline, a
 *  break in a table). A `<` that opens no tag is text, as markdown reads it. */
function stripHtml(line: string): string {
  return line.replace(/<!--[\s\S]*?-->|<\/?[A-Za-z][A-Za-z0-9-]*(?:\s[^<>]*)?\/?>/g, '');
}

const NAMED_ENTITIES: Record<string, string> = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'", nbsp: ' ' };

/**
 * Decode the entity references a body holds. The editor saves a typed `<`,
 * `>` and an `&` that would read as an entity as references, and an empty
 * paragraph as `&nbsp;`; numeric references come in through imports. One
 * pass, so `&amp;lt;` reads `&lt;`, as on screen.
 */
function decodeEntities(line: string): string {
  return line.replace(/&(#\d{1,7}|#x[0-9a-f]{1,6}|[a-z]+);/gi, (ref, name: string) => {
    if (name[0] !== '#') return NAMED_ENTITIES[name] ?? ref;
    const code = name[1] === 'x' || name[1] === 'X' ? parseInt(name.slice(2), 16) : parseInt(name.slice(1), 10);
    const valid = code > 0 && code <= 0x10ffff && (code < 0xd800 || code > 0xdfff);
    return String.fromCodePoint(valid ? code : 0xfffd);
  });
}

/**
 * A character the markdown spells literally, by a backslash escape or inside
 * a code span, crosses the strip passes as a private-use stand-in so that no
 * pass reads it as syntax, and `unshield` puts it back at the end. Only ASCII
 * punctuation is shielded, because no pass touches anything else.
 */
const SHIELD_BASE = 0xe000;
const ASCII_PUNCT = /[!-/:-@[-`{-~]/;
const shield = (c: string) => String.fromCharCode(SHIELD_BASE + c.charCodeAt(0));
const shieldAll = (s: string) => s.replace(/[!-/:-@[-`{-~]/g, shield);
const unshield = (s: string) =>
  s.replace(/[-]/g, (c) => String.fromCharCode(c.charCodeAt(0) - SHIELD_BASE));

/** Where the backtick run of exactly `n` that closes a code span starts, or -1. */
function closingBackticks(line: string, from: number, n: number): number {
  for (let j = line.indexOf('`', from); j !== -1; ) {
    let k = j;
    while (line[k] === '`') k++;
    if (k - j === n) return j;
    j = line.indexOf('`', k);
  }
  return -1;
}

/**
 * Read a line left to right as markdown does: `\` before ASCII punctuation is
 * that character, a code span is its text as typed (one space each side
 * trimmed when both are there), and a backtick run that closes nothing is
 * text too. Each of those leaves shielded.
 */
function shieldLiterals(line: string): string {
  let out = '';
  for (let i = 0; i < line.length; ) {
    const c = line[i]!;
    if (c === '\\' && i + 1 < line.length && ASCII_PUNCT.test(line[i + 1]!)) {
      out += shield(line[i + 1]!);
      i += 2;
    } else if (c === '`') {
      let n = 1;
      while (line[i + n] === '`') n++;
      const close = closingBackticks(line, i + n, n);
      if (close === -1) {
        out += shieldAll(line.slice(i, i + n));
        i += n;
        continue;
      }
      let code = line.slice(i + n, close);
      if (/^ [\s\S]* $/.test(code) && /\S/.test(code)) code = code.slice(1, -1);
      out += shieldAll(code);
      i = close + n;
    } else {
      out += c;
      i++;
    }
  }
  return out;
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
    // Footnote markers `[^1]` and inline notes `^[text]` -> ""; the
    // number they show is not in the stored text anyway.
    .replace(/\[\^[^\]\s]+\](?!:)/g, '')
    .replace(/\^\[[^\]]*\]/g, '')
    // ||spoiler|| -> a fixed mask, so a list row or a title never shows the
    // hidden text, nor its length. Same guard as the parse rule in
    // editorSpoiler.ts.
    .replace(/(^|[^|\\])\|\|(?![\s|])[^\n]*?\S\|\|(?!\|)/g, '$1•••')
    // ==highlight== -> highlight, with the guards of the parse rule in
    // editorInlineSyntax.ts, so "a == b" stays as typed.
    .replace(/==(?![\s=])([^\n]*?)==/g, (run, inner: string) => (inner && !/\s$/.test(inner) ? inner : run))
    // [text](url) -> text
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    // [[note link]] -> note link
    .replace(/\[\[([^\]]+)\]\]/g, '$1')
    // <http://...> autolink -> http://...
    .replace(/<((?:https?|mailto):[^>\s]+)>/g, '$1')
    // Emphasis and strike delimiters. Every literal `*`, `~` and backtick is
    // escaped on save, so what is left is syntax, except a run with space on
    // both sides, a lone `~` (strike takes two) and an underscore inside a
    // word (snake_case), which markdown reads as text too.
    .replace(/[*_~]+/g, (run, at: number, s: string) => {
      const before = s[at - 1] ?? ' ';
      const after = s[at + run.length] ?? ' ';
      if (/\s/.test(before) && /\s/.test(after)) return run;
      if (run === '~') return run;
      if (/^_+$/.test(run) && /[\p{L}\p{N}]/u.test(before) && /[\p{L}\p{N}]/u.test(after)) return run;
      return '';
    })
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
    .replace(/^\[!\w+\][+-]?\s*/, '')
    // Footnote definition: `[^1]: text` -> "text".
    .replace(/^\[\^[^\]\s]+\]:\s*/, '');
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
 * passes only work as a set: the literal characters are shielded first, so
 * no later pass mistakes a typed `\*` or `#` for syntax; then block markers
 * (they sit at the front of the line), the task checkbox they were hiding,
 * inline markdown, HTML, and the entity references last, so a typed `&lt;b&gt;`
 * is never read as a tag. Call one pass on its own and the preview leaks
 * whatever the others own - the Tasks list used `stripInlineMarkdown` alone
 * and printed a raw `<mark style="...">` at the user, because the editor
 * writes a highlight as HTML, not markdown. Whatever the editor saves, a line
 * of text comes back here as the text typed: `tests/notePreviewText.test.ts`
 * holds that for every ASCII character.
 */
export function stripToPlainText(line: string): string {
  return unshield(
    decodeEntities(
      stripHtml(stripInlineMarkdown(stripTaskMarker(stripBlockMarkers(shieldLiterals(line))))),
    ),
  ).trim();
}

/**
 * Whether a note says `query` as typed: several terms (`isPhraseQuery`), in
 * that order, within one line of the text the index reads
 * (`indexedBodyText`, so a vault password is never consulted) or in the
 * title. Case, runs of whitespace and inline markup do not count, because
 * the reader is matching what the editor shows; the raw line is tried too,
 * for a string the stripper would eat, like a name with underscores. The
 * check is `textMatcher`, the matcher every other list uses, and it folds
 * both sides as the index does, so the differences the index ignores, such
 * as accents, do not count here either. One term is never a phrase. The list
 * holds only the hits that say the phrase (GitHub #288).
 */
export function noteSaysPhrase(n: LocalNote, query: string): boolean {
  if (!isPhraseQuery(query)) return false;
  const says = textMatcher(query);
  if (says(n.title)) return true;
  for (const line of indexedBodyText(n).split(/\r?\n/)) {
    if (says(stripToPlainText(line)) || says(line)) return true;
  }
  return false;
}

/** The line that opens or closes a code block, with its language: syntax,
 *  never text, because the editor escapes a typed run of backticks. */
const FENCE_LINE = /^(?:`{3,}[^`]*|~{3,}.*)$/;

// First non-empty line of the body, stripped of the cheapest markdown
// syntax (#, *, _, backtick, list markers, link syntax). Used as the
// auto-title fallback, as the excerpt seed, and by any other preview
// that has a body string but no note to hand it to.
export function firstBodyLine(body: string): string {
  if (!body) return '';
  const lines = body.split(/\r?\n/);
  for (const line of lines) {
    const t = line.trim();
    if (!t || FENCE_LINE.test(t)) continue;
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
  // Every other structured body derives none. A vault item's is JSON, and a
  // type this build does not know holds a body it cannot read; the first line
  // of either is not a title in any language.
  if (hasStructuredBody(n.type)) return '';
  return firstBodyLine(n.body).slice(0, 80);
}

// Title shown in the notes-list row: what the content spells, else the
// stand-in for that note type. Every stand-in is translated, so a row in a
// Portuguese list does not read "Unnamed contact". A note behind a closed
// gate (`gated`) is named by its stored title alone: a name its content
// spells - a contact's email or number, a bookmark's domain, a first line -
// is content the gate keeps, so the stand-in takes its place.
export function deriveDisplayTitle(n: LocalNote, gated = false): string {
  const derived = gated ? (n.title ?? '').trim() : deriveTitleFromContent(n);
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
  if (n.type === 'login' || n.type === 'card' || n.type === 'ssh-key' || n.type === 'link') return i18n.t('notes:noteRow.empty');
  if (n.type === 'contact') return '';
  return i18n.t('notes:noteRow.noContent');
}

/**
 * Whether a note's body is anything but markdown: the JSON document of a form,
 * or the body of a type this build does not know, which it can neither parse
 * nor safely rewrite. The answer is "not a markdown pillar", so an unknown
 * type is structured by construction, and every pass that skips a structured
 * body skips it too.
 *
 * The editor pane, the note-link retarget, the body flush into React state,
 * the derived-title commit and the title derivation all ask this. Each once
 * carried its own copy of the list, which is how the contacts pillar came to
 * be missing from three of them (GitHub #305). One list, one answer.
 * Test: tests/unknownNoteType.test.ts
 */
export function hasStructuredBody(type: string | undefined): boolean {
  return !MARKDOWN_NOTE_TYPES.includes((type ?? 'note') as NoteType);
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
 *
 * A bookmark behind a closed gate (`gated`) offers its stored title alone:
 * its domain is content the gate keeps.
 */
export function noteLinkName(n: LocalNote, gated = false): string {
  const t = (n.title ?? '').trim();
  if (t) return t;
  if (n.type === 'link' && !gated) return linkDomain(parseLinkBody(n.body).url);
  return '';
}

// ── The PIN gate outside a note's pane ────────────────────────────
// Each decision NotesView makes about a note behind a closed gate lives here,
// so it can be tested without rendering the view; tests/lockGateWiring.test.ts
// pins that the view calls them with its own lock predicate.

type RequestPinGate = (action: () => Promise<void>, purpose: PinGatePurpose) => void;

/**
 * Run `action` at once when `gated` is false. When it is true the action is
 * refused until the PIN: `requestPinGate` asks, with the unlock wording, and
 * runs it once the PIN is verified. Every single-note export, print, burn
 * link, history and bookmark address goes through here.
 */
export async function runBehindGate(
  gated: boolean,
  requestPinGate: RequestPinGate,
  action: () => Promise<void> | void,
): Promise<void> {
  if (gated) requestPinGate(async () => { await action(); }, 'unlock');
  else await action();
}

/**
 * A Settings export that writes notes out readable, asking for the PIN once
 * when any note it carries is behind a closed gate.
 */
export function gateExportAll(
  run: (ns: LocalNote[]) => Promise<void>,
  isNoteLocked: (n: LocalNote) => boolean,
  requestPinGate: RequestPinGate,
): (ns: LocalNote[]) => Promise<void> {
  return (ns) => runBehindGate(ns.some(isNoteLocked), requestPinGate, () => run(ns));
}

/**
 * Whether a click on a row opens a bookmark's address rather than selecting
 * it: a live bookmark whose gate is open. In the Trash the row selects, so it
 * can be inspected and restored; behind the PIN it selects, so its pane asks.
 */
export function opensBookmarkOnClick(n: LocalNote, gated: boolean): boolean {
  return n.type === 'link' && n.trashed !== 1 && !gated;
}

/**
 * The week reflection the Stats card may show and write: the week journal's
 * text and its writer, or, while that journal's gate is closed, neither. The
 * text is its content, and an empty field typed into would overwrite it.
 */
export function weekReflectionFor(
  notes: LocalNote[],
  isNoteLocked: (n: LocalNote) => boolean,
  save: (text: string) => void,
): { weekReflection: string; onWeekReflectionChange?: (text: string) => void } {
  const entry = notes.find((n) => n.deleted === 0 && n.trashed === 0 && n.type === 'journal' && isWeekJournal(n));
  if (entry && isNoteLocked(entry)) return { weekReflection: '' };
  const trackers = entry?.trackers as Record<string, unknown> | undefined;
  return { weekReflection: (trackers?.weekReflection as string) ?? '', onWeekReflectionChange: save };
}

/**
 * Where Share is offered for the open note: nowhere while the PIN guards it;
 * otherwise the header button, or, in zen and a compact header where that
 * button stands down, the "..." menu's cell.
 */
export function shareSurface(gated: boolean, zenOrCompact: boolean): 'header' | 'menu' | 'none' {
  if (gated) return 'none';
  return zenOrCompact ? 'menu' : 'header';
}

/**
 * The copy of a conflict the dialog shows for a note behind a closed gate:
 * both versions keep their stored titles and lose their bodies, so the dialog
 * names each by its title or as untitled, never by its first line.
 */
export function conflictShownWhileGated(c: NoteConflict): NoteConflict {
  return { ...c, serverBody: '', localNote: { ...c.localNote, body: '' } };
}

/**
 * The "last edited" date of a note: the last change to its title, its body or
 * a tracker value. A row written before the field reads its sync stamp.
 */
export function editedAtOf(n: Pick<LocalNote, 'editedAt' | 'updatedAt'>): string {
  return n.editedAt ?? n.updatedAt;
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
  prefs: ListPrefs,
  /** The Journals pillar: the `created` sort orders by the day each entry is
   *  for, then by the time it was written. */
  entryDays = false,
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
    if (entryDays) {
      const da = entryDayOf(a);
      const db = entryDayOf(b);
      cmp = da < db ? -1 : da > db ? 1 : 0;
    }
    if (cmp === 0) cmp = a.createdAt < b.createdAt ? -1 : a.createdAt > b.createdAt ? 1 : 0;
  } else {
    const ea = editedAtOf(a);
    const eb = editedAtOf(b);
    cmp = ea < eb ? -1 : ea > eb ? 1 : 0;
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
 * A Markdown file is not measured here: `MarkdownItem` sets its size on disk,
 * because an estimate of what it would cost encrypted would be a number about
 * a note that does not exist.
 */
function deriveNoteSize(n: LocalNote): string {
  const total = noteSizeBytes(n);
  return total > 0 ? formatBytes(total) : '';
}

/**
 * The size a list row or grid tile shows, or '' for none. One rule, so the row
 * and the tile cannot drift.
 *
 * A note shows its size only
 * while the list is sorted by size: the rest of the time it is a byte count on
 * every row that nobody asked for, and while it is the sort key it is the only
 * way to see why the rows are in the order they are in.
 * Spec: ops/docs/ui-patterns.md (section 66)
 */
export function rowSizeLabel(n: LocalNote, sortField: string): string {
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
  if (m === 'message/rfc822') return i18n.t('shell:fileTypes.email');
  if (m.includes('zip') || m.includes('compress') || m.includes('archive')) return i18n.t('shell:fileTypes.archive');
  if (m.includes('document') || m.includes('word')) return i18n.t('shell:fileTypes.document');
  if (m.includes('sheet') || m.includes('excel')) return i18n.t('shell:fileTypes.spreadsheet');
  return i18n.t('shell:fileTypes.file');
}

/** Lines and characters a long preview takes from the body. The clamps in
 *  index.css (`.pn-preview-long`) decide how many of them a row or tile shows. */
const LONG_EXCERPT_LINES = 8;
const LONG_EXCERPT_CHARS = 400;

/**
 * The preview text under a row's title. `long` is the "Longer preview text"
 * list preference: a note then gives its first body lines, joined by line
 * breaks, instead of one line cut at 80 characters. Other types have one
 * natural second line (a username, a URL) and ignore it.
 */
export function deriveExcerpt(n: LocalNote, long = false): string {
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
  // Without a real title the first line IS the displayed title, so it is
  // skipped here rather than said twice.
  let skipped = !!explicitTitle && explicitTitle !== 'Untitled';
  const lines: string[] = [];
  for (const line of n.body.split(/\r?\n/)) {
    const t = line.trim();
    // A table's dash row and its width marker say nothing, and with column
    // widths the dash row can run to dozens of dashes.
    if (!t || FENCE_LINE.test(t) || isDelimiterRow(t) || tableWidthFromMarker(t) !== null) continue;
    if (!skipped) {
      skipped = true;
      continue;
    }
    const c = stripToPlainText(t);
    if (!c) continue;
    if (!long) return c.slice(0, 80);
    lines.push(c);
    if (lines.length >= LONG_EXCERPT_LINES) break;
  }
  if (lines.length) return lines.join('\n').slice(0, LONG_EXCERPT_CHARS);
  return imageExcerpt(n.body);
}

// The new-note key of this device and app, from the command list: ⌘N in the
// desktop apps, ⌥⇧N in a browser, which keeps Mod+N for a new window.
export const isMacPlatform =
  typeof navigator !== 'undefined' &&
  /Mac|iPhone|iPad|iPod/.test(navigator.platform);
const newNoteKey = visibleBindings('newNote', KEY_OS, DESKTOP_APP)[0]!;
export const hotkeyKeys = bindingCaps(newNoteKey, KEY_OS);
export const hotkeyLabel = bindingText(newNoteKey, KEY_OS);
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

// The one local-day helper lives with the date formatter; every caller that
// names a day imports it from here.
export { toLocalIso };

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
  // date-ok: the legacy title is matched as the exact en-US string
  return mondayOf(new Date()).toLocaleDateString('en-US', {
    weekday: 'long', year: 'numeric', month: 'long', day: 'numeric',
  });
}

/** Whether a string is a real local calendar day as `YYYY-MM-DD`: the shape,
 *  and a day the calendar has (no 31 April, no 29 February in 2027). */
export function isLocalIsoDay(s: string): boolean {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s);
  return m !== null && toLocalIso(new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), 12)) === s;
}

/** The calendar date an entry belongs to, or null if it predates the field. */
export function journalDateOf(n: LocalNote): string | null {
  const stored = (n.trackers as Record<string, unknown> | undefined)?.journalDate;
  return typeof stored === 'string' ? stored : null;
}

/** The live journal entry written for a day, tracker values or not. */
export function journalOn(notes: LocalNote[], date: string): LocalNote | undefined {
  return notes.find((n) => n.type === 'journal' && n.deleted === 0 && n.trashed === 0 && journalDateOf(n) === date);
}

/** The day an entry is for: its `journalDate`, or the local day it was
 *  written on for an entry from before the field. */
export function entryDayOf(n: LocalNote): string {
  return journalDateOf(n) ?? toLocalIso(new Date(n.createdAt));
}

/** Each day that holds a live journal entry, to the id of its newest one.
 *  Trashed and archived entries stay off the calendar.
 *  Spec: ops/docs/plans/journal-calendar.md (the data) */
export function journalEntriesByDay(notes: readonly LocalNote[]): Map<string, string> {
  const newest = new Map<string, LocalNote>();
  for (const n of notes) {
    if (n.type !== 'journal' || n.deleted !== 0 || n.trashed !== 0 || n.archived === 1) continue;
    const day = entryDayOf(n);
    const held = newest.get(day);
    if (!held || n.createdAt > held.createdAt) newest.set(day, n);
  }
  return new Map([...newest].map(([day, n]) => [day, n.id]));
}

/** The item types a calendar day can hold: the four that keep a day in
 *  `trackers.journalDate`, and a contact on its birthday. */
export type DayKind = 'event' | 'journal' | 'note' | 'task' | 'contact';

/** One item the calendar offers for a day: its type, its space (null with
 *  Spaces off) and the title the chooser shows, plus what the large calendar
 *  and the agenda draw: the time and end time, the span of a multi-day item
 *  (`start` is the occurrence's first day), whether it repeats or has alerts,
 *  and the day its occurrence starts on. The optional fields are absent when
 *  they do not apply, so a plain entry stays `{ id, kind, space, title }`. */
export type DayEntry = {
  id: string;
  kind: DayKind;
  space: Space | null;
  title: string;
  time?: string;
  timeEnd?: string;
  span?: { start: string; end: string };
  repeating?: true;
  alerted?: true;
  /** The first day of this occurrence of a repeating item. */
  occurrence?: string;
};

/** What a calendar reads: whether a day holds anything, and what. */
export type DayIndex = {
  has(day: string): boolean;
  entriesOf(day: string): readonly DayEntry[];
};

/** The journal calendar's day map: each day to its newest entry, as
 *  `journalEntriesByDay`, plus the newest entry of each space on a day. */
export type JournalDays = ReadonlyMap<string, string> & {
  entriesOf(day: string): readonly DayEntry[];
};

/** The day map with the space of each entry. A day with entries in both
 *  spaces lists the open space first. Spec: ops/docs/plans/spaces.md (section 9) */
export function journalDaysIndex(
  notes: readonly LocalNote[],
  spaces?: { spaceOf: (n: LocalNote) => Space; open: Space; titleOf: (n: LocalNote) => string },
): JournalDays {
  const newest = journalEntriesByDay(notes);
  const bySpace = new Map<string, Map<Space, LocalNote>>();
  if (spaces) {
    for (const n of notes) {
      if (n.type !== 'journal' || n.deleted !== 0 || n.trashed !== 0 || n.archived === 1) continue;
      const day = entryDayOf(n);
      const space = spaces.spaceOf(n);
      const held = bySpace.get(day) ?? new Map<Space, LocalNote>();
      const prev = held.get(space);
      if (!prev || n.createdAt > prev.createdAt) held.set(space, n);
      bySpace.set(day, held);
    }
  }
  const order: Space[] = spaces?.open === 'work' ? ['work', 'personal'] : ['personal', 'work'];
  return Object.assign(newest, {
    entriesOf(day: string): readonly DayEntry[] {
      if (!spaces) {
        const id = newest.get(day);
        return id ? [{ id, kind: 'journal', space: null, title: '' }] : [];
      }
      const held = bySpace.get(day);
      if (!held) return [];
      return order.flatMap((space) => {
        const n = held.get(space);
        return n ? [{ id: n.id, kind: 'journal', space, title: spaces.titleOf(n) }] : [];
      });
    },
  });
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

/** One date in the chosen shape, in the order the date setting names: the
 *  spelled-out shapes take its resolved tag, the digits its numeric style, so
 *  every preset agrees with every other date the app shows. */
function formatJournalDate(d: Date, format: JournalTitleFormat): string {
  const loc = writtenDateLocale();
  // date-ok: a title is written in the language it is created in, not the one it is read in
  const text = (opts: Intl.DateTimeFormatOptions) => d.toLocaleDateString(loc, opts);
  switch (format) {
    case 'iso':
      return toLocalIso(d);
    case 'iso-weekday':
      return `${toLocalIso(d)} ${text({ weekday: 'short' })}`;
    case 'short':
      return text({ weekday: 'short', year: 'numeric', month: 'short', day: 'numeric' });
    case 'numeric':
      // Digits in the order the date setting names.
      return formatInstant(d, 'numeric');
    default:
      return text({ weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
  }
}

/** The title a new journal entry is born with: the date plus the user's
 *  optional suffix, or the custom pattern, which wins while it is valid and
 *  not empty and takes no suffix. A stored pattern that is not valid falls
 *  back to the preset, so it never makes an untitled entry. Only the calls
 *  that make a title pass the pattern; the preset previews do not. */
export function journalTitle(
  d: Date,
  format: JournalTitleFormat,
  suffix: string,
  locale: string,
  pattern = '',
): string {
  if (pattern.trim()) {
    const custom = formatPattern(d, pattern, locale);
    if ('text' in custom) return custom.text;
  }
  const date = formatJournalDate(d, format);
  const tail = suffix.trim();
  return tail ? `${date} ${tail}` : date;
}

/**
 * Whether a title is still exactly one the app made for that day: the custom
 * pattern, or any preset with the current suffix or with none. Only such a
 * title follows the entry when its day changes; a title the person typed stays.
 * Spec: ops/docs/plans/dates.md (section 3.4)
 */
export function isGeneratedJournalTitle(title: string, day: string, suffix: string, locale: string, pattern = ''): boolean {
  const d = new Date(`${day}T12:00:00`);
  const custom = pattern.trim() ? formatPattern(d, pattern, locale) : null;
  if (custom && 'text' in custom && title === custom.text) return true;
  return JOURNAL_TITLE_FORMATS.some(
    (f) => title === journalTitle(d, f, suffix, locale) || title === journalTitle(d, f, '', locale),
  );
}

/**
 * The patch that moves a journal entry to another day, or null when the day
 * is not a real one or is the day the entry already has. It writes
 * `journalDate`, sets `backfilled` for a day before the one the entry was
 * written on (and clears it otherwise), and takes the title the app makes for
 * the new day while the title is still exactly one it made for the old day. A
 * read-only entry keeps its title: the write refuses a title change there. So
 * does an entry the PIN guards right now, which the caller says with
 * `keepTitle`, because the gate is the view's state, not the row's.
 * Spec: ops/docs/plans/dates.md (section 3.4)
 */
export function journalDatePatch(
  n: Pick<LocalNote, 'type' | 'title' | 'trackers' | 'createdAt' | 'locked'>,
  day: string,
  titles: { format: JournalTitleFormat; suffix: string; locale: string; pattern?: string },
  opts: { keepTitle?: boolean } = {},
): { trackers: Record<string, unknown>; title?: string } | null {
  if (n.type !== 'journal' || !isLocalIsoDay(day)) return null;
  const old = journalDateOf(n as LocalNote) ?? toLocalIso(new Date(n.createdAt));
  if (old === day) return null;
  const trackers: Record<string, unknown> = { ...(n.trackers ?? {}), journalDate: day };
  if (day < toLocalIso(new Date(n.createdAt))) trackers.backfilled = true;
  else delete trackers.backfilled;
  if (n.locked === 1 || opts.keepTitle || !isGeneratedJournalTitle(n.title, old, titles.suffix, titles.locale, titles.pattern)) return { trackers };
  return {
    trackers,
    title: journalTitle(new Date(`${day}T12:00:00`), titles.format, titles.suffix, titles.locale, titles.pattern),
  };
}

/** The day of an item a calendar shows, by its type: a journal entry's
 *  day (its creation day before the field), a note's, a task list's or an
 *  event's `journalDate`, or null. A contact is placed by its birthday instead. */
function itemDayOf(n: LocalNote): string | null {
  if (n.type === 'journal') return entryDayOf(n);
  if (n.type === 'note' || n.type === 'task' || n.type === 'event') return journalDateOf(n);
  return null;
}

/** Whether an item shows on a calendar: a day of its own, or a birthday
 *  on a contact its PIN does not guard. */
export function isOnCalendar(n: LocalNote, isGated: (n: LocalNote) => boolean): boolean {
  if (itemDayOf(n) !== null) return true;
  return n.type === 'contact' && !isGated(n) && contactBirthday(parseContactBody(n.body)) !== null;
}

const KIND_ORDER: Record<DayKind, number> = { event: 0, journal: 1, note: 2, task: 3, contact: 4 };

/** The days one expansion of a repeating event covers in the calendar index. */
const SERIES_WINDOW = 64;

/** The schedule of an item the index holds, read once. */
function scheduleOfItem(n: LocalNote): Schedule | null {
  return scheduleOf(n.trackers as Record<string, unknown> | undefined, n.type, itemDayOf(n));
}

/**
 * Every dated item for the calendars: events, journal entries, notes and task
 * lists on their day (every day of a multi-day item, every occurrence of a
 * repeating event), and contacts on their birthday in every year (29 February
 * on the 28th in a year without it). Trashed and archived items stay off, and
 * so does the birthday of a contact behind its PIN, whose body is the secret;
 * `openOnly` keeps the other space off too. A day lists the open space first,
 * then the all-day items before the timed ones, the timed ones by time, then
 * events, entries, notes, task lists and birthdays, newest first. A repeating
 * event is expanded for the day asked, so no window is needed and a day is
 * read once.
 * Spec: ops/docs/plans/note-date.md (section 4), ops/docs/plans/calendar-pillar-spec.md (section 4.3)
 */
export function calendarIndex(
  notes: readonly LocalNote[],
  opts: { titleOf: (n: LocalNote) => string; isGated: (n: LocalNote) => boolean; spaceOf?: (n: LocalNote) => Space; open?: Space; openOnly?: boolean },
): DayIndex {
  type Placed = { n: LocalNote; s: Schedule; start: string };
  const byDay = new Map<string, Placed[]>();
  const byBirthday = new Map<string, LocalNote[]>();
  const series: { n: LocalNote; s: Schedule; len: number }[] = [];
  for (const n of notes) {
    if (n.deleted !== 0 || n.trashed !== 0 || n.archived === 1) continue;
    if (opts.openOnly && opts.spaceOf && opts.spaceOf(n) !== (opts.open ?? 'personal')) continue;
    if (n.type === 'contact') {
      if (opts.isGated(n)) continue;
      const b = contactBirthday(parseContactBody(n.body));
      if (b) {
        const key = `${String(b.month).padStart(2, '0')}-${String(b.day).padStart(2, '0')}`;
        byBirthday.set(key, [...(byBirthday.get(key) ?? []), n]);
      }
      continue;
    }
    const s = scheduleOfItem(n);
    if (!s) continue;
    const len = spanLength(s);
    if (s.repeat) {
      series.push({ n, s, len });
      continue;
    }
    for (let i = 0; i <= len; i++) {
      const day = shiftDay(s.day, i);
      const list = byDay.get(day);
      if (list) list.push({ n, s, start: s.day });
      else byDay.set(day, [{ n, s, start: s.day }]);
    }
  }
  const leap = (year: number) => new Date(year, 1, 29).getDate() === 29;
  const birthdaysOn = (day: string): LocalNote[] => {
    const md = day.slice(5);
    const own = byBirthday.get(md) ?? [];
    return md === '02-28' && !leap(Number(day.slice(0, 4))) ? [...own, ...(byBirthday.get('02-29') ?? [])] : own;
  };
  // Each series is expanded once per window of SERIES_WINDOW days: the start
  // days that can cover a day of the window, kept per series. A day asked
  // takes the starts that cover it, so a long span costs no placement on
  // every day it covers.
  const windows = new Map<number, string[][]>();
  const seriesOn = (day: string): Placed[] => {
    if (series.length === 0) return [];
    const w = Math.floor(dayNumber(day) / SERIES_WINDOW);
    let starts = windows.get(w);
    if (!starts) {
      const first = shiftDay(day, w * SERIES_WINDOW - dayNumber(day));
      const lastDay = shiftDay(first, SERIES_WINDOW - 1);
      starts = series.map(({ s, len }) => occurrencesOf(s.day, s.repeat, shiftDay(first, -len), lastDay));
      windows.set(w, starts);
    }
    const out: Placed[] = [];
    series.forEach(({ n, s, len }, i) => {
      const from = len ? shiftDay(day, -len) : day;
      for (const start of starts![i]!) if (start >= from && start <= day) out.push({ n, s, start });
    });
    return out;
  };
  const spaceRank = (sp: Space | null) => (sp === null || sp === (opts.open ?? 'personal') ? 0 : 1);
  const cache = new Map<string, readonly DayEntry[]>();
  const entriesOf = (day: string): readonly DayEntry[] => {
    const held = cache.get(day);
    if (held) return held;
    const placed = [...(byDay.get(day) ?? []), ...seriesOn(day)];
    const entries = [
      ...placed.map(({ n, s, start }) => {
        const len = spanLength(s);
        const entry: DayEntry & { at: string } = {
          id: n.id,
          kind: n.type as DayKind,
          space: opts.spaceOf ? opts.spaceOf(n) : null,
          title: opts.titleOf(n),
          at: n.createdAt,
        };
        if (s.time) entry.time = s.time;
        if (s.timeEnd) entry.timeEnd = s.timeEnd;
        if (len > 0) entry.span = { start, end: shiftDay(start, len) };
        if (s.repeat) {
          entry.repeating = true;
          entry.occurrence = start;
        }
        if (s.alerts?.length) entry.alerted = true;
        return entry;
      }),
      ...birthdaysOn(day).map((n): DayEntry & { at: string } => ({
        id: n.id,
        kind: 'contact',
        space: opts.spaceOf ? opts.spaceOf(n) : null,
        title: opts.titleOf(n),
        at: n.createdAt,
      })),
    ]
      .sort((a, b) =>
        spaceRank(a.space) - spaceRank(b.space)
        || (a.span ? 0 : 1) - (b.span ? 0 : 1)
        || (a.time ? 1 : 0) - (b.time ? 1 : 0)
        || (a.time ?? '').localeCompare(b.time ?? '')
        || KIND_ORDER[a.kind] - KIND_ORDER[b.kind]
        || (a.at < b.at ? 1 : a.at > b.at ? -1 : 0))
      .map(({ at: _at, ...entry }) => entry);
    cache.set(day, entries);
    return entries;
  };
  return {
    has: (day) => byDay.has(day) || birthdaysOn(day).length > 0 || seriesOn(day).length > 0,
    entriesOf,
  };
}

/**
 * The items a typed date names: a journal entry, note or task list whose day
 * reads as the query in one of the shapes the app writes a day in (ISO, and
 * the date setting's full, numeric and day-and-month forms), part of a shape
 * included, so "Oct 14" finds an item on 14 October; and a contact whose
 * birthday falls on it this year, unless its PIN guards it. Read at query
 * time, so a new date setting needs no index rebuild. A query with no digit,
 * or shorter than four characters, names no day: a word never lists every
 * dated item.
 * Spec: ops/docs/plans/note-date.md
 */
export function itemsDatedAs(query: string, notes: readonly LocalNote[], isGated: (n: LocalNote) => boolean): Set<string> {
  const found = new Set<string>();
  const needle = foldForMatch(query).trim();
  if (needle.length < 4 || !/\d/.test(needle)) return found;
  const shapes = new Map<string, boolean>();
  const named = (day: string): boolean => {
    let hit = shapes.get(day);
    if (hit === undefined) {
      hit = [day, formatDay(day, 'date'), formatDay(day, 'numeric'), formatDay(day, 'dayMonth')]
        .some((shape) => foldForMatch(shape).includes(needle));
      shapes.set(day, hit);
    }
    return hit;
  };
  const year = new Date().getFullYear();
  for (const n of notes) {
    let day = itemDayOf(n);
    if (n.type === 'contact' && !isGated(n)) {
      const b = contactBirthday(parseContactBody(n.body));
      // 29 February falls on the 28th in a year without it, as on the calendar.
      const dayOfMonth = b && b.month === 2 && b.day === 29 && new Date(year, 1, 29).getDate() !== 29 ? 28 : b?.day;
      if (b) day = `${year}-${String(b.month).padStart(2, '0')}-${String(dayOfMonth).padStart(2, '0')}`;
    }
    if (day !== null && named(day)) found.add(n.id);
  }
  return found;
}

/**
 * The patch that puts a note, a task list or an event on a day, or takes a
 * note or a task list off the calendar (`null`), or null when nothing
 * changes. The day is the field a journal entry keeps its day in, so it syncs
 * and merges as one, and a note converted to a journal entry and back keeps
 * it. A move takes the whole schedule along: a multi-day item keeps its
 * length. Taking the day away removes the whole schedule, and `backfilled`,
 * which belongs to a journal entry, goes with it. An event always has a day.
 * Spec: ops/docs/plans/note-date.md, ops/docs/plans/calendar-pillar-spec.md (step 4)
 */
export function schedulePatch(
  n: Pick<LocalNote, 'type' | 'trackers'>,
  day: string | null,
): { trackers: Record<string, unknown> } | null {
  if ((n.type !== 'note' && n.type !== 'task' && n.type !== 'event') || (day !== null && !isLocalIsoDay(day))) return null;
  if (day === null && n.type === 'event') return null;
  const old = journalDateOf(n as LocalNote);
  if ((old ?? null) === day) return null;
  if (day === null) {
    const rest: Record<string, unknown> = { ...(n.trackers ?? {}) };
    for (const key of [...SCHEDULE_KEYS, 'backfilled']) delete rest[key];
    return { trackers: rest };
  }
  const { backfilled: _back, ...rest } = n.trackers ?? {};
  const end = typeof rest.dateEnd === 'string' && old ? shiftDay(rest.dateEnd, dayNumber(day) - dayNumber(old)) : undefined;
  return { trackers: withSchedule(rest, n.type, { day, ...(end ? { end } : {}) }) };
}

/**
 * The body a new task list starts with: one empty checkbox, in the form the
 * editor itself saves it. Written at creation with the birth timestamp, so an
 * untouched list still reads as a draft and isNoteEmpty can discard it; on
 * load the editor turns both `&nbsp;` back into empty paragraphs.
 */
export const TASK_LIST_EMPTY_BODY = '- [ ] &nbsp;\n\n&nbsp;';

// Empty body templates for vault item types. Shared between note creation
// and vault-type switching in NotesView.
export const VAULT_EMPTY_BODIES: Record<string, string> = {
  login: JSON.stringify({ url: '', username: '', password: '', notes: '' }),
  card: JSON.stringify({ cardholderName: '', cardNumber: '', expMonth: '', expYear: '', cvv: '', billingZip: '', notes: '' }),
  'ssh-key': JSON.stringify({ label: '', privateKey: '', publicKey: '', passphrase: '', notes: '' }),
  // A contact stores only what exists, so its empty body is the empty document.
  contact: '{}',
};

/**
 * "Empty" = no title, no body, no tags, no schedule the person gave it.
 * Used to decide whether a draft should be discarded when the user
 * navigates away instead of lingering as clutter in the list and on the
 * server. A note with a single space of body, a single tag or a day given
 * on the calendar is NOT empty - that's real user intent and we respect it.
 *
 * Task and journal notes get system-generated titles on creation
 * ("Tasks for Friday, May 15, 2026" / "Friday, May 15, 2026"), so
 * for those types the title alone doesn't prove user intent. It
 * doesn't disprove it either: someone who renames a journal entry
 * and writes no body meant to keep it, and we used to hard-delete
 * that on the next tap (#122). What tells the two apart is whether
 * the note was ever written to - createNote sets createdAt equal to
 * updatedAt, and every edit (title included) bumps updatedAt - so
 * an untouched draft is the only thing we discard.
 *
 * Vault items (login/card/ssh-key) get template JSON bodies on
 * creation. The Save button blocks empty saves (v0.135.8), but
 * navigating away without saving bypasses that - the template body
 * looks non-empty to a plain trim check. We treat template-matching
 * bodies as empty so discardIfEmpty catches them.
 */
export function isNoteEmpty(note: LocalNote | undefined): boolean {
  if (!note) return false;
  // An item of a type this build does not know is opaque: nothing here can
  // tell an empty one from a full one, so it is never discarded.
  if (!isKnownNoteType(note.type)) return false;
  const body = (note.body ?? '').trim();
  const hasTags = (note.tags ?? []).length > 0;
  const hasTitle = (note.title ?? '').trim() !== '';
  // Vault items: template JSON body = empty.
  const vaultTemplate = VAULT_EMPTY_BODIES[note.type];
  const hasBody = vaultTemplate ? body !== '' && body !== vaultTemplate : body !== '';
  // A schedule is content once it was written after the item was born, or
  // when the item was born with more than its day and alerts (a time, an end
  // or a repeat, as the quick add and a dragged range give it): the calendar
  // shows it and its reminders ring. An item born on a day with only that
  // day and the default alerts (the New button, a day in the calendar) is
  // still a draft until something is written to it.
  const trackers = note.trackers as Record<string, unknown> | undefined;
  const schedule = SCHEDULE_KEYS.filter((key) => trackers?.[key] !== undefined);
  const untouched = note.createdAt === note.updatedAt;
  if (schedule.length > 0 && (!untouched || schedule.some((key) => key !== 'journalDate' && key !== 'alerts'))) return false;
  if (note.type === 'event') return !hasTitle && !hasBody && !hasTags && untouched;
  // Task & journal titles are auto-generated - body is the real
  // signal, but only while the draft is still untouched (#122).
  // A new task list starts with one empty checkbox, which is no content.
  if (note.type === 'task' || note.type === 'journal') {
    const content = hasBody && !(note.type === 'task' && body === TASK_LIST_EMPTY_BODY);
    return !content && !hasTags && note.createdAt === note.updatedAt;
  }
  if (hasTitle) return false;
  if (hasBody) return false;
  if (hasTags) return false;
  return true;
}
