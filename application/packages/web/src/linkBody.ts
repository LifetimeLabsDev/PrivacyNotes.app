/**
 * Bookmark ('link') note body helpers - the single source of truth for how
 * a bookmark stores and displays its URL.
 *
 * A bookmark is a note with `type: 'link'` whose body is a small JSON
 * document, mirroring the vault's login body convention (LoginForm's
 * parseLoginBody). Two fields only, per the v1 spec:
 *   - title: the user-given name. Stored EMPTY when the user gave none;
 *     display falls back to the domain at render time (deriveDisplayTitle),
 *     never at save time, so an edited URL can never leave a stale name
 *     behind and user intent stays distinguishable from the default.
 *   - body:  JSON { url } - the normalized http(s) URL.
 *
 * Spec: ops/docs/plans/bookmarks-pillar.md (section 2)
 */

import { domainFromUrlString } from './favicon';

/** Parsed bookmark body. `url` is '' when the body does not parse. */
export function parseLinkBody(body: string): { url: string } {
  try {
    const data = JSON.parse(body);
    return { url: typeof data.url === 'string' ? data.url : '' };
  } catch {
    return { url: '' };
  }
}

export function buildLinkBody(url: string): string {
  return JSON.stringify({ url });
}

/**
 * Normalize user input into a saveable URL: trim, prepend https:// when the
 * scheme is missing (people paste "github.com/foo" - same rule the vault's
 * website field applies). Returns null when the result is not a parseable
 * http(s) URL, which is the form's validation signal.
 */
export function normalizeUrl(raw: string): string | null {
  let s = raw.trim();
  if (!s) return null;
  if (!/^https?:\/\//i.test(s)) {
    // A pasted value with another scheme (ftp:, javascript:, mailto:) is
    // rejected rather than silently rewritten to https.
    if (/^[a-z][a-z0-9+.-]*:/i.test(s)) return null;
    s = 'https://' + s;
  }
  try {
    const u = new URL(s);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
    if (!u.hostname || !u.hostname.includes('.')) {
      // Single-word hosts ("localhost", a typo like "githubcom") are almost
      // never what a bookmark means; localhost users can type the scheme.
      if (u.hostname !== 'localhost') return null;
    }
    return u.href;
  } catch {
    return null;
  }
}

/** Display domain for a bookmark URL ("github.com"). '' when unparseable. */
export function linkDomain(url: string): string {
  return url ? domainFromUrlString(url) : '';
}

/**
 * The export representation of a bookmark: a bare markdown autolink.
 * Markdown export prints it as text, and every surface that renders
 * markdown (HTML export, PDF/print, the burn viewer) turns it into a
 * clickable anchor - deliberately NOT the vault-fields table (2026-08-22
 * review: a one-URL table read as furniture). Returns null for anything
 * that is not a bookmark, so call sites can fall through unchanged.
 */
export function linkExportMarkdown(note: { type?: string; body: string }): string | null {
  if (note.type !== 'link') return null;
  const { url } = parseLinkBody(note.body);
  return url ? `<${url}>` : null;
}

/**
 * Dedupe key for a bookmark URL - the exact-match rule the importer and the
 * quick-add "already saved" logic share. Lowercased scheme+host (URL() does
 * that), original path/query kept, single trailing slash on a bare origin
 * kept as URL() emits it. Falls back to the raw string when unparseable so
 * two identical malformed rows still match each other.
 */
export function linkDedupeKey(url: string): string {
  try {
    return new URL(url).href;
  } catch {
    return url.trim();
  }
}

/** The shape the key map reads. `LocalNote` satisfies it. */
type BookmarkLike = { id: string; type?: string; body: string; trashed?: number };

/**
 * Every bookmark URL the account holds, as `linkDedupeKey` -> note id.
 *
 * Built over ALL active notes, never over a rendered list: the guard exists
 * to find the copy the user cannot see, so a search string, a folder or tag
 * filter, or the "hide locked / protected" toggles must not hide it. Feeding
 * it the visible list is what let a duplicate through whenever anything was
 * filtered (fixed 2026-08-26). Trashed rows are excluded, the same rule the
 * importer's dedupe applies - a bookmark in the trash is not the trap.
 *
 * First row wins on a key. The input order is the caller's (NotesView hands
 * it `activeNotes`, newest edit first), so when an account already holds one
 * URL twice the id names one of the two, not a particular one - every caller
 * only asks WHETHER the URL is taken.
 */
export function buildLinkKeyMap(notes: BookmarkLike[]): Map<string, string> {
  const keys = new Map<string, string>();
  for (const n of notes) {
    if (n.type !== 'link' || n.trashed === 1) continue;
    const { url } = parseLinkBody(n.body);
    if (!url) continue;
    const key = linkDedupeKey(url);
    if (!keys.has(key)) keys.set(key, n.id);
  }
  return keys;
}

/**
 * The id of the bookmark that already holds `url`, or null when it is free.
 *
 * `exceptId` is the bookmark being edited, so re-saving a row's own URL is
 * never a duplicate - without it, every commit in the editor collides with
 * itself.
 */
export function duplicateBookmarkId(
  keys: Map<string, string>,
  url: string,
  exceptId?: string
): string | null {
  const owner = keys.get(linkDedupeKey(url));
  return owner && owner !== exceptId ? owner : null;
}
