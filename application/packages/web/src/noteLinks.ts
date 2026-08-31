/**
 * The `[[note-link]]` syntax, in one place: what a target may contain, how a
 * target resolves to a note, and how a rename carries every link with it.
 *
 * A note-link stores its target as the target note's TITLE, not its id,
 * because the title is the portable form: `[[Some note]]` is what an Obsidian
 * vault writes, what our markdown export prints, and what a markdown folder
 * holds on disk. Storing ids instead would break that round trip with every
 * other app, so a rename rewrites the links rather than the format (#238).
 *
 * Three call sites share this module and MUST stay in agreement, because the
 * failure when they drift is a link that looks right and goes nowhere:
 *   - the importers write targets with `noteLinkTarget`;
 *   - navigation resolves a target to a note with `noteLinkKey`;
 *   - a rename moves the links with `retargetNoteLinks`, which matches with
 *     that same key, so it moves exactly the links a click would have followed.
 *
 * Pure: no DOM, no I/O, one string in and one string out. `useNoteEditing.ts`
 * owns the rename call site and the rules about WHICH notes are rewritten.
 * The edge cases are pinned by `tests/noteLinks.test.ts`.
 */

/**
 * What counts as a note-link. Mirrors the paste rule in `NoteLink.tsx`, and
 * the two must agree: a shape the editor turns into a link but this pass does
 * not recognise is a link that silently stops following its target.
 */
const NOTE_LINK_RE = /\[\[([^\]|]+?)(?:\|([^\]]+?))?\]\]/g;

/**
 * Regions markdown treats as code, where `[[x]]` is literal text the editor
 * never renders as a link. Rewriting inside one would edit the user's content.
 * Same set and same reasoning as `linkify.ts`, including its known gap: an
 * INDENTED code block is not detected, because four spaces after a list item
 * is list continuation rather than code.
 */
const CODE_RE: RegExp[] = [
  /```[\s\S]*?```/g,
  /~~~[\s\S]*?~~~/g,
  /`[^`\n]*`/g,
];

/**
 * Turn a note title into a target that survives `[[...]]`.
 *
 * Every importer that writes a note-link runs its target through this. A title
 * really can hold a pipe ("Recipes | 2024" is an ordinary Evernote title), and
 * writing it raw produces `[[Recipes | 2024]]`, which the editor parses as a
 * link to "Recipes" displayed as "2024" - wrong target AND wrong text.
 *
 * The sanitized target no longer equals the note's title, which is why
 * `noteLinkKey` exists: resolution compares the two through the same rule, so
 * the link still finds its note and the note keeps the title the user gave it.
 * Change one of these two functions and you must change the other.
 */
export function noteLinkTarget(title: string): string {
  return title.replace(/[[\]|]/g, ' ').replace(/\s+/g, ' ').trim();
}

/**
 * The key a target and a title are compared on. Case-insensitive, because
 * `[[recipes]]` has always found the note titled "Recipes", and through
 * `noteLinkTarget` so a title the syntax cannot hold still resolves.
 *
 * Callers match on the exact title FIRST and fall back to this, so a note
 * whose real title is written out beats a near-miss.
 */
export function noteLinkKey(value: string): string {
  return noteLinkTarget(value).toLowerCase();
}

type Span = { start: number; end: number };

/** Merged spans of the body that are code. */
function codeSpans(body: string): Span[] {
  const found: Span[] = [];
  for (const re of CODE_RE) {
    for (const m of body.matchAll(re)) {
      const start = m.index ?? 0;
      found.push({ start, end: start + m[0].length });
    }
  }
  found.sort((a, b) => a.start - b.start);
  const merged: Span[] = [];
  for (const s of found) {
    const last = merged[merged.length - 1];
    if (last && s.start <= last.end) last.end = Math.max(last.end, s.end);
    else merged.push({ ...s });
  }
  return merged;
}

/**
 * Point every `[[oldTitle]]` and `[[oldTitle|label]]` in `body` at `newTitle`.
 * A display label is kept as the user wrote it; a link with no label follows
 * the new title, which is the "the text updates itself" half of #238.
 *
 * Returns the rewritten body and how many links moved, or `null` when nothing
 * changed - so the caller can skip the write instead of marking a note dirty
 * for no reason.
 */
export function retargetNoteLinks(
  body: string,
  oldTitle: string,
  newTitle: string,
): { body: string; count: number } | null {
  const from = noteLinkKey(oldTitle);
  const to = noteLinkTarget(newTitle);
  if (!body || !from || !to || from === to.toLowerCase()) return null;
  // Cheap reject: most notes hold no note-link at all.
  if (!body.includes('[[')) return null;

  const parts: string[] = [];
  let count = 0;

  /**
   * Rewrite one stretch of NON-code body. The scan has to be segmented rather
   * than filtered afterwards: the target pattern accepts `[` and a backtick,
   * so a match starting at the `[[` inside a code span runs on and swallows
   * the real link behind it. Filtering that match out then skips both, which
   * is exactly how ``type `[[`, try [[Some note]]`` - our own welcome note -
   * stopped following its target. Walking the gaps is what `linkify.ts` does,
   * and for the same reason.
   */
  function rewriteSegment(text: string, offset: number) {
    NOTE_LINK_RE.lastIndex = 0;
    let last = 0;
    let m: RegExpExecArray | null;
    while ((m = NOTE_LINK_RE.exec(text)) !== null) {
      const start = m.index;
      const abs = offset + start;
      // `![[x]]` is Obsidian's EMBED, a different thing from a note-link - the
      // same guard the editor's markdown-it rule carries.
      if (abs > 0 && body[abs - 1] === '!') continue;
      // Match the way navigation resolves, so this moves exactly the links a
      // click would have followed - no more and no fewer.
      if (noteLinkKey(m[1] ?? '') !== from) continue;
      const label = m[2]?.trim();
      parts.push(text.slice(last, start));
      parts.push(label ? `[[${to}|${label}]]` : `[[${to}]]`);
      last = start + m[0].length;
      count += 1;
    }
    parts.push(text.slice(last));
  }

  let cursor = 0;
  for (const span of codeSpans(body)) {
    if (cursor < span.start) rewriteSegment(body.slice(cursor, span.start), cursor);
    parts.push(body.slice(span.start, span.end));
    cursor = span.end;
  }
  if (cursor < body.length) rewriteSegment(body.slice(cursor), cursor);

  if (count === 0) return null;
  return { body: parts.join(''), count };
}
