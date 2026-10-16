/**
 * Convert bare URLs and emails in a markdown body into `<...>` autolinks so
 * that tiptap-markdown's parser emits proper link nodes when the note loads.
 *
 * EVERY IMPORTER THAT PRODUCES A NOTE BODY MUST CALL THIS. It is not optional
 * polish - skipping it ships notes whose links are dead until the user puts a
 * caret behind each one and presses space. The failure is invisible in review
 * (the text looks right, it just is not a link) and invisible in the type
 * system, which is how the markdown importer went without it from the start
 * and was only caught in v0.300.0 by importing a test note by hand.
 *
 * Wired in: appleJournal, appleNotes, bitwarden, evernote, googleKeep,
 * markdown, notesnook, obsidian, samsungNotes, simplenote, standardNotes,
 * upnote.
 *
 * CHECK THE CALL SITE, NOT THE IMPORT. An importer can call this on one body
 * path and miss another, which is what happened twice - standardNotes (the
 * converted-checklist branch bypassed it) and bitwarden (the identity branch)
 * - and what a file-level grep cannot see. For any importer with more than one
 * body producer, confirm they all converge before the call: samsungNotes,
 * notesnook, obsidian and googleKeep funnel every branch into one variable
 * first, which is the shape to prefer. bitwarden cannot, because its branches
 * are switch cases over item types, so there each markdown branch needs its
 * own call and the count of branches is the thing to check against.
 *
 * Deliberately NOT wired in, and each for a reason that must be checked rather
 * than assumed:
 *   - `folderImport.ts`, `blobImport.ts`, `safariArchive.ts` - build no note
 *     bodies at all (folder tree helpers, attachment blobs, archive readers).
 *   - `browserBookmarks.ts`, `passwordCsv.ts` - structured bodies (a bookmark's
 *     JSON `{ url }`, a login's vault JSON) consumed by forms, not markdown -
 *     the same exemption as bitwarden's vault items below.
 *   - `privacynotes.ts` - restores our OWN export, whose bodies were already
 *     serialized out of the editor with real link nodes. A restore should
 *     reproduce what was backed up, not rewrite it.
 *   - bitwarden's login / card / sshKey items - those bodies are JSON consumed
 *     by the vault forms (`serializeLoginBody` and friends), NOT markdown.
 *     Linkifying them would wrap a URL inside a JSON string value and corrupt
 *     the stored field. Any future structured note type inherits this
 *     exemption. Its other TWO branches, secure-note and identity, are plain
 *     markdown pushed as `type: 'note'` and both must be wired in. Identity
 *     only became so in the v0.300.0 call-site audit: this exemption list
 *     named the three JSON types, which read as complete while silently
 *     accounting for only four of bitwarden's five branches.
 *
 * If you add an importer, you are in the first list unless you can name which
 * of those reasons puts you in the second.
 *
 * Why this exists:
 *   TipTap's Link extension is configured with `autolink: true`, but
 *   that only fires while the user is typing - it scans the word behind
 *   the cursor on a word break. Content loaded into the editor from
 *   markdown storage is parsed by tiptap-markdown, which only creates
 *   link nodes for URLs that are already in `<...>` autolink syntax or
 *   `[text](url)` inline-link syntax. Bare URLs come in as plain text.
 *
 *   So when we import 552 Standard Notes notes, the user has to go into
 *   each note and press Enter after every URL to trigger autolink.
 *   Preprocessing the body to wrap bare URLs in `<...>` means they load
 *   as clickable links from the very first render. That's the whole
 *   "we make your URLs clickable" selling point we want to pitch.
 *
 * Safety:
 *   We skip regions that are already handled by markdown - fenced code
 *   blocks (both ``` and ~~~), inline code spans, existing markdown links,
 *   existing autolinks, and raw HTML tags. Plain text outside those regions
 *   is the only place we rewrite.
 *
 *   KNOWN GAP, deliberate: an INDENTED (4-space) code block is not skipped,
 *   so a URL inside one is linkified. Detecting it needs block-level parsing,
 *   because four spaces after a list item is list continuation rather than
 *   code, and a regex that guesses would silently stop linkifying real links
 *   inside lists. The failure it leaves is cosmetic (visible angle brackets in
 *   a code block) rather than corrupting, which is why it lost to the risk of
 *   the fix. An unclosed fence has the same shape and the same verdict. Both
 *   are locked in by tests so the behavior is visible rather than assumed.
 *
 *   Do not reason about these from what OUR serializer emits. This pass runs
 *   over markdown produced by other apps, so the input space is all of
 *   CommonMark, not the subset we happen to write.
 *
 * Protocol support: `http`, `https`, `mailto` - matches what the editor
 * recognizes. `www.` without a scheme is intentionally left alone
 * (too many false positives on things like "filename.txt").
 */

// Bare URL matcher. Terminators: whitespace, angle brackets (would mean
// it's already an autolink), backticks (code span), double quotes, and
// control characters, which markdown refuses inside an autolink: the text
// after one would then be read as markdown.
// Trailing punctuation is trimmed in the replace callback.
const URL_RE = /(?:https?:\/\/|mailto:)[^\s<>`"\x00-\x1f\x7f]+/g;

/**
 * Bare email addresses, no `mailto:` prefix. Group 2 is the address; group 1
 * is the run of `.`, `+` and `-` in front of it, which stays text.
 *
 * The editor's Link extension autolinks these while typing (linkifyjs detects
 * them), so leaving them alone on import made the same address behave two
 * different ways depending on how it got into the note.
 *
 * Deliberately strict to keep false positives out: the domain must carry at
 * least one dot, which rules out `@media`, `@font-face`, `@user` handles and
 * npm scopes like `@tiptap/core`. Code spans and fences are already skipped by
 * the caller, so decorators and shell redirects never reach this.
 *
 * The lookbehind lets a match start only where a run of local-part characters
 * starts. `@` is not one of them, so every start inside one run reaches the
 * same `@` and only the first can match; letting the engine try the others
 * rescanned the run once per letter, which froze an import on a long
 * `a.a.a.` token. The address itself begins at the run's first word
 * character, where a word boundary would have put it.
 */
const EMAIL_RE = /(?<![\w.+-])([.+-]*)(\w[\w.+-]*@[\w-]+(?:\.[\w-]+)+\b)/g;

/**
 * Text this module's pass would rewrite: a bare URL or a bare email.
 *
 * Exported for the HTML-converting importers (upnote, notesnook), which
 * must NOT emit an aligned `<p style="text-align: ...">` HTML block around
 * text that linkify would touch: the `<...>` autolink it inserts reads as
 * a broken tag inside an HTML block and the address vanishes in the
 * editor. Those importers drop the alignment instead. Lives here so the
 * guard cannot drift from URL_RE / EMAIL_RE above.
 */
export const BARE_LINKABLE_RE = /(?:https?:\/\/|mailto:)|(?<![\w.+-])[.+-]*\w[\w.+-]*@[\w-]+(?:\.[\w-]+)+\b/;

// Punctuation characters that are almost never the final character of
// a real URL. `)` and `]` are handled separately because they can
// legitimately appear inside a URL (Wikipedia article names, query keys
// like `a[]`) - we balance them before stripping a trailing one.
//
// `*`, `_` and `~` are here because they are markdown's emphasis and
// strikethrough delimiters, and the URL matcher does not treat them as
// terminators. Without them `**https://example.com**` matched through the
// closing markers and emitted `**<https://example.com**>`, which breaks the
// link AND leaves the bold unclosed. A URL whose final character is genuinely
// one of these exists but is vanishingly rare, and losing that last character
// is a far smaller failure than corrupting the surrounding markdown.
const TRAILING_PUNCT_RE = /[.,;:!?"'}*_~]/;

type Span = { start: number; end: number };

/**
 * Existing inline links `[label](url)`, found the way the regex
 * `/\[[^\]\n]*\]\([^)\n]*\)/g` finds them, in one forward scan. Every `[`
 * before the same `]` reaches that `]`, so when one fails they all do, and a
 * destination scan that met a line end without `)` fails for every later
 * start before that line end. The regex retried both per start, which is
 * quadratic on a line full of `[` or `](`.
 */
function linkSpans(input: string, out: Span[]): void {
  let pos = 0;
  let destFailEnd = -1;
  while (pos < input.length) {
    const p = input.indexOf('[', pos);
    if (p < 0) return;
    let j = p + 1;
    while (j < input.length && input[j] !== ']' && input[j] !== '\n') j++;
    if (j >= input.length) return;
    if (input[j] === '\n' || input[j + 1] !== '(') {
      pos = input[j] === '\n' ? j : j + 1;
      continue;
    }
    let k = j + 2;
    if (k < destFailEnd) {
      pos = j + 1;
      continue;
    }
    while (k < input.length && input[k] !== ')' && input[k] !== '\n') k++;
    if (k < input.length && input[k] === ')') {
      out.push({ start: p, end: k + 1 });
      pos = k + 1;
    } else {
      destFailEnd = k;
      pos = j + 1;
    }
  }
}

/**
 * Raw HTML tags, found the way `/<[a-zA-Z][^>\n]*>/g` finds them, in one
 * forward scan: every `<` before the same `>` or line end reaches it, so a
 * failed start fails for all of them.
 */
function htmlTagSpans(input: string, out: Span[]): void {
  let pos = 0;
  while (pos < input.length) {
    const p = input.indexOf('<', pos);
    if (p < 0) return;
    if (!/[a-zA-Z]/.test(input[p + 1] ?? '')) {
      pos = p + 1;
      continue;
    }
    let j = p + 2;
    while (j < input.length && input[j] !== '>' && input[j] !== '\n') j++;
    if (j < input.length && input[j] === '>') {
      out.push({ start: p, end: j + 1 });
      pos = j + 1;
    } else {
      pos = j;
    }
  }
}

export function linkifyMarkdown(input: string): string {
  if (!input) return input;

  // Collect regions that must NOT be touched.
  const skipSpans: Span[] = [];
  const SKIPS: RegExp[] = [
    // Fenced code block - non-greedy so separate blocks don't merge.
    /```[\s\S]*?```/g,
    // Tilde-fenced code block. CommonMark treats ~~~ as equivalent to ```,
    // and we consume markdown written by OTHER apps, so which fence character
    // our own serializer happens to emit says nothing about what arrives.
    /~~~[\s\S]*?~~~/g,
    // Inline code span - single backticks, no newlines inside.
    /`[^`\n]*`/g,
    // Existing inline markdown links [label](url): linkSpans, below.
    // Existing autolink <http://...> or <mailto:...>.
    /<(?:https?:\/\/|mailto:)[^>\s]+>/g,
    // Math: `$$...$$` and `$...$`, with the editor's guards for the inline
    // form (no space inside either dollar, no digit after the closing one),
    // so a price stays prose and a formula is never turned into a link.
    /\$\$[\s\S]*?\$\$/g,
    /(?<![\\$])\$(?![\s\d$])[^$\n]*?[^\s$\\]\$(?!\d)/g,
  ];
  // Existing inline links, and raw HTML tags. Markdown allows inline HTML and
  // imported bodies carry it, so without the tag skip an `<a href="https://x">`
  // became `<a href="<https://x>">` - a corrupted attribute rather than a
  // link. A tag needs a letter after `<` so prose comparisons ("a < b") are
  // untouched, and stops at a newline so a stray `<` cannot swallow a
  // paragraph. Both are scans rather than regexes, so a crafted line stays linear.
  linkSpans(input, skipSpans);
  htmlTagSpans(input, skipSpans);

  for (const re of SKIPS) {
    for (const m of input.matchAll(re)) {
      const start = m.index ?? 0;
      skipSpans.push({ start, end: start + m[0].length });
    }
  }
  skipSpans.sort((a, b) => a.start - b.start);

  // Merge any overlapping or nested skip regions so we don't double-copy.
  const merged: Span[] = [];
  for (const s of skipSpans) {
    const last = merged[merged.length - 1];
    if (last && s.start <= last.end) {
      last.end = Math.max(last.end, s.end);
    } else {
      merged.push({ ...s });
    }
  }

  // Walk the input: copy skipped regions verbatim, run the linkify pass
  // on the gaps between them.
  const parts: string[] = [];
  let cursor = 0;
  for (const span of merged) {
    if (cursor < span.start) {
      parts.push(linkifyPlainSegment(input.slice(cursor, span.start)));
    }
    parts.push(input.slice(span.start, span.end));
    cursor = span.end;
  }
  if (cursor < input.length) {
    parts.push(linkifyPlainSegment(input.slice(cursor)));
  }
  return parts.join('');
}

function linkifyPlainSegment(text: string): string {
  return linkifyEmails(linkifyUrls(text));
}

/**
 * Wrap bare emails in `<...>` autolinks. Runs AFTER the URL pass so an address
 * already inside an autolink or an `https://` URL's query string is behind an
 * angle bracket and no longer matches as bare.
 *
 * Emits the BARE form `<me@example.com>`, never `<mailto:me@example.com>`.
 * CommonMark's email-autolink rule already prepends `mailto:` to the href while
 * leaving the visible text clean; writing the prefix ourselves takes the other
 * branch, which renders the link with `mailto:` showing in the note body.
 */
function linkifyEmails(text: string): string {
  return text.replace(EMAIL_RE, (whole: string, lead: string, match: string, at: number, src: string) => {
    const offset = at + lead.length;
    // Skip anything already inside an autolink we just produced, and anything
    // that is really the tail of a longer token (an already-linkified URL).
    const before = src.slice(Math.max(0, offset - 8), offset);
    if (/<(?:mailto:)?$/.test(before) || /[/@:]$/.test(before)) return whole;
    if (src[offset + match.length] === '>') return whole;
    return `${lead}<${match}>`;
  });
}

function linkifyUrls(text: string): string {
  return text.replace(URL_RE, (match: string, offset: number) => {
    // Inside an open `==highlight==` on this line, a closing `==` is the
    // highlight's, not the URL's. Outside one, `=` stays: base64 padding
    // ends real URLs.
    // Counted only when the URL ends in `==`, so a long line of URLs stays linear.
    let inHighlight = false;
    if (match.endsWith('==')) {
      const lineStart = text.lastIndexOf('\n', offset - 1) + 1;
      inHighlight = (text.slice(lineStart, offset).match(/==/g)?.length ?? 0) % 2 === 1;
    }
    const { url, trailing } = trimUrl(match, inHighlight);
    // Degenerate: the whole match was punctuation somehow. Leave it alone.
    if (url.length === 0) return match;
    return `<${url}>${trailing}`;
  });
}

/**
 * Split a URL match into the URL and the characters after it that are not
 * part of it. We keep stripping until the last char is a plausible URL
 * character. `literal` text has no markdown, so `*`, `_` and `~` at the end
 * are the URL's own. The brackets are counted once, so a long run of them
 * stays linear.
 */
function trimUrl(match: string, inHighlight: boolean, literal = false): { url: string; trailing: string } {
  let parens = 0;
  let brackets = 0;
  for (let i = 0; i < match.length; i++) {
    const ch = match[i];
    if (ch === '(') parens++;
    else if (ch === ')') parens--;
    else if (ch === '[') brackets++;
    else if (ch === ']') brackets--;
  }
  let end = match.length;
  while (end > 0) {
    const last = match[end - 1]!;
    if (last === ')' || last === ']') {
      // Balanced: the closing sign belongs to the URL (Wikipedia article
      // names like "Foo_(bar)", query keys like "a[]"). Keep it.
      if ((last === ')' ? parens : brackets) >= 0) break;
      if (last === ')') parens++;
      else brackets++;
      end--;
    } else if (TRAILING_PUNCT_RE.test(last) && !(literal && /[*_~]/.test(last))) {
      end--;
    } else if (inHighlight && match.endsWith('==', end)) {
      end -= 2;
      inHighlight = false;
    } else {
      break;
    }
  }
  return { url: match.slice(0, end), trailing: match.slice(end) };
}

/**
 * Text typed in an app that shows every character literally, as markdown:
 * each bare URL and email becomes an autolink, and everything between them
 * goes through `escape`. The escape must never reach a URL, because markdown
 * reads no backslash escape inside an autolink: an escaped `_`, `~` or `[`
 * there lands in the href as `%5C` and on screen as a backslash.
 * `wrap` writes a URL's autolink, for a caller that must escape inside it
 * (a table cell, where `|` splits the row). `links` counts the autolinks made.
 */
export function linkifyLiteralText(
  text: string,
  escape: (s: string) => string,
  wrap: (url: string) => string = (url) => `<${url}>`,
): { markdown: string; links: number } {
  let links = 0;
  const gap = (s: string): string => {
    let out = '';
    let cursor = 0;
    for (const m of s.matchAll(EMAIL_RE)) {
      const at = (m.index ?? 0) + m[1]!.length;
      // The tail of a longer token (`user:me@x.com`, `a/b@c.com`) stays text.
      if (at > 0 && /[/@:]/.test(s[at - 1]!)) continue;
      out += `${escape(s.slice(cursor, at))}<${m[2]}>`;
      cursor = at + m[2]!.length;
      links++;
    }
    return out + escape(s.slice(cursor));
  };
  let markdown = '';
  let cursor = 0;
  for (const m of text.matchAll(URL_RE)) {
    const at = m.index ?? 0;
    const { url } = trimUrl(m[0], false, true);
    if (!url) continue;
    markdown += `${gap(text.slice(cursor, at))}${wrap(url)}`;
    cursor = at + url.length;
    links++;
  }
  return { markdown: markdown + gap(text.slice(cursor)), links };
}
