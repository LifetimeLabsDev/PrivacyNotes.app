import { withoutArabicArticle } from './arabicFold';
import { foldText } from './textFold';

/**
 * One match of a query in a text. `rank` says where it starts: 3 at the start
 * of the text, 2 at the start of a word, 1 inside a word. `start` and `end`
 * are offsets into the text as written, for a highlight.
 */
export type TextMatch = { rank: 1 | 2 | 3; start: number; end: number };

const WHITESPACE_RUN = /\s+/g;
const WHITESPACE = /\s/;
const WORD_CHAR = /[\p{L}\p{N}\p{M}]/u;
const ARABIC = /\p{Script=Arabic}/u;
const LETTER_OR_MARK = /[\p{L}\p{M}]/u;
const ASCII_ONLY = /^[\x00-\x7f]*$/;

// A filter runs on every keystroke, and the Tasks pillar matches whole note
// bodies, so a long text is folded once and remembered. The memo forgets
// everything at once when it is full, so it never grows past its limit.
// Spec: ops/docs/design-decisions.md (search core)
const LONG_TEXT = 1000;
const REMEMBERED_TEXTS = 500;
const remembered = new Map<string, string>();

/**
 * What a match compares: the fold, with every run of whitespace as one space.
 * Exported for a caller that keeps folded copies of its own, which the notes
 * list does for the matches inside a word (`search.ts`).
 */
export function foldForMatch(text: string): string {
  return foldText(text).replace(WHITESPACE_RUN, ' ');
}

function foldedText(text: string): string {
  if (text.length < LONG_TEXT) return foldForMatch(text);
  let folded = remembered.get(text);
  if (folded === undefined) {
    if (remembered.size >= REMEMBERED_TEXTS) remembered.clear();
    folded = foldForMatch(text);
    remembered.set(text, folded);
  }
  return folded;
}

/** The character that ends at `i`, with a surrogate pair kept whole. */
function charBefore(s: string, i: number): string {
  if (i <= 0) return '';
  const low = s.charCodeAt(i - 1);
  if (low >= 0xdc00 && low <= 0xdfff && i >= 2) {
    const high = s.charCodeAt(i - 2);
    if (high >= 0xd800 && high <= 0xdbff) return s.slice(i - 2, i);
  }
  return s.charAt(i - 1);
}

function charFrom(s: string, i: number): string {
  const code = s.codePointAt(i);
  return code === undefined ? '' : String.fromCodePoint(code);
}

/**
 * Whether `at` follows an article that the index strips from the word it
 * starts, so "امان" starts a word in "الأمان" here as it does in the index.
 */
function afterArabicArticle(folded: string, at: number): boolean {
  if (!ARABIC.test(charBefore(folded, at))) return false;
  let start = at;
  for (let ch = charBefore(folded, start); ch && WORD_CHAR.test(ch); ch = charBefore(folded, start)) start -= ch.length;
  let end = at;
  for (let ch = charFrom(folded, end); ch && WORD_CHAR.test(ch); ch = charFrom(folded, end)) end += ch.length;
  const word = folded.slice(start, end);
  const bare = withoutArabicArticle(word);
  return bare !== null && start + word.length - bare.length === at;
}

function startsWord(folded: string, at: number): boolean {
  return !WORD_CHAR.test(charBefore(folded, at)) || afterArabicArticle(folded, at);
}

function rankAt(folded: string, at: number): 1 | 2 | 3 {
  // Leading whitespace, already one space, does not count.
  if (at === (folded.charCodeAt(0) === 32 ? 1 : 0)) return 3;
  return startsWord(folded, at) ? 2 : 1;
}

const graphemes =
  typeof Intl !== 'undefined' && 'Segmenter' in Intl
    ? new Intl.Segmenter(undefined, { granularity: 'grapheme' })
    : null;

function graphemesOf(text: string): Iterable<{ segment: string; index: number }> {
  if (graphemes) return graphemes.segment(text);
  const out: { segment: string; index: number }[] = [];
  let index = 0;
  for (const segment of text) {
    out.push({ segment, index });
    index += segment.length;
  }
  return out;
}

/**
 * The folded range [from, to) as offsets into the text as written. The fold
 * changes lengths (ß becomes "ss", İ loses its dot, a mark goes), so the walk
 * folds the text one grapheme at a time, with the same whitespace rule, and
 * stops at the end of the match. A range that ends inside a grapheme takes the
 * whole grapheme, and in Arabic the whole word, because a mark that splits an
 * Arabic word can break its letter joining. The range never leaves the text.
 */
function originalRange(text: string, folded: string, from: number, to: number): [number, number] {
  if (folded.length === text.length && ASCII_ONLY.test(text)) return [from, to];
  let start = -1;
  let end = text.length;
  let emitted = 0;
  let inSpace = false;
  for (const { segment, index } of graphemesOf(text)) {
    let length = 0;
    for (const ch of foldText(segment)) {
      const space = WHITESPACE.test(ch);
      if (space && inSpace) continue;
      inSpace = space;
      length += space ? 1 : ch.length;
    }
    if (length === 0) continue;
    if (start < 0 && emitted + length > from) start = index;
    emitted += length;
    if (emitted >= to) {
      end = index + segment.length;
      break;
    }
  }
  if (start < 0) start = Math.min(from, text.length);
  if (ARABIC.test(text.slice(start, end))) {
    for (let ch = charBefore(text, start); ch && LETTER_OR_MARK.test(ch); ch = charBefore(text, start)) start -= ch.length;
    for (let ch = charFrom(text, end); ch && LETTER_OR_MARK.test(ch); ch = charFrom(text, end)) end += ch.length;
  }
  return [start, Math.max(start, end)];
}

// Most lists only filter, so the offsets are worked out on the first read.
function located(text: string, folded: string, from: number, to: number, rank: 1 | 2 | 3): TextMatch {
  let range: [number, number] | undefined;
  const bounds = () => (range ??= originalRange(text, folded, from, to));
  return {
    rank,
    get start() {
      return bounds()[0];
    },
    get end() {
      return bounds()[1];
    },
  };
}

/**
 * The one matcher for every list that is not the notes index. The query folds
 * once, here, and a text matches when its fold holds the whole query as one
 * piece, anywhere: several words are one phrase, and a word inside a word
 * counts ("wagen" finds "Einkaufswagen"). Both sides go through `foldText`,
 * with each run of whitespace as one space and the query trimmed. The match
 * reported is the one with the best rank, the first of those. Chinese,
 * Japanese and Thai are not split into words, so a match inside a run of
 * their letters ranks 1. A query that folds to nothing matches nothing; an
 * empty query is the caller's to handle, and a list shows every item for it.
 * Spec: ops/docs/design-decisions.md (search core)
 */
export function textMatcher(query: string): (text: string) => TextMatch | null {
  const needle = foldForMatch(query).trim();
  if (!needle) return () => null;
  return (text) => {
    const folded = foldedText(text);
    let at = folded.indexOf(needle);
    if (at < 0) return null;
    let best = at;
    let rank = rankAt(folded, at);
    while (rank === 1) {
      at = folded.indexOf(needle, at + 1);
      if (at < 0) break;
      if (startsWord(folded, at)) {
        best = at;
        rank = 2;
      }
    }
    return located(text, folded, best, best + needle.length, rank);
  };
}
