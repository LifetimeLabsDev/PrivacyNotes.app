import { COMMAND_PREFIX } from './commandPalette';
import type { QuickAdd } from './quickAdd';
import { dayNumber, shiftDay } from './schedule';
import { stripToPlainText } from './notesViewUtils';
import { isDelimiterRow, tableWidthFromMarker } from './tableDelimiterRow';
import { foldForMatch, textMatcher } from './textMatch';

/**
 * What the quick switcher reads out of its query before it matches anything.
 * A prefix typed first picks one kind of row: "+" the quick add, ">" the
 * commands, "#" the tags, "/" the folders. The word "add" and a space is a
 * second way into the quick add, in English and in the reader's language
 * (`quickAdd.json` `words.add`). Anything else is a jump. The mode lives in
 * the query, so the input always shows it and Backspace leaves it.
 * Spec: ops/docs/archive/quick-add-prefix.md
 */
export const CREATE_PREFIX = '+';
export const TAG_PREFIX = '#';
export const FOLDER_PREFIX = '/';

export type SwitcherMode = 'create' | 'commands' | 'tags' | 'folders' | 'jump';

/**
 * The mode of a query and the text the rows match, its prefix taken off and
 * trimmed. The prefix is the first character as typed, so a leading space
 * escapes every one: " +1 ideas" finds a title that starts with "+". An add
 * word counts only with a space after it, so "address" stays a jump; the
 * words come folded, as `readWords` gives them. `filters` says the switcher
 * has the sidebar's tags and folders to list.
 */
export function readSwitcherQuery(
  query: string,
  filters: boolean,
  addWords: readonly string[] = [],
): { mode: SwitcherMode; text: string } {
  const rest = (n: number) => query.slice(n).trim();
  if (query.startsWith(CREATE_PREFIX)) return { mode: 'create', text: rest(1) };
  if (query.startsWith(COMMAND_PREFIX)) return { mode: 'commands', text: rest(1) };
  if (filters && query.startsWith(TAG_PREFIX)) return { mode: 'tags', text: rest(1) };
  if (filters && query.startsWith(FOLDER_PREFIX)) return { mode: 'folders', text: rest(1) };
  const word = /^(\S+)\s/.exec(query)?.[1];
  if (word && addWords.includes(foldForMatch(word))) return { mode: 'create', text: rest(word.length) };
  return { mode: 'jump', text: query.trim() };
}

/**
 * What the switcher says when it lists nothing. With nothing typed the vault
 * is empty, so it names the way to add an item, not a name that was missed.
 */
export function emptyMessage(mode: SwitcherMode, query: string, quickAdd: boolean): string {
  if (mode === 'commands') return 'palette.empty';
  if (mode === 'tags') return 'quickSwitcher.emptyTags';
  if (mode === 'folders') return 'quickSwitcher.emptyFolders';
  return !query && quickAdd ? 'quickSwitcher.emptyVault' : 'quickSwitcher.empty';
}

/** Typed inside a quick add, it adds the text to an item that exists. */
const APPEND_MARK = '>>';

/**
 * "milk, eggs >> groc": the text to add and the start of the item's title.
 * The last mark counts, so a ">>" inside the text stays text. Null when the
 * query has no mark or nothing before it. The target may be empty: the
 * switcher then offers the likely items.
 */
export function splitAppend(text: string): { text: string; target: string } | null {
  const at = text.lastIndexOf(APPEND_MARK);
  if (at < 0) return null;
  const before = text.slice(0, at).trim();
  if (!before) return null;
  return { text: before, target: text.slice(at + APPEND_MARK.length).trim() };
}

/** A list comma in any script: Latin, Arabic, the ideographic and the full-width one. */
const LIST_COMMA = /[,،、，]/;
/** A quoted run, as the quick add's parser reads one: its comma is text. */
const QUOTED = /"[^"]*"|“[^”]*”|«[^»]*»/g;

/**
 * The lines an append writes: a comma list becomes one line a part, with
 * the comma of any script. A comma inside quotes stays in its line, and the
 * quotes go, as they do from a quick add's title.
 */
export function appendLines(text: string): string[] {
  const quoted: string[] = [];
  const masked = text.replace(QUOTED, (m) => `\u0000${quoted.push(m.slice(1, -1)) - 1}\u0000`);
  return masked
    .split(LIST_COMMA)
    .map((s) => s.replace(/\u0000(\d+)\u0000/g, (_, k: string) => quoted[Number(k)]!).replace(/\s+/g, ' ').trim())
    .filter(Boolean);
}

/** The marks inside a word that the pre-check of a line drops ("**bo**ld"). */
const EMPHASIS_MARKS = /[*_~`=\\]/g;
/** How many characters of context a snippet keeps on each side of the match. */
const SNIPPET_SIDE = 40;

/**
 * One line of a body as the list preview shows it: through the one preview
 * stripper (`stripToPlainText`), so a snippet never shows what a list row
 * hides, a spoiler included. A table row reads as its cells; its rule row and
 * width marker read as nothing.
 */
function plainLine(line: string): string {
  const t = line.trim();
  if (!t || isDelimiterRow(t) || tableWidthFromMarker(t) !== null) return '';
  const plain = stripToPlainText(t);
  if (!/^\|.*\|$/.test(plain)) return plain.replace(/\s+/g, ' ');
  return plain
    .slice(1, -1)
    .split('|')
    .map((c) => c.replace(/\s+/g, ' ').trim())
    .filter(Boolean)
    .join(' · ');
}

/**
 * One line of a body around the first word of the query it holds, for a hit
 * on the text and not the title: the line as plain text, cut to a window
 * around the match, with the match's offsets for a highlight. The words are
 * tried in query order; null when the body holds none of them.
 */
export function bodySnippet(body: string, query: string): { text: string; start: number; end: number } | null {
  const words = query.split(/\s+/).filter((w) => w.length > 1);
  for (const word of words) {
    const match = textMatcher(word);
    const could = textMatcher(word.replace(EMPHASIS_MARKS, '') || word);
    for (const raw of body.split('\n')) {
      // Stripping a line costs far more than matching it, and a long body
      // has thousands: strip only a line whose raw text, its emphasis and
      // escape marks dropped, could hold the word.
      if (!could(raw.replace(EMPHASIS_MARKS, ''))) continue;
      const line = plainLine(raw);
      const m = line ? match(line) : null;
      if (!m) continue;
      const from = Math.max(0, m.start - SNIPPET_SIDE);
      const to = Math.min(line.length, m.end + SNIPPET_SIDE);
      const head = from > 0 ? '...' : '';
      const text = `${head}${line.slice(from, to)}${to < line.length ? '...' : ''}`;
      return { text, start: m.start - from + head.length, end: m.end - from + head.length };
    }
  }
  return null;
}

/**
 * Whether the switcher lists an item the search found by its text, and with
 * which snippet. A Markdown body lists only when the reader can see a word of
 * the query (a snippet); a hit that is only in markup, a link's address or a
 * masked spoiler is left out. Any other type (a vault item, a contact) lists
 * with no snippet, because its body is data, not text to quote.
 */
export function textHit(body: string, query: string, markdown: boolean): { snippet: ReturnType<typeof bodySnippet> } | null {
  if (!markdown) return { snippet: null };
  const snippet = bodySnippet(body, query);
  return snippet ? { snippet } : null;
}

/** A web address with no spaces: "example.com/a", "www.x.org", "https://x.io". */
const URL_LIKE = /^(?:https?:\/\/)?(?:[\p{L}\p{N}-]+\.)+\p{L}{2,}(?::\d+)?(?:[/?#]\S*)?$/iu;

/**
 * The text as a link a bookmark or a clip can take, "https://" added where
 * it was left out; null when the text is not one web address.
 */
export function asWebAddress(text: string): string | null {
  const clean = text.trim();
  // A typed scheme says it is a link, whatever the host ("http://localhost:5173").
  if (/^https?:\/\/\S+$/i.test(clean)) {
    try {
      return new URL(clean).hostname ? clean : null;
    } catch {
      return null;
    }
  }
  if (!URL_LIKE.test(clean)) return null;
  return /^https?:\/\//i.test(clean) ? clean : `https://${clean}`;
}

/**
 * The day a jump query names when it is a date and nothing else ("fri",
 * "oct 24", "12/24", "mon 3pm"): the switcher's "Go to day". Null for a
 * time alone ("3pm" names no day), a span, a repeat, or words left over.
 */
export function dayOfQuery(parsed: QuickAdd, today: string): string | null {
  if (!parsed.day || parsed.title.trim() || parsed.end || parsed.repeat) return null;
  if (!parsed.parts.some((p) => p.kind === 'date')) return null;
  // A date with no year was read as the next time it comes ("oct 1" in late
  // October is next year's). To go somewhere, the nearer one is meant: this
  // year's, three weeks ago.
  if (!parsed.guessedYear) return parsed.day;
  const before = `${Number(parsed.day.slice(0, 4)) - 1}${parsed.day.slice(4)}`;
  const away = (day: string) => Math.abs(dayNumber(day) - dayNumber(today));
  return shiftDay(before, 0) === before && away(before) < away(parsed.day) ? before : parsed.day;
}
