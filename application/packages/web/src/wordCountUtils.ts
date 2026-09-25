/**
 * Shared word-counting utility. Both the per-note WordCount component
 * and the aggregate stats (footer chip, StatsModal) use this so the
 * numbers always agree.
 *
 * Strips markdown syntax so only visible prose is counted. Covers
 * every format the TipTap toolbar can produce.
 */

import { hasCJK, segmentWords } from './cjkSegment';
import { isDelimiterRow } from './tableDelimiterRow';

export function stripMarkdown(md: string): string {
  return md
    // A table's delimiter row carries no words, and its dash counts are the
    // column widths: left in, each column read as a word and every dash as a
    // character, so resizing a column changed the note's count.
    .split('\n')
    .filter((line) => !isDelimiterRow(line))
    .join('\n')
    // Strip raw HTML the editor emits into the markdown body before counting:
    // the table fallback serializer writes full <table>...</table> HTML, and
    // colored text serializes as <span style="color:...">. Without this every
    // tag token ("<td", 'colspan="1"', ...) counts as a word - an empty 3x100
    // table read as ~1000 words and bloated the all-notes stats scan.
    .replace(/<\/?[a-zA-Z][^>]*>/g, ' ')    // HTML tags (table fallback, color spans, <br>)
    .replace(/&(?:[a-zA-Z]+|#\d+|#x[0-9a-fA-F]+);/g, ' ') // HTML entities incl. &nbsp; (empty-paragraph marker)
    .replace(/^#{1,6}\s+/gm, '')           // heading markers
    .replace(/^>\s?/gm, '')                 // blockquotes
    .replace(/^- \[[ xX]\]\s*/gm, '')       // task list markers
    .replace(/^[-*+]\s+/gm, '')             // unordered list markers
    .replace(/^\d+\.\s+/gm, '')             // ordered list markers
    .replace(/^---+$/gm, '')                // horizontal rules
    .replace(/```[\s\S]*?```/g, (m) =>      // code blocks → keep inner text
      m.replace(/^```.*\n?/m, '').replace(/\n?```$/m, ''))
    .replace(/!\[.*?\]\(.*?\)/g, '')        // images
    .replace(/\[([^\]]*)\]\(.*?\)/g, '$1')  // links → keep text
    .replace(/\|/g, ' ')                    // table pipes → spaces
    .replace(/[*_~`]+/g, '');               // bold / italic / strikethrough / inline code
}

/** Count visible prose words in a markdown string. Japanese and Chinese do not
 *  put spaces between words, so a whitespace split counts a whole page as one
 *  word (which also starved the writing milestones); segment CJK text into word
 *  units instead. Latin text keeps the exact whitespace split. Mixed text counts
 *  both. Spec: ops/docs/i18n-cjk-plan.md (CJK tokenization). */
export function countWords(md: string): number {
  const text = stripMarkdown(md).trim();
  if (!text) return 0;
  if (!hasCJK(text)) return text.split(/\s+/).filter(Boolean).length;
  return segmentWords(text).length;
}

/** Count visible prose characters (spaces included) in a markdown string.
 *  Mirrors countWords - strips markdown first so word and character figures
 *  agree, and collapses whitespace runs so stripped-out syntax (table pipes,
 *  HTML tags) can't inflate the count. */
export function countChars(md: string): number {
  return stripMarkdown(md).trim().replace(/\s+/g, ' ').length;
}
