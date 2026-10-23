/**
 * Find and replace over the raw text of the Markdown source view. The rich
 * editor's engine (editorSearch.ts) is a ProseMirror plugin and has nothing to
 * act on in a textarea; this is the same match rule on a plain string: the
 * query taken literally, case-insensitive unless asked, no regex.
 * Spec: ops/docs/archive/find-and-replace.md (section 14, the Markdown view)
 */

export type TextMatch = { from: number; to: number };

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Every match of `query` in `text`, in order, never overlapping. */
export function findTextMatches(text: string, query: string, caseSensitive: boolean): TextMatch[] {
  if (!query) return [];
  const re = new RegExp(escapeRegExp(query), caseSensitive ? 'g' : 'gi');
  const out: TextMatch[] = [];
  for (const m of text.matchAll(re)) out.push({ from: m.index, to: m.index + m[0].length });
  return out;
}

/** `text` with every match replaced by `replacement`, taken literally. */
export function replaceAllText(text: string, matches: readonly TextMatch[], replacement: string): string {
  let out = '';
  let at = 0;
  for (const m of matches) {
    out += text.slice(at, m.from) + replacement;
    at = m.to;
  }
  return out + text.slice(at);
}
