/** An open code fence: its character and how many of it opened the block. */
export type Fence = { char: string; len: number };

/**
 * The code fence state after one markdown line, and whether the line is a
 * fence line itself. CommonMark's rule: three or more backticks or tildes
 * open a block (a backtick fence carries no backtick in its info string), and
 * only a run of the same character, at least as long, with nothing after it
 * closes it; every other line inside is code. `maxIndent` is how far a fence
 * line may be indented: three spaces at the top level, any depth for a
 * reader that does not track list containers.
 */
export function nextFence(open: Fence | null, line: string, maxIndent = 3): { fence: Fence | null; isFence: boolean } {
  const m = /^([ \t]*)(`{3,}|~{3,})(.*)$/.exec(line);
  if (!m || m[1]!.length > maxIndent) return { fence: open, isFence: false };
  const char = m[2]![0]!;
  const len = m[2]!.length;
  if (open === null) {
    if (char === '`' && m[3]!.includes('`')) return { fence: null, isFence: false };
    return { fence: { char, len }, isFence: true };
  }
  if (char === open.char && len >= open.len && m[3]!.trim() === '') return { fence: null, isFence: true };
  return { fence: open, isFence: false };
}
