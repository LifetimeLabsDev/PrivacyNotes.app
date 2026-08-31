/**
 * Math source-editing geometry, kept out of Editor.tsx so it can be tested
 * without dragging in React, ProseMirror node views and `katex.min.css`.
 *
 * Spec: ops/docs/design-decisions.md (Math extension: official over third-party)
 */

/**
 * Where the caret goes when a math node is turned back into editable source.
 *
 * The arithmetic IS the bug this exists to prevent. An offset computed
 * against the position of the node being REPLACED, ignoring that a block
 * replacement is wrapped in a paragraph, sends the caret past the new text
 * and into the block below. Inline math has no wrapper and so no offset -
 * conflating the two is the trap.
 *
 * `pos` is the document position of the math node. The returned `caret` sits
 * just INSIDE the closing delimiter, which is where you want it to fix a typo
 * rather than parked after the final `$`.
 */
export function mathSourceEdit(
  latex: string,
  pos: number,
  block: boolean,
): { source: string; caret: number } {
  const delim = block ? '$$' : '$';
  const source = `${delim}${latex}${delim}`;
  // +1 for the paragraph's opening token when the text is wrapped in one.
  const wrapper = block ? 1 : 0;
  return { source, caret: pos + wrapper + source.length - delim.length };
}
