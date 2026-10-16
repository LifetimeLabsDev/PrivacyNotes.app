import { diffArrays } from 'diff';
import type { Node as PMNode } from '@tiptap/pm/model';
import { Decoration, DecorationSet } from '@tiptap/pm/view';

/**
 * The comparison Note history draws between a saved version and the current
 * note. It works on the two parsed documents, never on the markdown, so a
 * reader sees the note as the editor shows it and the syntax never shows up
 * as a change.
 *
 * Top-level blocks are matched first, by their whole structure. A removed
 * block and an added block at the same place are compared word by word when
 * they share enough text, and are shown as one removed and one added block
 * when they do not. Two blocks with the same words but a different shape (a
 * bold word, a paragraph made a heading, a note-link that points elsewhere)
 * are marked as a formatting change, never as replaced words.
 *
 * Each side gets its own decorations: removed text on the older version,
 * added text on the current note. Nothing is inserted into either document.
 */

export type NoteDiff = {
  older: DecorationSet;
  current: DecorationSet;
  /** Changed places: a run of changed words, a block, a formatting change. */
  changes: number;
};

/** Past this size of the two documents together (in editor positions,
 *  about one per character), no comparison is drawn: the word lists cost
 *  too much. */
const MAX_COMPARE_CHARS = 400_000;
/** Myers gives up past this many edits and the result says so. */
const MAX_EDIT_LENGTH = 4_000;
/** Below this share of common text, two blocks are not one block edited. */
const MIN_SHARED = 0.3;

type Token = { s: string; from: number; to: number };
type Block = { node: PMNode; pos: number; key: string };

const SEPARATOR: Token = { s: '\n', from: -1, to: -1 };

const segmenter =
  typeof Intl !== 'undefined' && 'Segmenter' in Intl
    ? new Intl.Segmenter(undefined, { granularity: 'word' })
    : null;

// Words, runs of spaces, and single marks; scripts written without spaces
// fall to one character each when the browser has no word segmenter.
const FALLBACK_WORD =
  /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Thai}]|[\p{L}\p{M}\p{N}_]+|\s+|./gsu;

function words(text: string): { s: string; at: number }[] {
  if (segmenter) return Array.from(segmenter.segment(text), (seg) => ({ s: seg.segment, at: seg.index }));
  return Array.from(text.matchAll(FALLBACK_WORD), (m) => ({ s: m[0], at: m.index ?? 0 }));
}

/** A leaf inside text (a note-link, an image, a hard break) is one token,
 *  keyed by everything it stores, so a changed target counts as a change. */
function atomToken(node: PMNode, from: number): Token {
  return { s: '￼' + JSON.stringify(node.toJSON()), from, to: from + node.nodeSize };
}

function textblockTokens(tb: PMNode, contentStart: number, out: Token[]) {
  let buf = '';
  let bufFrom = 0;
  const flush = () => {
    for (const w of words(buf)) out.push({ s: w.s, from: bufFrom + w.at, to: bufFrom + w.at + w.s.length });
    buf = '';
  };
  tb.forEach((inline, offset) => {
    if (inline.isText) {
      if (!buf) bufFrom = contentStart + offset;
      buf += inline.text ?? '';
    } else {
      flush();
      out.push(atomToken(inline, contentStart + offset));
    }
  });
  flush();
}

function blockTokens(block: Block): Token[] {
  const out: Token[] = [];
  if (block.node.isTextblock) {
    textblockTokens(block.node, block.pos + 1, out);
    return out;
  }
  block.node.descendants((child, pos) => {
    const at = block.pos + 1 + pos;
    if (child.isTextblock) {
      if (out.length) out.push(SEPARATOR);
      textblockTokens(child, at + 1, out);
      return false;
    }
    if (child.isLeaf) out.push(atomToken(child, at));
    return true;
  });
  return out;
}

function blocksOf(doc: PMNode): Block[] {
  const blocks: Block[] = [];
  doc.forEach((node, pos) => blocks.push({ node, pos, key: JSON.stringify(node.toJSON()) }));
  return blocks;
}

/** Adds one inline decoration per changed token, merged where they touch. */
function markTokens(tokens: Token[], into: Decoration[], kind: 'ins' | 'del') {
  let from = -1;
  let to = -1;
  const push = () => {
    if (from >= 0) into.push(Decoration.inline(from, to, { nodeName: kind, class: `pn-diff-${kind}` }));
    from = -1;
  };
  for (const t of tokens) {
    if (t.from < 0) continue;
    if (from >= 0 && t.from === to) {
      to = t.to;
    } else {
      push();
      from = t.from;
      to = t.to;
    }
  }
  push();
}

function blockDecoration(block: Block, cls: string, title?: string): Decoration {
  return Decoration.node(block.pos, block.pos + block.node.nodeSize, title ? { class: cls, title } : { class: cls });
}

export function computeNoteDiff(
  olderDoc: PMNode,
  currentDoc: PMNode,
  formatLabel: string,
): NoteDiff | null {
  if (olderDoc.content.size + currentDoc.content.size > MAX_COMPARE_CHARS) return null;
  const olderBlocks = blocksOf(olderDoc);
  const currentBlocks = blocksOf(currentDoc);
  const blockChanges = diffArrays(
    olderBlocks.map((b) => b.key),
    currentBlocks.map((b) => b.key),
    { maxEditLength: MAX_EDIT_LENGTH },
  );
  if (!blockChanges) return null;

  const olderDecos: Decoration[] = [];
  const currentDecos: Decoration[] = [];
  let changes = 0;

  const wholeBlocks = (removed: Block[], added: Block[]) => {
    for (const b of removed) olderDecos.push(blockDecoration(b, 'pn-diff-block-del'));
    for (const b of added) currentDecos.push(blockDecoration(b, 'pn-diff-block-ins'));
    changes += removed.length + added.length;
  };

  const pair = (o: Block, c: Block) => {
    if (o.node.isLeaf || c.node.isLeaf) return wholeBlocks([o], [c]);
    const ot = blockTokens(o);
    const ct = blockTokens(c);
    if (ot.map((t) => t.s).join('') === ct.map((t) => t.s).join('')) {
      olderDecos.push(blockDecoration(o, 'pn-diff-block-format', formatLabel));
      currentDecos.push(blockDecoration(c, 'pn-diff-block-format', formatLabel));
      changes += 1;
      return;
    }
    const tokenChanges = diffArrays(ot.map((t) => t.s), ct.map((t) => t.s), { maxEditLength: MAX_EDIT_LENGTH });
    if (!tokenChanges) return wholeBlocks([o], [c]);
    let shared = 0;
    for (const ch of tokenChanges) if (!ch.added && !ch.removed) shared += ch.value.join('').length;
    const longer = Math.max(ot.reduce((n, t) => n + t.s.length, 0), ct.reduce((n, t) => n + t.s.length, 0));
    if (shared / longer < MIN_SHARED) return wholeBlocks([o], [c]);
    let oi = 0;
    let ci = 0;
    let previousWasRemoval = false;
    for (const ch of tokenChanges) {
      if (ch.removed) {
        markTokens(ot.slice(oi, oi + ch.count), olderDecos, 'del');
        oi += ch.count;
        changes += 1;
      } else if (ch.added) {
        markTokens(ct.slice(ci, ci + ch.count), currentDecos, 'ins');
        ci += ch.count;
        // A replacement is one change, not a removal and an addition.
        if (!previousWasRemoval) changes += 1;
      } else {
        oi += ch.count;
        ci += ch.count;
      }
      previousWasRemoval = ch.removed;
    }
  };

  let oi = 0;
  let ci = 0;
  let removed: Block[] = [];
  let added: Block[] = [];
  const flush = () => {
    const paired = Math.min(removed.length, added.length);
    removed.slice(0, paired).forEach((o, k) => pair(o, added[k] as Block));
    wholeBlocks(removed.slice(paired), added.slice(paired));
    removed = [];
    added = [];
  };
  for (const ch of blockChanges) {
    if (ch.removed) {
      removed.push(...olderBlocks.slice(oi, oi + ch.count));
      oi += ch.count;
    } else if (ch.added) {
      added.push(...currentBlocks.slice(ci, ci + ch.count));
      ci += ch.count;
    } else {
      flush();
      oi += ch.count;
      ci += ch.count;
    }
  }
  flush();

  return {
    older: DecorationSet.create(olderDoc, olderDecos),
    current: DecorationSet.create(currentDoc, currentDecos),
    changes,
  };
}
