import type { Node as ProseMirrorNode } from '@tiptap/pm/model';
import type { LocalNote } from './db';
import type { ImportedNote } from './import/types';
import { NOTE_MAX_STORED_BYTES, storedNoteBytes } from './sync';

/**
 * Cutting a note that is too large to sync into parts that each fit.
 * Spec: ops/docs/plans/note-size-limit.md
 */

/** Room each part keeps under the ceiling for a longer title and the
 *  note-link to the next part. */
const PART_MARGIN = 2048;

const utf8 = new TextEncoder();

/** The bytes a piece of body adds to the sealed JSON: JSON escapes are per
 *  character, so the cost of a body is the sum of the cost of its pieces. */
function jsonCost(text: string): number {
  return utf8.encode(JSON.stringify(text)).length - 2;
}

const FENCE = /^ {0,3}(`{3,}|~{3,})/;
const HEADING = /^ {0,3}#{1,6}(\s|$)/;

/** The text cut into pieces before each line `cutBefore` names, outside code
 *  fences. Every line keeps its newline, so the pieces join back to `text`. */
function piecesAt(text: string, cutBefore: (line: string, prev: string | null) => boolean, fences = true): string[] {
  const lines = text.match(/[^\n]*\n|[^\n]+$/g) ?? [];
  const pieces: string[] = [];
  let current = '';
  let fence: string | null = null;
  let prev: string | null = null;
  for (const line of lines) {
    if (current && (!fences || fence === null) && cutBefore(line, prev)) {
      pieces.push(current);
      current = '';
    }
    current += line;
    const open = fences ? FENCE.exec(line) : null;
    const mark = open?.[1]?.[0] ?? null;
    if (mark) {
      if (fence === null) fence = mark;
      else if (mark === fence) fence = null;
    }
    prev = line;
  }
  if (current) pieces.push(current);
  return pieces;
}

const LEVELS: Array<(text: string) => string[]> = [
  (text) => piecesAt(text, (line) => HEADING.test(line)),
  // A block starts after a blank line, and a code fence starts and ends one
  // even with no blank line around it.
  (text) => piecesAt(text, (line, prev) =>
    line.trim() !== '' && prev !== null && (prev.trim() === '' || FENCE.test(line) || FENCE.test(prev))),
  (text) => piecesAt(text, () => true, false),
  (text) => [...text],
];

/**
 * The body cut into parts that each fit the sync ceiling: at headings first,
 * then at paragraphs, then at lines, never inside a code fence until only a
 * line cut is left. `measure` gives the stored size of a note with a body,
 * and is asked once, for the empty body, to learn what the rest of the note
 * costs. The parts join back to the body exactly.
 */
export function splitMarkdownToFit(body: string, measure: (body: string) => number): string[] {
  const fixed = Math.ceil((measure('') * 3) / 4);
  const budget = Math.floor((NOTE_MAX_STORED_BYTES * 3) / 4) - fixed - PART_MARGIN;
  if (jsonCost(body) <= budget) return [body];

  const parts: string[] = [];
  let current = '';
  let currentCost = 0;
  const flush = () => {
    if (current) parts.push(current);
    current = '';
    currentCost = 0;
  };
  const pack = (text: string, level: number) => {
    const cutLevel = LEVELS[level];
    if (!cutLevel) return;
    for (const piece of cutLevel(text)) {
      const cost = jsonCost(piece);
      if (cost > budget && level < LEVELS.length - 1) {
        flush();
        pack(piece, level + 1);
        flush();
        continue;
      }
      if (currentCost + cost > budget) flush();
      current += piece;
      currentCost += cost;
    }
  };
  pack(body, 0);
  flush();
  return parts;
}

/**
 * Where the editor's split puts the new note's first block, as an index into
 * the document's top-level blocks: the nearest heading at or above the
 * cursor's block, else the cursor's block, else the block at the middle of
 * the note. Null when the note has fewer than two blocks to divide.
 */
export function splitIndex(doc: ProseMirrorNode, pos: number): number | null {
  if (doc.childCount < 2) return null;
  const at = Math.min(doc.resolve(Math.max(0, Math.min(pos, doc.content.size))).index(0), doc.childCount - 1);
  for (let i = at; i > 0; i--) {
    if (doc.child(i).type.name === 'heading') return i;
  }
  if (at > 0) return at;
  let seen = 0;
  for (let i = 0; i < doc.childCount; i++) {
    seen += doc.child(i).nodeSize;
    if (seen * 2 >= doc.content.size) return Math.max(1, Math.min(i + 1, doc.childCount - 1));
  }
  return doc.childCount - 1;
}

/** The stored size an imported note will have once it is a row. */
export function importedNoteBytes(n: ImportedNote): number {
  const row = {
    id: '', title: n.title, body: n.body, tags: n.tags, createdAt: n.createdAt, updatedAt: n.updatedAt,
    editedAt: n.editedAt ?? n.updatedAt, dirty: 1, deleted: 0, trashed: n.trashed ? 1 : 0,
    starred: n.starred ? 1 : 0, locked: n.locked ? 1 : 0, pinProtected: n.pinProtected ? 1 : 0,
    type: n.type ?? 'note', folderId: n.folderId ?? null, trackers: n.trackers, archived: n.archived ? 1 : 0,
  } as LocalNote;
  return storedNoteBytes(row);
}

/** An imported plain note too large to sync. A note that carries its own id
 *  comes from our backup, which a restore matches by id, so it is never cut. */
export function isOversizeImport(n: ImportedNote): boolean {
  return (n.type ?? 'note') === 'note' && !n.id && importedNoteBytes(n) > NOTE_MAX_STORED_BYTES;
}

/**
 * An oversize imported note as parts that each fit, cut by
 * splitMarkdownToFit. Every part but the last ends with a note-link to the
 * next one; the parts share the note's tags, folder and dates.
 */
export function splitImportedNote<T extends ImportedNote>(
  n: T,
  partTitle: (index: number, total: number) => string,
  linkLine: (title: string) => string,
): T[] {
  const bodies = splitMarkdownToFit(n.body, (body) => importedNoteBytes({ ...n, body, title: partTitle(99, 99) }));
  if (bodies.length < 2) return [n];
  const titles = bodies.map((_, i) => partTitle(i + 1, bodies.length));
  return bodies.map((body, i) => {
    const next = titles[i + 1];
    return {
      ...n,
      title: titles[i] ?? n.title,
      body: next ? `${body.trimEnd()}\n\n${linkLine(next)}\n` : body,
    };
  });
}
