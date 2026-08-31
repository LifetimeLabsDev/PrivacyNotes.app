import type { LocalNote } from './db';
import type { ListPrefs } from './listPrefs';
import { compareNotes, deriveDisplayTitle } from './notesViewUtils';

/**
 * Tasks as a derived view over existing notes.
 *
 * We don't store tasks as their own entity. Every `- [ ] …` / `- [x] …`
 * line in any note's markdown body is a task; this module parses those
 * lines out of the live notes list and lets the UI render them as a
 * grouped checklist.
 *
 * Flipping a task re-writes the note's body (replacing `[ ]` with `[x]`
 * or vice versa on the same line index) and routes through the normal
 * updateNote path so sync / dirty flags just work.
 *
 * Matches TipTap's markdown serialization: one leading list marker
 * (`-`, `*`, `+`) + space + `[ ]` or `[x]` + space + content. Ordered
 * task lines (`1. [ ] …`) are intentionally NOT matched - TipTap's
 * tiptap-markdown doesn't emit those and treating them as tasks would
 * capture a numbered-list-with-brackets-in-the-text by accident.
 */

const TASK_LINE = /^(\s*)([-*+])\s+\[([ xX])\]\s?(.*)$/;

export type TaskItem = {
  noteId: string;
  noteTitle: string;
  lineIdx: number; // 0-based line index inside the note's body
  text: string; // task content, no marker, no checkbox
  checked: boolean;
  updatedAt: string; // parent note's updatedAt, for sorting
};

/**
 * Extract every task line from a single note body.
 */
function extractTasksFromNote(note: LocalNote): TaskItem[] {
  if (!note.body) return [];
  const out: TaskItem[] = [];
  const lines = note.body.split(/\r?\n/);
  // The notes list's own derivation, so a titleless note is called the same
  // thing in both places - and so the group header cannot print raw markdown
  // or HTML, which the hand-rolled first-line copy that used to live here did.
  const title = deriveDisplayTitle(note);
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i]!.match(TASK_LINE);
    if (!m) continue;
    out.push({
      noteId: note.id,
      noteTitle: title,
      lineIdx: i,
      text: (m[4] ?? '').replace(/&nbsp;/g, ' ').trim(),
      checked: m[3] === 'x' || m[3] === 'X',
      updatedAt: note.updatedAt,
    });
  }
  return out;
}

/**
 * Extract tasks across a set of notes. Caller is expected to pass the
 * active (non-trashed) notes. Trashed notes' tasks don't show up in the
 * Tasks view - if you trashed the note, you trashed its tasks too.
 */
export function extractAllTasks(notes: LocalNote[]): TaskItem[] {
  const all: TaskItem[] = [];
  for (const n of notes) {
    for (const t of extractTasksFromNote(n)) all.push(t);
  }
  return all;
}

/**
 * The Tasks pillar's note list: notes that carry task lines, plus notes
 * typed 'task' (so a task note stays visible once its last checkbox is
 * removed rather than becoming a ghost). Narrowed by the search box and
 * the read-only / PIN-protected toggles, ordered by the shared notes
 * comparator.
 *
 * Lives here rather than inside TasksList because NotesView derives the
 * same list to drive multi-select (shift-range, select-all). The two
 * hand-rolled copies had drifted apart on filtering, folder scope and
 * order, so multi-select could address rows the user could not see; one
 * selector makes them identical by construction.
 */
export function selectTaskNotes(
  activeNotes: LocalNote[],
  allTasks: TaskItem[],
  search: string,
  listPrefs: ListPrefs
): LocalNote[] {
  const q = search.trim().toLowerCase();
  const withTasks = new Set<string>();
  for (const t of allTasks) withTasks.add(t.noteId);
  let matching = activeNotes.filter(
    (n) => withTasks.has(n.id) || n.type === 'task'
  );
  if (!listPrefs.showLocked) matching = matching.filter((n) => n.locked !== 1);
  if (!listPrefs.showProtected)
    matching = matching.filter((n) => n.pinProtected !== 1);
  if (q) {
    matching = matching.filter(
      (n) =>
        (n.title ?? '').toLowerCase().includes(q) ||
        n.body.toLowerCase().includes(q)
    );
  }
  return matching.slice().sort((a, b) => compareNotes(a, b, listPrefs));
}

/**
 * Flip the checked state on a single task line. Returns the new body,
 * or null if the target line doesn't look like a task anymore (e.g.
 * the user edited the line between render and click).
 */
export function setTaskCheckedInBody(
  body: string,
  lineIdx: number,
  checked: boolean
): string | null {
  const lines = body.split(/\r?\n/);
  const line = lines[lineIdx];
  if (line == null) return null;
  const m = line.match(TASK_LINE);
  if (!m) return null;
  const [, indent, marker, , rest] = m;
  lines[lineIdx] = `${indent}${marker} [${checked ? 'x' : ' '}] ${rest ?? ''}`.replace(/\s+$/, '');
  return lines.join('\n');
}

/**
 * Append a new unchecked task line to the end of a body. If the body
 * doesn't already end with a blank line, one is inserted so the task
 * doesn't fuse with the previous paragraph.
 */
export function appendTaskToBody(body: string, text: string): string {
  const clean = text.trim();
  if (!clean) return body;
  const line = `- [ ] ${clean}`;
  if (!body) return line;
  // If the last non-empty line is already a task, just append another
  // task line directly - keeps the list contiguous.
  const trimmed = body.replace(/\s+$/, '');
  const lastNewline = trimmed.lastIndexOf('\n');
  const lastLine = lastNewline === -1 ? trimmed : trimmed.slice(lastNewline + 1);
  if (TASK_LINE.test(lastLine)) {
    return `${trimmed}\n${line}\n`;
  }
  return `${trimmed}\n\n${line}\n`;
}

/**
 * The dedicated "Inbox" note used by quick-add flows. Looked up by an
 * exact title match first (user-facing - they can see and rename it);
 * created on demand if missing. Returns the note id.
 */
export const INBOX_TITLE = 'Quick Tasks';
