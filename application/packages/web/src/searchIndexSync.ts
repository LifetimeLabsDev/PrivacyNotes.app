import { useEffect, useRef, useState } from 'react';
import type { LocalNote } from './db';
import { updateSearchIndex } from './search';

/**
 * Keeps the full-text index in lockstep with the notes STATE, which is
 * the one choke point every mutation flows through: refresh() replaces
 * the array, and local edits (create, rename, per-keystroke saves, bulk
 * rewrites, trash) patch it in place. Indexing here means a note is
 * searchable the moment the UI can show it - the class of bug where a
 * freshly created note returned "No matches" until the next tab focus
 * came from the index being rebuilt only inside refresh().
 *
 * The diff is by object REFERENCE: every state writer replaces exactly
 * the note objects it changed and passes the rest through, so reference
 * inequality is "this note changed" and the common case diffs in
 * microseconds. A full refresh replaces every reference; the index
 * module's rebuild heuristic turns that into one build, same cost as
 * the old refresh-owned rebuild.
 *
 * Returns a version counter that bumps AFTER each index write. Search
 * consumers (the displayNotes memo) list it as a dependency: effects
 * run after render, so the render that delivered new state computed
 * against the previous index - the bump triggers the recompute that
 * reads the fresh one.
 */
export function useSearchIndexSync(notes: LocalNote[]): number {
  const lastIndexed = useRef<Map<string, LocalNote>>(new Map());
  const [version, setVersion] = useState(0);

  useEffect(() => {
    const prev = lastIndexed.current;
    const next = new Map(notes.map((n) => [n.id, n]));
    const changed = diffNotesForIndex(prev, notes);
    lastIndexed.current = next;
    if (
      changed.added.length === 0 &&
      changed.updated.length === 0 &&
      changed.removed.length === 0
    ) {
      return;
    }
    updateSearchIndex(notes, changed);
    setVersion((v) => v + 1);
  }, [notes]);

  return version;
}

/** Classify state changes by reference. Exported for its unit tests. */
export function diffNotesForIndex(
  prev: Map<string, LocalNote>,
  notes: LocalNote[],
): { added: string[]; updated: string[]; removed: string[] } {
  const added: string[] = [];
  const updated: string[] = [];
  const removed: string[] = [];
  const seen = new Set<string>();
  for (const n of notes) {
    seen.add(n.id);
    const p = prev.get(n.id);
    if (!p) added.push(n.id);
    else if (p !== n) updated.push(n.id);
  }
  for (const id of prev.keys()) {
    if (!seen.has(id)) removed.push(id);
  }
  return { added, updated, removed };
}
