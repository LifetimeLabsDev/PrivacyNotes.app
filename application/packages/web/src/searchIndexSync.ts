import { useEffect, useRef, useState } from 'react';
import type { LocalNote } from './db';
import { buildSearchIndexSliced, searchIndexReady, updateSearchIndex, wantsFullBuild } from './search';

/**
 * Keeps the full-text index in lockstep with the notes STATE, which is
 * the one choke point every mutation flows through: refresh() replaces
 * the array, and local edits (create, rename, per-keystroke saves, bulk
 * rewrites, trash) patch it in place. Indexing here means a note is
 * searchable the moment the UI can show it - the class of bug where a
 * freshly created note returned "No matches" until the next tab focus
 * came from the index being rebuilt only inside refresh().
 *
 * The diff is by what the index reads (title, body, tags, type), not by
 * object reference: a refresh hands over a new object for every note, and
 * a flag change (archive, star, pin) replaces the object without touching
 * anything searchable. Neither re-indexes a note. Comparing the strings is
 * cheap, because an unchanged note keeps the very same body string.
 *
 * A full build (the first one, or a change to most notes) runs in slices
 * (search.ts buildSearchIndexSliced). The index in place keeps answering
 * meanwhile, and takes small changes directly; once the build lands, the
 * notes that changed during it are applied on top.
 *
 * Returns a version counter that bumps AFTER each index write. Search
 * consumers (the displayNotes memo) list it as a dependency: effects
 * run after render, so the render that delivered new state computed
 * against the previous index - the bump triggers the recompute that
 * reads the fresh one.
 */
export function useSearchIndexSync(notes: LocalNote[]): number {
  const lastIndexed = useRef<Map<string, LocalNote>>(new Map());
  const building = useRef(false);
  const latest = useRef(notes);
  latest.current = notes;
  const mounted = useRef(true);
  const [version, setVersion] = useState(0);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  useEffect(() => {
    const run = (current: LocalNote[]): void => {
      const changed = diffNotesForIndex(lastIndexed.current, current);
      if (changed.added.length === 0 && changed.updated.length === 0 && changed.removed.length === 0) return;
      if (building.current) {
        // The build in flight reads an older snapshot; the old index takes
        // a small change now, and the build's own pass applies it after.
        if (searchIndexReady() && !wantsFullBuild(changed)) {
          updateSearchIndex(current, changed);
          setVersion((v) => v + 1);
        }
        return;
      }
      if (wantsFullBuild(changed)) {
        building.current = true;
        const snapshot = current;
        void buildSearchIndexSliced(snapshot).then(() => {
          building.current = false;
          lastIndexed.current = new Map(snapshot.map((n) => [n.id, n]));
          if (!mounted.current) return;
          setVersion((v) => v + 1);
          run(latest.current);
        });
        return;
      }
      updateSearchIndex(current, changed);
      for (const id of changed.removed) lastIndexed.current.delete(id);
      for (const n of current) lastIndexed.current.set(n.id, n);
      setVersion((v) => v + 1);
    };
    run(notes);
  }, [notes]);

  return version;
}

/** Whether two copies of a note give the index the same text. */
function sameIndexedContent(a: LocalNote, b: LocalNote): boolean {
  if (a.title !== b.title || a.body !== b.body || a.type !== b.type) return false;
  // A login indexes its custom fields and extra websites too.
  if (a.type === 'login' && a.trackers?.login !== b.trackers?.login) return false;
  if (a.tags.length !== b.tags.length) return false;
  return a.tags.every((t, i) => t === b.tags[i]);
}

/** Classify state changes by what the index reads. Exported for its unit tests. */
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
    else if (p !== n && !sameIndexedContent(p, n)) updated.push(n.id);
  }
  for (const id of prev.keys()) {
    if (!seen.has(id)) removed.push(id);
  }
  return { added, updated, removed };
}
