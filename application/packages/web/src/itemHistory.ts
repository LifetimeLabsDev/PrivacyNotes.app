import { useCallback, useEffect, useRef } from 'react';

/** The most steps kept. Older ones fall off the start. */
const LIMIT = 100;

/**
 * Back and forward through the items opened in this session, as in a
 * browser, across item types: a note, then a login opened from a link, then
 * a contact (GitHub #331). Not through the order of a list, which J, K and
 * the list step keys follow.
 *
 * Every new selection is a step, whatever opened it: a click, a note-link, a
 * tab, J and K. A step that the walk itself made is not recorded again, and a
 * new selection after a step back drops the steps ahead of it, as a browser
 * does. The history lives in memory only and starts empty each session.
 *
 * `open` shows one item and returns false when it cannot (deleted or trashed
 * since), and the walk then goes on to the next step. `recent` lists the
 * steps newest first, for the quick switcher.
 *
 * Spec: ops/issues/0331.md
 */
export function useItemHistory(selectedId: string | null, open: (id: string) => boolean) {
  const steps = useRef<string[]>([]);
  const at = useRef(-1);
  const walking = useRef<string | null>(null);
  const openRef = useRef(open);
  openRef.current = open;

  useEffect(() => {
    if (!selectedId) return;
    if (walking.current === selectedId) {
      walking.current = null;
      return;
    }
    walking.current = null;
    if (steps.current[at.current] === selectedId) return;
    const kept = steps.current.slice(0, at.current + 1);
    kept.push(selectedId);
    steps.current = kept.slice(-LIMIT);
    at.current = steps.current.length - 1;
  }, [selectedId]);

  const step = useCallback((direction: 1 | -1) => {
    for (let i = at.current + direction; i >= 0 && i < steps.current.length; i += direction) {
      const id = steps.current[i]!;
      if (id === selectedId) continue;
      walking.current = id;
      if (openRef.current(id)) {
        at.current = i;
        return;
      }
      walking.current = null;
    }
  }, [selectedId]);

  /** The items opened in this session, newest first, each once. */
  const recent = useCallback(() => [...new Set([...steps.current].reverse())], []);

  return { step, recent };
}
