import { noteLinkKey, noteLinkTargets, parseNoteLinkTarget } from './noteLinks';

/**
 * Which items link to which, read from the note bodies on this device: the
 * data behind the Connections panel (backlinks).
 *
 * A link counts only when a click on it would open one item. That is the
 * resolution `navigateToNoteByTitle` runs (whole title first, then the key),
 * so a title two notes share links to neither of them here, as a click
 * offers a choice instead of following it.
 *
 * Sources are the notes whose body is markdown: a structured body (a contact,
 * a vault entry) is JSON and holds no note-link. Any item can be a target. A
 * PIN-protected source is never listed, only counted, so the panel says how
 * many it left out without naming them.
 * Spec: ops/issues/0351.md (Spec)
 */

type Item = { id: string; title: string; body: string; pinProtected?: number };

export type LinkIndex = {
  /** Target id to the ids of the listable notes that link to it. */
  incoming: Map<string, string[]>;
  /** Target id to how many PIN-protected notes link to it. */
  protectedIncoming: Map<string, number>;
  /** Source id to the ids it links to, and the targets no item carries. */
  outgoing: Map<string, { ids: string[]; missing: string[] }>;
};

export function buildLinkIndex<T extends Item>(
  items: readonly T[],
  {
    nameOf,
    isSource,
  }: {
    /** The name a note-link finds the item by (`noteLinkName`). */
    nameOf: (item: T) => string;
    /** False for an item whose body is not markdown. */
    isSource: (item: T) => boolean;
  },
): LinkIndex {
  const incoming = new Map<string, string[]>();
  const protectedIncoming = new Map<string, number>();
  const outgoing = new Map<string, { ids: string[]; missing: string[] }>();
  // Two lookups in place of `resolveNoteLinkMatches`, with its two passes:
  // the exact title (any case) first, then the key. A scan of every item per
  // link costs half a second on a library of a few thousand notes.
  const byExact = new Map<string, T[]>();
  const byKey = new Map<string, T[]>();
  const add = (map: Map<string, T[]>, k: string, n: T) => {
    const list = map.get(k);
    if (list) list.push(n);
    else map.set(k, [n]);
  };
  for (const n of items) {
    const name = nameOf(n);
    add(byExact, name.toLowerCase(), n);
    const key = noteLinkKey(name);
    if (key) add(byKey, key, n);
  }
  const hasNote = (name: string) => byKey.has(noteLinkKey(name));
  const resolve = (note: string): T[] => {
    const exact = byExact.get(note.toLowerCase());
    if (exact) return exact;
    const key = noteLinkKey(note);
    return key ? byKey.get(key) ?? [] : [];
  };

  for (const source of items) {
    if (!isSource(source)) continue;
    const targets = noteLinkTargets(source.body);
    if (targets.length === 0) continue;
    const isProtected = source.pinProtected === 1;
    const ids = new Set<string>();
    const missing = new Map<string, string>();
    for (const target of targets) {
      const { note } = parseNoteLinkTarget(target, hasNote);
      // `[[#Heading]]` points into the note that holds it.
      if (note === '') continue;
      const matches = resolve(note);
      if (matches.length === 0) {
        const key = noteLinkKey(note);
        if (key && !missing.has(key)) missing.set(key, note);
        continue;
      }
      if (matches.length > 1) continue;
      const match = matches[0]!;
      if (match.id !== source.id) ids.add(match.id);
    }
    outgoing.set(source.id, { ids: [...ids], missing: [...missing.values()] });
    for (const id of ids) {
      if (isProtected) {
        protectedIncoming.set(id, (protectedIncoming.get(id) ?? 0) + 1);
      } else {
        const list = incoming.get(id);
        if (list) list.push(source.id);
        else incoming.set(id, [source.id]);
      }
    }
  }
  return { incoming, protectedIncoming, outgoing };
}
