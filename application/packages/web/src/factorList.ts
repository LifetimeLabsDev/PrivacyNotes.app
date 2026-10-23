import { foldForMatch } from './textMatch';
import { FACTORS_MAX, activeFactors, cleanFactorName, type FactorDef } from './trackerTypes';

/**
 * The edits of the person's factor list, shared by the Factors pill and the
 * Factors tab of Settings > Trackers so both write the same rows. Every edit
 * stamps `updatedAt`, and a removal is a tombstone, because the list merges
 * by id across devices and a day that holds a removed factor keeps its name.
 * Spec: ops/issues/0439.md (Spec)
 */

/** A live factor with the same name, case and accents aside. */
function findFactor(list: readonly FactorDef[], name: string): FactorDef | undefined {
  const key = foldForMatch(name);
  return activeFactors([...list]).find((f) => foldForMatch(f.name) === key);
}

/**
 * The list with `raw` in it, and the id that names it: the existing factor
 * when the list already holds the name, a new one otherwise. Null when the
 * name is empty or the list is full.
 */
export function adoptFactor(list: readonly FactorDef[], raw: string): { list: FactorDef[]; id: string } | null {
  const name = cleanFactorName(raw);
  if (!name) return null;
  const same = findFactor(list, name);
  if (same) return { list: [...list], id: same.id };
  if (activeFactors([...list]).length >= FACTORS_MAX) return null;
  const now = new Date().toISOString();
  const f: FactorDef = { id: crypto.randomUUID(), name, createdAt: now, updatedAt: now };
  return { list: [...list, f], id: f.id };
}

/**
 * The list with every comma-separated name in `raw` in it, and the ids that
 * name them, in the order typed: "migraine, date night" adds two factors.
 * Names already on the list are reused; a full list stops the rest.
 */
export function adoptFactors(list: readonly FactorDef[], raw: string): { list: FactorDef[]; ids: string[] } {
  let out: FactorDef[] = [...list];
  const ids: string[] = [];
  for (const part of raw.split(/[,，、]/)) {
    const r = adoptFactor(out, part);
    if (!r) continue;
    out = r.list;
    if (!ids.includes(r.id)) ids.push(r.id);
  }
  return { list: out, ids };
}

/** The list with one factor renamed; unchanged when the name is empty or
 *  another live factor already has it. */
export function renameFactor(list: readonly FactorDef[], id: string, raw: string): FactorDef[] {
  const name = cleanFactorName(raw);
  const other = name ? findFactor(list, name) : undefined;
  if (!name || (other && other.id !== id)) return [...list];
  const now = new Date().toISOString();
  return list.map((f) => (f.id === id ? { ...f, name, updatedAt: now } : f));
}

/** The list with one factor tombstoned. */
export function removeFactor(list: readonly FactorDef[], id: string): FactorDef[] {
  const now = new Date().toISOString();
  return list.map((f) => (f.id === id ? { ...f, deletedAt: now, updatedAt: now } : f));
}
