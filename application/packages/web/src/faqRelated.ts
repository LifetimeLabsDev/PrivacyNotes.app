/**
 * Which questions a FAQ leaf lists under "Related questions".
 *
 * Until 2026-10-23 the list was the first five entries of the same group in
 * page order, so the trash page offered whatever "Your data" happened to
 * start with. This scores every pair of entries instead, from the ENGLISH
 * catalog only, and every locale renders the same ids: the ids never vary by
 * language, and a translation must not change which pages a reader is sent to.
 *
 * Three signals, added together:
 *
 * - A link between the two answers, in either direction. An author who wrote
 *   `[your storage](/help/storage-usage/)` already said the pages belong
 *   together, so it is the strongest signal and costs nothing to read.
 * - Word overlap: TF-IDF over the question (counted twice) and the answer,
 *   compared by cosine. Rare shared words such as "trash" or "dose" carry the
 *   weight; words every answer uses carry almost none.
 * - The same group, as a small bonus that breaks near ties.
 *
 * Runs at build time in Node, so nothing reaches the browser. Keep this
 * module import-free: `help-page.ts` evaluates it next to `faq.ts`.
 *
 * // Spec: ops/docs/help-center.md (related questions)
 */

type Entry = { q: string; a: string[] };
type Row = { id: string; group: string };

/** How many related questions a leaf lists. */
export const RELATED_COUNT = 6;

// Score weights. A link outranks any word overlap short of a near-duplicate.
const LINK_ONE_WAY = 0.35;
const LINK_BOTH_WAYS = 0.5;
const SAME_GROUP = 0.05;

const LINK = /\]\(\/help\/([a-z0-9-]+)\/?\)/g;

// Words too common in English to say anything about a topic. Product words
// such as "notes" or "settings" are left to the IDF weighting.
const STOP = new Set(
  ('the and for are but not you your yours with that this from have has had was were will would can could ' +
    'into onto out over under than then them they their there these those what when where which while who whom ' +
    'why how all any each every one two its it\'s also only just more most less such some same other own very ' +
    'about after again before between both does done doing down off once our ours too until upon via yet nor ' +
    'there here because being been get gets got make makes made like way ever never always still even much many')
    .split(' ')
);

function tokens(text: string): string[] {
  return text
    .replace(/\]\([^)]*\)/g, ']') // drop link targets, keep link text
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((w) => w.length > 2 && !STOP.has(w))
    .map((w) => (w.length > 4 && w.endsWith('s') && !w.endsWith('ss') ? w.slice(0, -1) : w));
}

function links(e: Entry): Set<string> {
  const out = new Set<string>();
  for (const par of e.a) for (const m of par.matchAll(LINK)) if (m[1]) out.add(m[1]);
  return out;
}

/**
 * The related ids for every entry, best first. `rows` gives the page order,
 * which also breaks ties, and the group of each entry. Entries without a
 * question are skipped, as the leaf pages skip them.
 */
export function relatedFaq(rows: ReadonlyArray<Row>, entries: Record<string, Entry | undefined>): Map<string, string[]> {
  const nodes = rows.flatMap((r, order) => {
    const e = entries[r.id];
    return e?.q ? [{ id: r.id, group: r.group, order, e, links: links(e), vec: new Map<string, number>() }] : [];
  });

  // Term frequencies, then IDF, then unit-length TF-IDF vectors.
  const tfs = nodes.map(({ e }) => {
    const tf = new Map<string, number>();
    for (const w of [...tokens(e.q), ...tokens(e.q), ...tokens(e.a.join(' '))]) tf.set(w, (tf.get(w) ?? 0) + 1);
    return tf;
  });
  const df = new Map<string, number>();
  for (const tf of tfs) for (const w of tf.keys()) df.set(w, (df.get(w) ?? 0) + 1);
  nodes.forEach((node, i) => {
    let norm = 0;
    for (const [w, n] of tfs[i] ?? []) {
      const x = (1 + Math.log(n)) * Math.log(nodes.length / (df.get(w) ?? 1));
      node.vec.set(w, x);
      norm += x * x;
    }
    norm = Math.sqrt(norm) || 1;
    for (const [w, x] of node.vec) node.vec.set(w, x / norm);
  });

  const result = new Map<string, string[]>();
  for (const a of nodes) {
    const scored = nodes
      .filter((b) => b !== a)
      .map((b) => {
        const [small, large] = a.vec.size < b.vec.size ? [a.vec, b.vec] : [b.vec, a.vec];
        let score = 0;
        for (const [w, x] of small) score += x * (large.get(w) ?? 0);
        const there = a.links.has(b.id);
        const back = b.links.has(a.id);
        if (there && back) score += LINK_BOTH_WAYS;
        else if (there || back) score += LINK_ONE_WAY;
        if (a.group === b.group) score += SAME_GROUP;
        return { id: b.id, score, order: b.order };
      });
    scored.sort((x, y) => y.score - x.score || x.order - y.order);
    result.set(a.id, scored.slice(0, RELATED_COUNT).map((s) => s.id));
  }
  return result;
}
