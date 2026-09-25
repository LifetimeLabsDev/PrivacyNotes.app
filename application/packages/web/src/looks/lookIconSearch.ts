/**
 * The icon search of the look picker, and its "Recently used" row.
 *
 * Both are pure, so the picker stays a view and the rules have a test
 * (tests/lookIconSearch.test.ts).
 * Spec: ops/docs/plans/folder-tag-icons.md (section 6.3)
 */
import type { ItemStyles } from '../itemStyles';
import { textMatcher } from '../textMatch';

export interface IconSearchEntry {
  id: string;
  /** What the query may match, best first: the name in the UI language, the
   *  English name, the group name. */
  texts: readonly string[];
}

/**
 * The ids whose texts hold the query. A hit on an earlier text beats a hit on
 * a later one, then the better rank wins, then the picker's own order.
 */
export function searchLookIcons(query: string, entries: readonly IconSearchEntry[]): string[] {
  const match = textMatcher(query);
  const hits: { id: string; field: number; rank: number; order: number }[] = [];
  entries.forEach((entry, order) => {
    for (let field = 0; field < entry.texts.length; field++) {
      const m = match(entry.texts[field]!);
      if (m) {
        hits.push({ id: entry.id, field, rank: m.rank, order });
        return;
      }
    }
  });
  hits.sort((a, b) => a.field - b.field || b.rank - a.rank || a.order - b.order);
  return hits.map((h) => h.id);
}

const RECENT_ICONS = 8;

/**
 * The icons that folders and tags wear, the latest pick first, each once.
 * It only reads the synced map, so it adds no state of its own: a reset has
 * no icon, and an id this build does not know is left out, because it has no
 * glyph to draw.
 */
export function recentLookIcons(styles: ItemStyles, known: (id: string) => boolean): string[] {
  const picks: { id: string; at: number }[] = [];
  for (const entry of Object.values(styles)) {
    const reg = entry.icon;
    if (reg && typeof reg.v === 'string' && known(reg.v)) picks.push({ id: reg.v, at: Date.parse(reg.at) });
  }
  picks.sort((a, b) => b.at - a.at);
  return [...new Set(picks.map((p) => p.id))].slice(0, RECENT_ICONS);
}
