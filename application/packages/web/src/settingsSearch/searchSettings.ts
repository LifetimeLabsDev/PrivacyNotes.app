import { textMatcher, type TextMatch } from '../textMatch';
import { keywordKey, SETTING_ENTRIES, type SectionId, type SettingEntry } from './registry';

/**
 * A catalog lookup with no fallback: `undefined` when the language has no
 * string for the key, so the English pass can say where a hit came from.
 */
export type Resolve = (lng: string, key: string) => string | undefined;

export type SettingHit = {
  entry: SettingEntry;
  /** The name to show, in the language on screen when it has one. */
  label: string;
  /** Where the hit landed: 3 the name, 2 an option or keyword. */
  tier: 2 | 3;
  rank: TextMatch['rank'];
  /** The query is the whole name. */
  exact: boolean;
  /** Found only through the English catalog. */
  english: boolean;
  /** The text that matched when it is not the name, for "Matched:". */
  why: string | null;
  /** The range of the name to highlight, when the name matched. */
  mark: { start: number; end: number } | null;
};

// Trans tags (`<sb>Sidebar</sb>`) are markup, not words.
const TAG = /<\/?[a-z0-9]+>/gi;

function text(resolve: Resolve, lng: string, key: string): string | undefined {
  const value = resolve(lng, key);
  return value === undefined ? undefined : value.replace(TAG, '');
}

function labelOf(entry: SettingEntry, resolve: Resolve, lng: string): string | undefined {
  return entry.brand ? entry.label : text(resolve, lng, entry.label);
}

type Found = Omit<SettingHit, 'entry' | 'label' | 'english'>;

function better(a: Found | null, b: Found): boolean {
  if (!a) return true;
  if (b.tier !== a.tier) return b.tier > a.tier;
  if (b.rank !== a.rank) return b.rank > a.rank;
  return b.exact && !a.exact;
}

function findIn(entry: SettingEntry, match: (t: string) => TextMatch | null, resolve: Resolve, lng: string): Found | null {
  let best: Found | null = null;
  const consider = (value: string | undefined, tier: 2 | 3) => {
    if (!value) return;
    const m = match(value);
    if (!m) return;
    const exact = m.rank === 3 && m.end === value.length;
    const found: Found = {
      tier,
      rank: m.rank,
      exact,
      why: tier === 3 ? null : value,
      mark: tier === 3 ? { start: m.start, end: m.end } : null,
    };
    if (better(best, found)) best = found;
  };
  consider(labelOf(entry, resolve, lng), 3);
  for (const key of entry.options ?? []) consider(text(resolve, lng, key), 2);
  if (entry.keywords) {
    for (const word of (text(resolve, lng, keywordKey(entry)) ?? '').split(',')) consider(word.trim(), 2);
  }
  // A section's or a tab's own name is an entry of its own, so it does not
  // also list every row under it.
  return best;
}

function order(a: SettingHit, b: SettingHit): number {
  if (a.english !== b.english) return a.english ? 1 : -1;
  if (a.tier !== b.tier) return b.tier - a.tier;
  if (a.rank !== b.rank) return b.rank - a.rank;
  if (a.exact !== b.exact) return a.exact ? -1 : 1;
  return 0;
}

/**
 * The settings that match `query` in `lng`, in the order they are shown:
 * grouped by section, the groups in the order of their best hit, each group
 * sorted by where its hits landed. An entry the language on screen does not
 * match is tried in English and marked. An empty query matches nothing.
 */
export function searchSettings(
  query: string,
  lng: string,
  resolve: Resolve,
  isShown: (entry: SettingEntry) => boolean = () => true,
  entries: readonly SettingEntry[] = SETTING_ENTRIES,
): SettingHit[] {
  if (!query.trim()) return [];
  const match = textMatcher(query);
  const hits: SettingHit[] = [];
  for (const entry of entries) {
    if (!isShown(entry)) continue;
    let found = findIn(entry, match, resolve, lng);
    let english = false;
    if (!found && lng !== 'en') {
      found = findIn(entry, match, resolve, 'en');
      english = found !== null;
      // The English name is what matched, so it is what "Matched in English" names.
      if (found && found.tier === 3) found = { ...found, why: labelOf(entry, resolve, 'en') ?? null, mark: null };
    }
    if (!found) continue;
    const label = labelOf(entry, resolve, lng) ?? labelOf(entry, resolve, 'en') ?? entry.id;
    hits.push({ entry, label, english, ...found });
  }
  // A stable sort keeps the registry order for ties.
  hits.sort(order);
  const groups = new Map<SectionId, SettingHit[]>();
  for (const hit of hits) {
    const group = groups.get(hit.entry.section);
    if (group) group.push(hit);
    else groups.set(hit.entry.section, [hit]);
  }
  return [...groups.values()].flat();
}
