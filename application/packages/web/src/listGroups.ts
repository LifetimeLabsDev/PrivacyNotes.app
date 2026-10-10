/**
 * The group headers of a list. One switch turns them on, and the sort decides
 * what they are: date buckets for a date sort, first letters for the title
 * sort, none for size. A group is a run of the list as it is already sorted,
 * so the builder never reorders anything and the sort direction needs no code.
 *
 * Generic over the item, so the list shell of every pane can call it.
 * Spec: ops/docs/plans/list-groups.md
 */
import type { SortField } from './listPrefs';

/** A run of the sorted list: `count` items from index `start`. */
export interface ListGroup {
  key: string;
  start: number;
  count: number;
}

export type GroupBasis = 'date' | 'title';

/** Which groups a sort gets, or null for none. */
export function groupBasis(sortField: SortField): GroupBasis | null {
  if (sortField === 'title') return 'title';
  if (sortField === 'created' || sortField === 'modified') return 'date';
  return null;
}

export const PINNED_KEY = 'pinned';
export const SYMBOL_KEY = '#';
/** Han characters, which have no reading the app could index by. */
export const OTHER_KEY = 'other';

const DAY_MS = 86_400_000;

function localMidnight(d: Date): number {
  return new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
}

/**
 * The date bucket of a day: today, yesterday, previous 7 days (2 to 6 days
 * ago), previous 30 days (7 to 29), then the month when it is this year, else
 * the year. A day in the future falls into its month or year.
 */
export function dateBucket(day: Date, now: Date): string {
  // Rounded, because a day that crosses a daylight-saving change is 23 or 25 hours.
  const ago = Math.round((localMidnight(now) - localMidnight(day)) / DAY_MS);
  if (ago === 0) return 'today';
  if (ago === 1) return 'yesterday';
  if (ago >= 2 && ago < 7) return 'prev7';
  if (ago >= 7 && ago < 30) return 'prev30';
  const y = day.getFullYear();
  if (y === now.getFullYear()) return `m:${y}-${String(day.getMonth() + 1).padStart(2, '0')}`;
  return `y:${y}`;
}

// Hangul leading consonants U+1100 to U+1112, as the jamo a reader knows.
const HANGUL_INITIALS = 'ㄱㄲㄴㄷㄸㄹㅁㅂㅃㅅㅆㅇㅈㅉㅊㅋㅌㅍㅎ';
// The first kana of each row of the gojuon, in code point order.
const KANA_ROWS = 'あかさたなはまやらわ';

/**
 * The index letter of a title: `l:` and the letter, `#` for a digit or a
 * symbol, or `other` for Han. The letter is upper case, and loses its accent
 * when the collator says the accent does not count, so "Élan" files under E
 * where the sort puts it there.
 */
export function letterKey(title: string, collator: Intl.Collator, locale?: string): string {
  const chars = [...title.trim()];
  let i = 0;
  // A Thai leading vowel is written first and sorted after its consonant.
  while (i < chars.length - 1 && /[เ-ไ]/.test(chars[i]!)) i++;
  const ch = chars[i];
  if (!ch || !/\p{L}/u.test(ch)) return SYMBOL_KEY;
  if (/\p{Script=Han}/u.test(ch)) return OTHER_KEY;
  if (/\p{Script=Hangul}/u.test(ch)) {
    const lead = ch.normalize('NFD').codePointAt(0)!;
    const jamo = lead >= 0x1100 && lead <= 0x1112 ? HANGUL_INITIALS[lead - 0x1100] : ch;
    return `l:${jamo}`;
  }
  if (/[\p{Script=Hiragana}\p{Script=Katakana}]/u.test(ch)) {
    // NFKC first: halfwidth katakana (ｶ) sorts with its fullwidth form (カ).
    let cp = ch.normalize('NFKC').codePointAt(0)!;
    if (cp >= 0x30a1 && cp <= 0x30f6) cp -= 0x60;
    let row = KANA_ROWS[0]!;
    for (const start of KANA_ROWS) if (cp >= start.codePointAt(0)!) row = start;
    return `l:${row}`;
  }
  const upper = [...ch.toLocaleUpperCase(locale)][0]!;
  const bare = upper.normalize('NFD').replace(/\p{M}/gu, '');
  return `l:${bare && collator.compare(bare, upper) === 0 ? bare : upper}`;
}

/** Whether two neighbouring keys are one group. Letters compare with the
 *  sort's collator; every other key must match exactly. */
function sameGroup(a: string, b: string, collator: Intl.Collator): boolean {
  if (a === b) return true;
  return a.startsWith('l:') && b.startsWith('l:') && collator.compare(a.slice(2), b.slice(2)) === 0;
}

export interface GroupOptions<T> {
  basis: GroupBasis;
  now: Date;
  /** The day the sort reads for an item. */
  dateOf: (item: T) => Date;
  /** The title the row shows. */
  titleOf: (item: T) => string;
  isPinned: (item: T) => boolean;
  /**
   * True for an item whose row hides its title, behind a closed PIN gate with
   * no stored title. It joins the group above it, so no header names the
   * first letter of a hidden body.
   */
  hidesTitle: (item: T) => boolean;
  /** The collator the sort uses, so the groups never cut a run in two. */
  collator: Intl.Collator;
  locale?: string;
}

/**
 * The groups of an already sorted list. Pinned items form their own group,
 * but only beside unpinned ones: in a list of pinned items alone, the header
 * would say nothing.
 */
export function buildGroups<T>(items: readonly T[], o: GroupOptions<T>): ListGroup[] {
  const mixed = items.some(o.isPinned) && !items.every(o.isPinned);
  const groups: ListGroup[] = [];
  items.forEach((item, index) => {
    const last = groups[groups.length - 1];
    let key: string;
    if (mixed && o.isPinned(item)) key = PINNED_KEY;
    else if (o.basis === 'date') key = dateBucket(o.dateOf(item), o.now);
    else if (o.hidesTitle(item)) key = last && last.key !== PINNED_KEY ? last.key : SYMBOL_KEY;
    else key = letterKey(o.titleOf(item), o.collator, o.locale);
    if (last && sameGroup(last.key, key, o.collator)) last.count++;
    else groups.push({ key, start: index, count: 1 });
  });
  return groups;
}
