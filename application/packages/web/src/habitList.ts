import { useSyncExternalStore } from 'react';
import i18n from 'i18next';
import { foldForMatch } from './textMatch';
import { HABIT_IDS, WATCH_HABITS, type HabitAnswers } from './trackerTypes';

/**
 * The person's own habit questions, beside the built-in ones of `HABIT_IDS`:
 * "Did you journal before bed?" A custom habit is a yes or no question like a
 * built-in one; its answers sit in the same `trackers.habits` record, it is
 * switched on in the same `trackerSettings.habits` list, and the statistics
 * read it the same way. The list itself is a top-level settings field merged
 * by id with tombstones, like the factors, because an older app keeps an
 * unknown top-level key and drops an unknown key inside `trackerSettings`.
 * Ids carry the `c-` prefix, so they never meet a built-in id.
 * Spec: ops/issues/0439.md (Spec)
 */

export type HabitKind = 'build' | 'watch';

export interface CustomHabitDef {
  id: string;
  /** The question the panel asks. */
  name: string;
  /** The chip, chart and export name; the question stands in when absent. */
  short?: string;
  kind: HabitKind;
  createdAt: string;
  updatedAt?: string;
  deletedAt?: string;
}

/** How many live custom habits a person can keep. */
export const CUSTOM_HABITS_MAX = 30;
/** The longest custom habit name. */
export const CUSTOM_HABIT_NAME_MAX = 60;
/** The longest short name, about the length of a built-in chip. */
export const CUSTOM_HABIT_SHORT_MAX = 24;
const ID_PREFIX = 'c-';

/** One empty list, so the store's start keeps its identity across renders. */
const NO_CUSTOM_HABITS: CustomHabitDef[] = [];

export function cleanHabitName(raw: string): string {
  return raw.replace(/\s+/g, ' ').trim().slice(0, CUSTOM_HABIT_NAME_MAX);
}

function cleanHabitShort(raw: string): string {
  return raw.replace(/\s+/g, ' ').trim().slice(0, CUSTOM_HABIT_SHORT_MAX);
}

/** The name a chip, a chart or an export shows for a custom habit. */
function customHabitLabel(h: CustomHabitDef): string {
  return h.short || h.name;
}

/** Read a stored list: well-formed entries only, each id once. */
export function readCustomHabits(raw: unknown): CustomHabitDef[] {
  if (!Array.isArray(raw)) return [];
  const out: CustomHabitDef[] = [];
  const seen = new Set<string>();
  for (const r of raw) {
    if (!r || typeof r !== 'object') continue;
    const h = r as Record<string, unknown>;
    if (typeof h.id !== 'string' || !h.id.startsWith(ID_PREFIX) || seen.has(h.id) || typeof h.name !== 'string') continue;
    const name = cleanHabitName(h.name);
    if (!name) continue;
    seen.add(h.id);
    const short = typeof h.short === 'string' ? cleanHabitShort(h.short) : '';
    out.push({
      id: h.id,
      name,
      ...(short ? { short } : {}),
      kind: h.kind === 'watch' ? 'watch' : 'build',
      createdAt: typeof h.createdAt === 'string' ? h.createdAt : new Date(0).toISOString(),
      ...(typeof h.updatedAt === 'string' ? { updatedAt: h.updatedAt } : {}),
      ...(typeof h.deletedAt === 'string' ? { deletedAt: h.deletedAt } : {}),
    });
  }
  return out;
}

export function activeCustomHabits(list: readonly CustomHabitDef[]): CustomHabitDef[] {
  return list.filter((h) => !h.deletedAt);
}

/** The list with a new habit, and its id; null when the name is empty, a
 *  live habit already has it, or the list is full. */
export function addCustomHabit(list: readonly CustomHabitDef[], raw: string, kind: HabitKind, rawShort = ''): { list: CustomHabitDef[]; id: string } | null {
  const name = cleanHabitName(raw);
  const short = cleanHabitShort(rawShort);
  if (!name) return null;
  const live = activeCustomHabits(list);
  if (live.some((h) => foldForMatch(h.name) === foldForMatch(name))) return null;
  if (live.length >= CUSTOM_HABITS_MAX) return null;
  const now = new Date().toISOString();
  const h: CustomHabitDef = { id: `${ID_PREFIX}${crypto.randomUUID()}`, name, ...(short ? { short } : {}), kind, createdAt: now, updatedAt: now };
  return { list: [...list, h], id: h.id };
}

/** The list with one habit edited: its question, its short name set or
 *  cleared, and its kind when given; unchanged when the name is empty or
 *  another live habit already has it. */
export function renameCustomHabit(list: readonly CustomHabitDef[], id: string, raw: string, rawShort = '', kind?: HabitKind): CustomHabitDef[] {
  const name = cleanHabitName(raw);
  const short = cleanHabitShort(rawShort);
  const clash = activeCustomHabits(list).some((h) => h.id !== id && foldForMatch(h.name) === foldForMatch(name));
  if (!name || clash) return [...list];
  const now = new Date().toISOString();
  return list.map((h) => {
    if (h.id !== id) return h;
    const { short: _old, ...rest } = h;
    return { ...rest, name, ...(short ? { short } : {}), ...(kind ? { kind } : {}), updatedAt: now };
  });
}

/** The list with one habit tombstoned; the days that answered it keep the
 *  answer, and the name stays for their history. */
export function removeCustomHabit(list: readonly CustomHabitDef[], id: string): CustomHabitDef[] {
  const now = new Date().toISOString();
  return list.map((h) => (h.id === id ? { ...h, deletedAt: now, updatedAt: now } : h));
}

// ------------------------------------------------------------------
// One view of every habit question, built-in and custom
// ------------------------------------------------------------------

export interface HabitQuestion {
  id: string;
  /** The short name: a chip, a chart label, an export column. */
  label: string;
  /** The question the panel asks. */
  question: string;
  watch: boolean;
  custom: boolean;
}

/** Every habit that can be asked, in the setup's order: the built-in habits
 *  to build, the person's own to build, the built-in to watch, the person's
 *  own to watch. A removed custom habit is left out. */
export function allHabitQuestions(custom: readonly CustomHabitDef[]): HabitQuestion[] {
  const t = (k: string) => i18n.t(`trackers:${k}`);
  const builtin = (watch: boolean) => HABIT_IDS.filter((id) => WATCH_HABITS.has(id) === watch).map((id) => ({
    id, label: t(`habits.short.${id}`), question: t(`habits.q.${id}`), watch, custom: false,
  }));
  const own = (kind: HabitKind) => activeCustomHabits(custom).filter((h) => h.kind === kind).map((h) => ({
    id: h.id, label: customHabitLabel(h), question: h.name, watch: kind === 'watch', custom: true,
  }));
  return [...builtin(false), ...own('build'), ...builtin(true), ...own('watch')];
}

/** The habits that are on, in the setup's order. */
export function askedHabits(on: readonly string[], custom: readonly CustomHabitDef[]): HabitQuestion[] {
  const set = new Set(on);
  return allHabitQuestions(custom).filter((q) => set.has(q.id));
}

/** The name of any habit id a day may hold, a removed custom one included,
 *  so an old day's answer keeps its name in the history and the exports. */
export function habitLabel(id: string, custom: readonly CustomHabitDef[]): string {
  if ((HABIT_IDS as readonly string[]).includes(id)) return i18n.t(`trackers:habits.short.${id}`);
  const own = custom.find((h) => h.id === id);
  return own ? customHabitLabel(own) : id;
}

/** Whether a habit is one to watch, which is never named outside the panel,
 *  the setup and the statistics. */
export function isWatchHabit(id: string, custom: readonly CustomHabitDef[]): boolean {
  if ((HABIT_IDS as readonly string[]).includes(id)) return WATCH_HABITS.has(id as never);
  return custom.find((h) => h.id === id)?.kind === 'watch';
}

/** The ids a day answered yes or no that something names: a built-in
 *  habit or one of the person's own, a removed one included. An id nothing
 *  names (a newer app's habit) is kept in the entry and counts nowhere. */
export function answeredHabitIds(answers: HabitAnswers | undefined, custom: readonly CustomHabitDef[]): string[] {
  if (!answers) return [];
  const own = new Set(custom.map((h) => h.id));
  return Object.keys(answers).filter((k) =>
    typeof (answers as Record<string, unknown>)[k] === 'boolean'
    && ((HABIT_IDS as readonly string[]).includes(k) || own.has(k)));
}

// ------------------------------------------------------------------
// The current list, for the readers that are not handed it
// ------------------------------------------------------------------

let current: CustomHabitDef[] = NO_CUSTOM_HABITS;
const listeners = new Set<() => void>();

/** The list the notes view holds; the registry, the check-in line and the
 *  exports read it from here rather than through every caller. */
export function setCustomHabitsStore(next: CustomHabitDef[]): void {
  if (next === current) return;
  current = next;
  listeners.forEach((l) => l());
}

export function customHabitsNow(): CustomHabitDef[] {
  return current;
}

export function useCustomHabits(): CustomHabitDef[] {
  return useSyncExternalStore(
    (l) => { listeners.add(l); return () => { listeners.delete(l); }; },
    () => current,
  );
}
