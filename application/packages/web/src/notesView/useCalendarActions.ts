import { useState } from 'react';
import type { LocalNote } from '../db';
import { splitOffCopy, updateNoteFrom } from '../notesRepo';
import { entryDayOf, journalDatePatch, schedulePatch, type JournalTitleFormat } from '../notesViewUtils';
import {
  applyScheduleEdit,
  dayNumber,
  detachOccurrence,
  liveOccurrence,
  scheduleOf,
  shiftDay,
  splitSeries,
  type ScheduleEdit,
} from '../schedule';

/** The three answers to "Change this item?" on a repeating event. */
type SeriesScope = 'this' | 'following' | 'all';

/** A question the shell draws as a ConfirmModal with three answers, naming the occurrence's day. */
export type SeriesQuestion = { kind: 'change' | 'delete'; title: string; day: string; answer: (scope: SeriesScope) => void };

/**
 * Every schedule write the calendar makes: a move, a new end day, a field of
 * the Schedule view, a list row dropped on a day, and a delete. One path per
 * side effect, so a repeating event asks "This occurrence, this and
 * following, or all?" wherever the change came from, and a journal entry's
 * day goes through `journalDatePatch`, which also moves its generated title.
 * Spec: ops/docs/plans/calendar-pillar-spec.md (steps 4 and 6)
 */
export function useCalendarActions(deps: {
  notes: readonly LocalNote[];
  isNoteLocked: (n: LocalNote) => boolean;
  titles: () => { format: JournalTitleFormat; suffix: string; locale: string; pattern?: string };
  patchLocal: (id: string, patch: Partial<LocalNote>, updatedAt: string, opts?: { edit?: false }) => void;
  scheduleSync: () => void;
  refresh: () => Promise<unknown>;
  /** Called after a schedule write, so reminders re-plan. */
  onScheduleChanged?: () => void;
  displayTitle: (n: LocalNote) => string;
  /** A split made a copy that now holds the occurrence the item was open on. */
  onSplit?: (fromId: string, copyId: string) => void;
}) {
  const [question, setQuestion] = useState<SeriesQuestion | null>(null);

  async function write(id: string, build: (current: LocalNote) => Record<string, unknown> | null): Promise<boolean> {
    const written = await updateNoteFrom(id, (current) => {
      const trackers = build(current);
      return trackers ? { trackers } : null;
    }, { edit: false });
    if (!written) return false;
    deps.patchLocal(id, written, new Date().toISOString(), { edit: false });
    deps.scheduleSync();
    deps.onScheduleChanged?.();
    return true;
  }

  /** One edit on one item, made on the occurrence that starts on `anchor`. */
  async function applyTo(id: string, anchor: string, edit: ScheduleEdit): Promise<void> {
    const item = deps.notes.find((n) => n.id === id);
    if (!item) return;
    // A journal entry moves through its own patch, which renames a generated title.
    if (item.type === 'journal' && edit.shiftDays) {
      const day = shiftDay(entryDayOf(item), edit.shiftDays);
      const written = await updateNoteFrom(id, (current) => {
        const moved = journalDatePatch(current, day, deps.titles(), { keepTitle: deps.isNoteLocked(current) });
        if (!moved) return null;
        const rest: ScheduleEdit = { ...edit, shiftDays: 0 };
        return { ...moved, trackers: applyScheduleEdit(moved.trackers, 'journal', day, rest) };
      }, { edit: false });
      if (written) {
        deps.patchLocal(id, written, new Date().toISOString(), { edit: false });
        deps.scheduleSync();
        deps.onScheduleChanged?.();
      }
      return;
    }
    await write(id, (current) => {
      const base = current.type === 'journal' && typeof current.trackers?.journalDate !== 'string'
        ? { ...(current.trackers ?? {}), journalDate: entryDayOf(current) }
        : current.trackers;
      return applyScheduleEdit(base, current.type, anchor, edit);
    });
  }

  /** The copy and the series' new rule in one write, both from the stored row. */
  async function split(item: LocalNote, build: (src: LocalNote) => { copy: Record<string, unknown>; series: Record<string, unknown> } | null): Promise<void> {
    const done = await splitOffCopy(item.id, build);
    if (!done) return;
    deps.patchLocal(item.id, done.series, new Date().toISOString(), { edit: false });
    deps.scheduleSync();
    await deps.refresh();
    deps.onSplit?.(item.id, done.copy.id);
    deps.onScheduleChanged?.();
  }

  /**
   * "This occurrence": the series skips the day, a copy holds the edit. Both
   * halves are built from the stored row, so a skip or a repeat change synced
   * while the question was open is kept, and a day the series lost since
   * splits nothing.
   */
  async function editOccurrence(item: LocalNote, occurrence: string, edit: ScheduleEdit): Promise<void> {
    await split(item, (src) => {
      const d = isLive(src, occurrence) ? detachOccurrence(src.trackers ?? {}, item.id, occurrence) : null;
      return d ? { copy: applyScheduleEdit(d.copyTrackers, 'event', occurrence, edit), series: { ...(src.trackers ?? {}), repeat: d.seriesRepeat } } : null;
    });
  }

  /** "This and following": the series ends the day before, a new one carries the edit. */
  async function editFollowing(item: LocalNote, occurrence: string, edit: ScheduleEdit): Promise<void> {
    if (!splitSeries(item.trackers ?? {}, occurrence)) {
      await applyTo(item.id, occurrence, edit);
      return;
    }
    await split(item, (src) => {
      const d = isLive(src, occurrence) ? splitSeries(src.trackers ?? {}, occurrence) : null;
      return d ? { copy: applyScheduleEdit(d.restTrackers, 'event', occurrence, edit), series: { ...(src.trackers ?? {}), repeat: d.seriesRepeat } } : null;
    });
  }

  /**
   * Change an item's schedule from the calendar or the Schedule view. A
   * repeating event opened on an occurrence asks which part of the series the
   * change is for; a change to the repeat itself is always for the series.
   */
  function edit(id: string, occurrence: string | null | undefined, change: ScheduleEdit): void {
    const item = deps.notes.find((n) => n.id === id);
    if (!item) return;
    const s = scheduleOf(item.trackers as Record<string, unknown> | undefined, item.type, item.type === 'journal' ? entryDayOf(item) : undefined);
    const occ = liveOccurrence(item.trackers as Record<string, unknown> | undefined, item.type, occurrence);
    // A day the series no longer holds (a stale drag, a screen behind a sync)
    // acts on nothing: falling back to the series would change all of it unasked.
    if (occurrence && s?.repeat && change.repeat === undefined && !occ) return;
    const anchor = occ ?? s?.day ?? entryDayOf(item);
    if (!s?.repeat || change.repeat !== undefined || !occ) {
      void applyTo(id, anchor, change);
      return;
    }
    setQuestion({
      kind: 'change',
      title: deps.displayTitle(item),
      day: occ,
      answer: (scope) => {
        if (scope === 'this') void editOccurrence(item, occ, change);
        else if (scope === 'following') void editFollowing(item, occ, change);
        else void applyTo(id, occ, change);
      },
    });
  }

  /** List rows dropped on a day (and an hour): each takes that day. */
  async function scheduleItems(ids: readonly string[], day: string, time?: string): Promise<void> {
    for (const id of ids) {
      const item = deps.notes.find((n) => n.id === id);
      if (!item) continue;
      if (item.type === 'journal') {
        await applyTo(id, entryDayOf(item), { shiftDays: diffDays(entryDayOf(item), day), ...(time ? { time } : {}) });
      } else if (item.type === 'note' || item.type === 'task' || item.type === 'event') {
        const s = scheduleOf(item.trackers as Record<string, unknown> | undefined, item.type);
        if (s?.repeat) continue;
        if (!s) await write(id, (current) => schedulePatch(current, day)?.trackers ?? null);
        else if (s.day !== day) await applyTo(id, s.day, { shiftDays: diffDays(s.day, day) });
        if (time) await applyTo(id, day, { time });
      }
    }
  }

  /**
   * Delete from the calendar: a repeating event opened on an occurrence asks
   * which part goes. "This occurrence" skips the day; "This and following"
   * ends the series the day before (all of it when that is the first);
   * "All" moves the item to the trash. Returns false when it handled nothing.
   */
  function deleteOccurrence(id: string, occurrence: string | null | undefined, trashAll: () => void, after?: () => void): boolean {
    const item = deps.notes.find((n) => n.id === id);
    const s = item ? scheduleOf(item.trackers as Record<string, unknown> | undefined, item.type) : null;
    if (!item || !s?.repeat || !occurrence || !isLive(item, occurrence)) return false;
    setQuestion({
      kind: 'delete',
      title: deps.displayTitle(item),
      day: occurrence,
      answer: (scope) => {
        if (scope === 'all' || (scope === 'following' && occurrence <= s.day)) {
          trashAll();
          return;
        }
        after?.();
        if (scope === 'this') {
          void write(id, (current) => {
            const cur = scheduleOf(current.trackers as Record<string, unknown> | undefined, 'event');
            if (!cur?.repeat || !isLive(current, occurrence)) return null;
            return { ...(current.trackers ?? {}), repeat: { ...cur.repeat, skip: [...new Set([...(cur.repeat.skip ?? []), occurrence])].sort() } };
          });
          return;
        }
        void write(id, (current) => {
          const cur = scheduleOf(current.trackers as Record<string, unknown> | undefined, 'event');
          if (!cur?.repeat || !isLive(current, occurrence)) return null;
          const { count: _count, ...rest } = cur.repeat;
          return { ...(current.trackers ?? {}), repeat: { ...rest, until: shiftDay(occurrence, -1) } };
        });
      },
    });
    return true;
  }

  return { question, dismissQuestion: () => setQuestion(null), edit, scheduleItems, deleteOccurrence };
}

/** Whether a day is still a live occurrence of the item as it is stored or
 *  shown: another tab can skip it or shorten the count while a question is open. */
function isLive(n: LocalNote, day: string): boolean {
  return liveOccurrence(n.trackers as Record<string, unknown> | undefined, n.type, day) !== null;
}

function diffDays(from: string, to: string): number {
  return dayNumber(to) - dayNumber(from);
}
