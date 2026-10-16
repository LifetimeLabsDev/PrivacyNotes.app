import { useCallback, useRef, useState } from 'react';
import { toLocalIso } from '../intlFormat';
import type { View } from '../views';

/** The three layouts of the Calendar pillar's editor pane. */
export type CalendarMode = 'day' | 'week' | 'month';

const MODE_KEY = 'privacynotes.calendarView';

function readMode(): CalendarMode {
  try {
    const v = localStorage.getItem(MODE_KEY);
    if (v === 'day' || v === 'week' || v === 'month') return v;
  } catch {
    // Storage refused (a private window): the month.
  }
  return 'month';
}

/**
 * The Calendar pillar's state, kept in the shell so an item opened from the
 * calendar and closed with Back returns to the same month, view and scroll:
 * the focused day, the layout (device-local, like the screen it is about),
 * the occurrence an open repeating item was opened on, and the hour grid's
 * scroll. The occurrence is kept with the id it was opened for and reads as
 * none while another item is selected: the quick switcher and a note-link
 * select an item without `openItem`, and a Delete or a schedule edit there
 * must never act at the day of the item opened before.
 * Spec: ops/docs/plans/calendar-pillar-spec.md (step 3)
 */
export function useCalendarPillar({ view, selectedId, setSelectedId, selectView }: {
  view: View;
  selectedId: string | null;
  setSelectedId: (id: string | null) => void;
  selectView: (view: View) => Promise<void> | void;
}) {
  const [mode, setModeState] = useState<CalendarMode>(readMode);
  const [focus, setFocus] = useState(() => toLocalIso(new Date()));
  const [opened, setOpened] = useState<{ id: string; day: string } | null>(null);
  // Another selection ends it, so coming back by another route does not revive it.
  if (opened && opened.id !== selectedId) setOpened(null);
  const occurrence = opened && opened.id === selectedId ? opened.day : null;
  const hourScroll = useRef<number | null>(null);

  const setMode = useCallback((next: CalendarMode) => {
    setModeState(next);
    try {
      localStorage.setItem(MODE_KEY, next);
    } catch {
      // Storage refused: the choice holds for this page only.
    }
  }, []);

  /** Opens an item in place of the calendar, remembering which occurrence. */
  const openItem = useCallback((id: string, occ?: string) => {
    setOpened(occ ? { id, day: occ } : null);
    setSelectedId(id);
  }, [setSelectedId]);

  /** Back to the calendar, as it was. */
  const back = useCallback(() => {
    setOpened(null);
    setSelectedId(null);
  }, [setSelectedId]);

  /** The pillar at a day's month (the card's expand button). */
  const openAt = useCallback(async (day: string) => {
    setFocus(day);
    await selectView('calendar');
    setSelectedId(null);
  }, [selectView, setSelectedId]);

  /** The day a new event takes: the focused one in the pillar, else today. */
  const newDay = useCallback(() => (view === 'calendar' ? focus : toLocalIso(new Date())), [view, focus]);

  return { mode, setMode, focus, setFocus, occurrence, openItem, back, openAt, newDay, hourScroll };
}

export type CalendarPillar = ReturnType<typeof useCalendarPillar>;
