import { useEffect, useRef, useState } from 'react';
import type { TFunction } from 'i18next';
import type { View } from '../views';
import {
  usePaneResize,
  useExpandDrag,
  SIDEBAR_WIDTH_DEFAULT, SIDEBAR_WIDTH_MIN, SIDEBAR_WIDTH_MAX,
  LIST_WIDTH_DEFAULT, LIST_WIDTH_MIN, LIST_WIDTH_MAX,
  SIDEBAR_VIEWPORT_CAP, LIST_VIEWPORT_CAP,
  EDITOR_DOCK_DEFAULT, EDITOR_DOCK_MIN, EDITOR_DOCK_STORE_MAX, GRID_DOCK_MIN,
  STRIPS_W, DOCK_SIDEBAR_RESERVE, DOCK_GRID_RESERVE,
} from '../usePaneResize';

/**
 * The shell's per-device layout: which panes are collapsed, how wide each
 * one is, and the drag strips that resize them. Nothing here is synced.
 */
export function useShellLayout(view: View, t: TFunction) {
  // ── UI layout collapse state (persisted per-device) ──────────────
  // All UI chrome collapse state is per-device, not synced: someone on
  // a 13" laptop wants a narrower shell than on a 27" desktop. Stored
  // as flat localStorage keys so there's no migration drift.
  const readUiBool = (key: string, fallback: boolean): boolean => {
    if (typeof window === 'undefined') return fallback;
    const v = window.localStorage.getItem(key);
    if (v === '1' || v === 'true') return true;
    if (v === '0' || v === 'false') return false;
    return fallback;
  };
  const writeUiBool = (key: string, value: boolean) => {
    try {
      window.localStorage.setItem(key, value ? '1' : '0');
    } catch { /* quota / disabled - fall back to in-memory */ }
  };
  const readUiPx = (key: string, fallback: number, min: number, max: number): number => {
    if (typeof window === 'undefined') return fallback;
    const v = parseInt(window.localStorage.getItem(key) ?? '', 10);
    if (Number.isNaN(v)) return fallback;
    return Math.max(min, Math.min(max, v));
  };
  const writeUiPx = (key: string, value: number) => {
    try {
      window.localStorage.setItem(key, String(Math.round(value)));
    } catch { /* quota / disabled - fall back to in-memory */ }
  };
  // Sidebar rests expanded at xl+ (1280) and as the icon rail in the
  // lg-xl band, where the full 240px rail crowds the list + editor.
  // Manual expand (rail buttons, handles, context menu) stays available
  // below xl as a session override; crossing the xl line resets the
  // sidebar to its width default, so the choice is deliberately NOT
  // persisted anymore.
  // Spec: ops/docs/ui-patterns.md section 40 (canonical breakpoints)
  const [xlScreen, setXlScreen] = useState<boolean>(
    () => typeof window !== 'undefined' && window.matchMedia('(min-width: 1280px)').matches,
  );
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(() => !xlScreen);
  // The list collapse is a MULTI-PANE affordance: both of its strips are
  // md+ only, and below that line the list is the whole screen. Honouring
  // the stored flag there unmounts the only pane, leaves no handle to
  // bring it back, and persists - a blank app that a restart cannot cure.
  // A phone reaches the strips at all because landscape is wider than md,
  // so dropping out of the md band forgets the collapse, the same session
  // reseed the sidebar does at the xl line above. The mount read is gated
  // too, so a device that is already stuck heals on its next launch
  // instead of painting one blank frame first.
  // Spec: ops/docs/ui-patterns.md section 56 (pane resize strips)
  const [mdScreen, setMdScreen] = useState<boolean>(
    () => typeof window !== 'undefined' && window.matchMedia('(min-width: 768px)').matches,
  );
  // The Calendar folds its agenda below lg, where the month needs the width.
  const [lgScreen, setLgScreen] = useState<boolean>(
    () => typeof window !== 'undefined' && window.matchMedia('(min-width: 1024px)').matches,
  );
  // The tab strip lives where the editor is a pane of its own, the same md
  // step: below it the list and the editor take turns on one screen.
  const tabsShown = mdScreen;
  const [notesListCollapsed, setNotesListCollapsed] = useState<boolean>(
    () => mdScreen && readUiBool('privacynotes.ui.notesListCollapsed', false)
  );
  /** The list's own collapsed state while a file opened from the file manager
   *  has the window to itself (usePendingFileOpens in NotesView), or null. The fold
   *  is not a layout choice, so it is never saved. */
  const fileFocusRef = useRef<boolean | null>(null);
  /** The list's own collapsed state while the Calendar folds the agenda on a
   *  window narrower than lg, or null. The month needs the width more than
   *  the agenda, which shows the same days; the fold is never saved, opening
   *  the list by hand ends it, and leaving the Calendar or widening the window
   *  past lg restores the list. A window narrowed below lg folds it too. The
   *  calendar header's agenda button opens and folds it by hand.
   *  Spec: ops/docs/plans/calendar-pillar-spec.md (step 3, responsiveness) */
  const calendarFoldRef = useRef<boolean | null>(null);
  const [viewsCollapsed, setViewsCollapsed] = useState<boolean>(
    () => readUiBool('privacynotes.ui.viewsCollapsed', false)
  );
  // Pane widths (GitHub #211) are per-device like the collapse state above.
  // Width and collapse are independent axes: resizing never writes a
  // collapse boolean, collapsing never rewrites a width, and the stored
  // width simply applies whenever the pane is expanded (so it survives
  // the sidebar's session-only xl reseed below).
  // Spec: ops/docs/design-decisions.md (pane resize)
  const [sidebarWidth, setSidebarWidth] = useState<number>(
    () => readUiPx('privacynotes.ui.sidebarWidth', SIDEBAR_WIDTH_DEFAULT, SIDEBAR_WIDTH_MIN, SIDEBAR_WIDTH_MAX)
  );
  const [notesListWidth, setNotesListWidth] = useState<number>(
    () => readUiPx('privacynotes.ui.notesListWidth', LIST_WIDTH_DEFAULT, LIST_WIDTH_MIN, LIST_WIDTH_MAX)
  );
  // Docked-grid editor column width (>=1400px grid mode with a note open).
  const [editorDockWidth, setEditorDockWidth] = useState<number>(
    () => readUiPx('privacynotes.ui.editorDockWidth', EDITOR_DOCK_DEFAULT, EDITOR_DOCK_MIN, EDITOR_DOCK_STORE_MAX)
  );

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const mq = window.matchMedia('(min-width: 1280px)');
    const on = () => setXlScreen(mq.matches);
    mq.addEventListener('change', on);
    return () => mq.removeEventListener('change', on);
  }, []);
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const mq = window.matchMedia('(min-width: 768px)');
    const on = () => setMdScreen(mq.matches);
    mq.addEventListener('change', on);
    return () => mq.removeEventListener('change', on);
  }, []);
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const mq = window.matchMedia('(min-width: 1024px)');
    const on = () => setLgScreen(mq.matches);
    mq.addEventListener('change', on);
    return () => mq.removeEventListener('change', on);
  }, []);
  useEffect(() => { setSidebarCollapsed(!xlScreen); }, [xlScreen]);
  useEffect(() => { if (!mdScreen) setNotesListCollapsed(false); }, [mdScreen]);
  useEffect(() => {
    // Opening the list by hand ends the file focus; until then nothing is
    // saved. Below md the list is open by layout, not by hand.
    if (fileFocusRef.current !== null && !notesListCollapsed && mdScreen) {
      fileFocusRef.current = null;
      void import('../markdownFolder/fileWindow').then((m) => m.leaveFileWindow());
    }
    if (calendarFoldRef.current !== null && !notesListCollapsed) calendarFoldRef.current = null;
    if (fileFocusRef.current === null && calendarFoldRef.current === null) writeUiBool('privacynotes.ui.notesListCollapsed', notesListCollapsed);
  }, [notesListCollapsed]);
  useEffect(() => {
    if (view === 'calendar') {
      if (mdScreen && !lgScreen && !notesListCollapsed && calendarFoldRef.current === null) {
        calendarFoldRef.current = false;
        setNotesListCollapsed(true);
      } else if (lgScreen && calendarFoldRef.current !== null) {
        // The window grew past lg again: the fold made room it no longer needs.
        const saved = calendarFoldRef.current;
        calendarFoldRef.current = null;
        setNotesListCollapsed(saved);
      }
      return;
    }
    if (calendarFoldRef.current === null) return;
    const saved = calendarFoldRef.current;
    calendarFoldRef.current = null;
    setNotesListCollapsed(saved);
    // The view switch and a window crossing lg decide; the fold is read as it stands.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [view, lgScreen, mdScreen]);
  useEffect(() => {
    if (view === 'markdown' || fileFocusRef.current === null) return;
    const saved = fileFocusRef.current;
    fileFocusRef.current = null;
    setNotesListCollapsed(saved);
    void import('../markdownFolder/fileWindow').then((m) => m.leaveFileWindow());
  }, [view]);
  useEffect(() => { writeUiBool('privacynotes.ui.viewsCollapsed', viewsCollapsed); }, [viewsCollapsed]);
  useEffect(() => { writeUiPx('privacynotes.ui.sidebarWidth', sidebarWidth); }, [sidebarWidth]);
  useEffect(() => { writeUiPx('privacynotes.ui.notesListWidth', notesListWidth); }, [notesListWidth]);
  useEffect(() => { writeUiPx('privacynotes.ui.editorDockWidth', editorDockWidth); }, [editorDockWidth]);

  // Drag-to-resize wiring for the four collapse strips. The refs are
  // shared: the root div carries the CSS vars, the badge is the floating
  // live-width readout. See usePaneResize.ts for the full contract.
  const shellRootRef = useRef<HTMLDivElement | null>(null);
  const dragBadgeRef = useRef<HTMLDivElement | null>(null);
  const sidebarResize = usePaneResize({
    rootRef: shellRootRef,
    badgeRef: dragBadgeRef,
    cssVar: '--pn-sidebar-w',
    min: SIDEBAR_WIDTH_MIN,
    getMax: () => Math.round(Math.min(SIDEBAR_WIDTH_MAX, SIDEBAR_VIEWPORT_CAP * window.innerWidth)),
    width: sidebarWidth,
    onCommitWidth: setSidebarWidth,
    onCollapse: () => setSidebarCollapsed(true),
    snapLabel: t('notes:sidebar.collapse'),
    snapAt: 'min',
  });
  const listResize = usePaneResize({
    rootRef: shellRootRef,
    badgeRef: dragBadgeRef,
    cssVar: '--pn-list-w',
    min: LIST_WIDTH_MIN,
    getMax: () => Math.round(Math.min(LIST_WIDTH_MAX, LIST_VIEWPORT_CAP * window.innerWidth)),
    width: notesListWidth,
    onCommitWidth: setNotesListWidth,
    onCollapse: () => setNotesListCollapsed(true),
    snapLabel: t('notes:notesList.collapse'),
    snapAt: 'min',
  });
  // Docked-grid divider (between grid and editor): drag sizes the editor
  // column (invert - the pane sits RIGHT of its strip), click collapses
  // the grid so the editor takes the full width. The cap mirrors
  // --pn-editor-render-dock: viewport minus strips, the grid floor
  // formula, and the sidebar's actual rendered width.
  const editorResize = usePaneResize({
    rootRef: shellRootRef,
    badgeRef: dragBadgeRef,
    cssVar: '--pn-editor-w',
    min: EDITOR_DOCK_MIN,
    getMax: () => {
      const vw = window.innerWidth;
      const gridFloor = Math.min(GRID_DOCK_MIN, vw - DOCK_GRID_RESERVE);
      const sb = sidebarCollapsed
        ? 52
        : Math.max(SIDEBAR_WIDTH_MIN, Math.min(sidebarWidth, Math.min(SIDEBAR_WIDTH_MAX, vw - DOCK_SIDEBAR_RESERVE)));
      return Math.max(EDITOR_DOCK_MIN, Math.round(vw - STRIPS_W - gridFloor - sb));
    },
    invert: true,
    width: editorDockWidth,
    onCommitWidth: setEditorDockWidth,
    onCollapse: () => setNotesListCollapsed(true),
    snapLabel: t('notes:notesList.collapse'),
    snapAt: 'max',
  });
  const sidebarExpandDrag = useExpandDrag(() => setSidebarCollapsed(false), 1);
  const listExpandDrag = useExpandDrag(() => setNotesListCollapsed(false), 1);
  // The docked grid sits left of its strip, so it opens on a drag to the left.
  const gridExpandDrag = useExpandDrag(() => setNotesListCollapsed(false), -1);

  /** The calendar header's agenda button. Folding goes through the calendar
   *  fold, so it is never saved and the list comes back outside the Calendar;
   *  opening by hand ends the fold, as the expand strip does. */
  function toggleCalendarAgenda() {
    if (notesListCollapsed) {
      setNotesListCollapsed(false);
      return;
    }
    if (calendarFoldRef.current === null) calendarFoldRef.current = false;
    setNotesListCollapsed(true);
  }

  return {
    tabsShown,
    fileFocusRef,
    toggleCalendarAgenda,
    sidebarCollapsed, setSidebarCollapsed,
    notesListCollapsed, setNotesListCollapsed,
    viewsCollapsed, setViewsCollapsed,
    sidebarWidth, setSidebarWidth, notesListWidth, setNotesListWidth, editorDockWidth, setEditorDockWidth,
    shellRootRef, dragBadgeRef,
    sidebarResize, listResize, editorResize,
    sidebarExpandDrag, listExpandDrag, gridExpandDrag,
  };
}
