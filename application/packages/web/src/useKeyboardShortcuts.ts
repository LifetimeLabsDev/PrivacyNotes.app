import { useEffect, useRef, type ComponentType } from 'react';
import { isEditableTarget } from './ContextMenu';
import { applyAppZoom, DEFAULT_APP_ZOOM, stepAppZoom } from './appZoom';
import { APP_KEYS, isDesktopApp, matchesKey } from './shortcutMatch';
import { closeTopOverlay, hasOpenOverlay } from './useEscapeToClose';
import { focusPane } from './paneFocus';
import { singleKeysOn } from './singleKeys';
import { editorCommands } from './editorCommands';
import type { LocalNote } from './db';
import type { View } from './views';
import {
  ArrowCounterClockwise, ArrowsLeftRight, ArrowsOutSimple, Browsers, Calendar, CaretLeft, CaretRight, Clock, FunnelSimpleX, Gear,
  Keyboard, Lightning, ListBullets, MagnifyingGlass, MagnifyingGlassMinus, MagnifyingGlassPlus, MarkdownLogo,
  Paragraph, Sidebar, Sun, Trash, X, type IconProps,
} from './icons';

export interface KeyboardShortcutHandlers {
  // Zen mode
  zenMode: boolean;
  setZenMode: (v: boolean | ((prev: boolean) => boolean)) => void;
  // True when Zen is usable: Pro users, or anyone in the public demo (which
  // unlocks it as a teaser). Gates the Cmd+Shift+F shortcut below.
  zenUnlocked: boolean;
  onOpenUpgrade: (trigger: string) => void;

  // New items
  handleNew: () => void;
  /** Open the New menu, where a letter picks the type (desktop apps). */
  openNewMenu: () => void;

  /** Open command mode in the search field. */
  openCommands: () => void;
  /** Open the quick switcher (jump to an item by title). */
  openQuickSwitcher: () => void;

  // Tabs
  /** How many tabs are open. */
  tabCount: number;
  /** Close the open item's tab. False when the item has none. */
  closeActiveTab: () => boolean;
  /** Open the next (1) or previous (-1) tab. */
  stepTab: (direction: 1 | -1) => void;

  // Search
  searchInputRef: React.RefObject<HTMLInputElement | null>;

  // Sidebar
  setSidebarCollapsed: (v: boolean | ((prev: boolean) => boolean)) => void;
  /** Open the nth section of the sidebar, counted from 1. */
  goToSection: (n: number) => void;

  // Theme and editor view
  toggleTheme: () => void;
  toggleInvisibles: () => void;

  // Note actions (need current selection state via refs)
  selectedId: string | null;
  view: View;
  handleTrash: (id: string) => void;
  /** Close the open note editor (Escape). */
  closeEditor: () => void;

  // Search and filters
  search: string;
  setSearch: (v: string) => void;
  /** True while a folder or tag filter narrows the list. */
  hasFilters: boolean;
  clearFilters: () => void;

  // Settings
  setShowSettings: (v: boolean) => void;

  // About modal (hotkeys tab)
  showAbout: false | { tab?: 'about' | 'hotkeys' | 'rating' };
  setShowAbout: (v: false | { tab?: 'about' | 'hotkeys' | 'rating' }) => void;

  // J/K navigation
  displayNotesRef: React.RefObject<LocalNote[]>;
  handleSelectNote: (id: string) => void;

  // Previous/next note in the list (GitHub #246)
  navigateList: (direction: 'prev' | 'next') => void;
  /** Back (-1) or forward (1) through the opened items (GitHub #331). */
  historyStep: (direction: 1 | -1) => void;

  // Multi-select
  selectionMode: boolean;
  clearSelection: () => void;
  /** The quick add (Q). */
  openQuickAdd: () => void;
  /** A Calendar key; false when nothing ran (an item is open over it). */
  calendarKey: (key: 'today' | 'day' | 'week' | 'month' | 'new') => boolean;
  selectAllVisible: () => void;
}

/**
 * The app's key handler. One listener on `window`, in the bubble phase, so
 * every inner owner acts first: the editor's keymap, a field, a menu, and the
 * Escape stack of the overlays (`useEscapeToClose`, capture phase). A key one
 * of them used arrives with `defaultPrevented`, which `matchesKey` refuses.
 * Each key press runs at most one command.
 *
 * Spec: ops/docs/archive/keyboard-shortcuts.md (sections 4.3 and 4.4)
 */
export function useKeyboardShortcuts(h: KeyboardShortcutHandlers): PaletteRunner {
  // The listener is added once and reads the latest handlers through a ref,
  // so it never calls a stale closure (a new-note listener with a fixed
  // dependency list keeps the first selectedId and never discards an empty
  // draft: GitHub #46).
  const ref = useRef(h);
  ref.current = h;

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const ran = runShortcut(e, ref.current);
      if (!ran) return;
      e.preventDefault();
      // A step to another item scrolls its row into view once the list
      // shows the new selection, so the list follows J and K.
      if (ran === STEP) requestAnimationFrame(() => revealRow(ref.current.selectedId));
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  // The mouse side buttons step back and forward through the opened items.
  // A browser takes them for its own history when the button comes up, and
  // the app keeps no browser history per item, so a Back there would leave
  // the app: both events are cancelled.
  useEffect(() => {
    function onMouse(e: MouseEvent) {
      if (e.button !== 3 && e.button !== 4) return;
      e.preventDefault();
      if (e.type === 'mouseup' && !hasOpenOverlay()) ref.current.historyStep(e.button === 3 ? -1 : 1);
    }
    window.addEventListener('mousedown', onMouse);
    window.addEventListener('mouseup', onMouse);
    return () => {
      window.removeEventListener('mousedown', onMouse);
      window.removeEventListener('mouseup', onMouse);
    };
  }, []);

  const runner = useRef<PaletteRunner | null>(null);
  runner.current ??= {
    available: (id) => commandAvailable(id, ref.current),
    run: (id) => runCommand(id, ref.current),
  };
  return runner.current;
}

/**
 * The commands command mode lists, besides the New items and the sections.
 * Each runs what its key runs (commandPalette.ts).
 */
export const PALETTE_COMMANDS = [
  'quickSwitcher', 'historyBack', 'historyForward', 'toggleSidebar', 'toggleTheme', 'openSettings', 'zen',
  'markdownView', 'invisibles', 'find', 'findReplace', 'outline', 'insertDate', 'insertDateTime', 'clearFilters', 'moveToTrash',
  'closeTab', 'nextTab', 'previousTab', 'zoomIn', 'zoomOut', 'zoomReset', 'help',
] as const;
export type PaletteCommand = (typeof PALETTE_COMMANDS)[number];

/**
 * Each command's row icon in the quick switcher: the glyph its own button
 * already draws (the editor header's back and forward, the footer's Sun and
 * Gear, the outline and find pills, the toolbar's date items, the About
 * window's Hotkeys tab), so a person meets one picture per feature. A
 * command added to PALETTE_COMMANDS without an icon here fails the type
 * check.
 */
export const PALETTE_ICONS = {
  quickSwitcher: Lightning,
  historyBack: CaretLeft,
  historyForward: CaretRight,
  toggleSidebar: Sidebar,
  toggleTheme: Sun,
  openSettings: Gear,
  zen: ArrowsOutSimple,
  markdownView: MarkdownLogo,
  invisibles: Paragraph,
  find: MagnifyingGlass,
  findReplace: ArrowsLeftRight,
  outline: ListBullets,
  insertDate: Calendar,
  insertDateTime: Clock,
  clearFilters: FunnelSimpleX,
  moveToTrash: Trash,
  closeTab: X,
  nextTab: Browsers,
  previousTab: Browsers,
  zoomIn: MagnifyingGlassPlus,
  zoomOut: MagnifyingGlassMinus,
  zoomReset: ArrowCounterClockwise,
  help: Keyboard,
} satisfies Record<PaletteCommand, ComponentType<IconProps>>;

export type PaletteRunner = { available: (id: PaletteCommand) => boolean; run: (id: PaletteCommand) => void };

function commandAvailable(id: PaletteCommand, h: KeyboardShortcutHandlers): boolean {
  switch (id) {
    case 'markdownView':
    case 'find':
    case 'findReplace':
    case 'outline':
    case 'insertDate':
    case 'insertDateTime':
      return !!editorCommands[id];
    case 'clearFilters':
      return h.hasFilters;
    case 'moveToTrash':
      return !!h.selectedId && h.view !== 'trash' && h.view !== 'tasks';
    case 'closeTab':
      return !!h.selectedId;
    case 'nextTab':
    case 'previousTab':
      return h.tabCount > 1;
    case 'zoomIn':
    case 'zoomOut':
    case 'zoomReset':
      return isDesktopApp();
    default:
      return true;
  }
}

function runCommand(id: PaletteCommand, h: KeyboardShortcutHandlers): void {
  switch (id) {
    case 'quickSwitcher': return h.openQuickSwitcher();
    case 'historyBack': return h.historyStep(-1);
    case 'historyForward': return h.historyStep(1);
    case 'toggleSidebar': return h.setSidebarCollapsed((v) => !v);
    case 'toggleTheme': return h.toggleTheme();
    case 'openSettings': return h.setShowSettings(true);
    case 'zen':
      if (!h.zenUnlocked) h.onOpenUpgrade('zen');
      else h.setZenMode((z) => !z);
      return;
    case 'markdownView':
    case 'find':
    case 'findReplace':
    case 'outline':
    case 'insertDate':
    case 'insertDateTime':
      return editorCommands[id]?.();
    case 'invisibles': return h.toggleInvisibles();
    case 'clearFilters': return h.clearFilters();
    case 'moveToTrash':
      if (h.selectedId) void h.handleTrash(h.selectedId);
      return;
    case 'closeTab':
      if (!h.closeActiveTab() && h.selectedId) h.closeEditor();
      return;
    case 'nextTab': return h.stepTab(1);
    case 'previousTab': return h.stepTab(-1);
    case 'zoomIn': return stepAppZoom(1);
    case 'zoomOut': return stepAppZoom(-1);
    case 'zoomReset': return applyAppZoom(DEFAULT_APP_ZOOM);
    case 'help': return h.setShowAbout({ tab: 'hotkeys' });
  }
}

/** A command that moved to another item. */
const STEP = 'step';

function revealRow(id: string | null) {
  if (!id) return;
  const row = document.querySelector<HTMLElement>(`[data-pane="list"] [data-item-id="${id}"]`);
  if (!row) return;
  row.scrollIntoView({ block: 'nearest' });
  // The keyboard's place in the list moves with the step (listKeys.ts).
  if (document.activeElement?.closest('[data-pane="list"] [data-item-id]')) {
    row.tabIndex = -1;
    row.focus();
  }
}

/** Runs the command of one key press. Truthy when one ran, so the key is cancelled. */
function runShortcut(e: KeyboardEvent, h: KeyboardShortcutHandlers): boolean | typeof STEP {
  const typing = isEditableTarget(e.target);
  const is = (id: keyof typeof APP_KEYS) => matchesKey(e, APP_KEYS[id], typing);

  // ── Commands that run anywhere, including in a text field ──
  // Each carries Cmd, Ctrl or Alt, so none of them types a character.

  // Commands that act on the app wait while a dialog or a menu is open: they
  // would change or move what is behind it, open a second dialog over it, or
  // take the focus out of it (F6). The key is still taken, so a browser
  // shortcut on the same keys does not fire either.
  const behind = hasOpenOverlay();

  // Cmd/Ctrl+Shift+F ("focus"), deliberately NOT Z: Cmd+Shift+Z is the
  // editor's redo. It runs while typing, which is the point: enter zen
  // without leaving the keyboard.
  if (is('zen')) {
    if (behind) return true;
    if (!h.zenUnlocked) h.onOpenUpgrade('zen');
    else h.setZenMode((z) => !z);
    return true;
  }

  if (is('newNote')) {
    if (!behind) void h.handleNew();
    return true;
  }
  // Mod+K, everywhere, the editor included (insert link is Mod+Shift+K).
  // Cancelled behind a dialog too: a browser would print the app page on the
  // Mod+P alias. The switcher closes itself on its own key.
  if (is('quickSwitcher')) {
    if (!behind) h.openQuickSwitcher();
    return true;
  }
  if (is('commandMode') && (e.metaKey || e.ctrlKey) && !behind) {
    h.openCommands();
    return true;
  }
  if (is('newMenu') && !behind) {
    h.openNewMenu();
    return true;
  }

  // Mod+W in the desktop apps closes the top overlay, else the item's tab,
  // else the open item. It never closes the window: on a Mac that moves to
  // Shift+Cmd+W. Alt+Shift+W only closes a tab, and is let through when
  // there is none, because on a Mac it types „.
  // Spec: ops/docs/archive/note-tabs.md (section 3)
  if (is('closeTab')) {
    const altKey = !(e.metaKey || e.ctrlKey);
    if (altKey) return h.closeActiveTab();
    if (hasOpenOverlay()) closeTopOverlay();
    else if (!h.closeActiveTab() && h.selectedId) h.closeEditor();
    return true;
  }
  if (!behind && (is('nextTab') || is('previousTab'))) {
    h.stepTab(is('nextTab') ? 1 : -1);
    return true;
  }

  if (is('toggleSidebar')) {
    if (!behind) h.setSidebarCollapsed((v) => !v);
    return true;
  }

  // The size of the whole desktop window. A browser keeps the same keys for
  // its own zoom, so the bindings are desktop-only. Plus and minus are read
  // as characters, so a keyboard that puts them elsewhere (Swedish, German)
  // still zooms the right way. ⌥⌘0 is Normal text and ⌥⌘1 to 6 are the
  // headings, which the bindings keep apart by refusing Option.
  if (isDesktopApp()) {
    if (is('zoomIn') || is('zoomOut')) {
      stepAppZoom(is('zoomIn') ? 1 : -1);
      return true;
    }
    if (is('zoomReset')) {
      applyAppZoom(DEFAULT_APP_ZOOM);
      return true;
    }
  }

  if (!behind && (is('historyBack') || is('historyForward'))) {
    h.historyStep(is('historyBack') ? -1 : 1);
    return STEP;
  }
  // The list step with a modifier, so it runs while typing, which J and K
  // cannot.
  if (!behind && (is('previousInList') || is('nextInList'))) {
    h.navigateList(is('previousInList') ? 'prev' : 'next');
    return STEP;
  }

  if (isDesktopApp() && !behind) {
    for (let n = 1; n <= 9; n++) {
      if (matchesKey(e, [APP_KEYS.goToSection[n - 1]!], typing)) {
        h.goToSection(n);
        return true;
      }
    }
  }

  if (!behind && (is('nextPane') || is('previousPane'))) {
    focusPane(is('nextPane') ? 1 : -1);
    return true;
  }

  if (is('openSettings')) {
    if (!behind) h.setShowSettings(true);
    return true;
  }
  if (is('toggleTheme')) {
    if (!behind) h.toggleTheme();
    return true;
  }
  if (is('invisibles')) {
    if (!behind) h.toggleInvisibles();
    return true;
  }

  // Let through behind a dialog, so a field in it keeps its own
  // Cmd+Backspace.
  if (is('moveToTrash')) {
    if (typing || behind || !h.selectedId || h.view === 'trash' || h.view === 'tasks') return false;
    void h.handleTrash(h.selectedId);
    return true;
  }

  if (h.selectionMode && is('selectAll') && !typing) {
    h.selectAllVisible();
    return true;
  }

  // Escape takes one step per press: the list search, a focused search
  // field, multi-select, zen, the folder and tag filter, then the open item.
  // An open dialog owns Escape (its own handler runs first, on the Escape
  // stack), and so does a menu that already used it (the note-link menu).
  if (is('escape')) return runEscape(h);

  // ── Single keys: never while typing, never while an overlay is open (a
  // menu or a dialog reads letters of its own), and not when the switch in
  // Settings > About > Hotkeys turned them off. ──
  if (typing || !singleKeysOn()) return false;

  // ? also closes the list it opened, which is an overlay itself.
  if (is('help') && (h.showAbout || !behind)) {
    h.setShowAbout(h.showAbout ? false : { tab: 'hotkeys' });
    return true;
  }
  if (behind) return false;

  if (is('quickAdd')) {
    h.openQuickAdd();
    return true;
  }
  // The Calendar's keys, only while it is the open view.
  if (h.view === 'calendar') {
    const key = is('calendarToday') ? 'today' : is('calendarDay') ? 'day' : is('calendarWeek') ? 'week'
      : is('calendarMonth') ? 'month' : is('calendarNew') ? 'new' : null;
    if (key && h.calendarKey(key)) return true;
  }

  if (is('commandMode')) {
    h.openCommands();
    return true;
  }
  // Cancelled, so Firefox does not open its quick find on "/".
  if (is('focusSearch')) {
    h.searchInputRef.current?.focus();
    h.searchInputRef.current?.select();
    return true;
  }

  const down = is('listDown');
  if (down || is('listUp')) {
    const list = h.displayNotesRef.current;
    if (!list || list.length === 0) return false;
    const idx = h.selectedId ? list.findIndex((n) => n.id === h.selectedId) : -1;
    const next = down
      ? (idx < 0 ? 0 : Math.min(list.length - 1, idx + 1))
      : (idx < 0 ? list.length - 1 : Math.max(0, idx - 1));
    const target = list[next];
    if (target) void h.handleSelectNote(target.id);
    return STEP;
  }
  return false;
}

function runEscape(h: KeyboardShortcutHandlers): boolean {
  if (h.search) {
    h.setSearch('');
    h.searchInputRef.current?.blur();
    return true;
  }
  // An Escape in an empty search field only leaves the field. Any field
  // built from the shared search input carries the marker, so the middle
  // column and the pane and picker fields behave alike.
  const focused = document.activeElement;
  if (focused instanceof HTMLElement && focused.hasAttribute('data-search-field')) {
    focused.blur();
    return true;
  }
  if (h.selectionMode) {
    h.clearSelection();
    return true;
  }
  if (h.zenMode) {
    h.setZenMode(false);
    return true;
  }
  if (document.querySelector('[role="dialog"], [aria-modal="true"]')) return false;
  // The filter goes before the item: the open item stays open in the wider
  // list, and the next Escape closes it.
  if (h.hasFilters) {
    h.clearFilters();
    return true;
  }
  if (h.selectedId) {
    h.closeEditor();
    return true;
  }
  return false;
}
