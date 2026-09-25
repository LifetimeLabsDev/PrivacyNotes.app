import { useEffect, useRef } from 'react';
import { isEditableTarget } from './ContextMenu';
import { isImeComposing } from './imeComposing';
import type { LocalNote } from './db';
import type { View } from './views';

export interface KeyboardShortcutHandlers {
  // Zen mode
  zenMode: boolean;
  setZenMode: (v: boolean | ((prev: boolean) => boolean)) => void;
  // True when Zen is usable: Pro users, or anyone in the public demo (which
  // unlocks it as a teaser). Gates the Cmd+Shift+F shortcut below.
  zenUnlocked: boolean;
  onOpenUpgrade: (trigger: string) => void;

  // New note
  handleNew: () => void;

  // Search
  searchInputRef: React.RefObject<HTMLInputElement | null>;

  // Sidebar
  setSidebarCollapsed: (v: boolean | ((prev: boolean) => boolean)) => void;

  // Theme
  toggleTheme: () => void;

  // Note actions (need current selection state via refs)
  selectedId: string | null;
  view: View;
  handleTrash: (id: string) => void;
  /** Close the open note editor (Escape). */
  closeEditor: () => void;

  // Search clear
  search: string;
  setSearch: (v: string) => void;

  // Settings
  setShowSettings: (v: boolean) => void;

  // About modal (hotkeys tab)
  showAbout: false | { tab?: 'about' | 'changelog' | 'hotkeys' };
  setShowAbout: (v: false | { tab?: 'about' | 'changelog' | 'hotkeys' }) => void;

  // J/K navigation
  displayNotesRef: React.RefObject<LocalNote[]>;
  handleSelectNote: (id: string) => void;

  // Previous/next note in the list (GitHub #246)
  navigateList: (direction: 'prev' | 'next') => void;

  // Multi-select
  selectionMode: boolean;
  clearSelection: () => void;
  selectAllVisible: () => void;
}

export function useKeyboardShortcuts(h: KeyboardShortcutHandlers) {
  // ── Zen mode: Cmd/Ctrl+Shift+Z toggle, Esc exits ──
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (isImeComposing(e)) return;
      // Cmd/Ctrl+Shift+F ("focus"), deliberately NOT Z: Cmd+Shift+Z is the
      // editor's redo, and sharing the key meant zen either double-fired
      // with redo or (guarded) was unreachable from the editor - the place
      // zen is for. Shift+F is free of editor bindings (plain ⌘F, find in
      // note, requires shift to be UP in useEditorPanels), so this fires
      // while typing too, which is the point: enter zen without leaving
      // the keyboard. Decided 2026-08-21 after the hotkey audit.
      if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.code === 'KeyF') {
        e.preventDefault();
        if (!h.zenUnlocked) { h.onOpenUpgrade('zen'); return; }
        h.setZenMode((z) => !z);
        return;
      }
      if (h.zenMode && e.key === 'Escape') {
        h.setZenMode(false);
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [h.zenMode, h.setZenMode, h.zenUnlocked, h.onOpenUpgrade]);

  // ── Alt/Option+Shift+N: new note ──
  // Uses a ref so the listener always calls the latest handleNew closure
  // (which reads selectedId, view, etc.). The old [] deps caused a stale
  // closure where selectedId was always the initial value, so
  // discardIfEmpty(previousId) never cleaned up empty drafts. Fix: #46.
  const handleNewRef = useRef(h.handleNew);
  handleNewRef.current = h.handleNew;
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.altKey && e.shiftKey && !e.metaKey && !e.ctrlKey && e.code === 'KeyN') {
        e.preventDefault();
        void handleNewRef.current();
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  // ── Main shortcuts (ref-indirection for stable listener) ──
  const shortcutHandlerRef = useRef<(e: KeyboardEvent) => void>(() => {});
  shortcutHandlerRef.current = (e: KeyboardEvent) => {
    const mod = e.metaKey || e.ctrlKey;
    const editing = isEditableTarget(e.target);

    // ── Shortcuts that work anywhere, including inside text fields ──

    // Cmd/Ctrl+K - focus search, EVERYWHERE including the editor: ⌘K is
    // the search key people expect these days, so insert-link moved to
    // ⌘⇧K (Editor.tsx handleKeyDown). Decided 2026-08-21.
    if (mod && !e.altKey && e.code === 'KeyK' && !e.shiftKey) {
      e.preventDefault();
      h.searchInputRef.current?.focus();
      h.searchInputRef.current?.select();
      return;
    }

    // ⌘\ - toggle sidebar.
    if (mod && !e.shiftKey && !e.altKey && e.code === 'Backslash') {
      e.preventDefault();
      h.setSidebarCollapsed((v) => !v);
      return;
    }

    // ⌘[ / ⌘] - previous and next note in the list. J and K do the same
    // thing, but only outside a text field; these fire while typing, which
    // is the point - stepping through a list of notes without first taking
    // your hands off the keyboard. TipTap binds no bracket, so nothing is
    // taken from the editor.
    if (mod && !e.shiftKey && !e.altKey && (e.code === 'BracketLeft' || e.code === 'BracketRight')) {
      e.preventDefault();
      h.navigateList(e.code === 'BracketLeft' ? 'prev' : 'next');
      return;
    }

    // ⌘, - open settings.
    if (mod && !e.shiftKey && !e.altKey && (e.code === 'Comma' || e.key === ',')) {
      e.preventDefault();
      h.setShowSettings(true);
      return;
    }

    // ⌘⇧L - toggle light/dark.
    if (mod && e.shiftKey && !e.altKey && e.code === 'KeyL') {
      e.preventDefault();
      h.toggleTheme();
      return;
    }

    // ⌘⌫ - move selected note to trash.
    if (mod && !e.shiftKey && !e.altKey && (e.code === 'Backspace' || e.code === 'Delete')) {
      if (editing) return;
      if (!h.selectedId || h.view === 'trash' || h.view === 'tasks') return;
      e.preventDefault();
      void h.handleTrash(h.selectedId);
      return;
    }

    // Esc - clear search first (works even when the search input is
    // focused); otherwise close the open note editor. Skipped when a
    // modal dialog is open (it owns Escape) or in zen / multi-select
    // (handled by their own listeners).
    if (e.key === 'Escape') {
      if (h.search) {
        e.preventDefault();
        h.setSearch('');
        h.searchInputRef.current?.blur();
        return;
      }
      if (
        h.selectedId &&
        !h.zenMode &&
        !h.selectionMode &&
        !document.querySelector('[role="dialog"], [aria-modal="true"]')
      ) {
        e.preventDefault();
        h.closeEditor();
      }
      return;
    }

    // ── Shortcuts that should NOT fire while typing in a text field ──
    if (editing) return;

    // ? - toggle Hotkeys Help.
    if (e.key === '?' && !mod && !e.altKey) {
      e.preventDefault();
      h.setShowAbout(h.showAbout ? false : { tab: 'hotkeys' });
      return;
    }

    // J / K - move down / up in the current notes list.
    if (!mod && !e.shiftKey && !e.altKey && (e.code === 'KeyJ' || e.code === 'KeyK')) {
      const list = h.displayNotesRef.current;
      if (!list || list.length === 0) return;
      e.preventDefault();
      const idx = h.selectedId ? list.findIndex((n) => n.id === h.selectedId) : -1;
      let next: number;
      if (e.code === 'KeyJ') {
        next = idx < 0 ? 0 : Math.min(list.length - 1, idx + 1);
      } else {
        next = idx < 0 ? list.length - 1 : Math.max(0, idx - 1);
      }
      const target = list[next];
      if (target) void h.handleSelectNote(target.id);
      return;
    }
  };
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      // Escape clears the search even while its field has focus, so an
      // Escape that cancels a conversion there would empty the search.
      if (isImeComposing(e)) return;
      shortcutHandlerRef.current(e);
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  // ── Multi-select keyboard: Esc exits, Cmd/Ctrl+A selects all visible ──
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (isImeComposing(e)) return;
      if (e.key === 'Escape' && h.selectionMode) {
        h.clearSelection();
        return;
      }
      const mod = e.metaKey || e.ctrlKey;
      if (mod && e.key.toLowerCase() === 'a' && h.selectionMode) {
        if (isEditableTarget(e.target)) return;
        e.preventDefault();
        h.selectAllVisible();
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [h.selectionMode, h.clearSelection, h.selectAllVisible]);
}
