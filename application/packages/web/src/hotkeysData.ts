/**
 * Keyboard shortcut reference data, shared by two renderers:
 *   - HotkeysModal.tsx (the in-app "?" modal; also re-exported for
 *     AboutModal's hotkeys tab)
 *   - help-page.ts (the static /help/keyboard-shortcuts leaf; evaluates
 *     this file standalone with esbuild, so it MUST stay free of imports)
 *
 * Keep the rows in sync with the handlers in useKeyboardShortcuts.ts,
 * NotesView.tsx, and Editor.tsx. `label`/`title` hold the English source
 * (also used as a fallback and React key by consumers); `i18nKey` is the
 * suffix under `hotkeys.*` in the common catalog. Render display text via
 * t(), keep keys for binding labels stable.
 * Order by how often they're reached for, not strictly by category.
 */

type HotkeyRow = { keys: string; label: string; i18nKey: string };
type HotkeyGroup = { title: string; i18nKey: string; rows: HotkeyRow[] };

export const HOTKEY_GROUPS: HotkeyGroup[] = [
  {
    title: 'Navigation',
    i18nKey: 'navigation',
    rows: [
      { keys: '⌘K', label: 'Focus search', i18nKey: 'focusSearch' },
      { keys: 'J / K', label: 'Move down / up in the list', i18nKey: 'moveInList' },
      // The same step as J and K, but free of editor bindings: TipTap binds
      // no bracket, so these fire while typing too, which J and K cannot.
      { keys: '⌘[', label: 'Previous note in the list', i18nKey: 'notePrev' },
      { keys: '⌘]', label: 'Next note in the list', i18nKey: 'noteNext' },
      // Esc actually does four things, in this order: clear the list search,
      // exit zen, exit multi-select, close the open note. "Close note" must
      // stay in the label: it is the one people notice - it deselects and the
      // editor remounts, which reads as the note jumping to the top.
      { keys: 'Esc', label: 'Clear search / close note / exit selection', i18nKey: 'clearSearch' },
    ],
  },
  {
    title: 'Notes',
    i18nKey: 'notes',
    rows: [
      { keys: '⌥⇧N', label: 'New note', i18nKey: 'newNote' },
      { keys: '⌘⌫', label: 'Move note to trash', i18nKey: 'moveToTrash' },
    ],
  },
  {
    title: 'Editor',
    i18nKey: 'editor',
    rows: [
      // Toggles. Esc deliberately does NOT close it - Esc closes the note.
      { keys: '⌘F', label: 'Find in note (press again to close)', i18nKey: 'findInNote' },
      // ⌥⌘F, never ⌘H: macOS takes ⌘H for Hide before a page sees it.
      { keys: '⌥⌘F', label: 'Find and replace', i18nKey: 'findReplace' },
      { keys: '⌘⇧O', label: 'Toggle outline', i18nKey: 'toggleOutline' },
      // ⌘⇧K, not ⌘K: plain ⌘K focuses search everywhere since 2026-08-21
      // (useKeyboardShortcuts.ts); the link popover took the shifted key.
      { keys: '⌘⇧K', label: 'Insert link (while editing)', i18nKey: 'insertLink' },
      { keys: '⌘Z', label: 'Undo', i18nKey: 'undo' },
      { keys: '⌘⇧Z', label: 'Redo (while editing)', i18nKey: 'redo' },
    ],
  },
  {
    title: 'Formatting',
    i18nKey: 'formatting',
    rows: [
      { keys: '⌘B', label: 'Bold', i18nKey: 'bold' },
      { keys: '⌘I', label: 'Italic', i18nKey: 'italic' },
      { keys: '⌘U', label: 'Underline', i18nKey: 'underline' },
      { keys: '⌘⇧S', label: 'Strikethrough', i18nKey: 'strikethrough' },
      { keys: '⌘⇧H', label: 'Highlight', i18nKey: 'highlight' },
      { keys: '⌘E', label: 'Inline code', i18nKey: 'inlineCode' },
      { keys: '⌘.', label: 'Superscript', i18nKey: 'superscript' },
      { keys: '⌥⌘1 – ⌥⌘6', label: 'Heading 1 to 6', i18nKey: 'headings' },
      { keys: '⌥⌘0', label: 'Normal text', i18nKey: 'normalText' },
      { keys: '⇧⌘7', label: 'Numbered list', i18nKey: 'numberedList' },
      { keys: '⇧⌘8', label: 'Bulleted list', i18nKey: 'bulletedList' },
      { keys: '⇧⌘9', label: 'Task list', i18nKey: 'taskList' },
      // Tab/Shift+Tab reach every list kind, checklists included.
      { keys: 'Tab', label: 'Increase indent (list or checklist)', i18nKey: 'indentList' },
      { keys: '⇧Tab', label: 'Decrease indent (list or checklist)', i18nKey: 'outdentList' },
      { keys: '⌘⇧B', label: 'Blockquote', i18nKey: 'blockquote' },
      { keys: '⌥⌘C', label: 'Code block', i18nKey: 'codeBlock' },
    ],
  },
  {
    // Left is deliberately absent: it is not a stored state (see
    // ALIGNMENT_VALUES in Editor.tsx), and its upstream ⌘⇧L binding is
    // removed because ⌘⇧L is our light/dark toggle.
    title: 'Alignment',
    i18nKey: 'alignment',
    rows: [
      { keys: '⌘⇧E', label: 'Center', i18nKey: 'alignCenter' },
      { keys: '⌘⇧R', label: 'Align right', i18nKey: 'alignRight' },
      { keys: '⌘⇧J', label: 'Justify', i18nKey: 'alignJustify' },
    ],
  },
  {
    title: 'View',
    i18nKey: 'view',
    rows: [
      { keys: '⌘,', label: 'Open settings', i18nKey: 'openSettings' },
      { keys: '⌘\\', label: 'Toggle sidebar', i18nKey: 'toggleSidebar' },
      { keys: '⌘⇧L', label: 'Toggle light / dark mode', i18nKey: 'toggleTheme' },
      // ⌘⇧F ("focus"), not ⌘⇧Z: Z is the editor's redo, and zen must be
      // reachable WHILE writing - see the zen branch in
      // useKeyboardShortcuts.ts. Plain ⌘F stays find-in-note.
      { keys: '⌘⇧F', label: 'Zen / Focus mode (Pro)', i18nKey: 'zenMode' },
      { keys: '?', label: 'Toggle this help', i18nKey: 'toggleHelp' },
    ],
  },
];
