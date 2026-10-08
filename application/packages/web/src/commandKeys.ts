/**
 * The keys of every command, on each OS and in each app: the data the key
 * handlers read (through `APP_KEYS` in shortcutMatch.ts) and the formatter
 * that writes a key for the help and for a tooltip. The help rows that show
 * them live in hotkeysData.ts, which only the help needs, so they stay out of
 * the app's first load.
 *
 * help-page.ts evaluates this file on its own, so it MUST stay free of
 * imports, and nothing at the top level may read a build constant.
 *
 * Spec: ops/docs/plans/keyboard-shortcuts.md (sections 4.1 and 5)
 */

export type KeyOs = 'mac' | 'pc';

export interface KeyBinding {
  /** A lowercase letter, a digit, a punctuation character, or a key name such as 'Escape'. 'Click' is a mouse gesture, shown in the help only. */
  readonly key: string;
  /** Cmd on macOS and iOS, Ctrl everywhere else. */
  readonly mod?: boolean;
  /** The Ctrl key itself on a Mac, where Mod is Cmd. Named keys only: Ctrl plus a letter edits text on a Mac. */
  readonly ctrl?: boolean;
  /** Option on macOS. */
  readonly alt?: boolean;
  /** Letters, digits and key names only: a punctuation character carries its own Shift. */
  readonly shift?: boolean;
  /** A held key runs it again. Everything else runs once per press. */
  readonly repeat?: boolean;
  /**
   * macOS: an Option binding without Cmd runs in a text field too. Option
   * types a character there, so this is only for a key whose character nobody
   * types (the ˜ of Option+Shift+N).
   */
  readonly optionWhileTyping?: boolean;
  /** One OS only. Missing means every OS. */
  readonly os?: KeyOs;
  /** The desktop apps only: a browser keeps this key for itself, or gives it a meaning of its own. */
  readonly desktop?: boolean;
  /** Works, but the help shows it only when no other key of the command applies. */
  readonly alias?: boolean;
}

/**
 * The keys of every command. The app's handlers read them through
 * `APP_KEYS`; the editor's own keys (`owner: 'editor'` below) run inside
 * TipTap's keymap and are listed here for the help.
 */
export const COMMAND_KEYS = {
  // ── Navigation ──
  // A single key, as on GitHub and Gmail: Mod+K belongs to the quick
  // switcher, whose last row runs this same search.
  focusSearch: [{ key: '/' }],
  listDown: [{ key: 'j', repeat: true }],
  listUp: [{ key: 'k', repeat: true }],
  // The list step while typing. Ctrl+Up alone is Mission Control on a Mac,
  // and Option+Up moves the caret there; Alt+Up does nothing in a text
  // field on Windows and Linux.
  previousInList: [
    { mod: true, ctrl: true, key: 'ArrowUp', os: 'mac', repeat: true },
    { alt: true, key: 'ArrowUp', os: 'pc', repeat: true },
  ],
  nextInList: [
    { mod: true, ctrl: true, key: 'ArrowDown', os: 'mac', repeat: true },
    { alt: true, key: 'ArrowDown', os: 'pc', repeat: true },
  ],
  // Back and forward through the opened items, as in a browser. Option+Left
  // moves the caret by a word on a Mac, so the Alt keys are for Windows and
  // Linux only. Spec: ops/issues/0331.md
  historyBack: [
    { mod: true, key: '[', repeat: true },
    { alt: true, key: 'ArrowLeft', os: 'pc', repeat: true },
  ],
  historyForward: [
    { mod: true, key: ']', repeat: true },
    { alt: true, key: 'ArrowRight', os: 'pc', repeat: true },
  ],
  // A browser keeps Mod+1 to 9 for its tabs.
  goToSection: [1, 2, 3, 4, 5, 6, 7, 8, 9].map((n) => ({ mod: true, key: String(n), desktop: true })),
  nextPane: [{ key: 'F6' }],
  previousPane: [{ shift: true, key: 'F6' }],
  escape: [{ key: 'Escape' }],
  // Mod+K, the "go anywhere" key of most apps. Mod+P stays as an alias in
  // every app, because a browser prints the page on it and the app page has
  // nothing to print. Mod+O, the switcher key of other note apps, opens a file
  // in a browser, so it is the desktop apps' alone.
  quickSwitcher: [
    { mod: true, key: 'k' },
    { mod: true, key: 'p', alias: true },
    { mod: true, key: 'o', desktop: true, alias: true },
  ],
  // Command mode in the search field; ">" is also the text that opens it there.
  commandMode: [
    { key: '>' },
    { mod: true, shift: true, key: 'p', desktop: true },
  ],

  // ── Items ──
  newNote: [
    { mod: true, key: 'n', desktop: true },
    { alt: true, shift: true, key: 'n', optionWhileTyping: true, alias: true },
  ],
  newMenu: [{ mod: true, shift: true, key: 'n', desktop: true }],
  moveToTrash: [
    { mod: true, key: 'Backspace' },
    { mod: true, key: 'Delete', alias: true },
  ],
  selectAll: [{ mod: true, key: 'a' }],

  // ── Lists and tabs ──
  selectSeveral: [{ mod: true, key: 'Click' }],
  selectRange: [{ shift: true, key: 'Click' }],
  openInTab: [{ alt: true, key: 'Click' }],
  // A browser closes its own tab on Mod+W before a page can refuse it.
  closeTab: [
    { mod: true, key: 'w', desktop: true },
    { alt: true, shift: true, key: 'w', alias: true },
  ],
  nextTab: [
    { ctrl: true, key: 'Tab', os: 'mac', desktop: true, repeat: true },
    { mod: true, key: 'Tab', os: 'pc', desktop: true, repeat: true },
    { mod: true, alt: true, key: 'ArrowRight', os: 'mac', desktop: true, alias: true, repeat: true },
  ],
  previousTab: [
    { ctrl: true, shift: true, key: 'Tab', os: 'mac', desktop: true, repeat: true },
    { mod: true, shift: true, key: 'Tab', os: 'pc', desktop: true, repeat: true },
    { mod: true, alt: true, key: 'ArrowLeft', os: 'mac', desktop: true, alias: true, repeat: true },
  ],

  // ── Editor ──
  find: [{ mod: true, key: 'f' }],
  // Ctrl+Alt+F is AltGr+F off the Mac ("[" on a Czech keyboard), so Windows
  // and Linux take Ctrl+H, their own convention; the old key stays as a
  // silent alias where AltGr types nothing.
  findReplace: [
    { mod: true, alt: true, key: 'f', os: 'mac' },
    { mod: true, key: 'h', os: 'pc' },
    { mod: true, alt: true, key: 'f', os: 'pc', alias: true },
  ],
  outline: [{ mod: true, shift: true, key: 'o' }],
  insertLink: [{ mod: true, shift: true, key: 'k' }],
  markdownView: [{ mod: true, shift: true, key: 'm' }],
  // A browser opens its developer tools on Mod+Shift+I.
  invisibles: [{ mod: true, shift: true, key: 'i', desktop: true }],
  taskList: [{ mod: true, shift: true, key: '9' }],
  // The keys of Google Sheets. A Mac browser shows its spelling check on
  // them, which stays in its Edit menu.
  insertDate: [{ mod: true, key: ';' }],
  insertDateTime: [{ mod: true, key: ':' }],

  // ── View ──
  openSettings: [{ mod: true, key: ',' }],
  // "\" needs AltGr on many keyboards (German, French), and AltGr is Ctrl+Alt,
  // so those keyboards cannot press Ctrl+\. D is the letter they can.
  toggleSidebar: [
    { mod: true, key: '\\' },
    { mod: true, shift: true, key: 'd' },
  ],
  toggleTheme: [{ mod: true, shift: true, key: 'l' }],
  zoomIn: [
    { mod: true, key: '+', repeat: true, desktop: true },
    { mod: true, key: '=', repeat: true, desktop: true, alias: true },
  ],
  zoomOut: [{ mod: true, key: '-', repeat: true, desktop: true }],
  zoomReset: [{ mod: true, key: '0', desktop: true }],
  zen: [{ mod: true, shift: true, key: 'f' }],
  help: [{ key: '?' }],

  // ── Owned by the editor's keymap (TipTap); listed for the help ──
  undo: [{ mod: true, key: 'z' }],
  redo: [
    { mod: true, shift: true, key: 'z' },
    { mod: true, key: 'y', alias: true },
  ],
  bold: [{ mod: true, key: 'b' }],
  italic: [{ mod: true, key: 'i' }],
  underline: [{ mod: true, key: 'u' }],
  strikethrough: [{ mod: true, shift: true, key: 's' }],
  highlight: [{ mod: true, shift: true, key: 'h' }],
  inlineCode: [{ mod: true, key: 'e' }],
  superscript: [{ mod: true, key: '.' }],
  headings: [1, 2, 3, 4, 5, 6].map((n) => ({ mod: true, alt: true, key: String(n) })),
  normalText: [{ mod: true, alt: true, key: '0' }],
  numberedList: [{ mod: true, shift: true, key: '7' }],
  bulletedList: [{ mod: true, shift: true, key: '8' }],
  indentList: [{ key: 'Tab' }],
  outdentList: [{ shift: true, key: 'Tab' }],
  blockquote: [{ mod: true, shift: true, key: 'b' }],
  codeBlock: [{ mod: true, alt: true, key: 'c' }],
  alignCenter: [{ mod: true, shift: true, key: 'e' }],
  alignRight: [{ mod: true, shift: true, key: 'r' }],
  alignJustify: [{ mod: true, shift: true, key: 'j' }],
} satisfies Record<string, readonly KeyBinding[]>;

export type CommandId = keyof typeof COMMAND_KEYS;

/** Commands whose keys TipTap's keymap handles, not an app listener. */
export const EDITOR_COMMANDS: readonly CommandId[] = [
  'undo', 'redo', 'bold', 'italic', 'underline', 'strikethrough', 'highlight', 'inlineCode',
  'superscript', 'headings', 'normalText', 'numberedList', 'bulletedList', 'indentList',
  'outdentList', 'blockquote', 'codeBlock', 'alignCenter', 'alignRight', 'alignJustify',
];

/** True when a binding works on this OS and in this app. */
export function bindingApplies(b: KeyBinding, os: KeyOs, desktop: boolean): boolean {
  return (!b.os || b.os === os) && (!b.desktop || desktop);
}

/**
 * The keys the help shows for a command: the applicable keys that are not
 * aliases, or the aliases when nothing else applies (Alt+Shift+N in a
 * browser, where Mod+N belongs to the browser).
 */
export function visibleBindings(id: CommandId, os: KeyOs, desktop: boolean): KeyBinding[] {
  const applies = (COMMAND_KEYS[id] as readonly KeyBinding[]).filter((b) => bindingApplies(b, os, desktop));
  const primary = applies.filter((b) => !b.alias);
  return primary.length ? primary : applies;
}

const MAC_NAMES: Record<string, string> = {
  Backspace: '⌫', Delete: '⌦', Escape: 'Esc', Enter: '↩', Tab: 'Tab',
  ArrowLeft: '←', ArrowRight: '→', ArrowUp: '↑', ArrowDown: '↓',
};
const PC_NAMES: Record<string, string> = {
  Backspace: 'Backspace', Delete: 'Delete', Escape: 'Esc', Enter: 'Enter', Tab: 'Tab',
  ArrowLeft: '←', ArrowRight: '→', ArrowUp: '↑', ArrowDown: '↓',
};

/** One binding as key caps: ['⌥', '⌘', 'F'] on a Mac, ['Ctrl', 'Alt', 'F'] elsewhere. */
export function bindingCaps(b: KeyBinding, os: KeyOs): string[] {
  const names = os === 'mac' ? MAC_NAMES : PC_NAMES;
  const key = names[b.key] ?? (b.key.length === 1 ? b.key.toUpperCase() : b.key);
  // The Apple order is ⌃ ⌥ ⇧ ⌘; the PC order is Ctrl Alt Shift.
  if (os === 'mac') {
    return [b.ctrl && '⌃', b.alt && '⌥', b.shift && '⇧', b.mod && '⌘', key].filter((c): c is string => !!c);
  }
  return [(b.mod || b.ctrl) && 'Ctrl', b.alt && 'Alt', b.shift && 'Shift', key].filter((c): c is string => !!c);
}

/** One binding as text: "⌥⌘F" on a Mac, "Ctrl+Alt+F" elsewhere. */
export function bindingText(b: KeyBinding, os: KeyOs): string {
  return bindingCaps(b, os).join(os === 'mac' ? '' : '+');
}

/** The first key the help shows for a command, as text, for a tooltip: "⇧⌘K", "Ctrl+Shift+K". */
export function commandKeyText(id: CommandId, os: KeyOs, desktop: boolean): string {
  const b = visibleBindings(id, os, desktop)[0];
  return b ? bindingText(b, os) : '';
}
