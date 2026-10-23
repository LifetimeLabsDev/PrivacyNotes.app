/**
 * Whether a key press is one of the app's shortcuts.
 *
 * Every key handler the app owns asks this one function, so a key press has
 * one meaning on every keyboard. A shortcut names the character a key types,
 * the way the editor's own keymap does, never the place that key has on a US
 * keyboard: the Bépo layout puts Z where a US keyboard has "[", so a match by
 * place would make Ctrl+Z run "previous note" as well as undo (GitHub #395).
 * Typing always wins: a key that types a character on this keyboard runs
 * nothing.
 *
 * Spec: ops/docs/archive/keyboard-shortcuts.md (section 4.3, the matcher rules)
 */

import { COMMAND_KEYS, bindingText, commandKeyText, type CommandId, type KeyBinding, type KeyOs } from './commandKeys';
import { isPlainEscape } from './plainEscape';

export type { KeyBinding };

/** The parts of a keydown the rules read. A KeyboardEvent is one. */
export interface KeyPress {
  readonly key: string;
  readonly code: string;
  readonly keyCode?: number;
  readonly metaKey: boolean;
  readonly ctrlKey: boolean;
  readonly altKey: boolean;
  readonly shiftKey: boolean;
  readonly repeat?: boolean;
  readonly isComposing?: boolean;
  readonly defaultPrevented?: boolean;
  getModifierState?(key: string): boolean;
}

/** The same test the editor's keymap uses, so "Mod" means one key in both. */
const APPLE = typeof navigator !== 'undefined' && /Mac|iP(hone|[oa]d)/.test(navigator.platform);

/**
 * The desktop apps (macOS, Windows, Linux). A constant of the build, so a
 * desktop-only branch folds away in the web bundle. The phone apps use the
 * browser keys: a hardware keyboard on a phone has no windows or tabs.
 */
export function isDesktopApp(): boolean {
  return __PN_BUILD_PLATFORM__ !== '' && __PN_BUILD_PLATFORM__ !== 'ios' && __PN_BUILD_PLATFORM__ !== 'android';
}
export const DESKTOP_APP = isDesktopApp();

/** The key names this device shows: ⌘ on Apple, Ctrl elsewhere. */
export const KEY_OS: KeyOs = APPLE ? 'mac' : 'pc';

/** A command's key as this device and app show it, for a tooltip: "⇧⌘K", "Ctrl+Shift+K". */
export function keyText(id: CommandId): string {
  return commandKeyText(id, KEY_OS, DESKTOP_APP);
}

/** The key of the nth sidebar section (1 is All), or '' past 9 and in a
 *  browser, which keeps Mod+1 to 9 for its tabs. */
export function sectionKeyText(n: number): string {
  const b = COMMAND_KEYS.goToSection[n - 1];
  return b && DESKTOP_APP ? bindingText(b, KEY_OS) : '';
}

/** A key that belongs to one control and to no command (Enter in the find
 *  bar), in the same format as `keyText`: "⇧↩", "Shift+Enter". */
export function bindingKeyText(b: KeyBinding): string {
  return bindingText(b, KEY_OS);
}

/** The US keyboard key of each unshifted punctuation character. */
const PUNCTUATION_CODES: Record<string, string> = {
  '[': 'BracketLeft',
  ']': 'BracketRight',
  '\\': 'Backslash',
  ',': 'Comma',
  '.': 'Period',
  '/': 'Slash',
  ';': 'Semicolon',
  "'": 'Quote',
  '=': 'Equal',
  '-': 'Minus',
  '`': 'Backquote',
};

/** The character each of those keys types with Shift on a US keyboard. */
const US_SHIFTED: Record<string, string> = {
  BracketLeft: '{',
  BracketRight: '}',
  Backslash: '|',
  Comma: '<',
  Period: '>',
  Slash: '?',
  Semicolon: ':',
  Quote: '"',
  Equal: '+',
  Minus: '_',
  Backquote: '~',
};

function isAscii(key: string): boolean {
  return key.length === 1 && key.charCodeAt(0) < 0x80;
}

function matchesOne(e: KeyPress, b: KeyBinding, typing: boolean, apple: boolean, desktop: boolean): boolean {
  if (b.os && (b.os === 'mac') !== apple) return false;
  if (b.desktop && !desktop) return false;
  // The input method owns a key while it composes (ui-patterns.md section
  // 111), and a dead key is half of a character.
  if (e.isComposing || e.keyCode === 229 || e.key === 'Process' || e.key === 'Dead') return false;
  // An inner owner already acted on it: the editor, a field, a menu. The
  // editor prevents every Escape, and marks the one none of its handlers used.
  if (e.defaultPrevented && !isPlainEscape(e)) return false;
  if (e.repeat && !b.repeat) return false;

  // Mod is Cmd on Apple and Ctrl elsewhere, and the other one must be up:
  // Ctrl on a Mac edits text (Ctrl+K deletes to the end of the line). Only a
  // binding that names Ctrl itself (Ctrl+Tab on a Mac) takes it there.
  const mod = apple ? e.metaKey : e.ctrlKey;
  const otherMod = apple ? e.ctrlKey : e.metaKey;
  if (otherMod !== (apple && !!b.ctrl) || mod !== (!!b.mod || (!apple && !!b.ctrl))) return false;

  // Off Apple, AltGr arrives as Ctrl+Alt, and the key may be typing a
  // character ("[" is AltGr+F on a Czech keyboard). Only a Ctrl+Alt binding
  // whose own character came out matches.
  if (!apple && ((e.ctrlKey && e.altKey) || e.getModifierState?.('AltGraph'))) {
    return !!b.mod && !!b.alt && e.shiftKey === !!b.shift && e.key.toLowerCase() === b.key;
  }

  const isLetter = /^[a-z]$/.test(b.key);
  const isDigit = /^[0-9]$/.test(b.key);
  if (!isLetter && !isDigit && b.key.length === 1) {
    // A Mac reports a key held with Cmd and Shift without its Shift (Cmd+Shift+;
    // arrives as ";"), so there the character comes from the key's US place,
    // as the editor's keymap reads it. A layout that types it on another key
    // misses, and no other command runs in its place.
    if (apple && e.metaKey && e.shiftKey && !e.altKey) return US_SHIFTED[e.code] === b.key;
    // Punctuation: the character, with any Shift. On Apple, Option is how
    // many layouts type it ("[" is Option+5 on a German Mac), so an extra
    // Option is fine when the bound character came out.
    if (e.key === b.key) return e.altKey === !!b.alt || (apple && !b.alt);
    // A key that types a non-ASCII character here (х on a Russian keyboard)
    // cannot type the bound one, so its US place stands in, as every OS does.
    return !isAscii(e.key) && !e.shiftKey && e.altKey === !!b.alt && e.code === PUNCTUATION_CODES[b.key];
  }

  if (e.shiftKey !== !!b.shift || e.altKey !== !!b.alt) return false;
  // Option types a character on a Mac (Option+Shift+W is „), so an Option
  // binding without Cmd waits until focus leaves the text.
  if (apple && b.alt && !b.mod && typing && !b.optionWhileTyping) return false;

  if (isLetter) {
    if (e.key.toLowerCase() === b.key) return true;
    return !isAscii(e.key) && e.code === `Key${b.key.toUpperCase()}`;
  }
  // Digits by place: AZERTY and Bépo type a digit only with Shift. A keypad
  // digit needs Num Lock (Ctrl+Insert shares its key), and Alt plus a
  // keypad digit is a Windows Alt code.
  if (isDigit) return e.code === `Digit${b.key}` || (e.code === `Numpad${b.key}` && e.key === b.key);
  return e.key === b.key;
}

/**
 * True when the key press is one of the bindings. `typing` is true while
 * focus is in a text field or the editor.
 */
export function matchesKey(
  e: KeyPress,
  bindings: readonly KeyBinding[],
  typing = false,
  apple = APPLE,
  desktop = DESKTOP_APP,
): boolean {
  return bindings.some((b) => matchesOne(e, b, typing, apple, desktop));
}

/**
 * The keys of every command, from the command list. The editor's formatting
 * keys run inside TipTap's keymap and are listed there for the help only.
 */
export const APP_KEYS = COMMAND_KEYS;
