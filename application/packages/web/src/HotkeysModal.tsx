import { HOTKEY_GROUPS } from './hotkeysData';

// Data lives in hotkeysData.ts (imports-free) so the static help page can
// evaluate it too; re-exported here so existing consumers (AboutModal)
// keep importing from this module.
export { HOTKEY_GROUPS };

function isMac(): boolean {
  if (typeof navigator === 'undefined') return true;
  return /Mac|iPhone|iPad/i.test(navigator.platform || navigator.userAgent);
}

export function renderKey(k: string): string {
  if (isMac()) return k;
  // Windows / Linux: swap symbols to words, then join with +
  // Split on symbol boundaries, map each token, rejoin with +
  const tokens: string[] = [];
  let rest = k;
  const map: Record<string, string> = {
    '⌘': 'Ctrl',
    '⌥': 'Alt',
    '⇧': 'Shift',
    '⌫': 'Backspace',
  };
  while (rest.length > 0) {
    const sym = rest[0]!;
    if (map[sym] != null) {
      tokens.push(map[sym]!);
      rest = rest.slice(1);
    } else {
      // Everything remaining is the final key (e.g. "K", "1", "\\", " / K")
      tokens.push(rest);
      break;
    }
  }
  return tokens.join('+');
}
