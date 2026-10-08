// An Escape pressed in the note editor that none of the editor's own
// handlers used. ProseMirror prevents the default of every Escape it sees, so
// "already prevented" cannot tell a menu's Escape from a plain one there; the
// editor marks the plain one and the shortcut matcher reads the mark.
const plain = new WeakSet<object>();

export function markPlainEscape(e: object): void {
  plain.add(e);
}

export function isPlainEscape(e: object): boolean {
  return plain.has(e);
}
