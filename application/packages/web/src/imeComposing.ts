import type { KeyboardEvent as ReactKeyboardEvent } from 'react';

/**
 * Whether a key belongs to the input method that is composing text, and not
 * to the page. While Japanese, Chinese or Korean is composed, Enter, Space,
 * Tab, Escape, the arrows and the comma confirm, pick or cancel the
 * conversion, so a field or a shortcut that acted on them would commit a
 * half-typed reading, clear a search or close a window. Safari sends the
 * Enter that ends a conversion after `compositionend`, with keyCode 229, so
 * the code is read as well as the flag. The editor needs no call: ProseMirror
 * already ignores keys while it composes.
 * Spec: ops/docs/ui-patterns.md (keys that belong to the input method)
 */
export function isImeComposing(event: KeyboardEvent | ReactKeyboardEvent): boolean {
  const key = 'nativeEvent' in event ? event.nativeEvent : event;
  return key.isComposing || key.keyCode === 229;
}
