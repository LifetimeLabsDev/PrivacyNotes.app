import { useCallback } from 'react';

/**
 * @catalog useProGate
 * use: every Pro action. Wrap the handler: an unlocked account (Pro, or the demo) runs it, a free account gets the upgrade window. The control stays enabled and shows the Pro mark (`Button pro`, `ProMark` after a heading).
 * never: `disabled={!isPro}`; a Pro control that does nothing on click; a second upgrade text.
 */
export function useProGate(unlocked: boolean, onUpgrade: (() => void) | undefined) {
  return useCallback(
    <A extends unknown[]>(action: (...args: A) => void) =>
      (...args: A) => {
        if (unlocked) action(...args);
        else onUpgrade?.();
      },
    [unlocked, onUpgrade],
  );
}
