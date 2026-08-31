import { useState, useEffect } from 'react';

/** Matches Tailwind's `lg` breakpoint (1024px). Below that = mobile. */
const MQ = '(max-width: 1023px)';

/**
 * Matches a touch-first device. Same `(hover: none)` heuristic as
 * `isSoftKeyboardDevice()` in `softKeyboard.ts` and the `(hover: hover)`
 * blocks in `index.css`, so one device means one thing across the app.
 */
const TOUCH_MQ = '(hover: none)';

function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() =>
    typeof window !== 'undefined' ? window.matchMedia(query).matches : false
  );

  useEffect(() => {
    const mql = window.matchMedia(query);
    const handler = (e: MediaQueryListEvent) => setMatches(e.matches);
    mql.addEventListener('change', handler);
    return () => mql.removeEventListener('change', handler);
  }, [query]);

  return matches;
}

/**
 * Returns `true` when the viewport is below the `lg` breakpoint.
 *
 * Primary use: set `tabIndex={-1}` on inputs so iOS Safari doesn't
 * show the prev/next form-assistant toolbar above the keyboard.
 * Users can still tap to focus - only the automatic tab chain is
 * removed.
 *
 * This is a WIDTH test, so a desktop window narrowed below `lg` counts as
 * mobile. For an affordance that needs a finger rather than a small
 * viewport, use `useIsTouchDevice()` instead.
 */
export function useIsMobile(): boolean {
  return useMediaQuery(MQ);
}

/**
 * Returns `true` on a touch-first device (phone, tablet), `false` wherever
 * there is a mouse or a trackpad.
 *
 * Use it for an affordance only a finger has. The case it was built for:
 * a chip row that scrolls sideways with its scrollbar hidden. A finger
 * swipes it; a pointer cannot reach it at all, because the scrollbar is
 * gone and a vertical wheel does not move a horizontal scroller.
 * Spec: ops/docs/ui-patterns.md section 85 (hidden sideways scroll).
 */
export function useIsTouchDevice(): boolean {
  return useMediaQuery(TOUCH_MQ);
}
