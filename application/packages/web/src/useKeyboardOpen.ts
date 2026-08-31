/**
 * useKeyboardOpen - detects whether the on-screen keyboard is visible.
 *
 * Uses the Visual Viewport API: stores the maximum observed viewport
 * height as a baseline, then checks if the current height is
 * significantly smaller (keyboard eating space). This works on iOS
 * Safari where `window.innerHeight` also shrinks when the keyboard
 * opens, making a simple `innerHeight - vv.height` delta unreliable.
 *
 * Returns `false` on desktop or when the API isn't available.
 *
 * The same baseline is published as `--pn-stable-vh`, the viewport height with
 * no keyboard in the way. Anything sized against the viewport that must not
 * move while someone types reads that instead of a viewport unit, because
 * `interactive-widget=resizes-content` in index.html resizes the layout
 * viewport itself: on Android every unit, `svh` included, follows the keyboard
 * down. Spec: ops/docs/ui-patterns.md (stable viewport height)
 */

import { useEffect, useRef, useState } from 'react';

const THRESHOLD = 150;

export function useKeyboardOpen(): boolean {
  const [open, setOpen] = useState(false);
  const maxHeight = useRef(0);
  const lastWidth = useRef(0);

  useEffect(() => {
    const vv = window.visualViewport;
    if (!vv) return;

    const publish = () => {
      document.documentElement.style.setProperty('--pn-stable-vh', `${maxHeight.current}px`);
    };

    // Seed with the larger of innerHeight and current viewport height.
    maxHeight.current = Math.max(window.innerHeight, vv.height);
    lastWidth.current = vv.width;
    publish();

    const check = () => {
      // The on-screen keyboard only changes viewport HEIGHT, never width. A
      // width change is a window resize / orientation change, so re-baseline to
      // the new height and report closed. Without this, dragging a desktop
      // window shorter reads as a keyboard opening and hides mobile chrome (the
      // header hamburger), since the now-narrow window also counts as mobile.
      if (vv.width !== lastWidth.current) {
        lastWidth.current = vv.width;
        maxHeight.current = vv.height;
        publish();
        setOpen(false);
        return;
      }
      const h = vv.height;
      if (h > maxHeight.current) {
        // Viewport grew (e.g. browser toolbar hide) - update baseline.
        maxHeight.current = h;
        publish();
      }
      setOpen(maxHeight.current - h > THRESHOLD);
    };

    vv.addEventListener('resize', check);
    check();
    return () => vv.removeEventListener('resize', check);
  }, []);

  return open;
}
