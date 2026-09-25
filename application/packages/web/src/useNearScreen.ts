import { useEffect, useState, type RefObject } from 'react';

/**
 * True once the element has come within 300px of the screen, and from then
 * on. A tile that has to decrypt a file to draw itself waits for this, so a
 * list of two hundred files reads only the ones somebody scrolls to.
 */
export function useNearScreen(ref: RefObject<Element | null>, enabled = true): boolean {
  const [near, setNear] = useState(false);

  useEffect(() => {
    if (!enabled || near) return;
    const el = ref.current;
    if (!el) return;
    const io = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          io.disconnect();
          setNear(true);
        }
      },
      { rootMargin: '300px' },
    );
    io.observe(el);
    return () => io.disconnect();
  }, [ref, enabled, near]);

  return near;
}
