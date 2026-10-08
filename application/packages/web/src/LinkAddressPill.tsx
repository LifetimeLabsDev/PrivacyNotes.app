/**
 * Where a link goes, shown while the pointer rests on it.
 *
 * A reader should be able to see the address before they commit to it, which
 * is the habit a browser teaches with the bar in its bottom corner, and the
 * reason GitHub #406 asks for it inside a note as well.
 *
 * The address lands in the editor's own bottom corner rather than in a tip
 * above the link, and that is the whole design decision. A tip hung on the
 * link is clipped: the note scroller clips horizontally, so a centered pill
 * over a link near either margin loses an end, and an address is both long
 * and the one string that must never be read half. The corner is as wide as
 * the pane, never clipped on any axis, and holds a long address whole.
 *
 * It is not the `title` attribute either, which the house forbids for every
 * tip: it waits about a second, wears OS chrome, and differs per platform.
 *
 * Two kinds of link stay out of it. A note-link carries a note title rather
 * than an address and has its own tip in its node view, and it is a `span`,
 * so it never matches here. An attachment chip is an anchor whose href is an
 * internal file id, which tells a reader nothing.
 */

import { useEffect, useState, type RefObject } from 'react';
import { TIP_PILL_LOOK } from './HoverLabel';

/** The anchor under the pointer whose address is worth showing, or null. */
function addressOf(target: EventTarget | null): string | null {
  if (!(target instanceof Element)) return null;
  const anchor = target.closest('a[href]');
  if (!anchor || anchor.hasAttribute('data-attachment')) return null;
  // Only a link in the note body. The toolbar and the link panel hold
  // anchors of their own, and their addresses are not the reader's business.
  if (!anchor.closest('.ProseMirror')) return null;
  return anchor.getAttribute('href') || null;
}

export function LinkAddressPill({ rootRef }: { rootRef: RefObject<HTMLDivElement | null> }) {
  const [href, setHref] = useState<string | null>(null);

  useEffect(() => {
    const root = rootRef.current;
    if (!root) return;
    // `mouseover` alone covers every move INSIDE the editor, because it
    // fires again on each element the pointer enters and the answer for
    // plain text is null. Leaving the editor enters no element here, so
    // that one case needs its own listener.
    const onOver = (e: Event) => setHref(addressOf(e.target));
    const onLeave = () => setHref(null);
    root.addEventListener('mouseover', onOver);
    root.addEventListener('mouseleave', onLeave);
    return () => {
      root.removeEventListener('mouseover', onOver);
      root.removeEventListener('mouseleave', onLeave);
    };
  }, [rootRef]);

  if (!href) return null;
  return (
    // Sticky and zero height, the same trick the find bar uses at the top of
    // this pane: the pill floats over the note instead of reserving a row,
    // and it stays in the corner while the note scrolls under it. On a short
    // note there is nothing to scroll and it sits below the last line.
    <div
      aria-hidden="true"
      className="sticky bottom-0 z-[5] flex h-0 items-end justify-start overflow-visible pointer-events-none"
    >
      <div className={`${TIP_PILL_LOOK} mb-1 max-w-full truncate`} dir="ltr">
        {href}
      </div>
    </div>
  );
}
