/**
 * Where a link goes, shown while the pointer rests on it.
 *
 * A reader should be able to see the address before they commit to it, which
 * is the habit a browser teaches with the bar in its bottom corner, and the
 * reason GitHub #406 asks for it inside a note as well.
 *
 * The address lands in the bottom corner of the pane's visible area, flush
 * against both edges, the place and the look of a browser's status bar. A tip
 * hung on the link is clipped: the note scroller clips horizontally, so a
 * centered pill over a link near either margin loses an end, and an address
 * is both long and the one string that must never be read half. The corner
 * is as wide as the pane and holds a long address whole. It is fixed to the
 * pane, not to the note, so a short note does not carry it up under its last
 * line, where it reads as a stray element of the note.
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
import { createPortal } from 'react-dom';
import { visibleBox } from './HoverLabel';

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

type Shown = { href: string; left: number; right: number; bottom: number; rtl: boolean };

export function LinkAddressPill({ rootRef }: { rootRef: RefObject<HTMLDivElement | null> }) {
  const [shown, setShown] = useState<Shown | null>(null);

  useEffect(() => {
    const root = rootRef.current;
    if (!root) return;
    // `mouseover` alone covers every move INSIDE the editor, because it
    // fires again on each element the pointer enters and the answer for
    // plain text is null. Leaving the editor enters no element here, so
    // that one case needs its own listener.
    const onOver = (e: Event) => {
      const href = addressOf(e.target);
      if (!href) return setShown(null);
      // Read once per link: the pointer rests on the link, so the pane does
      // not move under it.
      const box = visibleBox(root);
      setShown({
        href,
        left: box.left,
        right: window.innerWidth - box.right,
        bottom: window.innerHeight - box.bottom,
        rtl: getComputedStyle(root).direction === 'rtl',
      });
    };
    const onLeave = () => setShown(null);
    root.addEventListener('mouseover', onOver);
    root.addEventListener('mouseleave', onLeave);
    return () => {
      root.removeEventListener('mouseover', onOver);
      root.removeEventListener('mouseleave', onLeave);
    };
  }, [rootRef]);

  if (!shown) return null;
  const width = window.innerWidth - shown.left - shown.right;
  return createPortal(
    // The pane's start corner: the bottom left, or the bottom right in a
    // right-to-left layout. Only the corner that faces into the pane is round.
    // The pill itself is always left to right (an address), so its classes
    // name physical sides.
    <div
      aria-hidden="true"
      dir="ltr"
      className={`pointer-events-none fixed z-50 truncate border-t border-divider bg-surface-2 px-2 py-0.5 text-[11px] leading-4 text-pn-muted [@media(hover:none)]:hidden ${shown.rtl ? 'border-l rounded-tl-md' : 'border-r rounded-tr-md'}`} // rtl-ok: physical sides of an always-LTR pill, chosen by the pane's direction
      style={{
        bottom: shown.bottom,
        maxWidth: Math.max(0, width * 0.75),
        ...(shown.rtl ? { right: shown.right } : { left: shown.left }), // rtl-ok: the pane's own start edge, measured
      }}
    >
      {shown.href}
    </div>,
    document.body,
  );
}
