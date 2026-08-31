import { useEffect, useRef, useState } from 'react';
import { useEscapeToClose } from '../useEscapeToClose';
import { useIsMobile } from '../useIsMobile';

// Spec: ops/docs/ui-patterns.md (section 38 - mobile drawer gestures)
/** Leftward travel on the open panel that dismisses it. */
const SWIPE_CLOSE_PX = 48;

/**
 * Mobile sidebar drawer - slides in from the left over a dimmed
 * backdrop. Owns Escape, backdrop tap, and swipe-left to dismiss; the
 * parent just flips `open`.
 *
 * Stays mounted below the lg breakpoint with the pose driven purely by
 * `open` (transform/opacity + delayed visibility). No mount animation
 * state, no rAF, no timers: correctness must not depend on frame
 * callbacks, which throttled/hidden webviews suspend entirely. The
 * delayed `visibility` transition keeps the exit slide visible, then
 * drops the closed drawer from the a11y tree and tab order. At lg+ it
 * renders null, so desktop never pays for a second tags-rail render.
 */
export function MobileDrawer({
  open,
  onClose,
  children,
}: {
  open: boolean;
  onClose: () => void;
  children: React.ReactNode;
}) {
  const isMobile = useIsMobile();
  useEscapeToClose(onClose, open && isMobile);
  const touchStart = useRef<{ x: number; y: number; id: number } | null>(null);

  // Remount children on every close: the always-mounted panel would
  // otherwise preserve transient child state across opens (an open
  // folder-actions menu, an inline rename), which the old conditional
  // mount wiped. Bumping on close keeps the exit slide intact and the
  // next open starts clean.
  const [epoch, setEpoch] = useState(0);
  useEffect(() => {
    if (!open) setEpoch((e) => e + 1);
  }, [open]);

  if (!isMobile) return null;
  return (
    // pointer-events-none so the full-viewport container never eats taps;
    // the backdrop and panel opt back in below.
    <div className="lg:hidden fixed inset-0 z-30 flex pointer-events-none" aria-hidden={!open}>
      <div
        className={`absolute inset-0 bg-black/50 backdrop-blur-sm ${
          open
            ? 'opacity-100 pointer-events-auto [transition:opacity_200ms_ease-out]'
            : 'opacity-0 invisible [transition:opacity_200ms_ease-out,visibility_0s_200ms]'
        }`}
        onClick={onClose}
      />
      {/* `relative` is required so the sidebar paints above the backdrop. */}
      <div
        className={`relative flex h-full w-72 bg-surface-0 shadow-2xl flex-col pointer-events-auto ${
          open
            ? 'translate-x-0 visible [transition:transform_200ms_ease-out]' // rtl-ok: identity transform, direction-neutral
            : '-translate-x-full rtl:translate-x-full invisible [transition:transform_200ms_ease-out,visibility_0s_200ms]'
        }`}
        onTouchStart={(e) => {
          const t = e.touches[0];
          if (t) touchStart.current = { x: t.clientX, y: t.clientY, id: t.identifier };
        }}
        onTouchMove={(e) => {
          const s = touchStart.current;
          if (!s) return;
          let t: React.Touch | undefined;
          for (let i = 0; i < e.changedTouches.length; i++) {
            const c = e.changedTouches[i];
            if (c && c.identifier === s.id) {
              t = c;
              break;
            }
          }
          if (!t) return;
          const dx = t.clientX - s.x;
          const dy = Math.abs(t.clientY - s.y);
          // Dominantly-horizontal leftward swipe closes; vertical
          // movement stays with the scrolling rail inside.
          if (dx <= -SWIPE_CLOSE_PX && -dx > dy) {
            touchStart.current = null;
            onClose();
          }
        }}
        onTouchEnd={() => {
          touchStart.current = null;
        }}
        onTouchCancel={() => {
          touchStart.current = null;
        }}
      >
        <div key={epoch} className="flex h-full w-full flex-col">
          {children}
        </div>
      </div>
    </div>
  );
}
