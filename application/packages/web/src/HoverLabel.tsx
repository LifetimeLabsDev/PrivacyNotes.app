import type { PointerEvent, ReactNode } from 'react';

// Spec: ops/docs/archive/ui-patterns.md (section 18 - instant CSS hover labels)

/*
 * `position` names say WHERE THE TIP LANDS. `above` puts it above the element,
 * `below` below it, `start` before it and `end` after it (both mirror under
 * RTL, which is the desired behavior for a side tip).
 *
 * The `Position` union makes a wrong name a build error.
 *
 * Where a tip lands is decided twice. The class from this map gives its
 * place beside the element; then, as the tip gets a box, `fitTip` measures
 * the tip against every box that would cut it (each ancestor that clips an
 * axis, and the window) and moves it back inside: sideways when it would
 * hang past an edge, to the other side when there is no room above or below.
 * So a button at the end of a clipping row, or one a person moved there on
 * the format bar, needs no rule of its own. A tip that is not showing has no
 * box (`.pn-tip-host` in index.css), so a tip hanging past an edge cannot
 * make a clipping scroller scroll sideways either.
 *
 * Adding a new entry here is for a genuinely new geometry only.
 *
 * Full decision order: ops/docs/archive/ui-patterns.md section 18.
 */
export const positionClasses = {
  end: 'start-full top-1/2 -translate-y-1/2 ms-2',
  start: 'end-full top-1/2 -translate-y-1/2 me-2',
  above: 'bottom-full left-1/2 -translate-x-1/2 mb-2',
  below: 'top-full left-1/2 -translate-x-1/2 mt-2',
  'below-end': 'top-full end-0 mt-2',
  // The start-aligned twin, for a control at the START of a pane: a centered
  // tip under it hangs half its width back over whatever pane sits before this
  // one (the editor's close button over the notes list), which reads as a tip
  // belonging to the wrong column rather than as a clipped one.
  'below-start': 'top-full start-0 mt-2',
  // Edge-aligned variants for elements near a viewport corner, where the
  // centered 'above' tip would clip off-screen: 'above-start' keeps its start
  // edge on the element (start corner of the screen), 'above-end' its end edge.
  'above-start': 'bottom-full start-0 mb-2',
  'above-end': 'bottom-full end-0 mb-2',
} as const;

type Position = keyof typeof positionClasses;

/**
 * The look every tip pill wears: its box, its colour, its type size.
 *
 * A tip only ever shows on hover, so on touch it is display:none rather
 * than merely transparent: a transparent tip still has a box, and a box
 * hanging past the screen edge widened the phone shell, after which typing
 * in a field scrolled the whole app sideways.
 */
/** The look of every tooltip, shared by the fixed tips (OverflowTip, the
 *  list options help) so that one line changes them all. */
export const TIP_SKIN =
  // theme-ok: a tooltip is a dark pill in every theme
  'px-2 py-[3px] rounded-[5px] bg-neutral-900 dark:bg-neutral-800 border border-neutral-800 dark:border-neutral-700 text-[12px] leading-4 text-neutral-100';

const TIP_PILL_LOOK = `pn-tip pointer-events-none ${TIP_SKIN} z-50 [@media(hover:none)]:hidden`;

/**
 * The hover tip: the pill above, placed absolutely against its `group/tip`
 * wrapper and revealed by hovering it. Exported for the one tip built
 * outside React, the code block's wrap toggle (a node view is plain DOM).
 */
export const TIP_PILL =
  `${TIP_PILL_LOOK} absolute opacity-0 [@media(hover:hover)]:group-hover/tip:opacity-100 transition-opacity duration-75`;

/** The visible part of the window around `el`: the window cut down by every
 *  ancestor that clips an axis. A fixed ancestor ends the walk, because what
 *  sits above it in the tree cannot clip it. */
export function visibleBox(el: HTMLElement) {
  let left = 0, top = 0, right = window.innerWidth, bottom = window.innerHeight;
  for (let a = el.parentElement; a; a = a.parentElement) {
    const cs = getComputedStyle(a);
    const clipX = cs.overflowX !== 'visible';
    const clipY = cs.overflowY !== 'visible';
    if (clipX || clipY) {
      const r = a.getBoundingClientRect();
      const l = r.left + a.clientLeft;
      const tp = r.top + a.clientTop;
      if (clipX) { left = Math.max(left, l); right = Math.min(right, l + a.clientWidth); }
      if (clipY) { top = Math.max(top, tp); bottom = Math.min(bottom, tp + a.clientHeight); }
    }
    if (cs.position === 'fixed') break;
  }
  return { left, top, right, bottom };
}

const EDGE = 4;
const PLACED = ['left', 'right', 'top', 'bottom', 'translate', 'transform', 'margin-top', 'margin-bottom'];

/**
 * Moves a showing tip that sits above or below `host` back inside the
 * visible box: sideways first, then to the other side of the host when it
 * does not fit vertically and the other side does.
 */
function fitTip(tip: HTMLElement, host: HTMLElement) {
  const s = tip.style;
  for (const p of PLACED) s.removeProperty(p);
  const t = tip.getBoundingClientRect();
  if (t.width === 0) return;
  const h = host.getBoundingClientRect();
  // A side tip (start, end) keeps its place.
  if (t.right <= h.left + 1 || t.left >= h.right - 1) return;
  const box = visibleBox(host);
  // A tip that hangs past an edge lines up with its own button's edge on that
  // side first, the way an end-aligned tip ("Note options") reads; only a tip
  // too wide for that is pushed to the edge of the visible box.
  let left = t.left;
  if (t.right > box.right - EDGE) left = h.right - t.width;
  else if (t.left < box.left + EDGE) left = h.left;
  if (left + t.width > box.right) left = box.right - EDGE - t.width;
  if (left < box.left) left = box.left + EDGE;
  if (Math.abs(left - t.left) > 0.5) {
    s.left = `${left - h.left}px`;
    s.right = 'auto';
    s.translate = 'none';
    s.transform = 'none';
  }
  const below = t.top >= h.bottom - 1;
  const gap = below ? t.top - h.bottom : h.top - t.bottom;
  if (below && t.bottom > box.bottom - EDGE && h.top - gap - t.height >= box.top + EDGE) {
    s.top = 'auto';
    s.bottom = `calc(100% + ${gap}px)`;
    s.marginTop = '0';
  } else if (!below && t.top < box.top + EDGE && h.bottom + gap + t.height <= box.bottom - EDGE) {
    s.bottom = 'auto';
    s.top = `calc(100% + ${gap}px)`;
    s.marginBottom = '0';
  }
}

/**
 * Fits a tip the moment it gets a box, whatever showed it. A tip shows on
 * `:hover`, and `:hover` is not an event: a button that appears under a
 * pointer that does not move (the view switch at the end of the format bar
 * swaps itself for its twin) matches `:hover` with no `pointerenter` in some
 * browsers, and a browser can fire `pointerenter` before the tip has a box.
 * A size change is what every one of those has in common: the tip goes from
 * `display: none` to its own width. One observer serves every tip. Moving a
 * tip does not resize it, so the fit never triggers itself.
 */
const tipObserver = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver((entries) => {
  for (const entry of entries) {
    const tip = entry.target as HTMLElement;
    if (entry.contentRect.width > 0 && tip.parentElement) fitTip(tip, tip.parentElement);
  }
});

function observeTip(tip: HTMLElement | null) {
  if (!tip || !tipObserver) return;
  tipObserver.observe(tip);
  return () => tipObserver.unobserve(tip);
}

/** A host that moved while its tip was hidden: fit again on entry. */
function placeTip(e: PointerEvent<HTMLElement>) {
  if (e.pointerType === 'touch') return;
  const tip = e.currentTarget.querySelector<HTMLElement>(':scope > .pn-tip');
  if (tip) fitTip(tip, e.currentTarget);
}

/** CSS-only instant hover label. Replaces native title="" attributes. */
export function HoverLabel({
  label,
  keys,
  count,
  pro = false,
  position = 'end',
  multiline = false,
  disabled = false,
  hiddenAtXl = false,
  hiddenAtSm = false,
  inline = false,
  className,
  children,
}: {
  label: string;
  /** The shortcut that does the same, shown after the label in the one
   *  tooltip key format (`keyText` in shortcutMatch.ts). Empty shows none,
   *  so a key this app or OS lacks needs no branch at the call site. */
  keys?: string;
  count?: number;
  /** Adds a gold "· Pro" after the label, for a control that opens the
   *  upgrade window. */
  pro?: boolean;
  position?: Position;
  /** Wrap long labels (max ~280px) instead of forcing a single nowrap line. */
  multiline?: boolean;
  /** Suppress the tip (keeps the wrapper) - for conditional tooltips. */
  disabled?: boolean;
  /**
   * Hide the tip from `xl` up, for triggers that reveal their own text
   * label at that width (`hidden xl:inline`). Below xl the button is
   * icon-only and the tip is the only thing naming it; at xl the word is
   * right there and the tip is just noise. Pure CSS, so it tracks a
   * window resize with no listener.
   */
  hiddenAtXl?: boolean;
  /**
   * Same idea as `hiddenAtXl`, one breakpoint down: for triggers that
   * reveal their own text label at `sm` (`hidden sm:inline`). Below sm
   * the button is icon-only and the tip names it; from sm up the word
   * is on the button and the tip only repeats it.
   */
  hiddenAtSm?: boolean;
  /** Render span wrappers so the label can sit inside inline text flow
      (e.g. the note-link node view) without forcing a line break. The tip
      itself is position:absolute, which blockifies it regardless of tag. */
  inline?: boolean;
  className?: string;
  children: ReactNode;
}) {
  const Wrapper = inline ? 'span' : 'div';
  return (
    <Wrapper
      className={`pn-tip-host relative group/tip${inline ? ' inline' : ''}${className ? ` ${className}` : ''}`}
      onPointerEnter={disabled ? undefined : placeTip}
    >
      {children}
      {!disabled && <Wrapper
        ref={observeTip}
        className={`${TIP_PILL}${hiddenAtXl ? ' xl:hidden' : ''}${hiddenAtSm ? ' sm:hidden' : ''} ${positionClasses[position]} ${multiline ? 'block w-[260px] whitespace-normal text-center' : 'flex items-center gap-2 whitespace-nowrap'}`}
      >
        <span>{label}</span>
        {/* rtl-ok: a key sequence never reorders */}
        {keys && <span dir="ltr" /* theme-ok: on the dark tooltip pill */ className={`text-neutral-400${multiline ? ' ms-2' : ''}`}>{keys}</span>}
        {count != null && <span /* theme-ok: on the dark tooltip pill */ className="text-neutral-400 tabular-nums">{count}</span>}
        {/* Gold in every theme: the pill is dark in every theme, and the
            theme's own Pro colour is bronze on a light one. */}
        {pro && <span /* theme-ok: on the dark tooltip pill */ className="-ms-1 font-semibold text-amber-300">· Pro</span>}
      </Wrapper>}
    </Wrapper>
  );
}
