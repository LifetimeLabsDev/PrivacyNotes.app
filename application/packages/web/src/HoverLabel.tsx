import type { ReactNode } from 'react';

// Spec: ops/docs/ui-patterns.md (section 18 - instant CSS hover labels)

/*
 * `position` names say WHERE THE TIP LANDS. `above` puts it above the element,
 * `below` below it, `start` before it and `end` after it (both mirror under
 * RTL, which is the desired behavior for a side tip).
 *
 * They did not always. Until v0.400.0 these were named for the CSS class they
 * set rather than the result - `bottom` meant `bottom-full`, which renders the
 * tip ABOVE - so every name meant its opposite. That was documented here at
 * length and still caught people repeatedly, including one tip "fixed" in the
 * wrong direction more than once (GitHub #206). A warning that has to be read
 * and remembered is the weakest tool available; the names now carry the meaning
 * themselves, and the `Position` union makes a wrong one a build error.
 *
 * STILL TRUE, AND THE MORE COMMON PROBLEM: A CLIPPED TIP IS USUALLY NOT THIS
 * FILE'S PROBLEM. A tip is cut by any ancestor that clips on the axis it
 * overhangs, and the default centered tip overhangs BOTH sides. If the element
 * sits at the end of a row that clips (the editor's `.pn-format-row`, the rail,
 * a scroller), the fix is a CSS rule on the ROW that edge-aligns its
 * `:first-child` / `:last-child` tips, NOT a new position on one button. Which
 * child is at the end moves with the window, so a per-button prop cannot
 * express it and will look right at one width and wrong at another. Those rules
 * live in `index.css` next to the row they belong to.
 *
 * Adding a new entry here is for a genuinely new geometry only. Confirm the tip
 * is clipped by the VIEWPORT rather than by a clipping ancestor: only the
 * former is this map's job.
 *
 * Full decision order: ops/docs/ui-patterns.md section 18.
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
 * The pill every tip wears. Exported for the one tip built outside React,
 * the code block's wrap toggle (a node view is plain DOM), so the two cannot
 * drift apart. A tip only ever shows on hover, so on touch it is
 * display:none rather than merely transparent: a transparent tip still has
 * a box, and a box hanging past the screen edge widened the phone shell,
 * after which typing in a field scrolled the whole app sideways.
 */
export const TIP_PILL =
  'pn-tip pointer-events-none absolute px-2.5 py-1.5 rounded-md bg-neutral-900 dark:bg-neutral-800 border border-neutral-700 dark:border-neutral-700 text-[12px] text-neutral-100 opacity-0 [@media(hover:hover)]:group-hover/tip:opacity-100 transition-opacity duration-75 z-50 [@media(hover:none)]:hidden';

/** CSS-only instant hover label. Replaces native title="" attributes. */
export function HoverLabel({
  label,
  count,
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
  count?: number;
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
    <Wrapper className={`relative group/tip${inline ? ' inline' : ''}${className ? ` ${className}` : ''}`}>
      {children}
      {!disabled && <Wrapper
        className={`${TIP_PILL}${hiddenAtXl ? ' xl:hidden' : ''}${hiddenAtSm ? ' sm:hidden' : ''} ${positionClasses[position]} ${multiline ? 'block w-[260px] whitespace-normal leading-snug text-center' : 'flex items-center gap-2 whitespace-nowrap'}`}
      >
        <span>{label}</span>
        {count != null && <span className="text-neutral-400 tabular-nums">{count}</span>}
      </Wrapper>}
    </Wrapper>
  );
}
