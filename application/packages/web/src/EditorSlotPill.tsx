import type { ReactNode } from 'react';

/**
 * A control in the editor's top-right slot, the strip that floats over the
 * note body under the toolbar: find, the text switch, invisible characters,
 * and the outline.
 *
 * The shape is the collapsed outline pill's, which was the slot's first and
 * only inhabitant and set its rules. Two of those rules matter and neither
 * is obvious:
 *
 * It carries a border, a surface and a shadow where the header rows carry
 * none, because this one sits over the note's own text and has to stay
 * legible against whatever is under it.
 *
 * It names itself with a label that slides out on hover, not with a
 * `HoverLabel` tip. A tip here would hang over the note text a reader has
 * not reached for, and the slot's own zero-height sticky wrapper is a poor
 * host for one. The label is inside the pill, so it pushes rather than
 * covers.
 * Spec: ops/docs/ui-patterns.md (section 80)
 */
export function EditorSlotPill({
  label,
  onClick,
  active,
  tabIndex,
  children,
}: {
  label: string;
  onClick: () => void;
  /**
   * Toggled on, for a control whose glyph cannot say so itself. The
   * invisible-characters pill is the case: one glyph, two states. A control
   * that CHANGES glyph with its state - the rich/markdown switch - leaves
   * this alone, or it reads as a different kind of button beside its
   * neighbours rather than as the same button in another state.
   */
  active?: boolean;
  tabIndex?: number;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      tabIndex={tabIndex}
      onMouseDown={(e) => e.preventDefault()}
      onClick={onClick}
      aria-label={label}
      aria-pressed={active}
      className={`group pointer-events-auto mt-1 flex items-center h-8 overflow-hidden rounded-lg border shadow-lg text-sm active:scale-95 transition outline-none ${
        // The ON state keeps the same OPAQUE surface as the off state and
        // says so with the border and the glyph. The tinted `bg-accent/10`
        // the bordered toggles elsewhere use is translucent, and elsewhere
        // it sits on a pane; here it sits on the note's own text, which
        // read straight through it.
        active
          ? 'border-accent/60 bg-surface-1 text-accent'
          : 'border-divider bg-surface-1 text-neutral-600 dark:text-neutral-300 [@media(hover:hover)]:hover:bg-neutral-200 [@media(hover:hover)]:dark:hover:bg-neutral-800'
      }`}
    >
      {/* Label hidden by default; slides out on hover so it never sits over
          the note text unless the user is reaching for it. Icon stays put.

          The open cap is deliberately far larger than any label needs. It
          is a CAP, not a width: the span is nowrap, so it renders at the
          label's own width and the number only stops a runaway. The pill
          was built at 7rem for the word "Outline" and clipped "Show
          invisible characters" the moment the slot gained neighbours, and
          German and Turkish are longer again. The vw half keeps a long
          label inside a narrow pane; hover only exists on pointer devices,
          so no phone ever expands one. A grid 0fr-to-1fr animation was
          tried first and collapses here: `overflow-hidden` zeroes the
          track's min-content contribution, so 1fr resolves to free space
          rather than to the label. */}
      <span className="max-w-0 overflow-hidden whitespace-nowrap [@media(hover:hover)]:group-hover:max-w-[min(60vw,20rem)] transition-[max-width] duration-150 ease-out">
        <span className="ps-2.5 pe-1">{label}</span>
      </span>
      <span className="flex h-8 w-8 items-center justify-center shrink-0">
        {children}
      </span>
    </button>
  );
}
