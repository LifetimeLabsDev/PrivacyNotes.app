import type { ReactNode, RefObject } from 'react';
import { HoverLabel } from './HoverLabel';
import { X } from './icons';

/** The collapsed pill's box in px: `w-8` plus its 1px border on each side,
 *  and `h-8` plus the `mt-1` above it. Keep in step with the classes below. */
export const SLOT_PILL_WIDTH = 34;
export const SLOT_PILL_HEIGHT = 36;

/** A count in a slot panel: in its header, or beside a group. */
export const SLOT_BADGE = 'rounded-full bg-pn/10 px-1.5 text-[11px] leading-4 tabular-nums text-pn-muted';

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
 * Spec: ops/docs/archive/ui-patterns.md (section 80)
 */
export function EditorSlotPill({
  label,
  keys,
  onClick,
  active,
  tabIndex,
  children,
}: {
  label: string;
  /** The shortcut that does the same, after the label, as a tooltip shows it. */
  keys?: string;
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
        // Every state keeps an OPAQUE surface: the pill sits on the note's
        // own text, which reads straight through a translucent tint such as
        // `bg-accent/10` or `bg-pn/10`. ON says so with the border and the
        // glyph; hover darkens the surface by mixing the text colour into it,
        // which stays solid.
        active
          ? 'border-accent/60 bg-surface-1 text-accent'
          : 'border-divider bg-surface-1 text-pn-soft [@media(hover:hover)]:hover:bg-[color-mix(in_srgb,var(--color-surface-1)_90%,var(--color-pn))]'
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
        {/* rtl-ok: a key sequence never reorders */}
        {keys && <span dir="ltr" className="ps-1 pe-1.5 text-pn-muted">{keys}</span>}
      </span>
      <span className="flex h-8 w-8 items-center justify-center shrink-0">
        {children}
      </span>
    </button>
  );
}

/** Row classes for a list inside `EditorSlotPanel`: an inset, rounded row. */
export const SLOT_PANEL_ROW =
  'flex w-full items-center gap-2 rounded-md py-1.5 text-start text-sm transition outline-none [@media(hover:hover)]:hover:bg-pn/5 focus-visible:bg-pn/10';

/**
 * An open panel in the editor's corner slot: the outline and the
 * Connections list. It stands where its pill was, under the same rules -
 * an opaque surface over the note text - and the two share one frame so the
 * corner never shows two looks. An open panel always goes last in the row,
 * into the corner, so the closed pills stay together to its left.
 * Spec: ops/docs/archive/ui-patterns.md (section 80)
 */
export function EditorSlotPanel({
  panelRef,
  label,
  icon,
  title,
  count,
  closeLabel,
  closeKeys,
  onClose,
  children,
}: {
  panelRef?: RefObject<HTMLElement | null>;
  /** The accessible name of the panel. */
  label: string;
  icon: ReactNode;
  title: string;
  /** Left out when the panel's groups carry their own counts. */
  count?: number;
  closeLabel: string;
  closeKeys?: string;
  onClose: () => void;
  children: ReactNode;
}) {
  return (
    <nav
      ref={panelRef as RefObject<HTMLElement>}
      aria-label={label}
      onKeyDown={(e) => {
        if (e.key === 'Escape') { e.preventDefault(); onClose(); }
      }}
      className="order-last pointer-events-auto mt-1 w-72 max-w-[75vw] flex flex-col overflow-hidden rounded-xl border border-divider bg-surface-1 shadow-lg"
    >
      <div className="flex items-center gap-2 ps-3 pe-1.5 py-1.5 border-b border-divider">
        <span className="flex shrink-0 text-accent">{icon}</span>
        <span className="text-sm font-semibold text-pn">{title}</span>
        {count !== undefined && <span className={SLOT_BADGE}>{count}</span>}
        <div className="flex-1" />
        <HoverLabel label={closeLabel} keys={closeKeys} position="start">
          <button
            type="button"
            onClick={onClose}
            aria-label={closeLabel}
            className="flex items-center justify-center w-6 h-6 rounded-md text-pn-muted [@media(hover:hover)]:hover:bg-pn/10 [@media(hover:hover)]:hover:text-pn active:scale-95 transition shrink-0 outline-none"
          >
            <X size={14} />
          </button>
        </HoverLabel>
      </div>
      <div className="p-1 overflow-y-auto max-h-[min(55vh,360px)]">{children}</div>
    </nav>
  );
}
