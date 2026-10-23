import { createContext, useContext, useEffect, useRef, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { Plus } from '../icons';

/**
 * Context providing the DOM node where expanded pill content renders inline
 * (below the pill row). Set by TrackerPills.
 */
export const PillExpandContext = createContext<HTMLDivElement | null>(null);

/** Whether a tap outside an open panel closes it. Off in the check-in card:
 *  there a pane resize, a dialog or a click elsewhere on the page closed the
 *  panel the person was filling in; the pills, Next and Done move on. */
export const PillCloseOutsideContext = createContext(true);

/**
 * Shared pill chrome used by every tracker. Renders a compact button;
 * when expanded, the picker content portals into the PillExpandContext
 * container (rendered by TrackerPills below the pill row) so it appears
 * inline without floating/positioning issues.
 *
 * The tag chip's shape (6 px corners), not a round pill, so the row reads
 * like the tags above it. Three looks, the same in the check-in card and in
 * the journal entry: an empty pill is a dashed outline with a plus, a logged pill is a soft success tint
 * with its tracker icon, the open pill is the accent. The tracker's own color
 * stays on the charts and the calendar dots, where it tells trackers apart;
 * on one row of logged pills it only shouted. `mark` replaces the icon on a
 * logged pill (the Mood pill's number chip).
 * Spec: ops/docs/archive/ui-patterns.md section 141
 */
export function PillShell({
  label,
  filled,
  expanded,
  onToggle,
  filledLabel,
  icon,
  mark,
  ariaLabel,
  children,
  readOnly,
}: {
  label: string;
  filled: boolean;
  expanded: boolean;
  onToggle: () => void;
  filledLabel?: string;
  icon?: ReactNode;
  mark?: ReactNode;
  /** What a screen reader hears for the button; the visible text otherwise. */
  ariaLabel?: string;
  children?: ReactNode;
  readOnly?: boolean;
}) {
  const btnRef = useRef<HTMLButtonElement>(null);
  const contentRef = useRef<HTMLDivElement>(null);
  const expandTarget = useContext(PillExpandContext);
  const closeOutside = useContext(PillCloseOutsideContext);

  // Close on outside click - pointerdown for reliable mobile support.
  useEffect(() => {
    if (!expanded || !closeOutside) return;
    function handler(e: PointerEvent) {
      const target = e.target as Node;
      if (
        btnRef.current && !btnRef.current.contains(target) &&
        contentRef.current && !contentRef.current.contains(target)
      ) {
        onToggle();
      }
    }
    document.addEventListener('pointerdown', handler);
    return () => document.removeEventListener('pointerdown', handler);
  }, [expanded, onToggle, closeOutside]);

  return (
    <>
      <div className="shrink-0">
        <button
          ref={btnRef}
          type="button"
          onPointerDown={(e) => {
            if (readOnly) return;
            e.preventDefault();
            e.stopPropagation();
            onToggle();
          }}
          // Enter and Space fire a click with no pointer before it (detail 0);
          // a pointer already toggled on pointerdown, so its click is ignored.
          onClick={(e) => {
            if (readOnly || e.detail !== 0) return;
            onToggle();
          }}
          aria-expanded={expanded}
          aria-label={ariaLabel}
          disabled={readOnly}
          className={`pn-pill inline-flex items-center gap-1.5 rounded-md border px-2 h-7 [@media(hover:none)]:h-8 text-[12px] font-medium transition-colors ${
            filled
              ? 'border-transparent bg-success/10 text-success'
              : expanded
                ? 'border-accent text-accent bg-accent/10'
                : 'border-dashed border-pn-muted/50 text-pn-muted hover:border-pn-muted hover:text-pn-soft'
          } ${filled && expanded ? 'ring-2 ring-accent ring-offset-1 ring-offset-surface-2' : ''} ${readOnly ? 'opacity-60 cursor-default' : 'cursor-pointer'}`}
        >
          {filled ? (mark ?? icon) : <Plus size={11} aria-hidden="true" />}
          <span className="truncate max-w-[200px]">{filled ? filledLabel ?? label : label}</span>
        </button>
      </div>
      {expanded && !readOnly && expandTarget && createPortal(
        <div
          ref={contentRef}
          className="px-4 sm:px-6 py-3 border-t border-divider"
          style={{ touchAction: 'manipulation' }}
          onPointerDown={(e) => e.stopPropagation()}
        >
          {children}
        </div>,
        expandTarget
      )}
    </>
  );
}

/**
 * Save a picker's in-progress value when the picker closes.
 *
 * A number pill committed only on Enter or the Save button, while
 * `PillShell` closes on any outside pointerdown - so a typed value was
 * discarded silently and the reopen reset the field as if nothing had
 * been entered. `onBlur` does NOT fix it: pointerdown closes the picker
 * and React unmounts the input before the browser dispatches blur.
 *
 * The cleanup of an effect that only runs while expanded does fire, and
 * it fires for every way out - outside click, Escape, a note switch, an
 * unmount. `commit` is read through a ref so the cleanup always sees the
 * latest draft rather than the closure from the render that opened it.
 */
export function useCommitOnCollapse(expanded: boolean, commit: () => void): void {
  const commitRef = useRef(commit);
  commitRef.current = commit;
  useEffect(() => {
    if (!expanded) return;
    return () => { commitRef.current(); };
  }, [expanded]);
}
