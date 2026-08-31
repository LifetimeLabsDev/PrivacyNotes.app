import { createContext, useContext, useEffect, useRef, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { Plus } from '../icons';

/**
 * Context providing the DOM node where expanded pill content renders inline
 * (below the pill row). Set by TrackerPills.
 */
export const PillExpandContext = createContext<HTMLDivElement | null>(null);

/**
 * Shared pill chrome used by every tracker. Renders a compact button;
 * when expanded, the picker content portals into the PillExpandContext
 * container (rendered by TrackerPills below the pill row) so it appears
 * inline without floating/positioning issues.
 */
export function PillShell({
  label,
  color,
  filled,
  expanded,
  onToggle,
  filledLabel,
  icon,
  children,
  readOnly,
}: {
  label: string;
  color: string;
  filled: boolean;
  expanded: boolean;
  onToggle: () => void;
  filledLabel?: string;
  icon?: ReactNode;
  children?: ReactNode;
  readOnly?: boolean;
}) {
  const btnRef = useRef<HTMLButtonElement>(null);
  const contentRef = useRef<HTMLDivElement>(null);
  const expandTarget = useContext(PillExpandContext);

  // Close on outside click - pointerdown for reliable mobile support.
  useEffect(() => {
    if (!expanded) return;
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
  }, [expanded, onToggle]);

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
          disabled={readOnly}
          className={`inline-flex items-center gap-1 rounded-full px-2.5 py-1 text-xs font-medium transition-colors ${
            filled
              ? 'text-white'
              : 'border border-neutral-300 dark:border-neutral-700 text-neutral-500 dark:text-neutral-400 hover:border-neutral-400 dark:hover:border-neutral-500'
          } ${readOnly ? 'opacity-60 cursor-default' : 'cursor-pointer'}`}
          style={filled ? { backgroundColor: color } : undefined}
        >
          {filled && icon ? icon : !filled && (
            <Plus size={10} />
          )}
          {filled ? filledLabel ?? label : label}
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
