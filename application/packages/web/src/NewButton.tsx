import { createContext, useContext, type ReactNode, type Ref } from 'react';
import { createPortal } from 'react-dom';
import { HoverLabel } from './HoverLabel';
import { CaretDown, PlusCircle } from './icons';

/**
 * Where a list's New button lives. On a phone it leaves the list header for
 * the end of the bottom bar, where a thumb reaches it; `slot` is the bar's
 * empty box for it, and null while the bar holds no New (an item is open, the
 * keyboard is up). Wider screens keep the button in the header.
 * Spec: ops/docs/ui-patterns.md section 137
 */
export const NewButtonDock = createContext<{ docked: boolean; slot: HTMLElement | null }>({ docked: false, slot: null });

// No word in either home, so no locale has to squeeze its "New" into the
// header. In the header a filled square, 36px like the view picker and the
// quick switcher beside it. In the bar a solid plus with no box, so it sits
// among the bar's plain icons with a little more weight than they have; its
// 44px box is the smallest touch target either phone platform recommends.
// The two never show at once.
const HEADER_LOOK = 'inline-flex h-9 items-center justify-center rounded-lg bg-accent-fill hover:bg-accent-fill-hover active:scale-95 text-white transition cursor-pointer';
const DOCKED_LOOK = 'inline-flex h-11 w-11 items-center justify-center rounded-lg text-accent hover:bg-pn/5 active:bg-pn/10 transition cursor-pointer';

/** The New button of every list pane. `label` names it for screen readers and the tip. */
export function NewButton({
  label,
  hover,
  onClick,
  buttonRef,
  wrapRef,
  popup,
  expanded,
  tabIndex,
  children,
}: {
  label: string;
  /** A longer tip, such as one that carries the hotkey. */
  hover?: string;
  onClick: () => void;
  buttonRef?: Ref<HTMLButtonElement>;
  /** The box that holds the button and its menu, for an outside-click test. */
  wrapRef?: Ref<HTMLDivElement>;
  popup?: 'menu' | 'dialog';
  expanded?: boolean;
  tabIndex?: number;
  /** A menu or popover hung off the button. */
  children?: ReactNode;
}) {
  const { docked, slot } = useContext(NewButtonDock);
  if (docked && !slot) return null;
  const body = (
    <div ref={wrapRef} className="relative shrink-0">
      <HoverLabel label={hover ?? label} position={docked ? 'above-end' : 'below-end'}>
        <button
          ref={buttonRef}
          type="button"
          onClick={onClick}
          aria-label={label}
          aria-haspopup={popup}
          aria-expanded={popup ? expanded : undefined}
          tabIndex={tabIndex}
          className={docked ? DOCKED_LOOK : `${HEADER_LOOK} ${popup ? 'gap-1 px-2' : 'w-9'}`}
        >
          {docked ? <PlusCircle size={32} weight="fill" /> : <PlusCircle size={22} weight="bold" />}
          {/* In the header a caret marks the buttons that open a menu or a
              calendar. The bar's button stays a plain square: it is the one
              action at the end of the bar, and its menu opens on the tap. */}
          {popup && !docked && <CaretDown size={12} weight="bold" />}
        </button>
      </HoverLabel>
      {children}
    </div>
  );
  return docked && slot ? createPortal(body, slot) : body;
}
