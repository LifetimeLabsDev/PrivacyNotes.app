import { createContext, useContext, useEffect, useRef, useState, type ReactNode, type Ref } from 'react';
import { createPortal } from 'react-dom';
import { HoverLabel } from './HoverLabel';
import { keyText } from './shortcutMatch';
import { Kbd } from './ui/misc';
import { CaretDown, PlusCircle } from './icons';

/**
 * Where a list's New button lives. On a phone it leaves the list header for
 * the end of the bottom bar, where a thumb reaches it; `slot` is the bar's
 * empty box for it, and null while the bar holds no New (an item is open, the
 * keyboard is up). Wider screens keep the button in the header.
 * Spec: ops/docs/archive/ui-patterns.md section 137
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
  keys,
  onClick,
  buttonRef,
  wrapRef,
  popup,
  expanded,
  tabIndex,
  children,
}: {
  label: string;
  /** The shortcut that does the same, for the tip. */
  keys?: string;
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
      <HoverLabel label={label} keys={keys} position={docked ? 'above-end' : 'below-end'}>
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

/** One entry in a "New" dropdown menu. */
export type NewMenuOption = {
  key: string;
  label: string;
  icon: React.ReactNode;
  onSelect: () => void;
  /** The key that runs it, drawn at the row's end. */
  keys?: string;
};

/* ── Shared "New" dropdown ──────────────────────────────────────────
 * One menu, reused by the Vault view (login / card / ssh-key), the All
 * view (every type) and the Tasks view (task list / Kanban board) so they can't drift in
 * style or behaviour. Callers pass fully-built, already-translated options;
 * the button label ("New") is the only string this component owns. */
export function NewDropdown({ options, label }: { options: NewMenuOption[]; label: string }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const { docked, slot } = useContext(NewButtonDock);
  // The bar's slot comes and goes with an open item; a menu left open would
  // greet the person on the way back.
  useEffect(() => setOpen(false), [slot]);

  useEffect(() => {
    if (!open) return;
    const handler = (e: PointerEvent | MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    // Use pointerdown for reliable mobile touch support; fall back to
    // mousedown for environments where PointerEvent isn't available.
    const evt = typeof PointerEvent !== 'undefined' ? 'pointerdown' : 'mousedown';
    document.addEventListener(evt, handler as EventListener);
    return () => document.removeEventListener(evt, handler as EventListener);
  }, [open]);

  return (
    // Spec: ops/docs/archive/ui-patterns.md section 45 (z-index tier system - the
    // NewButton wrapper must not create a z-20 stacking context, or it traps the
    // MobileHeader's z-50 pillar dropdown beneath it in the Vault view).
    <NewButton
      wrapRef={ref}
      onClick={() => setOpen(!open)}
      label={label}
      keys={keyText('newMenu')}
      popup="menu"
      expanded={open}
    >
      {/*
        `w-max` on the menu below is load-bearing, not decoration. The menu is
        absolutely positioned inside a `relative` wrapper that is only as wide as
        the "New" button, and an auto-width absolute box with `end-0` and no
        `start` shrink-to-fits against its CONTAINING BLOCK, not the viewport. So
        the menu was capped at the button's ~110px and every label longer than
        that wrapped onto two lines. English never showed it ("Credit Card", 11
        chars, fits); es "Tarjeta de credito" (18), pt "Cartao de Credito" (17),
        ca (17), it (16), pl (15), fr (14) and cs (18) all wrapped, and had done
        since each locale shipped. `w-max` opts out of the containing-block cap;
        `max-w` keeps a pathological string from running off a narrow viewport;
        `whitespace-nowrap` on the rows stops a two-word label breaking anyway.
        Spec: ops/docs/archive/ui-patterns.md section 45.
      */}
      {open && (
        <div role="menu" className={`absolute end-0 ${docked ? 'bottom-full mb-2' : 'top-full mt-1'} z-50 w-max max-w-[calc(100vw-1.5rem)] bg-surface-2 border border-divider rounded-lg shadow-lg py-1`}>
          {options.map(({ key, label, icon, onSelect, keys }) => (
            <button
              key={key}
              type="button"
              role="menuitem"
              onClick={() => { onSelect(); setOpen(false); }}
              className="w-full flex items-center gap-2.5 px-3 py-2 text-sm text-start whitespace-nowrap text-pn-soft hover:bg-pn/5 transition cursor-pointer"
            >
              {/* Accent, like every other menu that lists things to go to or
                  make: the rail rows, the sidebar option menus and the view
                  picker. Grey here made this the one menu whose glyphs read as
                  decoration. The colour lives on the row rather than in
                  NEW_GLYPHS, because the same glyphs are also drawn inside the
                  New button itself, where they sit on an accent-tinted pill. */}
              <span className="text-accent">{icon}</span>
              {label}
              {keys && <span className="ms-auto ps-4"><Kbd>{keys}</Kbd></span>}
            </button>
          ))}
        </div>
      )}
    </NewButton>
  );
}
