import { useRef, useState, type ReactNode, type Ref } from 'react';
import { CaretDown, CaretLeft } from '../icons';
import { Button, IconButton } from './Button';
import { Popover } from './misc';

/**
 * @catalog GlyphTile
 * use: the square tile tinted in an item's color with its glyph, in a picker row or the button that opens one (a tracker, a medication).
 * never: a tinted square of your own; the 36px bordered row tile (`MarkTile`) at picker size.
 */
export function GlyphTile({ color, size, children }: { color?: string; size: number; children?: ReactNode }) {
  const tint = color ?? 'var(--color-pn-muted)';
  return (
    <span
      aria-hidden="true"
      className="inline-flex shrink-0 items-center justify-center rounded-md"
      style={{ width: size, height: size, color: tint, backgroundColor: `color-mix(in srgb, ${tint} 14%, transparent)` }}
    >
      {children ?? <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: tint }} />}
    </span>
  );
}

export type SwitcherItem = {
  id: string;
  name: string;
  /** The item's tile at the size asked for: small on the button, larger in the list. */
  tile: (size: number) => ReactNode;
  /** A short value at the row's end; it gives way before the name does. */
  detail?: ReactNode;
};

/**
 * @catalog SubViewHeader, ItemSwitcher
 * use: the top of a sub-view that shows one item of a list (a tracker's statistics, a tracker's edit page): the back caret, then `ItemSwitcher`, the item's name as a button that opens its siblings, so a person moves to the next item without going back.
 * never: a `BackRow` with the item's name as plain text over a page of one item; a select of your own for the siblings.
 */
export function SubViewHeader({ backLabel, onBack, anchorRef, children }: {
  /** Where the caret goes, for its tooltip. */
  backLabel: string;
  onBack: () => void;
  /** The view's top, for a scroll to it when the view opens. */
  anchorRef?: Ref<HTMLDivElement>;
  children: ReactNode;
}) {
  // The pane's own heading already names the place, so the back row is one compact line.
  return (
    <div ref={anchorRef} className="-mt-2 flex items-center gap-2 scroll-mt-6">
      <IconButton label={backLabel} onClick={onBack}><CaretLeft size={16} aria-hidden="true" /></IconButton>
      {children}
    </div>
  );
}

/** Up and down arrows on the button step to the neighbours. */
export function ItemSwitcher({ items, currentId, label, onPick }: {
  items: SwitcherItem[];
  currentId: string;
  /** Names the list, for a screen reader. */
  label: string;
  onPick: (id: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const anchor = useRef<HTMLSpanElement>(null);
  const at = items.findIndex((x) => x.id === currentId);
  const current = items[at];
  if (!current) return null;
  const step = (by: number) => {
    const next = items[at + by];
    if (next) onPick(next.id);
  };
  return (
    <>
      <span ref={anchor} className="inline-flex min-w-0">
      <Button
        icon={current.tile(20)}
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        onKeyDown={(e) => {
          if (e.key === 'ArrowDown') { e.preventDefault(); step(1); }
          if (e.key === 'ArrowUp') { e.preventDefault(); step(-1); }
        }}
      >
        <span className="truncate">{current.name}</span>
        <CaretDown size={12} aria-hidden="true" className="shrink-0 text-pn-muted" />
      </Button>
      </span>
      <Popover open={open} anchorRef={anchor} onClose={() => setOpen(false)} className="w-80">
        <div role="listbox" aria-label={label} className="max-h-80 overflow-y-auto py-1">
          {items.map((x) => (
            <button
              key={x.id}
              type="button"
              role="option"
              aria-selected={x.id === currentId}
              onClick={() => { setOpen(false); onPick(x.id); }}
              className={`w-full flex items-center gap-2.5 rounded-md px-2 py-1.5 text-start text-sm ${x.id === currentId ? 'bg-accent/10 text-accent-strong' : 'text-pn hover:bg-pn/5'}`}
            >
              {x.tile(22)}
              {/* The name always shows in full; a long value (a set of emotions) is the part that gives way. */}
              <span className="shrink-0 whitespace-nowrap">{x.name}</span>
              {x.detail != null && <span className="flex-1 min-w-0 truncate text-end text-xs text-pn-muted tabular-nums">{x.detail}</span>}
            </button>
          ))}
        </div>
      </Popover>
    </>
  );
}
