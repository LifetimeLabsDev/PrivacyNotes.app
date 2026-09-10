import { useEffect, useRef, type RefObject } from 'react';
import { usePopoverPosition } from './usePopoverPosition';
import { useEscapeToClose } from './useEscapeToClose';
import type { ViewRow } from './viewRows';
import type { View } from './views';

/**
 * The dropdown behind every "pick one view" control: the below-lg pillar
 * switcher hanging off a list title, and the Start in row in Appearance.
 *
 * Only the MENU is shared. Each caller keeps its own trigger, because the two
 * are genuinely different controls - one is a page heading with a caret, the
 * other a settings pill - and a variant prop would branch the whole button for
 * nothing gained.
 *
 * Position is `fixed`, from usePopoverPosition. Both hosts clip: the list
 * title sits in a row with its own overflow, and the settings pane scrolls.
 *
 * The glyphs are accent on every row, chosen and unchosen alike, which is the
 * rule the sidebar rows and the option menus already follow: blue means this
 * is structure. The chosen row is told apart by its tinted band and its accent
 * LABEL, so the icon is free to stay one colour.
 *
 * The sibling of this component is SidebarOptionsPopover, which shares the
 * skeleton and answers a different question - which of these do I want, many
 * at a time. They stay apart on purpose: merging them means a mode prop that
 * branches at every row and at the ARIA.
 * Spec: ops/docs/plans/start-view.md (one menu, two triggers)
 */
export function ViewMenu({
  rows,
  current,
  onPick,
  anchorRef,
  onClose,
  align = 'start',
}: {
  rows: ViewRow[];
  /** The row drawn as chosen. */
  current: View;
  onPick: (next: View) => void;
  /** The trigger this menu hangs from; also excluded from outside-click. */
  anchorRef: RefObject<HTMLElement | null>;
  onClose: () => void;
  align?: 'start' | 'end';
}) {
  const menuRef = useRef<HTMLDivElement>(null);
  const pos = usePopoverPosition(true, anchorRef, menuRef, { align, gap: 6 });

  useEscapeToClose(onClose, true);

  useEffect(() => {
    function handler(e: PointerEvent) {
      const target = e.target as Node | null;
      if (!target) return;
      if (menuRef.current?.contains(target)) return;
      // The trigger toggles the menu itself; closing here too would reopen it.
      if (anchorRef.current?.contains(target)) return;
      onClose();
    }
    document.addEventListener('pointerdown', handler);
    return () => document.removeEventListener('pointerdown', handler);
  }, [anchorRef, onClose]);

  return (
    <div
      ref={menuRef}
      role="menu"
      className="fixed bg-surface-2 border border-divider rounded-xl shadow-lg py-1 min-w-[140px] z-[9999]"
      style={{
        top: pos?.top ?? 0,
        left: pos?.left ?? 0,
        visibility: pos ? 'visible' : 'hidden',
      }}
    >
      {rows.map((r) => (
        <button
          key={r.key}
          type="button"
          role="menuitemradio"
          aria-checked={current === r.key}
          onClick={() => { onPick(r.key); onClose(); }}
          className={`flex items-center gap-2 w-full px-3 py-2 text-sm transition-colors ${
            current === r.key
              ? 'text-accent bg-accent/10'
              : 'text-neutral-600 dark:text-neutral-400 hover:bg-neutral-100 dark:hover:bg-neutral-800'
          }`}
        >
          <r.icon size={16} className="shrink-0 text-accent" aria-hidden="true" />
          {r.label}
        </button>
      ))}
    </div>
  );
}
