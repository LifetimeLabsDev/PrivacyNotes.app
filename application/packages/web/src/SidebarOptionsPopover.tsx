import { useEffect, useRef, type RefObject } from 'react';
import { usePopoverPosition } from './usePopoverPosition';
import { useEscapeToClose } from './useEscapeToClose';
import { Check, type Icon } from './icons';
import type { View } from './views';
import { markdownSupport } from './markdownFolder/capability';
import { PILLAR_GLYPHS } from './icons';
import type { TFunction } from 'i18next';

export interface SidebarOption {
  /** The view this row switches. Also the React key. */
  key: View;
  label: string;
  icon: Icon;
  checked: boolean;
}

/**
 * The checkbox menu behind both sidebar option icons: the gear beside the
 * Views caption (which rows the rail draws) and the funnel in the All row
 * (which item types the All list holds). One component, two configurations -
 * they differ only in title and rows.
 *
 * Checkboxes rather than the ToggleRow switch the list popovers use: eight
 * switches in a 224px menu is a wall of accent colour, and this menu answers
 * "which of these do I want" rather than "is this feature on".
 *
 * Position is `fixed`, from usePopoverPosition, and that is load-bearing.
 * The Views block is `overflow-y-auto`, and CSS forces overflow-x to `auto`
 * alongside it, so the block clips on BOTH axes - an absolutely positioned
 * menu inside it is cut off at the rail's edge. The hook also re-measures
 * when the popover's own height changes, which happens here on every tick:
 * the rail behind it shortens as rows switch off.
 *
 * Spec: ops/docs/plans/sidebar-views.md
 */
export function SidebarOptionsPopover({
  title,
  options,
  anchorRef,
  onToggle,
  onClose,
}: {
  title: string;
  options: SidebarOption[];
  /** The icon button this menu hangs from; also excluded from outside-click. */
  anchorRef: RefObject<HTMLElement | null>;
  onToggle: (key: View) => void;
  onClose: () => void;
}) {
  const popoverRef = useRef<HTMLDivElement>(null);
  const pos = usePopoverPosition(true, anchorRef, popoverRef, { align: 'start', gap: 6 });

  useEscapeToClose(onClose, true);

  useEffect(() => {
    function handler(e: PointerEvent) {
      const target = e.target as Node | null;
      if (!target) return;
      if (popoverRef.current?.contains(target)) return;
      // The trigger toggles the menu itself; closing here too would reopen it.
      if (anchorRef.current?.contains(target)) return;
      onClose();
    }
    document.addEventListener('pointerdown', handler);
    return () => document.removeEventListener('pointerdown', handler);
  }, [anchorRef, onClose]);

  return (
    <div
      ref={popoverRef}
      role="dialog"
      aria-label={title}
      className="fixed z-[9999] w-56 rounded-lg border border-divider bg-surface-2 shadow-lg py-2"
      style={{
        top: pos?.top ?? 0,
        left: pos?.left ?? 0,
        visibility: pos ? 'visible' : 'hidden',
      }}
    >
      <div className="px-3 pb-1.5 text-[10px] font-semibold tracking-wider uppercase text-neutral-500 dark:text-neutral-400">
        {title}
      </div>
      {options.map((o) => (
        <button
          key={o.key}
          type="button"
          role="checkbox"
          aria-checked={o.checked}
          onClick={() => onToggle(o.key)}
          className="w-full flex items-center gap-2.5 px-3 py-1.5 text-[14px] text-pn hover:bg-neutral-100 dark:hover:bg-neutral-800 transition"
        >
          <o.icon size={16} className="shrink-0 text-accent" aria-hidden="true" />
          <span className="flex-1 min-w-0 text-start truncate">{o.label}</span>
          <ViewCheckBox checked={o.checked} />
        </button>
      ))}
    </div>
  );
}

/**
 * The rows both option surfaces offer, in sidebar order.
 *
 * 'home' is in neither list: All cannot be hidden (the collapsed rail's logo
 * goes there) and cannot be removed from itself. Markdown appears only where
 * the platform can open a folder, and never in the All list at all - those
 * files live on the user's disk and never enter the encrypted store.
 *
 * Takes a `t` bound to the SHELL namespace: the labels are the sidebar's own
 * strings, so a menu and the row beside it can never disagree in any language.
 * Spec: ops/docs/plans/sidebar-views.md
 */
export function sidebarViewRows(t: TFunction): SidebarRow[] {
  return [
    { key: 'starred', label: t('tagsRail.pinned'), icon: PILLAR_GLYPHS.pinned },
    { key: 'all', label: t('tagsRail.notes'), icon: PILLAR_GLYPHS.notes },
    { key: 'tasks', label: t('tagsRail.tasks'), icon: PILLAR_GLYPHS.tasks },
    { key: 'vault', label: t('tagsRail.vault'), icon: PILLAR_GLYPHS.vault },
    { key: 'files', label: t('tagsRail.files'), icon: PILLAR_GLYPHS.files },
    { key: 'journal', label: t('tagsRail.journals'), icon: PILLAR_GLYPHS.journals },
    ...(markdownSupport() !== 'unavailable'
      ? [{ key: 'markdown' as View, label: t('tagsRail.markdown'), icon: PILLAR_GLYPHS.markdown }]
      : []),
    { key: 'bookmarks', label: t('tagsRail.bookmarks'), icon: PILLAR_GLYPHS.bookmarks },
  ];
}

export type SidebarRow = { key: View; label: string; icon: SidebarOption['icon'] };

/** The rows that can be switched off in the All list. */
export function allViewRows(t: TFunction): SidebarRow[] {
  return sidebarViewRows(t).filter((r) => r.key !== 'starred' && r.key !== 'markdown');
}

/**
 * The 16px tick box, shared by the menus and the Appearance table so the two
 * cannot drift. Presentational only: the caller owns the button and the
 * `role="checkbox"` state, because the menu's whole row is the control while
 * the table's cell is only the box.
 */
export function ViewCheckBox({ checked }: { checked: boolean }) {
  return (
    <span
      aria-hidden="true"
      className={`shrink-0 w-4 h-4 rounded border inline-flex items-center justify-center transition ${
        checked ? 'bg-accent border-accent text-white' : 'border-neutral-300 dark:border-neutral-600'
      }`}
    >
      {checked && <Check size={11} weight="bold" />}
    </span>
  );
}
