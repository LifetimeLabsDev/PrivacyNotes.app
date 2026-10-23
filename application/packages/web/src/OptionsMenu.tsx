/**
 * The frame and rows of an options menu: the note's "..." menu and a Kanban
 * board's menu draw through here, so both open, move, step back and look
 * the same. The frame is a dropdown at its "..." button that stays on
 * screen, closes on a click outside, steps back from a second view on
 * Escape before it closes, and moves between rows with the arrow keys.
 * Spec: ops/docs/archive/ui-patterns.md section 15
 */

import { useEffect, useRef, type ReactNode, type RefObject } from 'react';
import { createPortal } from 'react-dom';
import { useEscapeToClose } from './useEscapeToClose';
import { usePopoverPosition } from './usePopoverPosition';
import { CaretRight } from './icons';

export function OptionsMenu({
  anchorRef,
  label,
  view,
  onClose,
  onEscape,
  className = 'w-80',
  children,
}: {
  anchorRef: RefObject<HTMLElement | null>;
  label: string;
  /** The open view; focus moves into the menu each time it changes. */
  view: string;
  onClose: () => void;
  /** Escape: steps back from a second view, or closes. Defaults to close. */
  onEscape?: () => void;
  /** The menu's width. */
  className?: string;
  children: ReactNode;
}) {
  useEscapeToClose(onEscape ?? onClose);
  const ref = useRef<HTMLDivElement | null>(null);
  // Right-aligned dropdown under the "..." button. The hook measures the menu
  // (which changes height as items toggle) and keeps it on-screen, flipping
  // above when there's no room below.
  const pos = usePopoverPosition(true, anchorRef, ref, { align: 'end' });

  // Close on outside pointerdown. Anchor clicks are ignored so the
  // "..." button can toggle without a re-open flicker.
  useEffect(() => {
    function handler(e: PointerEvent) {
      const target = e.target as Node | null;
      if (!target) return;
      if (ref.current && ref.current.contains(target)) return;
      if (anchorRef.current && anchorRef.current.contains(target)) return;
      onClose();
    }
    window.addEventListener('pointerdown', handler, true);
    return () => window.removeEventListener('pointerdown', handler, true);
  }, [onClose, anchorRef]);

  // Focus moves into the menu on open and on every view change, so the
  // arrow keys below have somewhere to start. The container takes it, not
  // the first row, so a mouse user sees no ring.
  useEffect(() => {
    ref.current?.focus({ preventScroll: true });
  }, [view]);

  function onKeyDown(e: React.KeyboardEvent) {
    if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(e.key)) return;
    const items = Array.from(
      ref.current?.querySelectorAll<HTMLButtonElement>('button:not([disabled])') ?? [],
    );
    if (items.length === 0) return;
    e.preventDefault();
    const i = items.indexOf(document.activeElement as HTMLButtonElement);
    const next =
      e.key === 'Home' ? 0
        : e.key === 'End' ? items.length - 1
          : e.key === 'ArrowDown' ? (i + 1) % items.length
            : i <= 0 ? items.length - 1 : i - 1;
    items[next]?.focus();
  }


  return createPortal(
    <div
      ref={ref}
      role="dialog"
      tabIndex={-1}
      aria-label={label}
      onKeyDown={onKeyDown}
      className={`fixed z-50 ${className} max-w-[calc(100vw-16px)] max-h-[calc(100dvh-16px)] overflow-y-auto overscroll-contain rounded-xl border border-divider bg-surface-2 shadow-lg outline-none divide-y divide-divider`}
      style={{
        top: pos?.top ?? 0,
        left: pos?.left ?? 0,
        visibility: pos ? 'visible' : 'hidden',
      }}
    >
      {children}
    </div>,
    document.body,
  );
}

/**
 * Colour of an item's icon. Blue is the standard; burn keeps the amber
 * it wears elsewhere, and anything that destroys keeps its red, so the
 * two actions worth a second thought are the two that stand out.
 */
export type Tone = 'accent' | 'burn' | 'danger' | 'success' | 'muted';

export const TONE_TEXT: Record<Tone, string> = {
  accent: 'text-accent',
  burn: 'text-orange-800 dark:text-orange-400',
  danger: 'text-danger',
  success: 'text-success',
  muted: 'text-pn-muted',
};

const ROW_TEXT: Record<Tone, string> = {
  accent: 'text-pn hover:bg-surface-1 focus-visible:bg-surface-1',
  burn: 'text-pn hover:bg-surface-1 focus-visible:bg-surface-1',
  muted: 'text-pn-muted hover:bg-surface-1 focus-visible:bg-surface-1',
  danger: 'text-danger hover:bg-danger/10 focus-visible:bg-danger/10',
  success: 'text-success hover:bg-emerald-50 dark:hover:bg-emerald-950/30 focus-visible:bg-emerald-50 dark:focus-visible:bg-emerald-950/30',
};

/** Compact with a mouse, a full 44px finger target on a touch screen. */
const ROW = 'w-full flex items-center gap-3 px-4 min-h-9 py-1.5 [@media(hover:none)]:min-h-11 text-start text-sm outline-none transition';

/** One block between two hairlines. The dividers come from the parent. */
export function Group({ children }: { children: React.ReactNode }) {
  return <div className="py-1">{children}</div>;
}

/** The quiet Pro marker: grey, no icon, never louder than the label. */
export function ProBadge() {
  return (
    <span className="shrink-0 rounded-md px-1.5 py-0.5 text-[11px] font-medium leading-none bg-pn/10 text-pn-soft">
      Pro
    </span>
  );
}

export function ToggleItem({
  label,
  icon,
  checked,
  pro,
  onClick,
}: {
  label: string;
  icon: React.ReactNode;
  checked: boolean;
  /** When true, the feature is Pro-gated for this user. Shown as a badge. */
  pro?: boolean;
  onClick: () => void;
}) {
  return (
    <button type="button" onClick={onClick} aria-pressed={checked} className={`${ROW} ${ROW_TEXT.accent}`}>
      <span className={`shrink-0 ${TONE_TEXT.accent}`}>{icon}</span>
      <span className="flex-1 min-w-0 truncate">{label}</span>
      {pro && <ProBadge />}
      <span
        aria-hidden
        className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition ${
          checked ? 'bg-accent-fill' : 'bg-pn-muted/35'
        }`}
      >
        <span
          className={`inline-block h-4 w-4 transform rounded-full bg-white transition ${
            checked ? 'translate-x-4 rtl:-translate-x-4' : 'translate-x-0.5 rtl:-translate-x-0.5'
          }`}
        />
      </span>
    </button>
  );
}

export function ActionItem({
  label,
  icon,
  onClick,
  pro,
  disabled,
  value,
  chevron,
  tone = 'accent',
}: {
  label: React.ReactNode;
  icon: React.ReactNode;
  onClick: () => void;
  pro?: boolean;
  disabled?: boolean;
  /** A short value at the end of the row: a size, a color. */
  value?: React.ReactNode;
  /** The row opens a second view of this menu. */
  chevron?: boolean;
  tone?: Tone;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={`${ROW} ${ROW_TEXT[tone]} disabled:opacity-50 disabled:cursor-not-allowed`}
    >
      <span className={`shrink-0 ${TONE_TEXT[tone]}`}>{icon}</span>
      <span className="flex-1 min-w-0 truncate">{label}</span>
      {pro && <ProBadge />}
      {value !== undefined && (
        <span className="shrink min-w-0 max-w-[45%] text-[13px] text-pn-muted">
          {value}
        </span>
      )}
      {chevron && <CaretRight size={14} aria-hidden="true" className="shrink-0 text-pn-muted" />}
    </button>
  );
}
