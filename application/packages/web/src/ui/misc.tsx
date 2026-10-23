import { useEffect, useRef, type ReactNode, type RefObject } from 'react';
import { createPortal } from 'react-dom';
import { Check, Copy } from '../icons';
import { useCopyToClipboard } from '../clipboard';
import { useEscapeToClose } from '../useEscapeToClose';
import { usePopoverPosition } from '../usePopoverPosition';
import { CloseButton, IconButton } from './Button';
import type { Tone } from './feedback';

/**
 * @catalog Popover
 * use: a small panel anchored to the control that opened it (view options, a picker, a short form): it stays in the window, flips above when there is no room below, closes on Escape and a click outside. `title` adds a header with the close X.
 * never: a floating panel of your own (its own corners, shadow or layer); a popover without Escape and outside click.
 */
export function Popover({ open, anchorRef, onClose, title, align = 'start', className = 'w-72', children }: {
  open: boolean;
  anchorRef: RefObject<HTMLElement | null>;
  onClose: () => void;
  title?: ReactNode;
  align?: 'start' | 'end';
  /** The panel's width. */
  className?: string;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDivElement | null>(null);
  const pos = usePopoverPosition(open, anchorRef, ref, { align, shrink: true });
  useEscapeToClose(onClose, open);
  useEffect(() => {
    if (!open) return;
    const down = (e: PointerEvent) => {
      const target = e.target as Node;
      if (ref.current?.contains(target) || anchorRef.current?.contains(target)) return;
      onClose();
    };
    document.addEventListener('pointerdown', down, true);
    return () => document.removeEventListener('pointerdown', down, true);
  }, [open, onClose, anchorRef]);
  if (!open) return null;
  return createPortal(
    <div
      ref={ref}
      role="dialog"
      aria-label={typeof title === 'string' ? title : undefined}
      className={`fixed z-50 overflow-y-auto rounded-lg border border-divider bg-surface-2 p-2 text-pn shadow-lg ${className}`}
      style={{ top: pos?.top ?? -9999, left: pos?.left ?? -9999, maxHeight: pos?.maxHeight }}
    >
      {title && (
        <div className="mb-1 flex items-center justify-between gap-2 ps-1.5">
          <p className="text-sm font-semibold">{title}</p>
          <CloseButton onClick={onClose} />
        </div>
      )}
      {children}
    </div>,
    document.body,
  );
}

/**
 * @catalog Kbd
 * use: a key in running text or a list ("Press Esc", the shortcut beside a command): 11px, a framed key.
 * never: a <kbd> with its own border or font; a key cap inside a tooltip (HoverLabel `keys` draws those).
 */
export function Kbd({ children }: { children: ReactNode }) {
  return (
    <kbd className="inline-flex min-w-[1.25rem] items-center justify-center rounded border border-divider bg-surface-1 px-1 font-sans text-[11px] leading-5 text-pn-muted">
      {children}
    </kbd>
  );
}

/**
 * @catalog Divider
 * use: a rule between groups in a menu, a toolbar or a panel: horizontal by default, `vertical` between toolbar groups.
 * never: a border-t or a w-px of your own between groups.
 */
export function Divider({ vertical = false }: { vertical?: boolean }) {
  return <div role="separator" aria-orientation={vertical ? 'vertical' : 'horizontal'} className={vertical ? 'mx-1 h-4 w-px shrink-0 bg-divider' : 'my-1 h-px w-full bg-divider'} />;
}

/**
 * @catalog CopyButton
 * use: copy a value with one click (a code, a link, an address): the copy glyph, a green check for two seconds after it worked, the label as the tooltip.
 * never: a copy button of your own with another check color or timing.
 */
export function CopyButton({ value, label }: { value: string; label: string }) {
  const { copy, copied } = useCopyToClipboard();
  return (
    <IconButton label={label} onClick={() => copy(value, 'value')}>
      {copied ? <Check size={16} className="text-success" aria-hidden="true" /> : <Copy size={16} aria-hidden="true" />}
    </IconButton>
  );
}

const TILE: Record<Tone, string> = {
  info: 'bg-accent/10 text-accent',
  warning: 'bg-warning/10 text-warning',
  danger: 'bg-danger/10 text-danger',
  success: 'bg-success/10 text-success',
};

/**
 * @catalog IconTile
 * use: the round tinted tile with a 20px glyph at the start of a confirm, a toast or a short window head, in a tone.
 * never: a round or square tint of your own; a fixed red-500 or amber-500.
 */
export function IconTile({ tone = 'info', children }: { tone?: Tone; children: ReactNode }) {
  return <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-full [&>svg]:h-5 [&>svg]:w-5 ${TILE[tone]}`}>{children}</div>;
}
