import {
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { createPortal } from 'react-dom';
import { IconUpgrade } from './UpgradeModal';
import { Check } from './icons';

/**
 * App-wide right-click context menu primitive.
 *
 * Why this exists: on native (Tauri) the default browser right-click
 * menu makes the app feel like a website. We take over right-click on
 * app chrome and list rows, but *intentionally* leave it alone on
 * editable text (inputs, textareas, contenteditable) so copy/paste,
 * spellcheck, and dictionary lookups still work.
 *
 * This is a right-click affordance only. A touch long-press is the
 * platform's own gesture (select + copy) and the app's multi-select
 * gesture, so it never opens this menu - see isTouchContextMenu.
 *
 * Usage:
 *   const ctx = useContextMenu();
 *   <div onContextMenu={(e) => ctx.open(e, buildMenu())}>…</div>
 *   <ContextMenu state={ctx.state} onClose={ctx.close} />
 */

export type ContextMenuItem =
  | {
      type?: 'item';
      label: string;
      onSelect: () => void;
      shortcut?: string;
      destructive?: boolean;
      success?: boolean;
      disabled?: boolean;
      icon?: ReactNode;
      /** When true, show Pro badge (rocket icon + "Pro" text). */
      pro?: boolean;
      /** A toggle that is currently on. Marked with a check on the trailing
       *  edge, so one label serves both states. */
      checked?: boolean;
    }
  | { type: 'separator' }
  | { type: 'header'; label: string };

export type ContextMenuState = {
  x: number;
  y: number;
  items: ContextMenuItem[];
} | null;

function isSelectable(it: ContextMenuItem): it is Extract<
  ContextMenuItem,
  { label: string; onSelect: () => void }
> {
  return !('type' in it && (it.type === 'separator' || it.type === 'header'));
}

/**
 * Treat the target as "editable" if it accepts character input -
 * inputs, textareas, the TipTap editor body. Used by useKeyboardShortcuts
 * to gate global hotkeys so typing chars never collides with hotkeys.
 */
export function isEditableTarget(target: EventTarget | null): boolean {
  if (!target || !(target instanceof HTMLElement)) return false;
  return !!target.closest(
    'input, textarea, [contenteditable="true"], [contenteditable=""]',
  );
}

/**
 * Right-click suppression rule (Strategy B - partial).
 * Returns true when the browser's native menu should win - editable
 * text (paste, spellcheck), images (Save image as…), and links (Open
 * in new tab, Copy link). Everywhere else, the app menu wins. Spec:
 * ops/docs/backlog.md #74.
 */
export function shouldUseBrowserDefault(target: EventTarget | null): boolean {
  if (!target || !(target instanceof HTMLElement)) return false;
  return !!target.closest(
    'input, textarea, [contenteditable="true"], [contenteditable=""], img, a[href]',
  );
}

/**
 * True when a `contextmenu` event came from a touch long-press rather
 * than a mouse right-click. Long-press already belongs to the platform
 * (select text, copy) and to the app's multi-select gesture, so the app
 * menu must stay out of its way. Chromium reports `pointerType` on the
 * event; WebKit and Firefox fire a plain MouseEvent, so fall back to
 * asking whether the device has a pointer that can right-click at all.
 * Spec: ops/docs/backlog.md #74 (issue #208).
 */
export function isTouchContextMenu(e: React.MouseEvent): boolean {
  const pointerType = (e.nativeEvent as PointerEvent).pointerType;
  if (pointerType) return pointerType !== 'mouse';
  return typeof window !== 'undefined' && window.matchMedia('(hover: none)').matches;
}

/**
 * True when the target sits inside a subtree that opted out of the app
 * menu with `data-no-app-menu`. Overlays use it - the global "New note /
 * Sign out" menu is app chrome and means nothing on top of a settings
 * dialog, where it only blocks selecting text. Spec: issue #208.
 */
export function optsOutOfAppMenu(target: EventTarget | null): boolean {
  if (!target || !(target instanceof HTMLElement)) return false;
  return !!target.closest('[data-no-app-menu]');
}

export function useContextMenu() {
  const [state, setState] = useState<ContextMenuState>(null);
  const open = (
    e: { clientX: number; clientY: number; preventDefault: () => void; stopPropagation: () => void },
    items: ContextMenuItem[],
  ) => {
    if (items.length === 0) return;
    e.preventDefault();
    e.stopPropagation();
    setState({ x: e.clientX, y: e.clientY, items });
  };
  const close = () => setState(null);
  return { state, open, close };
}

export function ContextMenu({
  state,
  onClose,
}: {
  state: ContextMenuState;
  onClose: () => void;
}) {
  const ref = useRef<HTMLDivElement | null>(null);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
  const [activeIdx, setActiveIdx] = useState<number>(-1);

  // For each new menu: reset the highlighted row + measure/flip near
  // viewport edges. Both jobs stay in one layout effect on purpose:
  // resetting `pos` in a separate post-paint effect clobbers the
  // just-measured position and makes the menu flash then vanish.
  useLayoutEffect(() => {
    if (!state) {
      setActiveIdx(-1);
      setPos(null);
      return;
    }
    setActiveIdx(-1);
    const el = ref.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    const m = 8;
    let left = state.x;
    let top = state.y;
    if (left + rect.width > vw - m) left = Math.max(m, vw - rect.width - m);
    if (top + rect.height > vh - m) top = Math.max(m, vh - rect.height - m);
    setPos({ top, left });
  }, [state]);

  // Dismiss on outside mousedown, Escape, scroll, resize, or another
  // contextmenu elsewhere. Capture phase so we win over list clicks.
  useEffect(() => {
    if (!state) return;

    const onPointerDown = (e: PointerEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    const onCtx = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    const onScroll = () => onClose();
    // A soft keyboard sliding in or out changes the viewport height and leaves
    // the width alone. That is chrome moving, not the page under the menu, and
    // it is the ordinary case on a phone: a long press takes focus off the
    // editor, the keyboard retracts, and the resize lands about 20ms after the
    // menu opened. Closing on it makes the menu flash and vanish on the first
    // try, then work on the second, once the keyboard is already down. A
    // rotation or a real window resize changes the width, and still closes.
    let lastWidth = window.innerWidth;
    const onResize = () => {
      if (window.innerWidth === lastWidth) return;
      lastWidth = window.innerWidth;
      onClose();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
        return;
      }
      const items = state.items;
      const selectableIdx: number[] = [];
      items.forEach((it, i) => {
        if (isSelectable(it) && !it.disabled) selectableIdx.push(i);
      });
      if (selectableIdx.length === 0) return;

      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setActiveIdx((cur) => {
          const curPos = selectableIdx.indexOf(cur);
          const nextPos =
            curPos < 0 ? 0 : (curPos + 1) % selectableIdx.length;
          return selectableIdx[nextPos] ?? cur;
        });
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setActiveIdx((cur) => {
          const curPos = selectableIdx.indexOf(cur);
          const nextPos =
            curPos < 0
              ? selectableIdx.length - 1
              : (curPos - 1 + selectableIdx.length) % selectableIdx.length;
          return selectableIdx[nextPos] ?? cur;
        });
      } else if (e.key === 'Enter' || e.key === ' ') {
        if (activeIdx < 0) return;
        const it = state.items[activeIdx];
        if (it && isSelectable(it) && !it.disabled) {
          e.preventDefault();
          it.onSelect();
          onClose();
        }
      } else if (e.key === 'Home') {
        e.preventDefault();
        const first = selectableIdx[0];
        if (first !== undefined) setActiveIdx(first);
      } else if (e.key === 'End') {
        e.preventDefault();
        const last = selectableIdx[selectableIdx.length - 1];
        if (last !== undefined) setActiveIdx(last);
      }
    };

    window.addEventListener('pointerdown', onPointerDown, true);
    window.addEventListener('contextmenu', onCtx, true);
    window.addEventListener('keydown', onKey);
    window.addEventListener('scroll', onScroll, true);
    window.addEventListener('resize', onResize);
    return () => {
      window.removeEventListener('pointerdown', onPointerDown, true);
      window.removeEventListener('contextmenu', onCtx, true);
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('scroll', onScroll, true);
      window.removeEventListener('resize', onResize);
    };
  }, [state, onClose, activeIdx]);

  if (!state) return null;

  const style: React.CSSProperties = {
    position: 'fixed',
    top: pos?.top ?? state.y,
    left: pos?.left ?? state.x,
    // Hide until we've measured + flipped so it doesn't flash offscreen.
    visibility: pos ? 'visible' : 'hidden',
  };

  const content = (
    <div
      ref={ref}
      role="menu"
      tabIndex={-1}
      style={style}
      onContextMenu={(e) => e.preventDefault()}
      className="z-[1000] min-w-[220px] py-1 rounded-md border border-divider bg-surface-2/95 backdrop-blur shadow-xl text-[13px] text-pn select-none"
    >
      {state.items.map((it, i) => {
        if ('type' in it && it.type === 'separator') {
          return (
            <div
              key={`sep-${i}`}
              className="my-1 border-t border-divider"
            />
          );
        }
        if ('type' in it && it.type === 'header') {
          return (
            <div
              key={`hdr-${i}`}
              className="px-3 pt-1.5 pb-0.5 text-[10px] font-semibold uppercase tracking-wider text-neutral-500 dark:text-neutral-500"
            >
              {it.label}
            </div>
          );
        }
        const item = it;
        const active = activeIdx === i && !item.disabled;
        const base =
          'w-full text-start flex items-center gap-2.5 px-3 py-1.5 outline-none';
        const tone = item.disabled
          ? 'opacity-40 cursor-default'
          : active
            ? item.destructive
              ? 'bg-red-500 text-white dark:bg-red-600'
              : item.success
                ? 'bg-emerald-500 text-white dark:bg-emerald-600'
                : 'bg-accent text-white'
            : item.destructive
              ? 'text-red-600 dark:text-red-400 cursor-pointer'
              : item.success
                ? 'text-emerald-600 dark:text-emerald-400 cursor-pointer'
                : 'cursor-pointer';
        return (
          <button
            key={`item-${i}`}
            role="menuitem"
            type="button"
            disabled={item.disabled}
            onMouseEnter={() => !item.disabled && setActiveIdx(i)}
            onMouseLeave={() => setActiveIdx(-1)}
            // Preserve the selection / focus in whatever element the
            // user right-clicked on. Without this, clicking Cut/Copy
            // would blur the editor and collapse the selection, so
            // execCommand would fire with nothing selected.
            onMouseDown={(e) => e.preventDefault()}
            onClick={() => {
              if (item.disabled) return;
              item.onSelect();
              onClose();
            }}
            className={`${base} ${tone}`}
          >
            <span className="w-4 h-4 shrink-0 inline-flex items-center justify-center">
              {item.icon}
            </span>
            <span className="flex-1 truncate">{item.label}</span>
            {item.pro && (
              <span className="shrink-0 inline-flex items-center gap-1 text-[11px] font-semibold text-accent">
                <IconUpgrade size={12} /> Pro
              </span>
            )}
            {item.checked && (
              <span className={`shrink-0 ${active ? 'text-white' : 'text-accent'}`}>
                <Check size={14} />
              </span>
            )}
            {item.shortcut && (
              <span
                className={`text-[11px] ms-4 tabular-nums ${
                  active
                    ? 'text-white/70'
                    : 'text-neutral-400 dark:text-neutral-500'
                }`}
              >
                {item.shortcut}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );

  return createPortal(content, document.body);
}
