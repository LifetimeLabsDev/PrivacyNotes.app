import { useEffect, useRef, useState, type DragEvent, type KeyboardEvent, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { useTranslation } from 'react-i18next';
import { ArrowDown, ArrowLeft, ArrowRight, ArrowUp, Check, DotsSixVertical, DotsThree, Paperclip, Plus, PushPin } from './icons';
import { useEscapeToClose } from './useEscapeToClose';
import { HoverLabel } from './HoverLabel';
import { useIsTouchDevice } from './useIsMobile';
import { usePopoverPosition } from './usePopoverPosition';
import {
  FORMAT_BAR_GROUPS,
  canStep,
  formatBarItem,
  homeOf,
  placeItem,
  refusalFor,
  stepItem,
  type FormatBarHome,
  type FormatBarRefusal,
  type ResolvedFormatBar,
} from './formatBar';
import { FORMAT_BAR_LOOK } from './formatBarItems';
import type { BarPosition } from './editorPrefs';

export type FormatBarBoardProps = {
  layout: ResolvedFormatBar;
  onUpdate: (move: (current: ResolvedFormatBar) => ResolvedFormatBar | null) => void;
  /** Where the bar sits, top or bottom; free and per device. */
  position?: BarPosition;
  onPositionChange?: (next: BarPosition) => void;
  /** Drawn under the bar position row, over the arranging part: the
   *  pane's headline, with the Pro mark. */
  heading?: ReactNode;
  /** A free account: the board arranges a draft that is not saved. */
  locked?: boolean;
  /** The draft differs from the saved layout. */
  previewing?: boolean;
  /** Hands the draft to the upgrade window. */
  onKeep?: () => void;
  onDiscard?: () => void;
  /** The tab opened and closed: the draft goes on close, unless it was
   *  handed on. */
  onEnter?: () => void;
  onLeave?: () => void;
};

/** A part of the board: the bar's row, the bar's end, the menu, the attach menu, hidden. */
type Part = FormatBarHome;

const DRAG_TYPE = 'application/x-pn-format-bar';

/**
 * Settings > Toolbar: the bar itself, every item
 * named and in its left-to-right order, the hidden row right under it, then
 * the + menu with a column for each group. On a narrow pane the groups
 * stack.
 *
 * Every item is a button. A click opens its menu (move up, move down, and
 * the three homes), which is the whole of the tab for the keyboard and for a
 * finger. Under a pointer an item also drags: onto another item (it lands
 * before it) or onto the bar or a column (it lands at the end).
 *
 * Moves that would break the bar are refused with a line that says why. Every
 * write goes through `onUpdate`, which applies the move to the freshest
 * arrangement in the settings cache, never to the one this render drew.
 * Spec: ops/docs/plans/format-bar.md (section 5)
 */
export function FormatBarBoard({ layout, onUpdate, position = 'top', onPositionChange, previewing = false, onEnter, onLeave, heading }: FormatBarBoardProps) {
  const { t } = useTranslation('editor');
  const touch = useIsTouchDevice();
  const canDrag = !touch;
  const [refusal, setRefusal] = useState<{ reason: Exclude<FormatBarRefusal, null>; key: string } | null>(null);
  const [dragKey, setDragKey] = useState<string | null>(null);
  // The bar marches its edge for a moment when the tab opens (pn-bar-ants).
  const [barIntro, setBarIntro] = useState(true);
  useEffect(() => {
    const id = window.setTimeout(() => setBarIntro(false), 1200);
    return () => window.clearTimeout(id);
  }, []);
  const lifeRef = useRef({ onEnter, onLeave });
  lifeRef.current = { onEnter, onLeave };
  useEffect(() => {
    lifeRef.current.onEnter?.();
    return () => lifeRef.current.onLeave?.();
  }, []);
  const [overPart, setOverPart] = useState<Part | null>(null);
  const [menuKey, setMenuKey] = useState<string | null>(null);
  // A move remounts the item in its new column, so the focus is put back on
  // it by key after the render that moved it.
  const [refocus, setRefocus] = useState<string | null>(null);
  const rootRef = useRef<HTMLDivElement>(null);
  const anchorRef = useRef<HTMLElement | null>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const menuPos = usePopoverPosition(menuKey !== null, anchorRef, menuRef);

  const label = (key: string) => t(FORMAT_BAR_LOOK[key]!.label);
  const itemButton = (key: string) =>
    rootRef.current?.querySelector<HTMLButtonElement>(`[data-key="${key}"][data-item]`) ?? null;

  // The focus goes back to the control that opened the menu (an item or an
  // icon of the live bar) while it is still in the page, else to the item.
  useEffect(() => {
    if (!refocus) return;
    const opener = anchorRef.current;
    if (opener?.isConnected) opener.focus();
    else itemButton(refocus)?.focus();
    setRefocus(null);
  }, [refocus, layout]);

  function closeMenu(focusItem = true) {
    const key = menuKey;
    setMenuKey(null);
    if (focusItem && key) setRefocus(key);
  }
  useEscapeToClose(() => closeMenu(), menuKey !== null);

  // The menu is hidden until it has a position, and a hidden button takes no
  // focus, so the focus moves in once the position is known.
  const menuPlaced = menuPos !== null;
  useEffect(() => {
    if (menuKey !== null && menuPlaced) {
      menuRef.current?.querySelector<HTMLButtonElement>('button:not(:disabled)')?.focus();
    }
  }, [menuKey, menuPlaced]);

  useEffect(() => {
    if (menuKey === null) return;
    function outside(e: PointerEvent) {
      const target = e.target as Node;
      if (menuRef.current?.contains(target) || anchorRef.current?.contains(target)) return;
      setMenuKey(null);
    }
    document.addEventListener('pointerdown', outside);
    return () => document.removeEventListener('pointerdown', outside);
  }, [menuKey]);

  /** Apply a move, or say why it is refused. */
  function moveTo(key: string, to: FormatBarHome, beforeKey: string | null = null) {
    const reason = refusalFor(layout, key, to);
    if (reason) {
      setRefusal({ reason, key });
      return;
    }
    setRefusal(null);
    onUpdate((current) => placeItem(current, key, to, beforeKey));
  }

  function openMenu(key: string, anchor: HTMLElement) {
    if (menuKey === key) {
      setMenuKey(null);
      return;
    }
    anchorRef.current = anchor;
    setRefusal(null);
    if (menuKey === null) {
      setMenuKey(key);
      return;
    }
    // The position is measured when the menu opens, so a menu that moves to
    // another item closes for one render and opens there (the effect below).
    pendingMenu.current = key;
    setMenuKey(null);
  }
  const pendingMenu = useRef<string | null>(null);
  useEffect(() => {
    if (menuKey !== null || !pendingMenu.current) return;
    const key = pendingMenu.current;
    pendingMenu.current = null;
    setMenuKey(key);
  }, [menuKey]);

  // Up and Down move between the menu's choices, Home and End to the ends.
  // Tab closes the menu and gives the focus back to the item that opened it:
  // the menu sits at the end of the page, so a Tab out of it would land
  // behind the Settings window.
  function menuKeys(e: KeyboardEvent<HTMLDivElement>) {
    if (e.key === 'Tab') {
      e.preventDefault();
      closeMenu();
      return;
    }
    const items = [...e.currentTarget.querySelectorAll<HTMLButtonElement>('button:not(:disabled)')];
    if (!items.length) return;
    const at = items.indexOf(document.activeElement as HTMLButtonElement);
    const to = e.key === 'ArrowDown' ? (at + 1) % items.length
      : e.key === 'ArrowUp' ? (at - 1 + items.length) % items.length
      : e.key === 'Home' ? 0
      : e.key === 'End' ? items.length - 1
      : -1;
    if (to < 0) return;
    e.preventDefault();
    items[to]!.focus();
  }

  // Drag, on a pointer device only (a drag does not start from a finger).
  // While a drag is over the board, `target` says where the item would land,
  // and a line is drawn there: the half of the item under the pointer
  // decides before or after it, and the empty part of a list means its end.
  // A spot where the item already is draws nothing, and a refused home takes
  // no drop (the cursor says so) and shows its reason. The drop applies the
  // target, never a guess from the element under the pointer.
  // A drop target accepts in dragenter as well as dragover, because Chromium
  // may never send a dragover to a target that did not accept the enter.
  // Spec: ops/docs/plans/drag-to-folder-and-tag.md (section 3)
  type DropTarget = { part: Part; before: string | null };
  const [target, setTarget] = useState<DropTarget | null>(null);
  const dragFrame = useRef(0);
  // The dragged key for the drop logic, set at once; `dragKey` (state) only
  // drives the fade, a frame later.
  const dragRef = useRef<string | null>(null);
  const groupOf = (k: string) => formatBarItem(k)!.group;
  const listOf = (part: Part) =>
    layout[part];
  /** The key after `key` in its list (in the menu, inside its group), or null at the end. */
  function nextIn(part: Part, key: string): string | null {
    const list = listOf(part);
    const next = list[list.indexOf(key) + 1] ?? null;
    return part === 'menu' && next && groupOf(next) !== groupOf(key) ? null : next;
  }

  function endDrag() {
    cancelAnimationFrame(dragFrame.current);
    dragRef.current = null;
    setDragKey(null);
    setTarget(null);
  }
  const dragProps = (key: string) => (canDrag ? {
    draggable: true,
    onDragStart: (e: DragEvent) => {
      e.dataTransfer.setData(DRAG_TYPE, key);
      e.dataTransfer.effectAllowed = 'move';
      dragRef.current = key;
      setMenuKey(null);
      setRefusal(null);
      // A frame later, so the drag picture is taken before the item fades.
      // A drag that ends sooner cancels it, so no stale key outlives it.
      dragFrame.current = requestAnimationFrame(() => setDragKey(key));
    },
    onDragEnd: endDrag,
  } : {});

  /** Where the dragged item would land for `before` in `part`, null for no move, 'refused' for a refused home. */
  function aim(part: Part, before: string | null): DropTarget | null | 'refused' {
    const key = dragRef.current;
    if (!key) return null;
    const item = formatBarItem(key)!;
    const to = part;
    if (refusalFor(layout, key, to)) return 'refused';
    let at = before;
    // In the menu an item lands in its own group, at the end when the spot is in another.
    if (part === 'menu' && at && groupOf(at) !== item.group) at = null;
    if (homeOf(layout, key) === to && (at === key || at === nextIn(part, key))) return null;
    if (homeOf(layout, key) === to && at === null && nextIn(part, key) === null) return null;
    return { part, before: at };
  }

  /** dragover and dragenter on an item or on the empty part of a list. */
  const over = (part: Part, key: string | null, sideways = false) => (e: DragEvent) => {
    const dragged = dragRef.current;
    if (!dragged) return;
    e.stopPropagation();
    let before: string | null = null;
    if (key) {
      const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
      const rtl = document.documentElement.dir === 'rtl';
      const after = sideways
        ? (rtl ? e.clientX < r.left + r.width / 2 : e.clientX > r.left + r.width / 2)
        : e.clientY > r.top + r.height / 2;
      before = after ? nextIn(part, key) : key;
    }
    const next = aim(part, before);
    if (next === 'refused') {
      // No preventDefault: the drop is refused and the cursor shows it.
      const reason = refusalFor(layout, dragged, part);
      if (reason && (refusal?.key !== dragged || refusal.reason !== reason)) setRefusal({ reason, key: dragged });
      if (target) setTarget(null);
      return;
    }
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    if (refusal) setRefusal(null);
    if (next?.part !== target?.part || next?.before !== target?.before) setTarget(next);
  };
  const drop = (e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    const key = dragRef.current ?? e.dataTransfer.getData(DRAG_TYPE);
    const at = target;
    endDrag();
    if (!key || !formatBarItem(key) || !at) return;
    moveTo(key, at.part, at.before);
  };
  const dropZone = (part: Part) => ({
    onDragEnter: over(part, null),
    onDragOver: over(part, null),
    onDrop: drop,
  });

  /** The line that marks where a dragged item lands. */
  const marker = (part: Part, before: string | null, sideways: boolean) =>
    target && target.part === part && target.before === before
      ? <li key={`drop-${before ?? 'end'}`} aria-hidden="true" className={sideways ? 'self-stretch w-0.5 my-1 rounded-full bg-accent' : 'h-0.5 mx-1 rounded-full bg-accent'} />
      : null;

  function item(key: string, part: Part): ReactNode {
    const def = formatBarItem(key)!;
    const { Icon } = FORMAT_BAR_LOOK[key]!;
    const home = homeOf(layout, key);
    const open = menuKey === key;
    const name = label(key);
    const common = {
      type: 'button' as const,
      'data-key': key,
      'data-item': '',
      'aria-haspopup': 'menu' as const,
      'aria-expanded': open,
      onClick: (e: React.MouseEvent<HTMLButtonElement>) => openMenu(key, e.currentTarget),
      ...dragProps(key),
      onDrop: drop,
    };
    // On the bar and in the hidden row an item looks like its toolbar
    // button: the icon alone, the name in a hover label (and at the top of
    // its menu on touch). Only the two menus list names, as the toolbar's do.
    if (part !== 'menu' && part !== 'attachMenu') {
      const thinLine = key.startsWith('separator') && part !== 'hidden';
      return (
        <li key={key} className="shrink-0" onDragEnter={over(part, key, true)} onDragOver={over(part, key, true)}>
          <HoverLabel label={name} position="below">
            <button
              {...common}
              aria-label={name}
              // On the bar a separator is the toolbar's thin line in a narrow
              // slot; in the hidden row it is a full button, so it can be seen and grabbed.
              className={`flex items-center justify-center ${thinLine ? 'w-2 [@media(hover:none)]:w-5' : 'w-8 [@media(hover:none)]:w-10'} h-8 [@media(hover:none)]:h-10 rounded-md transition ${
                open ? 'bg-accent/15 text-accent-strong' : 'text-pn-soft [@media(hover:hover)]:hover:bg-pn/10'
              } ${canDrag ? 'cursor-grab' : ''} ${dragKey === key ? 'opacity-40' : ''}`}
            >
              {thinLine
                ? <span aria-hidden="true" className="h-4 w-px bg-pn-muted/35" />
                : <Icon size={18} aria-hidden="true" />}
            </button>
          </HoverLabel>
        </li>
      );
    }
    return (
      <li key={key} onDragEnter={over(part, key)} onDragOver={over(part, key)}>
        <button
          {...common}
          className={`w-full flex items-center gap-2 min-h-[44px] [@media(hover:hover)]:min-h-[34px] rounded-md ps-2 pe-1.5 text-start text-sm bg-surface-2 border transition ${
            open ? 'border-accent' : 'border-transparent [@media(hover:hover)]:hover:border-divider'
          } ${canDrag ? 'cursor-grab' : ''} ${dragKey === key ? 'opacity-40' : ''} ${home === 'hidden' ? 'text-pn-muted' : 'text-pn-soft'}`}
        >
          {canDrag && <DotsSixVertical size={14} className="shrink-0 text-pn-muted" aria-hidden="true" />}
          <Icon size={18} className="shrink-0" aria-hidden="true" />
          <span className="flex-1 min-w-0 leading-tight break-words hyphens-auto">{name}</span>
          {/* The pin says why the item cannot go into the menu. */}
          {part === 'menu' && !def.menuAllowed && <PushPin size={12} className="shrink-0 text-pn-muted" aria-label={t('formatBar.pinned')} />}
          {touch && <DotsThree size={18} className="shrink-0 text-pn-muted" aria-hidden="true" />}
        </button>
      </li>
    );
  }

  const empty = (text: string) => <p className="px-1 py-2 text-xs text-pn-muted">{text}</p>;
  /** A column list, with the drop line before an item or at its end. */
  const list = (keys: string[], part: Part, endMarker = true) => (
    <ul className="space-y-1">
      {keys.flatMap((k) => [marker(part, k, false), item(k, part)])}
      {endMarker && marker(part, null, false)}
    </ul>
  );
  const subhead = (text: string) => (
    <div className="px-1 pt-3 pb-1 text-[11px] uppercase tracking-wide text-pn-muted">{text}</div>
  );

  // In the menu the end of a list is the end of a group: the line goes at the
  // end of the dragged item's own group.
  const dragGroup = target?.part === 'menu' && dragRef.current ? groupOf(dragRef.current) : null;
  const menuColumn = layout.menu.length
    ? FORMAT_BAR_GROUPS.map((g) => {
        const inGroup = layout.menu.filter((k) => groupOf(k) === g);
        // The menu keeps its groups. A group with nothing in it shows no
        // header, except while an item of that group is dragged over the
        // menu: then it shows where the item will land.
        if (!inGroup.length) {
          return g === dragGroup
            ? <div key={g}>{subhead(t(`insertGroup.${g}`))}<ul>{marker('menu', null, false)}</ul></div>
            : null;
        }
        return <div key={g} className="min-w-0">{subhead(t(`insertGroup.${g}`))}{list(inGroup, 'menu', g === dragGroup)}</div>;
      })
    : <>{empty(t('formatBar.menuEmpty'))}{target?.part === 'menu' && <ul>{marker('menu', null, false)}</ul>}</>;
  // The attach menu, drawn under the Blocks group: the paperclip's own list,
  // a drop target of its own inside the + menu box.
  const attachSection = (
    <div
      key="attachMenu"
      {...dropZone('attachMenu')}
      className={`min-w-0 mt-2 rounded-md transition-colors ${target?.part === 'attachMenu' ? 'bg-accent/10' : ''}`}
    >
      <div className="flex items-center gap-1.5 px-1 pt-3 pb-1 text-[11px] uppercase tracking-wide text-pn-muted">
        <Paperclip size={12} aria-hidden="true" />{t('formatBar.inAttachMenu')}
      </div>
      {layout.attachMenu.length
        ? list(layout.attachMenu, 'attachMenu')
        : <>{empty(t('formatBar.attachMenuEmpty'))}<ul>{marker('attachMenu', null, false)}</ul></>}
    </div>
  );
  const blocksAt = Array.isArray(menuColumn) ? FORMAT_BAR_GROUPS.indexOf('blocks') : -1;
  const menuWithAttach = Array.isArray(menuColumn)
    ? menuColumn.map((col, n) => (n === blocksAt
        ? <div key="blocks" className="min-w-0">{col}{attachSection}</div>
        : col))
    : <>{menuColumn}{attachSection}</>;
  // The hidden row says what a hidden button still does, or how to hide one.
  // A separator is not a button, so it does not count as a hidden one.
  const hiddenNote = layout.hidden.some((k) => !k.startsWith('separator')) ? t('formatBar.hiddenNote')
    : canDrag ? t('formatBar.hiddenDrop')
    : t('formatBar.hiddenEmpty');
  const overBar = target?.part === 'bar' || target?.part === 'end';

  const menuItem = menuKey ? formatBarItem(menuKey) : undefined;
  const menuHome = menuKey ? homeOf(layout, menuKey) : null;
  const ordered = menuHome === 'bar' || menuHome === 'end' || menuHome === 'menu' || menuHome === 'attachMenu';
  // The bar runs sideways, so its order moves are left and right (across the
  // '+' between its two zones), mirrored in a right-to-left language; the
  // menu runs down.
  const sideways = menuHome === 'bar' || menuHome === 'end';
  const rtl = typeof document !== 'undefined' && document.documentElement.dir === 'rtl';
  const earlierLabel = sideways ? t(rtl ? 'formatBar.moveRight' : 'formatBar.moveLeft') : t('formatBar.moveUp');
  const laterLabel = sideways ? t(rtl ? 'formatBar.moveLeft' : 'formatBar.moveRight') : t('formatBar.moveDown');
  const EarlierIcon = sideways ? (rtl ? ArrowRight : ArrowLeft) : ArrowUp;
  const LaterIcon = sideways ? (rtl ? ArrowLeft : ArrowRight) : ArrowDown;
  const menuAction = (act: () => void) => () => {
    act();
    closeMenu();
  };
  const menuBtn = 'w-full flex items-center gap-2.5 text-start px-3 min-h-[44px] [@media(hover:hover)]:min-h-0 [@media(hover:hover)]:py-1.5 text-sm rounded-md text-pn-soft [@media(hover:hover)]:hover:bg-pn/5 disabled:opacity-40 disabled:cursor-default';

  return (
    <div
      ref={rootRef}
      className="space-y-3"
      onDragLeave={(e) => {
        if (!(e.currentTarget as Node).contains(e.relatedTarget as Node | null)) setTarget(null);
      }}
    >
      {/* Top or bottom, on every device (per device). */}
      {onPositionChange && (
        <div className="flex items-center justify-between gap-3">
          <div className="min-w-0">
            <p className="text-sm font-medium">{t('formatBar.positionTitle')}</p>
            <p className="text-xs text-pn-muted">{t('formatBar.positionNote')}</p>
          </div>
          <div
            role="radiogroup"
            aria-label={t('formatBar.positionTitle')}
            className="shrink-0 flex gap-1 rounded-md p-1 bg-track"
            // A radio group is one Tab stop, and an arrow key picks the other
            // choice, as every radio group does.
            onKeyDown={(e) => {
              if (!['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].includes(e.key)) return;
              e.preventDefault();
              const next = position === 'top' ? 'bottom' : 'top';
              onPositionChange(next);
              e.currentTarget.querySelector<HTMLButtonElement>(`[data-position="${next}"]`)?.focus();
            }}
          >
            {(['top', 'bottom'] as const).map((p) => (
              <button
                key={p}
                type="button"
                role="radio"
                data-position={p}
                aria-checked={position === p}
                tabIndex={position === p ? 0 : -1}
                onClick={() => onPositionChange(p)}
                className={`min-h-[36px] px-3 rounded text-xs transition ${position === p ? 'bg-surface-2 text-pn font-medium shadow-sm' : 'text-pn-muted'}`}
              >
                {t(p === 'top' ? 'formatBar.positionTop' : 'formatBar.positionBottom')}
              </button>
            ))}
          </div>
        </div>
      )}

      {heading}

      <div className="min-w-0 space-y-3">
        {/* The bar itself, in its left-to-right order: every item named, the
            + mark where the menu sits, and the fixed end with the picture,
            file and recording buttons. It wraps onto more lines when the
            pane is narrow. */}
        <section
          aria-label={t('formatBar.onBar')}
          {...dropZone('bar')}
          className="rounded-lg p-2 bg-surface-1"
        >
          {/* Each hint sits where it applies: how to move a button next to
              the heading, and the fixed end of the bar named above it. */}
          <div className="flex items-baseline gap-2 px-1 pb-1.5">
            <h3 className="shrink-0 text-xs font-semibold text-pn-muted">{t('formatBar.onBar')}</h3>
            <p className="min-w-0 truncate text-xs text-pn-muted">{touch ? t('formatBar.hintTap') : t('formatBar.hintDrag')}</p>
            {layout.end.length > 0 && <p className="ms-auto shrink-0 text-xs text-pn-muted">{t('formatBar.alwaysVisible')}</p>}
          </div>
          {/* Drawn like the toolbar: one row of icon buttons in bar order, the
              + mark where the menu sits, a hairline, then the end of the bar,
              which the person fills and which never gives way behind the •••. On
              a touch screen a long row scrolls sideways, as the toolbar does.
              Under a pointer it stays unclipped, because the names show in
              hover labels below the icons, and only an unusually long bar
              wraps. */}
          {/* The bar reads as a live drop target at rest (an accent edge and
              tint, marching on hover and when the tab opens), turns dashed
              while any button is dragged, and fills when the drag is over it,
              as the Hidden box below does. */}
          <div className={`rounded-lg ${overBar || dragKey ? '' : 'pn-bar-ants'}`} data-intro={barIntro ? '' : undefined}>
          <ul className={`pn-format-row flex items-center rounded-lg border px-1.5 py-1 transition-colors [@media(hover:none)]:overflow-x-auto [@media(hover:none)]:[scrollbar-width:none] [@media(hover:hover)]:flex-wrap ${
            overBar ? 'border-accent bg-accent/10 ring-2 ring-accent/25'
              : dragKey ? 'border-dashed border-accent/60 bg-accent/5'
              : 'border-accent/40 bg-accent/5'
          }`}>
            {layout.bar.flatMap((k) => [marker('bar', k, true), item(k, 'bar')])}
            {marker('bar', null, true)}
            <li aria-hidden="true" className="flex-1" />
            {layout.menu.length > 0 && (
              <li aria-hidden="true" className="flex items-center justify-center w-8 h-8 text-pn-muted">
                <Plus size={18} />
              </li>
            )}
            <li aria-hidden="true" className="mx-0.5 h-4 w-px bg-pn-muted/35" />
            {/* The end zone: its own drop target, so an empty end can still be
                filled; while a drag is on, it shows as a slot. */}
            <li
              {...dropZone('end')}
              className={`flex items-center min-w-8 min-h-8 rounded-md ${dragKey && !layout.end.length ? 'border border-dashed border-divider' : ''}`}
            >
              <ul className="flex items-center">
                {layout.end.flatMap((k) => [marker('end', k, true), item(k, 'end')])}
                {marker('end', null, true)}
              </ul>
            </li>
          </ul>
          </div>
          {/* Hidden, right under the bar and as wide, drawn like it: a
              heading with its note, then one row of icons that wraps. The
              whole part is the drop target. */}
          <section
            aria-label={t('formatBar.hidden')}
            {...dropZone('hidden')}
            className="mt-3"
          >
            <div className="flex items-baseline gap-2 px-1 pb-1.5">
              <h3 className="shrink-0 text-xs font-semibold text-pn-muted">{t('formatBar.hidden')}</h3>
              <p className="min-w-0 truncate text-xs text-pn-muted">{hiddenNote}</p>
            </div>
            <ul className={`flex flex-wrap items-center min-h-[2.625rem] [@media(hover:none)]:min-h-[3.125rem] rounded-lg border border-dashed px-1.5 py-1 transition-colors ${
              target?.part === 'hidden' ? 'border-accent bg-accent/10' : 'border-divider'
            }`}>
              {layout.hidden.flatMap((k) => [marker('hidden', k, true), item(k, 'hidden')])}
              {marker('hidden', null, true)}
            </ul>
          </section>
        </section>

        {/* A refused move is named above the menu box, in view of the drag
            that caused it rather than under the fold. A free account's
            preview says it is not saved in the same line, so the pitch takes
            no room of its own; a refusal replaces it while it shows. */}
        <div className="min-w-0">
          <p aria-live="polite" className={`mb-1.5 px-1 text-xs empty:mb-0 ${refusal ? 'text-danger' : 'text-pro'}`}>
            {refusal ? (refusal.reason === 'menuNotAllowed'
              ? t('formatBar.refuse.menuNotAllowed', { item: label(refusal.key) })
              : t(`formatBar.refuse.${refusal.reason}`))
              : previewing && t('formatBar.previewOnly')}
          </p>
          <section
            aria-label={t('formatBar.inMenu')}
            {...dropZone('menu')}
            className={`min-w-0 rounded-lg p-2 transition-colors ${target?.part === 'menu' ? 'bg-accent/10' : 'bg-surface-1'}`}
          >
            <h3 className="px-1 text-xs font-semibold text-pn-muted">{t('formatBar.inMenu')}</h3>
            <div className="grid gap-x-3 [grid-template-columns:repeat(auto-fit,minmax(11rem,1fr))] items-start">
              {menuWithAttach}
            </div>
          </section>
        </div>
      </div>

      {menuKey && menuItem && createPortal(
        <div
          ref={menuRef}
          role="menu"
          aria-label={t('formatBar.optionsFor', { item: label(menuKey) })}
          onKeyDown={menuKeys}
          // Focus that moves to another element closes the menu, so it never
          // stays open behind the focus. A blur to nothing keeps it open: WebKit
          // gives no focus to a tapped button, so a tap on a choice blurs the
          // menu with no next element, and closing then would eat the click.
          // A tap outside is handled by the pointerdown listener.
          onBlur={(e) => {
            const next = e.relatedTarget as Node | null;
            if (next && !menuRef.current?.contains(next) && !anchorRef.current?.contains(next)) closeMenu(false);
          }}
          className="fixed z-[60] w-60 rounded-lg border border-divider bg-surface-1 p-1 shadow-lg"
          style={{ top: menuPos?.top ?? 0, left: menuPos?.left ?? 0, visibility: menuPos ? 'visible' : 'hidden' }}
        >
          <div className="flex items-center gap-2 px-3 pt-1.5 pb-1 text-xs font-semibold text-pn-muted" aria-hidden="true">
            {(() => { const { Icon } = FORMAT_BAR_LOOK[menuKey]!; return <Icon size={14} />; })()}
            <span className="truncate">{label(menuKey)}</span>
          </div>
          {ordered && (
            <>
              <button type="button" role="menuitem" className={menuBtn} disabled={!canStep(layout, menuKey, -1)}
                onClick={menuAction(() => onUpdate((c) => stepItem(c, menuKey, -1)))}>
                <EarlierIcon size={16} aria-hidden="true" />{earlierLabel}
              </button>
              <button type="button" role="menuitem" className={menuBtn} disabled={!canStep(layout, menuKey, 1)}
                onClick={menuAction(() => onUpdate((c) => stepItem(c, menuKey, 1)))}>
                <LaterIcon size={16} aria-hidden="true" />{laterLabel}
              </button>
              <div className="my-1 h-px bg-divider" aria-hidden="true" />
            </>
          )}
          {(['bar', 'menu', 'attachMenu', 'hidden'] as const).filter((home) => home !== 'attachMenu' || menuItem.attachAllowed).map((home) => {
            const blocked = home === 'menu' && !menuItem.menuAllowed;
            const current = menuHome === home || (home === 'bar' && menuHome === 'end');
            return (
              <button
                key={home}
                type="button"
                role="menuitemradio"
                aria-checked={current}
                className={menuBtn}
                disabled={blocked}
                onClick={menuAction(() => { if (!current) moveTo(menuKey, home); })}
              >
                <span className="w-4 shrink-0">{current && <Check size={16} aria-hidden="true" />}</span>
                <span className="flex-1">{t(`formatBar.home.${home}`)}</span>
                {blocked && <span className="text-xs text-pn-muted">{t(menuKey === 'audio' ? 'formatBar.showsRecording' : 'formatBar.opensPanel')}</span>}
              </button>
            );
          })}
        </div>,
        document.body,
      )}
    </div>
  );
}
