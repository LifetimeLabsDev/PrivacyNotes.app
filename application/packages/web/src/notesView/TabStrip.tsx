import { useContext, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { LocalNote } from '../db';
import type { ContextMenuItem } from '../ContextMenu';
import { ArrowsInLineHorizontal, PushPin, X, XSquare } from '../icons';
import { LooksContext } from '../looks/LookGlyph';
import { resolveNoteColor, type LookColor } from '../itemStyles';
import { noteFaviconDomain, typeGlyph } from '../NoteRow';
import { Favicon } from '../VaultItem';

/**
 * The tabs above the editor. It owns no state: the list of tabs comes from
 * `useOpenTabs`, and the active tab is whichever one holds the open item, so
 * an item opened from the list leaves every tab unmarked.
 * Spec: ops/docs/plans/note-tabs.md (section 3)
 */
export default function TabStrip({
  tabs,
  activeId,
  pinnedIds,
  titleOf,
  isGated,
  onActivate,
  onClose,
  onCloseOthers,
  onCloseAll,
  onTogglePin,
  onMove,
  onContextMenu,
}: {
  tabs: LocalNote[];
  activeId: string | null;
  pinnedIds: Set<string>;
  titleOf: (n: LocalNote) => string;
  /** Behind the PIN right now: the tab then reads nothing from the body. */
  isGated: (n: LocalNote) => boolean;
  onActivate: (id: string) => void;
  onClose: (id: string) => void;
  onCloseOthers: (id: string) => void;
  onCloseAll: () => void;
  onTogglePin: (id: string) => void;
  onMove: (id: string, beforeId: string | null) => void;
  onContextMenu: (e: React.MouseEvent, items: ContextMenuItem[]) => void;
}) {
  const { t } = useTranslation('shell');
  const stripRef = useRef<HTMLDivElement | null>(null);
  const [dragId, setDragId] = useState<string | null>(null);
  /** Where the dragged tab would land: beside which tab, on which side. The
   *  marker is drawn on that edge so the drop is visible before it happens. */
  const [dropAt, setDropAt] = useState<{ id: string; side: 'before' | 'after' } | null>(null);
  const endDrag = () => { setDragId(null); setDropAt(null); };
  const drop = () => {
    if (!dragId || !dropAt) { endDrag(); return; }
    const at = tabs.findIndex((n) => n.id === dropAt.id);
    const beforeId = dropAt.side === 'before' ? dropAt.id : (tabs[at + 1]?.id ?? null);
    if (beforeId !== dragId) onMove(dragId, beforeId);
    endDrag();
  };

  useEffect(() => {
    if (!activeId) return;
    stripRef.current
      ?.querySelector<HTMLElement>(`[data-tab-id="${CSS.escape(activeId)}"]`)
      ?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
  }, [activeId, tabs.length]);

  // A pinned tab offers no way to close it; the bulk rows appear only while
  // there is an unpinned tab for them to close.
  const menuFor = (id: string): ContextMenuItem[] => {
    const pinned = pinnedIds.has(id);
    const closable = tabs.filter((n) => !pinnedIds.has(n.id));
    const items: ContextMenuItem[] = [
      { label: t(pinned ? 'contextMenu.unpinTab' : 'contextMenu.pinTab'), icon: <PushPin size={14} weight={pinned ? 'fill' : 'bold'} />, onSelect: () => onTogglePin(id) },
    ];
    if (!pinned) items.push({ label: t('contextMenu.closeTab'), icon: <X size={14} />, onSelect: () => onClose(id) });
    if (closable.some((n) => n.id !== id)) items.push({ label: t('contextMenu.closeOtherTabs'), icon: <ArrowsInLineHorizontal size={14} />, onSelect: () => onCloseOthers(id) });
    if (closable.length > 0) items.push({ label: t('contextMenu.closeAllTabs'), icon: <XSquare size={14} />, onSelect: onCloseAll });
    return items;
  };

  const activeAt = tabs.findIndex((n) => n.id === activeId);
  // The row's own color rule (`useNoteColor` resolves the same way), read here
  // rather than per tab because a divider depends on both of its neighbours.
  const { styles, tintNotes, filter } = useContext(LooksContext);
  const colors = tabs.map((n) => resolveNoteColor(n.id, n.tags, n.folderId, styles, tintNotes, filter));
  // A hairline only between two plain resting tabs: the active tab and a
  // colored tab each have their own edges, and a line against those reads as
  // a stray mark.
  const plain = (i: number) => i !== activeAt && !colors[i];

  return (
    <div
      ref={stripRef}
      role="tablist"
      aria-label={t('tabStrip.label')}
      className="flex items-end shrink-0 overflow-x-auto scrollbar-none bg-surface-1 border-b border-divider px-2 pt-1.5"
      onDragOver={(e) => {
        if (!dragId) return;
        e.preventDefault();
        // Past the last tab: the end of the strip, or of the pinned group for
        // a pinned tab, which cannot leave it.
        const group = pinnedIds.has(dragId) ? tabs.filter((x) => pinnedIds.has(x.id)) : tabs;
        const last = group[group.length - 1];
        if (e.target === e.currentTarget && last) setDropAt({ id: last.id, side: 'after' });
      }}
      onDrop={(e) => { if (dragId) { e.preventDefault(); drop(); } }}
    >
      {tabs.map((n, i) => (
        <Tab
          key={n.id}
          note={n}
          title={titleOf(n)}
          gated={isGated(n)}
          color={colors[i] ?? null}
          active={i === activeAt}
          pinned={pinnedIds.has(n.id)}
          divider={i < tabs.length - 1 && plain(i) && plain(i + 1)}
          dragging={dragId === n.id}
          dropSide={dragId && dropAt?.id === n.id ? dropAt.side : null}
          closeLabel={t('tabStrip.close', { title: titleOf(n) })}
          onActivate={() => onActivate(n.id)}
          onClose={() => onClose(n.id)}
          onContextMenu={(e) => onContextMenu(e, menuFor(n.id))}
          onDragStart={() => setDragId(n.id)}
          onDragEnd={endDrag}
          onDragOverSide={dragId ? (side) => {
            // A tab never crosses the pinned boundary, so over the other group
            // the marker sits on that boundary, where the tab will land.
            const dragPinned = pinnedIds.has(dragId);
            let next = { id: n.id, side };
            if (pinnedIds.has(n.id) !== dragPinned) {
              const group = tabs.filter((x) => pinnedIds.has(x.id) === dragPinned);
              const edge = dragPinned ? group[group.length - 1] : group[0];
              if (edge) next = { id: edge.id, side: dragPinned ? 'after' : 'before' };
            }
            if (dropAt?.id !== next.id || dropAt.side !== next.side) setDropAt(next);
          } : null}
        />
      ))}
    </div>
  );
}

/**
 * One tab. The item's type glyph (or its site's icon) and its color come from
 * the same helpers the list row uses, so a tab and its row always match.
 */
function Tab({
  note: n, title, gated, color, active, pinned, divider, dragging, dropSide, closeLabel,
  onActivate, onClose, onContextMenu, onDragStart, onDragEnd, onDragOverSide,
}: {
  note: LocalNote;
  title: string;
  gated: boolean;
  color: LookColor | null;
  active: boolean;
  /** Narrower, a pin where the X would be, and deaf to the middle button. */
  pinned: boolean;
  divider: boolean;
  dragging: boolean;
  dropSide: 'before' | 'after' | null;
  closeLabel: string;
  onActivate: () => void;
  onClose: () => void;
  onContextMenu: (e: React.MouseEvent) => void;
  onDragStart: () => void;
  onDragEnd: () => void;
  /** Set while a tab is dragged: reports which half of this tab is under the
   *  pointer. The drop itself is handled by the strip. */
  onDragOverSide: ((side: 'before' | 'after') => void) | null;
}) {
  const { Icon, color: glyphColor } = typeGlyph(n.type);
  const domain = gated ? '' : noteFaviconDomain(n);
  const tint = color ? `var(--pn-label-${color}-tint)` : null;
  const ink = color ? `var(--pn-label-${color}-ink)` : 'var(--color-accent)';

  return (
    <div
      role="tab"
      aria-selected={active}
      tabIndex={active ? 0 : -1}
      data-tab-id={n.id}
      title={title}
      draggable
      onDragStart={(e) => {
        onDragStart();
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/plain', title);
      }}
      onDragEnd={onDragEnd}
      onDragOver={(e) => {
        if (!onDragOverSide) return;
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
        const r = e.currentTarget.getBoundingClientRect();
        const firstHalf = e.clientX < r.left + r.width / 2;
        // In a right-to-left strip the first half is the right one.
        const rtl = getComputedStyle(e.currentTarget).direction === 'rtl';
        onDragOverSide(firstHalf !== rtl ? 'before' : 'after');
      }}
      onClick={onActivate}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onActivate(); }
      }}
      // Middle button: the browser's own "close this tab".
      onMouseDown={(e) => { if (e.button === 1) e.preventDefault(); }}
      onAuxClick={(e) => { if (e.button === 1 && !pinned) { e.preventDefault(); onClose(); } }}
      onContextMenu={onContextMenu}
      style={{
        // The tint is drawn as an image, so the surface underneath (active,
        // hover) still shows through it, the way a colored list row does.
        ...(tint ? { backgroundImage: `linear-gradient(${tint}, ${tint})` } : {}),
        // One soft line for every active tab, colored or not.
        ...(active ? { boxShadow: `inset 0 2px 0 color-mix(in srgb, ${ink} 55%, transparent)` } : {}),
      }}
      className={`group relative flex items-center gap-2 h-9 ${pinned ? 'min-w-[96px] max-w-[160px] flex-[0_1_160px]' : 'min-w-[110px] max-w-[220px] flex-[0_1_220px]'} ps-3 pe-1.5 rounded-t-[9px] text-[13px] cursor-pointer select-none transition-colors ${
        active
          ? 'bg-surface-2 border border-b-0 border-divider text-neutral-900 dark:text-neutral-100 -mb-px h-[calc(2.25rem+1px)] z-10'
          : 'border border-transparent border-b-0 text-neutral-500 dark:text-neutral-400 hover:bg-neutral-200/50 dark:hover:bg-neutral-800/50 hover:text-neutral-800 dark:hover:text-neutral-200'
      } ${dragging ? 'opacity-50' : ''}`}
    >
      {domain ? (
        <span className="shrink-0 flex" aria-hidden="true"><Favicon domain={domain} size={14} /></span>
      ) : (
        <Icon
          size={14}
          aria-hidden="true"
          className={`shrink-0 ${color ? '' : active ? glyphColor : 'opacity-80'}`}
          style={color ? { color: ink } : undefined}
        />
      )}
      <span dir="auto" className={`flex-1 min-w-0 truncate ${active ? 'font-medium' : ''}`}>{title}</span>
      {pinned ? (
        <PushPin size={12} weight="fill" aria-hidden="true" className="shrink-0 mx-1 opacity-60" />
      ) : (
      <button
        type="button"
        aria-label={closeLabel}
        onClick={(e) => { e.stopPropagation(); onClose(); }}
        className={`shrink-0 flex items-center justify-center w-5 h-5 rounded-md hover:bg-neutral-900/10 dark:hover:bg-white/10 ${
          active ? '' : 'opacity-0 group-hover:opacity-100 focus-visible:opacity-100'
        }`}
      >
        <X size={11} />
      </button>
      )}
      {dropSide && (
        <span
          aria-hidden="true"
          className={`absolute top-0.5 bottom-0.5 w-[3px] rounded-full bg-accent z-20 pointer-events-none ${
            dropSide === 'before' ? '-start-px' : '-end-px'
          }`}
        />
      )}
      {divider && !dropSide && (
        <span
          aria-hidden="true"
          className="absolute end-0 top-1/2 -translate-y-1/2 h-4 w-px bg-divider group-hover:opacity-0"
        />
      )}
    </div>
  );
}
