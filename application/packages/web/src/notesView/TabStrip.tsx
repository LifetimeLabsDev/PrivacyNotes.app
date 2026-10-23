import { useCallback, useContext, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { LocalNote } from '../db';
import type { ContextMenuItem } from '../ContextMenu';
import { ArrowsInLineHorizontal, CaretDown, PushPin, X, XSquare } from '../icons';
import { LooksContext, PathGlyph, useNoteIconPaths } from '../looks/LookGlyph';
import { resolveNoteLook, type NoteLook } from '../itemStyles';
import { noteFaviconDomain, typeGlyph } from '../NoteRow';
import { Favicon } from '../VaultItem';
import { OverflowTip } from '../OverflowTip';
import { HoverLabel } from '../HoverLabel';

/** The width of a pinned tab, which is its icon alone (`w-10` on the tab). */
const PINNED_WIDTH = 40;

/**
 * The tabs above the editor. It owns no state: the list of tabs comes from
 * `useOpenTabs`, and the active tab is whichever one holds the open item, so
 * an item opened from the list leaves every tab unmarked. A pinned tab is its
 * icon alone. When the tabs do not fit, a count at the end names how many are
 * out of view and opens a list of them. In zen mode the strip is quiet
 * (titles only, on the editor surface, the active tab marked by its text and a
 * thin underline), with the same widths, count and list: only the look changes.
 * Spec: ops/docs/archive/note-tabs.md (section 3)
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
  zen = false,
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
  /** The zen look: no icons, pin marks, dividers, tints or raised card. */
  zen?: boolean;
}) {
  const { t } = useTranslation('shell');
  const stripRef = useRef<HTMLDivElement | null>(null);
  const pinnedRef = useRef<HTMLDivElement | null>(null);
  // Pinned tabs come first in `tabs`, so they are its first `pinnedCount`.
  const pinnedCount = tabs.filter((n) => pinnedIds.has(n.id)).length;
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

  // The tabs wholly or partly out of view; the count at the end names how
  // many and lists them.
  const [hidden, setHidden] = useState<string[]>([]);
  /** Whether tabs continue past the start or the end of the view. */
  const [cut, setCut] = useState({ start: false, end: false, rtl: false });
  const measure = useCallback(() => {
    const el = stripRef.current;
    if (!el) return;
    // The pinned group stays in view and covers the start of the strip, so a
    // tab under it is out of view too.
    const box = el.getBoundingClientRect();
    let { left, right } = box;
    const pin = pinnedRef.current?.getBoundingClientRect();
    if (pin) {
      if (getComputedStyle(el).direction === 'rtl') right = pin.left;
      else left = pin.right;
    }
    const out: string[] = [];
    el.querySelectorAll<HTMLElement>('[role="tab"]').forEach((tab) => {
      if (pinnedRef.current?.contains(tab)) return;
      const r = tab.getBoundingClientRect();
      if ((r.left < left - 1 || r.right > right + 1) && tab.dataset.tabId) out.push(tab.dataset.tabId);
    });
    setHidden((prev) => (prev.length === out.length && prev.every((id, i) => id === out[i]) ? prev : out));
    // scrollLeft runs negative in a right-to-left strip.
    const past = Math.abs(el.scrollLeft);
    const next = { start: past > 1, end: past + el.clientWidth < el.scrollWidth - 1, rtl: getComputedStyle(el).direction === 'rtl' };
    setCut((prev) => (prev.start === next.start && prev.end === next.end && prev.rtl === next.rtl ? prev : next));
  }, []);
  useEffect(() => {
    const el = stripRef.current;
    if (!el) return;
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    el.addEventListener('scroll', measure, { passive: true });
    return () => { ro.disconnect(); el.removeEventListener('scroll', measure); };
  }, [measure, tabs.length, pinnedCount, activeId, zen]);

  const moreTabs = (): ContextMenuItem[] => tabs.filter((n) => hidden.includes(n.id)).map((n) => {
    const { Icon } = typeGlyph(n.type);
    return { label: titleOf(n), icon: <Icon size={14} />, onSelect: () => onActivate(n.id) };
  });

  const activeAt = tabs.findIndex((n) => n.id === activeId);
  // The row's own color rule (`useNoteColor` resolves the same way), read here
  // rather than per tab because a divider depends on both of its neighbours.
  const { styles, tintNotes, noteColorStyle, filter } = useContext(LooksContext);
  const looks = tabs.map((n) => resolveNoteLook(n.id, n.tags, n.folderId, styles, tintNotes, noteColorStyle, filter));
  // A hairline only between two plain resting tabs: the active tab and a
  // tinted tab each have their own edges, and a line against those reads as
  // a stray mark. An accent tab has no tint, so it keeps its line.
  const plain = (i: number) => i !== activeAt && looks[i]?.style !== 'background';

  const renderTab = (n: LocalNote, i: number) => (
        <Tab
          key={n.id}
          note={n}
          title={titleOf(n)}
          gated={isGated(n)}
          look={looks[i] ?? null}
          active={i === activeAt}
          pinned={pinnedIds.has(n.id)}
          divider={!zen && i < tabs.length - 1 && plain(i) && plain(i + 1)}
          zen={zen}
          cutOff={hidden.includes(n.id)}
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
  );

  // A tab cut by an edge of the view fades out there instead of ending in
  // the middle of a letter. Overlays in the strip's own color rather than a
  // mask, because a mask would also hide the title tips below the strip.
  const fade = (side: 'start' | 'end') => (
    <span
      aria-hidden="true"
      className={`absolute top-0 bottom-0 w-6 z-30 pointer-events-none ${side === 'start' ? '' : 'end-0'}`}
      style={{
        ...(side === 'start' ? { insetInlineStart: pinnedCount * PINNED_WIDTH } : {}),
        background: `linear-gradient(to ${(side === 'start') !== cut.rtl ? 'right' : 'left'}, rgb(var(${zen ? '--pn-surface-2' : '--pn-surface-1'})), transparent)`,
      }}
    />
  );

  return (
    <div className={`flex items-end shrink-0 border-b border-divider ps-2 ${zen ? '' : 'bg-surface-1'}`}>
    <div className="relative flex-1 min-w-0 flex">
    {cut.start && fade('start')}
    {cut.end && fade('end')}
    <div
      ref={stripRef}
      role="tablist"
      aria-label={t('tabStrip.label')}
      className="flex-1 min-w-0 flex items-end overflow-x-auto scrollbar-none pt-1"
      // A tab scrolled into view stops beside the pinned group, not under it.
      style={pinnedCount > 0 ? { scrollPaddingInlineStart: pinnedCount * PINNED_WIDTH } : undefined}
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
      {pinnedCount > 0 && (
        // The pinned tabs stay at the start while the rest scroll, as in a
        // browser. The group is opaque, on the strip's own surface, so a tab
        // scrolling under it does not show through.
        <div ref={pinnedRef} className={`sticky start-0 z-20 flex items-end shrink-0 ${zen ? 'bg-surface-2' : 'bg-surface-1'}`}>
          {tabs.slice(0, pinnedCount).map((n, i) => renderTab(n, i))}
        </div>
      )}
      {tabs.slice(pinnedCount).map((n, i) => renderTab(n, i + pinnedCount))}
    </div>
    </div>
    {hidden.length > 0 && (
      <HoverLabel label={t('tabStrip.moreTabs')} position="below" className="shrink-0">
        <button
          type="button"
          aria-label={t('tabStrip.moreTabs')}
          onClick={(e) => onContextMenu(e, moreTabs())}
          className={`flex items-center gap-0.5 h-7 mb-0.5 mx-1 px-2 rounded-md text-[12px] tabular-nums text-pn-muted hover:text-pn ${zen ? '' : 'hover:bg-pn/5'}`}
        >
          <CaretDown size={12} aria-hidden="true" />
          {hidden.length}
        </button>
      </HoverLabel>
    )}
    </div>
  );
}

/**
 * One tab. The item's type glyph (or its site's icon) and its color come from
 * the same helpers the list row uses, so a tab and its row always match.
 */
function Tab({
  note: n, title, gated, look, active, pinned, divider, zen, cutOff, dragging, dropSide, closeLabel,
  onActivate, onClose, onContextMenu, onDragStart, onDragEnd, onDragOverSide,
}: {
  note: LocalNote;
  title: string;
  gated: boolean;
  look: NoteLook | null;
  active: boolean;
  /** Its icon alone, no X, and deaf to the middle button. */
  pinned: boolean;
  divider: boolean;
  zen: boolean;
  /** Partly out of view: it offers no X, so a click on the sliver that shows
   *  only opens it (and scrolls it into view) and never closes it. */
  cutOff: boolean;
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
  // The note's own icon wins over its site icon, so a pinned tab can be told
  // apart from the next one.
  const iconPaths = useNoteIconPaths(n.id);
  const domain = gated || iconPaths ? '' : noteFaviconDomain(n);
  // While a site has no icon to show, the tab draws its type glyph, as a
  // list row draws its themed placeholder; the Favicon stays mounted
  // (hidden) so it can still load and report back.
  const [noIcon, setNoIcon] = useState(false);
  const onMissing = useCallback((m: boolean) => setNoIcon(m), []);
  const color = look?.color ?? null;
  // Only a background look tints the tab; an accent keeps it plain and
  // colors the icon alone.
  const tint = look?.style === 'background' ? `var(--pn-label-${look.color}-tint)` : null;
  const ink = color ? `var(--pn-label-${color}-ink)` : 'var(--color-accent)';

  // In zen the icon only marks a pinned tab, so it drops the item color.
  const plainGlyph = zen;
  const glyph = (
    <>
      {domain && (
        <span
          className={noIcon ? 'hidden' : 'shrink-0 flex rounded-[4px]'}
          aria-hidden="true"
          // A site icon cannot take the ink, so an accent lays the tint
          // behind it instead.
          style={!plainGlyph && look?.style === 'accent' ? { padding: 2, margin: -2, background: `var(--pn-label-${look.color}-tint)` } : undefined}
        >
          <Favicon domain={domain} size={14} onMissing={onMissing} />
        </span>
      )}
      {iconPaths ? (
        <PathGlyph
          paths={iconPaths}
          size={14}
          className={`shrink-0 ${plainGlyph ? '' : color ? '' : active ? glyphColor : 'opacity-80'}`}
          style={!plainGlyph && color ? { color: ink } : undefined}
        />
      ) : (!domain || noIcon) && (
        <Icon
          size={14}
          aria-hidden="true"
          className={`shrink-0 ${plainGlyph ? '' : color ? '' : active ? glyphColor : 'opacity-80'}`}
          style={!plainGlyph && color ? { color: ink } : undefined}
        />
      )}
    </>
  );

  return (
    <div
      role="tab"
      aria-selected={active}
      tabIndex={active ? 0 : -1}
      data-tab-id={n.id}
      aria-label={title}
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
      style={zen ? undefined : {
        // The tint is drawn as an image, so the surface underneath (active,
        // hover) still shows through it, the way a colored list row does.
        ...(tint ? { backgroundImage: `linear-gradient(${tint}, ${tint})` } : {}),
        // One soft line for every active tab, colored or not.
        ...(active ? { boxShadow: `inset 0 2px 0 color-mix(in srgb, ${ink} 55%, transparent)` } : {}),
      }}
      className={`group relative flex items-center gap-2 h-8 ${pinned ? 'w-10 flex-none justify-center' : 'min-w-[110px] max-w-[220px] flex-[0_1_220px] ps-3 pe-1.5'} rounded-t-[9px] text-[13px] cursor-pointer select-none transition-colors ${
        zen
          ? active ? 'text-pn' : 'text-pn-muted hover:text-pn'
          : active
            ? 'bg-surface-2 border border-b-0 border-divider text-pn -mb-px h-[calc(2rem+1px)] z-10'
            : 'border border-transparent border-b-0 text-pn-muted hover:bg-pn/5 hover:text-pn'
      } ${dragging ? 'opacity-50' : ''}`}
    >
      {pinned ? (
        // A pinned tab is its icon alone, as in a browser, in zen too, so
        // both looks share one width; its title shows in the tip every time.
        // The wrapper covers the tab's 1 px border, so the tip lines up with
        // the tab's outer edge.
        <OverflowTip text={title} always className="flex items-center justify-center -mx-px w-[calc(100%+2px)] h-full">
          {glyph}
        </OverflowTip>
      ) : (
        <>
          {!zen && glyph}
          {/* The full title in the app's own tip, and only when it is cut
              off. On a resting tab the X takes no room until hover, when
              the title gives way to it. */}
          <OverflowTip text={title} className={`flex-1 min-w-0 flex ${active || cutOff ? '' : 'group-hover:pe-6 group-focus-within:pe-6'}`}>
            <span dir="auto" className={`min-w-0 truncate ${active && !zen ? 'font-medium' : ''}`}>{title}</span>
          </OverflowTip>
          {!cutOff && <button
            type="button"
            aria-label={closeLabel}
            onClick={(e) => { e.stopPropagation(); onClose(); }}
            className={`flex items-center justify-center w-5 h-5 rounded-md hover:bg-pn/10 ${
              active ? 'shrink-0' : 'absolute end-1.5 top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 focus-visible:opacity-100'
            }`}
          >
            <X size={11} />
          </button>}
        </>
      )}
      {dropSide && (
        <span
          aria-hidden="true"
          className={`absolute top-0.5 bottom-0.5 w-[3px] rounded-full bg-accent-fill z-20 pointer-events-none ${
            dropSide === 'before' ? '-start-px' : '-end-px'
          }`}
        />
      )}
      {/* The zen mark of the active tab: inside the tab, because the strip
          scrolls sideways and so cuts anything drawn over its hairline. */}
      {zen && active && (
        <span aria-hidden="true" className="absolute inset-x-3 bottom-0 h-px bg-current opacity-40 pointer-events-none" />
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
