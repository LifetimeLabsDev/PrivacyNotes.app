import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { Editor as TipTapEditor } from '@tiptap/react';
import { ListBullets, X } from './icons';
import { HoverLabel } from './HoverLabel';
import { EditorSlotPill } from './EditorSlotPill';
import { CALLOUT_BY_TYPE, type CalloutType } from './calloutTypes';

type OutlineItem = { pos: number; level: number; text: string; callout?: CalloutType };

/**
 * Walk the document and collect every heading and callout with its position,
 * level and text. Display-only - reads the doc, never mutates it. Headings and
 * callouts are leaf entries; we don't descend into their content (a callout
 * contributes one entry - its title - not its body's headings).
 */
function readHeadings(editor: TipTapEditor): OutlineItem[] {
  const out: OutlineItem[] = [];
  editor.state.doc.descendants((node, pos) => {
    if (node.type.name === 'heading') {
      out.push({ pos, level: node.attrs.level ?? 1, text: node.textContent.trim() });
      return false;
    }
    if (node.type.name === 'callout') {
      // The title is the callout's first child (calloutTitle); it may be empty,
      // in which case the render falls back to the type label.
      const title = node.firstChild?.textContent.trim() ?? '';
      out.push({ pos, level: 1, text: title, callout: (node.attrs.type ?? 'info') as CalloutType });
      return false;
    }
    return true;
  });
  return out;
}

/** Cheap structural signature so we only re-render when the outline changes. */
function sig(hs: OutlineItem[]): string {
  return hs.map((h) => `${h.pos}:${h.level}:${h.callout ?? ''}:${h.text}`).join('|');
}

/**
 * The measurable element for a doc position. nodeDOM is typed Node | null
 * and Firefox does return a bare text node here (Chrome returns the
 * element) - calling Element methods on it unguarded crashed the whole
 * app to a white page. Fall back to the nearest parent element.
 */
function elementAt(editor: TipTapEditor, pos: number): Element | null {
  const dom = editor.view.nodeDOM(pos);
  if (dom instanceof Element) return dom;
  return dom?.parentElement ?? null;
}

// Right-gutter width (px) the OPEN panel asks the editor to keep clear of
// text. The collapsed pill asks for nothing: it parks in the click row that
// sits above every note body, so there is no content under it to displace.
const PANEL_RESERVE = 240;

type Props = {
  editor: TipTapEditor;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /**
   * Reports the top-right footprint (px) the editor floats content around.
   * Width is the reserved strip, height the panel's measured height, so
   * content reclaims full width below it. Zero while collapsed - the pill
   * lives in the editor's top click row, above the body.
   */
  onReserve?: (reserve: { width: number; height: number }) => void;
};

/**
 * Document outline. A twin of the FindBar: it lives in the same zero-height
 * sticky slot pinned top-right of the note body, and the parent (Editor)
 * keeps it mutually exclusive with find. Collapsed it is a single toggle
 * button; open it is a Card panel listing the note's headings. Clicking a
 * heading scrolls it into view; a scroll-spy marks the section you're in.
 *
 * Renders nothing when the note has no headings - there is nothing to outline.
 */
export function OutlinePanel({ editor, open, onOpenChange, onReserve }: Props) {
  const { t } = useTranslation('editor');
  const [headings, setHeadings] = useState<OutlineItem[]>(() => readHeadings(editor));
  const [activePos, setActivePos] = useState<number>(-1);
  const rootRef = useRef<HTMLElement>(null);

  // Keep the list in sync with the document, but skip the re-render when the
  // set of headings is unchanged (the common case while typing body text).
  useEffect(() => {
    const refresh = () =>
      setHeadings((prev) => {
        const next = readHeadings(editor);
        return sig(prev) === sig(next) ? prev : next;
      });
    refresh();
    editor.on('update', refresh);
    return () => { editor.off('update', refresh); };
  }, [editor]);

  // Scroll-spy: the active heading is the last one whose top has passed the
  // activation line (the top of this slot, which sits just under the sticky
  // chrome). Recomputed on any scroll - capture phase so it fires for the
  // editor's own scroll container, whichever ancestor that is.
  const recomputeActive = useCallback(() => {
    if (!open || editor.isDestroyed) return;
    const first = headings[0];
    if (!first) return;
    const lineY = (rootRef.current?.getBoundingClientRect().top ?? 0) + 8;
    let active = first.pos;
    for (const h of headings) {
      const dom = elementAt(editor, h.pos);
      if (dom && dom.getBoundingClientRect().top <= lineY) active = h.pos;
    }
    setActivePos(active);
  }, [open, editor, headings]);

  useEffect(() => {
    if (!open) return;
    let raf = 0;
    const onScroll = () => {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(recomputeActive);
    };
    recomputeActive();
    window.addEventListener('scroll', onScroll, true);
    window.addEventListener('resize', onScroll);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('scroll', onScroll, true);
      window.removeEventListener('resize', onScroll);
    };
  }, [open, recomputeActive]);

  const jumpTo = useCallback((pos: number) => {
    if (editor.isDestroyed) return;
    elementAt(editor, pos)?.scrollIntoView({ block: 'start', behavior: 'smooth' });
    setActivePos(pos);
  }, [editor]);

  // Tell the editor the footprint to float content around: nothing when there
  // are no headings or the panel is collapsed (the pill sits in the top click
  // row, over no content), the panel's width plus its measured height when
  // open (a ResizeObserver keeps the height current as headings are
  // added/removed). The cleanup resets it when find takes over the slot.
  useLayoutEffect(() => {
    if (headings.length === 0) { onReserve?.({ width: 0, height: 0 }); return; }
    if (!open) { onReserve?.({ width: 0, height: 0 }); return; }
    const el = rootRef.current;
    if (!el) return;
    const report = () => onReserve?.({ width: PANEL_RESERVE, height: el.offsetHeight + 8 });
    report();
    const ro = new ResizeObserver(report);
    ro.observe(el);
    return () => ro.disconnect();
  }, [onReserve, headings.length, open]);
  useLayoutEffect(() => () => onReserve?.({ width: 0, height: 0 }), [onReserve]);

  if (headings.length === 0) return null;

  if (!open) {
    // The pill this slot is built around. Its shape now lives in
    // EditorSlotPill, shared with find, the text switch and the
    // invisible-characters toggle that sit beside it.
    return (
      <EditorSlotPill label={t('outline.title')} onClick={() => onOpenChange(true)}>
        <ListBullets size={16} />
      </EditorSlotPill>
    );
  }

  return (
    <nav
      ref={rootRef}
      aria-label={t('outline.ariaLabel')}
      onKeyDown={(e) => {
        if (e.key === 'Escape') { e.preventDefault(); onOpenChange(false); }
      }}
      className="pointer-events-auto mt-1 w-56 max-w-[70vw] flex flex-col overflow-hidden rounded-lg border border-divider bg-surface-1 shadow-lg"
    >
      <div className="flex items-center gap-1.5 px-2 py-1.5 border-b border-divider">
        <ListBullets size={15} className="text-neutral-500 dark:text-neutral-400 shrink-0" />
        <span className="text-sm font-medium text-neutral-700 dark:text-neutral-200">{t('outline.title')}</span>
        <span className="text-xs tabular-nums text-neutral-400 dark:text-neutral-500">{headings.length}</span>
        <div className="flex-1" />
        <HoverLabel label={t('outline.hideTitle')} position="below-end">
          <button
            type="button"
            onClick={() => onOpenChange(false)}
            aria-label={t('outline.hide')}
            className="flex items-center justify-center w-6 h-6 rounded text-neutral-500 dark:text-neutral-400 [@media(hover:hover)]:hover:bg-neutral-200 [@media(hover:hover)]:dark:hover:bg-neutral-800 active:scale-95 transition shrink-0 outline-none"
          >
            <X size={14} />
          </button>
        </HoverLabel>
      </div>
      <ul className="py-1 overflow-y-auto max-h-[min(50vh,320px)]">
        {headings.map((h) => {
          const isActive = h.pos === activePos;
          const label = h.text || (h.callout ? t(`callout.types.${h.callout}`) : t('common:state.untitled'));
          const CalloutIcon = h.callout ? CALLOUT_BY_TYPE[h.callout].icon : null;
          return (
            <li key={h.pos}>
              <button
                type="button"
                onClick={() => jumpTo(h.pos)}
                aria-current={isActive || undefined}
                // Native title (not HoverLabel): the pn-tip would be clipped
                // by this list's overflow-y-auto, like the rail scroll tier.
                title={label}
                style={{ paddingInlineStart: `${(Math.min(h.level, 4) - 1) * 12 + 8}px` }}
                className={`flex w-full items-center gap-1.5 pe-2 py-1 text-start text-sm transition outline-none [@media(hover:hover)]:hover:bg-neutral-200/70 [@media(hover:hover)]:dark:hover:bg-neutral-800/70 ${
                  isActive
                    ? 'bg-neutral-200/60 dark:bg-neutral-800/60 font-medium text-neutral-900 dark:text-neutral-100'
                    : !h.callout && h.level >= 3
                      ? 'text-neutral-400 dark:text-neutral-500'
                      : 'text-neutral-600 dark:text-neutral-300'
                }`}
              >
                <span className="flex w-4 shrink-0 items-center justify-center">
                  {CalloutIcon && <CalloutIcon size={14} weight="bold" color={CALLOUT_BY_TYPE[h.callout!].color} />}
                </span>
                <span className="truncate" dir="auto">{label}</span>
              </button>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}
