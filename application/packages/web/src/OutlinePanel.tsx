import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { Editor as TipTapEditor } from '@tiptap/react';
import type { Transaction } from '@tiptap/pm/state';
import { BracketsSquare, CaretDown, Check, LinkSimple, ListBullets, X } from './icons';
import { ContextMenu, useContextMenu } from './ContextMenu';
import { shortcutUrl, isShortcutId } from './noteShortcut';
import { useCopyToClipboard } from './clipboard';
import { getWikiLinkCurrentNote } from './NoteLinkSuggestion';
import { headingCodeAt, headingsFromDoc } from './noteHeadings';
import { noteLinkTarget } from './noteLinks';
import { HoverLabel } from './HoverLabel';
import { keyText } from './shortcutMatch';
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

/**
 * The rows the panel shows once some branches are folded. A heading folds the
 * rows after it up to the next heading at its level or higher. A callout is
 * content of the section above it: it hides with that section, never ends
 * one, and never folds anything itself, so its row indents one step under
 * the heading above it. `shownAs` maps a hidden row to the folded heading
 * that stands in for it, so the scroll-spy still marks a row.
 */
export function foldOutline(items: OutlineItem[], folded: ReadonlySet<number>) {
  const rows: { item: OutlineItem; hasKids: boolean; depth: number }[] = [];
  const hiddenUnder = new Map<number, number>();
  let fold: OutlineItem | null = null;
  let sectionLevel = 0;
  items.forEach((item, i) => {
    if (!item.callout) sectionLevel = item.level;
    if (fold && (item.callout || item.level > fold.level)) {
      hiddenUnder.set(item.pos, fold.pos);
      return;
    }
    fold = null;
    const next = items[i + 1];
    const hasKids = !item.callout && !!next && (!!next.callout || next.level > item.level);
    const depth = Math.min(item.callout ? sectionLevel + 1 : item.level, 4);
    rows.push({ item, hasKids, depth });
    if (hasKids && folded.has(item.pos)) fold = item;
  });
  return { rows, shownAs: (pos: number) => hiddenUnder.get(pos) ?? pos };
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

type Props = {
  editor: TipTapEditor;
  open: boolean;
  onOpenChange: (open: boolean) => void;
};

/**
 * Document outline. A twin of the FindBar: it lives in the same zero-height
 * sticky slot pinned top-right of the note body, and the parent (Editor)
 * keeps it mutually exclusive with find. Collapsed it is a single toggle
 * button; open it is a Card panel listing the note's headings. Clicking a
 * heading scrolls it into view; a scroll-spy marks the section you're in.
 * A heading row carries a link icon with two copies: `[[Note#Heading]]`, the
 * note-link that opens this note at that heading, and the shortcut that
 * opens it from other apps. It shows on hover and on
 * the active row, and on every row of a touch screen, which has no hover.
 *
 * Renders nothing when the note has no headings - there is nothing to outline.
 */
export function OutlinePanel({ editor, open, onOpenChange }: Props) {
  const { t } = useTranslation('editor');
  const [headings, setHeadings] = useState<OutlineItem[]>(() => readHeadings(editor));
  const [activePos, setActivePos] = useState<number>(-1);
  // Positions of the folded headings. A view state of this panel only: the
  // editor remounts per note, so a fold never outlives its note.
  const [folded, setFolded] = useState<ReadonlySet<number>>(() => new Set());
  const rootRef = useRef<HTMLElement>(null);
  const { copy, copied } = useCopyToClipboard();
  const linkMenu = useContextMenu();

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

  // An edit above a folded heading moves it; map the fold along with it.
  useEffect(() => {
    const remap = ({ transaction }: { transaction: Transaction }) => {
      if (!transaction.docChanged) return;
      setFolded((prev) => (prev.size === 0 ? prev : new Set([...prev].map((p) => transaction.mapping.map(p)))));
    };
    editor.on('transaction', remap);
    return () => { editor.off('transaction', remap); };
  }, [editor]);

  const toggleFold = useCallback((pos: number) => {
    setFolded((prev) => {
      const next = new Set(prev);
      if (!next.delete(pos)) next.add(pos);
      return next;
    });
  }, []);

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

  if (headings.length === 0) return null;
  const outline = foldOutline(headings, folded);
  const currentPos = outline.shownAs(activePos);
  // Only a heading a link can find gets the icon: not a callout, and not a
  // heading inside a quote. Outside the notes app (a Markdown folder file)
  // the editor names no note, so no row does.
  const linkNote = getWikiLinkCurrentNote(editor);
  const linkable = new Set(linkNote ? headingsFromDoc(editor.state.doc).map((h) => h.pos) : []);

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
        <ListBullets size={15} className="text-pn-muted shrink-0" />
        <span className="text-sm font-medium text-pn-soft">{t('outline.title')}</span>
        <span className="text-xs tabular-nums text-pn-muted">{headings.length}</span>
        <div className="flex-1" />
        <HoverLabel label={t('outline.hideTitle', { keys: keyText('outline') })} position="start">
          <button
            type="button"
            onClick={() => onOpenChange(false)}
            aria-label={t('outline.hide')}
            className="flex items-center justify-center w-6 h-6 rounded text-pn-muted [@media(hover:hover)]:hover:bg-pn/10 active:scale-95 transition shrink-0 outline-none"
          >
            <X size={14} />
          </button>
        </HoverLabel>
      </div>
      <ul className="py-1 overflow-y-auto max-h-[min(50vh,320px)]">
        {outline.rows.map(({ item: h, hasKids, depth }) => {
          const isActive = h.pos === currentPos;
          const isFolded = hasKids && folded.has(h.pos);
          const label = h.text || (h.callout ? t(`callout.types.${h.callout}`) : t('common:state.untitled'));
          const CalloutIcon = h.callout ? CALLOUT_BY_TYPE[h.callout].icon : null;
          const indent = (depth - 1) * 12 + 8;
          const canLink = linkNote !== null && linkable.has(h.pos);
          const isCopied = copied === String(h.pos);
          return (
            <li key={h.pos} className="group relative">
              <button
                type="button"
                onClick={() => jumpTo(h.pos)}
                aria-current={isActive || undefined}
                // Native title (not HoverLabel): the pn-tip would be clipped
                // by this list's overflow-y-auto, like the rail scroll tier.
                title={label}
                style={{ paddingInlineStart: `${indent}px` }}
                className={`flex w-full items-center gap-1.5 ${canLink ? 'pe-7' : 'pe-2'} py-1 text-start text-sm transition outline-none [@media(hover:hover)]:hover:bg-pn/5 ${
                  isActive
                    ? 'bg-pn/10 font-medium text-pn'
                    : !h.callout && h.level >= 3
                      ? 'text-pn-muted'
                      : 'text-pn-soft'
                }`}
              >
                <span className="flex w-4 shrink-0 items-center justify-center">
                  {CalloutIcon && <CalloutIcon size={14} weight="bold" color={CALLOUT_BY_TYPE[h.callout!].color} />}
                </span>
                <span className="truncate" dir="auto">{label}</span>
              </button>
              {canLink && (
                <button
                  type="button"
                  onClick={(e) => {
                    const noteLink = `[[${noteLinkTarget(linkNote.title)}#${noteLinkTarget(h.text)}]]`;
                    const code = isShortcutId(linkNote.id) ? headingCodeAt(editor.state.doc, linkNote.id, h.pos) : null;
                    if (!code) {
                      copy(noteLink, String(h.pos));
                      return;
                    }
                    // Two links to the same heading: the note-link for inside
                    // the notes, the shortcut for other apps.
                    // Spec: ops/docs/plans/note-shortcuts.md (4)
                    const r = e.currentTarget.getBoundingClientRect();
                    const rtl = document.documentElement.dir === 'rtl';
                    linkMenu.open(
                      { clientX: rtl ? r.left : r.right, clientY: r.bottom + 4, preventDefault: () => e.preventDefault(), stopPropagation: () => e.stopPropagation() },
                      [
                        { label: t('outline.copyNoteLink'), icon: <BracketsSquare size={14} aria-hidden="true" />, onSelect: () => copy(noteLink, String(h.pos)) },
                        { label: t('outline.copyHeadingShortcut'), icon: <LinkSimple size={14} aria-hidden="true" />, onSelect: () => copy(shortcutUrl(linkNote.id, code), String(h.pos)) },
                      ],
                      e.detail === 0,
                      undefined,
                      true,
                    );
                  }}
                  aria-label={isCopied ? t('outline.copied') : t('outline.copyHeadingLink')}
                  className={`absolute inset-y-0 end-1 flex w-6 items-center justify-center rounded transition outline-none focus-visible:opacity-100 [@media(hover:none)]:opacity-100 ${
                    isCopied
                      ? 'opacity-100 text-accent'
                      : `text-pn-muted [@media(hover:hover)]:hover:text-accent ${isActive ? 'opacity-100' : 'opacity-0 group-hover:opacity-100'}`
                  }`}
                >
                  {/* No tip: the list clips any tip that leaves its visible
                      part, and the menu this icon opens names both links. */}
                  {isCopied
                    ? <Check size={14} weight="bold" aria-hidden="true" />
                    : <LinkSimple size={14} aria-hidden="true" />}
                </button>
              )}
              {/* The fold arrow sits over the row's icon slot, which a heading
                  leaves empty. A sibling of the row, because a button may not
                  hold another button; the folder tree's caret and labels. */}
              {hasKids && (
                <button
                  type="button"
                  onClick={() => toggleFold(h.pos)}
                  aria-expanded={!isFolded}
                  aria-label={isFolded ? t('shell:folders.expand') : t('shell:folders.collapse')}
                  title={isFolded ? t('shell:folders.expand') : t('shell:folders.collapse')}
                  style={{ insetInlineStart: `${indent}px` }}
                  className="absolute inset-y-0 flex w-4 items-center justify-center text-pn-muted [@media(hover:hover)]:hover:text-accent transition outline-none"
                >
                  <CaretDown
                    size={10}
                    weight="bold"
                    aria-hidden="true"
                    className={`transition-transform ${isFolded ? '-rotate-90 rtl:rotate-90' : ''}`}
                  />
                </button>
              )}
            </li>
          );
        })}
      </ul>
      <ContextMenu state={linkMenu.state} onClose={linkMenu.close} />
    </nav>
  );
}
