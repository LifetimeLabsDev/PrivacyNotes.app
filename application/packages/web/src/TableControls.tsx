import { useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import {
  ArrowUp as ArrowUpIcon,
  ArrowDown as ArrowDownIcon,
  ArrowLeft as ArrowLeftIcon,
  ArrowRight as ArrowRightIcon,
  Trash as TrashIcon,
} from './icons';
import { type Editor as TipTapEditor } from '@tiptap/react';
import { HoverLabel } from './HoverLabel';

// ------------------------------------------------------------------
// Table Controls (floating toolbar glued below the active table)
// ------------------------------------------------------------------

/** Document position of the table the caret sits in, or -1 when it is outside one. */
function activeTablePos(editor: TipTapEditor): number {
  const { $anchor } = editor.state.selection;
  for (let depth = $anchor.depth; depth > 0; depth--) {
    if ($anchor.node(depth).type.name === 'table') return $anchor.before(depth);
  }
  return -1;
}

export function TableControls({ editor }: { editor: TipTapEditor }) {
  const { t } = useTranslation('editor');
  const toolbarRef = useRef<HTMLDivElement>(null);

  /**
   * Visibility and position both come from the editor, never from a React
   * render.
   *
   * A transaction does not re-render this tree: TipTap 3 leaves
   * `shouldRerenderOnTransaction` off, and the Editor component it lives in is
   * not memoized, so a render happens when some unrelated state happens to
   * change. Reading the caret at render time therefore answered whatever was
   * true at that unrelated moment - the bar stayed after the caret left the
   * table, refused to appear after it entered, and kept its old spot over the
   * new last row after Add row below. Subscribing to `transaction` covers every
   * caret move and every edit; the observer covers geometry that shifts with no
   * transaction at all, such as a window resize or an image above the table
   * finishing its load.
   *
   * The bar is hidden with `display: none` and measured against its own parent
   * rather than `offsetParent`, which is null while an element is hidden. That
   * makes the Editor root's `relative` a requirement of this component: keep
   * the bar a direct child of it.
   */
  useEffect(() => {
    const toolbar = toolbarRef.current;
    if (!toolbar) return;
    let frame = 0;

    const hide = () => { toolbar.style.display = 'none'; };

    const place = () => {
      frame = 0;
      if (editor.isDestroyed || !(editor.view as any).docView) return hide();

      const tablePos = activeTablePos(editor);
      if (tablePos < 0) return hide();

      let tableDOM: Node | null | undefined;
      try { tableDOM = editor.view.nodeDOM(tablePos); } catch { return hide(); }
      if (!(tableDOM instanceof HTMLElement)) return hide();

      const wrapper = toolbar.parentElement;
      if (!wrapper) return hide();
      const wrapperRect = wrapper.getBoundingClientRect();
      const tableRect = tableDOM.getBoundingClientRect();

      toolbar.style.display = '';
      toolbar.style.top = `${tableRect.bottom - wrapperRect.top}px`;
      toolbar.style.left = `${tableRect.left - wrapperRect.left}px`;
    };

    // One measurement per frame, however many transactions land in it.
    const schedule = () => { if (!frame) frame = requestAnimationFrame(place); };

    place();
    editor.on('transaction', schedule);
    const observer = new ResizeObserver(schedule);
    observer.observe(editor.view.dom);
    return () => {
      editor.off('transaction', schedule);
      observer.disconnect();
      if (frame) cancelAnimationFrame(frame);
    };
  }, [editor]);

  return (
    <div
      ref={toolbarRef}
      className="pn-table-toolbar"
      contentEditable={false}
      suppressContentEditableWarning
      style={{ position: 'absolute', zIndex: 10, display: 'none' }}
    >
      {/* + Row above */}
      <HoverLabel label={t('table.addRowAbove')} position="below">
        <button type="button" className="pn-table-toolbar-btn" onPointerDown={(e) => { e.preventDefault(); e.stopPropagation(); editor.chain().focus().addRowBefore().run(); }}>
          <ArrowUpIcon size={16} />
        </button>
      </HoverLabel>
      {/* + Row below */}
      <HoverLabel label={t('table.addRowBelow')} position="below">
        <button type="button" className="pn-table-toolbar-btn" onPointerDown={(e) => { e.preventDefault(); e.stopPropagation(); editor.chain().focus().addRowAfter().run(); }}>
          <ArrowDownIcon size={16} />
        </button>
      </HoverLabel>
      <div className="pn-table-toolbar-divider" />
      {/* + Col left */}
      <HoverLabel label={t('table.addColumnLeft')} position="below">
        <button type="button" className="pn-table-toolbar-btn" onPointerDown={(e) => { e.preventDefault(); e.stopPropagation(); editor.chain().focus().addColumnBefore().run(); }}>
          <ArrowLeftIcon size={16} />
        </button>
      </HoverLabel>
      {/* + Col right */}
      <HoverLabel label={t('table.addColumnRight')} position="below">
        <button type="button" className="pn-table-toolbar-btn" onPointerDown={(e) => { e.preventDefault(); e.stopPropagation(); editor.chain().focus().addColumnAfter().run(); }}>
          <ArrowRightIcon size={16} />
        </button>
      </HoverLabel>
      <div className="pn-table-toolbar-divider" />
      {/* Header row on/off. New tables carry one, and it is what lets a table
          be written as a pipe table rather than as raw HTML, so turning it off
          is a choice worth being able to reverse. */}
      <HoverLabel label={t('table.toggleHeaderRow')} position="below">
        <button type="button" className="pn-table-toolbar-btn" onPointerDown={(e) => { e.preventDefault(); e.stopPropagation(); editor.chain().focus().toggleHeaderRow().run(); }}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 5h16v4H4z" fill="currentColor" stroke="none"/><rect x="3" y="4" width="18" height="16" rx="1"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="12" y1="9" x2="12" y2="20"/></svg>
        </button>
      </HoverLabel>
      <div className="pn-table-toolbar-divider" />
      {/* Delete row */}
      <HoverLabel label={t('table.deleteRow')} position="below">
        <button type="button" className="pn-table-toolbar-btn pn-table-toolbar-danger" onPointerDown={(e) => { e.preventDefault(); e.stopPropagation(); editor.chain().focus().deleteRow().run(); }}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="8" width="18" height="8" rx="1"/><line x1="9" y1="11" x2="9" y2="13"/><line x1="15" y1="11" x2="15" y2="13"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/></svg>
        </button>
      </HoverLabel>
      {/* Delete column */}
      <HoverLabel label={t('table.deleteColumn')} position="below">
        <button type="button" className="pn-table-toolbar-btn pn-table-toolbar-danger" onPointerDown={(e) => { e.preventDefault(); e.stopPropagation(); editor.chain().focus().deleteColumn().run(); }}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="8" y="3" width="8" height="18" rx="1"/><line x1="11" y1="9" x2="11" y2="15"/><line x1="13" y1="9" x2="13" y2="15"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/></svg>
        </button>
      </HoverLabel>
      <div className="pn-table-toolbar-divider" />
      {/* Delete table */}
      <HoverLabel label={t('table.deleteTable')} position="below">
        <button type="button" className="pn-table-toolbar-btn pn-table-toolbar-danger" onPointerDown={(e) => { e.preventDefault(); e.stopPropagation(); editor.chain().focus().deleteTable().run(); }}>
          <TrashIcon size={16} />
        </button>
      </HoverLabel>
    </div>
  );
}
