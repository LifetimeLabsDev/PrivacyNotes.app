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

export function TableControls({ editor }: { editor: TipTapEditor }) {
  const { t } = useTranslation('editor');
  const toolbarRef = useRef<HTMLDivElement>(null);

  // Position imperatively - no state, no re-render loop.
  // Runs on every render (parent re-renders on editor state changes).
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => {
    const toolbar = toolbarRef.current;
    if (!toolbar) return;
    if (!(editor.view as any).docView) { toolbar.style.display = 'none'; return; }

    const { $anchor } = editor.state.selection;
    let depth = $anchor.depth;
    let tablePos = -1;
    while (depth > 0) {
      if ($anchor.node(depth).type.name === 'table') {
        tablePos = $anchor.before(depth);
        break;
      }
      depth--;
    }
    if (tablePos < 0) { toolbar.style.display = 'none'; return; }

    let tableDOM: Node | null | undefined;
    try { tableDOM = editor.view.nodeDOM(tablePos); } catch { toolbar.style.display = 'none'; return; }
    if (!(tableDOM instanceof HTMLElement)) { toolbar.style.display = 'none'; return; }

    // Position relative to offsetParent (the editor wrapper with position:relative)
    const wrapper = toolbar.offsetParent as HTMLElement | null;
    if (!wrapper) { toolbar.style.display = 'none'; return; }
    const wrapperRect = wrapper.getBoundingClientRect();
    const tableRect = tableDOM.getBoundingClientRect();

    toolbar.style.display = '';
    toolbar.style.top = `${tableRect.bottom - wrapperRect.top}px`;
    toolbar.style.left = `${tableRect.left - wrapperRect.left}px`;
  });

  return (
    <div
      ref={toolbarRef}
      className="pn-table-toolbar"
      contentEditable={false}
      suppressContentEditableWarning
      style={{ position: 'absolute', zIndex: 10 }}
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
