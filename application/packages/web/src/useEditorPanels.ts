import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type RefObject,
} from 'react';
import { type Editor as TipTapEditor } from '@tiptap/react';
import { getActiveMatchRange } from './editorSearch';
import { readOutlinePref, writeOutlinePref } from './editorPrefs';

/**
 * Height of the always-present click row above the note body (rendered by
 * Editor.tsx). It is the collapsed outline pill's parking space - 32px of
 * button plus its 4px top margin - so the pill sits in a row of its own
 * instead of on the note's first block.
 */
export const EDITOR_TOP_GAP_PX = 36;

export function useEditorPanels({
  rootRef,
  editorRef,
  editor,
  isMobile,
  readOnly,
  toolbarVisible,
}: {
  rootRef: RefObject<HTMLDivElement | null>;
  editorRef: RefObject<TipTapEditor | null>;
  editor: TipTapEditor | null;
  isMobile: boolean;
  readOnly: boolean;
  toolbarVisible: boolean;
}) {
  // Find-in-note bar. Opened by Cmd/Ctrl+F; focusTick bumps so a repeated
  // Cmd/Ctrl+F refocuses + selects the input even while it is already open.
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchFocusTick, setSearchFocusTick] = useState(0);
  // Document outline panel. Opened via the top-right toggle or Cmd/Ctrl+Shift+O;
  // shares the top-right slot with the find bar, so only one is open at a time.
  const [outlineOpen, setOutlineOpen] = useState(readOutlinePref);
  // Footprint the outline reserves so body text floats around it: a thin
  // square for the collapsed icon, the panel's width + measured height when
  // open (so text wraps beside it and reclaims full width below).
  const [outlineReserve, setOutlineReserve] = useState({ width: 0, height: 0 });

  /**
   * Close the find bar, leaving the caret ON the match the reader was looking
   * at rather than wherever it was before the search.
   *
   * The find engine is decoration-only - it highlights and scrolls without
   * ever moving the selection - so on close the caret is still at the top of
   * the note, and focusing it scrolled the whole view back there, undoing the
   * search. Parking the selection on the active hit first is what a browser's
   * own find does.
   *
   * Shared by the X button (via onClose) and the Cmd+F toggle, so the two
   * cannot drift apart.
   */
  /** Mirror of searchOpen for the capture-phase Esc guard, which is registered
   *  once and must not re-subscribe on every open/close. */
  const searchOpenRef = useRef(false);
  useEffect(() => { searchOpenRef.current = searchOpen; }, [searchOpen]);

  const closeFind = useCallback(() => {
    setSearchOpen(false);
    if (!editorRef.current) return;
    const ed = editorRef.current;
    const hit = getActiveMatchRange(ed.view);
    if (hit) ed.chain().focus().setTextSelection(hit).run();
    else ed.commands.focus();
  }, []);

  const openFind = useCallback(() => {
    setSearchOpen(true);
    setSearchFocusTick((t) => t + 1);
    setOutlineOpen(false);
  }, []);

  /**
   * The single open/close path, shared by Cmd/Ctrl+F and the tag-row magnifier
   * so the two cannot drift: whichever one you reach for, pressing it again
   * closes the bar. Reads the mirror ref rather than state because both callers
   * fire from event handlers, long after the effect below has synced it.
   */
  const toggleFind = useCallback(() => {
    if (searchOpenRef.current) closeFind();
    else openFind();
  }, [closeFind, openFind]);

  // Cmd/Ctrl+F opens find; Cmd/Ctrl+Shift+O toggles the outline. One
  // document-level capture listener catches both, whether the caret is in the
  // editor body or the editor is merely on screen. We stand down when focus is
  // in some other input/textarea (e.g. the note-list search) so we don't hijack
  // their shortcuts; our own UI lives inside rootRef so it still counts.
  useEffect(() => {
    if (readOnly) return;
    const onKeyDown = (e: KeyboardEvent) => {
      const root = rootRef.current;
      if (!root) return;
      const ae = document.activeElement as HTMLElement | null;
      const inEditor = !!ae && root.contains(ae);
      // Stand down whenever focus is in an input/textarea that is NOT ours -
      // the note-list search box being the one that matters. This check has to
      // come FIRST, before the Escape branch: the find bar being open must not
      // give us a claim on Escape typed into somebody else's field, or Esc
      // stops clearing the list search.
      const inForeignField = !!ae && /^(input|textarea)$/i.test(ae.tagName) && !inEditor;

      // Swallow Escape while OUR find bar is open and focus is ours, so it
      // neither closes the bar nor reaches the global Esc cascade in
      // useKeyboardShortcuts.
      //
      // That cascade calls handleCloseEditor(), which does setSelectedId(null)
      // - and on desktop the auto-select effect immediately re-selects the
      // same note, REMOUNTING the editor (it is keyed by note id). That is the
      // "Esc scrolls every note to the top" behaviour: not a scroll at all, a
      // deselect and remount, which also wiped searchOpen. Removing Esc from
      // the bar's own handler was therefore not enough on its own.
      //
      // This listener is capture-phase on `document` and the cascade is
      // bubble-phase on `window`, so stopPropagation here wins. Esc with the
      // bar closed, or with focus in the list search, is untouched.
      if (e.key === 'Escape') {
        if (searchOpenRef.current && !inForeignField) {
          e.preventDefault();
          e.stopPropagation();
        }
        return;
      }

      const mod = e.metaKey || e.ctrlKey;
      if (!mod || e.altKey) return;
      const isOutline = e.shiftKey && (e.key === 'o' || e.key === 'O');
      const isFind = !e.shiftKey && (e.key === 'f' || e.key === 'F');
      if (!isOutline && !isFind) return;
      if (inForeignField) return;
      e.preventDefault();
      if (isOutline) {
        // Outline and find share the top-right slot - only one at a time.
        setOutlineOpen((v) => {
          if (!v) setSearchOpen(false);
          return !v;
        });
        return;
      }
      // Cmd/Ctrl+F TOGGLES. It is the only key that closes the bar: Esc used
      // to, but Esc is a global "get me out" that scrolls the note back to the
      // top, so it fought the caret-parking in closeFind - the bar closed
      // correctly and the note jumped anyway. Closing with the same key that
      // opened it is also the more discoverable pairing.
      //
      // The toggle has to live HERE rather than in FindBar's own keydown: this
      // listener is capture-phase on `document`, so it sees Cmd+F before any
      // handler inside the bar could.
      toggleFind();
    };
    document.addEventListener('keydown', onKeyDown, true);
    return () => document.removeEventListener('keydown', onKeyDown, true);
  }, [readOnly, toggleFind]);

  // Persist the outline open/closed choice.
  useEffect(() => {
    writeOutlinePref(outlineOpen);
  }, [outlineOpen]);

  // Reserve space for the OPEN outline panel on the right of the note body: it
  // is floated as a top-right spacer (see .ProseMirror::before) sized to its
  // footprint, so content wraps beside it and the column reclaims full width
  // below - no full-height gutter. On mobile it overlays the column (no
  // reflow) rather than crushing it.
  //
  // The collapsed pill reserves nothing (OutlinePanel reports a zero
  // footprint): it parks in the click row above the body, which is always
  // there. The panel's top aligns with that row, so the float only has to
  // cover what hangs BELOW it - hence subtracting the row's height.
  useLayoutEffect(() => {
    const root = rootRef.current;
    if (!root) return;
    const hasOutline = outlineReserve.width > 0;
    const overlay = outlineOpen && isMobile;
    const fw = hasOutline && !overlay ? outlineReserve.width : 0;
    const fh = hasOutline && !overlay
      ? Math.max(0, outlineReserve.height - EDITOR_TOP_GAP_PX)
      : 0;
    root.style.setProperty('--pn-outline-fw', `${fw}px`);
    root.style.setProperty('--pn-outline-fh', `${fh}px`);
  }, [outlineReserve, outlineOpen, isMobile]);

  // Pin the find bar just below the formatting toolbar. The toolbar height
  // varies (one row, or two when the overflow row is expanded), so measure it
  // live and expose it as a CSS var the bar's sticky `top` reads. Falls back
  // to 0 when the toolbar is hidden so the bar pins under the tag row instead.
  useEffect(() => {
    const root = rootRef.current;
    if (!root) return;
    const toolbarEl = root.querySelector('.pn-editor-toolbar') as HTMLElement | null;
    if (!toolbarEl) {
      root.style.setProperty('--pn-editor-toolbar-h', '0px');
      return;
    }
    const apply = () =>
      root.style.setProperty('--pn-editor-toolbar-h', `${toolbarEl.offsetHeight}px`);
    apply();
    const ro = new ResizeObserver(apply);
    ro.observe(toolbarEl);
    return () => ro.disconnect();
  }, [editor, toolbarVisible, readOnly]);

  return {
    searchOpen,
    setSearchOpen,
    searchFocusTick,
    outlineOpen,
    setOutlineOpen,
    setOutlineReserve,
    closeFind,
    toggleFind,
  };
}
