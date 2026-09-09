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
import { proUnlocked } from './demo';

/**
 * Height of the always-present click row above the note body (rendered by
 * Editor.tsx). It is the collapsed outline pill's parking space - 32px of
 * button plus its 4px top margin - so the pill sits in a row of its own
 * instead of on the note's first block.
 */
export const EDITOR_TOP_GAP_PX = 36;

/** Which bar holds the editor's top-right slot. */
type EditorBar = 'none' | 'find' | 'replace';

export function useEditorPanels({
  rootRef,
  editorRef,
  editor,
  isMobile,
  readOnly,
  toolbarVisible,
  isPro,
  onOpenUpgrade,
}: {
  rootRef: RefObject<HTMLDivElement | null>;
  editorRef: RefObject<TipTapEditor | null>;
  editor: TipTapEditor | null;
  isMobile: boolean;
  readOnly: boolean;
  toolbarVisible: boolean;
  isPro: boolean;
  /** Opens the upgrade modal when a free account asks for replace. */
  onOpenUpgrade?: (trigger: 'replace') => void;
}) {
  // The find bar (Cmd/Ctrl+F) and the replace bar (Option/Alt+Cmd/Ctrl+F).
  // One value rather than two flags: the bars share the slot and the
  // search plugin, so opening one is closing the other. focusTick bumps on
  // every open so the bar's input takes focus and selects its text.
  const [bar, setBar] = useState<EditorBar>('none');
  const [barFocusTick, setBarFocusTick] = useState(0);
  // The word a search result opened the find bar on, or null for a bar the
  // reader opened. The tick changes on every seeded open and keys the bar in
  // Editor.tsx, so a repeat takes the new word even while the bar is up.
  const [findSeed, setFindSeed] = useState<{ term: string; tick: number } | null>(null);
  // Document outline panel. Opened via the top-right toggle or Cmd/Ctrl+Shift+O;
  // shares the top-right slot with the find bar, so only one is open at a time.
  const [outlineOpen, setOutlineOpen] = useState(readOutlinePref);
  // Footprint the outline reserves so body text floats around it: a thin
  // square for the collapsed icon, the panel's width + measured height when
  // open (so text wraps beside it and reclaims full width below).
  const [outlineReserve, setOutlineReserve] = useState({ width: 0, height: 0 });

  /** Mirror of `bar` for the capture-phase Esc guard, which is registered
   *  once and must not re-subscribe on every open/close. */
  const barRef = useRef<EditorBar>('none');
  useEffect(() => { barRef.current = bar; }, [bar]);

  /**
   * Close whichever bar is open, leaving the caret ON the match the reader
   * was looking at rather than wherever it was before the search.
   *
   * Highlighting is decoration-only - it highlights and scrolls without ever
   * moving the selection - so on close the caret is still at the top of the
   * note, and focusing it scrolled the whole view back there, undoing the
   * search. Parking the selection on the active hit first is what a
   * browser's own find does.
   *
   * Shared by each bar's X button (via onClose) and both keyboard toggles,
   * so none of them can drift apart.
   */
  const closeBar = useCallback(() => {
    setBar('none');
    if (!editorRef.current) return;
    const ed = editorRef.current;
    const hit = getActiveMatchRange(ed.view);
    if (hit) ed.chain().focus().setTextSelection(hit).run();
    else ed.commands.focus();
  }, []);

  const openFind = useCallback(() => {
    setFindSeed(null);
    setBar('find');
    setBarFocusTick((t) => t + 1);
    setOutlineOpen(false);
  }, []);

  /**
   * Open the find bar on a word the list search matched in this note, so the
   * open note shows its hits as the query is typed (GitHub #288). No focus
   * tick: the reader is in the list search box or clicked a result, never
   * the bar, and the caret stays put. On a phone that is the difference
   * between a highlight and a keyboard.
   */
  const openFindWith = useCallback((term: string) => {
    setFindSeed((s) => ({ term, tick: (s?.tick ?? 0) + 1 }));
    setBar('find');
    setOutlineOpen(false);
  }, []);

  /** Mirror of `findSeed` for closeSeededFind, which fires from an effect in
   *  NotesView and must not re-subscribe on every seed. */
  const findSeedRef = useRef(findSeed);
  useEffect(() => { findSeedRef.current = findSeed; }, [findSeed]);

  /**
   * Close the find bar only if the list search opened it. Runs when that
   * search is emptied, so the bar leaves with the query that brought it.
   * Neither parks the caret nor focuses the note the way closeBar does: the
   * reader is in the list search box, and must stay there.
   */
  const closeSeededFind = useCallback(() => {
    if (findSeedRef.current && barRef.current === 'find') setBar('none');
    setFindSeed(null);
  }, []);

  /**
   * Replace is the Pro half of search, and this is its one gate: the
   * shortcut and the "..." menu row both land here, so a free account meets
   * the same upgrade pitch from either. `proUnlocked`, so the public demo
   * hands the feature out like every other client-side gate.
   * Spec: ops/docs/pro-features.md (Find and replace)
   */
  const openReplace = useCallback(() => {
    if (!proUnlocked(isPro)) {
      onOpenUpgrade?.('replace');
      return;
    }
    setBar('replace');
    setBarFocusTick((t) => t + 1);
    setOutlineOpen(false);
  }, [isPro, onOpenUpgrade]);

  /**
   * The single open/close path, shared by Cmd/Ctrl+F and the tag-row magnifier
   * so the two cannot drift: whichever one you reach for, pressing it again
   * closes the bar. Reads the mirror ref rather than state because both callers
   * fire from event handlers, long after the effect above has synced it.
   * Pressed while the replace bar is up, it swaps to the find bar.
   */
  const toggleFind = useCallback(() => {
    if (barRef.current === 'find') closeBar();
    else openFind();
  }, [closeBar, openFind]);

  /** Same shape for replace: the shortcut and the menu row both toggle. */
  const toggleReplace = useCallback(() => {
    if (barRef.current === 'replace') closeBar();
    else openReplace();
  }, [closeBar, openReplace]);

  // Cmd/Ctrl+F opens find, Option/Alt+Cmd/Ctrl+F opens replace, and
  // Cmd/Ctrl+Shift+O toggles the outline. One document-level capture listener
  // catches all three, whether the caret is in the editor body or the editor
  // is merely on screen. We stand down when focus is
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

      // Swallow Escape while one of OUR bars is open and focus is ours, so it
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
        if (barRef.current !== 'none' && !inForeignField) {
          e.preventDefault();
          e.stopPropagation();
        }
        return;
      }

      const mod = e.metaKey || e.ctrlKey;
      if (!mod) return;
      if (e.altKey) {
        // Option+Cmd+F opens replace (Alt+Ctrl+F off the Mac). The physical
        // `code` is tested beside `key` because on macOS, Option rewrites the
        // key to the character it types (ƒ for F) - the same reason
        // Editor.tsx tests `code` for its own shifted shortcuts. No other
        // Option/Alt combination is ours.
        const isReplace = !e.shiftKey && (e.code === 'KeyF' || e.key === 'f' || e.key === 'F');
        if (!isReplace || inForeignField) return;
        e.preventDefault();
        toggleReplace();
        return;
      }
      const isOutline = e.shiftKey && (e.key === 'o' || e.key === 'O');
      const isFind = !e.shiftKey && (e.key === 'f' || e.key === 'F');
      if (!isOutline && !isFind) return;
      if (inForeignField) return;
      e.preventDefault();
      if (isOutline) {
        // The outline and the bars share the top-right slot - one at a time.
        setOutlineOpen((v) => {
          if (!v) setBar('none');
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
  }, [readOnly, toggleFind, toggleReplace]);

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

  // Pin the find and replace bars just below the formatting toolbar. The toolbar height
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
    bar,
    setBar,
    barFocusTick,
    outlineOpen,
    setOutlineOpen,
    setOutlineReserve,
    findSeed,
    openFindWith,
    closeSeededFind,
    closeBar,
    toggleFind,
    toggleReplace,
  };
}
