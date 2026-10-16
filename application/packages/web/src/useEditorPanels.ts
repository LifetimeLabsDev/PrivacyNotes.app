import {
  useCallback,
  useContext,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type RefObject,
} from 'react';
import { type Editor as TipTapEditor } from '@tiptap/react';
import { getActiveMatchRange } from './editorSearch';
import { isImeComposing } from './imeComposing';
import { APP_KEYS, matchesKey } from './shortcutMatch';
import { editorCommands, insertDateText, registerEditorCommand } from './editorCommands';
import { readOutlinePref, writeOutlinePref } from './editorPrefs';
import { proUnlocked } from './demo';
import { FormatBarContext } from './formatBarContext';
import { SLOT_PILL_HEIGHT, SLOT_PILL_WIDTH } from './EditorSlotPill';

/**
 * The note body's top padding (`.ProseMirror` in index.css). The corner
 * pills and the outline panel start at the top of that padding, so the
 * float that keeps text beside them only covers what hangs below it.
 */
const EDITOR_TOP_PAD_PX = 16;

/** Which bar holds the editor's top-right slot. */
type EditorBar = 'none' | 'find' | 'replace';

export function useEditorPanels({
  rootRef,
  editorRef,
  editor,
  readOnly,
  preview,
  toolbarVisible,
  isPro,
  onOpenUpgrade,
}: {
  rootRef: RefObject<HTMLDivElement | null>;
  editorRef: RefObject<TipTapEditor | null>;
  editor: TipTapEditor | null;
  readOnly: boolean;
  /** The note history preview: no bars, no outline, no shortcuts. */
  preview: boolean;
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
  // The term a bar starts on when the reader swaps find for replace or back
  // with the button in the bar, so the swap keeps what they typed.
  const [swapTerm, setSwapTerm] = useState('');
  // Document outline panel. Opened via the top-right toggle or Cmd/Ctrl+Shift+O;
  // shares the top-right slot with the find bar, so only one is open at a time.
  const [outlineOpen, setOutlineOpen] = useState(readOutlinePref);
  // The row of corner pills (find, the outline), measured so the note's
  // first lines wrap beside it instead of under it. The footprint is the
  // collapsed row whether the outline is open or not: the open panel covers
  // the note below that row, so opening or closing it moves no text.
  const [pillsEl, setPillsEl] = useState<HTMLDivElement | null>(null);
  const [pillsReserve, setPillsReserve] = useState({ width: 0, height: 0 });
  useLayoutEffect(() => {
    if (!pillsEl) { setPillsReserve({ width: 0, height: 0 }); return; }
    const report = () => {
      // Counted, never measured: a pill's label slides out on hover and the
      // open panel stands where the outline pill was, and neither may move
      // the text. Each slot is one collapsed pill, plus 8px of air.
      const slots = [...pillsEl.children].filter((k) => (k as HTMLElement).offsetWidth > 0).length;
      const gap = parseFloat(getComputedStyle(pillsEl).columnGap) || 0;
      const width = slots ? slots * SLOT_PILL_WIDTH + (slots - 1) * gap + 8 : 0;
      const height = slots ? SLOT_PILL_HEIGHT : 0;
      setPillsReserve((r) => (r.width === width && r.height === height ? r : { width, height }));
    };
    report();
    const ro = new ResizeObserver(report);
    ro.observe(pillsEl);
    return () => ro.disconnect();
  }, [pillsEl]);

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

  const openFind = useCallback((term = '') => {
    setFindSeed(null);
    setSwapTerm(term);
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
   * hands the feature out like every other client-side gate. A read-only
   * note refuses before the pitch: it cannot take the action at all.
   * Spec: ops/docs/pro-features.md (Find and replace)
   */
  const openReplace = useCallback((term = '') => {
    if (readOnly) return;
    if (!proUnlocked(isPro)) {
      onOpenUpgrade?.('replace');
      return;
    }
    setSwapTerm(term);
    setBar('replace');
    setBarFocusTick((t) => t + 1);
    setOutlineOpen(false);
  }, [readOnly, isPro, onOpenUpgrade]);

  // Turning read-only on under an open replace bar closes it. The find bar
  // stays: finding is reading, and a read-only note keeps it.
  useEffect(() => {
    if (readOnly) setBar((b) => (b === 'replace' ? 'none' : b));
  }, [readOnly]);

  /**
   * The single open/close path, shared by Cmd/Ctrl+F and the corner magnifier
   * so the two cannot drift: whichever one you reach for, pressing it again
   * closes the bar. Reads the mirror ref rather than state because both callers
   * fire from event handlers, long after the effect above has synced it.
   * Pressed while the replace bar is up, it swaps to the find bar.
   */
  const toggleFind = useCallback(() => {
    if (barRef.current === 'find') closeBar();
    else openFind();
  }, [closeBar, openFind]);

  /** The swap button in either bar: find grows into replace, replace
   *  shrinks back to find, and the term the reader typed goes along. */
  const swapBar = useCallback((term: string) => {
    if (barRef.current === 'find') openReplace(term);
    else openFind(term);
  }, [openFind, openReplace]);

  /** Same shape for replace: the shortcut and the menu row both toggle. */
  const toggleReplace = useCallback(() => {
    if (barRef.current === 'replace') closeBar();
    else openReplace();
  }, [closeBar, openReplace]);

  // The same three toggles for command mode in the search field. Command
  // mode offers a command only while it is registered, so a read-only note,
  // which refuses replace, does not offer it.
  useEffect(() => {
    if (preview) return;
    const off = [
      registerEditorCommand('find', toggleFind),
      ...(readOnly ? [] : [registerEditorCommand('findReplace', toggleReplace)]),
      registerEditorCommand('outline', () =>
        setOutlineOpen((v) => {
          if (!v) setBar('none');
          return !v;
        }),
      ),
    ];
    return () => off.forEach((f) => f());
  }, [preview, readOnly, toggleFind, toggleReplace]);

  // The date inserts, while the note can be edited. The Markdown source view
  // registers its own (MarkdownSourceEditor.tsx), since this editor is not
  // mounted there.
  useEffect(() => {
    if (preview || readOnly || !editor) return;
    const off = [
      registerEditorCommand('insertDate', () => insertDateText(editor, 'date')),
      registerEditorCommand('insertDateTime', () => insertDateText(editor, 'dateTime')),
    ];
    return () => off.forEach((f) => f());
  }, [preview, readOnly, editor]);

  // Cmd/Ctrl+F opens find, Option/Alt+Cmd/Ctrl+F opens replace, and
  // Cmd/Ctrl+Shift+O toggles the outline. One document-level capture listener
  // catches all three, and the date keys, whether the caret is in the editor
  // body or the editor is merely on screen. We stand down when focus is
  // in some other input/textarea (e.g. the note-list search) so we don't hijack
  // their shortcuts; our own UI lives inside rootRef so it still counts.
  useEffect(() => {
    if (preview) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (isImeComposing(e)) return;
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

      // The date keys run the insert registered while the note can be
      // edited; with none registered, the key is left to the browser.
      const insert = matchesKey(e, APP_KEYS.insertDate)
        ? editorCommands.insertDate
        : matchesKey(e, APP_KEYS.insertDateTime)
          ? editorCommands.insertDateTime
          : null;
      if (insert !== null) {
        if (inForeignField || !insert) return;
        e.preventDefault();
        insert();
        return;
      }

      // Option+Cmd+F opens replace (Alt+Ctrl+F off the Mac). On macOS Option
      // turns F into ƒ, which the matcher reads back as F. Off the Mac,
      // Ctrl+Alt is also AltGr, and a keyboard that types a character there
      // ("[" is AltGr+F in Czech) keeps the character.
      if (matchesKey(e, APP_KEYS.findReplace)) {
        if (inForeignField) return;
        e.preventDefault();
        toggleReplace();
        return;
      }
      const isOutline = matchesKey(e, APP_KEYS.outline);
      const isFind = matchesKey(e, APP_KEYS.find);
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
  }, [preview, toggleFind, toggleReplace]);

  // Persist the outline open/closed choice.
  useEffect(() => {
    writeOutlinePref(outlineOpen);
  }, [outlineOpen]);

  // The pill row's footprint becomes a top-right spacer (see
  // .ProseMirror::before), so the first line wraps beside it. The spacer
  // starts at the top of the body's padding, so it only has to cover what
  // hangs BELOW that.
  useLayoutEffect(() => {
    const root = rootRef.current;
    if (!root) return;
    const reserve = pillsReserve;
    const fh = Math.max(0, reserve.height - EDITOR_TOP_PAD_PX);
    root.style.setProperty('--pn-outline-fw', `${fh > 0 ? reserve.width : 0}px`);
    root.style.setProperty('--pn-outline-fh', `${fh}px`);
    // A note that starts with a box (a callout, a code block) cannot wrap
    // beside the pills, so it starts below them instead (pn-top-line-pad).
    root.style.setProperty('--pn-pills-clear', `${reserve.height}px`);
  }, [pillsReserve]);

  // Pin the find and replace bars just below the formatting toolbar. The toolbar height
  // varies (one row, or two when the overflow row is expanded), so measure it
  // live and expose it as a CSS var the bar's sticky `top` reads. Falls back
  // to 0 when the toolbar is hidden so the bar pins under the tag row instead,
  // and when it sits at the bottom, outside this root. Moving the bar to the
  // top or the bottom re-measures, so the pills never cover it.
  const barPosition = useContext(FormatBarContext).position;
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
  }, [editor, toolbarVisible, readOnly, barPosition]);

  return {
    bar,
    setBar,
    barFocusTick,
    outlineOpen,
    setOutlineOpen,
    setPillsEl,
    findSeed,
    openFindWith,
    closeSeededFind,
    closeBar,
    toggleFind,
    toggleReplace,
    swapBar,
    swapTerm,
  };
}
