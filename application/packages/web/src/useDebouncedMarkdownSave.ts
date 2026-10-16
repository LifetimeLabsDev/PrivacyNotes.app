import { useCallback, useEffect, useRef } from 'react';
import type { Editor as TipTapEditor, EditorEvents } from '@tiptap/react';
import { cleanEmptyTaskItems, collapseMediaGaps } from './editorExtensions';
import { stashPendingEdit } from './flushStash';
import { writeDocCacheFromEditor } from './editorDocCache';

/** Cancel the save still waiting (a debounce, or a large note's frame) and
 *  say whether there was one, so the caller serializes in its place. */
function takePendingSave(debounceRef: { current: number | null }, frameRef: { current: number | null }): boolean {
  const pending = debounceRef.current !== null || frameRef.current !== null;
  if (debounceRef.current !== null) window.clearTimeout(debounceRef.current);
  if (frameRef.current !== null) cancelAnimationFrame(frameRef.current);
  debounceRef.current = null;
  frameRef.current = null;
  return pending;
}

function useFlushOnExitEffects(
  editor: TipTapEditor | null,
  debounceRef: { current: number | null },
  frameRef: { current: number | null },
  onChangeRef: { current: (markdown: string) => void },
  noteIdRef: { current: string | undefined },
) {
  // On unmount, flush any pending change so it doesn't get lost when
  // switching notes mid-type: a debounce still waiting, or a large note's
  // save waiting for its frame. handleBodyChange writes by note ID so it
  // doesn't interfere with the newly selected note. (#64)
  //
  // The serialization runs NOW, at every size. TipTap tears the editor down
  // on a 1 ms timer scheduled in its own unmount cleanup, which runs before
  // this one, and the teardown empties the editor's storage, the markdown
  // serializer included; a flush deferred past that timer found nothing and
  // the keystrokes were lost. A large note pays one serialization on the
  // switch, and only when a save was still pending. Pinned by
  // tests/largeNoteUnmountFlush.test.ts.
  useEffect(() => {
    const editorInstance = editor;
    return () => {
      if (!takePendingSave(debounceRef, frameRef) || !editorInstance) return;
      try {
        const md: string = collapseMediaGaps(cleanEmptyTaskItems(editorInstance.storage.markdown.getMarkdown()));
        onChangeRef.current(md);
        writeDocCacheFromEditor(noteIdRef.current, md, editorInstance);
      } catch { /* editor already destroyed */ }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [editor]);

  // Flush pending debounce on tab close or hide so edits aren't lost.
  // Covers the ~300ms window between last keystroke and debounce resolve.
  // Fix: GitHub #81. Large-doc deferral: #91.
  useEffect(() => {
    if (!editor) return;
    const flush = () => {
      if (takePendingSave(debounceRef, frameRef)) {
        const md: string = collapseMediaGaps(cleanEmptyTaskItems(editor.storage.markdown.getMarkdown()));
        // Synchronous last-chance copy FIRST: the onChange save path is
        // async and a closing tab dies before its IndexedDB write
        // commits (measured: edits in the final ~300 ms were lost).
        // reconcileFlushStash() folds this back in at next boot.
        if (noteIdRef.current) stashPendingEdit(noteIdRef.current, md);
        onChangeRef.current(md);
        writeDocCacheFromEditor(noteIdRef.current, md, editor);
      }
    };
    // beforeunload must be synchronous (page is closing, async won't fire).
    const onBeforeUnload = () => flush();
    // visibilitychange (tab hide) can defer for large docs - the tab is
    // hidden so a brief delay is invisible to the user.
    const onVisibilityChange = () => {
      if (!document.hidden) return;
      if (editor.state.doc.content.size > 150_000) {
        setTimeout(flush, 0);
      } else {
        flush();
      }
    };
    window.addEventListener('beforeunload', onBeforeUnload);
    document.addEventListener('visibilitychange', onVisibilityChange);
    return () => {
      window.removeEventListener('beforeunload', onBeforeUnload);
      document.removeEventListener('visibilitychange', onVisibilityChange);
    };
  }, [editor]);
}

export function useDebouncedMarkdownSave({
  value,
  onChange,
  readOnly,
  noteId,
}: {
  value: string;
  onChange: (markdown: string) => void;
  readOnly: boolean;
  /** Enables the synchronous flush stash on tab close - see flushStash.ts. */
  noteId?: string;
}) {
  const debounceRef = useRef<number | null>(null);
  /** A large note's save that waits for the next frame (see onUpdate). */
  const frameRef = useRef<number | null>(null);
  // Stable ref for onChange - used by beforeunload/visibilitychange listeners
  // to avoid stale closures. Fix: GitHub #81.
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;
  const noteIdRef = useRef(noteId);
  noteIdRef.current = noteId;
  // Suppress onUpdate during TipTap's initial content parse. Without this,
  // markdown round-trip normalization (especially task lists) fires onChange
  // on mount, bumping updatedAt and re-sorting the list.
  const mountedRef = useRef(false);
  useEffect(() => {
    mountedRef.current = false;
    const id = requestAnimationFrame(() => { mountedRef.current = true; });
    return () => cancelAnimationFrame(id);
  }, [value]);

  const onUpdate = ({ editor }: EditorEvents['update']) => {
    if (readOnly) return;
    if (!mountedRef.current) return; // suppress initial parse normalization
    if (debounceRef.current) window.clearTimeout(debounceRef.current);
    // Scale debounce with document size. ProseMirror's content.size is
    // roughly proportional to character count. Keeps small notes snappy
    // while giving large notes breathing room. Perf fix for #58, #66, #91.
    const docSize = editor.state.doc.content.size;
    // Spec: ops/docs/design-decisions.md (editor adaptive debounce thresholds)
    const delay = docSize > 500_000 ? 5000
      : docSize > 150_000 ? 2000
      : docSize > 50_000 ? 600
      : 300;
    debounceRef.current = window.setTimeout(() => {
      debounceRef.current = null;
      // For very large docs, yield to the main thread before the
      // expensive getMarkdown() serialization so pending input events
      // and paints aren't blocked. requestAnimationFrame lets the
      // browser finish its current frame first. (#91) The unmount flush
      // takes over a frame still waiting.
      if (docSize > 150_000) {
        if (frameRef.current !== null) cancelAnimationFrame(frameRef.current);
        frameRef.current = requestAnimationFrame(() => {
          frameRef.current = null;
          const md: string = collapseMediaGaps(cleanEmptyTaskItems(editor.storage.markdown.getMarkdown()));
          onChange(md);
          writeDocCacheFromEditor(noteId, md, editor);
        });
      } else {
        const md: string = collapseMediaGaps(cleanEmptyTaskItems(editor.storage.markdown.getMarkdown()));
        onChange(md);
        writeDocCacheFromEditor(noteId, md, editor);
      }
    }, delay);
  };

  const useFlushOnExit = (editor: TipTapEditor | null) =>
    useFlushOnExitEffects(editor, debounceRef, frameRef, onChangeRef, noteIdRef);

  // Synchronous flush for callers that swap the editor out in the SAME
  // event (the Formatted/Markdown mode toggle). The unmount flush above
  // runs in effect cleanup, which is AFTER the replacement editor has
  // already rendered from the stale parent state - so the last debounce
  // window of typing would not be in what it mounts with. No large-doc
  // deferral here on purpose: the serialized body must exist before the
  // re-render, and a one-off click can afford the serialization cost.
  const flushNow = useCallback((editor: TipTapEditor) => {
    if (!takePendingSave(debounceRef, frameRef)) return;
    const md: string = collapseMediaGaps(cleanEmptyTaskItems(editor.storage.markdown.getMarkdown()));
    onChangeRef.current(md);
    writeDocCacheFromEditor(noteIdRef.current, md, editor);
  // Everything read inside is a ref - stable by contract.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return { onUpdate, useFlushOnExit, flushNow };
}
