import { useCallback, useEffect, useRef } from 'react';
import type { Editor as TipTapEditor, EditorEvents } from '@tiptap/react';
import { cleanEmptyTaskItems, collapseMediaGaps } from './editorExtensions';
import { stashPendingEdit } from './flushStash';
import { writeDocCacheFromEditor } from './editorDocCache';

function useFlushOnExitEffects(
  editor: TipTapEditor | null,
  debounceRef: { current: number | null },
  onChangeRef: { current: (markdown: string) => void },
  noteIdRef: { current: string | undefined },
) {
  // On unmount, flush any pending debounced change so it doesn't get lost
  // when switching notes mid-type. For large docs, defer the expensive
  // getMarkdown() so the note switch isn't blocked. The editor instance
  // survives unmount briefly; handleBodyChange writes by note ID so it
  // doesn't interfere with the newly selected note. (#91, #64)
  useEffect(() => {
    const editorInstance = editor;
    return () => {
      if (debounceRef.current) {
        window.clearTimeout(debounceRef.current);
        debounceRef.current = null;
        if (editorInstance) {
          const large = editorInstance.state.doc.content.size > 150_000;
          const doFlush = () => {
            try {
              const md: string = collapseMediaGaps(cleanEmptyTaskItems(editorInstance.storage.markdown.getMarkdown()));
              onChangeRef.current(md);
              writeDocCacheFromEditor(noteIdRef.current, md, editorInstance);
            } catch { /* editor may be destroyed */ }
          };
          if (large) {
            setTimeout(doFlush, 0);
          } else {
            doFlush();
          }
        }
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [editor]);

  // Flush pending debounce on tab close or hide so edits aren't lost.
  // Covers the ~300ms window between last keystroke and debounce resolve.
  // Fix: GitHub #81. Large-doc deferral: #91.
  useEffect(() => {
    if (!editor) return;
    const flush = () => {
      if (debounceRef.current) {
        window.clearTimeout(debounceRef.current);
        debounceRef.current = null;
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
      // For very large docs, yield to the main thread before the
      // expensive getMarkdown() serialization so pending input events
      // and paints aren't blocked. requestAnimationFrame lets the
      // browser finish its current frame first. (#91)
      if (docSize > 150_000) {
        requestAnimationFrame(() => {
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
    useFlushOnExitEffects(editor, debounceRef, onChangeRef, noteIdRef);

  // Synchronous flush for callers that swap the editor out in the SAME
  // event (the Formatted/Markdown mode toggle). The unmount flush above
  // runs in effect cleanup, which is AFTER the replacement editor has
  // already rendered from the stale parent state - so the last debounce
  // window of typing would not be in what it mounts with. No large-doc
  // deferral here on purpose: the serialized body must exist before the
  // re-render, and a one-off click can afford the serialization cost.
  const flushNow = useCallback((editor: TipTapEditor) => {
    if (!debounceRef.current) return;
    window.clearTimeout(debounceRef.current);
    debounceRef.current = null;
    const md: string = collapseMediaGaps(cleanEmptyTaskItems(editor.storage.markdown.getMarkdown()));
    onChangeRef.current(md);
    writeDocCacheFromEditor(noteIdRef.current, md, editor);
  // Everything read inside is a ref - stable by contract.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return { onUpdate, useFlushOnExit, flushNow };
}
