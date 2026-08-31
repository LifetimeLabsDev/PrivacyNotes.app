import { useEffect, useRef } from 'react';
import { useTheme } from './theme';

type Props = {
  /** Initial markdown content. Only read on mount - use a `key` prop to force reload. */
  value: string;
  /** Called with the latest markdown on every keystroke. */
  onChange: (markdown: string) => void;
  readOnly?: boolean;
};

/**
 * Plain markdown source editor: a textarea bound to the note body.
 *
 * The body is already stored as markdown (Editor.tsx parses markdown in
 * and serializes markdown out via tiptap-markdown), so this shares the
 * exact same value/onChange contract and the same save + sync path. No
 * serialization, no schema change.
 *
 * Deliberately boring - no toolbar, no note-link autocomplete, no image
 * paste, no find bar. It is the reliable fallback when the rich editor
 * misbehaves, and the source view for people who prefer raw markdown.
 *
 * Uncontrolled (defaultValue + key), mirroring Editor, so typing never
 * round-trips through parent state.
 *
 * Spec: ops/specs/editor-mode-toggle.md (no custom Tab-key handling in v1, deliberately)
 */
export function MarkdownSourceEditor({ value, onChange, readOnly = false }: Props) {
  const ref = useRef<HTMLTextAreaElement>(null);
  const { spellcheck } = useTheme();

  // Grow to fit the content so the note scrolls in the editor pane
  // rather than in a nested textarea scrollbar.
  function fit() {
    const el = ref.current;
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = `${el.scrollHeight}px`;
  }

  useEffect(() => {
    fit();
  }, []);

  // mt-4: the rich editor's formatting bar normally separates the body from
  // the sticky tag row above. There is no bar here, so the textarea owns that
  // gap or the text sits glued to the row.
  // min-h-[60vh]: matches `.ProseMirror` in index.css so toggling modes does
  // not jump the page height.
  return (
    <textarea
      ref={ref}
      // The tag row's undo/redo drive the native undo stack of whichever
      // textarea holds focus, and reach for this one by name when nothing
      // does. See handleHistory in NotesView.tsx.
      data-pn-source
      defaultValue={value}
      readOnly={readOnly}
      spellCheck={spellcheck}
      onChange={(e) => {
        onChange(e.target.value);
        fit();
      }}
      // Tracks the Text size setting like the rich editor does, from the
      // same --pn-text-scale knob. Its own 14px base is kept (monospace
      // runs visually larger than the prose face at the same size).
      style={{ fontSize: 'calc(14px * var(--pn-text-scale))' }}
      className="mt-4 w-full min-h-[60vh] resize-none border-0 bg-transparent p-0 font-mono leading-relaxed text-pn outline-none"
    />
  );
}
