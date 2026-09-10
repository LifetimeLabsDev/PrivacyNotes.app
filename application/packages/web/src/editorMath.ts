import katex, { type KatexOptions } from 'katex';
import type { NodeViewRendererProps } from '@tiptap/core';
import type { NodeView } from '@tiptap/pm/view';
import i18n from './i18n';

/**
 * Math node view: KaTeX output that swaps to its own LaTeX source in place.
 *
 * The formula stays a NODE the whole time, and that is the point. A math
 * node serializes through its own markdown spec, which writes `$$latex$$`
 * with `state.write` and escapes nothing. Plain text does not: every text
 * node goes through prosemirror-markdown's `esc`, which escapes a backslash
 * as `\\`. LaTeX is almost all backslashes, so a source run parked in a text
 * node doubled every backslash on each save - `\hbar` became `\\hbar`, which
 * KaTeX reads as a line break, and a second edit doubled it again.
 *
 * So the source line lives in an input inside the node view instead of in
 * the document. Nothing the user types is part of the document until it is
 * committed back onto the `latex` attribute, and the document never holds a
 * `$$...$$` text run at all.
 *
 * Committing on blur is what makes the formula come back. Leaving it as raw
 * source had no way back: the input rule fires on typed input matching a
 * complete `$$...$$`, and the caret sits INSIDE the closing delimiter, so no
 * keystroke ever completed the pattern.
 *
 * Spec: ops/docs/design-decisions.md (Math extension: official over third-party)
 */
export function mathNodeView(config: { block: boolean; katexOptions?: KatexOptions }) {
  const { block, katexOptions } = config;

  return ({ node, getPos, editor }: NodeViewRendererProps): NodeView => {
    let current = node;
    let editing = false;

    const dom = document.createElement(block ? 'div' : 'span');
    dom.className = 'tiptap-mathematics-render';
    if (editor.isEditable) dom.classList.add('tiptap-mathematics-render--editable');
    dom.dataset['type'] = block ? 'block-math' : 'inline-math';

    // KaTeX replaces the whole content of its target, so it gets a child of
    // its own rather than the wrapper - the source input is the wrapper's
    // other child and has to survive every re-render.
    const rendered = document.createElement(block ? 'div' : 'span');
    if (block) rendered.className = 'block-math-inner';

    const input = document.createElement(block ? 'textarea' : 'input');
    input.className = 'pn-math-source';
    input.dir = 'ltr';
    input.spellcheck = false;
    input.setAttribute('aria-label', i18n.t('editor:math.sourceLabel'));
    input.style.display = 'none';

    dom.appendChild(rendered);
    dom.appendChild(input);

    function paint(): void {
      const latex = (current.attrs['latex'] as string) ?? '';
      dom.setAttribute('data-latex', latex);
      try {
        katex.render(latex, rendered, katexOptions);
        dom.classList.remove('math-error');
      } catch {
        rendered.textContent = latex;
        dom.classList.add('math-error');
      }
    }

    function open(): void {
      if (editing || !editor.isEditable) return;
      editing = true;
      input.value = (current.attrs['latex'] as string) ?? '';
      if (block) (input as HTMLTextAreaElement).rows = input.value.split('\n').length;
      rendered.style.display = 'none';
      input.style.display = block ? 'block' : 'inline-block';
      input.focus();
      input.select();
    }

    /**
     * `focusEditor` is false on blur: the blur already moved the caret
     * somewhere the user chose, and pulling focus back would undo that.
     */
    function close(commit: boolean, focusEditor: boolean): void {
      if (!editing) return;
      editing = false;
      input.style.display = 'none';
      rendered.style.display = '';
      paint();
      const pos = getPos();
      const latex = input.value.trim();
      if (!commit || pos == null || latex === ((current.attrs['latex'] as string) ?? '')) {
        if (focusEditor) editor.commands.focus();
        return;
      }
      const chain = editor.chain();
      if (focusEditor) chain.focus();
      chain
        .command(({ tr }) => {
          const target = tr.doc.nodeAt(pos);
          if (!target || target.type !== current.type) return false;
          // An emptied source deletes the formula. The alternative is an
          // empty node that renders as nothing and cannot be clicked again.
          if (latex) tr.setNodeMarkup(pos, undefined, { ...target.attrs, latex });
          else tr.delete(pos, pos + target.nodeSize);
          return true;
        })
        .run();
    }

    // mousedown rather than click, so ProseMirror never makes a node
    // selection we would immediately have to fight for focus.
    const onMouseDown: EventListener = (event) => {
      if (editing) return;
      event.preventDefault();
      open();
    };
    const onKeyDown: EventListener = (event) => {
      // Every key typed here belongs to the source line, so none of them
      // reach the window-level shortcuts. Escape is the one that bites: it
      // closes the open note from anywhere, text fields included, so an
      // Escape meant to discard a formula edit closed the note instead.
      event.stopPropagation();
      const key = event as KeyboardEvent;
      if (key.key === 'Escape') {
        event.preventDefault();
        close(false, true);
        return;
      }
      if (key.key === 'Enter' && !key.shiftKey) {
        event.preventDefault();
        close(true, true);
      }
    };
    const onBlur: EventListener = () => close(true, false);

    dom.addEventListener('mousedown', onMouseDown);
    input.addEventListener('keydown', onKeyDown);
    input.addEventListener('blur', onBlur);
    paint();

    return {
      dom,
      update(updated) {
        if (updated.type !== current.type) return false;
        current = updated;
        if (!editing) paint();
        return true;
      },
      // The node is an atom with no editable content, and while the source
      // input is open every keystroke belongs to it.
      stopEvent: () => true,
      ignoreMutation: () => true,
      destroy() {
        dom.removeEventListener('mousedown', onMouseDown);
        input.removeEventListener('keydown', onKeyDown);
        input.removeEventListener('blur', onBlur);
      },
    };
  };
}
