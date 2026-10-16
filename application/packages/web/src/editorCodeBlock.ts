import i18n from './i18n';
import type { Editor as TipTapEditor } from '@tiptap/react';
import { CodeBlockLowlight } from '@tiptap/extension-code-block-lowlight';
import { createLowlight, common } from 'lowlight';
import { Extension, type NodeViewRendererProps } from '@tiptap/core';
import type { Node as ProseMirrorNode } from '@tiptap/pm/model';
import { Plugin, PluginKey, TextSelection } from '@tiptap/pm/state';
import { getCodeWrap, setCodeWrap, subscribeCodeWrap } from './codeWrap';
import { codeLanguageLabel, openCodeLanguageMenu } from './codeLanguages';
import { TIP_PILL, positionClasses } from './HoverLabel';

/**
 * When the user copies text whose selection sits entirely inside a single
 * code block, write the raw text to the clipboard instead of letting
 * tiptap-markdown serialize it as markdown. Prevents `[user@host](mailto:...)`
 * and friends leaking into pasted CLI snippets. Normal prose selections fall
 * through to the default markdown serializer.
 *
 * Spec: ops/docs/design-decisions.md (code-block plain-text copy)
 */
export const CodeBlockPlainCopy = Extension.create({
  name: 'codeBlockPlainCopy',
  addProseMirrorPlugins() {
    return [
      new Plugin({
        key: new PluginKey('codeBlockPlainCopy'),
        props: {
          handleDOMEvents: {
            copy(view, event) {
              const { from, to, $from, $to, empty } = view.state.selection;
              if (empty) return false;
              if (
                $from.parent.type.name !== 'codeBlock' ||
                $to.parent.type.name !== 'codeBlock' ||
                $from.parent !== $to.parent
              ) {
                return false;
              }
              const text = view.state.doc.textBetween(from, to, '\n');
              event.clipboardData?.setData('text/plain', text);
              event.clipboardData?.setData('text/html', text);
              event.preventDefault();
              return true;
            },
          },
        },
      }),
    ];
  },
});

/**
 * Code block with a Copy button and a wrap toggle in its top corner.
 *
 * The pre is the visible box and keeps every typography rule (margins,
 * colours, radius, the spacing after a heading). A span inside it is the
 * element that scrolls sideways, and the tools hang off the pre, not the
 * span: a control inside the scroller travels with the text, and a long
 * line scrolled it out of the block (GitHub #340).
 *
 * The scroller reserves a band above the first line, so nothing covers
 * code: the language label sits in it on the left, always visible, and the
 * tools on the right, on hover where there is one and always on touch. Copy
 * writes the node's raw text; the wrap toggle flips one device-wide setting
 * (codeWrap.ts), so every block follows; the label opens the language menu
 * (codeLanguages.ts).
 *
 * Spec: ops/docs/design-decisions.md (code blocks wrap by default)
 *
 * Base is CodeBlockLowlight (same node name `codeBlock`, so markdown
 * round-trip and toggleCodeBlockSmart are unchanged): its ProseMirror
 * plugin decorates the content with hljs token spans, which our custom
 * node view's contentDOM receives like any other decoration. Token
 * colors live in index.css (one bright-on-dark palette - the code panel
 * is dark in both themes). `common` registers the ~37 stock hljs
 * grammars; the fence's language string picks one, anything unknown
 * falls back to plain text.
 */
export const lowlight = createLowlight(common);

/**
 * The fence language of a copy box: a code block drawn as a light box in
 * the note's own font, with the code block's wrap and copy buttons in a
 * light look and no language label. Stored as ```copy, so another Markdown app shows a plain
 * code block. Registered as plain text, or lowlight would guess a language
 * and colour it. Spec: ops/docs/plans/spoiler-and-copy.md
 */
export const COPY_BOX_LANGUAGE = 'copy';
lowlight.registerAlias({ plaintext: [COPY_BOX_LANGUAGE] });

/** Phosphor's ArrowElbowDownLeft, bold: the return glyph editors use for
 *  wrap. A node view is plain DOM, so the icon is markup, not a component. */
const WRAP_ICON =
  '<svg viewBox="0 0 256 256" width="14" height="14" fill="currentColor" aria-hidden="true">' +
  '<path d="M204,32V176a12,12,0,0,1-12,12H77l27.52,27.51a12,12,0,0,1-17,17l-48-48a12,12,0,0,1,0-17l48-48a12,12,0,1,1,17,17L77,164H180V32a12,12,0,0,1,24,0Z"/></svg>';

/** Phosphor's Copy and Check, bold: the copy button and its done state,
 *  the same pair the vault's copy actions use. */
const COPY_ICON =
  '<svg viewBox="0 0 256 256" width="14" height="14" fill="currentColor" aria-hidden="true">' +
  '<path d="M216,28H88A12,12,0,0,0,76,40V76H40A12,12,0,0,0,28,88V216a12,12,0,0,0,12,12H168a12,12,0,0,0,12-12V180h36a12,12,0,0,0,12-12V40A12,12,0,0,0,216,28ZM156,204H52V100H156Zm48-48H180V88a12,12,0,0,0-12-12H100V52H204Z"/></svg>';
const CHECK_ICON =
  '<svg viewBox="0 0 256 256" width="14" height="14" fill="currentColor" aria-hidden="true">' +
  '<path d="M232.49,80.49l-128,128a12,12,0,0,1-17,0l-56-56a12,12,0,1,1,17-17L96,183,215.51,63.51a12,12,0,0,1,17,17Z"/></svg>';

/** Phosphor's CaretDown, bold, for the language label. */
const CARET_ICON =
  '<svg viewBox="0 0 256 256" width="10" height="10" fill="currentColor" aria-hidden="true">' +
  '<path d="M216.49,104.49l-80,80a12,12,0,0,1-17,0l-80-80a12,12,0,0,1,17-17L128,159l71.51-71.52a12,12,0,0,1,17,17Z"/></svg>';

const CODE_TOOL_BTN =
  'inline-flex items-center justify-center h-5 rounded text-xs transition ' +
  '[@media(hover:none)]:h-7';

/**
 * A block longer than FOLD_MIN_LINES opens folded to its first
 * FOLD_SHOWN_LINES, with a button under it (GitHub #427). The gap between the
 * two numbers is deliberate: a fold that hides three lines costs more than it
 * saves. The fold is a view state and is never saved, because a fence stores
 * a language and nothing else (the same limit codeWrap.ts records), so every
 * open starts folded. A cursor or a find match that lands in the hidden part
 * opens the block, so nothing is typed or found out of sight.
 * Spec: ops/docs/design-decisions.md (long code blocks fold)
 */
const FOLD_MIN_LINES = 30;
const FOLD_SHOWN_LINES = 20;

/** Each folded node view's "open it" hook, keyed by its pre. */
const unfolders = new WeakMap<Node, () => void>();

export const CodeBlockWithCopy = CodeBlockLowlight.extend({
  addKeyboardShortcuts() {
    return {
      ...this.parent?.(),
      // Select all selects the code first and the note on a second press, as
      // code editors do: one press and Delete must not clear the text around
      // the block (GitHub #426). An empty block or a selection that already
      // covers the code falls through to the stock select-all.
      'Mod-a': ({ editor }) => {
        const { $from, $to, from, to } = editor.state.selection;
        if ($from.parent.type !== this.type || !$from.sameParent($to)) return false;
        const start = $from.start();
        const end = $from.end();
        if (start === end || (from === start && to === end)) return false;
        return editor.commands.setTextSelection({ from: start, to: end });
      },
    };
  },

  addProseMirrorPlugins() {
    const type = this.type;
    let lastHit = -1;
    // Opens a folded block when `bottom()` (a viewport y) falls below its
    // last clearly readable line, the fade included. A cursor in the visible
    // lines leaves the fold alone, so a click to copy line 3 does not unroll
    // 500. Layout is read only for a block that is folded.
    const revealIfHidden = (block: Node | null | undefined, bottom: () => number) => {
      if (!(block instanceof HTMLElement) || !block.classList.contains('pn-codeblock-folded')) return;
      const scroller = block.querySelector('.pn-codeblock-scroll');
      if (!scroller) return;
      const fade = 2 * (parseFloat(getComputedStyle(scroller).lineHeight) || 24);
      if (bottom() > scroller.getBoundingClientRect().bottom - fade) unfolders.get(block)?.();
    };
    return [
      ...(this.parent?.() ?? []),
      new Plugin({
        key: new PluginKey('codeBlockUnfold'),
        view: () => ({
          update: (view, prev) => {
            const { selection } = view.state;
            if (!selection.eq(prev.selection) && selection.$head.parent.type === type) {
              revealIfHidden(view.nodeDOM(selection.$head.before()), () => view.coordsAtPos(selection.head).bottom);
            }
            // The find bar marks its current match with a decoration and
            // scrolls to it without moving the selection.
            const hit = view.dom.querySelector('.pn-search-hit-current');
            const hitPos = hit ? view.posAtDOM(hit, 0) : -1;
            if (hit && hitPos !== lastHit) {
              revealIfHidden(hit.closest('.pn-codeblock'), () => hit.getBoundingClientRect().bottom);
            }
            lastHit = hitPos;
          },
        }),
      }),
    ];
  },

  addStorage() {
    return {
      markdown: {
        // tiptap-markdown's serializer with three changes. The fence is one
        // backtick longer than any fence line inside the code, so a block
        // holding markdown keeps its ``` lines. A trailing newline gets a line
        // of its own, which the parse strips back to one. The language is
        // written only with the characters an info string can carry. No `parse` key: the
        // library's parse half is merged underneath and must stay.
        serialize(state: any, node: ProseMirrorNode) {
          const text = node.textContent;
          const runs = text.match(/^ {0,3}`{3,}/gm) ?? [];
          const longest = Math.max(2, ...runs.map((r) => r.trim().length));
          const fence = '`'.repeat(longest + 1);
          // The parse takes any class after `language-`, so a pasted block can
          // carry a language with a backtick, which no backtick fence's info
          // string may hold, or a space, which ends it. Neither is written.
          const language = String(node.attrs['language'] || '').replace(/[`\s]/g, '');
          state.write(fence + language + '\n');
          state.text(text, false);
          if (text.endsWith('\n')) state.out += '\n';
          state.ensureNewLine();
          state.write(fence);
          state.closeBlock(node);
        },
      },
    };
  },

  addNodeView() {
    return ({ node, getPos, editor }: NodeViewRendererProps) => {
      // ProseMirror keeps this view while the text inside changes, so Copy
      // reads the node `update` last handed over, never the one the view
      // was built with.
      let current = node;

      const pre = document.createElement('pre');
      pre.className = 'pn-codeblock';
      const scroller = document.createElement('span');
      scroller.className = 'pn-codeblock-scroll';
      const code = document.createElement('code');
      scroller.appendChild(code);
      pre.appendChild(scroller);

      const tools = document.createElement('span');
      tools.className = 'pn-codeblock-tools';
      tools.contentEditable = 'false';

      const wrapBtn = document.createElement('button');
      wrapBtn.type = 'button';
      wrapBtn.innerHTML = WRAP_ICON;
      // Module-level node view - no useTranslation hook here, so the
      // i18n instance is called directly (the non-component pattern
      // from i18n.ts).
      const wrapLabel = i18n.t('editor:codeBlock.wrap');
      wrapBtn.setAttribute('aria-label', wrapLabel);
      // HoverLabel's `start` tip built as DOM, from HoverLabel's own
      // classes. It opens to the left: the pre is an LTR island, and its
      // overflow: hidden would cut a tip above a button 8px from its top.
      const wrapTip = document.createElement('span');
      wrapTip.className = 'pn-codeblock-wrap relative group/tip inline-flex';
      const tip = document.createElement('span');
      tip.className = `${TIP_PILL} ${positionClasses.start} flex items-center gap-2 whitespace-nowrap`;
      tip.textContent = wrapLabel;
      wrapTip.append(wrapBtn, tip);
      // A copy box carries the same tools, in the same place and look; only
      // the box around them differs. The buttons are opaque, because in a
      // copy box the text runs under them.
      const paintWrap = () => {
        const on = getCodeWrap();
        wrapBtn.setAttribute('aria-pressed', String(on));
        wrapBtn.className = `${CODE_TOOL_BTN} w-6 [@media(hover:none)]:w-8 ${
          on
            ? 'bg-accent-fill text-white hover:bg-accent-fill-hover'
            // theme-ok: the code block toolbar is dark in every theme
            : 'bg-neutral-700 text-neutral-300 hover:bg-neutral-600 hover:text-neutral-100'
        }`;
      };
      paintWrap();
      const unsubscribe = subscribeCodeWrap(paintWrap);
      wrapBtn.addEventListener('mousedown', (e) => e.preventDefault());
      wrapBtn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        setCodeWrap(!getCodeWrap());
      });

      // An icon, not a word: a word grows in other languages and the tools
      // sit on the code's first line. The tip names it; a copy turns the
      // icon into a check and the tip into "Copied" for a moment.
      const copyLabel = i18n.t('editor:codeBlock.copy');
      const copyBtn = document.createElement('button');
      copyBtn.type = 'button';
      copyBtn.innerHTML = COPY_ICON;
      copyBtn.className =
        `${CODE_TOOL_BTN} w-6 [@media(hover:none)]:w-8 ` +
        // theme-ok: the code block toolbar is dark in every theme
        'bg-neutral-700 text-neutral-100 hover:bg-neutral-600';
      copyBtn.setAttribute('aria-label', copyLabel);
      const copyTip = document.createElement('span');
      copyTip.className = 'pn-codeblock-copy relative group/tip inline-flex';
      const copyTipText = document.createElement('span');
      copyTipText.className = `${TIP_PILL} ${positionClasses.start} whitespace-nowrap`;
      copyTipText.setAttribute('aria-live', 'polite');
      copyTipText.textContent = copyLabel;
      copyTip.append(copyBtn, copyTipText);
      let copyReset = 0;
      copyBtn.addEventListener('mousedown', (e) => e.preventDefault());
      copyBtn.addEventListener('click', async (e) => {
        e.preventDefault();
        e.stopPropagation();
        let done = true;
        try {
          await navigator.clipboard.writeText(current.textContent);
        } catch {
          done = false;
        }
        window.clearTimeout(copyReset);
        copyBtn.innerHTML = done ? CHECK_ICON : COPY_ICON;
        copyBtn.classList.toggle('pn-copied', done);
        copyTipText.textContent = i18n.t(done ? 'editor:codeBlock.copied' : 'editor:codeBlock.copyFailed');
        copyTip.classList.add('pn-tip-shown');
        copyReset = window.setTimeout(() => {
          copyBtn.innerHTML = COPY_ICON;
          copyBtn.classList.remove('pn-copied');
          copyTipText.textContent = copyLabel;
          copyTip.classList.remove('pn-tip-shown');
        }, 1500);
      });

      tools.append(wrapTip, copyTip);
      pre.appendChild(tools);

      // The language, always on show in the band above the first line, so a
      // plain block says why it has no colours and offers the fix in place.
      const lang = document.createElement('span');
      lang.className = 'pn-codeblock-lang';
      lang.contentEditable = 'false';
      const langBtn = document.createElement('button');
      langBtn.type = 'button';
      langBtn.className =
        `${CODE_TOOL_BTN} gap-1 px-2 [@media(hover:none)]:px-2.5 ` +
        // theme-ok: the code block toolbar is dark in every theme
        'text-neutral-400 hover:bg-neutral-700/80 hover:text-neutral-100';
      const langName = document.createElement('span');
      langBtn.append(langName);
      langBtn.insertAdjacentHTML('beforeend', CARET_ICON);
      lang.appendChild(langBtn);
      pre.appendChild(lang);
      let langShown: string | null | undefined;
      const paintLang = () => {
        const language = current.attrs['language'] as string | null;
        if (language === langShown) return;
        pre.classList.toggle('pn-copybox', language === COPY_BOX_LANGUAGE);
        langShown = language;
        const name = codeLanguageLabel(language) ?? i18n.t('editor:codeBlock.plainText');
        langName.textContent = name;
        langBtn.setAttribute('aria-label', i18n.t('editor:codeBlock.language', { name }));
      };
      paintLang();
      langBtn.addEventListener('mousedown', (e) => e.preventDefault());
      langBtn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (!editor.isEditable) return;
        openCodeLanguageMenu(langBtn, current.attrs['language'] as string | null, (language) => {
          const pos = typeof getPos === 'function' ? getPos() : undefined;
          if (typeof pos !== 'number') return;
          // setNodeMarkup, not setNodeAttribute: the lowlight plugin only
          // re-highlights a block a step's from/to range covers, and an
          // attribute step has none, so the old colours stayed.
          editor.view.dispatch(editor.state.tr.setNodeMarkup(pos, undefined, { ...current.attrs, language }));
          editor.view.focus();
        });
      });

      const fold = document.createElement('span');
      fold.className = 'pn-codeblock-fold';
      fold.contentEditable = 'false';
      const foldBtn = document.createElement('button');
      foldBtn.type = 'button';
      foldBtn.className =
        `${CODE_TOOL_BTN} px-2.5 [@media(hover:none)]:px-3 ` +
        // theme-ok: the code block toolbar is dark in every theme
        'bg-neutral-700/80 text-neutral-100 hover:bg-neutral-700';
      fold.appendChild(foldBtn);
      pre.appendChild(fold);
      pre.style.setProperty('--pn-fold-lines', String(FOLD_SHOWN_LINES));

      let expanded = false;
      let foldLabel = '';
      const paintFold = () => {
        const lines = current.textContent.split('\n').length;
        const long = lines > FOLD_MIN_LINES;
        pre.classList.toggle('pn-codeblock-folded', long && !expanded);
        fold.hidden = !long;
        const label = !long ? '' : expanded
          ? i18n.t('editor:codeBlock.showLess')
          : i18n.t('editor:codeBlock.showAll', { count: lines });
        if (label !== foldLabel) foldBtn.textContent = foldLabel = label;
      };
      paintFold();
      unfolders.set(pre, () => {
        if (expanded || !pre.classList.contains('pn-codeblock-folded')) return;
        expanded = true;
        paintFold();
      });
      foldBtn.addEventListener('mousedown', (e) => e.preventDefault());
      foldBtn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        expanded = !expanded;
        paintFold();
        // Folding from the foot of a long block pulls the button up past the
        // top of the screen; bring it back to where the reader is.
        const r = fold.getBoundingClientRect();
        if (r.top < 0 || r.bottom > window.innerHeight) fold.scrollIntoView({ block: 'center' });
      });

      return {
        dom: pre,
        contentDOM: code,
        update: (next: ProseMirrorNode) => {
          if (next.type !== current.type) return false;
          current = next;
          paintFold();
          paintLang();
          return true;
        },
        // The tools, the language label and the fold button are not document
        // content: their clicks, label changes and class flips are not edits
        // for ProseMirror to read back, and neither is the fold class on the
        // pre.
        stopEvent: (e: Event) => [tools, lang, fold].some((el) => el.contains(e.target as Node)),
        ignoreMutation: (m: { type: string; target: Node }) =>
          [tools, lang, fold].some((el) => el.contains(m.target)) || (m.type === 'attributes' && m.target === pre),
        destroy: unsubscribe,
      };
    };
  },
});

/**
 * Smart code-block toggle for the toolbar button.
 *
 * TipTap's stock `toggleCodeBlock` runs `setBlockType` per textblock, so a
 * multi-line selection becomes one code block PER LINE instead of a single
 * block (bug #142). This helper merges the selected textblocks into one code
 * block whose lines are joined by `\n` - matching how a pasted script looks.
 * It is symmetric: toggling off a multi-line code block splits it back into
 * one paragraph per line.
 *
 * Lists, task lists, quotes and code blocks merge too, their markers kept as
 * text. Falls back to the default command for a caret or a selection inside
 * one textblock, and when the selection holds a block with no text form
 * (an image, a table, a callout).
 *
 * Spec: ops/docs/design-decisions.md (code-block multi-line merge, #142)
 */
export function toggleCodeBlockSmart(editor: TipTapEditor, language: string | null = null) {
  const { state } = editor;
  const { schema, selection, doc } = state;
  const { $from, $to } = selection;
  const codeBlockType = schema.nodes['codeBlock']!;
  const paragraphType = schema.nodes['paragraph']!;

  // Toggle OFF: selection sits inside a single code block. Split it back into
  // one paragraph per line so the line breaks survive the round trip (the
  // default command would collapse them into a single paragraph).
  if ($from.parent.type === codeBlockType && $from.parent === $to.parent) {
    // A code block asked to be the other kind (a copy box, or back) changes
    // its language and keeps its text.
    const current = ($from.parent.attrs['language'] as string | null) === COPY_BOX_LANGUAGE ? COPY_BOX_LANGUAGE : null;
    if (current !== language) {
      const pos = $from.before();
      editor.view.dispatch(state.tr.setNodeMarkup(pos, undefined, { ...$from.parent.attrs, language }));
      editor.view.focus();
      return;
    }
    const from = $from.before();
    const to = $from.after();
    const lines = $from.parent.textContent.split('\n');
    const paragraphs = lines.map((line) =>
      paragraphType.create(null, line ? schema.text(line) : undefined),
    );
    const tr = state.tr.replaceWith(from, to, paragraphs);
    editor.view.dispatch(tr.scrollIntoView());
    editor.view.focus();
    return;
  }

  // Toggle ON. A caret or a selection inside one textblock keeps the stock
  // command, which also makes a code block inside a list item.
  if ($from.sameParent($to)) {
    editor.chain().focus().toggleCodeBlock(language ? { language } : undefined).run();
    return;
  }

  // A selection inside one list takes only the items it touches: the list
  // splits around the new block, and the part after it keeps its numbers.
  const top = doc.resolve(selection.from).node(1);
  const topTo = doc.resolve(selection.to).node(1);
  if (top && top === topTo && /^(bulletList|orderedList|taskList)$/.test(top.type.name)) {
    const listPos = doc.resolve(selection.from).before(1);
    const picked: ProseMirrorNode[] = [];
    const before: ProseMirrorNode[] = [];
    const after: ProseMirrorNode[] = [];
    top.forEach((item, offset) => {
      const from = listPos + 1 + offset;
      const to = from + item.nodeSize;
      if (to <= selection.from) before.push(item);
      else if (from >= selection.to) after.push(item);
      else picked.push(item);
    });
    const start = Number(top.attrs['start'] ?? 1) || 1;
    const asList = (items: ProseMirrorNode[], first: number) =>
      top.type.create(top.type.name === 'orderedList' ? { ...top.attrs, start: first } : top.attrs, items);
    const lines = codeLinesOf(asList(picked, start + before.length), '');
    if (lines) {
      const text = lines.join('\n');
      const parts: ProseMirrorNode[] = [];
      if (before.length) parts.push(asList(before, start));
      const codeAt = listPos + parts.reduce((n, part) => n + part.nodeSize, 0);
      parts.push(codeBlockType.create(language ? { language } : null, text ? schema.text(text) : undefined));
      if (after.length) parts.push(asList(after, start + before.length + picked.length));
      const tr = state.tr.replaceWith(listPos, listPos + top.nodeSize, parts);
      tr.setSelection(TextSelection.create(tr.doc, codeAt + 1, codeAt + 1 + text.length));
      editor.view.dispatch(tr.scrollIntoView());
      editor.view.focus();
      return;
    }
  }

  // A selection across blocks: every top-level block it touches becomes ONE
  // code block, a line per textblock. A list keeps its markers as text, so a
  // numbered list stays numbered in the block. A block that has no text form
  // (a table, an image, a callout) leaves the stock command in charge.
  let mergeFrom = -1;
  let mergeTo = -1;
  const lines: string[] = [];
  let bail = false;
  doc.forEach((node, offset) => {
    if (bail) return;
    const intersects = offset < selection.to && offset + node.nodeSize > selection.from;
    if (!intersects) return;
    const blockLines = codeLinesOf(node, '');
    if (!blockLines) {
      bail = true;
      return;
    }
    if (mergeFrom === -1) mergeFrom = offset;
    mergeTo = offset + node.nodeSize;
    lines.push(...blockLines);
  });

  if (bail || mergeFrom === -1) {
    editor.chain().focus().toggleCodeBlock(language ? { language } : undefined).run();
    return;
  }

  const text = lines.join('\n');
  const codeNode = codeBlockType.create(language ? { language } : null, text ? schema.text(text) : undefined);
  const tr = state.tr.replaceRangeWith(mergeFrom, mergeTo, codeNode);
  tr.setSelection(
    TextSelection.create(tr.doc, mergeFrom + 1, mergeFrom + 1 + text.length),
  );
  editor.view.dispatch(tr.scrollIntoView());
  editor.view.focus();
}

/**
 * The text lines a block gives inside a code block, each led by `pad`, or
 * null for a block with no text form. List items carry their marker (`1. `,
 * `- `, `- [x] `) and their nested blocks are indented under it.
 */
function codeLinesOf(node: ProseMirrorNode, pad: string): string[] | null {
  const name = node.type.name;
  if (name === 'codeBlock') return node.textContent.split('\n').map((l) => pad + l);
  if (node.isTextblock) return [pad + node.textContent];
  if (name === 'blockquote') return childLines(node, pad + '> ');
  if (name === 'bulletList' || name === 'orderedList' || name === 'taskList') {
    const out: string[] = [];
    let n = Number(node.attrs['start'] ?? 1) || 1;
    let ok = true;
    node.forEach((item) => {
      if (!ok) return;
      const marker =
        name === 'orderedList' ? `${n++}. `
        : name === 'taskList' ? `- [${item.attrs['checked'] ? 'x' : ' '}] `
        : '- ';
      let first = true;
      item.forEach((child) => {
        if (!ok) return;
        const childPad = first ? pad + marker : pad + ' '.repeat(marker.length);
        const got = first && child.isTextblock ? [childPad + child.textContent] : codeLinesOf(child, childPad);
        if (!got) ok = false;
        else out.push(...got);
        first = false;
      });
    });
    return ok ? out : null;
  }
  return null;
}

function childLines(node: ProseMirrorNode, pad: string): string[] | null {
  const out: string[] = [];
  let ok = true;
  node.forEach((child) => {
    const got = ok ? codeLinesOf(child, pad) : null;
    if (!got) ok = false;
    else out.push(...got);
  });
  return ok ? out : null;
}
