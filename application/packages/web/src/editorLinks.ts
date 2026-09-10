/**
 * What a URL link does inside a note: which click opens it, what the link
 * button makes of a selection, and which text counts as an address.
 *
 * Inside a note the caret comes first. A mouse click on a link puts the
 * cursor in the link, the way a click on any other word does, and opens
 * nothing; Cmd (Ctrl off a Mac) with the click is how the reader asks for
 * the URL instead, which is the modifier every browser already uses for
 * that job. A finger keeps the plain tap, because it carries no modifier
 * and has no hover to offer one.
 *
 * That rule is what makes a link removable. The toolbar's Remove button
 * acts on the link the caret sits in, so as long as reaching the link
 * hands the reader to their browser, the caret never lands in it and the
 * button never offers Remove (GitHub #293). The link menu in `Editor.tsx`
 * is the other half of the answer.
 *
 * One click has three possible openers, so each one states the case it
 * does NOT take: the anchor interceptor in `App.tsx` opens every anchor a
 * native build still hands it, this plugin opens the rest, and the Link
 * extension's own `openOnClick` is off so it opens nothing.
 */

import { Extension, getMarkRange } from '@tiptap/core';
import type { Editor } from '@tiptap/core';
import { Plugin, PluginKey } from '@tiptap/pm/state';
import type { EditorState } from '@tiptap/pm/state';
import { detectPlatform } from './devices';
import { openExternal } from './openExternal';
import { isTouchPointer } from './useIsMobile';

const IS_NATIVE = detectPlatform() !== 'web';

/** The same test as `isMacPlatform` in notesViewUtils.ts, kept here so a
 *  click rule does not pull the note-list utilities, and i18n behind them,
 *  into the editor. Asked per click rather than at import. */
function isMac(): boolean {
  return typeof navigator !== 'undefined' && /Mac|iPhone|iPad|iPod/.test(navigator.platform);
}

/** Cmd on a Mac, Ctrl everywhere else. A Ctrl-click on a Mac is a right
 *  click: it opens the link menu, and must never open the URL as well. */
export function isOpenLinkModifier(event: { metaKey: boolean; ctrlKey: boolean }): boolean {
  return isMac() ? event.metaKey : event.ctrlKey;
}

/**
 * The href of the link mark covering `pos`, or null where there is none.
 * Both sides of the position are read, because a click at either end of a
 * link resolves to a boundary the mark sits on only one side of.
 */
export function linkHrefAt(state: EditorState, pos: number): string | null {
  const type = state.schema.marks.link;
  if (!type) return null;
  const nodes = [state.doc.nodeAt(pos), pos > 0 ? state.doc.nodeAt(pos - 1) : null];
  for (const node of nodes) {
    const href = node?.marks.find((m) => m.type === type)?.attrs.href as string | undefined;
    if (href) return href;
  }
  return null;
}

/**
 * Whether this click opens the URL. Read `view.editable` and the pointer at
 * click time rather than at construction: the editor is built once per note
 * and then told to go read-only in place when the note is locked.
 */
function clickOpensLink(editable: boolean, event: { metaKey: boolean; ctrlKey: boolean }): boolean {
  if (isOpenLinkModifier(event)) return true;
  // A native build leaves a plain click to the interceptor, which is still
  // the opener for every anchor outside a note being edited. Opening here
  // too would open the URL twice.
  if (IS_NATIVE) return false;
  return !editable || isTouchPointer();
}

export const LinkModifierOpen = Extension.create({
  name: 'linkModifierOpen',

  addProseMirrorPlugins() {
    return [
      new Plugin({
        key: new PluginKey('linkModifierOpen'),
        props: {
          handleClick: (view, pos, event) => {
            if (event.button !== 0) return false;
            const href = linkHrefAt(view.state, pos);
            if (!href) return false;
            if (!clickOpensLink(view.editable, event)) return false;
            openExternal(href);
            return true;
          },
        },
      }),
    ];
  },
});

const URL_PATTERN = /^([a-z][a-z0-9+.-]*:\/\/|mailto:|tel:)/i;
const BARE_HOST_PATTERN = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z]{2,})+/i;

/** Whether a string reads as a web address: a scheme, or a bare host with
 *  a top-level domain on it. */
export function looksLikeUrl(input: string): boolean {
  const trimmed = input.trim();
  if (!trimmed) return false;
  return URL_PATTERN.test(trimmed) || BARE_HOST_PATTERN.test(trimmed);
}

/** The href to store for what the reader typed. A bare host gets https,
 *  which is what a person means by "heise.de" and what the site answers
 *  on. A path or a query is left as the relative reference it is. */
export function normalizeUrl(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) return '';
  if (/^[a-z][a-z0-9+.-]*:/i.test(trimmed)) return trimmed;
  if (/^[/?#]/.test(trimmed)) return trimmed;
  return `https://${trimmed}`;
}

/**
 * Link a selection that is already an address, and report whether it did.
 * The link button asks first: a reader who selected `heise.de/ffs` has
 * said where the link goes, so a panel asking for the URL has nothing to
 * add, and every other selection opens the panel as before. A space in
 * the selection is the tell that it is prose rather than an address.
 */
export function linkSelectionIfUrl(editor: Editor): boolean {
  const { from, to } = editor.state.selection;
  if (from === to || editor.isActive('link')) return false;
  const text = editor.state.doc.textBetween(from, to, ' ').trim();
  if (!text || /\s/.test(text) || !looksLikeUrl(text)) return false;
  editor.chain().focus().setLink({ href: normalizeUrl(text) }).run();
  return true;
}

/** Punctuation that ends a sentence rather than an address. A link run can
 *  carry it in its text; its href never should. */
const TRAILING_SENTENCE_PUNCT = /[.,;:!?]+$/;

/**
 * The address a link's text stands for, or null when the text is a label
 * rather than an address. This is what separates the two kinds of link a
 * note holds: one carries its own URL as its words, which is what a paste
 * and every autolink produce, and the other carries a name.
 */
function selfLinkHref(text: string): string | null {
  const address = text.replace(TRAILING_SENTENCE_PUNCT, '');
  if (!address || /\s/.test(address) || !looksLikeUrl(address)) return null;
  return normalizeUrl(address);
}

/** The link run covering `pos`. `getMarkRange` reads the mark on the node
 *  AFTER the position, so a caret resting at the end of a run has to ask
 *  about the character behind it. */
function linkRunAt(state: EditorState, pos: number): { from: number; to: number } | null {
  const type = state.schema.marks.link;
  if (!type) return null;
  const here = getMarkRange(state.doc.resolve(pos), type);
  if (here) return here;
  return (pos > 0 ? getMarkRange(state.doc.resolve(pos - 1), type) : undefined) ?? null;
}

/**
 * Typing inside a link whose text IS its address edits both.
 *
 * The link mark is not inclusive, so a character typed at the edge of a
 * link is plain text and the link ends where it ended. That is the right
 * answer for a link that carries a name, where what follows it is prose.
 * It is the wrong one for a link that carries its own address, which is
 * the shape a paste produces: adding a path to one splits it, leaving the
 * head blue and the tail plain, and typing inside one leaves an address on
 * screen that is not the address the link goes to.
 *
 * So a run whose text is its own address takes the typed character into
 * the mark and re-points its href at the text it now holds. A label link
 * keeps the plain edge, whitespace never extends a link, and a character
 * typed at the very start of a run stays outside it, because that is a
 * word being written in front of the link rather than a URL being fixed.
 */
export const SelfLinkTyping = Extension.create({
  name: 'selfLinkTyping',

  addProseMirrorPlugins() {
    return [
      new Plugin({
        key: new PluginKey('selfLinkTyping'),
        props: {
          handleTextInput: (view, from, to, text) => {
            if (!view.editable || !text || /\s/.test(text)) return false;
            const { state } = view;
            const type = state.schema.marks.link;
            if (!type) return false;
            const run = linkRunAt(state, from);
            if (!run || from <= run.from || to > run.to) return false;
            const before = state.doc.textBetween(run.from, run.to);
            if (!selfLinkHref(before)) return false;
            const after = before.slice(0, from - run.from) + text + before.slice(to - run.from);
            const href = selfLinkHref(after);
            if (!href) return false;
            const tr = state.tr.insertText(text, from, to);
            tr.addMark(run.from, run.to + text.length - (to - from), type.create({ href }));
            // The autolink pass reads the same text and would answer with
            // its own mark on top of this one.
            view.dispatch(tr.setMeta('preventAutolink', true));
            return true;
          },
        },
      }),
    ];
  },
});
