// In-note find and replace: a ProseMirror plugin that highlights matches
// of a query, tracks an "active" match for jump-to navigation, and can
// rewrite the matched ranges. Highlighting is decoration-only; the two
// replace drivers at the bottom of this file are the plugin's only writes
// to the note, and each one is a single transaction, so a replace-all is
// one undo step.
//
// Matches are found per block: consecutive text nodes inside the same
// block are concatenated before searching, so a query can span multiple
// marks (e.g. a word that is partly bold) but never crosses a block
// boundary - the same granularity a browser find gives.
//
// Two React bars drive this through the exported helpers: FindBar.tsx
// (search only) and ReplaceBar.tsx (search plus replace, a Pro feature).
// They share this one plugin because they share the editor's top-right
// slot, so only one of them is ever open. Editor.tsx registers the
// SearchHighlight extension and renders whichever bar is open. CSS for the
// highlight classes lives in index.css.

import { Extension } from '@tiptap/core';
import { Plugin, PluginKey } from '@tiptap/pm/state';
import { Decoration, DecorationSet, type EditorView } from '@tiptap/pm/view';
import type { Node as PMNode } from '@tiptap/pm/model';

type SearchMatch = {
  from: number;
  to: number;
  /** True when the match is a whole atom node (attachment chip matched by
   *  filename) rather than a text range; decorated via Decoration.node. */
  node?: boolean;
};

type PluginState = {
  query: string;
  caseSensitive: boolean;
  matches: SearchMatch[];
  /** Index into `matches`, or -1 when there are none. */
  active: number;
  decorations: DecorationSet;
};

const searchPluginKey = new PluginKey<PluginState>('pnEditorSearch');

const HIT_CLASS = 'pn-search-hit';
const HIT_CURRENT_CLASS = 'pn-search-hit pn-search-hit-current';

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Collect every match of `query` in the document, case-insensitive unless
 * `caseSensitive` is set.
 * Consecutive text nodes are merged into one run before searching so a
 * match can cross mark boundaries; a non-text node (block break, image,
 * hard break, note-link) ends the run. Sibling text nodes are
 * position-contiguous, so `run.pos + offset` maps back to a real doc
 * position.
 *
 * Attachment chips are matched by their filename attr (GitHub #167 - the
 * filename is node metadata, not document text, so the text scan can't
 * see it), and images by their caption and title the same way, because the
 * list search reads both from the markdown and a note it lists for a
 * photo's name must have something the bar can show (GitHub #288). A hit
 * marks the whole node as one node match.
 */
function findMatches(doc: PMNode, query: string, caseSensitive: boolean): SearchMatch[] {
  if (!query) return [];
  let re: RegExp;
  try {
    re = new RegExp(escapeRegExp(query), caseSensitive ? 'g' : 'gi');
  } catch {
    return [];
  }

  const runs: { text: string; pos: number }[] = [];
  const nodeMatches: SearchMatch[] = [];
  let current: { text: string; pos: number } | null = null;
  doc.descendants((node, pos) => {
    if (node.isText) {
      if (current) current.text += node.text ?? '';
      else {
        current = { text: node.text ?? '', pos };
        runs.push(current);
      }
    } else {
      current = null;
      const labels =
        node.type.name === 'attachment'
          ? [node.attrs['filename'] as string | null]
          : node.type.name === 'image'
            ? [node.attrs['alt'] as string | null, node.attrs['title'] as string | null]
            : [];
      if (labels.some((label) => { re.lastIndex = 0; return !!label && re.test(label); })) {
        nodeMatches.push({ from: pos, to: pos + node.nodeSize, node: true });
      }
    }
    return true;
  });

  const matches: SearchMatch[] = [...nodeMatches];
  for (const run of runs) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(run.text)) !== null) {
      const from = run.pos + m.index;
      matches.push({ from, to: from + m[0].length });
      if (m.index === re.lastIndex) re.lastIndex++; // guard against zero-width
    }
  }
  // Doc order so next/previous stepping walks the note top to bottom.
  matches.sort((a, b) => a.from - b.from);
  return matches;
}

function buildDecorations(doc: PMNode, matches: SearchMatch[], active: number): DecorationSet {
  if (matches.length === 0) return DecorationSet.empty;
  const decos = matches.map((m, i) => {
    const cls = i === active ? HIT_CURRENT_CLASS : HIT_CLASS;
    return m.node
      ? Decoration.node(m.from, m.to, { class: cls })
      : Decoration.inline(m.from, m.to, { class: cls });
  });
  return DecorationSet.create(doc, decos);
}

function recompute(doc: PMNode, query: string, caseSensitive: boolean, preferActive: number): PluginState {
  const matches = findMatches(doc, query, caseSensitive);
  let active = -1;
  if (matches.length > 0) {
    active = preferActive < 0 ? 0 : Math.min(preferActive, matches.length - 1);
  }
  return { query, caseSensitive, matches, active, decorations: buildDecorations(doc, matches, active) };
}

type Meta =
  | { kind: 'query'; query: string; caseSensitive: boolean }
  | { kind: 'active'; active: number }
  /** A single match was rewritten; `pos` is the end of the replacement. */
  | { kind: 'afterReplace'; pos: number }
  | { kind: 'clear' };

// `caseSensitive` lives here so that `clear` resets it: the find bar never
// sets the flag, and a find opened after a replace must not inherit a
// case rule it has no control to show.
const EMPTY: PluginState = {
  query: '',
  caseSensitive: false,
  matches: [],
  active: -1,
  decorations: DecorationSet.empty,
};

const searchPlugin = new Plugin<PluginState>({
  key: searchPluginKey,
  state: {
    init: () => EMPTY,
    apply(tr, value, _oldState, newState) {
      const meta = tr.getMeta(searchPluginKey) as Meta | undefined;
      if (meta) {
        if (meta.kind === 'clear') return EMPTY;
        if (meta.kind === 'query') return recompute(newState.doc, meta.query, meta.caseSensitive, 0);
        if (meta.kind === 'active') {
          const n = value.matches.length;
          if (n === 0) return value;
          const active = ((meta.active % n) + n) % n; // wrap past either end
          return { ...value, active, decorations: buildDecorations(newState.doc, value.matches, active) };
        }
        if (meta.kind === 'afterReplace') {
          // Land on the first match at or after the replacement, wrapping to
          // the top. One rule covers both outcomes of a replace: when the
          // replacement no longer matches, the list shrank and the next hit
          // slid into the old index; when it still matches ("cat" to
          // "cats"), the position rule steps past it instead of targeting
          // the text that was just written.
          const matches = findMatches(newState.doc, value.query, value.caseSensitive);
          let active = matches.findIndex((m) => m.from >= meta.pos);
          if (active < 0) active = matches.length > 0 ? 0 : -1;
          return { ...value, matches, active, decorations: buildDecorations(newState.doc, matches, active) };
        }
      }
      // Keep highlights live as the note is edited under an open bar.
      if (tr.docChanged && value.query) {
        return recompute(newState.doc, value.query, value.caseSensitive, value.active);
      }
      return value;
    },
  },
  props: {
    decorations(state) {
      return searchPluginKey.getState(state)?.decorations ?? DecorationSet.empty;
    },
  },
});

/** TipTap extension that registers the search-highlight plugin. */
export const SearchHighlight = Extension.create({
  name: 'pnSearchHighlight',
  addProseMirrorPlugins() {
    return [searchPlugin];
  },
});

// --- Drivers used by the React bars -------------------------------------

export function setSearchQuery(view: EditorView, query: string, caseSensitive = false): void {
  view.dispatch(view.state.tr.setMeta(searchPluginKey, { kind: 'query', query, caseSensitive }));
}

/** Move the active match by absolute index; wraps past either end. */
export function setActiveMatch(view: EditorView, active: number): void {
  view.dispatch(view.state.tr.setMeta(searchPluginKey, { kind: 'active', active }));
}

export function clearSearch(view: EditorView): void {
  view.dispatch(view.state.tr.setMeta(searchPluginKey, { kind: 'clear' }));
}

export type SearchInfo = {
  active: number;
  total: number;
  /** The active match is an attachment chip, which replace must refuse. */
  activeIsNode: boolean;
};

export function getSearchInfo(view: EditorView): SearchInfo {
  const st = searchPluginKey.getState(view.state);
  if (!st || st.matches.length === 0) return { active: -1, total: 0, activeIsNode: false };
  return { active: st.active, total: st.matches.length, activeIsNode: st.matches[st.active]?.node === true };
}

/** Center the current match in the scroll viewport (clear of sticky bars). */
export function scrollToCurrentMatch(view: EditorView): void {
  const hit = view.dom.querySelector('.pn-search-hit-current') as HTMLElement | null;
  hit?.scrollIntoView({ block: 'center', inline: 'nearest' });
}

/**
 * Center the current match and keep it centered until layout settles. On a
 * note that has just opened, the images above a hit decode and grow after
 * the first scroll and push it off screen, so this re-centers every frame
 * until the hit's position holds for five frames or 1.2 s pass, the settle
 * rule the file jump uses. The element is looked up each frame because
 * ProseMirror rebuilds the decoration spans on every update.
 */
export function scrollToCurrentMatchUntilSettled(view: EditorView): void {
  const start = performance.now();
  let lastTop = Number.NaN;
  let stableFrames = 0;
  const step = () => {
    if (view.isDestroyed) return;
    const hit = view.dom.querySelector('.pn-search-hit-current') as HTMLElement | null;
    if (!hit) return;
    const top = hit.getBoundingClientRect().top;
    if (Math.abs(top - lastTop) < 1) stableFrames++;
    else stableFrames = 0;
    lastTop = top;
    hit.scrollIntoView({ block: 'center', inline: 'nearest' });
    if (stableFrames >= 5 || performance.now() - start > 1200) return;
    requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

/**
 * Document range of the match currently highlighted, or null when there is
 * none. Used when the bar closes, to park the caret on the hit the reader was
 * looking at instead of leaving it wherever it was before the search started.
 */
export function getActiveMatchRange(view: EditorView): { from: number; to: number } | null {
  const st = searchPluginKey.getState(view.state);
  if (!st || st.active < 0) return null;
  const hit = st.matches[st.active];
  return hit ? { from: hit.from, to: hit.to } : null;
}

/**
 * Rewrite the active match and move on to the next one. Returns false when
 * there is nothing to replace: no active match, a read-only note, or an
 * attachment chip - its filename is node metadata, not text, so there is no
 * range to write into.
 *
 * `storedMarks` is cleared first so the new text takes the marks at its own
 * position. A stale stored mark (bold toggled with an empty selection before
 * the bar opened) would otherwise paint every replacement in it. An empty
 * replacement deletes the match; `insertText` routes that to `deleteRange`.
 */
export function replaceActiveMatch(view: EditorView, replacement: string): boolean {
  if (!view.editable) return false;
  const st = searchPluginKey.getState(view.state);
  if (!st || st.active < 0) return false;
  const hit = st.matches[st.active];
  if (!hit || hit.node) return false;
  const tr = view.state.tr.setStoredMarks(null).insertText(replacement, hit.from, hit.to);
  tr.setMeta(searchPluginKey, { kind: 'afterReplace', pos: hit.from + replacement.length });
  view.dispatch(tr);
  return true;
}

/**
 * Rewrite every text match in one transaction and return how many were
 * rewritten. Attachment chips are skipped for the reason above. The walk
 * runs from the last match to the first, because each write shifts every
 * position after it; in reverse, the positions still to be used are the
 * ones nothing has moved yet.
 */
export function replaceAllMatches(view: EditorView, replacement: string): number {
  if (!view.editable) return 0;
  const st = searchPluginKey.getState(view.state);
  if (!st || st.matches.length === 0) return 0;
  const text = st.matches.filter((m) => !m.node);
  if (text.length === 0) return 0;
  const tr = view.state.tr.setStoredMarks(null);
  for (let i = text.length - 1; i >= 0; i--) {
    const m = text[i]!;
    tr.insertText(replacement, m.from, m.to);
  }
  view.dispatch(tr);
  return text.length;
}
