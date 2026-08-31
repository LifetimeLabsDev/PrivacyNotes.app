// In-note find: a ProseMirror plugin that highlights case-insensitive
// matches of a query and tracks an "active" match for jump-to navigation.
// It is display-only (decorations), so it never mutates the note content.
//
// Matches are found per block: consecutive text nodes inside the same
// block are concatenated before searching, so a query can span multiple
// marks (e.g. a word that is partly bold) but never crosses a block
// boundary - the same granularity a browser find gives.
//
// The React find bar (EditorSearch.tsx) drives this through the exported
// helpers; Editor.tsx registers the SearchHighlight extension and renders
// the bar. CSS for the highlight classes lives in index.css.

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
 * Collect every case-insensitive match of `query` in the document.
 * Consecutive text nodes are merged into one run before searching so a
 * match can cross mark boundaries; a non-text node (block break, image,
 * hard break, note-link) ends the run. Sibling text nodes are
 * position-contiguous, so `run.pos + offset` maps back to a real doc
 * position.
 *
 * Attachment chips are matched by their filename attr (GitHub #167 - the
 * filename is node metadata, not document text, so the text scan can't
 * see it). A hit marks the whole chip as one node match.
 */
function findMatches(doc: PMNode, query: string): SearchMatch[] {
  if (!query) return [];
  let re: RegExp;
  try {
    re = new RegExp(escapeRegExp(query), 'gi');
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
      if (node.type.name === 'attachment') {
        const filename = node.attrs['filename'] as string | null;
        re.lastIndex = 0;
        if (filename && re.test(filename)) {
          nodeMatches.push({ from: pos, to: pos + node.nodeSize, node: true });
        }
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

function recompute(doc: PMNode, query: string, preferActive: number): PluginState {
  const matches = findMatches(doc, query);
  let active = -1;
  if (matches.length > 0) {
    active = preferActive < 0 ? 0 : Math.min(preferActive, matches.length - 1);
  }
  return { query, matches, active, decorations: buildDecorations(doc, matches, active) };
}

type Meta =
  | { kind: 'query'; query: string }
  | { kind: 'active'; active: number }
  | { kind: 'clear' };

const EMPTY: PluginState = {
  query: '',
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
        if (meta.kind === 'query') return recompute(newState.doc, meta.query, 0);
        if (meta.kind === 'active') {
          const n = value.matches.length;
          if (n === 0) return value;
          const active = ((meta.active % n) + n) % n; // wrap past either end
          return { ...value, active, decorations: buildDecorations(newState.doc, value.matches, active) };
        }
      }
      // Keep highlights live as the note is edited under an open bar.
      if (tr.docChanged && value.query) {
        return recompute(newState.doc, value.query, value.active);
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

// --- Drivers used by the React find bar --------------------------------

export function setSearchQuery(view: EditorView, query: string): void {
  view.dispatch(view.state.tr.setMeta(searchPluginKey, { kind: 'query', query }));
}

/** Move the active match by absolute index; wraps past either end. */
export function setActiveMatch(view: EditorView, active: number): void {
  view.dispatch(view.state.tr.setMeta(searchPluginKey, { kind: 'active', active }));
}

export function clearSearch(view: EditorView): void {
  view.dispatch(view.state.tr.setMeta(searchPluginKey, { kind: 'clear' }));
}

export function getSearchInfo(view: EditorView): { active: number; total: number } {
  const st = searchPluginKey.getState(view.state);
  if (!st || st.matches.length === 0) return { active: -1, total: 0 };
  return { active: st.active, total: st.matches.length };
}

/** Center the current match in the scroll viewport (clear of sticky bars). */
export function scrollToCurrentMatch(view: EditorView): void {
  const hit = view.dom.querySelector('.pn-search-hit-current') as HTMLElement | null;
  hit?.scrollIntoView({ block: 'center', inline: 'nearest' });
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
