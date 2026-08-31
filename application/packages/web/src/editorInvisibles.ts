/**
 * Builders for the invisible-characters overlay, with the space builder
 * replaced by one that stops shattering links.
 *
 * @tiptap/extension-invisible-characters paints one widget decoration per
 * space, and hardcodes `marks: []` on the widget spec. prosemirror-view reads
 * that as "draw this widget outside every open mark", so it closes the
 * surrounding mark elements and reopens them after the widget. Inside a link
 * that splits one <a> into one <a> PER WORD: the favicon our Link.renderHTML
 * hangs off ::before then repeats on every word, and hover only lights up the
 * word under the cursor. Reported on an OpenStreetMap link from the Apple
 * Journal importer; reproduces with any multi-word link once invisibles are on.
 *
 * Omitting `marks` entirely, rather than passing the marks found at decoration
 * time, is deliberate: prosemirror-view then resolves the marks from the LIVE
 * document as it renders, so linking text that already carries space dots is
 * right immediately. Marks captured when the decoration is built would go
 * stale in exactly that case, because AddMarkStep maps to an empty StepMap and
 * the plugin only rebuilds decorations for ranges a step reports.
 *
 * Only the space builder needs this. The pilcrow and the line-break arrow are
 * positioned at block boundaries, where staying outside the inline marks is
 * what we want.
 *
 * Spec: ops/docs/design-decisions.md (Invisible characters toggle)
 */

import { Decoration, DecorationSet } from '@tiptap/pm/view';
import type { Node as PMNode } from '@tiptap/pm/model';
import { Plugin, PluginKey, AllSelection } from '@tiptap/pm/state';
import type { EditorState, Transaction } from '@tiptap/pm/state';
import {
  HardBreakNode,
  InvisibleCharacters,
  ParagraphNode,
  SpaceCharacter,
  type InvisibleCharacter,
  type InvisibleNode,
} from '@tiptap/extension-invisible-characters';

/** The extension's own widget factory, minus the `marks: []`. `key` and `side`
 *  are copied verbatim so decoration identity and ordering are unchanged. */
function spaceWidget(pos: number): Decoration {
  return Decoration.widget(
    pos,
    () => {
      const el = document.createElement('span');
      el.classList.add('tiptap-invisible-character');
      el.classList.add('tiptap-invisible-character--space');
      return el;
    },
    { key: 'space', side: 1000 },
  );
}

/** Mirrors InvisibleCharacter.createDecoration (its own textBetween walk is
 *  private), differing only in the widget it builds. */
class MarkPreservingSpaceCharacter extends SpaceCharacter {
  createDecoration(from: number, to: number, doc: PMNode, decorations: DecorationSet): DecorationSet {
    const widgets: Decoration[] = [];
    doc.nodesBetween(from, to, (node, pos) => {
      if (!node.isText || !node.text) return;
      const offset = Math.max(from, pos) - pos;
      const text = node.text.slice(offset, to - pos);
      for (let i = 0; i < text.length; i++) {
        if (this.test(text[i]!)) widgets.push(spaceWidget(pos + offset + i));
      }
    });
    return widgets.length === 0 ? decorations : decorations.add(doc, widgets);
  }
}

/**
 * The extension's default builder list with our space builder swapped in.
 * Passing `builders` REPLACES the defaults wholesale, so the pilcrow and
 * line-break builders have to be re-listed here or they stop rendering.
 *
 * A fresh array per call because the plugin sorts `options.builders` in place
 * on every decoration pass.
 */
export function invisibleCharacterBuilders(): (InvisibleCharacter | InvisibleNode)[] {
  return [new MarkPreservingSpaceCharacter(), new ParagraphNode(), new HardBreakNode()];
}

const lazyInvisiblesKey = new PluginKey<{ visible: boolean; decorations: DecorationSet | null }>(
  'invisibleCharacters',
);

/** Mirrors the package's private getUpdatedRanges: the doc ranges this
 *  transaction touched, mapped to final coordinates. */
function updatedRanges(tr: Transaction): [number, number][] {
  const ranges: [number, number][] = [];
  tr.mapping.maps.forEach((stepMap, i) => {
    stepMap.forEach((_oldStart, _oldEnd, newStart, newEnd) => {
      ranges.push([tr.mapping.slice(i + 1).map(newStart), tr.mapping.slice(i + 1).map(newEnd)]);
    });
  });
  return ranges;
}

/**
 * InvisibleCharacters with the decoration work made lazy (#150).
 *
 * Upstream's plugin builds one widget decoration per space, pilcrow and
 * break across the ENTIRE document inside plugin init - even with
 * `visible: false` - and keeps that set mapped on every transaction while
 * hidden. At a few thousand blocks that init alone cost ~600 ms of the
 * editor-creation freeze, paid on every note open with the toggle off.
 * This variant builds NOTHING while hidden: the full set is built once
 * when the toggle turns on (the cost then buys something the user asked
 * to see), maintained incrementally while visible with the same
 * ranges-touched walk as upstream, and dropped again when hidden.
 *
 * The inherited show/hide commands only set the
 * `setInvisibleCharactersVisible` meta this plugin reads, so they work
 * unchanged. `toggleInvisibleCharacters` and `storage.visibility()` read
 * plugin STATE by key, which upstream resolves via its own module-private
 * key - both are re-pointed at ours here. CSS injection is dropped with
 * the init that carried it: the base rules are vendored in index.css
 * (invisible-characters block), where our overrides already lived.
 */
export const LazyInvisibleCharacters = InvisibleCharacters.extend({
  addProseMirrorPlugins() {
    const options = this.options;
    const buildBetween = (from: number, to: number, doc: PMNode, decorations: DecorationSet) =>
      [...options.builders]
        .sort((a, b) => (a.priority > b.priority ? 1 : -1))
        .reduce((set, builder) => builder.createDecoration(from, to, doc, set), decorations);
    const buildAll = (state: EditorState) => {
      const { $from, $to } = new AllSelection(state.doc);
      return buildBetween($from.pos, $to.pos, state.doc, DecorationSet.empty);
    };
    return [
      new Plugin({
        key: lazyInvisiblesKey,
        state: {
          init: (_config, state) => ({
            visible: options.visible,
            decorations: options.visible ? buildAll(state) : null,
          }),
          apply: (tr, pluginState, _old, currentState) => {
            const meta = tr.getMeta('setInvisibleCharactersVisible') as boolean | undefined;
            const visible = meta === undefined ? pluginState.visible : meta;
            if (!visible) return { visible, decorations: null };
            let decorations = pluginState.decorations;
            if (decorations === null) {
              decorations = buildAll(currentState);
            } else if (tr.docChanged) {
              decorations = updatedRanges(tr).reduce(
                (set, [from, to]) => buildBetween(from, to, currentState.doc, set),
                decorations.map(tr.mapping, tr.doc),
              );
            }
            return { visible, decorations };
          },
        },
        props: {
          decorations(state) {
            const ps = lazyInvisiblesKey.getState(state);
            return ps?.visible && ps.decorations ? ps.decorations : DecorationSet.empty;
          },
        },
      }),
    ];
  },
  onBeforeCreate() {
    this.storage.visibility = () => lazyInvisiblesKey.getState(this.editor.state)?.visible ?? false;
  },
  addCommands() {
    return {
      ...this.parent?.(),
      toggleInvisibleCharacters: () => ({ dispatch, tr, state }) => {
        const visibility = !(lazyInvisiblesKey.getState(state)?.visible ?? false);
        if (dispatch) tr.setMeta('setInvisibleCharactersVisible', visibility);
        return true;
      },
    };
  },
});
