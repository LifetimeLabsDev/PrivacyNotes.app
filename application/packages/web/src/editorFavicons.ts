/**
 * The link favicon chip, applied only once the icon is actually in hand.
 *
 * The chip itself is CSS: `--fav` carries the image and a ::before paints it
 * on a light tile (index.css). The tile is drawn whether or not the image
 * loads, so setting `--fav` from the Link mark's renderHTML - which cannot
 * know whether a domain HAS an icon - left an empty white box sitting in the
 * middle of a sentence for every domain the proxy misses. That is not a rare
 * case: example.com is one, DuckDuckGo answering 200 with zero bytes and
 * Google 404ing, and any word ending in a real TLD that autolink turned into
 * a link is another.
 *
 * So the property is applied here instead, as an inline decoration, and only
 * for a URL `ensureFavicon` has already resolved. A miss paints nothing at
 * all - no box, no gap, no repeat request - and an icon that arrives later
 * repaints through the plugin's own meta transaction.
 *
 * The decoration covers the link's FIRST CHARACTER rather than its whole
 * range on purpose. prosemirror-view renders an inline decoration as a span
 * INSIDE the mark, one per text node it spans, so a whole-link decoration
 * would repeat the chip on every link the document happens to split - bold
 * inside a link, or an invisible-characters widget at a space, which is the
 * shape of GitHub #205. One character is always one span.
 *
 * Spec: ops/docs/design-decisions.md (Website icons toggle)
 */

import { Extension } from '@tiptap/core';
import type { Editor } from '@tiptap/core';
import { Plugin, PluginKey } from '@tiptap/pm/state';
import { Decoration, DecorationSet } from '@tiptap/pm/view';
import type { Node as PMNode } from '@tiptap/pm/model';
import { domainFromUrlString, faviconUrl } from './favicon';
import { ensureFavicon } from './faviconQueue';
import { getFavicons } from './theme';

const faviconKey = new PluginKey<DecorationSet>('pnFavicons');

function build(doc: PMNode, onResolved: () => void): DecorationSet {
  if (!getFavicons()) return DecorationSet.empty;

  const decos: Decoration[] = [];
  // A single link can span several text nodes (bold or coloured runs inside
  // it). Only the first of a run gets a chip.
  let prevEnd = -1;
  let prevHref = '';

  doc.descendants((node, pos) => {
    if (!node.isText) return;
    const link = node.marks.find((m) => m.type.name === 'link');
    if (!link) {
      prevEnd = -1;
      return;
    }

    const href: string = link.attrs.href || '';
    const continued = pos === prevEnd && href === prevHref;
    prevEnd = pos + node.nodeSize;
    prevHref = href;
    if (continued || !/^https?:\/\//i.test(href)) return;

    const domain = domainFromUrlString(href);
    const url = domain ? faviconUrl(domain) : '';
    if (!url) return;

    const icon = ensureFavicon(url, onResolved);
    if (icon) decos.push(Decoration.inline(pos, pos + 1, { style: `--fav:url(${icon})` }));
  });

  return DecorationSet.create(doc, decos);
}

/** Recompute the chips without touching the document. Used when an icon
 *  finishes downloading, and when the Appearance toggle flips. */
export function refreshFavicons(editor: Editor | null): void {
  const view = editor?.view;
  if (!view || view.isDestroyed) return;
  view.dispatch(view.state.tr.setMeta(faviconKey, true));
}

export const FaviconChips = Extension.create({
  name: 'faviconChips',

  addProseMirrorPlugins() {
    const { editor } = this;
    const onResolved = () => { refreshFavicons(editor); };

    return [
      new Plugin<DecorationSet>({
        key: faviconKey,
        state: {
          init: (_config, state) => build(state.doc, onResolved),
          apply: (tr, current, _old, state) =>
            tr.docChanged || tr.getMeta(faviconKey) ? build(state.doc, onResolved) : current,
        },
        props: {
          decorations(state) { return faviconKey.getState(state); },
        },
      }),
    ];
  },
});
