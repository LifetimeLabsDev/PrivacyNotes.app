/**
 * Fence highlighting for markdownRender, loaded on demand.
 *
 * A separate module for one load-bearing reason: markdownRender must reach
 * lowlight through a DYNAMIC import (the burn viewer's chunk cannot carry a
 * highlighter for notes that have no code in them), and dynamically importing
 * the 'lowlight' package itself keeps its entire namespace alive - including
 * `all`, every hljs grammar there is - which quadrupled the lowlight chunk to
 * ~294 kB gz the first time it was tried. The STATIC import below tree-shakes
 * back down to `common`, the exact grammar set the editor's own instance
 * (editorExtensions.ts) already ships, so this module adds nothing the app
 * was not already carrying.
 *
 * The output is hljs token <span>s, the same classes CodeBlockLowlight emits
 * in the editor, so the burn viewer colors them through the `.prose pre
 * .hljs-*` palette in index.css and the export stylesheet carries a copy.
 */
import { createLowlight, common } from 'lowlight';

const lowlight = createLowlight(common);

interface HastNode {
  type: string;
  value?: string;
  tagName?: string;
  properties?: { className?: string[] };
  children?: HastNode[];
}

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function hastToHtml(nodes: HastNode[]): string {
  let out = '';
  for (const n of nodes) {
    if (n.type === 'text') {
      out += esc(n.value ?? '');
    } else if (n.type === 'element' && n.tagName === 'span') {
      out += `<span class="${(n.properties?.className ?? []).join(' ')}">${hastToHtml(n.children ?? [])}</span>`;
    } else if (n.children) {
      out += hastToHtml(n.children);
    }
  }
  return out;
}

/** hljs-tokenized HTML for the fence, or null when the language is unknown. */
export function highlightCode(code: string, lang: string): string | null {
  try {
    if (!lang || !lowlight.registered(lang)) return null;
    return hastToHtml(lowlight.highlight(lang, code).children as unknown as HastNode[]);
  } catch {
    return null;
  }
}
