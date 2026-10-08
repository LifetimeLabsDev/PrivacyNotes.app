/**
 * Markdown footnotes: `[^label]` in the text, `[^label]: text` at the end.
 *
 * Three nodes. A marker is an inline atom that stores its label; the shown
 * number is computed from marker order and never written back, so a label a
 * person typed (`[^source]`) stays exactly as it was. The definitions live in
 * one `footnotes` section that the document schema keeps last and single.
 *
 * The parse borrows markdown-it-footnote's block and inline rules, which win
 * over markdown-it's own link reference definitions: without them a one-word
 * definition such as `[^1]: Source.` read as a link target and was lost on the
 * next save. Its tail rule and its HTML are replaced, because the tail drops
 * every definition no marker uses, and a dropped definition is a dropped node.
 *
 * Spec: ops/docs/plans/footnotes.md
 */
import i18n from './i18n';
import footnotePlugin from 'markdown-it-footnote';
import { Extension, InputRule, Node, mergeAttributes, type Editor as TipTapEditor } from '@tiptap/core';
import { sanitizePastedHtml } from './EncryptedImage';
import { DOMParser as PMDOMParser, DOMSerializer, Fragment, Slice, type Node as ProseMirrorNode, type Schema } from '@tiptap/pm/model';
import {
  NodeSelection,
  Plugin,
  PluginKey,
  Selection,
  TextSelection,
  type EditorState,
  type Transaction,
} from '@tiptap/pm/state';
import { Decoration, DecorationSet, type EditorView } from '@tiptap/pm/view';

/* ------------------------------------------------------------------ */
/* Reading the document                                               */
/* ------------------------------------------------------------------ */

const REF = 'footnoteReference';
const SECTION = 'footnotes';

/**
 * The section's one attribute, required on purpose. After the first block the
 * document's content rule lists `footnotes` as its first allowed type, so
 * ProseMirror's `defaultType` (what a command reaches for as "the normal block
 * here") was the section: TipTap's `clearNodes`, run by every list toggle over
 * a whole-note selection, threw "Invalid content for node type footnotes".
 * `defaultType` and the content fitter skip a type with a required attribute.
 */
const SECTION_ATTRS = { kind: 'footnotes' };
const DEF = 'footnote';

/** The section, when the note has one, with its position. */
function sectionOf(doc: ProseMirrorNode): { node: ProseMirrorNode; pos: number } | null {
  const last = doc.lastChild;
  if (!last || last.type.name !== SECTION) return null;
  return { node: last, pos: doc.content.size - last.nodeSize };
}

interface DefEntry {
  node: ProseMirrorNode;
  pos: number;
}

/** Every definition in section order. The first one with a label binds. */
function definitionsOf(doc: ProseMirrorNode): DefEntry[] {
  const section = sectionOf(doc);
  if (!section) return [];
  const out: DefEntry[] = [];
  section.node.forEach((child, offset) => {
    out.push({ node: child, pos: section.pos + 1 + offset });
  });
  return out;
}

interface RefEntry {
  label: string;
  pos: number;
}

function refsIn(node: ProseMirrorNode, base: number, out: RefEntry[]): void {
  node.descendants((child, pos) => {
    if (child.type.name === REF) out.push({ label: child.attrs['label'] as string, pos: base + pos });
    return !child.isLeaf;
  });
}

export interface FootnoteIndex {
  /** Shown number of each label that a marker uses. */
  numbers: Map<string, number>;
  /** First definition of each label. */
  defs: Map<string, DefEntry>;
  /** Every marker, body first, then those inside definitions. */
  refs: RefEntry[];
  /** First marker of each label. */
  firstRef: Map<string, number>;
}

/**
 * Numbers the markers of the body in order, then the markers inside the
 * definitions in the order those definitions are reached. Each label is
 * visited once, so two definitions that point at each other end the walk.
 */
export function indexFootnotes(doc: ProseMirrorNode): FootnoteIndex {
  const defs = new Map<string, DefEntry>();
  for (const d of definitionsOf(doc)) {
    const label = d.node.attrs['label'] as string;
    if (!defs.has(label)) defs.set(label, d);
  }
  const section = sectionOf(doc);
  const body: RefEntry[] = [];
  doc.forEach((child, offset) => {
    if (child !== section?.node) refsIn(child, offset + 1, body);
  });
  const numbers = new Map<string, number>();
  const firstRef = new Map<string, number>();
  const refs: RefEntry[] = [...body];
  const order: string[] = [];
  const take = (r: RefEntry) => {
    if (!firstRef.has(r.label)) firstRef.set(r.label, r.pos);
    if (defs.has(r.label) && !numbers.has(r.label)) {
      numbers.set(r.label, numbers.size + 1);
      order.push(r.label);
    }
  };
  body.forEach(take);
  for (let i = 0; i < order.length; i++) {
    const d = defs.get(order[i]!)!;
    const inner: RefEntry[] = [];
    refsIn(d.node, d.pos + 1, inner);
    inner.forEach((r) => {
      refs.push(r);
      take(r);
    });
  }
  return { numbers, defs, refs, firstRef };
}

/** One more than the largest number label, skipping any label in use. */
function nextFreeLabel(doc: ProseMirrorNode, taken: Iterable<string> = []): string {
  const used = new Set<string>(taken);
  doc.descendants((node) => {
    if (node.type.name === REF || node.type.name === DEF) used.add(node.attrs['label'] as string);
    return true;
  });
  let max = 0;
  // Nine digits at most: past 2^53 adding one changes nothing, and the
  // free-label loop below would never end.
  for (const l of used) if (/^\d{1,9}$/.test(l)) max = Math.max(max, Number(l));
  let n = max + 1;
  while (used.has(String(n))) n++;
  return String(n);
}

/**
 * Where a new definition for `label` goes: before the first definition that
 * numbers later or is not used, so the section keeps reading 1, 2, 3.
 * Returns null when the note has no section yet.
 */
function sortedInsertPos(doc: ProseMirrorNode, label: string): number | null {
  const section = sectionOf(doc);
  if (!section) return null;
  const { numbers } = indexFootnotes(doc);
  const target = numbers.get(label) ?? Number.POSITIVE_INFINITY;
  for (const d of definitionsOf(doc)) {
    const n = numbers.get(d.node.attrs['label'] as string);
    if (n === undefined || n > target) return d.pos;
  }
  return section.pos + section.node.nodeSize - 1;
}

/** Adds `def` to the section at its sorted place, making the section if needed. */
function insertDefinition(tr: Transaction, def: ProseMirrorNode): number {
  const at = sortedInsertPos(tr.doc, def.attrs['label'] as string);
  if (at !== null) {
    tr.insert(at, def);
    return at;
  }
  const section = tr.doc.type.schema.nodes[SECTION]!.create(SECTION_ATTRS, def);
  const end = tr.doc.content.size;
  tr.insert(end, section);
  return end + 1;
}

function emptyDefinition(schema: Schema, label: string): ProseMirrorNode {
  return schema.nodes[DEF]!.create({ label }, schema.nodes['paragraph']!.create());
}

function isEmptyDefinition(def: ProseMirrorNode): boolean {
  return def.childCount === 1 && def.firstChild!.type.name === 'paragraph' && def.firstChild!.content.size === 0;
}

/** Position at the end of the last textblock of a definition. */
function endOfDefinition(doc: ProseMirrorNode, defPos: number): number {
  const def = doc.nodeAt(defPos)!;
  return Selection.near(doc.resolve(defPos + def.nodeSize - 1), -1).from;
}

/* ------------------------------------------------------------------ */
/* Markdown parse                                                     */
/* ------------------------------------------------------------------ */

/* Minimal shapes of the markdown-it objects the rules below touch. */
interface MdToken {
  type: string;
  tag: string;
  nesting: number;
  meta: { label?: string; id?: number } | null;
  block: boolean;
  content: string;
  children: MdToken[] | null;
}
interface MdFootnoteEnv {
  refs?: Record<string, number>;
  list?: { label?: string; content?: string; tokens?: MdToken[] }[];
  labels?: Record<number, string>;
}
interface MdCoreState {
  tokens: MdToken[];
  env: { footnotes?: MdFootnoteEnv };
  Token: new (type: string, tag: string, nesting: number) => MdToken;
}
type MdRenderRule = (tokens: MdToken[], idx: number, options: unknown, env: { footnotes?: MdFootnoteEnv }) => string;
interface FootnoteMarkdownIt {
  use: (plugin: unknown) => unknown;
  core: { ruler: { at: (name: string, fn: (state: MdCoreState) => void) => void } };
  renderer: { rules: Record<string, MdRenderRule> };
  utils: { escapeHtml: (s: string) => string };
}

/**
 * The replacement tail. Pulls every definition out of the token stream in
 * file order, binds the first of each label, and emits one section: the used
 * definitions in marker order (inline `^[...]` notes among them), then the
 * unused ones in file order. A later definition that repeats a label gets a
 * free label of its own, so its text is never lost.
 */
function footnoteTail(state: MdCoreState): void {
  const env = state.env.footnotes;
  if (!env) return;

  const groups: { label: string; tokens: MdToken[] }[] = [];
  const stack: { label: string; tokens: MdToken[] }[] = [];
  const kept: MdToken[] = [];
  for (const tok of state.tokens) {
    if (tok.type === 'footnote_reference_open') {
      const g = { label: tok.meta?.label ?? '', tokens: [] as MdToken[] };
      groups.push(g);
      stack.push(g);
      continue;
    }
    if (tok.type === 'footnote_reference_close') {
      stack.pop();
      continue;
    }
    (stack.length ? stack[stack.length - 1]!.tokens : kept).push(tok);
  }
  const list = env.list ?? [];
  if (!groups.length && !list.length) return;
  state.tokens = kept;

  const used = new Set<string>(groups.map((g) => g.label));
  let max = 0;
  // Nine digits at most: past 2^53 adding one changes nothing, and the
  // free-label loop below would never end.
  for (const l of used) if (/^\d{1,9}$/.test(l)) max = Math.max(max, Number(l));
  const fresh = () => {
    let n = max + 1;
    while (used.has(String(n))) n++;
    max = n;
    used.add(String(n));
    return String(n);
  };

  const bound = new Map<string, { label: string; tokens: MdToken[] }>();
  const extras: { label: string; tokens: MdToken[] }[] = [];
  for (const g of groups) {
    if (bound.has(g.label)) extras.push({ label: fresh(), tokens: g.tokens });
    else bound.set(g.label, g);
  }

  const out: { label: string; tokens: MdToken[] }[] = [];
  const emitted = new Set<string>();
  env.labels = {};
  list.forEach((entry, id) => {
    if (entry.label !== undefined) {
      env.labels![id] = entry.label;
      const g = bound.get(entry.label);
      if (g && !emitted.has(g.label)) {
        emitted.add(g.label);
        out.push(g);
      }
      return;
    }
    // An inline `^[text]` note: it becomes a definition of its own.
    const label = fresh();
    env.labels![id] = label;
    const open = new state.Token('paragraph_open', 'p', 1);
    open.block = true;
    const inline = new state.Token('inline', '', 0);
    inline.children = entry.tokens ?? [];
    inline.content = entry.content ?? '';
    const close = new state.Token('paragraph_close', 'p', -1);
    close.block = true;
    out.push({ label, tokens: [open, inline, close] });
    emitted.add(label);
  });
  for (const g of groups) if (bound.get(g.label) === g && !emitted.has(g.label)) out.push(g);
  out.push(...extras);

  state.tokens.push(new state.Token('footnote_block_open', '', 1));
  for (const g of out) {
    const open = new state.Token('footnote_open', '', 1);
    open.meta = { label: g.label };
    state.tokens.push(open, ...g.tokens, new state.Token('footnote_close', '', -1));
  }
  state.tokens.push(new state.Token('footnote_block_close', '', -1));
}

const setUp = new WeakSet<object>();

/**
 * Registers the footnote rules on a markdown-it instance, once. tiptap-markdown
 * calls every `parse.setup` on every parse, on the same instance, so a bare
 * `md.use` here would stack another copy of each rule per load.
 */
function setupFootnoteMarkdown(md: FootnoteMarkdownIt): void {
  if (setUp.has(md)) return;
  setUp.add(md);
  md.use(footnotePlugin);
  md.core.ruler.at('footnote_tail', footnoteTail);
  const esc = md.utils.escapeHtml;
  md.renderer.rules['footnote_ref'] = (tokens, idx, _o, env) => {
    const meta = tokens[idx]!.meta ?? {};
    const label = (meta.id !== undefined ? env.footnotes?.labels?.[meta.id] : undefined) ?? meta.label ?? '';
    return `<sup data-fn-ref="" data-fn-label="${esc(label)}"></sup>`;
  };
  md.renderer.rules['footnote_block_open'] = () => '<section data-fn-section="">\n';
  md.renderer.rules['footnote_block_close'] = () => '</section>\n';
  md.renderer.rules['footnote_open'] = (tokens, idx) =>
    `<div data-fn-def="" data-fn-label="${esc(tokens[idx]!.meta?.label ?? '')}">\n`;
  md.renderer.rules['footnote_close'] = () => '</div>\n';
  md.renderer.rules['footnote_anchor'] = () => '';
}

/* ------------------------------------------------------------------ */
/* Pasted HTML from the web                                           */
/* ------------------------------------------------------------------ */

const BACKLINKS = 'a.footnote-backref, a[data-footnote-backref], .mw-cite-backlink';

/**
 * Rewrites the footnotes of pasted web HTML into ours: GitHub, pandoc and
 * markdown-it (`section.footnotes li[id]`), and Wikipedia
 * (`ol.references li[id]`). A marker whose definition is not in the paste
 * stays as the text it showed, never a node with no text behind it.
 */
export function normalizePastedFootnotes(html: string): string {
  if (!/footnote|cite_note|fnref|data-fn-/i.test(html)) return html;
  // Never throws: a throw here would fail the paste open, past every other paste step.
  try {
    return rewritePastedFootnotes(html);
  } catch {
    return html;
  }
}

function rewritePastedFootnotes(html: string): string {
  const doc = new DOMParser().parseFromString(html, 'text/html');
  const items = new Map<string, Element>();
  doc.querySelectorAll('section.footnotes li[id], section[data-footnotes] li[id], div.footnotes li[id], ol.references li[id]').forEach(
    (li) => items.set(li.id, li),
  );
  let changed = false;
  const labels = new Map<string, string>();
  let next = 1;
  doc.querySelectorAll('sup').forEach((sup) => {
    if (sup.hasAttribute('data-fn-ref')) return;
    const a = sup.querySelector('a[href^="#"]');
    if (!a) return;
    const raw = a.getAttribute('href')!.slice(1);
    let id = raw;
    try {
      id = decodeURIComponent(raw);
    } catch {
      /* a malformed escape keeps the raw id */
    }
    if (!/fn|cite_note|footnote/i.test(id) && !items.has(id)) return;
    changed = true;
    const li = items.get(id);
    if (!li) {
      sup.replaceWith(doc.createTextNode(a.textContent ?? ''));
      return;
    }
    if (!labels.has(id)) labels.set(id, String(next++));
    const ref = doc.createElement('sup');
    ref.setAttribute('data-fn-ref', '');
    ref.setAttribute('data-fn-label', labels.get(id)!);
    sup.replaceWith(ref);
  });
  if (labels.size) {
    const section = doc.createElement('section');
    section.setAttribute('data-fn-section', '');
    for (const [id, label] of labels) {
      const li = items.get(id)!;
      li.querySelectorAll(BACKLINKS).forEach((el) => el.remove());
      const def = doc.createElement('div');
      def.setAttribute('data-fn-def', '');
      def.setAttribute('data-fn-label', label);
      const hasBlock = Array.from(li.children).some((c) => /^(P|UL|OL|PRE|BLOCKQUOTE|TABLE)$/.test(c.tagName));
      if (hasBlock) def.append(...Array.from(li.childNodes));
      else {
        const p = doc.createElement('p');
        p.append(...Array.from(li.childNodes));
        def.append(p);
      }
      section.append(def);
    }
    doc.body.append(section);
  }
  // The source's own list goes either way: its items are in the section now,
  // or none of them had a marker in the paste.
  if (changed) {
    doc.querySelectorAll('section.footnotes, section[data-footnotes], div.footnotes, ol.references').forEach((el) => {
      if (!el.hasAttribute('data-fn-section')) el.remove();
    });
  }
  return changed ? doc.body.innerHTML : html;
}

/* ------------------------------------------------------------------ */
/* Copy and paste                                                     */
/* ------------------------------------------------------------------ */

/**
 * A copy carries the definition of every marker it holds, and the definitions
 * those point at in turn, as the `carry` attribute: the definition's HTML. A
 * footnote moved between notes keeps its text that way and never binds to the
 * target note's own footnote of the same label. The attribute is a string on
 * purpose: ProseMirror compares attributes deeply, and a node there would walk
 * the schema's cycles. It is never stored: `repairFootnotes` takes it off in
 * the same change, so the live view never draws it.
 */
function carryDefinitions(slice: Slice, doc: ProseMirrorNode): Slice {
  const defs = new Map([...indexFootnotes(doc).defs].map(([label, d]) => [label, d.node]));
  const content = attachCarry(slice.content, defs);
  return content === slice.content ? slice : new Slice(content, slice.openStart, slice.openEnd);
}

/**
 * Gives every marker in `fragment` whose definition is in `defs` the HTML of
 * that definition, with its own markers carried in turn. A label already on
 * the way down is not carried again, so two definitions that point at each
 * other end. Returns the same fragment when nothing was carried.
 */
function attachCarry(fragment: Fragment, defs: Map<string, ProseMirrorNode>, visiting = new Set<string>()): Fragment {
  let touched = false;
  const out: ProseMirrorNode[] = [];
  fragment.forEach((node) => {
    const label = node.attrs['label'] as string;
    if (node.type.name === REF && !node.attrs['carry'] && defs.has(label) && !visiting.has(label)) {
      touched = true;
      const def = defs.get(label)!;
      const carried = def.copy(attachCarry(def.content, defs, new Set(visiting).add(label)));
      out.push(node.type.create({ ...node.attrs, carry: carryHtml(carried) }));
      return;
    }
    if (node.isLeaf) {
      out.push(node);
      return;
    }
    const inner = attachCarry(node.content, defs, visiting);
    if (inner !== node.content) touched = true;
    out.push(inner === node.content ? node : node.copy(inner));
  });
  return touched ? Fragment.fromArray(out) : fragment;
}

/** The schema's own parser: the view caches it, from the same module as the nodes. */
function parserOf(schema: Schema): PMDOMParser {
  return (schema.cached['domParser'] as PMDOMParser | undefined) ?? PMDOMParser.fromSchema(schema);
}

/** A definition's content as HTML. Built in a detached document. */
function carryHtml(def: ProseMirrorNode): string {
  const doc = document.implementation.createHTMLDocument('');
  const holder = doc.createElement('div');
  const serializer = (def.type.schema.cached['domSerializer'] as DOMSerializer | undefined) ?? DOMSerializer.fromSchema(def.type.schema);
  holder.append(serializer.serializeFragment(def.content, { document: doc }));
  return holder.innerHTML;
}

/**
 * The definition a marker carries, as a node, or null. The HTML is never data
 * a node is built from: it goes through the paste's picture step (only the
 * app's own pictures stay) and is parsed in a detached document, which loads
 * and runs nothing, by the schema's own rules.
 */
function carriedNode(html: unknown, schema: Schema, label: string): ProseMirrorNode | null {
  if (typeof html !== 'string') return null;
  try {
    const holder = document.implementation.createHTMLDocument('').createElement('div');
    holder.innerHTML = sanitizePastedHtml(html, { store: false });
    const node = parserOf(schema).parse(holder, { topNode: schema.nodes[DEF]!.create({ label }) });
    node.check();
    return node;
  } catch {
    return null;
  }
}

/**
 * A pasted slice can hold a section of its own (a paste of Markdown text with
 * definitions, a copy that reached the end of a note, web HTML). A section
 * can only be the last child of a document, so it cannot land in the middle
 * of a paragraph: its definitions move onto the markers as `carry` instead.
 */
function liftPastedSection(slice: Slice): Slice {
  const last = slice.content.lastChild;
  if (!last || last.type.name !== SECTION) return slice;
  const defs = new Map<string, ProseMirrorNode>();
  last.forEach((def) => {
    const label = def.attrs['label'] as string;
    if (!defs.has(label)) defs.set(label, def);
  });
  const rest = attachCarry(slice.content.cut(0, slice.content.size - last.nodeSize), defs);
  if (rest.size === 0) return Slice.empty;
  // Open the new end, so the last pasted line joins the text after the caret
  // as it would have without the section behind it.
  return new Slice(rest, slice.openStart, Slice.maxOpen(rest).openEnd);
}

/** The definitions a copied fragment carries, as a section, for the text form of the copy. */
export function carriedSection(content: Fragment, schema: Schema): ProseMirrorNode | null {
  const defs: ProseMirrorNode[] = [];
  const seen = new Set<string>();
  const walk = (fragment: Fragment) =>
    fragment.descendants((node) => {
      if (node.type.name !== REF) return true;
      const label = node.attrs['label'] as string;
      if (seen.has(label)) return false;
      const def = carriedNode(node.attrs['carry'], schema, label);
      if (!def) return false;
      seen.add(label);
      defs.push(def);
      walk(def.content);
      return false;
    });
  walk(content);
  return defs.length ? schema.nodes[SECTION]!.create(SECTION_ATTRS, defs) : null;
}

/** A node with every `carry` taken off, for comparing a carried definition with a stored one. */
function withoutCarry(node: ProseMirrorNode): ProseMirrorNode {
  if (node.type.name === REF) return node.attrs['carry'] ? node.type.create({ ...node.attrs, carry: null }) : node;
  if (node.isLeaf) return node;
  const children: ProseMirrorNode[] = [];
  node.forEach((child) => children.push(withoutCarry(child)));
  return node.copy(Fragment.fromArray(children));
}

function sameContent(stored: ProseMirrorNode, carried: ProseMirrorNode): boolean {
  return stored.content.eq(withoutCarry(carried).content);
}

/**
 * Adopts the definitions that pasted markers carry, then repairs a label used
 * by two definitions. A carried definition can hold markers that carry their
 * own, so adoption runs until no marker carries anything: ProseMirror never
 * shows a plugin its own appended transaction, so a second round would not
 * come by itself. Each repair runs once, so a later change finds nothing to do.
 */
function repairFootnotes(state: EditorState): Transaction | null {
  const { schema } = state;
  // In the history: the history merges an appended change into the event of
  // the change that caused it, so one undo takes a paste and its footnotes.
  const tr = state.tr;

  // A label another definition already uses: the later one takes a free label.
  const seen = new Set<string>();
  for (const d of definitionsOf(state.doc)) {
    const label = d.node.attrs['label'] as string;
    if (seen.has(label)) tr.setNodeMarkup(tr.mapping.map(d.pos), undefined, { label: nextFreeLabel(tr.doc) });
    seen.add(label);
  }

  const renamed = new Map<string, string>();
  for (let round = 0; round < 16; round++) {
    const carriers: { pos: number; node: ProseMirrorNode }[] = [];
    tr.doc.descendants((node, pos) => {
      if (node.type.name === REF && node.attrs['carry']) carriers.push({ pos, node });
      return true;
    });
    if (!carriers.length) break;
    const start = tr.mapping.maps.length;
    for (const c of carriers) {
      const pos = tr.mapping.slice(start).map(c.pos);
      const label = c.node.attrs['label'] as string;
      const carried = carriedNode(c.node.attrs['carry'], schema, label);
      // One key per carried text, so two pasted markers of one footnote land on one definition.
      const key = `${label}\u0000${c.node.attrs['carry'] as string}`;
      let finalLabel = renamed.get(key) ?? label;
      if (carried && !renamed.has(key)) {
        const existing = indexFootnotes(tr.doc).defs.get(label);
        if (!existing) {
          insertDefinition(tr, carried.type.create({ label }, carried.content));
        } else if (!sameContent(existing.node, carried)) {
          finalLabel = nextFreeLabel(tr.doc);
          insertDefinition(tr, carried.type.create({ label: finalLabel }, carried.content));
        }
        renamed.set(key, finalLabel);
      }
      tr.setNodeMarkup(pos, undefined, { label: finalLabel, carry: null });
    }
  }
  // Deeper than the rounds allow: drop what is still carried, never store it.
  tr.doc.descendants((node, pos) => {
    if (node.type.name === REF && node.attrs['carry']) tr.setNodeMarkup(pos, undefined, { ...node.attrs, carry: null });
    return true;
  });
  return tr.docChanged ? tr : null;
}

/* ------------------------------------------------------------------ */
/* Jumps                                                              */
/* ------------------------------------------------------------------ */

interface JumpState {
  /** The marker the last jump came from, mapped through every change. */
  backTo: number | null;
}

const jumpKey = new PluginKey<JumpState>('footnoteJump');

function flash(dom: globalThis.Node | null): void {
  if (!(dom instanceof HTMLElement)) return;
  dom.scrollIntoView({ block: 'center', inline: 'nearest' });
  dom.classList.remove('pn-file-flash');
  void dom.offsetWidth;
  dom.classList.add('pn-file-flash');
  window.setTimeout(() => dom.classList.remove('pn-file-flash'), 1700);
}

/** From a marker to the end of its definition's text. */
function jumpToDefinition(view: EditorView, refPos: number): boolean {
  const ref = view.state.doc.nodeAt(refPos);
  if (!ref || ref.type.name !== REF) return false;
  const def = indexFootnotes(view.state.doc).defs.get(ref.attrs['label'] as string);
  if (!def) {
    if (!view.editable) return false;
    // A marker with no text behind it: make the definition, then go there.
    const tr = view.state.tr;
    const at = insertDefinition(tr, emptyDefinition(view.state.schema, ref.attrs['label'] as string));
    tr.setSelection(TextSelection.create(tr.doc, endOfDefinition(tr.doc, at)));
    tr.setMeta(jumpKey, { backTo: refPos });
    view.dispatch(tr.scrollIntoView());
    view.focus();
    requestAnimationFrame(() => flash(view.nodeDOM(at)));
    return true;
  }
  if (view.editable) {
    const tr = view.state.tr.setSelection(TextSelection.create(view.state.doc, endOfDefinition(view.state.doc, def.pos)));
    tr.setMeta(jumpKey, { backTo: refPos });
    view.dispatch(tr);
    view.focus();
  } else {
    view.dispatch(view.state.tr.setMeta(jumpKey, { backTo: refPos }));
  }
  flash(view.nodeDOM(def.pos));
  return true;
}

/** From a definition back to the marker the person came from, or its first marker. */
function jumpBack(view: EditorView, defPos: number): boolean {
  const def = view.state.doc.nodeAt(defPos);
  if (!def || def.type.name !== DEF) return false;
  const label = def.attrs['label'] as string;
  const remembered = jumpKey.getState(view.state)?.backTo ?? null;
  const at = remembered !== null && view.state.doc.nodeAt(remembered)?.attrs['label'] === label
    ? remembered
    : indexFootnotes(view.state.doc).firstRef.get(label);
  if (at === undefined) return false;
  if (view.editable) {
    view.dispatch(view.state.tr.setSelection(TextSelection.create(view.state.doc, at + 1)));
    view.focus();
  }
  flash(view.nodeDOM(at));
  return true;
}

/** The definition that holds the selection, if any. */
function definitionAround(state: EditorState): { node: ProseMirrorNode; pos: number } | null {
  const { $from } = state.selection;
  for (let d = $from.depth; d > 0; d--) {
    if ($from.node(d).type.name === DEF) return { node: $from.node(d), pos: $from.before(d) };
  }
  return null;
}

/* ------------------------------------------------------------------ */
/* Commands                                                           */
/* ------------------------------------------------------------------ */

/**
 * The + menu's "Footnote": a marker after the selection with the next free
 * label, an empty definition at its sorted place, and the caret in it.
 */
export function insertFootnote(editor: TipTapEditor): boolean {
  if (!editor.isEditable) return false;
  const { state, view } = editor;
  const label = nextFreeLabel(state.doc);
  const at = state.selection.to;
  const tr = state.tr.insert(at, state.schema.nodes[REF]!.create({ label }));
  const defAt = insertDefinition(tr, emptyDefinition(state.schema, label));
  tr.setSelection(TextSelection.create(tr.doc, endOfDefinition(tr.doc, defAt)));
  tr.setMeta(jumpKey, { backTo: at });
  view.dispatch(tr.scrollIntoView());
  view.focus();
  requestAnimationFrame(() => flash(view.nodeDOM(defAt)));
  return true;
}

/** Removes a definition, and the section with it when it was the last one. */
function removeDefinition(view: EditorView, defPos: number): boolean {
  const { state } = view;
  const def = state.doc.nodeAt(defPos);
  const section = sectionOf(state.doc);
  if (!def || def.type.name !== DEF || !section) return false;
  const tr = section.node.childCount === 1
    ? state.tr.delete(section.pos, section.pos + section.node.nodeSize)
    : state.tr.delete(defPos, defPos + def.nodeSize);
  const target = Math.min(defPos, tr.doc.content.size);
  tr.setSelection(Selection.near(tr.doc.resolve(target), -1));
  view.dispatch(tr.scrollIntoView());
  return true;
}

/* ------------------------------------------------------------------ */
/* Nodes                                                              */
/* ------------------------------------------------------------------ */

/** The document, with room for one section after the body. */
const FootnoteDocument = Node.create({
  name: 'doc',
  topNode: true,
  content: 'block+ footnotes?',
});

// A label from HTML keeps only what a typed label can hold: no space, no
// bracket, no caret. A newline in it would write Markdown of its own on save.
const LABEL_ATTR = {
  label: {
    default: '1',
    parseHTML: (el: HTMLElement) => (el.getAttribute('data-fn-label') ?? '').replace(/[\s[\]^]/g, '') || '1',
    renderHTML: (attrs: Record<string, unknown>) => ({ 'data-fn-label': attrs['label'] }),
  },
};

const FootnoteReference = Node.create({
  name: REF,
  group: 'inline',
  inline: true,
  atom: true,
  selectable: true,
  draggable: false,

  addAttributes() {
    return {
      ...LABEL_ATTR,
      // The definition a copy carries, as HTML (see carryDefinitions);
      // never stored.
      carry: {
        default: null,
        parseHTML: (el: HTMLElement) => el.getAttribute('data-fn-carry'),
        renderHTML: (attrs: Record<string, unknown>) => (attrs['carry'] ? { 'data-fn-carry': attrs['carry'] } : {}),
      },
    };
  },

  // Above the superscript mark's `sup` rule, which would otherwise claim it.
  parseHTML() {
    return [{ tag: 'sup[data-fn-ref]', priority: 100 }];
  },

  renderHTML({ HTMLAttributes }) {
    return ['sup', mergeAttributes({ 'data-fn-ref': '', class: 'pn-fn-ref' }, HTMLAttributes)];
  },

  // No text: an outline entry, a heading match and a find read the heading
  // `## Results[^1]` as "Results".
  renderText() {
    return '';
  },

  addStorage() {
    return {
      markdown: {
        serialize(state: { write: (s: string) => void }, node: ProseMirrorNode) {
          state.write(`[^${node.attrs['label'] as string}]`);
        },
        parse: {},
      },
    };
  },
});

const FootnoteSection = Node.create({
  name: SECTION,
  content: 'footnote+',
  isolating: true,
  selectable: false,

  addAttributes() {
    return { kind: { isRequired: true, rendered: false, parseHTML: () => SECTION_ATTRS.kind } };
  },

  parseHTML() {
    return [{ tag: 'section[data-fn-section]' }];
  },

  renderHTML() {
    return [
      'section',
      { 'data-fn-section': '', class: 'pn-footnotes', role: 'doc-endnotes', 'aria-label': i18n.t('editor:footnote.ariaSection') },
      0,
    ];
  },

  addStorage() {
    return {
      markdown: {
        serialize(state: { renderContent: (n: ProseMirrorNode) => void }, node: ProseMirrorNode) {
          state.renderContent(node);
        },
        parse: {
          setup(md: FootnoteMarkdownIt) {
            setupFootnoteMarkdown(md);
          },
          // `block+` comes before the section, so a note of definitions alone
          // needs a body line in front of them, or the parser cannot place the
          // section and turns it into paragraphs. The empty paragraph writes
          // nothing on save (ParagraphWithMarkdown).
          updateDOM(element: HTMLElement) {
            const first = element.firstElementChild;
            if (first?.matches('section[data-fn-section]')) element.prepend(document.createElement('p'));
          },
        },
      },
    };
  },
});

const FootnoteDefinition = Node.create({
  name: DEF,
  content: 'block+',
  isolating: true,
  defining: true,

  addAttributes() {
    return LABEL_ATTR;
  },

  parseHTML() {
    return [{ tag: 'div[data-fn-def]' }];
  },

  renderHTML({ HTMLAttributes }) {
    return ['div', mergeAttributes({ 'data-fn-def': '', class: 'pn-footnote' }, HTMLAttributes), 0];
  },

  addStorage() {
    return {
      markdown: {
        serialize(
          state: {
            write: (s: string) => void;
            closeBlock: (n: ProseMirrorNode) => void;
            wrapBlock: (delim: string, first: string, n: ProseMirrorNode, f: () => void) => void;
            renderContent: (n: ProseMirrorNode) => void;
          },
          node: ProseMirrorNode,
        ) {
          const lead = `[^${node.attrs['label'] as string}]:`;
          if (isEmptyDefinition(node)) {
            state.write(lead);
            state.closeBlock(node);
            return;
          }
          // The continuation lines of a definition are indented four spaces,
          // the way a list item writes its own indent.
          state.wrapBlock('    ', `${lead} `, node, () => state.renderContent(node));
        },
        parse: {},
      },
    };
  },
});

/* ------------------------------------------------------------------ */
/* The plugin: numbers, jumps, hover card, repairs                    */
/* ------------------------------------------------------------------ */

const REF_PATTERN = /(?<=\S)\[\^([^\s\]^]+)\]$/;
const DEF_PATTERN = /^\[\^([^\s\]^]+)\]:\s$/;

function decorate(doc: ProseMirrorNode, editable: boolean): DecorationSet {
  const idx = indexFootnotes(doc);
  const decos: Decoration[] = [];
  for (const r of idx.refs) {
    const n = idx.numbers.get(r.label);
    const attrs: Record<string, string> = n !== undefined
      ? { 'data-fn-number': String(n), role: 'doc-noteref', 'aria-label': i18n.t('editor:footnote.ariaRef', { n }) }
      : { 'data-fn-missing': '', title: i18n.t('editor:footnote.missing') };
    if (!editable) attrs['tabindex'] = '0';
    decos.push(Decoration.node(r.pos, r.pos + 1, attrs));
  }
  const firstOfLabel = new Set<string>();
  for (const d of definitionsOf(doc)) {
    const label = d.node.attrs['label'] as string;
    const n = idx.numbers.get(label);
    const bound = !firstOfLabel.has(label);
    firstOfLabel.add(label);
    decos.push(Decoration.node(d.pos, d.pos + d.node.nodeSize, n !== undefined && bound
      ? { 'data-fn-number': String(n) }
      : { 'data-fn-unused': '', 'data-fn-unused-label': i18n.t('editor:footnote.unused') }));
    const first = d.node.firstChild;
    if (first?.isTextblock) {
      const pStart = d.pos + 1;
      const empty = first.content.size === 0 && d.node.childCount === 1;
      if (empty) {
        decos.push(Decoration.node(pStart, pStart + first.nodeSize, {
          class: 'pn-fn-empty',
          'data-placeholder': i18n.t('editor:footnote.placeholder'),
        }));
      }
      const end = pStart + 1 + first.content.size;
      // An empty definition shows its placeholder there instead; Escape
      // still goes back.
      if (n !== undefined && bound && !empty) {
        decos.push(Decoration.widget(end, () => {
          const b = document.createElement('button');
          b.type = 'button';
          b.className = 'pn-fn-back';
          b.setAttribute('data-fn-back', '');
          b.setAttribute('contenteditable', 'false');
          b.setAttribute('aria-label', i18n.t('editor:footnote.back'));
          b.title = i18n.t('editor:footnote.back');
          b.textContent = '\u21a9\uFE0E';
          return b;
        }, { side: 1, key: `fn-back-${label}`, ignoreSelection: true }));
      } else if (editable && !empty && (n === undefined || !bound)) {
        decos.push(Decoration.widget(end, () => {
          const b = document.createElement('button');
          b.type = 'button';
          b.className = 'pn-fn-remove';
          b.setAttribute('data-fn-remove', '');
          b.setAttribute('contenteditable', 'false');
          b.setAttribute('aria-label', i18n.t('editor:footnote.remove'));
          b.title = i18n.t('editor:footnote.remove');
          b.textContent = '\u00d7';
          return b;
        }, { side: 1, key: `fn-remove-${d.pos}`, ignoreSelection: true }));
      }
    }
  }
  return DecorationSet.create(doc, decos);
}

/** The hover card on a marker: the definition's text, read-only. */
class HoverCard {
  private card: HTMLDivElement | null = null;
  private timer = 0;
  private target: HTMLElement | null = null;

  constructor(private view: EditorView) {
    view.dom.addEventListener('pointerover', this.over);
    view.dom.addEventListener('pointerout', this.out);
    window.addEventListener('scroll', this.hide, true);
  }

  private over = (e: PointerEvent) => {
    if (e.pointerType !== 'mouse') return;
    const sup = (e.target as Element | null)?.closest?.('sup[data-fn-ref]') as HTMLElement | null;
    if (!sup || sup === this.target) return;
    this.hide();
    this.target = sup;
    this.timer = window.setTimeout(() => this.show(sup), 350);
  };

  private out = (e: PointerEvent) => {
    const to = e.relatedTarget as Element | null;
    if (this.target && to && this.target.contains(to)) return;
    this.hide();
  };

  private show(sup: HTMLElement) {
    if (!sup.isConnected) return;
    const pos = this.view.posAtDOM(sup, 0);
    const ref = this.view.state.doc.nodeAt(pos);
    if (!ref || ref.type.name !== REF) return;
    const def = indexFootnotes(this.view.state.doc).defs.get(ref.attrs['label'] as string);
    if (!def) return;
    const lines: string[] = [];
    def.node.forEach((block) => lines.push(block.textContent));
    const text = lines.join('\n').trim();
    if (!text) return;
    const card = document.createElement('div');
    card.className = 'pn-fn-card';
    card.setAttribute('role', 'tooltip');
    card.textContent = text;
    document.body.append(card);
    const r = sup.getBoundingClientRect();
    const w = card.offsetWidth;
    const left = Math.max(8, Math.min(r.left + r.width / 2 - w / 2, window.innerWidth - w - 8));
    const below = r.bottom + 6 + card.offsetHeight < window.innerHeight;
    card.style.left = `${left}px`;
    card.style.top = below ? `${r.bottom + 6}px` : `${r.top - 6 - card.offsetHeight}px`;
    this.card = card;
  }

  hide = () => {
    window.clearTimeout(this.timer);
    this.card?.remove();
    this.card = null;
    this.target = null;
  };

  destroy() {
    this.hide();
    this.view.dom.removeEventListener('pointerover', this.over);
    this.view.dom.removeEventListener('pointerout', this.out);
    window.removeEventListener('scroll', this.hide, true);
  }
}

const decoKey = new PluginKey<DecorationSet>('footnoteDecorations');

export const Footnotes = Extension.create({
  name: 'footnotes',

  addExtensions() {
    return [FootnoteDocument, FootnoteReference, FootnoteSection, FootnoteDefinition];
  },

  addInputRules() {
    return [
      // `[^label]` after a word becomes a marker. A label with no definition
      // gets an empty one, and the caret stays in the text.
      new InputRule({
        find: REF_PATTERN,
        handler: ({ state, range, match }) => {
          const label = match[1]!;
          const { tr } = state;
          tr.replaceWith(range.from, range.to, state.schema.nodes[REF]!.create({ label }));
          if (!indexFootnotes(tr.doc).defs.has(label)) insertDefinition(tr, emptyDefinition(state.schema, label));
          tr.setSelection(TextSelection.create(tr.doc, tr.mapping.map(range.from) + 1));
        },
      }),
      // `[^label]: ` at the start of a top-level line opens that definition.
      new InputRule({
        find: DEF_PATTERN,
        handler: ({ state, range, match }) => {
          const $from = state.doc.resolve(range.from);
          if ($from.depth !== 1 || $from.parent.type.name !== 'paragraph') return null;
          const label = match[1]!;
          const { tr } = state;
          tr.delete(range.from, range.to);
          const para = tr.doc.resolve(tr.mapping.map(range.from)).parent;
          const paraPos = tr.mapping.map(range.from) - 1;
          const bodyCount = tr.doc.childCount - (sectionOf(tr.doc) ? 1 : 0);
          if (para.content.size === 0 && bodyCount > 1) tr.delete(paraPos, paraPos + para.nodeSize);
          const existing = indexFootnotes(tr.doc).defs.get(label);
          const at = existing ? existing.pos : insertDefinition(tr, emptyDefinition(state.schema, label));
          tr.setSelection(TextSelection.create(tr.doc, endOfDefinition(tr.doc, at)));
        },
      }),
    ];
  },

  addKeyboardShortcuts() {
    return {
      // From inside a definition, back to the marker the person came from.
      Escape: ({ editor }) => {
        const def = definitionAround(editor.state);
        return def ? jumpBack(editor.view, def.pos) : false;
      },
      // A selected marker opens its definition.
      Enter: ({ editor }) => {
        const sel = editor.state.selection;
        if (sel instanceof NodeSelection && sel.node.type.name === REF) return jumpToDefinition(editor.view, sel.from);
        // An empty last line of a definition leaves it: to the next
        // definition, or after the last one to the end of the body.
        const def = definitionAround(editor.state);
        const { $from, empty } = sel;
        if (!def || !empty || $from.parent.type.name !== 'paragraph' || $from.parent.content.size !== 0) return false;
        if ($from.depth < 2 || $from.node($from.depth - 1) !== def.node) return false;
        if ($from.index($from.depth - 1) !== def.node.childCount - 1) return false;
        const { state, view } = editor;
        const tr = state.tr;
        if (def.node.childCount > 1) tr.delete($from.before(), $from.after());
        const section = sectionOf(tr.doc)!;
        const defAfter = tr.mapping.map(def.pos);
        const defNode = tr.doc.nodeAt(defAfter)!;
        const nextPos = defAfter + defNode.nodeSize;
        const target = nextPos < section.pos + section.node.nodeSize - 1
          ? Selection.near(tr.doc.resolve(nextPos + 1), 1)
          : Selection.near(tr.doc.resolve(section.pos), -1);
        tr.setSelection(target);
        view.dispatch(tr.scrollIntoView());
        return true;
      },
      // Backspace in an empty definition removes it.
      Backspace: ({ editor }) => {
        const def = definitionAround(editor.state);
        if (!def || !editor.state.selection.empty || !isEmptyDefinition(def.node)) return false;
        return removeDefinition(editor.view, def.pos);
      },
    };
  },

  addProseMirrorPlugins() {
    const editor = this.editor;
    return [
      new Plugin<JumpState>({
        key: jumpKey,
        state: {
          init: () => ({ backTo: null }),
          apply(tr, value) {
            const meta = tr.getMeta(jumpKey) as JumpState | undefined;
            if (meta) return meta;
            if (value.backTo === null || !tr.docChanged) return value;
            const mapped = tr.mapping.mapResult(value.backTo);
            return { backTo: mapped.deleted ? null : mapped.pos };
          },
        },
      }),
      new Plugin<DecorationSet>({
        key: decoKey,
        state: {
          init: (_c, state) => decorate(state.doc, editor.isEditable),
          apply: (tr, old, _o, state) =>
            tr.docChanged || tr.getMeta('footnoteEditable') ? decorate(state.doc, editor.isEditable) : old,
        },
        view(view) {
          const card = new HoverCard(view);
          let editable = view.editable;
          return {
            update(v) {
              card.hide();
              if (v.editable !== editable) {
                editable = v.editable;
                v.dispatch(v.state.tr.setMeta('footnoteEditable', true));
              }
            },
            destroy() {
              card.destroy();
            },
          };
        },
        props: {
          decorations: (state) => decoKey.getState(state),
          handleClickOn(view, _pos, node, nodePos, event, direct) {
            if (!direct || node.type.name !== REF || event.button !== 0) return false;
            return jumpToDefinition(view, nodePos);
          },
          handleDOMEvents: {
            mousedown(view, event) {
              const el = (event.target as Element | null)?.closest?.('[data-fn-back], [data-fn-remove]');
              if (!el) return false;
              event.preventDefault();
              const pos = view.posAtDOM(el, 0);
              const $pos = view.state.doc.resolve(pos);
              for (let d = $pos.depth; d > 0; d--) {
                if ($pos.node(d).type.name !== DEF) continue;
                if (el.hasAttribute('data-fn-back')) jumpBack(view, $pos.before(d));
                else if (view.editable) removeDefinition(view, $pos.before(d));
                return true;
              }
              return true;
            },
            keydown(view, event) {
              // A marker reached with Tab in a read-only note.
              if (view.editable || event.key !== 'Enter') return false;
              const sup = (event.target as Element | null)?.closest?.('sup[data-fn-ref]');
              if (!sup) return false;
              event.preventDefault();
              return jumpToDefinition(view, view.posAtDOM(sup, 0));
            },
          },
          transformCopied: (slice, view) => carryDefinitions(slice, view.state.doc),
          transformPasted: (slice) => liftPastedSection(slice),
          transformPastedHTML: (html) => normalizePastedFootnotes(html),
        },
        appendTransaction(trs, _old, state) {
          if (!editor.isEditable || !trs.some((t) => t.docChanged)) return null;
          return repairFootnotes(state);
        },
      }),
    ];
  },
});

