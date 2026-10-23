/**
 * Callout keywords and colors, with no icons, so the export renderer
 * (markdownRender.ts) reads the same table as the editor without pulling in
 * the icon set. calloutTypes.ts adds the icons and the picker order.
 *
 * Colors reuse the editor's text-color palette (editorColors.ts) so callouts
 * and text color share one legible-on-light-and-dark set of hues. The plain
 * types (Fold, Box, Panel) have no color: they draw in the text color, and
 * the caret is their only control.
 *
 * Spec: ops/docs/callouts.md (the type table)
 */

export type CalloutType =
  | 'fold'
  | 'box'
  | 'panel'
  | 'info'
  | 'note'
  | 'update'
  | 'tip'
  | 'idea'
  | 'important'
  | 'warning'
  | 'caution'
  | 'danger'
  | 'success'
  | 'failure'
  | 'bug'
  | 'todo'
  | 'goal'
  | 'decision'
  | 'time'
  | 'steps'
  | 'place'
  | 'quote'
  | 'example'
  | 'abstract'
  | 'question'
  | 'definition'
  | 'seealso'
  | 'kanban'
  | 'column';

export interface CalloutColor {
  /** Accent hex, used for the border, icon, and title. Empty for Fold. */
  color: string;
  /** Space-separated rgb triple (e.g. "25 113 194") for rgb(var(--cc) / a) tints. */
  rgb: string;
}

const BLUE = { color: '#1971c2', rgb: '25 113 194' };
const TEAL = { color: '#0c8599', rgb: '12 133 153' };
const YELLOW = { color: '#f08c00', rgb: '240 140 0' };
const PURPLE = { color: '#7048e8', rgb: '112 72 232' };
const ORANGE = { color: '#e8590c', rgb: '232 89 12' };
const PINK = { color: '#c2255c', rgb: '194 37 92' };
const RED = { color: '#e03131', rgb: '224 49 49' };
const GREEN = { color: '#2f9e44', rgb: '47 158 68' };
const GRAY = { color: '#868e96', rgb: '134 142 150' };

/** Every type with its color, in picker order: rows of three grouped by
 *  meaning (fold styles, plain, ideas, warnings, outcomes, plans, practical,
 *  content, learning). An empty color marks a plain type. */
export const CALLOUT_COLORS: Record<CalloutType, CalloutColor> = {
  fold: { color: '', rgb: '' },
  box: { color: '', rgb: '' },
  panel: { color: '', rgb: '' },
  info: BLUE,
  note: BLUE,
  update: BLUE,
  tip: TEAL,
  idea: YELLOW,
  important: PURPLE,
  warning: ORANGE,
  caution: PINK,
  danger: RED,
  success: GREEN,
  failure: RED,
  bug: PINK,
  todo: BLUE,
  goal: GREEN,
  decision: PURPLE,
  time: TEAL,
  steps: GREEN,
  place: ORANGE,
  quote: GRAY,
  example: PURPLE,
  abstract: TEAL,
  question: YELLOW,
  definition: TEAL,
  seealso: GRAY,
  // A Kanban board and its columns. Neither is in the callout picker: the
  // board comes from the + menu, and a column takes its color from its
  // metadata (`[!column|green]`), gray when it has none.
  kanban: { color: '', rgb: '' },
  column: GRAY,
};

/** The palette keys a Kanban column can carry as `[!column|key]`, with the
 *  same hues as the text colors and the callouts. */
const COLUMN_COLORS = {
  gray: GRAY,
  red: RED,
  orange: ORANGE,
  yellow: YELLOW,
  green: GREEN,
  teal: TEAL,
  blue: BLUE,
  purple: PURPLE,
  pink: PINK,
} as const;

export type ColumnColor = keyof typeof COLUMN_COLORS;

export function isColumnColor(key: string | null | undefined): key is ColumnColor {
  return !!key && Object.prototype.hasOwnProperty.call(COLUMN_COLORS, key);
}

/** The color of a callout: a column reads its metadata, every other type its table row. */
export function calloutColorOf(type: CalloutType, meta: string | null | undefined): CalloutColor {
  if (type === 'column' && isColumnColor(meta)) return COLUMN_COLORS[meta];
  return CALLOUT_COLORS[type];
}

/**
 * Keyword -> canonical type. Covers Obsidian's aliases, GitHub's five alerts
 * (matched case-insensitively), and the few extra keywords other editors
 * write. Anything unknown falls back to `info` (a neutral box) rather than
 * being dropped; the node keeps the keyword itself, so it saves back as
 * written.
 * Spec: ops/docs/callouts.md (import alias map)
 */
const CALLOUT_ALIASES: Record<string, CalloutType> = {
  fold: 'fold',
  toggle: 'fold',
  details: 'fold',
  collapse: 'fold',
  box: 'box',
  frame: 'box',
  panel: 'panel',
  card: 'panel',
  info: 'info',
  note: 'note',
  update: 'update',
  edit: 'update',
  updated: 'update',
  tip: 'tip',
  hint: 'tip',
  idea: 'idea',
  important: 'important',
  pinned: 'important',
  warning: 'warning',
  warn: 'warning',
  attention: 'warning',
  caution: 'caution',
  danger: 'danger',
  error: 'danger',
  success: 'success',
  check: 'success',
  done: 'success',
  failure: 'failure',
  fail: 'failure',
  missing: 'failure',
  bug: 'bug',
  todo: 'todo',
  goal: 'goal',
  decision: 'decision',
  time: 'time',
  deadline: 'time',
  date: 'time',
  due: 'time',
  steps: 'steps',
  howto: 'steps',
  'how-to': 'steps',
  place: 'place',
  location: 'place',
  address: 'place',
  quote: 'quote',
  cite: 'quote',
  example: 'example',
  abstract: 'abstract',
  summary: 'abstract',
  tldr: 'abstract',
  question: 'question',
  help: 'question',
  faq: 'question',
  definition: 'definition',
  seealso: 'seealso',
  'see-also': 'seealso',
  related: 'seealso',
  kanban: 'kanban',
  column: 'column',
};

/** Fold a raw callout keyword (Obsidian alias or our own) to a canonical type. */
export function canonicalCalloutType(raw: string): CalloutType {
  const key = raw.trim().toLowerCase();
  // Own-property only: `constructor` and `__proto__` are already lower case.
  return Object.hasOwn(CALLOUT_ALIASES, key) ? CALLOUT_ALIASES[key]! : 'info';
}
