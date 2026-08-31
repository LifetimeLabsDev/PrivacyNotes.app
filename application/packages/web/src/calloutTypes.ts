/**
 * Callout type registry - the single source of truth for the callout
 * types: their canonical key, accent color, icon, and Pro gating.
 *
 * Colors reuse the editor's text-color palette (editorColors.ts) so callouts
 * and text color share one legible-on-light-and-dark set of hues. The three
 * free types (info, success, warning) are listed first so the picker shows
 * them before the Pro set with no section header - just ordering.
 *
 * Spec: ops/docs/callouts.md (Pro gate is only in the toolbar picker, not rendering)
 */

import type { Icon } from '@phosphor-icons/react';
import {
  Info,
  CheckCircle,
  Warning,
  Lightbulb,
  WarningOctagon,
  Question,
  Quotes,
  ListChecks,
  Bug,
  PencilSimple,
  ClipboardText,
  XCircle,
} from './icons';

export type CalloutType =
  | 'info'
  | 'success'
  | 'warning'
  | 'tip'
  | 'danger'
  | 'question'
  | 'quote'
  | 'example'
  | 'bug'
  | 'note'
  | 'abstract'
  | 'failure';

export interface CalloutTypeDef {
  type: CalloutType;
  /** Accent hex, used for the border, icon, and title. */
  color: string;
  /** Space-separated rgb triple (e.g. "25 113 194") for rgb(var(--cc) / a) tints. */
  rgb: string;
  icon: Icon;
  /** True = gated behind Pro (shows a rocket in the picker, opens the upsell). */
  pro: boolean;
}

// Display + serialize order: the 3 free types first, then the 9 Pro types.
// Spec: ops/docs/callouts.md (free tier = info, success, warning)
export const CALLOUT_TYPES: CalloutTypeDef[] = [
  { type: 'info', color: '#1971c2', rgb: '25 113 194', icon: Info, pro: false },
  { type: 'success', color: '#2f9e44', rgb: '47 158 68', icon: CheckCircle, pro: false },
  { type: 'warning', color: '#e8590c', rgb: '232 89 12', icon: Warning, pro: false },
  { type: 'tip', color: '#0c8599', rgb: '12 133 153', icon: Lightbulb, pro: true },
  { type: 'danger', color: '#e03131', rgb: '224 49 49', icon: WarningOctagon, pro: true },
  { type: 'question', color: '#f08c00', rgb: '240 140 0', icon: Question, pro: true },
  { type: 'quote', color: '#868e96', rgb: '134 142 150', icon: Quotes, pro: true },
  { type: 'example', color: '#7048e8', rgb: '112 72 232', icon: ListChecks, pro: true },
  { type: 'bug', color: '#c2255c', rgb: '194 37 92', icon: Bug, pro: true },
  { type: 'note', color: '#1971c2', rgb: '25 113 194', icon: PencilSimple, pro: true },
  { type: 'abstract', color: '#0c8599', rgb: '12 133 153', icon: ClipboardText, pro: true },
  { type: 'failure', color: '#e03131', rgb: '224 49 49', icon: XCircle, pro: true },
];

export const CALLOUT_BY_TYPE: Record<CalloutType, CalloutTypeDef> = Object.fromEntries(
  CALLOUT_TYPES.map((c) => [c.type, c]),
) as Record<CalloutType, CalloutTypeDef>;

/**
 * Obsidian alias -> canonical type, so imported/pasted Obsidian callouts
 * render even though we expose a tighter set. Anything unknown falls
 * back to `info` (a neutral box) rather than being dropped.
 * Spec: ops/docs/callouts.md (import alias map)
 */
const CALLOUT_ALIASES: Record<string, CalloutType> = {
  info: 'info',
  note: 'note',
  todo: 'info',
  abstract: 'abstract',
  summary: 'abstract',
  tldr: 'abstract',
  success: 'success',
  check: 'success',
  done: 'success',
  warning: 'warning',
  caution: 'warning',
  attention: 'warning',
  tip: 'tip',
  hint: 'tip',
  important: 'tip',
  danger: 'danger',
  error: 'danger',
  failure: 'failure',
  fail: 'failure',
  missing: 'failure',
  question: 'question',
  help: 'question',
  faq: 'question',
  quote: 'quote',
  cite: 'quote',
  example: 'example',
  bug: 'bug',
};

/** Fold a raw callout keyword (Obsidian alias or our own) to a canonical type. */
export function canonicalCalloutType(raw: string): CalloutType {
  return CALLOUT_ALIASES[raw.trim().toLowerCase()] ?? 'info';
}
