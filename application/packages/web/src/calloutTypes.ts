/**
 * Callout type registry for the editor: every type's color (from
 * calloutKeywords.ts), its icon, and the picker order. Every type is free.
 *
 * Spec: ops/docs/callouts.md (the type table and the picker order)
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
  CaretDown,
  Sparkle,
  Star,
  HandPalm,
  CheckSquare,
  Target,
  Gavel,
  BookOpen,
  Link,
  Browser,
  Rectangle,
  ArrowsClockwise,
  Clock,
  ListNumbers,
  MapPin,
} from './icons';
import { CALLOUT_COLORS, type CalloutColor, type CalloutType } from './calloutKeywords';

export { canonicalCalloutType, type CalloutType } from './calloutKeywords';

export interface CalloutTypeDef extends CalloutColor {
  type: CalloutType;
  icon: Icon;
}

const ICONS: Record<CalloutType, Icon> = {
  fold: CaretDown,
  box: Browser,
  panel: Rectangle,
  info: Info,
  note: PencilSimple,
  update: ArrowsClockwise,
  tip: Lightbulb,
  idea: Sparkle,
  important: Star,
  warning: Warning,
  caution: HandPalm,
  danger: WarningOctagon,
  success: CheckCircle,
  failure: XCircle,
  bug: Bug,
  todo: CheckSquare,
  goal: Target,
  decision: Gavel,
  time: Clock,
  steps: ListNumbers,
  place: MapPin,
  quote: Quotes,
  example: ListChecks,
  abstract: ClipboardText,
  question: Question,
  definition: BookOpen,
  seealso: Link,
};

/** Picker order is the key order of CALLOUT_COLORS. */
export const CALLOUT_TYPES: CalloutTypeDef[] = (Object.keys(CALLOUT_COLORS) as CalloutType[]).map((type) => ({
  type,
  ...CALLOUT_COLORS[type],
  icon: ICONS[type],
}));

export const CALLOUT_BY_TYPE: Record<CalloutType, CalloutTypeDef> = Object.fromEntries(
  CALLOUT_TYPES.map((c) => [c.type, c]),
) as Record<CalloutType, CalloutTypeDef>;
