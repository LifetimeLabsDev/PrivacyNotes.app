import type { ReactNode } from 'react';
import { Info } from './icons';

/**
 * Settings pane typography tokens - the single source of truth.
 * See ops/docs/ui-patterns.md section 36. Every pane rendered inside
 * SettingsShell uses these so section headers and helper text can never
 * drift back into per-pane styles.
 *
 * The ladder: accent = structure (eyebrows, functional icons), soft =
 * supporting prose (descriptions, helpers, hints), muted = metadata only
 * (timestamps, counts, price fine print, legal footers - inline
 * `text-pn-muted`, deliberately not a token here).
 *
 * - SETTINGS_EYEBROW: the one uppercase section-header style.
 * - SETTINGS_EYEBROW_DANGER: the red variant (e.g. the danger zone).
 * - SETTINGS_HELP: the one helper / description / footnote style.
 * - SettingsCallout: the one container for important notes that must not
 *   read as a footnote (limits, bonuses, anything involving money).
 *
 * Use the SectionEyebrow component for plain section headers. For an
 * eyebrow that is not a plain <div> (a <span>, a centered field label,
 * a shared row label), keep the element and apply the constant.
 */
export const SETTINGS_EYEBROW =
  'text-[11px] font-semibold uppercase tracking-wide text-accent';
const SETTINGS_EYEBROW_DANGER =
  'text-[11px] font-semibold uppercase tracking-wide text-red-600 dark:text-red-400';
export const SETTINGS_HELP = 'text-xs text-pn-soft';

/** Standard uppercase section header for a settings pane. */
export function SectionEyebrow({
  children,
  className,
  danger = false,
  setting,
}: {
  children: ReactNode;
  /** Layout-only classes (spacing), e.g. "mb-2". */
  className?: string;
  danger?: boolean;
  /** The settings search id of the section this header names. */
  setting?: string;
}) {
  const base = danger ? SETTINGS_EYEBROW_DANGER : SETTINGS_EYEBROW;
  return <div data-setting={setting} className={className ? `${base} ${className}` : base}>{children}</div>;
}

/**
 * Accent bar that prefixes a floating headline. Always paired with
 * HeadlineRule in the same `flex items-center gap-2.5` row:
 * bar, title, rule.
 */
export function AccentBar() {
  return <span className="w-[3px] h-4 rounded-full bg-accent shrink-0" aria-hidden="true" />;
}

/**
 * Hairline that extends a floating headline to the row's end. Place it
 * after the title inside a `flex items-center gap-2.5` row, with an
 * AccentBar before the title. Only for headlines with no bordered bar
 * of their own - inside a `border-b` header bar it would read as a
 * doubled line.
 */
export function HeadlineRule() {
  return <div className="h-px flex-1 bg-divider" aria-hidden="true" />;
}

/**
 * Important note row - accent-tinted so it can never be mistaken for a
 * muted footnote. For copy the user must not skim past: limits, plan
 * perks, anything that affects what they pay or lose.
 */
export function SettingsCallout({
  children,
  className,
}: {
  children: ReactNode;
  /** Layout-only classes (spacing), e.g. "mb-4". */
  className?: string;
}) {
  return (
    <div
      className={`flex items-start gap-2 rounded-md border border-accent/30 bg-accent/10 px-3 py-2 text-xs leading-relaxed text-pn${className ? ` ${className}` : ''}`}
    >
      <Info size={15} className="shrink-0 mt-0.5 text-accent" aria-hidden="true" />
      <div className="min-w-0">{children}</div>
    </div>
  );
}
