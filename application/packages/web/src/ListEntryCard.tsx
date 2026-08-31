import type { ComponentType } from 'react';
import { X } from './icons';

/**
 * The shell every standing list entry wears - the import offer
 * (`ImportPrompt.tsx`) and the active-filter hint (`ListFilterChips.tsx`).
 *
 * A standing entry is a non-item drawn among a pillar's items: a row in a list
 * pane, a dashed tile in a grid pane. One component rather than two copies of
 * these class strings, for the same reason `ListFilterChips` is one component -
 * the two entries sit in the same slot and often on the same screen, so a 1px
 * difference between them reads as a bug rather than as two components.
 *
 * `tone` is the only thing that separates them, and it carries meaning rather
 * than decoration: amber says "a filter is on" everywhere in the pane, accent
 * is the app's own colour and reads as furniture.
 *
 * Spec: ops/docs/ui-patterns.md (section 41)
 */
export function ListEntryCard({
  variant,
  as = 'li',
  tone = 'accent',
  icon: Icon,
  label,
  onClick,
  onDismiss,
  dismissLabel,
}: {
  /** 'tile' in a grid pane, 'row' in a list pane. */
  variant: 'row' | 'tile';
  /** The element to render as. `li` inside a `ul`, which is what every pillar
   *  but Files builds its list from; `div` in the Files pane, whose rows are
   *  buttons in a plain container. */
  as?: 'li' | 'div';
  /** 'accent' for an offer, 'amber' for anything that says a filter is on. */
  tone?: 'accent' | 'amber';
  icon: ComponentType<{ size?: number }>;
  label: string;
  onClick: () => void;
  /** Omit to draw no dismiss button. A hint about the pane's own state has
   *  nothing to dismiss - clearing the filter is what removes it. */
  onDismiss?: () => void;
  dismissLabel?: string;
}) {
  const Tag = as;
  const glyphClass =
    tone === 'amber' ? 'bg-amber-500/10 text-amber-700 dark:text-amber-400' : 'bg-accent/10 text-accent';
  const dismissClass =
    'inline-flex shrink-0 items-center justify-center rounded-md text-neutral-400 transition hover:bg-neutral-200/60 hover:text-neutral-700 dark:text-neutral-500 dark:hover:bg-neutral-800/60 dark:hover:text-neutral-200';

  if (variant === 'tile') {
    return (
      <Tag
        className={`relative flex flex-col items-center justify-center gap-2 rounded-xl border border-dashed border-divider bg-surface-2/40 p-4 text-center transition ${
          tone === 'amber' ? 'hover:border-amber-500/60' : 'hover:border-accent/60'
        }`}
      >
        <button type="button" onClick={onClick} className="flex flex-col items-center gap-2">
          <span className={`inline-flex h-9 w-9 items-center justify-center rounded-full ${glyphClass}`}>
            <Icon size={17} />
          </span>
          <span className="text-[13px] font-medium">{label}</span>
        </button>
        {onDismiss && (
          <button
            type="button"
            onClick={onDismiss}
            aria-label={dismissLabel}
            className={`absolute end-1.5 top-1.5 h-6 w-6 ${dismissClass}`}
          >
            <X size={12} />
          </button>
        )}
      </Tag>
    );
  }

  return (
    <Tag className="flex items-center gap-2 border-b border-divider/50 px-4 py-3 transition hover:bg-neutral-200/50 dark:hover:bg-neutral-900/50">
      <button type="button" onClick={onClick} className="flex min-w-0 flex-1 items-center gap-3 text-start">
        <span className={`inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-md ${glyphClass}`}>
          <Icon size={16} />
        </span>
        <span className="min-w-0 truncate text-[14px] font-medium">{label}</span>
      </button>
      {onDismiss && (
        <button
          type="button"
          onClick={onDismiss}
          aria-label={dismissLabel}
          className={`h-7 w-7 ${dismissClass}`}
        >
          <X size={14} />
        </button>
      )}
    </Tag>
  );
}
