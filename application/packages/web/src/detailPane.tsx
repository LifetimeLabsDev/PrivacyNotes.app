import type { ReactNode } from 'react';
import { HoverLabel } from './HoverLabel';
import { AccentBar, HeadlineRule } from './settingsUI';
import { openExternal } from './openExternal';
import { Check, Copy, PencilSimple } from './icons';

/**
 * The detail-pane kit: what a contact and a vault item share when they sit
 * under the standard note header. One column width, one hero, one row
 * anatomy (icon and label at the start, the value start-aligned, the row's
 * actions as ONE outlined group at the end), one headline over a group, one
 * notes block. A pane composes these and owns nothing of the look, which is
 * what keeps the two panes from drifting apart again.
 * Spec: ops/docs/ui-patterns.md (section 99)
 */

/**
 * The column. Every pane in the kit is a stack of label-and-value rows, so
 * at the editor column's full width the value sits stranded far from its
 * label. One number, shared by both panes and their edit forms.
 */
export const DETAIL_COLUMN = 'w-full max-w-[520px]';

/** The hero tile's edge in px: a photo chip, a favicon tile or a type tile. */
export const DETAIL_TILE_PX = 48;

/** The hero: the tile, the title, a second line, and the Edit button. */
export function DetailHero({ tile, title, subtitle, onEdit, editLabel }: {
  tile: ReactNode;
  title: string;
  subtitle?: ReactNode;
  /** Absent when the item cannot be edited: trashed, or locked. */
  onEdit?: () => void;
  editLabel: string;
}) {
  return (
    <div className="flex items-center justify-between gap-3 mb-2">
      <div className="flex items-center gap-4 min-w-0">
        {tile}
        <div className="min-w-0">
          <div className="text-lg font-semibold truncate text-neutral-900 dark:text-white" dir="auto">{title}</div>
          {subtitle}
        </div>
      </div>
      {onEdit && (
        <button
          type="button"
          onClick={onEdit}
          className="shrink-0 inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-surface-1 border border-divider text-neutral-700 dark:text-neutral-300 hover:bg-neutral-200 dark:hover:bg-surface-0 transition"
        >
          <PencilSimple size={13} /> {editLabel}
        </button>
      )}
    </div>
  );
}

/**
 * A square hero tile. `light` keeps a light ground in both themes, which a
 * favicon needs; the default is the surface a type icon sits on.
 */
export function DetailTile({ children, light = false }: { children: ReactNode; light?: boolean }) {
  return (
    <span
      className={`shrink-0 rounded-md flex items-center justify-center overflow-hidden ${light ? 'bg-[#f0efec]' : 'bg-surface-1 border border-divider text-accent'}`}
      style={{ width: DETAIL_TILE_PX, height: DETAIL_TILE_PX }}
    >
      {children}
    </span>
  );
}

/** A group of rows under the headline every settings pane draws: the accent
 *  bar, the title, and the rule that runs to the edge. */
export function DetailGroup({ heading, children }: { heading: string; children: ReactNode }) {
  return (
    <div className="mt-5">
      <div className="flex items-center gap-2.5 mb-1">
        <AccentBar />
        <h3 className="text-sm font-semibold text-neutral-900 dark:text-white truncate" dir="auto">{heading}</h3>
        <HeadlineRule />
      </div>
      {children}
    </div>
  );
}

/** One row: the icon (accent) and the label at the start, the value, and the row's actions. */
export function DetailRow({ icon, label, children, actions, multiline = false }: {
  icon?: ReactNode;
  label: ReactNode;
  children: ReactNode;
  actions?: ReactNode;
  multiline?: boolean;
}) {
  return (
    <div className={`flex ${multiline ? 'items-start' : 'items-center'} gap-3 py-2 border-b border-neutral-100 dark:border-neutral-800 last:border-b-0`}>
      <span className="shrink-0 w-24 flex items-center gap-1.5 text-xs text-neutral-500 dark:text-neutral-400 pt-0.5" dir="auto">
        {icon && <span className="shrink-0 text-accent" aria-hidden="true">{icon}</span>}
        <span className="truncate">{label}</span>
      </span>
      <div className="min-w-0 flex-1 text-sm text-neutral-800 dark:text-neutral-200 break-words" dir="auto">{children}</div>
      {actions && <span className="shrink-0 inline-flex items-center rounded-md border border-divider bg-surface-1">{actions}</span>}
    </div>
  );
}

/** One cell of a row's action group. The hover fill sits on the cell, which
 *  rounds at the group's ends; the group never clips, so the hover label shows. */
export function DetailAction({ label, onClick, href, children }: {
  label: string;
  onClick?: () => void;
  href?: string;
  children: ReactNode;
}) {
  // Accent, like every glyph beside a label in the app: a grey one in a
  // bordered cell read as a disabled control rather than as a button.
  const cls = 'w-8 h-8 inline-flex items-center justify-center text-accent/70 hover:text-accent transition';
  return (
    <span className="inline-flex border-s border-divider first:border-s-0 first:rounded-s-[5px] last:rounded-e-[5px] hover:bg-accent/10 transition">
      <HoverLabel label={label} position="start">
        {href ? (
          <a href={href} aria-label={label} className={cls}>{children}</a>
        ) : (
          <button type="button" onClick={onClick} aria-label={label} className={cls}>{children}</button>
        )}
      </HoverLabel>
    </span>
  );
}

/** The copy cell: a check replaces the icon while `copied` names this row. */
export function DetailCopyAction({ value, id, copied, onCopy, label }: {
  value: string;
  id: string;
  copied: string | null;
  onCopy: (text: string, id: string) => void;
  label: string;
}) {
  return (
    <DetailAction label={label} onClick={() => onCopy(value, id)}>
      {copied === id ? <Check size={15} className="text-green-500" /> : <Copy size={15} />}
    </DetailAction>
  );
}

/** A web address as a link: it opens the way the Open cell does, and reads as a link, like an email. */
export function DetailLink({ href, children }: { href: string; children: string }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      onClick={(e) => { e.preventDefault(); openExternal(href); }}
      className="text-accent hover:underline break-all"
      dir="ltr"
    >
      {children}
    </a>
  );
}

/** The notes block: an eyebrow and the text as written, no italics. */
export function DetailNotes({ heading, children }: { heading: string; children: string }) {
  return (
    <DetailGroup heading={heading}>
      <div className="py-2 text-sm text-neutral-800 dark:text-neutral-200 whitespace-pre-wrap break-words" dir="auto">{children}</div>
    </DetailGroup>
  );
}
