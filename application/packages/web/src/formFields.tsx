import type { ReactNode } from 'react';
import { AccentBar, HeadlineRule } from './settingsUI';

/**
 * What the four item forms share: the field box, the label over it, the
 * headline over a section, and the buttons that stand beside a field.
 *
 * The contact, login, card and SSH forms each carried their own copy of the
 * same two class strings, and the labels drifted from the panes those forms
 * save into: a contact read as one design in view mode and another in edit
 * mode. A form is the same pane with the values typeable, so it takes its
 * headline and its label anatomy from the same place the pane does.
 * Spec: ops/docs/ui-patterns.md (the item forms wear the detail pane's anatomy)
 */

export const FIELD_CLASS =
  'w-full rounded-md border border-divider bg-surface-1 px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-accent disabled:opacity-60';

/** A button that sits beside a field, outside it, so nothing covers the value. */
export const FIELD_BUTTON =
  'shrink-0 rounded-md p-2 text-accent/70 hover:text-accent hover:bg-neutral-100 dark:hover:bg-surface-0 transition';

/**
 * The headline over a section, the same one the panes draw: an accent bar,
 * the title, a rule to the end. It replaced an uppercase eyebrow in the
 * contact form, which was the one place in either pane that still used one.
 */
export function GroupHeading({ children }: { children: ReactNode }) {
  return (
    <div className="flex items-center gap-2.5 mb-2">
      <AccentBar />
      <h3 className="text-sm font-semibold text-neutral-900 dark:text-white truncate" dir="auto">{children}</h3>
      <HeadlineRule />
    </div>
  );
}

/**
 * The label over a field: the accent glyph and the text, the same pair the
 * pane puts at the start of the row this field saves into. The glyph is
 * what carries the field's identity at a glance, and it is accent because
 * every glyph beside a label in this app is.
 */
export function FieldLabel({ icon, children, htmlFor }: { icon?: ReactNode; children: ReactNode; htmlFor?: string }) {
  return (
    <label
      htmlFor={htmlFor}
      className="flex items-center gap-1.5 text-xs font-medium text-neutral-500 dark:text-neutral-400 mb-1"
      dir="auto"
    >
      {icon && <span className="shrink-0 text-accent" aria-hidden="true">{icon}</span>}
      {children}
    </label>
  );
}
