import { useId, type ReactNode } from 'react';
import { SETTINGS_HELP } from './settingsUI';

/**
 * The one boolean switch. `label` is required because it is the control's
 * name: a screen reader announces the control, not the text drawn beside
 * it, so a switch whose words sit in a sibling reads "switch, on" and says
 * nothing about what it turns on (WCAG 2.2, 4.1.2).
 *
 * The whole row is the `<label>`, so a click anywhere on it flips the
 * switch. `aria-labelledby` names the control with the label alone, which
 * keeps a description out of the name; the description is read after it.
 * The row is always one line with the switch at its end: a switch belongs
 * beside its label, at every width.
 * Spec: ops/docs/ui-patterns.md section 36
 */
export function Switch({
  label,
  checked,
  onChange,
  disabled = false,
  id,
  className = '',
  labelClassName = 'text-sm font-medium',
  description,
  icon,
  setting,
  hint,
}: {
  label: ReactNode;
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
  /** The input's id, for a caller that points at it from outside the row. */
  id?: string;
  /** The row's spacing and edges. */
  className?: string;
  labelClassName?: string;
  description?: ReactNode;
  /** A glyph before the label, kept out of the name. */
  icon?: ReactNode;
  /** The settings search id of this row. */
  setting?: string;
  /** A control beside the label, such as a help button, kept out of the name. */
  hint?: ReactNode;
}) {
  const uid = useId();
  const labelId = `${uid}-label`;
  const descriptionId = `${uid}-description`;
  // The label names its checkbox explicitly: without `htmlFor` it would
  // control the first labelable element inside it, which is a `hint` button
  // when there is one, and a click on the row would press that instead.
  const inputId = id ?? `${uid}-input`;
  return (
    <label htmlFor={inputId} data-setting={setting} className={`flex items-center justify-between gap-4 ${disabled ? 'cursor-default' : 'cursor-pointer'} ${className}`}>
      <span className="min-w-0 flex-1 flex flex-col">
        {hint ? (
          <span className="flex items-center gap-1.5">
            <span id={labelId} className={labelClassName}>
              {icon && <span aria-hidden="true" className="flex shrink-0">{icon}</span>}
              {label}
            </span>
            {hint}
          </span>
        ) : (
          <span id={labelId} className={labelClassName}>
            {icon && <span aria-hidden="true" className="flex shrink-0">{icon}</span>}
            {label}
          </span>
        )}
        {description && (
          <span id={descriptionId} className={`${SETTINGS_HELP} mt-0.5`}>
            {description}
          </span>
        )}
      </span>
      <span className="relative shrink-0">
        {/* A native checkbox carries its state in `checked`, which the
            browser maps into the tree, so no aria-checked sits beside it
            to disagree. */}
        <input
          id={inputId}
          type="checkbox"
          role="switch"
          checked={checked}
          disabled={disabled}
          onChange={(e) => onChange(e.target.checked)}
          aria-labelledby={labelId}
          aria-describedby={description ? descriptionId : undefined}
          className="sr-only peer"
        />
        <span
          aria-hidden="true"
          className="block w-9 h-5 rounded-full transition-colors bg-pn-muted/35 peer-checked:bg-accent-fill peer-disabled:bg-pn-muted/20 peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-accent"
        />
        <span
          aria-hidden="true"
          className="absolute start-0.5 top-0.5 w-4 h-4 rounded-full shadow-sm bg-white peer-disabled:bg-white/50 transition-transform peer-checked:translate-x-4 peer-checked:rtl:-translate-x-4"
        />
      </span>
    </label>
  );
}
