import { forwardRef, useId, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes } from 'react';
import { FIELD_CLASS } from '../formFields';
import { SETTINGS_HELP, SETTINGS_SELECT } from '../settingsUI';

/** The two field boxes: `md` in a window or an item form, `sm` in a settings row. */
const BOX = { md: FIELD_CLASS, sm: SETTINGS_SELECT } as const;

/** The label over a field: the accent glyph and 12px medium text. */
const LABEL = 'mb-1 flex items-center gap-1.5 text-xs font-medium text-pn-muted';

/**
 * @catalog TextField
 * use: every one-line text, number or time input. `size="md"` (the default) in a window or an item form, `size="sm"` in a settings row. `label` sits over it with an optional accent `icon` (13px), the anatomy of the item forms; `hint` sits under it in the helper style; `error` replaces the hint in red.
 * never: an <input> with its own border, padding or text size; a label of your own over a field; a placeholder that carries the only instruction.
 */
export const TextField = forwardRef<HTMLInputElement, Omit<InputHTMLAttributes<HTMLInputElement>, 'size'> & {
  label?: ReactNode;
  icon?: ReactNode;
  hint?: ReactNode;
  error?: ReactNode;
  size?: 'md' | 'sm';
}>(function TextField({ label, icon, hint, error, size = 'md', className = '', id, ...rest }, ref) {
  const auto = useId();
  const fieldId = id ?? auto;
  const wrapped = Boolean(label || hint || error);
  const field = (
    <input
      ref={ref}
      id={fieldId}
      aria-invalid={error ? true : undefined}
      {...rest}
      className={`min-w-0${wrapped ? ' w-full' : ''} ${BOX[size]}${error ? ' border-danger' : ''}${className ? ` ${className}` : ''}`}
    />
  );
  if (!wrapped) return field;
  return (
    <div className="min-w-0">
      {label && (
        <label htmlFor={fieldId} className={LABEL} dir="auto">
          {icon && <span className="shrink-0 text-accent" aria-hidden="true">{icon}</span>}
          {label}
        </label>
      )}
      {field}
      {error ? <p className="mt-1 text-xs text-danger">{error}</p> : hint && <p className={`mt-1 ${SETTINGS_HELP}`}>{hint}</p>}
    </div>
  );
});

/**
 * @catalog Select
 * use: a choice from a list too long for a segmented control (a range, a time, a unit). Native <select>; `size` as TextField.
 * never: a <select> with its own classes; a select for two or three options (use Segmented).
 */
export function Select({ size = 'md', className = '', children, ...rest }: Omit<SelectHTMLAttributes<HTMLSelectElement>, 'size'> & { size?: 'md' | 'sm'; children: ReactNode }) {
  return (
    <select {...rest} className={`${BOX[size]}${className ? ` ${className}` : ''}`}>
      {children}
    </select>
  );
}
