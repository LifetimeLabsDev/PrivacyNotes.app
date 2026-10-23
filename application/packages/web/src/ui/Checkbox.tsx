import type { InputHTMLAttributes, ReactNode } from 'react';

/**
 * @catalog Checkbox
 * use: a yes or no that is part of a form or a confirm ("Also delete its subfolders", "Require PIN to view", "I wrote it down"), with an optional `description` under the label. `card` frames it, for a choice that needs its own box. A setting that applies at once is a Switch.
 * never: an <input type="checkbox"> with its own classes; a red checkbox; a tick box of your own.
 */
export function Checkbox({ label, description, card = false, className = '', ...rest }: Omit<InputHTMLAttributes<HTMLInputElement>, 'type'> & {
  label: ReactNode;
  description?: ReactNode;
  card?: boolean;
}) {
  return (
    <label
      className={`flex items-start gap-2.5 text-sm text-pn ${rest.disabled ? 'cursor-not-allowed opacity-50' : 'cursor-pointer'}${card ? ' rounded-lg border border-divider p-3 hover:bg-surface-1 transition' : ''}${className ? ` ${className}` : ''}`}
    >
      <input type="checkbox" {...rest} className="mt-0.5 h-4 w-4 shrink-0 accent-accent" />
      <span className="min-w-0">
        <span className="block">{label}</span>
        {description && <span className="mt-0.5 block text-xs text-pn-muted">{description}</span>}
      </span>
    </label>
  );
}
