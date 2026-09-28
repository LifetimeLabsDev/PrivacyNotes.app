import type { InputHTMLAttributes } from 'react';
import { isImeComposing } from './imeComposing';

type Props = Omit<InputHTMLAttributes<HTMLInputElement>, 'value' | 'onChange' | 'onKeyDown' | 'onBlur'> & {
  value: string;
  onValueChange: (value: string) => void;
  /** Enter and blur. The caller decides what an empty or unchanged value means. */
  onCommit: () => void;
  onCancel: () => void;
};

/**
 * The rename field of a file chip and a device row. Opens focused; Enter and
 * blur save, Escape cancels, and a key that finishes an IME composition does
 * neither. Other input props pass through, which is how the file chip keeps
 * its drag and pointer stops.
 * Spec: ops/docs/ui-patterns.md (inline rename field)
 */
export function InlineRenameField({ value, onValueChange, onCommit, onCancel, ...rest }: Props) {
  return (
    <input
      autoFocus
      dir="auto"
      enterKeyHint="done"
      {...rest}
      value={value}
      onChange={(e) => onValueChange(e.target.value)}
      onKeyDown={(e) => {
        if (isImeComposing(e)) return;
        if (e.key === 'Enter') {
          e.preventDefault();
          onCommit();
        } else if (e.key === 'Escape') {
          // Escape belongs to the field while it is open; without the stop
          // it reaches the handlers around it (the editor, a modal).
          e.preventDefault();
          e.stopPropagation();
          onCancel();
        }
      }}
      onBlur={onCommit}
    />
  );
}
