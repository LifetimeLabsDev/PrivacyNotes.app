import type { InputHTMLAttributes } from 'react';

export const TASK_CHECK_PATH = 'M2 6.5 5 9 10 3';

/**
 * @catalog TaskCheckbox
 * use: completing a task. The editor and Kanban node views share its path and pn-task-checkbox styles.
 * never: a hand-drawn task toggle or a separate check animation. Forms use Checkbox.
 */
export function TaskCheckbox({ className = '', ...props }: Omit<InputHTMLAttributes<HTMLInputElement>, 'type'>) {
  return (
    <label className={`relative inline-flex shrink-0 items-center ${className}`}>
      <input {...props} type="checkbox" className="pn-task-checkbox" />
      <span className="pn-check" aria-hidden="true">
        <svg viewBox="0 0 12 12"><path d={TASK_CHECK_PATH} /></svg>
      </span>
    </label>
  );
}
