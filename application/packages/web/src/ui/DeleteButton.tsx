import { useEffect, useRef, useState, type ComponentProps } from 'react';
import { useTranslation } from 'react-i18next';
import { Trash } from '../icons';
import { useEscapeToClose } from '../useEscapeToClose';
import { IconButton } from './Button';

/** How long the armed "Delete?" waits for the second click. */
const ARMED_MS = 3000;

/**
 * @catalog DeleteButton
 * use: removing one item from a row (a file, a medication, a habit, a field): a trash button that turns into a red "Delete?" (or "Remove?" with `kind="remove"`) in the same place for three seconds; a second click there deletes, Escape or the time disarms it. It always sits in the row itself.
 * never: a delete or remove row in a "..." or context menu when the row has this button; a confirm that opens somewhere else (a menu, a second row, a window) for a time-limited arm; a red confirm row of your own.
 */
export function DeleteButton({ label, onConfirm, kind = 'delete', confirmLabel, position }: {
  /** Names the button: "Delete qa-repeat.jpg", "Remove Multivitamin". */
  label: string;
  onConfirm: () => void;
  kind?: 'delete' | 'remove';
  /** The armed words, when the item has its own ("Delete?" is the default). */
  confirmLabel?: string;
  /** Where the tooltip sits, as on IconButton. */
  position?: ComponentProps<typeof IconButton>['position'];
}) {
  const { t } = useTranslation('common');
  const [armed, setArmed] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pill = useRef<HTMLButtonElement | null>(null);
  const fromKeyboard = useRef(false);
  const disarm = () => {
    if (timer.current) clearTimeout(timer.current);
    setArmed(false);
  };
  useEscapeToClose(disarm, armed);
  useEffect(() => () => { if (timer.current) clearTimeout(timer.current); }, []);
  // A keyboard user lands on the armed button, so Enter confirms.
  useEffect(() => { if (armed && fromKeyboard.current) pill.current?.focus(); }, [armed]);

  // A click must not move the caret of an editor the row sits in.
  const keepFocus = (e: React.MouseEvent) => { e.preventDefault(); e.stopPropagation(); };

  if (armed) {
    return (
      <button
        ref={pill}
        type="button"
        onMouseDown={keepFocus}
        onClick={(e) => { e.stopPropagation(); disarm(); onConfirm(); }}
        className="inline-flex h-8 shrink-0 select-none items-center gap-1 rounded-lg bg-danger/10 px-2.5 text-xs font-medium text-danger transition hover:bg-danger/15"
      >
        <Trash size={13} aria-hidden="true" />
        {confirmLabel ?? t(kind === 'remove' ? 'actions.removeConfirm' : 'actions.deleteConfirm')}
      </button>
    );
  }
  return (
    <span onMouseDown={keepFocus} className="inline-flex">
      <IconButton
        label={label}
        position={position}
        tone="danger"
        onClick={(e) => {
          e.stopPropagation();
          fromKeyboard.current = e.detail === 0;
          setArmed(true);
          timer.current = setTimeout(() => setArmed(false), ARMED_MS);
        }}
      >
        <Trash size={15} aria-hidden="true" />
      </IconButton>
    </span>
  );
}
