import { useEscapeToClose } from '../useEscapeToClose';
import { Button } from './Button';

/**
 * @catalog EditRow
 * use: the footer of every inline edit or add form: Cancel, then a labeled Save (or Add). Escape cancels the edit, not the window around it.
 * never: an icon-only check mark as Save; Save before Cancel; a form that only Enter can save.
 */
export function EditRow({
  onSave,
  onCancel,
  saveLabel,
  canSave = true,
  className = '',
}: {
  onSave: () => void;
  onCancel: () => void;
  /** Defaults to "Save"; an add form passes "Add". */
  saveLabel?: string;
  canSave?: boolean;
  className?: string;
}) {
  useEscapeToClose(onCancel);
  return (
    <div className={`flex justify-end gap-2${className ? ` ${className}` : ''}`}>
      <Button action="cancel" onClick={onCancel} />
      <Button action="save" onClick={onSave} disabled={!canSave}>
        {saveLabel}
      </Button>
    </div>
  );
}
