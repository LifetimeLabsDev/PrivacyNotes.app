import { useTranslation } from 'react-i18next';
import { FOLDER_NAME_MAX_LENGTH } from './folders';
import { Check, X } from './icons';
import { isImeComposing } from './imeComposing';

/**
 * The inline "name this folder" field, used wherever a folder is created or
 * renamed: the sidebar tree, the Move dialog's rows, and that dialog's
 * footer.
 *
 * It carries VISIBLE save and cancel buttons. Enter and Escape still work
 * and are what a desktop user reaches for, but they were the only way to
 * finish, and a phone keyboard's return key is not an obvious "save" - the
 * field looked like it had no way out (reported 2026-08-27).
 *
 * Both buttons cancel the pointer's default before it lands, so the field
 * never blurs first. Without that the blur commit fires ahead of the click
 * and Cancel saves the thing it was asked to throw away.
 */
export function FolderNameInput({
  value,
  onChange,
  onCommit,
  onCancel,
  scale,
  tabIndex,
}: {
  value: string;
  onChange: (next: string) => void;
  onCommit: () => void;
  onCancel: () => void;
  /** 'rail' is the sidebar's tighter scale, 'dialog' the modal's. */
  scale: 'rail' | 'dialog';
  tabIndex?: number;
}) {
  const { t } = useTranslation('shell');
  const rail = scale === 'rail';
  const button =
    'shrink-0 inline-flex items-center justify-center w-7 h-7 rounded-md border border-divider bg-surface-1 transition';
  return (
    <>
      <input
        autoFocus
        tabIndex={tabIndex}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => {
          if (isImeComposing(e)) return;
          if (e.key === 'Enter') {
            e.preventDefault();
            onCommit();
          } else if (e.key === 'Escape') {
            // Escape belongs to the input while it is open - without the
            // stop it reaches useEscapeToClose and shuts the whole dialog.
            e.preventDefault();
            e.stopPropagation();
            onCancel();
          }
        }}
        onBlur={onCommit}
        onClick={(e) => e.stopPropagation()}
        maxLength={FOLDER_NAME_MAX_LENGTH + 5}
        placeholder={t('folders.namePlaceholder')}
        enterKeyHint="done"
        className={`min-w-0 flex-1 bg-transparent border-b border-accent/50 focus:border-accent outline-none text-pn placeholder:text-neutral-400 dark:placeholder:text-neutral-600 ${
          rail ? 'text-[15px] lg:text-[13px] font-medium' : 'text-[14px]'
        }`}
      />
      <button
        type="button"
        tabIndex={tabIndex}
        onPointerDown={(e) => e.preventDefault()}
        onClick={(e) => {
          e.stopPropagation();
          onCommit();
        }}
        aria-label={t('folders.saveName')}
        className={`${button} text-accent hover:border-accent`}
      >
        <Check size={14} />
      </button>
      <button
        type="button"
        tabIndex={tabIndex}
        onPointerDown={(e) => e.preventDefault()}
        onClick={(e) => {
          e.stopPropagation();
          onCancel();
        }}
        aria-label={t('common:actions.cancel')}
        className={`${button} text-neutral-500 dark:text-neutral-400 hover:text-accent hover:border-accent`}
      >
        <X size={14} />
      </button>
    </>
  );
}
