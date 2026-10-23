import { useTranslation } from 'react-i18next';
import { CaretLeft } from '../icons';

/**
 * @catalog BackRow
 * use: the Back row at the top of a sub-view inside a menu or a pane (a caret and the title of where it goes); `wide` makes the whole row the button.
 * never: an ArrowLeft text link or a bordered "Back" button of your own.
 */
export function BackRow({ title, onBack, wide = false }: { title: string; onBack: () => void; wide?: boolean }) {
  const { t } = useTranslation('common');
  // Wide: the whole row is the button, for a Back row at the top of a pane
  // (the Calendar's), where the title names where it goes.
  if (wide) {
    return (
      <button
        type="button"
        onClick={onBack}
        className="w-full flex items-center gap-1 px-1.5 py-1 text-start rounded-md hover:bg-surface-1 focus-visible:bg-surface-1 outline-none transition"
      >
        <span className="shrink-0 inline-flex items-center justify-center w-9 h-9 [@media(hover:none)]:w-11 [@media(hover:none)]:h-11 text-accent">
          <CaretLeft size={16} aria-hidden="true" />
        </span>
        <span className="text-[14px] font-medium text-pn">{title}</span>
      </button>
    );
  }
  return (
    <div className="flex items-center gap-1 px-1.5 py-1">
      <button
        type="button"
        onClick={onBack}
        aria-label={t('actions.back')}
        className="shrink-0 inline-flex items-center justify-center w-9 h-9 [@media(hover:none)]:w-11 [@media(hover:none)]:h-11 rounded-md text-accent hover:bg-surface-1 focus-visible:bg-surface-1 outline-none transition"
      >
        <CaretLeft size={16} aria-hidden="true" />
      </button>
      <span className="text-[14px] font-medium text-pn">{title}</span>
    </div>
  );
}
