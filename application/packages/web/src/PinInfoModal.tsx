import { createPortal } from 'react-dom';
import { useTranslation } from 'react-i18next';
import { useEscapeToClose } from './useEscapeToClose';
import { X } from './icons';

type Props = { onClose: () => void };

export function PinInfoModal({ onClose }: Props) {
  const { t } = useTranslation('security');
  useEscapeToClose(onClose);
  return createPortal(
    <div className="fixed inset-0 bg-black/50 dark:bg-black/70 flex items-center justify-center p-4 z-50" onClick={onClose}>
      <div className="bg-surface-2 border border-divider text-pn rounded-lg max-w-sm w-full p-5 space-y-3" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-start justify-between">
          <h2 className="text-base font-semibold">{t('pinInfo.title')}</h2>
          <button onClick={onClose} className="text-pn-muted hover:text-pn-soft transition p-1 -m-1" aria-label={t('common:actions.close')}>
            <X size={18} />
          </button>
        </div>
        <p className="text-sm text-pn-muted leading-relaxed">
          {t('pinInfo.body')}
        </p>
        <button onClick={onClose} className="w-full rounded-md bg-accent-fill text-white hover:bg-accent-fill-hover px-4 py-2 text-sm font-medium transition">{t('pinInfo.gotIt')}</button>
      </div>
    </div>,
    document.body,
  );
}
