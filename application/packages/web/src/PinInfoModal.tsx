import { createPortal } from 'react-dom';
import { useTranslation } from 'react-i18next';
import { Modal } from './ui';

type Props = { onClose: () => void };

export function PinInfoModal({ onClose }: Props) {
  const { t } = useTranslation('security');
  return createPortal(
    <Modal onClose={onClose} title={t('pinInfo.title')} className="max-w-sm p-6 space-y-3">
        <p className="text-sm text-pn-muted leading-relaxed">
          {t('pinInfo.body')}
        </p>
    </Modal>,
    document.body,
  );
}
