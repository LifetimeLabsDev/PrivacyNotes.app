import { Trans, useTranslation } from 'react-i18next';
import { ConfirmModal } from './ConfirmModal';

type Props = {
  noteCount: number;
  onConfirm: () => void;
  onClose: () => void;
};

export function EmptyTrashModal({ noteCount, onConfirm, onClose }: Props) {
  const { t } = useTranslation('common');
  return (
    <ConfirmModal
      title={t('emptyTrash.title')}
      confirmLabel={t('emptyTrash.confirm')}
      variant="danger"
      onConfirm={onConfirm}
      onClose={onClose}
    >
      <Trans
        i18nKey="common:emptyTrash.body"
        count={noteCount}
        values={{ count: noteCount }}
        components={{ highlight: <span className="font-medium text-pn" /> }}
      />
    </ConfirmModal>
  );
}
