import { Trans, useTranslation } from 'react-i18next';
import { ConfirmModal } from './ConfirmModal';

type Props = {
  noteTitle: string;
  onConfirm: () => void;
  onClose: () => void;
};

export function DeleteNoteModal({ noteTitle, onConfirm, onClose }: Props) {
  const { t } = useTranslation('common');
  return (
    <ConfirmModal
      title={t('deleteNote.title')}
      confirmLabel={t('deleteNote.confirm')}
      variant="danger"
      onConfirm={onConfirm}
      onClose={onClose}
    >
      <Trans
        i18nKey="common:deleteNote.body"
        values={{ title: noteTitle || t('deleteNote.untitled') }}
        components={{ highlight: <span className="font-medium text-pn" /> }}
      />
    </ConfirmModal>
  );
}
