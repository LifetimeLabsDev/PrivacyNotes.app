import { Trans, useTranslation } from 'react-i18next';
import { ConfirmModal } from './ConfirmModal';
import { NeverBackedUpNotice } from './neverBackedUp';

type Props = {
  noteCount: number;
  /** The trashed ids, for the never-backed-up warning. */
  noteIds?: readonly string[];
  onConfirm: () => void;
  onClose: () => void;
};

export function EmptyTrashModal({ noteCount, noteIds, onConfirm, onClose }: Props) {
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
      <NeverBackedUpNotice ids={noteIds ?? null} />
    </ConfirmModal>
  );
}
