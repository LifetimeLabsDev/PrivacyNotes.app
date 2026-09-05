import { Trans, useTranslation } from 'react-i18next';
import { ConfirmModal } from './ConfirmModal';
import { NeverBackedUpNotice } from './neverBackedUp';

type Props = {
  noteTitle: string;
  /** Enables the never-backed-up warning; absent where the caller has no id at hand. */
  noteId?: string;
  onConfirm: () => void;
  onClose: () => void;
};

export function DeleteNoteModal({ noteTitle, noteId, onConfirm, onClose }: Props) {
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
      <NeverBackedUpNotice ids={noteId ? [noteId] : null} />
    </ConfirmModal>
  );
}
