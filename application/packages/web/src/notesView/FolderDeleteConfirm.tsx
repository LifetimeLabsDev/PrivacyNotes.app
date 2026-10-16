import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ConfirmModal } from '../ConfirmModal';
import { subtreeIds, type FolderDef } from '../folders';

/**
 * "Delete folder?" for one folder. A folder with subfolders offers to delete
 * them too, off by default, so a whole imported branch goes in one step; the
 * notes of every deleted folder still move up and are never deleted.
 * Spec: ops/issues/0514.md
 */
export function FolderDeleteConfirm({ folders, id, name, onDelete, onClose }: {
  folders: FolderDef[];
  id: string;
  name: string;
  onDelete: (withSubfolders: boolean) => void;
  onClose: () => void;
}) {
  const { t } = useTranslation('shell');
  const [withSubfolders, setWithSubfolders] = useState(false);
  const target = folders.find((f) => f.id === id);
  const parent = target?.parentId ? folders.find((f) => f.id === target.parentId) : undefined;
  const subfolders = subtreeIds(folders, id).size - 1;
  const branch = withSubfolders && subfolders > 0;
  const body = parent
    ? t(branch ? 'folders.deleteConfirmBranchNested' : 'folders.deleteConfirmBodyNested', { folder: name, parent: parent.name })
    : t(branch ? 'folders.deleteConfirmBranchRoot' : 'folders.deleteConfirmBodyRoot', { folder: name });
  return (
    <ConfirmModal
      title={t('folders.deleteConfirmTitle')}
      confirmLabel={t('folders.delete')}
      variant="danger"
      onConfirm={() => onDelete(branch)}
      onClose={onClose}
    >
      <p>{body}</p>
      {subfolders > 0 && (
        <label className="mt-3 flex items-center gap-2 text-pn-soft cursor-pointer">
          <input
            type="checkbox"
            checked={withSubfolders}
            onChange={(e) => setWithSubfolders(e.target.checked)}
            className="accent-accent"
          />
          {t('folders.deleteSubfolders', { count: subfolders })}
        </label>
      )}
    </ConfirmModal>
  );
}
