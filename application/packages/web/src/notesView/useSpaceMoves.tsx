import { useRef, useState } from 'react';
import type { TFunction } from 'i18next';
import { SPACE_ICONS, SpaceMoveLabel, spaceMoveText } from '../SpaceSwitch';
import type { LocalNote } from '../db';
import type { FolderDef } from '../folders';
import { foldersIn, inSpace, type Space, type SpaceView } from '../spaces';
import type { UpgradeTrigger } from '../UpgradeModal';
import type { useFolderActions } from './useFolderActions';

type FolderActions = ReturnType<typeof useFolderActions>;

/**
 * Moving folders and items between the Personal and Work spaces, and the
 * space switch the sidebar draws. Spaces filter the lists only; nothing here
 * touches sync or export. Spec: ops/docs/plans/spaces.md
 */
export function useSpaceMoves({
  t,
  notes,
  folders,
  spacesOn,
  foldersUnlocked,
  proMark,
  view,
  filterSpace,
  setActiveSpace,
  spaceOfFolder,
  handleMoveFolderToSpace,
  handleCreateFolder,
  handleMoveNotesToFolder,
  setFolderPicker,
  flashToast,
  setDrawerOpen,
  setShowUpgrade,
}: {
  t: TFunction;
  notes: LocalNote[];
  folders: FolderDef[];
  spacesOn: boolean;
  foldersUnlocked: boolean;
  /** Not Pro: Personal and Work carry the rocket, also in the demo where they work. */
  proMark: boolean;
  /** The open view of the switch. */
  view: SpaceView;
  /** The space the lists show, or null while All is open. */
  filterSpace: Space | null;
  setActiveSpace: (view: SpaceView) => void;
  spaceOfFolder: Parameters<typeof foldersIn>[1];
  handleMoveFolderToSpace: FolderActions['handleMoveFolderToSpace'];
  handleCreateFolder: FolderActions['handleCreateFolder'];
  handleMoveNotesToFolder: FolderActions['handleMoveNotesToFolder'];
  setFolderPicker: FolderActions['setFolderPicker'];
  flashToast: (message: string) => void;
  setDrawerOpen: (open: boolean) => void;
  setShowUpgrade: (next: { trigger: UpgradeTrigger }) => void;
}) {
  // A root folder moved to the other space leaves the tree on screen, so the
  // toast names where it went and offers the way back.
  const [spaceToast, setSpaceToast] = useState<{ id: string; name: string; to: Space } | null>(null);
  const spaceToastTimer = useRef<number | undefined>(undefined);
  const moveFolderToSpace = (id: string, to: Space) => {
    handleMoveFolderToSpace(id, to);
    const name = folders.find((f) => f.id === id)?.name ?? '';
    setSpaceToast({ id, name, to });
    window.clearTimeout(spaceToastTimer.current);
    spaceToastTimer.current = window.setTimeout(() => setSpaceToast(null), 5000);
  };
  /** "Move to Work" from Personal, "Move to Personal" from Work: one or more
   *  items, through the picker of the other space's folders. Work with no
   *  folder yet gets one named "Work", and the items go straight in. */
  const spaceMoveLabel = (to: Space) => spaceMoveText(t, to);
  const moveItemsToSpace = (ids: string[], to: Space) => {
    if (to === 'work' && foldersIn(folders, spaceOfFolder, 'work').length === 0) {
      const id = handleCreateFolder(t('shell:spaces.work'), null);
      if (!id) return;
      handleMoveFolderToSpace(id, 'work');
      void handleMoveNotesToFolder(ids, id);
      flashToast(t('shell:spaces.itemMovedToWork'));
      return;
    }
    const folderIds = new Set(ids.map((id) => notes.find((n) => n.id === id)?.folderId ?? null));
    setFolderPicker({
      mode: 'note',
      noteIds: ids,
      currentFolderId: folderIds.size === 1 ? [...folderIds][0] ?? null : undefined,
      space: to,
    });
  };
  /** The space these items move to: the one that is not open, or, while All
   *  shows both, the other space of the items when they share one. */
  const moveTarget = (ids: string[]): Space | null => {
    if (filterSpace) return filterSpace === 'work' ? 'personal' : 'work';
    const inWork = ids.map((id) => {
      const n = notes.find((x) => x.id === id);
      return !!n && inSpace(n, 'work', spaceOfFolder);
    });
    if (inWork.every(Boolean)) return 'personal';
    if (!inWork.some(Boolean)) return 'work';
    return null;
  };
  const spaceMove = spacesOn
    ? (ids: string[]) => {
        const to = moveTarget(ids);
        if (!to) return undefined;
        const Glyph = SPACE_ICONS[to];
        return { label: <SpaceMoveLabel to={to} />, icon: <Glyph size={16} aria-hidden="true" />, run: (picked: string[]) => moveItemsToSpace(picked, to) };
      }
    : undefined;
  /** The same move for one item to a named space, as a menu row draws it. */
  const spaceMoveTo = spacesOn
    ? (to: Space) => {
        const Glyph = SPACE_ICONS[to];
        return { label: <SpaceMoveLabel to={to} />, icon: <Glyph size={14} aria-hidden="true" />, run: (ids: string[]) => moveItemsToSpace(ids, to) };
      }
    : undefined;
  // A free account sees the switch too, on All: Personal and Work close the
  // drawer, which would cover the window, and open the upgrade window. A Pro
  // account that switched Spaces off sees no switch.
  const spacesRail = spacesOn
    ? {
        active: view,
        onChange: setActiveSpace,
        onMoveFolder: moveFolderToSpace,
        folderSpace: (id: string) => spaceOfFolder.get(id) ?? 'personal',
        locked: proMark,
      }
    : !foldersUnlocked
      ? {
          active: 'all' as const,
          locked: true,
          // All is the only view a free account has, so it is no choice.
          noAll: true,
          onChange: (to: SpaceView) => {
            if (to === 'all') return;
            setDrawerOpen(false);
            setShowUpgrade({ trigger: 'spaces' });
          },
        }
      : undefined;

  return { spaceToast, setSpaceToast, spaceToastTimer, spaceMoveLabel, spaceMove, spaceMoveTo, spacesRail };
}
