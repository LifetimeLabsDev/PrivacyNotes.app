/**
 * The look picker opened on one note, from the note menu's Icon row. It holds
 * what the folder and tag pickers hold in the sidebar: the state before the
 * visit, for Cancel, and a sync once a pick was saved.
 * Spec: ops/docs/archive/folder-tag-icons.md (section 6)
 */
import { useRef, useState } from 'react';
import { noteLookKey, restoreLooks, setItemLook, snapshotLooks } from '../itemStyles';
import type { UserSettings } from '../userSettings';
import { LookPicker } from './LookPicker';

export function NoteIconPicker({
  noteId,
  name,
  settings,
  mutateSettings,
  onSaved,
  onClose,
}: {
  noteId: string;
  name: string;
  settings: UserSettings;
  mutateSettings: (fn: (prev: UserSettings) => UserSettings) => void;
  onSaved: () => void;
  onClose: () => void;
}) {
  const lookKey = noteLookKey(noteId);
  const [before] = useState(() => snapshotLooks(settings.itemStyles, [lookKey]));
  const saved = useRef(false);
  return (
    <LookPicker
      target={{ kind: 'note', lookKey, name }}
      styles={settings.itemStyles}
      // The color tab is not shown for a note; the props stay for the type.
      noteColors="off"
      onNoteColors={() => {}}
      onPick={(patch) => {
        saved.current = true;
        mutateSettings((prev) => {
          const itemStyles = setItemLook(prev.itemStyles, lookKey, { icon: patch.icon ?? null });
          return itemStyles === prev.itemStyles ? prev : { ...prev, itemStyles };
        });
      }}
      onCancel={() => {
        mutateSettings((prev) => {
          const itemStyles = restoreLooks(prev.itemStyles, before);
          return itemStyles === prev.itemStyles ? prev : { ...prev, itemStyles };
        });
      }}
      onClose={() => {
        onClose();
        if (saved.current) onSaved();
      }}
    />
  );
}
