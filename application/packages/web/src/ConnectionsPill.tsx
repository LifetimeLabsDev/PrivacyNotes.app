import { Suspense, lazy, useEffect, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { Graph } from './icons';
import type { LocalNote } from './db';
import { EditorSlotPill } from './EditorSlotPill';
import { registerEditorCommand } from './editorCommands';
import { keyText } from './shortcutMatch';
import { deriveDisplayTitle } from './notesViewUtils';
import type { LinkIndex } from './connectionsIndex';
import type { ConnectionLists } from './ConnectionsPanel';

const ConnectionsPanel = lazy(() => import('./ConnectionsPanel').then((m) => ({ default: m.ConnectionsPanel })));

/**
 * The Connections pill in the editor's corner slot: the notes that link to
 * the open item, and the items it links to. Like every pill in that slot it
 * takes itself away when it has nothing to say, so a note with no links
 * shows nothing. Open, it becomes the panel in the same place, as the outline
 * does; the editor keeps one panel open at a time.
 * Spec: ops/issues/0351.md (Spec)
 */
export function ConnectionsPill({
  note,
  notes,
  index,
  isNoteLocked,
  onOpen,
  open,
  onOpenChange,
  tabIndex,
}: {
  note: LocalNote;
  notes: readonly LocalNote[];
  index: LinkIndex;
  isNoteLocked: (n: LocalNote) => boolean;
  onOpen: (n: LocalNote) => void;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  tabIndex?: number;
}) {
  const { t } = useTranslation('notes');

  const byId = useMemo(() => new Map(notes.map((n) => [n.id, n])), [notes]);
  const lists = useMemo((): ConnectionLists => {
    const pick = (ids: readonly string[] | undefined) =>
      (ids ?? [])
        .map((id) => byId.get(id))
        .filter((n): n is LocalNote => !!n)
        .sort((a, b) => deriveDisplayTitle(a, isNoteLocked(a)).localeCompare(deriveDisplayTitle(b, isNoteLocked(b))));
    const out = index.outgoing.get(note.id);
    return {
      from: pick(index.incoming.get(note.id)),
      to: pick(out?.ids),
      missing: out?.missing ?? [],
      hidden: index.protectedIncoming.get(note.id) ?? 0,
    };
    // isNoteLocked changes identity every render; the titles it gates follow `notes`.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [index, byId, note.id]);

  const shown = lists.from.length + lists.to.length + lists.missing.length;
  const visible = shown + lists.hidden > 0;

  // The key (Mod+Shift+X) runs this toggle, and only while the pill is on screen.
  useEffect(() => {
    if (!visible) return;
    return registerEditorCommand('connections', () => onOpenChange(!open));
  }, [visible, open, onOpenChange]);

  if (!visible) return null;

  if (!open) {
    return (
      <EditorSlotPill label={t('connections.title')} keys={keyText('connections')} onClick={() => onOpenChange(true)} tabIndex={tabIndex}>
        <Graph size={17} />
      </EditorSlotPill>
    );
  }

  return (
    <Suspense fallback={null}>
      <ConnectionsPanel lists={lists} isNoteLocked={isNoteLocked} onOpen={onOpen} onClose={() => onOpenChange(false)} />
    </Suspense>
  );
}
