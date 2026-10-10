import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { readBarPositionPref, writeBarPositionPref, type BarPosition } from '../editorPrefs';
import {
  readFormatBarSetting,
  resolveFormatBar,
  stockFormatBar,
  writeFormatBarSetting,
  type FormatBarSetting,
  type ResolvedFormatBar,
} from '../formatBar';
import type { FormatBarContextValue } from '../formatBarContext';
import type { FormatBarBoardProps } from '../FormatBarBoard';
import type { UserSettings } from '../userSettings';

/**
 * The format bar wiring NotesView owns: what every toolbar under it draws,
 * the door from the toolbar's gear, and the props of the board in
 * Settings > Format bar. Every move is applied to the arrangement in the
 * settings cache at the moment of the write, never to the one the board last
 * drew, so two quick moves cannot undo each other.
 *
 * Arranging is Pro. A free account still uses the whole board, on a draft:
 * the editor's bar keeps the saved layout, leaving the tab drops the draft,
 * and "Keep this layout" hands it to the upgrade window. When the account
 * turns Pro the draft is saved, so the arrangement is not lost.
 * Spec: ops/docs/plans/format-bar.md
 */
export function useFormatBar({
  formatBar,
  mutateSettings,
  onOpenSettings,
  locked,
  onOpenUpgrade,
}: {
  formatBar: FormatBarSetting;
  mutateSettings: (updater: (prev: UserSettings) => UserSettings) => void;
  /** Opens Settings > Format bar. */
  onOpenSettings: () => void;
  /** A free account: moves change a draft, never the saved layout. */
  locked: boolean;
  /** Closes Settings and opens the upgrade window on the toolbar pitch. */
  onOpenUpgrade: () => void;
}): { formatBarContext: FormatBarContextValue; formatBarBoard: FormatBarBoardProps } {
  const saved = useMemo(() => resolveFormatBar(readFormatBarSetting(formatBar)), [formatBar]);
  // Where the bar sits, top or bottom. Device-local and free.
  const [position, setPositionState] = useState<BarPosition>(readBarPositionPref);
  const setPosition = useCallback((next: BarPosition) => {
    writeBarPositionPref(next);
    setPositionState(next);
  }, []);
  const drawn = saved;

  const formatBarContext = useMemo(
    () => ({ layout: drawn, onCustomize: onOpenSettings, position }),
    [drawn, onOpenSettings, position],
  );

  const [draft, setDraft] = useState<ResolvedFormatBar | null>(null);
  // Set by "Keep this layout": leaving the tab for the upgrade window keeps
  // the draft, any other way out drops it.
  const handoff = useRef(false);

  const save = useCallback(
    (move: (current: ResolvedFormatBar) => ResolvedFormatBar | null) => {
      mutateSettings((prev) => {
        const current = resolveFormatBar(readFormatBarSetting(prev.formatBar));
        const next = writeFormatBarSetting(prev.formatBar, move(current));
        return next === prev.formatBar ? prev : { ...prev, formatBar: next };
      });
    },
    [mutateSettings],
  );

  const onUpdate = useCallback(
    (move: (current: ResolvedFormatBar) => ResolvedFormatBar | null) => {
      if (!locked) { save(move); return; }
      setDraft((current) => move(current ?? saved) ?? stockFormatBar());
    },
    [locked, save, saved],
  );

  // The purchase landed while a draft was waiting: it becomes the layout.
  useEffect(() => {
    if (locked || !draft) return;
    save(() => draft);
    setDraft(null);
  }, [locked, draft, save]);

  const onKeep = useCallback(() => {
    handoff.current = true;
    onOpenUpgrade();
  }, [onOpenUpgrade]);
  const onDiscard = useCallback(() => setDraft(null), []);
  // The drop waits a microtask and needs no board mounted, so a remount
  // (development mode mounts every effect twice) never counts as leaving.
  const mounted = useRef(0);
  const onEnter = useCallback(() => {
    mounted.current += 1;
    handoff.current = false;
  }, []);
  const onLeave = useCallback(() => {
    mounted.current -= 1;
    queueMicrotask(() => {
      if (mounted.current === 0 && !handoff.current) setDraft(null);
    });
  }, []);

  const formatBarBoard = useMemo(
    () => ({
      layout: locked && draft ? draft : drawn,
      onUpdate,
      position,
      onPositionChange: setPosition,
      locked,
      previewing: locked && draft !== null,
      onKeep,
      onDiscard,
      onEnter,
      onLeave,
    }),
    [locked, draft, drawn, onUpdate, position, setPosition, onKeep, onDiscard, onEnter, onLeave],
  );

  return { formatBarContext, formatBarBoard };
}
