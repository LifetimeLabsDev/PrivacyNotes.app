import { hasPin } from './pin';
import { proUnlocked } from './demo';
import type { LocalNote } from './db';

/**
 * Which upgrade pitch the modal opens on. Wider than the four triggers the
 * guards below raise, because it is the same prop the "..." menu declares
 * and both surfaces are wired from one object.
 */
type NoteUpgradeTrigger = 'lock' | 'protect' | 'history' | 'devices' | 'folders' | null;

export type NoteActionGuardDeps = {
  note: LocalNote;
  isPro: boolean;
  onSetLocked: (locked: boolean) => void;
  onSetPinProtected: (protectedOn: boolean) => void;
  /** Turning protection OFF passes the same check as opening the note. The
   *  caller opens the gate, which does the asking and the removing. */
  onRequestRemoveProtection: () => void;
  onOpenUpgrade: (trigger: NoteUpgradeTrigger) => void;
  onOpenHistory?: () => void;
  /** Open Security > PIN so the user can set a PIN before protecting a note. */
  onSetPin?: () => void;
  onMoveToFolder?: () => void;
  /**
   * Dismiss the surface these buttons live on, where a flow replaces it.
   * The "..." menu closes itself; the header row passes a no-op, because
   * the row stays on screen behind the modal it opens.
   */
  onClose: () => void;
};

/**
 * The Pro and PIN checks in front of four per-note actions.
 *
 * Two surfaces run them: the "..." options menu and the editor header's
 * icon row. They must behave identically, and the PIN check is a security
 * boundary rather than a nicety, so there is one copy of it.
 *
 * Every gate here is `proUnlocked`, so the public demo can exercise all
 * four - note history included, via its local demo snapshot path
 * (noteVersions.ts).
 * Spec: ops/docs/pro-features.md (of these four, only history is server-enforced via RLS)
 */
export function noteActionGuards(d: NoteActionGuardDeps) {
  const unlocked = proUnlocked(d.isPro);

  return {
    toggleLock() {
      if (!unlocked) {
        d.onOpenUpgrade('lock');
        return;
      }
      d.onSetLocked(d.note.locked !== 1);
    },

    toggleProtect() {
      if (!unlocked) {
        d.onOpenUpgrade('protect');
        return;
      }
      if (d.note.pinProtected === 1) {
        d.onRequestRemoveProtection();
        return;
      }
      // There is nothing to protect a note with until a PIN exists.
      if (!hasPin()) {
        d.onClose();
        d.onSetPin?.();
        return;
      }
      d.onSetPinProtected(true);
    },

    openHistory() {
      if (!unlocked) {
        d.onOpenUpgrade('history');
        return;
      }
      d.onOpenHistory?.();
    },

    moveToFolder() {
      if (!unlocked) {
        d.onOpenUpgrade('folders');
        return;
      }
      d.onMoveToFolder?.();
      d.onClose();
    },
  };
}

export type BulkActionGuardDeps = {
  isPro: boolean;
  /** True when every item in the selection already has the flag on. It is
   *  what decides the direction, the same way one note's own flag does. */
  allLocked: boolean;
  allProtected: boolean;
  onSetLocked: (locked: boolean) => void;
  onSetPinProtected: (protectedOn: boolean) => void;
  /** Taking protection off a selection asks for the PIN once, then applies
   *  it to all of them. A single note gets its own screen instead. */
  onRequestRemoveProtection: () => void;
  onOpenUpgrade: (trigger: NoteUpgradeTrigger) => void;
  onSetPin?: () => void;
  onClose: () => void;
};

/**
 * The same two gates for a whole selection.
 *
 * It sits beside its single-note twin on purpose: the checks are a Pro
 * boundary and a PIN boundary, and a reader comparing the two functions
 * must be able to see at a glance that they ask for the same things in
 * the same order. A selection that could protect or unlock items the
 * single path refuses would be a hole, not a shortcut.
 * Spec: ops/docs/pro-features.md
 */
export function bulkActionGuards(d: BulkActionGuardDeps) {
  const unlocked = proUnlocked(d.isPro);

  return {
    toggleLock() {
      if (!unlocked) {
        d.onOpenUpgrade('lock');
        return;
      }
      d.onSetLocked(!d.allLocked);
    },

    toggleProtect() {
      if (!unlocked) {
        d.onOpenUpgrade('protect');
        return;
      }
      if (d.allProtected) {
        d.onRequestRemoveProtection();
        return;
      }
      // There is nothing to protect a note with until a PIN exists.
      if (!hasPin()) {
        d.onClose();
        d.onSetPin?.();
        return;
      }
      d.onSetPinProtected(true);
    },
  };
}
