import type { NoteType } from '@notes/shared';

/**
 * What each note type's body holds: markdown the editor writes, or a JSON
 * document a form owns (a bookmark's `{url}`, a contact, a login, a card, an
 * SSH key). Keyed by the whole `NoteType` union, so a type added to it does
 * not build until it is placed here.
 */
const BODY_KIND: Record<NoteType, 'markdown' | 'form'> = {
  note: 'markdown',
  task: 'markdown',
  journal: 'markdown',
  file: 'markdown',
  link: 'form',
  contact: 'form',
  login: 'form',
  card: 'form',
  'ssh-key': 'form',
};

/** The markdown pillars: the note types whose body the editor writes. */
export const MARKDOWN_NOTE_TYPES: readonly NoteType[] = (Object.keys(BODY_KIND) as NoteType[])
  .filter((type) => BODY_KIND[type] === 'markdown');

/**
 * Whether this build knows the note type. A newer build can add a pillar, and
 * its items reach this one through sync with their type intact; the editor
 * pane opens such an item as a notice, because this build cannot read its
 * body. A row with no type is a plain note.
 */
export function isKnownNoteType(type: string | undefined): boolean {
  return Object.hasOwn(BODY_KIND, type ?? 'note');
}

/**
 * The types an item can be converted to from the "..." menu. A file is a
 * source and never a target: its body holds one attachment that the editor
 * draws as a file card, and a note with none or several has no such card.
 * Spec: ops/docs/plans/convert-type.md
 */
export const CONVERT_TARGETS = ['note', 'task', 'journal'] as const;
export type ConvertTarget = (typeof CONVERT_TARGETS)[number];

/** Whether the "..." menu offers Convert to: the editor writes the body. */
export function isConvertSource(type: string | undefined): boolean {
  const kind = BODY_KIND[(type ?? 'note') as NoteType];
  return kind === 'markdown';
}

/**
 * The patch that converts an item. Only `type` changes and no field is
 * removed, so converting back restores the item. An item that becomes a
 * journal entry with no entry date takes `today` (a local ISO day), because
 * the fallback, the UTC day of createdAt, would file its tracker values
 * under the day the item was made.
 */
export function convertPatch(
  trackers: Record<string, unknown> | undefined,
  target: ConvertTarget,
  today: string,
): { type: ConvertTarget; trackers?: Record<string, unknown> } {
  const existing = trackers ?? {};
  return target === 'journal' && typeof existing.journalDate !== 'string'
    ? { type: target, trackers: { ...existing, journalDate: today } }
    : { type: target };
}
