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
