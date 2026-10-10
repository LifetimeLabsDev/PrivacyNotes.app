import React from 'react';
import type { NoteRowProps } from './NoteRow';
import { noteItemState, noteRootProps, useNoteItem } from './NoteRow';
import { ItemTile } from './listItem';

/**
 * The grid tile of a note: the item `NoteRow` shows, laid out by `ItemTile`.
 * Both build the item through `useNoteItem`, so the row and the tile cannot
 * disagree about a part; `tests/listItemParity.test.ts` holds them together.
 * Shares NoteRowProps so a list can render either one with the same handlers.
 *
 * React.memo mirrors NoteRow: unchanged notes keep object identity and skip
 * the render on every keystroke - critical for large vaults.
 */
export default React.memo(function NoteCard(props: NoteRowProps) {
  const item = useNoteItem(props);
  return (
    <ItemTile
      item={item}
      state={noteItemState(props)}
      rootProps={noteRootProps(props)}
      onToggleSelect={props.onToggleSelect}
      trailing={props.trailing}
    />
  );
});
