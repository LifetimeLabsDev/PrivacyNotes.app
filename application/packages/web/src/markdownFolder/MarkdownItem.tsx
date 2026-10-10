import React from 'react';
import type { NoteRowProps } from '../NoteRow';
import { CardGlyph, noteItemState, noteRootProps, useNoteItem } from '../NoteRow';
import { ItemRow, ItemTile, applyCompactRows } from '../listItem';
import { FileMd, FileTxt } from '../icons';
import { useCompactRows } from '../viewMode';

/**
 * A Markdown or text file as a list item. The file is adapted into a note's
 * shape (`entryToNote`), so the note adapter derives its title, preview and
 * date; this one replaces what a note would get wrong. The type says 'note',
 * so the icon and the mini glyph name the extension instead, because that is
 * the one thing about a row the filename stem does not say: `notes.md` and
 * `notes.txt` would be two identical rows without it. The size comes from the
 * filesystem, not from attachment references in a body.
 */
export default React.memo(function MarkdownItem(
  props: NoteRowProps & { grid: boolean; text: boolean; size: string | null },
) {
  const base = useNoteItem(props);
  const compactRows = useCompactRows();
  const Glyph = props.text ? FileTxt : FileMd;
  // Compact rows again, after the icon and glyph of our own, which they drop.
  const item = applyCompactRows({
    ...base,
    icon: (
      <span className="shrink-0 w-7 h-7 rounded-lg bg-accent/10 flex items-center justify-center text-accent-strong">
        <Glyph size={18} />
      </span>
    ),
    glyph: <CardGlyph type="note" override={Glyph} />,
    size: props.size ?? base.size,
  }, compactRows);
  const Layout = props.grid ? ItemTile : ItemRow;
  return (
    <Layout
      item={item}
      state={noteItemState(props)}
      rootProps={noteRootProps(props)}
      onToggleSelect={props.onToggleSelect}
    />
  );
});
