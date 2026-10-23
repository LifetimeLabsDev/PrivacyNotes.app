import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { ArrowsIn, ArrowsOut, FileDashed, Graph, LockSimple } from './icons';
import type { LocalNote } from './db';
import { EditorSlotPanel, SLOT_BADGE, SLOT_PANEL_ROW } from './EditorSlotPill';
import { keyText } from './shortcutMatch';
import { typeGlyph } from './NoteRow';
import { deriveDisplayTitle } from './notesViewUtils';
import { PathGlyph, useItemLook } from './looks/LookGlyph';

/** What the panel lists for the open item (ConnectionsPill works it out). */
export type ConnectionLists = {
  from: LocalNote[];
  to: LocalNote[];
  missing: string[];
  hidden: number;
};

/**
 * One item in the panel, drawn the way the list draws it: its own icon when
 * it has one, else its type's, and its color at the strength the reader
 * chose (a tinted row, or a colored icon). The tint is a background image,
 * so the hover color still shows under it.
 */
function ConnectionRow({ note, title, onOpen }: { note: LocalNote; title: string; onOpen: () => void }) {
  const { iconPaths: paths, row, icon } = useItemLook(note.id, note.tags, note.folderId);
  const { Icon, color } = typeGlyph(note.type);
  const iconClass = `shrink-0 ${icon ? '' : color}`;
  return (
    <li>
      <button
        type="button"
        onClick={onOpen}
        title={title}
        style={row}
        className={`${SLOT_PANEL_ROW} px-2 text-pn-soft`}
      >
        {paths
          ? <PathGlyph paths={paths} size={16} className={iconClass} style={icon} />
          : <Icon size={16} aria-hidden="true" className={iconClass} style={icon} />}
        <span className="truncate" dir="auto">{title}</span>
      </button>
    </li>
  );
}

/**
 * The open Connections panel. A file of its own, loaded the first time a
 * reader opens it: the closed pill is on every note, the panel is not.
 * Spec: ops/issues/0351.md (Spec)
 */
export function ConnectionsPanel({
  lists,
  isNoteLocked,
  onOpen,
  onClose,
}: {
  lists: ConnectionLists;
  isNoteLocked: (n: LocalNote) => boolean;
  onOpen: (n: LocalNote) => void;
  onClose: () => void;
}) {
  const { t } = useTranslation('notes');
  const row = (n: LocalNote) => (
    <ConnectionRow key={n.id} note={n} title={deriveDisplayTitle(n, isNoteLocked(n))} onOpen={() => onOpen(n)} />
  );

  // An empty group is left out. Each group carries its direction three ways
  // at once, so no one has to read a label to tell them apart: a side bar, an
  // arrow icon and a color. In (the notes that link here) is the warm color,
  // out (what this note links to) the accent; both follow the theme.
  const group = (
    label: string,
    GroupIcon: typeof ArrowsIn,
    tone: { bar: string; text: string },
    count: number,
    body: ReactNode,
  ) => count === 0 && !body ? null : (
    <section className={`mx-0.5 border-s-[3px] ${tone.bar}`}>
      <p className="flex items-center gap-2 px-2 pt-1 pb-0.5 text-sm font-semibold text-pn">
        <GroupIcon size={16} weight="bold" aria-hidden="true" className={`shrink-0 ${tone.text}`} />
        {label}
        <span className={`font-normal ${SLOT_BADGE}`}>{count}</span>
      </p>
      {body}
    </section>
  );
  const inTone = { bar: 'border-warning', text: 'text-warning' };
  const outTone = { bar: 'border-accent', text: 'text-accent' };
  const hasIn = lists.from.length + lists.hidden > 0;
  const hasOut = lists.to.length + lists.missing.length > 0;

  return (
    <EditorSlotPanel
      label={t('connections.title')}
      icon={<Graph size={16} />}
      title={t('connections.title')}
      closeLabel={t('connections.hide')}
      closeKeys={keyText('connections')}
      onClose={onClose}
    >
      {group(t('connections.linkedFrom'), ArrowsIn, inTone, lists.from.length, hasIn && (
        <>
          <ul>{lists.from.map(row)}</ul>
          {lists.hidden > 0 && (
            <p className="flex items-center gap-2 px-2 py-1 text-xs text-pn-muted">
              <LockSimple size={14} aria-hidden="true" className="shrink-0" />
              {t('connections.protectedHidden', { count: lists.hidden })}
            </p>
          )}
        </>
      ))}
      {hasIn && hasOut && <div role="separator" className="-mx-1 my-1.5 border-t border-divider" />}
      {group(t('connections.linksTo'), ArrowsOut, outTone, lists.to.length + lists.missing.length, hasOut && (
        <ul>
          {lists.to.map(row)}
          {lists.missing.map((name) => (
            <li key={name} className="flex items-center gap-2 rounded-md px-2 py-1.5 text-sm text-pn-muted">
              <FileDashed size={16} aria-hidden="true" className="shrink-0" />
              <span className="truncate" dir="auto" title={name}>{name}</span>
              <span className="ms-auto shrink-0 text-xs">{t('connections.missing')}</span>
            </li>
          ))}
        </ul>
      ))}
    </EditorSlotPanel>
  );
}
