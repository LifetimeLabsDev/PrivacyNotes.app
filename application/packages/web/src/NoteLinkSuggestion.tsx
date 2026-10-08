/**
 * Wiki-link autocomplete dropdown.
 *
 * Renders a floating list of note titles filtered by the user's query.
 * Triggered when the user types `[[` in the editor. Arrow keys navigate,
 * Enter/click selects, Escape dismisses.
 *
 * A `#` after a note name switches the list to that note's headings, and
 * `[[#` lists the headings of the open note, so the list only grows by a
 * note's headings when the user asks for them. A note behind a closed lock
 * lists none: its headings are its content.
 *
 * Uses @tiptap/suggestion under the hood. The dropdown is a plain DOM
 * element positioned via clientRect - no portal, no React context needed.
 */

import { ReactRenderer } from '@tiptap/react';
import Suggestion, { type SuggestionOptions, type SuggestionProps, type SuggestionKeyDownProps } from '@tiptap/suggestion';
import {
  forwardRef,
  useEffect,
  useImperativeHandle,
  useRef,
  useState,
} from 'react';
import { useTranslation } from 'react-i18next';
import i18n from './i18n';
import type { Editor, Range } from '@tiptap/core';
import { PluginKey, type EditorState } from '@tiptap/pm/state';
import { textMatcher } from './textMatch';
import { noteLinkKey, noteLinkTarget, resolveNoteLinkMatches } from './noteLinks';
import { headingsFromDoc, uniqueHeadings, type NoteHeadingsAnswer } from './noteHeadings';

/* ------------------------------------------------------------------ */
/* Note titles provider - set from NotesView                          */
/* ------------------------------------------------------------------ */

const TITLES_KEY = '__wikiLinkNoteTitles';

export type NoteTitleEntry = { id: string; title: string };

/** Call from NotesView to pass the current note titles into the extension. */
export function setWikiLinkNoteTitles(
  // `storage: unknown`: TipTap 3 types editor.storage as an interface without
  // an index signature, so a Record parameter no longer matches structurally.
  editor: { storage: unknown } | null,
  titles: NoteTitleEntry[],
) {
  if (!editor) return;
  const store = (editor.storage as Record<string, Record<string, unknown>>).wikiLink;
  if (store) store[TITLES_KEY] = titles;
}

/** Read note titles from extension storage. */
function getNoteTitles(editor: { storage: unknown }): NoteTitleEntry[] {
  return (wikiLinkStore(editor)?.[TITLES_KEY] as NoteTitleEntry[] | undefined) ?? [];
}

function wikiLinkStore(editor: { storage: unknown }): Record<string, unknown> | undefined {
  return (editor.storage as Record<string, Record<string, unknown>>).wikiLink;
}

/* ------------------------------------------------------------------ */
/* Headings of a link's note - also set from NotesView                */
/* ------------------------------------------------------------------ */

const CURRENT_KEY = '__wikiLinkCurrentNote';
const HEADINGS_KEY = '__wikiLinkHeadingsOf';

/** Call from the host: the open note, and how to read another note's
 *  headings. A host that cannot read them (a Markdown folder, whose files
 *  are read from disk on demand) passes none, and only the open note
 *  offers its headings. */
export function setWikiLinkNoteContext(
  editor: { storage: unknown } | null,
  current: NoteTitleEntry | null,
  headingsOf?: (id: string) => NoteHeadingsAnswer,
) {
  if (!editor) return;
  const store = wikiLinkStore(editor);
  if (!store) return;
  store[CURRENT_KEY] = current;
  store[HEADINGS_KEY] = headingsOf;
}

/** The note open in this editor, as a link names it. */
export function getWikiLinkCurrentNote(editor: { storage: unknown }): NoteTitleEntry | null {
  return (wikiLinkStore(editor)?.[CURRENT_KEY] as NoteTitleEntry | null | undefined) ?? null;
}

const hasNoteCache = new WeakMap<NoteTitleEntry[], (name: string) => boolean>();

/** Whether a name is a note title, for `parseNoteLinkTarget`. */
export function wikiLinkHasNote(editor: { storage: unknown }): (name: string) => boolean {
  const titles = getNoteTitles(editor);
  let fn = hasNoteCache.get(titles);
  if (!fn) {
    const keys = new Set(titles.map((e) => noteLinkKey(e.title)));
    fn = (name: string) => !!name && keys.has(noteLinkKey(name));
    hasNoteCache.set(titles, fn);
  }
  return fn;
}

/** The one note a link's note part names ('' is the open note), or null. */
export function resolveWikiLinkNote(editor: { storage: unknown }, note: string): NoteTitleEntry | null {
  if (!note) return getWikiLinkCurrentNote(editor);
  const matches = resolveNoteLinkMatches(getNoteTitles(editor), note);
  return matches.length === 1 ? matches[0]! : null;
}

/** The headings a link into `entry` can name, one row per text, or null
 *  when the host cannot read that note. The open note answers from the live
 *  document rather than its last saved body. */
export function wikiLinkHeadings(
  editor: { storage: unknown; state: { doc: Parameters<typeof headingsFromDoc>[0] } },
  entry: NoteTitleEntry,
): NoteHeadingsAnswer | null {
  if (entry.id === getWikiLinkCurrentNote(editor)?.id) {
    return uniqueHeadings(headingsFromDoc(editor.state.doc));
  }
  const headingsOf = wikiLinkStore(editor)?.[HEADINGS_KEY] as ((id: string) => NoteHeadingsAnswer) | undefined;
  if (!headingsOf) return null;
  const found = headingsOf(entry.id);
  return found === 'locked' ? found : uniqueHeadings(found);
}

/* ------------------------------------------------------------------ */
/* Suggestion list component                                          */
/* ------------------------------------------------------------------ */

interface SuggestionListRef {
  onKeyDown: (props: SuggestionKeyDownProps) => boolean;
}

/**
 * One row of the list. A `note` row inserts that note; a `heading` row
 * inserts `[[Note#Heading]]`; an `info` row says why a note lists no
 * headings and inserts nothing of its own.
 */
type SuggestionItem =
  | { kind: 'note'; id: string; title: string }
  | { kind: 'heading'; id: string; title: string; level: number; target: string; note: string }
  | { kind: 'info'; id: string; title: string; note: string };

interface SuggestionListProps {
  items: SuggestionItem[];
  query: string;
  command: (item: { target: string }) => void;
}

const SuggestionList = forwardRef<SuggestionListRef, SuggestionListProps>(
  ({ items, query, command }, ref) => {
    const { t } = useTranslation('editor');
    const [selectedIndex, setSelectedIndex] = useState(0);
    const listRef = useRef<HTMLDivElement | null>(null);

    // Reset selection when items change
    useEffect(() => setSelectedIndex(0), [items]);

    // Scroll selected item into view
    useEffect(() => {
      const el = listRef.current?.querySelector('[data-selected="true"]');
      el?.scrollIntoView({ block: 'nearest' });
    }, [selectedIndex]);

    const headingMode = items.length > 0 && items[0]!.kind !== 'note';
    const pick = (item: SuggestionItem | undefined) => {
      if (item?.kind === 'note') command({ target: item.title });
      else if (item?.kind === 'heading') command({ target: item.target });
      else if (query.trim()) command({ target: query.trim() });
    };

    useImperativeHandle(ref, () => ({
      onKeyDown: ({ event }: SuggestionKeyDownProps) => {
        if (event.key === 'ArrowUp') {
          event.preventDefault();
          setSelectedIndex((i) => (i <= 0 ? items.length - 1 : i - 1));
          return true;
        }
        if (event.key === 'ArrowDown') {
          event.preventDefault();
          setSelectedIndex((i) => (i >= items.length - 1 ? 0 : i + 1));
          return true;
        }
        if (event.key === 'Enter') {
          event.preventDefault();
          pick(items[selectedIndex]);
          return true;
        }
        if (event.key === 'Escape') {
          return true; // let suggestion plugin handle dismiss
        }
        return false;
      },
    }));

    const showCreate = !headingMode && query.trim() && !items.some(
      (i) => i.title.toLowerCase() === query.trim().toLowerCase()
    );

    if (items.length === 0 && !showCreate) {
      return (
        <div className="z-50 w-64 rounded-lg border border-divider bg-surface-2 shadow-lg overflow-hidden">
          <div className="px-3 py-2 text-sm text-pn-muted">
            {t('noteLinkSuggestion.noMatches')}
          </div>
        </div>
      );
    }

    if (headingMode) {
      const first = items[0]!;
      const filter = query.slice(query.indexOf('#') + 1);
      const top = Math.min(...items.map((i) => (i.kind === 'heading' ? i.level : 1)));
      return (
        <div
          ref={listRef}
          className="z-50 w-72 max-h-64 overflow-y-auto rounded-lg border border-divider bg-surface-2 shadow-lg"
        >
          <div className="px-3 pt-2 pb-1 text-xs text-pn-muted truncate" dir="auto">
            {t('noteLinkSuggestion.headingsIn', { title: 'note' in first ? first.note : '' })}
          </div>
          {items.map((item, index) =>
            item.kind === 'heading' ? (
              <button
                key={item.id}
                type="button"
                data-selected={index === selectedIndex}
                onClick={() => pick(item)}
                onMouseEnter={() => setSelectedIndex(index)}
                style={{ paddingInlineStart: `${12 + (item.level - top) * 12}px` }}
                className={`w-full text-start pe-3 py-1.5 text-sm truncate transition ${
                  index === selectedIndex
                    ? 'bg-accent/10 text-accent-strong dark:bg-accent/20'
                    : 'text-pn hover:bg-pn/5'
                }`}
              >
                {highlightMatch(item.title, filter)}
              </button>
            ) : (
              <div key={item.id} className="px-3 py-2 text-sm text-pn-muted">
                {item.title}
              </div>
            ),
          )}
        </div>
      );
    }

    return (
      <div
        ref={listRef}
        className="z-50 w-72 max-h-64 overflow-y-auto rounded-lg border border-divider bg-surface-2 shadow-lg"
      >
        {items.map((item, index) => (
          <button
            key={item.id}
            type="button"
            data-selected={index === selectedIndex}
            onClick={() => pick(item)}
            onMouseEnter={() => setSelectedIndex(index)}
            className={`w-full text-start px-3 py-2 text-sm truncate transition ${
              index === selectedIndex
                ? 'bg-accent/10 text-accent-strong dark:bg-accent/20'
                : 'text-pn hover:bg-pn/5'
            }`}
          >
            {highlightMatch(item.title, query)}
          </button>
        ))}
        {showCreate && (
          <>
            {items.length > 0 && (
              <div className="border-t border-divider" />
            )}
            <button
              type="button"
              data-selected={selectedIndex === items.length}
              onClick={() => command({ target: query.trim() })}
              onMouseEnter={() => setSelectedIndex(items.length)}
              className={`w-full text-start px-3 py-2 text-sm transition ${
                selectedIndex === items.length
                  ? 'bg-accent/10 text-accent-strong dark:bg-accent/20'
                  : 'text-pn-muted hover:bg-pn/5'
              }`}
            >
              {t('noteLinkSuggestion.create', { query: query.trim() })}
            </button>
          </>
        )}
      </div>
    );
  }
);
SuggestionList.displayName = 'SuggestionList';

/** Highlight the matching part of a title, at the matcher's own offsets. */
function highlightMatch(title: string, query: string) {
  if (!query.trim()) return title;
  const match = textMatcher(query)(title);
  if (!match) return title;
  return (
    <>
      {title.slice(0, match.start)}
      <span className="font-semibold text-accent">
        {title.slice(match.start, match.end)}
      </span>
      {title.slice(match.end)}
    </>
  );
}

/* ------------------------------------------------------------------ */
/* Suggestion plugin config                                           */
/* ------------------------------------------------------------------ */

/**
 * `[[` in code is text: a code block holds no note-link, and a shell
 * character class such as `[[:space:]]` is not one.
 */
export function allowNoteLinkSuggestion(state: EditorState, from: number): boolean {
  if (state.doc.resolve(from).parent.type.spec.code) return false;
  return !state.doc.nodeAt(from)?.marks.some((m) => m.type.spec.code);
}

/**
 * Build the suggestion plugin options for the WikiLink extension.
 * Called from WikiLink.addProseMirrorPlugins().
 */
export function wikiLinkSuggestion(editor: Editor): ReturnType<typeof Suggestion> {
  const options: SuggestionOptions<SuggestionItem, { target: string }> = {
    pluginKey: new PluginKey('wikiLinkSuggestion'),
    editor,
    char: '[[',
    allowSpaces: true,
    // Allow [[ at start of line (no prefix required) and after whitespace
    allowedPrefixes: null,
    allow: ({ state, range }) => allowNoteLinkSuggestion(state, range.from),

    items: ({ query }) => {
      const headings = headingItems(editor, query);
      if (headings) return headings;
      const titles = getNoteTitles(editor);
      const asItem = (e: NoteTitleEntry): SuggestionItem => ({ kind: 'note', id: e.id, title: e.title });
      if (!query) return titles.slice(0, 20).map(asItem);
      return ranked(titles, query, (e) => e.title).slice(0, 20).map(asItem);
    },

    command: ({ editor: ed, range, props }) => {
      const nodeType = ed.schema.nodes.wikiLink;
      if (!nodeType) return;
      ed.chain()
        .focus()
        .deleteRange(range)
        .insertContent({ type: 'wikiLink', attrs: { target: props.target, label: null } })
        .run();
    },

    render: () => {
      let component: ReactRenderer<SuggestionListRef> | null = null;
      let popup: HTMLDivElement | null = null;
      let blurHandler: (() => void) | null = null;
      // Escape means "no dropdown for the rest of this [[", so the list must
      // stay away until the run ends. A lost focus means nothing of the kind,
      // and the two teardowns are otherwise identical, so they are told apart
      // here rather than in cleanup().
      let dismissed = false;

      return {
        onStart(props: SuggestionProps<SuggestionItem, { target: string }>) {
          dismissed = false;
          mount(props);
        },

        onUpdate(props: SuggestionProps<SuggestionItem, { target: string }>) {
          // The suggestion stays active across a lost focus while the dropdown
          // does not, so an update can arrive with nothing on screen. It has to
          // be rebuilt, not re-propped: on Android a backspace blurs and
          // refocuses the editor to keep the virtual keyboard up, which
          // otherwise leaves the note titles gone for the rest of the [[ run
          // and the user typing into a list that never answers.
          if (!component && !dismissed) {
            mount(props);
            return;
          }

          component?.updateProps({
            items: props.items,
            query: props.query,
            command: props.command,
          });

          if (popup) updatePosition(popup, props.clientRect);
        },

        onKeyDown(props: SuggestionKeyDownProps) {
          if (props.event.key === 'Escape') {
            dismissed = true;
            cleanup();
            return true;
          }
          return component?.ref?.onKeyDown(props) ?? false;
        },

        onExit() {
          dismissed = false;
          cleanup();
        },
      };

      function mount(props: SuggestionProps<SuggestionItem, { target: string }>) {
        component = new ReactRenderer(SuggestionList, {
          props: {
            items: props.items,
            query: props.query,
            command: props.command,
          },
          editor: props.editor,
        });

        popup = document.createElement('div');
        popup.style.position = 'absolute';
        popup.style.zIndex = '9999';
        // Prevent mousedown inside the popup from stealing focus from the
        // editor - without this, focusout fires before the click handler
        // can run, destroying the popup and swallowing the selection.
        popup.addEventListener('mousedown', (e) => e.preventDefault());
        popup.appendChild(component.element);
        document.body.appendChild(popup);

        updatePosition(popup, props.clientRect);

        // Dismiss popup when editor loses focus (e.g. modal opens on top)
        const editorDom = props.editor.view.dom;
        blurHandler = () => cleanup();
        editorDom.addEventListener('focusout', blurHandler);
      }

      function cleanup() {
        if (blurHandler) {
          editor.view.dom.removeEventListener('focusout', blurHandler);
          blurHandler = null;
        }
        component?.destroy();
        component = null;
        if (popup) {
          popup.remove();
          popup = null;
        }
      }
    },
  };

  return Suggestion(options);
}

/**
 * The best rank first, then the given order, so an entry that starts with
 * the query is never pushed past a cap by one that holds it inside a word.
 * Array sort is stable.
 */
function ranked<T>(list: readonly T[], query: string, text: (item: T) => string): T[] {
  const match = textMatcher(query);
  return list
    .map((item) => ({ item, rank: match(text(item))?.rank ?? 0 }))
    .filter((r) => r.rank > 0)
    .sort((a, b) => b.rank - a.rank)
    .map((r) => r.item);
}

/**
 * The heading rows for a query such as `Recipes#br` or `#br`, or null when
 * the query is still a note name. A title that starts with the whole query
 * keeps the note list, so `C# t` still finds the note "C# tips".
 */
function headingItems(editor: Editor, query: string): SuggestionItem[] | null {
  if (!query.includes('#')) return null;
  const match = textMatcher(query);
  if (getNoteTitles(editor).some((e) => match(e.title)?.start === 0)) return null;
  // From the right, so the longest note name wins, as a click resolves it.
  for (let i = query.lastIndexOf('#'); i >= 0; i = i > 0 ? query.lastIndexOf('#', i - 1) : -1) {
    const notePart = query.slice(0, i).trim();
    const entry = resolveWikiLinkNote(editor, notePart);
    if (!entry) continue;
    const note = entry.title;
    const answer = wikiLinkHeadings(editor, entry);
    if (answer === null) return null;
    if (answer === 'locked') {
      return [{ kind: 'info', id: 'locked', title: i18n.t('editor:noteLink.headingsLocked'), note }];
    }
    if (answer.length === 0) {
      return [{ kind: 'info', id: 'none', title: i18n.t('editor:noteLink.noHeadings'), note }];
    }
    const filter = query.slice(i + 1);
    const shown = filter.trim() ? ranked(answer, filter, (h) => h.text) : answer;
    if (shown.length === 0) {
      return [{ kind: 'info', id: 'nomatch', title: i18n.t('editor:noteLinkSuggestion.noHeadingMatches'), note }];
    }
    const prefix = notePart ? noteLinkTarget(note) : '';
    return shown.slice(0, 50).map((h, n) => ({
      kind: 'heading',
      id: `h${n}`,
      title: h.text,
      level: h.level,
      target: `${prefix}#${noteLinkTarget(h.text)}`,
      note,
    }));
  }
  return null;
}

/** Position the popup below the cursor using the clientRect from suggestion. */
function updatePosition(
  popup: HTMLDivElement,
  clientRect?: (() => DOMRect | null) | null,
) {
  if (!clientRect) return;
  const rect = clientRect();
  if (!rect) return;

  const top = rect.bottom + window.scrollY + 4;
  const left = rect.left + window.scrollX;

  popup.style.top = `${top}px`;
  popup.style.left = `${left}px`;

  // Keep the popup from going off the right edge
  requestAnimationFrame(() => {
    const popupRect = popup.getBoundingClientRect();
    if (popupRect.right > window.innerWidth - 8) {
      popup.style.left = `${window.innerWidth - popupRect.width - 8}px`;
    }
  });
}
