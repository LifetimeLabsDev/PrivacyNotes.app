/**
 * Wiki-link autocomplete dropdown.
 *
 * Renders a floating list of note titles filtered by the user's query.
 * Triggered when the user types `[[` in the editor. Arrow keys navigate,
 * Enter/click selects, Escape dismisses.
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
import type { Editor, Range } from '@tiptap/core';
import { PluginKey } from '@tiptap/pm/state';

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
function getNoteTitles(editor: Editor): NoteTitleEntry[] {
  const store = (editor.storage as unknown as Record<string, Record<string, unknown>>).wikiLink;
  return (store?.[TITLES_KEY] as NoteTitleEntry[] | undefined) ?? [];
}

/* ------------------------------------------------------------------ */
/* Suggestion list component                                          */
/* ------------------------------------------------------------------ */

interface SuggestionListRef {
  onKeyDown: (props: SuggestionKeyDownProps) => boolean;
}

interface SuggestionListProps {
  items: NoteTitleEntry[];
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
          const item = items[selectedIndex];
          if (item) command({ target: item.title });
          else if (query.trim()) command({ target: query.trim() });
          return true;
        }
        if (event.key === 'Escape') {
          return true; // let suggestion plugin handle dismiss
        }
        return false;
      },
    }));

    const showCreate = query.trim() && !items.some(
      (i) => i.title.toLowerCase() === query.trim().toLowerCase()
    );

    if (items.length === 0 && !showCreate) {
      return (
        <div className="z-50 w-64 rounded-lg border border-divider bg-surface-2 shadow-lg overflow-hidden">
          <div className="px-3 py-2 text-sm text-neutral-400 dark:text-neutral-500">
            {t('noteLinkSuggestion.noMatches')}
          </div>
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
            onClick={() => command({ target: item.title })}
            onMouseEnter={() => setSelectedIndex(index)}
            className={`w-full text-start px-3 py-2 text-sm truncate transition ${
              index === selectedIndex
                ? 'bg-accent/10 text-accent dark:bg-accent/20'
                : 'text-pn hover:bg-neutral-100 dark:hover:bg-neutral-800'
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
                  ? 'bg-accent/10 text-accent dark:bg-accent/20'
                  : 'text-neutral-500 dark:text-neutral-400 hover:bg-neutral-100 dark:hover:bg-neutral-800'
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

/** Highlight the matching substring in a title. */
function highlightMatch(title: string, query: string) {
  if (!query) return title;
  const lower = title.toLowerCase();
  const qLower = query.toLowerCase();
  const idx = lower.indexOf(qLower);
  if (idx < 0) return title;
  return (
    <>
      {title.slice(0, idx)}
      <span className="font-semibold text-accent">
        {title.slice(idx, idx + query.length)}
      </span>
      {title.slice(idx + query.length)}
    </>
  );
}

/* ------------------------------------------------------------------ */
/* Suggestion plugin config                                           */
/* ------------------------------------------------------------------ */

/**
 * Build the suggestion plugin options for the WikiLink extension.
 * Called from WikiLink.addProseMirrorPlugins().
 */
export function wikiLinkSuggestion(editor: Editor): ReturnType<typeof Suggestion> {
  const options: SuggestionOptions<NoteTitleEntry, { target: string }> = {
    pluginKey: new PluginKey('wikiLinkSuggestion'),
    editor,
    char: '[[',
    allowSpaces: true,
    // Allow [[ at start of line (no prefix required) and after whitespace
    allowedPrefixes: null,

    items: ({ query }) => {
      const titles = getNoteTitles(editor);
      if (!query) return titles.slice(0, 20);
      const lower = query.toLowerCase();
      return titles
        .filter((t) => t.title.toLowerCase().includes(lower))
        .slice(0, 20);
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
        onStart(props: SuggestionProps<NoteTitleEntry, { target: string }>) {
          dismissed = false;
          mount(props);
        },

        onUpdate(props: SuggestionProps<NoteTitleEntry, { target: string }>) {
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

      function mount(props: SuggestionProps<NoteTitleEntry, { target: string }>) {
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
