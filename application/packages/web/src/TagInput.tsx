import {
  createPortal,
  flushSync,
} from 'react-dom';
import {
  forwardRef,
  useCallback,
  useEffect,
  useImperativeHandle,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactNode,
} from 'react';
import { useTranslation } from 'react-i18next';
import { normalizeTag, sortTags, TAG_MAX_LENGTH } from './notesRepo';
import { textMatcher } from './textMatch';
import { isImeComposing } from './imeComposing';
import { useIsMobile } from './useIsMobile';
import { useTheme } from './theme';
import { TagMark } from './looks/LookGlyph';

type Props = {
  tags: string[];
  onChange: (tags: string[]) => void;
  /** All existing tags with note counts, for auto-suggest. */
  allTags?: [string, number][];
  /**
   * Called when the user presses Tab (forward) from the tag input with no
   * pending draft left to commit. Parent uses this to move focus into the
   * editor body so title → tags → body flows naturally.
   */
  onTabOut?: () => void;
  /**
   * Optional element rendered at the right end of the tag row. Used to host
   * the formatting-toolbar Hide/Show toggle so it sits inline with the tags
   * instead of overlapping the note body.
   */
  trailing?: ReactNode;
  /**
   * Optional element rendered at the left end of the tag row, as the first
   * item INSIDE the horizontal scroll region. Hosts the folder chip (Pro
   * folders), which therefore scrolls away with the tags instead of
   * covering them.
   */
  leading?: ReactNode;
};

export type TagInputHandle = {
  focus: () => void;
};

const MAX_SUGGESTIONS = 5;

export const TagInput = forwardRef<TagInputHandle, Props>(function TagInput(
  { tags, onChange, allTags, onTabOut, trailing, leading },
  ref
) {
  const { t } = useTranslation('common');
  const [draft, setDraft] = useState('');
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [highlightIndex, setHighlightIndex] = useState(-1);
  const [dropdownPos, setDropdownPos] = useState<{ top: number; left: number; width: number } | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const blurTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const isMobile = useIsMobile();
  const { spellcheck } = useTheme();

  // The chip strip scrolls horizontally instead of wrapping. Keep the
  // input (always the right-most element) in view when a tag is ADDED,
  // so typing several tags in a row never pushes the caret off-screen.
  // The caret is what this follows, not the new chip: the chips sort
  // alphabetically, so a fresh tag lands wherever its name puts it.
  // Only a growing count scrolls: on a phone the trailing toolbar leaves
  // the strip narrow, so scrolling to the end when a note opens hid every
  // tag the note already had, and the folder chip with them. A count
  // comparison rather than a mounted flag, because StrictMode invokes the
  // effect twice on mount and a flag would let the second run scroll.
  const prevTagCount = useRef(tags.length);
  useEffect(() => {
    const grew = tags.length > prevTagCount.current;
    prevTagCount.current = tags.length;
    if (!grew) return;
    const el = scrollRef.current;
    if (el) el.scrollLeft = el.scrollWidth;
  }, [tags.length]);

  useImperativeHandle(
    ref,
    () => ({
      focus: () => inputRef.current?.focus(),
    }),
    []
  );

  // The row draws the tags alphabetically, whatever order they were typed
  // in. Every position-based thing below reads THIS array rather than the
  // `tags` prop, so the chip a user sees last is the chip Backspace takes.
  const shown = useMemo(() => sortTags(tags), [tags]);

  // Suggestions that start with the draft (rank 3 of the one matcher, so
  // "sec" suggests "Sécurité"), excluding tags already on this note.
  const suggestions = useMemo(() => {
    if (!allTags || draft.length === 0) return [];
    const match = textMatcher(draft.replace(/^#/, ''));
    const currentLower = new Set(tags.map((t) => t.toLowerCase()));
    return allTags
      .filter(([t]) => !currentLower.has(t.toLowerCase()) && match(t)?.rank === 3)
      .sort((a, b) => b[1] - a[1]) // most-used first
      .slice(0, MAX_SUGGESTIONS);
  }, [allTags, draft, tags]);

  // Whether the "Create" row should appear.
  const normalizedDraft = normalizeTag(draft);
  const normalizedLower = normalizedDraft.toLowerCase();
  const showCreate = normalizedDraft
    && !tags.some((t) => t.toLowerCase() === normalizedLower)
    && !suggestions.some(([t]) => t.toLowerCase() === normalizedLower);

  // Total rows in dropdown (suggestions + optional create).
  const totalRows = suggestions.length + (showCreate ? 1 : 0);
  const hasDropdown = showSuggestions && totalRows > 0;

  // Update dropdown position from the input element's bounding rect.
  const updatePosition = useCallback(() => {
    if (!inputRef.current) return;
    const rect = inputRef.current.getBoundingClientRect();
    setDropdownPos({
      top: rect.bottom + 4,
      left: rect.left,
      width: 0, // unused - width is intrinsic via min/max
    });
  }, []);

  // Reposition on scroll/resize while open.
  useEffect(() => {
    if (!hasDropdown) return;
    updatePosition();
    window.addEventListener('scroll', updatePosition, true);
    window.addEventListener('resize', updatePosition);
    return () => {
      window.removeEventListener('scroll', updatePosition, true);
      window.removeEventListener('resize', updatePosition);
    };
  }, [hasDropdown, updatePosition]);

  function openSuggestions() {
    setShowSuggestions(true);
    setHighlightIndex(-1);
    updatePosition();
  }

  function closeSuggestions() {
    setShowSuggestions(false);
    setHighlightIndex(-1);
  }

  /** Case-insensitive check: does this note already have a tag matching `t`? */
  function hasTag(t: string): boolean {
    const lower = t.toLowerCase();
    return tags.some((x) => x.toLowerCase() === lower);
  }

  function selectTag(tag: string) {
    if (hasTag(tag)) return;
    onChange([...tags, tag]);
    setDraft('');
    closeSuggestions();
    inputRef.current?.focus();
  }

  function commit() {
    const t = normalizeTag(draft);
    setDraft('');
    closeSuggestions();
    if (!t) return;
    if (hasTag(t)) return;
    onChange([...tags, t]);
  }

  function handleKey(e: KeyboardEvent<HTMLInputElement>) {
    // Space, comma and Enter commit a tag, and each one is also a key the
    // input method uses to convert a reading.
    if (isImeComposing(e)) return;
    // Arrow nav (desktop only).
    if (!isMobile && hasDropdown) {
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setHighlightIndex((i) => (i + 1) % totalRows);
        return;
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault();
        setHighlightIndex((i) => (i - 1 + totalRows) % totalRows);
        return;
      }
      if (e.key === 'Escape') {
        e.preventDefault();
        closeSuggestions();
        return;
      }
    }

    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      // If a suggestion is highlighted, select it.
      if (hasDropdown && highlightIndex >= 0) {
        const hit = suggestions[highlightIndex];
        if (hit) {
          selectTag(hit[0]);
        } else {
          // "Create" row
          commit();
        }
      } else {
        commit();
      }
    } else if (e.key === ' ') {
      // Only treat space as a tag-commit if there's actually draft text.
      // Empty space shouldn't do anything (was eating shift-space etc).
      if (draft.trim() !== '') {
        e.preventDefault();
        commit();
      }
    } else if (e.key === 'Tab' && !e.shiftKey) {
      // Tab → body of the note. Commit any pending draft first so a
      // half-typed tag doesn't get lost.
      e.preventDefault();
      commit();
      onTabOut?.();
    } else if (e.key === 'Backspace' && draft === '') {
      const last = shown[shown.length - 1];
      if (!last) return;
      e.preventDefault();
      remove(last);
    }
  }

  function remove(tag: string) {
    onChange(tags.filter((t) => t !== tag));
  }

  function handleInputChange(value: string) {
    // Mobile keyboards often insert comma/space directly without firing
    // keyDown, so detect delimiters in the incoming value and commit.
    // Also handles paste of "tag1, tag2, tag3".
    if (value.includes(',') || value.includes('#')) {
      const parts = value.split(/[,#]+/).map((s) => normalizeTag(s)).filter(Boolean);
      const existing = new Set(tags.map((t) => t.toLowerCase()));
      const toAdd: string[] = [];
      for (const p of parts) {
        if (!existing.has(p.toLowerCase())) {
          toAdd.push(p);
          existing.add(p.toLowerCase());
        }
      }
      if (toAdd.length > 0) onChange([...tags, ...toAdd]);
      flushSync(() => setDraft(''));
      closeSuggestions();
      return;
    }

    // Space commits the current draft on mobile too (desktop handles via
    // keyDown, but mobile keyboards skip it).
    if (isMobile && value.endsWith(' ') && value.trim() !== '') {
      const t = normalizeTag(value);
      flushSync(() => setDraft(''));
      closeSuggestions();
      if (t && !hasTag(t)) {
        onChange([...tags, t]);
      }
      return;
    }

    flushSync(() => setDraft(value));
    if (value.length > 0) {
      openSuggestions();
    } else {
      closeSuggestions();
    }
  }

  function handleFocus() {
    if (blurTimeoutRef.current) {
      clearTimeout(blurTimeoutRef.current);
      blurTimeoutRef.current = null;
    }
    if (draft.length > 0) openSuggestions();
  }

  function handleBlur() {
    // Delay so click on dropdown suggestion fires before we close.
    const delay = isMobile ? 200 : 150;
    blurTimeoutRef.current = setTimeout(() => {
      commit();
    }, delay);
  }

  // Clean up timeout on unmount.
  useEffect(() => {
    return () => {
      if (blurTimeoutRef.current) clearTimeout(blurTimeoutRef.current);
    };
  }, []);

  // The part of a suggestion the draft matched, in bold. The offsets come
  // from the matcher, because the fold changes lengths ("İ", "ß").
  const prefixMatch = textMatcher(draft.replace(/^#/, ''));
  function boldPrefix(tag: string) {
    const match = prefixMatch(tag);
    if (!match) return tag;
    return (
      <>
        {tag.slice(0, match.start)}
        <span className="font-semibold">{tag.slice(match.start, match.end)}</span>
        {tag.slice(match.end)}
      </>
    );
  }

  // Render the dropdown via portal.

  const dropdown = hasDropdown && dropdownPos
    ? createPortal(
        <div
          className="fixed bg-surface-2 border border-divider rounded-lg overflow-hidden shadow-lg"
          style={{
            top: dropdownPos.top,
            left: dropdownPos.left,
            minWidth: 160,
            maxWidth: 260,
            zIndex: 50,
          }}
          onMouseDown={(e) => e.preventDefault()} // prevent blur
        >
          {suggestions.map(([tag, count], i) => (
            <button
              key={tag}
              type="button"
              onClick={() => selectTag(tag)}
              className={`w-full flex items-center gap-2 px-3 text-sm cursor-pointer transition-colors ${
                i === highlightIndex
                  ? 'bg-neutral-100 dark:bg-neutral-900'
                  : 'hover:bg-neutral-50 dark:hover:bg-neutral-900/50'
              } ${isMobile ? 'min-h-[44px] py-2.5' : 'py-2'}`}
            >
              <span className="text-neutral-400 dark:text-neutral-600 text-xs">#</span>
              <span className="text-pn truncate">{boldPrefix(tag)}</span>
              <span className="ml-auto text-xs text-neutral-400 dark:text-neutral-600 tabular-nums shrink-0">
                {count}
              </span>
            </button>
          ))}
          {showCreate && (
            <>
              {suggestions.length > 0 && (
                <div className="border-t border-divider" />
              )}
              <button
                type="button"
                onClick={() => commit()}
                className={`w-full flex items-center gap-2 px-3 text-sm cursor-pointer transition-colors text-neutral-500 dark:text-neutral-400 ${
                  highlightIndex === suggestions.length
                    ? 'bg-neutral-100 dark:bg-neutral-900'
                    : 'hover:bg-neutral-50 dark:hover:bg-neutral-900/50'
                } ${isMobile ? 'min-h-[44px] py-2.5' : 'py-2'}`}
              >
                <span className="text-xs">+</span>
                <span>{t('tagInput.create', { tag: normalizedDraft })}</span>
              </button>
            </>
          )}
        </div>,
        document.body
      )
    : null;

  return (
    <div
      ref={containerRef}
      className="flex items-center gap-1.5 px-4 sm:px-6 py-2 border-b border-divider shrink-0 min-w-0"
    >
      {/* Single-line chip strip - scrolls horizontally, never wraps. The
          folder chip scrolls WITH the tags rather than staying pinned at
          the left: pinned, it sat over the scroller's left edge, so a tag
          scrolled underneath it and read as cut in half - worst on a phone,
          where the chip and the trailing toolbar leave the strip about
          110px wide. One strip, one scroll position. */}
      <div
        ref={scrollRef}
        className="flex-1 min-w-0 flex flex-nowrap items-center gap-1.5 overflow-x-auto pn-scrollbar-none"
      >
        {leading}
        {/* Hairline between the folder chip and the tags. The folder is the
            one place a note LIVES and the tags are however many labels it
            carries, so the row reads as two zones rather than one strip of
            chips. Only drawn when a leading slot exists. */}
        {leading && <span aria-hidden="true" className="shrink-0 w-px h-4 bg-divider" />}
        {shown.map((tag) => (
          <span
            key={tag}
            /* Accent tint, never raw neutrals: a neutral-200 chip is a COOL
               grey, so on the warm-cream and slate themes it sank into the
               row and the tags read as disabled chrome. The accent token
               follows every theme. Round pills here and a square-cornered
               folder chip in the leading slot are the same split as list vs
               container: many labels vs one location.
               Spec: ops/docs/ui-patterns.md (editor tag row) */
            className="group inline-flex shrink-0 items-center gap-1 text-xs px-2.5 py-0.5 rounded-full bg-accent/10 text-accent hover:bg-accent/20 transition whitespace-nowrap"
            dir="auto"
          >
            <span className="inline-flex items-center">
              <TagMark tag={tag} size={11} />
              {tag}
            </span>
            <button
              onClick={() => remove(tag)}
              className="text-accent/60 hover:text-red-500 dark:hover:text-red-400 transition text-[11px] leading-none"
              aria-label={t('tagInput.removeTag', { tag })}
              tabIndex={-1}
            >
              ×
            </button>
          </span>
        ))}
        <input
          ref={inputRef}
          tabIndex={isMobile ? -1 : undefined}
          value={draft}
          onChange={(e) => handleInputChange(e.target.value)}
          onKeyDown={handleKey}
          onFocus={handleFocus}
          onBlur={handleBlur}
          maxLength={TAG_MAX_LENGTH + 5}
          placeholder={
            tags.length === 0 ? t('tagInput.placeholder') : ''
          }
          enterKeyHint="done"
          autoComplete="off"
          spellCheck={spellcheck ? undefined : false}
          className="flex-1 min-w-[80px] shrink-0 bg-transparent text-xs focus:outline-none placeholder:text-neutral-400 dark:placeholder:text-neutral-600 py-0.5"
        />
      </div>
      {trailing}
      {dropdown}
    </div>
  );
});
