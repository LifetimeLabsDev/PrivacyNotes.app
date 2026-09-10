import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { LocalNote } from './db';
import { parseLinkBody, buildLinkBody, normalizeUrl, linkDomain, duplicateBookmarkId } from './linkBody';
import { SiteChip } from './NoteRow';
import { useCopyToClipboard } from './clipboard';
import { openExternal } from './openExternal';
import { hasPin } from './pin';
import { PinInfoModal } from './PinInfoModal';
import { ArrowSquareOut, CaretDown, Check, Copy, Info } from './icons';

/**
 * The bookmark column, the vault's `VAULT_COLUMN` one size up: the URL row
 * carries a long value plus the Copy and Open buttons, so it needs more room
 * than the vault's label + value pairs. Wider than 720 and the field trails a
 * lane of empty space to the buttons.
 * Spec: ops/docs/ui-patterns.md (the vault column)
 */
const BOOKMARK_COLUMN = 'w-full max-w-[720px]';

/**
 * The bookmark body, seated under the STANDARD note header exactly like
 * VaultItem: the header owns title, pin, share, trash and the options
 * menu (read-only, PIN-protect), the shared tag line owns folder + tags,
 * and this component owns only what a bookmark is - its URL.
 *
 * Edits auto-save through the normal note pipeline (onBodyChange ->
 * useNoteEditing's debounced sync), but ONLY when the value parses as an
 * http(s) URL and no OTHER bookmark already holds it: a half-typed edit
 * shows the red hint, a collision shows the amber one, and neither touches
 * the stored body. The duplicate half is the same guard the quick-add bar
 * runs, against the same account-wide key map - editing a bookmark onto a
 * URL you already have was the one way past it (fixed 2026-08-26).
 * Spec: ops/docs/plans/bookmarks-pillar.md (standard-header rework)
 */
export function BookmarkItem({
  note,
  bookmarkKeys,
  isTrash,
  onBodyChange,
  onPinProtectedChange,
}: {
  note: LocalNote;
  /** Every saved bookmark URL in the account, keyed by dedupe key -> note id
   *  (buildLinkKeyMap). This note's own entry is excluded by id, so re-saving
   *  its own URL is not a collision. */
  bookmarkKeys: Map<string, string>;
  isTrash: boolean;
  onBodyChange: (id: string, body: string) => void;
  onPinProtectedChange: (id: string, pinProtected: boolean) => void;
}) {
  const { t } = useTranslation('shell');
  const { copy, copied } = useCopyToClipboard();
  // Never memoize this. Settings opens over a mounted form, so a PIN
  // can appear or vanish while the toggle below is on screen, and
  // localStorage fires nothing that would refresh a frozen value.
  const pinConfigured = hasPin();
  const [showPinInfo, setShowPinInfo] = useState(false);
  /** The website-icon explainer under the URL field, collapsed by default. */
  const [iconHintOpen, setIconHintOpen] = useState(false);
  const pinProtected = note.pinProtected === 1;
  const savedUrl = parseLinkBody(note.body).url;
  const [draft, setDraft] = useState(savedUrl);
  const [invalid, setInvalid] = useState(false);
  const [duplicate, setDuplicate] = useState(false);

  // A remote edit or note switch replaces the draft (the component is
  // keyed by note id in NoteEditorPane, so this covers same-id refreshes).
  useEffect(() => {
    setDraft(savedUrl);
    setInvalid(false);
    setDuplicate(false);
  }, [savedUrl]);

  function commit(value: string) {
    const normalized = normalizeUrl(value);
    if (!normalized) {
      setInvalid(value.trim().length > 0);
      return;
    }
    setInvalid(false);
    if (normalized === savedUrl) return;
    // The quick-add bar's guard, on the edit path: without it the same trap
    // (two rows, one URL - trash "the copy" and lose the tagged original)
    // was one rename away. The edit is refused, not merged: the two rows may
    // carry different names, tags and folders, and picking a winner for the
    // user is a data decision the field cannot make.
    if (duplicateBookmarkId(bookmarkKeys, normalized, note.id)) {
      setDuplicate(true);
      return;
    }
    setDuplicate(false);
    onBodyChange(note.id, buildLinkBody(normalized));
  }

  return (
    <div className={`flex-1 p-6 ${BOOKMARK_COLUMN}`}>
      {/* The pane holds one field, so the label carries it as a heading
          rather than the form-label 12px it used to wear. Two steps under
          `pn-note-title` above it - H3 to the title's H1 - because at H2 a
          one-field pane read as two titles competing (reported 2026-08-25). */}
      <label className="block text-base lg:text-lg font-semibold tracking-tight text-neutral-800 dark:text-neutral-100 mb-3">
        {t('bookmarks.urlLabel')}
      </label>
      <div className="flex items-center gap-1.5">
        {/* The row chip, in the editor. It is the SAME `SiteChip` the list
            row draws, so an item looks like itself on both sides of a click,
            and it is fixed-size in every state (favicon, loading, globe
            fallback) - the field can never jump when an icon resolves. The
            domain comes from the SAVED url, so a half-typed value fetches
            nothing; the icon appears when the edit commits. */}
        <SiteChip
          domain={linkDomain(savedUrl)}
          tall
          trashTint={isTrash}
          fallback={isTrash ? 'bookmark' : 'globe'}
        />
        <input
          value={draft}
          onChange={(e) => { setDraft(e.target.value); setInvalid(false); setDuplicate(false); }}
          onBlur={() => commit(draft)}
          onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); commit(draft); } }}
          readOnly={isTrash || note.locked === 1}
          dir="ltr"
          enterKeyHint="done"
          className={`w-full rounded-md bg-surface-1 border px-3 py-2 text-sm focus:outline-none focus:border-accent ${invalid ? 'border-red-500' : duplicate ? 'border-amber-500' : 'border-divider'}`}
        />
        <button
          type="button"
          onClick={() => copy(savedUrl, 'url')}
          className="shrink-0 inline-flex items-center gap-1.5 h-9 rounded-md border border-divider bg-surface-1 px-3 text-[13px] text-neutral-600 dark:text-neutral-300 transition hover:text-accent hover:border-accent"
        >
          {/* The label never changes - a wider "copied" caption resized
              the button and squeezed the URL field mid-click. The green
              check is the feedback, the vault's own pattern. */}
          {copied === 'url' ? <Check size={15} className="text-green-500" /> : <Copy size={15} />}
          {t('common:actions.copy')}
        </button>
        <button
          type="button"
          onClick={() => openExternal(savedUrl)}
          className="shrink-0 inline-flex items-center gap-1.5 h-9 rounded-md bg-accent/10 px-3 text-[13px] font-semibold text-accent transition hover:bg-accent/20"
        >
          <ArrowSquareOut size={15} />
          {t('bookmarks.openAction')}
        </button>
      </div>
      {invalid && (
        <div className="mt-1.5 text-[12px] font-medium text-red-600 dark:text-red-400">{t('bookmarks.urlInvalid')}</div>
      )}
      {/* Amber, not red: the quick-add bar's colour for the same refusal, so
          "already saved" reads as the same event on both sides of a click. */}
      {duplicate && (
        <div className="mt-1.5 text-[12px] font-medium text-amber-600 dark:text-amber-400">{t('bookmarks.urlDuplicate')}</div>
      )}

      {/* Where the icon beside the field comes from, folded away until asked
          for. The chip fetches a third party's favicon, which is exactly the
          kind of thing a privacy-minded reader wants explained AT the field
          rather than in a modal three clicks away - but it is a paragraph,
          and a paragraph under every bookmark would be noise. The strings are
          the Trust tab's own (`landing:trust.favicons*`), never a second copy
          of them: one wording, two places. */}
      <button
        type="button"
        onClick={() => setIconHintOpen((v) => !v)}
        aria-expanded={iconHintOpen}
        className="mt-3 inline-flex items-center gap-1.5 text-[12px] text-pn-soft transition hover:text-accent"
      >
        <Info size={13} className="shrink-0 text-accent" />
        {t('landing:trust.faviconsHeading')}
        <CaretDown size={11} className={`shrink-0 transition-transform ${iconHintOpen ? '' : '-rotate-90'}`} aria-hidden="true" />
      </button>
      {/* No prose cap on the paragraph: it runs to the same edge as the field
          row above it, and the pane already caps its own column width. */}
      {iconHintOpen && (
        <p className="mt-1.5 text-[12px] leading-relaxed text-pn-soft">
          {t('landing:trust.faviconsBody1')} {t('landing:trust.faviconsBody2')}
        </p>
      )}

      {/* PIN-protect toggle - the vault form's exact block (LoginForm),
          same strings, same info modal, same disabled state without a PIN. */}
      {!isTrash && (
        <>
          <label className={`mt-6 flex items-center gap-2 pt-2 border-t border-divider ${!pinConfigured && !pinProtected ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}>
            <input
              type="checkbox"
              checked={pinProtected}
              onChange={(e) => onPinProtectedChange(note.id, e.target.checked)}
              // Read-only locks CONTENT, not protection: toggling the PIN gate
              // changes no data, so it stays available on a locked item.
              disabled={!pinConfigured && !pinProtected}
              className="rounded accent-accent"
            />
            <span className="text-sm text-neutral-600 dark:text-neutral-400">
              {t('auth:loginForm.requirePin')}
            </span>
            <button
              type="button"
              onClick={(e) => { e.preventDefault(); setShowPinInfo(true); }}
              className="text-accent/60 hover:text-accent transition p-1 -m-1"
              aria-label={t('auth:loginForm.whatDoesThisDo')}
            >
              <Info />
            </button>
          </label>
          {showPinInfo && <PinInfoModal onClose={() => setShowPinInfo(false)} />}
          {!pinConfigured && !pinProtected && (
            <p className="mt-1 text-[11px] text-neutral-400 dark:text-neutral-500">
              {t('auth:loginForm.setUpPinFirst')}
            </p>
          )}
        </>
      )}
    </div>
  );
}
