/**
 * LinkSheet - mobile bottom sheet / desktop dropdown for adding, editing,
 * and removing URL links in the TipTap editor.
 *
 * Replaces the old floating LinkPopover that broke on mobile (keyboard
 * pushed it off-screen, coordsAtPos unreliable after layout shift).
 *
 * Mobile: slides up from the bottom as a sheet, sits above the keyboard.
 * Desktop: drops down from the toolbar area as a compact panel.
 *
 * Pre-fills "Link text" from the current selection. URL field validates
 * on submit. Supports edit + remove for existing links.
 */

import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useEscapeToClose } from './useEscapeToClose';
import type { Editor } from '@tiptap/react';

type Props = {
  editor: Editor;
  isMobile: boolean;
  onClose: () => void;
};

const URL_PATTERN = /^([a-z][a-z0-9+.-]*:\/\/|mailto:|tel:)/i;
const BARE_HOST_PATTERN = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z]{2,})+/i;

function looksLikeUrl(input: string): boolean {
  const trimmed = input.trim();
  if (!trimmed) return false;
  if (URL_PATTERN.test(trimmed)) return true;
  if (BARE_HOST_PATTERN.test(trimmed)) return true;
  return false;
}

function normalizeUrl(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) return '';
  if (/^[a-z][a-z0-9+.-]*:/i.test(trimmed)) return trimmed;
  if (/^[/?#]/.test(trimmed)) return trimmed;
  return `https://${trimmed}`;
}

export function LinkSheet({ editor, isMobile, onClose }: Props) {
  const { t } = useTranslation('editor');
  const sheetRef = useRef<HTMLDivElement | null>(null);
  const urlRef = useRef<HTMLInputElement | null>(null);

  // Existing link attributes (if cursor is inside a link).
  const existingHref: string =
    (editor.getAttributes('link').href as string | undefined) ?? '';

  // Selected text for pre-filling the link text field.
  const { from, to } = editor.state.selection;
  const selectionText = from !== to
    ? editor.state.doc.textBetween(from, to, ' ')
    : '';

  const [url, setUrl] = useState(existingHref);
  const [text, setText] = useState(selectionText);
  const [urlError, setUrlError] = useState('');

  // Focus the URL input on mount.
  useEffect(() => {
    requestAnimationFrame(() => {
      urlRef.current?.focus();
      if (existingHref) urlRef.current?.select();
    });
  }, [existingHref]);

  // Outside-click dismisses (desktop).
  useEffect(() => {
    if (isMobile) return;
    function handler(e: PointerEvent) {
      if (sheetRef.current && !sheetRef.current.contains(e.target as Node)) {
        onClose();
      }
    }
    document.addEventListener('pointerdown', handler);
    return () => document.removeEventListener('pointerdown', handler);
  }, [isMobile, onClose]);

  useEscapeToClose(onClose);

  function validate(): boolean {
    const trimmed = url.trim();
    if (!trimmed) {
      setUrlError(t('link.errorEnterUrl'));
      return false;
    }
    if (!looksLikeUrl(trimmed)) {
      setUrlError(t('link.errorInvalidUrl'));
      return false;
    }
    setUrlError('');
    return true;
  }

  function apply() {
    if (!validate()) return;
    const href = normalizeUrl(url);
    const linkText = text.trim();

    // Read fresh selection state from the editor - the component-body
    // `from`/`to` can go stale if ProseMirror processes transactions
    // while the sheet is open (e.g. after a previous link insertion).
    // Fix: GitHub #77
    const { from: curFrom, to: curTo } = editor.state.selection;
    const curHasSelection = curFrom !== curTo;
    const inLink = editor.isActive('link');

    if (!curHasSelection && !inLink && linkText) {
      // No selection, not on a link, but user typed link text - insert both.
      editor
        .chain()
        .focus()
        .insertContent({
          type: 'text',
          text: linkText,
          marks: [{ type: 'link', attrs: { href } }],
        })
        .run();
    } else if (!curHasSelection && !inLink) {
      // No selection, no link text - insert the URL as both text and link.
      editor
        .chain()
        .focus()
        .insertContent({
          type: 'text',
          text: href,
          marks: [{ type: 'link', attrs: { href } }],
        })
        .run();
    } else {
      // Has selection or cursor is inside an existing link - wrap / update.
      editor
        .chain()
        .focus()
        .extendMarkRange('link')
        .setLink({ href })
        .run();
    }
    onClose();
  }

  function remove() {
    editor.chain().focus().extendMarkRange('link').unsetLink().run();
    onClose();
  }

  const hasSelection = from !== to;
  const isEditing = !!existingHref;

  // Shared form content - used in both mobile and desktop layouts.
  const form = (
    <>
      <label className="block text-[11px] font-medium text-neutral-500 dark:text-neutral-400 mb-1">
        {t('link.urlLabel')}
      </label>
      <input
        ref={urlRef}
        type="url"
        inputMode="url"
        autoComplete="off"
        placeholder={t('link.urlPlaceholder')}
        value={url}
        onChange={(e) => { setUrl(e.target.value); if (urlError) setUrlError(''); }}
        onKeyDown={(e) => {
          if (e.key === 'Enter') { e.preventDefault(); apply(); }
          if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); onClose(); }
        }}
        className={`w-full rounded-md border ${
          urlError
            ? 'border-red-400 dark:border-red-500'
            : 'border-divider'
        } bg-surface-2 px-3 py-2 text-sm text-pn focus:outline-none focus:ring-1 focus:ring-accent`}
      />
      {urlError && (
        <p className="text-[11px] text-red-500 dark:text-red-400 mt-1">{urlError}</p>
      )}

      <label className="block text-[11px] font-medium text-neutral-500 dark:text-neutral-400 mb-1 mt-3">
        {t('link.textLabel')}
      </label>
      <input
        type="text"
        autoComplete="off"
        placeholder={hasSelection ? '' : t('link.textPlaceholder')}
        value={text}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter') { e.preventDefault(); apply(); }
          if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); onClose(); }
        }}
        disabled={hasSelection || isEditing}
        className={`w-full rounded-md border border-divider bg-surface-2 px-3 py-2 text-sm text-pn focus:outline-none focus:ring-1 focus:ring-accent ${
          (hasSelection || isEditing) ? 'opacity-50 cursor-not-allowed' : ''
        }`}
      />
      {(hasSelection || isEditing) && (
        <p className="text-[10px] text-neutral-400 dark:text-neutral-500 mt-1">
          {hasSelection ? t('link.selectedTextHint') : t('link.editTextHint')}
        </p>
      )}

      <div className="flex gap-2 mt-4">
        {isEditing && (
          <button
            type="button"
            onMouseDown={(e) => e.preventDefault()}
            onClick={remove}
            className="rounded-md px-3 py-2 text-sm font-medium text-red-600 dark:text-red-400 hover:bg-red-100 dark:hover:bg-red-900/30 transition"
          >
            {t('common:actions.remove')}
          </button>
        )}
        <div className="flex-1" />
        <button
          type="button"
          onMouseDown={(e) => e.preventDefault()}
          onClick={onClose}
          className="rounded-md px-3 py-2 text-sm font-medium text-neutral-600 dark:text-neutral-400 hover:bg-neutral-100 dark:hover:bg-neutral-800 transition"
        >
          {t('common:actions.cancel')}
        </button>
        <button
          type="button"
          onMouseDown={(e) => e.preventDefault()}
          onClick={apply}
          disabled={!url.trim()}
          className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-white hover:bg-accent-hover transition disabled:opacity-40 disabled:cursor-not-allowed"
        >
          {isEditing ? t('link.update') : t('link.apply')}
        </button>
      </div>
    </>
  );

  if (isMobile) {
    // Bottom sheet - fixed to viewport bottom, above keyboard.
    return (
      <>
        {/* Backdrop */}
        <div
          className="fixed inset-0 bg-black/30 dark:bg-black/50 z-50"
          onClick={onClose}
        />
        {/* Sheet */}
        <div
          ref={sheetRef}
          className="fixed bottom-0 inset-x-0 z-50 bg-surface-2 border-t border-divider rounded-t-xl px-4 pt-3 pb-[max(1rem,env(safe-area-inset-bottom))]"
          role="dialog"
          aria-label={isEditing ? t('link.editTitle') : t('link.addTitle')}
        >
          {/* Handle */}
          <div className="w-8 h-1 bg-neutral-300 dark:bg-neutral-700 rounded-full mx-auto mb-4" />
          <h3 className="text-base font-semibold text-pn mb-3">
            {isEditing ? t('link.editTitle') : t('link.addTitle')}
          </h3>
          {form}
        </div>
      </>
    );
  }

  // Desktop - dropdown panel anchored below the toolbar.
  return (
    <div
      ref={sheetRef}
      className="absolute top-full left-1/2 -translate-x-1/2 mt-1 z-50 w-80 bg-surface-1 border border-divider rounded-lg p-4 shadow-lg"
      role="dialog"
      aria-label={isEditing ? t('link.editTitle') : t('link.addTitle')}
    >
      <h3 className="text-sm font-semibold text-pn mb-3">
        {isEditing ? t('link.editTitle') : t('link.addTitle')}
      </h3>
      {form}
    </div>
  );
}
