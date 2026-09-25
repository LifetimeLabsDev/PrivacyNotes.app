import { useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { useEscapeToClose } from './useEscapeToClose';
import { HoverLabel } from './HoverLabel';
import { Switch } from './Switch';
import { ArrowDown, ArrowUp, PencilSimpleSlash, Shield } from './icons';
import {
  resolvePrefs,
  setPillarPrefs,
  type ListPrefs,
  type ListPrefsStore,
  type Pillar,
  type SortField,
} from './listPrefs';

/**
 * Preferences popover for the notes list:
 *   - SORT BY: Modified / Created / Title + asc/desc arrow
 *   - VIEW: Show preview / Show date / Show tags
 *   - OTHER: Show read-only / Show protected (with matching icons)
 *
 * Two pillar-specific switches deliberately do NOT live here: Files' "Show
 * notes with attachments" and Bookmarks' "Show links from notes". Each pillar
 * already draws its own inline row for it under the search bar, and one switch
 * in two places is one place too many (2026-08-25).
 *
 * Edits the copy the pane in front of you READS - `pillar`, defaulting to the
 * shared Global copy. This used to write Global unconditionally while every
 * list rendered from `resolvePrefs(store, pillar)`, so the moment a pillar
 * owned a copy the menu edited something that pillar no longer read: in Files,
 * one flip of the attachments toggle left "Show preview" reading ON in the
 * menu with the list stuck OFF forever. Passing the pillar is what keeps a
 * switch and its list from disagreeing.
 *
 * The store lives in UserSettings so changes sync across devices via
 * the encrypted user_settings pipeline.
 */
type Props = {
  /** Live prefs store - owner keeps this in sync with UserSettings. */
  store: ListPrefsStore;
  /** Called with the next store on every edit. Owner persists it. */
  onChange: (next: ListPrefsStore) => void;
  /** Called when the user clicks outside or presses Escape. */
  onClose: () => void;
  /** Anchor element - clicks on the trigger don't count as "outside". */
  anchorRef?: React.RefObject<HTMLElement | null>;
  /**
   * Which copy of the prefs this menu edits. Defaults to the shared Global
   * copy, which is what Notes, Tasks, Markdown, All, Pinned and Trash use.
   * A pillar that owns its view (bookmarks, files, journal, vault) passes its
   * own name, and MUST be the same pillar its list renders from.
   */
  pillar?: Pillar;
  /** CSS classes merged onto the popover container. Positioning only. */
  className?: string;
  /** Hide the VIEW toggles section (preview, date, tags). */
  hideViewSection?: boolean;
  /** Hide the OTHER toggles section (read-only, protected). */
  hideOtherSection?: boolean;
  /** Label for the title/name sort option. Defaults to "Title". */
  titleLabel?: string;
};

export function ListPrefsPopover({
  store,
  onChange,
  onClose,
  anchorRef,
  className = '',
  hideViewSection = false,
  hideOtherSection = false,
  titleLabel,
  pillar = 'global',
}: Props) {
  const { t } = useTranslation('shell');
  // Read and write the SAME copy the pane's list renders from.
  const prefs: ListPrefs = resolvePrefs(store, pillar);
  const resolvedTitleLabel = titleLabel ?? t('listPrefs.title');

  const popoverRef = useRef<HTMLDivElement | null>(null);

  // Click-outside to close. Pointerdown beats click so drags don't
  // stay trapped, and we skip clicks inside the anchor (the button
  // that opened the popover) to avoid the open/close flicker.
  useEffect(() => {
    function handler(e: PointerEvent) {
      const target = e.target as Node | null;
      if (!target) return;
      if (popoverRef.current && popoverRef.current.contains(target)) return;
      if (anchorRef?.current && anchorRef.current.contains(target)) return;
      onClose();
    }
    window.addEventListener('pointerdown', handler, true);
    return () => window.removeEventListener('pointerdown', handler, true);
  }, [onClose, anchorRef]);

  useEscapeToClose(onClose);

  function update<K extends keyof ListPrefs>(key: K, value: ListPrefs[K]) {
    const nextPrefs: ListPrefs = { ...prefs, [key]: value };
    onChange(setPillarPrefs(store, pillar, nextPrefs));
  }

  function setSort(field: SortField) {
    update('sortField', field);
  }

  function toggleDir() {
    update('sortDir', prefs.sortDir === 'asc' ? 'desc' : 'asc');
  }

  return (
    <div
      ref={popoverRef}
      role="dialog"
      aria-label={t('listPrefs.listPreferences')}
      className={`z-50 w-72 rounded-lg border border-divider bg-surface-2 shadow-lg ${className}`}
    >
      {/* ── SORT BY ──────────────────────────────────────────────── */}
      <div className="px-4 pt-3 pb-2">
        <div className="text-[10px] font-semibold tracking-wider text-neutral-500 dark:text-neutral-400 uppercase mb-1.5 mt-1">
          {t('listPrefs.sortBy')}
        </div>
        <div className="space-y-0.5">
          <SortRow
            label={t('listPrefs.dateCreated')}
            active={prefs.sortField === 'created'}
            dir={prefs.sortField === 'created' ? prefs.sortDir : null}
            onSelect={() => setSort('created')}
            onToggleDir={toggleDir}
          />
          <SortRow
            label={t('listPrefs.dateModified')}
            active={prefs.sortField === 'modified'}
            dir={prefs.sortField === 'modified' ? prefs.sortDir : null}
            onSelect={() => setSort('modified')}
            onToggleDir={toggleDir}
          />
          <SortRow
            label={resolvedTitleLabel}
            active={prefs.sortField === 'title'}
            dir={prefs.sortField === 'title' ? prefs.sortDir : null}
            onSelect={() => setSort('title')}
            onToggleDir={toggleDir}
          />
          <SortRow
            label={t('listPrefs.size')}
            active={prefs.sortField === 'size'}
            dir={prefs.sortField === 'size' ? prefs.sortDir : null}
            onSelect={() => setSort('size')}
            onToggleDir={toggleDir}
          />
        </div>
      </div>

      {/* ── VIEW ─────────────────────────────────────────────────── */}
      {!hideViewSection && (
      <div className="px-4 pt-2 pb-3 border-t border-divider">
        <div className="text-[10px] font-semibold tracking-wider text-neutral-500 dark:text-neutral-400 uppercase mb-1.5 mt-1">
          {t('listPrefs.view')}
        </div>
        <div className="space-y-0.5">
          <ToggleRow
            label={t('listPrefs.showPreview')}
            checked={prefs.showPreview}
            onChange={(v) => update('showPreview', v)}
          />
          <ToggleRow
            label={t('listPrefs.showDate')}
            checked={prefs.showDate}
            onChange={(v) => update('showDate', v)}
          />
          <ToggleRow
            label={t('listPrefs.showTags')}
            checked={prefs.showTags}
            onChange={(v) => update('showTags', v)}
          />
        </div>
      </div>
      )}

      {/* ── OTHER ────────────────────────────────────────────────── */}
      {!hideOtherSection && (
      <div className="px-4 pt-2 pb-3 border-t border-divider">
        <div className="text-[10px] font-semibold tracking-wider text-neutral-500 dark:text-neutral-400 uppercase mb-1.5 mt-1">
          {t('listPrefs.other')}
        </div>
        <div className="space-y-0.5">
          <ToggleRow
            label={t('listPrefs.showReadOnly')}
            icon={<IconPencilSlash />}
            checked={prefs.showLocked}
            onChange={(v) => update('showLocked', v)}
          />
          <ToggleRow
            label={t('listPrefs.showProtected')}
            icon={<IconShield />}
            checked={prefs.showProtected}
            onChange={(v) => update('showProtected', v)}
          />
        </div>
      </div>
      )}
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────
 * Sub-components
 * ──────────────────────────────────────────────────────────────── */

export function SortRow({
  label,
  hint,
  active,
  dir,
  onSelect,
  onToggleDir,
}: {
  label: string;
  /**
   * One line under the label, shown only while the row is selected. The
   * folder tree's Custom order needs it: no single word says "drag the
   * folders around", and a label long enough to say it does not fit
   * beside two one-word siblings.
   */
  hint?: string;
  active: boolean;
  dir: 'asc' | 'desc' | null;
  onSelect: () => void;
  onToggleDir: () => void;
}) {
  const { t } = useTranslation('shell');
  return (
    <>
    <div className="flex items-center gap-2 py-1">
      <button
        type="button"
        onClick={onSelect}
        className="flex items-center gap-2 flex-1 text-start group"
      >
        <span
          className={`shrink-0 w-4 h-4 rounded-full border-2 flex items-center justify-center transition ${
            active
              ? 'border-accent'
              : 'border-neutral-300 group-hover:border-neutral-400 dark:border-neutral-600 dark:group-hover:border-neutral-500'
          }`}
        >
          {active && (
            <span className="w-2 h-2 rounded-full bg-accent" aria-hidden />
          )}
        </span>
        <span className="text-[14px] text-pn">
          {label}
        </span>
      </button>
      {active && dir && (
        <HoverLabel label={dir === 'asc' ? t('listPrefs.ascending') : t('listPrefs.descending')} position="above">
        <button
          type="button"
          onClick={onToggleDir}
          aria-label={dir === 'asc' ? t('listPrefs.switchToDescending') : t('listPrefs.switchToAscending')}
          className="shrink-0 inline-flex items-center gap-1 px-1.5 h-7 rounded hover:bg-neutral-100 dark:hover:bg-neutral-800 transition"
        >
          <span className="text-[11px] font-medium text-accent uppercase">{dir === 'asc' ? t('listPrefs.asc') : t('listPrefs.desc')}</span>
          {dir === 'asc' ? (
            <ArrowUp className="text-accent" />
          ) : (
            <ArrowDown className="text-accent" />
          )}
        </button>
        </HoverLabel>
      )}
    </div>
    {active && hint && (
      <div className="ps-6 pb-1 -mt-0.5 text-[11.5px] text-pn-muted">{hint}</div>
    )}
    </>
  );
}

function ToggleRow({
  label,
  icon,
  checked,
  onChange,
}: {
  label: string;
  icon?: React.ReactNode;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <Switch
      label={label}
      icon={icon}
      checked={checked}
      onChange={onChange}
      className="gap-2 py-1 select-none"
      labelClassName="flex items-center gap-1.5 text-[14px] text-pn"
    />
  );
}

/* ────────────────────────────────────────────────────────────────
 * Icons - match NoteOptionsMenu's lock / shield so users see the
 * same visual language in both places.
 * ──────────────────────────────────────────────────────────────── */

function IconPencilSlash() {
  return <PencilSimpleSlash aria-hidden="true" className="shrink-0" />;
}

function IconShield() {
  return <Shield aria-hidden="true" className="shrink-0" />;
}

// Re-export default prefs for convenience
