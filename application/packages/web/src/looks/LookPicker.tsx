/**
 * The folder and tag look picker: a color, an icon, and the one switch that
 * decides whether an open note takes its color as its background.
 *
 * Two tabs, Icon first, because the icon search needs the room: with the
 * colors above it, a phone keyboard left the hits no space at all.
 *
 * A window in the middle of the screen; a bottom sheet under `lg`, where the
 * sidebar is a drawer. While a soft keyboard is up, the sheet spans the
 * visible viewport from its top to the keyboard, so the hits stay in view
 * whether or not the browser resizes the page for the keyboard. A pick saves at once and keeps the picker open, so a
 * color and an icon can be set in one visit. Cancel puts back what the
 * picker found; Done, the close button, Escape and a click outside keep the
 * picks, because they are already saved. Picks happen on a
 * click, never on pointer-down, so a finger that starts a scroll in the sheet
 * never picks. Hovering an icon shows it, with its name, in the header: the
 * grid scrolls, and a hover label above a cell would be clipped by it. A
 * query in the search field swaps the groups for one list of hits; with no
 * query, the icons the folders and tags already wear lead as one row.
 * Spec: ops/docs/plans/folder-tag-icons.md (section 6)
 */
import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import { createPortal } from 'react-dom';
import { useTranslation } from 'react-i18next';
import { Folder, Hash, Star, X } from '../icons';
import { ColorSwatch } from '../ColorSwatch';
import { useEscapeToClose } from '../useEscapeToClose';
import { useIsMobile } from '../useIsMobile';
import {
  folderLookKey,
  isLookColor,
  LOOK_COLORS,
  lookOf,
  type ItemStyles,
  type LookAttr,
  type LookColor,
} from '../itemStyles';
import { inkStyle, PathGlyph } from './LookGlyph';
import { useLookIcons } from './lookIconsLoader';
import { recentLookIcons, searchLookIcons } from './lookIconSearch';
import i18n, { activeLocale, ensureLooksLoaded } from '../i18n';
import { isImeComposing } from '../imeComposing';
import { isSoftKeyboardDevice } from '../softKeyboard';
import { HeadlineRule, SETTINGS_HELP } from '../settingsUI';
import { useKeyboardOpen } from '../useKeyboardOpen';
import { Switch } from '../Switch';
import { ListSearchInput } from '../ListSearchInput';

// Search keywords per language, from Unicode CLDR (tools/gen-look-keywords.mjs).
// Only the reader's language and English load, with the picker.
const keywordModules = import.meta.glob<{ default: Record<string, string> }>('./keywords/*.gen.json');

async function loadKeywords(): Promise<{ local: Record<string, string>; en: Record<string, string> }> {
  const read = async (lng: string) => (await keywordModules[`./keywords/${lng}.gen.json`]?.())?.default ?? {};
  const [local, en] = await Promise.all([read(activeLocale()), read('en')]);
  return { local, en };
}

export interface LookTarget {
  kind: 'folder' | 'tag';
  /** `folderLookKey(id)` or `tagLookKey(tag)`. */
  lookKey: string;
  /** The folder id, for a folder target. */
  folderId?: string;
  name: string;
  favorite?: boolean;
}

const TOUCH_SWATCH = '[@media(hover:none)]:w-11 [@media(hover:none)]:h-11';

export function LookPicker({
  target,
  styles,
  subfolderIds = [],
  tintNotes,
  onPick,
  onSubfoldersFollow,
  onTintNotes,
  onCancel,
  onClose,
}: {
  target: LookTarget;
  styles: ItemStyles;
  /** Every folder below a folder target; empty for a tag. */
  subfolderIds?: readonly string[];
  tintNotes: boolean;
  onPick: (patch: Partial<Record<LookAttr, string | null>>) => void;
  /** The subfolder switch: on copies the folder's color to every folder
   *  below it, off clears those copies. */
  onSubfoldersFollow?: (on: boolean) => void;
  onTintNotes: (on: boolean) => void;
  /** Undo every pick of this visit. The picker closes itself after it. */
  onCancel: () => void;
  onClose: () => void;
}) {
  const { t } = useTranslation('looks');
  const { t: tShell } = useTranslation('shell');
  const { t: tEditor } = useTranslation('editor');
  const { t: tSettings } = useTranslation('settings');
  const { t: tCommon } = useTranslation('common');
  const isSheet = useIsMobile();
  const catalog = useLookIcons(true);
  const panelRef = useRef<HTMLDivElement>(null);
  const gridRef = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const [tab, setTab] = useState<'icon' | 'color'>('icon');
  const [query, setQuery] = useState('');
  const keyboard = useKeyboardRect(isSheet);
  const [hoverIcon, setHoverIcon] = useState<string | null>(null);
  // The names load with the picker (i18n.ts, ensureLooksLoaded); the state
  // redraws it once they are in.
  const [namesReady, setNamesReady] = useState(false);
  const [keywords, setKeywords] = useState<{ local: Record<string, string>; en: Record<string, string> } | null>(null);
  useEffect(() => {
    let live = true;
    void ensureLooksLoaded().then(
      () => live && setNamesReady(true),
      () => {},
    );
    // Without keywords the search still finds names; a failed load leaves it so.
    void loadKeywords().then(
      (k) => live && setKeywords(k),
      () => {},
    );
    return () => {
      live = false;
    };
  }, []);

  // Escape clears a query first, and closes the picker after that.
  useEscapeToClose(() => (query ? setQuery('') : onClose()));

  // A press that starts and ends on the backdrop closes the window, so a drag
  // that leaves the panel does not.
  const downOnBackdrop = useRef(false);
  const backdropProps = {
    onPointerDown: (e: React.PointerEvent) => {
      downOnBackdrop.current = e.target === e.currentTarget;
    },
    onClick: (e: React.MouseEvent) => {
      if (downOnBackdrop.current && e.target === e.currentTarget) onClose();
    },
  };

  const look = lookOf(styles, target.lookKey);
  const ownColor: LookColor | null = isLookColor(look.color) ? look.color : null;
  // On when every folder below shows this folder's color (subfoldersFollow).
  const follow =
    ownColor !== null &&
    subfolderIds.length > 0 &&
    subfolderIds.every((id) => lookOf(styles, folderLookKey(id)).color === ownColor);

  // Straight into the search field where a keyboard is already out; a phone
  // would otherwise raise its keyboard over the icons on open.
  useEffect(() => {
    if (tab === 'icon' && !isSoftKeyboardDevice()) searchRef.current?.focus({ preventScroll: true });
  }, [tab]);

  function iconName(id: string): string {
    const n = catalog?.lookIconNumber(id) ?? null;
    return n === null ? t(`icons.${id}`) : t('number', { n });
  }

  // Every icon with the texts a query may match: the name in the UI language,
  // then in English, so a German reader finds the heart by "herz" and by
  // "heart", then the emoji keywords in both, then the group name.
  const entries = useMemo(() => {
    if (!catalog || !namesReady) return [];
    const tEn = i18n.getFixedT('en', 'looks');
    return catalog.LOOK_ICON_GROUPS.flatMap((group) =>
      group.ids.map((id) => {
        const n = catalog.lookIconNumber(id);
        const names = n === null ? [t(`icons.${id}`), tEn(`icons.${id}`)] : [t('number', { n }), tEn('number', { n })];
        const words = [keywords?.local[id], keywords?.en[id]].filter((w): w is string => !!w);
        return { id, texts: [...names, ...words, t(`groups.${group.key}`)] };
      }),
    );
  }, [catalog, namesReady, keywords, t]);
  const hits = query.trim() ? searchLookIcons(query, entries) : null;
  const recent = catalog ? recentLookIcons(styles, (id) => id in catalog.LOOK_ICONS) : [];

  const previewIcon = hoverIcon ?? look.icon;
  const previewPaths = previewIcon ? catalog?.LOOK_ICONS[previewIcon] : undefined;
  const DefaultGlyph = target.kind === 'folder' ? Folder : target.favorite ? Star : Hash;
  const caption = hoverIcon
    ? iconName(hoverIcon)
    : target.kind === 'folder'
      ? t('captionFolder')
      : t('captionTag');

  /** Arrow keys walk the grid by position, across the group headings. */
  function onGridKeyDown(e: KeyboardEvent<HTMLDivElement>) {
    const list = [...(gridRef.current?.querySelectorAll<HTMLButtonElement>('[data-look-icon]') ?? [])];
    const i = list.indexOf(document.activeElement as HTMLButtonElement);
    if (i === -1) return;
    const rtl = document.documentElement.dir === 'rtl';
    let next: HTMLButtonElement | undefined;
    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
      next = list[i + ((e.key === 'ArrowRight') !== rtl ? 1 : -1)];
    } else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      const here = list[i]!.getBoundingClientRect();
      const down = e.key === 'ArrowDown';
      let best: { el: HTMLButtonElement; dy: number; dx: number } | null = null;
      for (const el of list) {
        const r = el.getBoundingClientRect();
        const dy = down ? r.top - here.top : here.top - r.top;
        if (dy <= 4) continue;
        const dx = Math.abs(r.left - here.left);
        if (!best || dy < best.dy - 4 || (Math.abs(dy - best.dy) <= 4 && dx < best.dx)) {
          best = { el, dy, dx };
        }
      }
      next = best?.el;
      if (!next && !down) {
        e.preventDefault();
        searchRef.current?.focus();
        return;
      }
    } else if (e.key === 'Home') {
      next = list[0];
    } else if (e.key === 'End') {
      next = list[list.length - 1];
    } else {
      return;
    }
    e.preventDefault();
    next?.focus();
  }

  /** Down moves from the field into the icons; Enter takes the first hit. */
  function onSearchKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (isImeComposing(e)) return;
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      gridRef.current?.querySelector<HTMLButtonElement>('[data-look-icon]')?.focus();
    } else if (e.key === 'Enter') {
      // The field hands its value up after a short pause, so the hits are
      // read from what is typed now, not from the last value handed up.
      const typed = e.currentTarget.value;
      const first = typed.trim() ? searchLookIcons(typed, entries)[0] : undefined;
      if (!first) return;
      e.preventDefault();
      onPick({ icon: first });
    }
  }

  const searchField = (
    <div className="mt-3 flex">
      <ListSearchInput
        inputRef={searchRef}
        value={query}
        onChange={setQuery}
        onKeyDown={onSearchKeyDown}
        placeholder={t('searchPlaceholder')}
        ariaLabel={t('searchPlaceholder')}
      />
    </div>
  );

  const header = (
    <div className="flex items-center gap-3">
      <span
        className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0 border border-divider bg-surface-2"
        style={ownColor ? { background: `var(--pn-label-${ownColor}-tint)` } : undefined}
      >
        {previewPaths ? (
          <PathGlyph
            paths={previewPaths}
            size={20}
            className={ownColor ? undefined : 'text-amber-600/80 dark:text-amber-500/80'}
            style={inkStyle(ownColor)}
          />
        ) : (
          <DefaultGlyph
            size={20}
            weight={target.kind === 'tag' && target.favorite ? 'fill' : undefined}
            className={ownColor ? undefined : 'text-amber-600/80 dark:text-amber-500/80'}
            style={inkStyle(ownColor)}
            aria-hidden="true"
          />
        )}
      </span>
      <div className="min-w-0 flex-1">
        <p className="text-[14px] font-medium text-pn truncate" dir="auto">
          {target.kind === 'tag' ? `#${target.name}` : target.name}
        </p>
        <p className="text-[11px] text-pn-muted truncate" aria-live="polite">{caption}</p>
      </div>
      <button
        type="button"
        onClick={() => onPick({ icon: null, color: null })}
        disabled={!look.icon && !look.color}
        className="shrink-0 text-[12px] font-medium px-2 py-1 rounded-md text-accent hover:bg-accent/10 disabled:opacity-40 disabled:hover:bg-transparent transition"
      >
        {t('useDefault')}
      </button>
      <button
        type="button"
        onClick={onClose}
        aria-label={tCommon('actions.close')}
        className="shrink-0 -me-1 w-8 h-8 [@media(hover:none)]:w-11 [@media(hover:none)]:h-11 inline-flex items-center justify-center rounded-md text-pn-muted hover:text-pn hover:bg-neutral-200/70 dark:hover:bg-neutral-800 transition"
      >
        <X size={16} />
      </button>
    </div>
  );

  const footer = (
    <div className="shrink-0 grid grid-cols-2 gap-2 border-t border-divider px-4 pt-3">
      <button
        type="button"
        onClick={() => {
          onCancel();
          onClose();
        }}
        className="h-9 [@media(hover:none)]:h-11 rounded-md border border-divider text-pn text-[14px] font-medium hover:bg-neutral-200/60 dark:hover:bg-neutral-800/60 transition"
      >
        {tCommon('actions.cancel')}
      </button>
      <button
        type="button"
        onClick={onClose}
        className="h-9 [@media(hover:none)]:h-11 rounded-md bg-accent text-white text-[14px] font-medium hover:opacity-90 transition"
      >
        {tCommon('actions.done')}
      </button>
    </div>
  );

  const tabs = (
    <div role="tablist" aria-label={tShell('looks.menu')} className="mt-3 flex items-stretch border-b border-divider">
      {(['icon', 'color'] as const).map((id) => (
        <button
          key={id}
          type="button"
          role="tab"
          aria-selected={tab === id}
          onClick={() => setTab(id)}
          className={`flex-1 px-3 py-2 [@media(hover:none)]:py-3 text-sm font-medium border-b-2 -mb-px transition ${
            tab === id ? 'border-accent text-accent' : 'border-transparent text-pn-soft hover:text-pn'
          }`}
        >
          {t(id)}
        </button>
      ))}
    </div>
  );

  const colorSection = (
    <>
      <div className="mt-4 flex flex-wrap gap-1.5 [@media(hover:none)]:gap-2">
        <ColorSwatch
          label={t('noColor')}
          none
          selected={!ownColor}
          className={TOUCH_SWATCH}
          // The first swatch sits at the panel's start edge, where a centered
          // tip would hang out of the panel.
          labelPosition="below-start"
          onClick={() => onPick({ color: null })}
        />
        {LOOK_COLORS.map((c) => (
          <ColorSwatch
            key={c}
            label={tEditor(`color.names.${c}`)}
            background={`var(--pn-label-${c}-ink)`}
            selected={ownColor === c}
            className={TOUCH_SWATCH}
            labelPosition="below"
            onClick={() => onPick({ color: c })}
          />
        ))}
      </div>
      <div className="mt-3 border-t border-divider divide-y divide-divider">
        {onSubfoldersFollow && subfolderIds.length > 0 && (
          <Switch
            className="py-2.5"
            label={t('applyToSubfolders')}
            checked={follow}
            disabled={!ownColor}
            onChange={onSubfoldersFollow}
          />
        )}
        {/* One setting for all notes, shown here because this is where a
            color is chosen. */}
        <Switch
          className="py-2.5"
          label={tSettings('appearance.tintNotesTitle')}
          description={tSettings('appearance.tintNotesDesc')}
          checked={tintNotes}
          onChange={onTintNotes}
        />
      </div>
    </>
  );

  function iconButton(id: string) {
    if (!catalog) return null;
    const pressed = look.icon === id;
    return (
      <button
        key={id}
        type="button"
        data-look-icon
        aria-label={iconName(id)}
        aria-pressed={pressed}
        onClick={() => onPick({ icon: id })}
        onPointerEnter={(e) => e.pointerType === 'mouse' && setHoverIcon(id)}
        onPointerLeave={() => setHoverIcon(null)}
        onFocus={() => setHoverIcon(id)}
        onBlur={() => setHoverIcon(null)}
        className={`h-9 [@media(hover:none)]:h-11 rounded-md flex items-center justify-center transition ${
          pressed
            ? 'bg-accent/15 text-accent ring-1 ring-inset ring-accent'
            : 'text-neutral-600 dark:text-neutral-300 hover:bg-neutral-200/60 dark:hover:bg-neutral-800/60'
        }`}
      >
        <PathGlyph paths={catalog.LOOK_ICONS[id] ?? []} size={20} />
      </button>
    );
  }

  const cellGrid = `grid gap-0.5 ${isSheet ? 'grid-cols-[repeat(auto-fill,minmax(44px,1fr))]' : 'grid-cols-8'}`;

  function section(key: string, heading: string, ids: readonly string[]) {
    return (
      <section key={key}>
        <h3 className={`mt-3 mb-1.5 flex items-center gap-2 ${SETTINGS_HELP}`}>
          <span className="shrink-0">{heading}</span>
          <HeadlineRule />
        </h3>
        <div className={cellGrid}>{ids.map(iconButton)}</div>
      </section>
    );
  }

  const grid = (
    <div ref={gridRef} role="group" aria-label={t('icon')} onKeyDown={onGridKeyDown}>
      {!catalog ? (
        // The catalog is a separate chunk. The sheet grows upward from
        // the bottom edge when it lands; the popover has a fixed height.
        <div className="h-64" aria-busy="true" />
      ) : hits ? (
        hits.length > 0 ? (
          <div className={`mt-2 ${cellGrid}`}>{hits.map(iconButton)}</div>
        ) : (
          <p className="mt-4 text-center text-[13px] text-pn-muted" role="status">
            {tCommon('state.noResults')}
          </p>
        )
      ) : (
        <>
          {recent.length > 0 && section('recent', t('recent'), recent)}
          {catalog.LOOK_ICON_GROUPS.map((group) => section(group.key, t(`groups.${group.key}`), group.ids))}
        </>
      )}
    </div>
  );

  const dialogLabel = tShell('looks.menu');
  const top = (
    <>
      {header}
      {tabs}
      {tab === 'icon' && searchField}
    </>
  );
  const body = tab === 'icon' ? grid : colorSection;

  if (isSheet) {
    return createPortal(
      <>
        {/* Nearly the whole screen, and a fixed height, so a search with few
            hits does not shrink the sheet under the finger. */}
        <div className="fixed inset-0 z-[60] bg-black/30 dark:bg-black/50" {...backdropProps} />
        <div
          ref={panelRef}
          role="dialog"
          aria-label={dialogLabel}
          className={`fixed inset-x-0 z-[60] flex flex-col bg-surface-1 border-divider ${
            keyboard
              ? 'border-b rounded-b-xl pb-2'
              : 'bottom-0 h-[calc(100dvh-env(safe-area-inset-top)-1rem)] border-t rounded-t-xl pb-[max(0.75rem,env(safe-area-inset-bottom))]'
          }`}
          style={keyboard ? { top: keyboard.top, height: keyboard.height } : undefined}
        >
          {!keyboard && (
            <div className="w-8 h-1 bg-neutral-300 dark:bg-neutral-700 rounded-full mx-auto mt-3 mb-3 shrink-0" />
          )}
          <div className={`px-4 shrink-0 ${keyboard ? 'pt-3' : ''}`}>{top}</div>
          <div className="px-4 pt-1 pb-2 overflow-y-auto min-h-0 flex-1 overscroll-contain">{body}</div>
          {/* Done is the close button, which stays in the header. */}
          {!keyboard && footer}
        </div>
      </>,
      document.body,
    );
  }

  // A fixed height, not a maximum: the icons land after the window opens and
  // must not make it jump. The grid is always taller than the panel.
  return createPortal(
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/30 dark:bg-black/50"
      {...backdropProps}
    >
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label={dialogLabel}
        className="w-[380px] [@media(hover:none)]:w-[420px] max-w-full h-[min(640px,calc(100dvh-32px))] flex flex-col bg-surface-1 border border-divider rounded-xl shadow-xl pb-3"
      >
        <div className="px-4 pt-4 shrink-0">{top}</div>
        <div className="px-4 pt-1 pb-3 overflow-y-auto min-h-0 flex-1 overscroll-contain">{body}</div>
        {footer}
      </div>
    </div>,
    document.body,
  );
}

/**
 * The part of the screen a soft keyboard leaves visible, or null while no
 * keyboard is up. Read from the visual viewport, which shrinks for the
 * keyboard both where the page is resized with it and where the keyboard
 * only covers the page.
 */
function useKeyboardRect(enabled: boolean): { top: number; height: number } | null {
  const open = useKeyboardOpen();
  const [rect, setRect] = useState<{ top: number; height: number } | null>(null);
  useEffect(() => {
    const vv = window.visualViewport;
    if (!enabled || !open || !vv) {
      setRect(null);
      return;
    }
    const read = () => setRect({ top: vv.offsetTop, height: vv.height });
    read();
    vv.addEventListener('resize', read);
    vv.addEventListener('scroll', read);
    return () => {
      vv.removeEventListener('resize', read);
      vv.removeEventListener('scroll', read);
    };
  }, [enabled, open]);
  return rect;
}
