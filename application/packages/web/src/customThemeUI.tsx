import { useEffect, useMemo, useRef, useState, type MouseEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { parseThemeCode, resolveTheme, serializeThemeCode, themePasses, type CustomTheme } from './themeCode';
import { deleteCustomTheme, liveCustomThemes, newCustomThemeId, saveCustomTheme, type CustomThemes } from './customThemes';
import { TEAM_THEMES } from './teamThemes';
import { customChoice, isFreeTheme, peekThemeMode, previewCustomTheme, type ColorTheme, type CustomSnapshot, type Theme, type ThemeChoice } from './theme';
import { BUILTIN_THEME_CODES } from './builtinThemeCodes';
import type { ContextMenuItem } from './ContextMenu';
import type { ThemeBuilderTarget } from './notesView/useThemeBuilder';
import { ConfirmModal } from './ConfirmModal';
import { CardMenuButton, ProCorner } from './ThemeCardMenuButton';
import { IconUpgrade } from './UpgradeModal';
import { Copy, PencilSimple, Trash } from './icons';

/**
 * The team and custom theme UI of Settings > Appearance > Themes and of
 * the footer popover: the extra cards of each gallery with their menus, and
 * the Paste theme code field. A lazy chunk, with the theme code module in it,
 * so none of it is on the boot path: the built-in cards show first and these
 * join them a moment later.
 * Spec: ops/docs/color-themes.md (section 6)
 */

export interface CustomThemeEntry {
  id: string;
  theme: CustomTheme;
  snapshot: CustomSnapshot;
  /** One of the team's themes; absent on a theme of your own. */
  team?: boolean;
}

/** What a slot paints for a theme: its resolved colors, under its id. */
export function snapshotOf(id: string, theme: CustomTheme): CustomSnapshot {
  const resolved = resolveTheme(theme);
  return { id, code: serializeThemeCode(theme), mode: resolved.mode, colors: { ...resolved.colors } };
}

/** The team's themes, in the order of their list. */
export function teamThemeEntries(): CustomThemeEntry[] {
  return TEAM_THEMES.flatMap(({ id, code }) => {
    const theme = parseThemeCode(code);
    return theme ? [{ id, theme, snapshot: snapshotOf(id, theme), team: true }] : [];
  });
}

/** The listed themes this version can paint, sorted by name. */
export function customThemeEntries(themes: CustomThemes): CustomThemeEntry[] {
  return liveCustomThemes(themes)
    .flatMap(({ id, code }) => {
      const theme = parseThemeCode(code);
      return theme ? [{ id, theme, snapshot: snapshotOf(id, theme) }] : [];
    })
    .sort((a, b) => a.theme.name.localeCompare(b.theme.name));
}

/** What the extra cards and the paste field need from the gallery around them. */
export interface ThemeGalleryCtx {
  customThemes: CustomThemes;
  isPro: boolean;
  /** Pro, or the demo. */
  canSave: boolean;
  lightTheme: ThemeChoice;
  darkTheme: ThemeChoice;
  /** The mode painted now. */
  painted: Theme;
  /** A card click: save it in its slot, or preview it on a free account. */
  pick: (mode: Theme, choice: ThemeChoice, snapshot?: CustomSnapshot) => void;
  openMenu: (e: MouseEvent<HTMLButtonElement>, items: ContextMenuItem[]) => void;
  /** "<name> copy", short enough for a name. */
  copyName: (name: string) => string;
  onCopied: (name: string) => void;
  setColorTheme: (mode: Theme, choice: ThemeChoice) => void;
  openUpgrade: () => void;
  /** Embedded pane only. */
  onChange?: (update: (prev: CustomThemes) => CustomThemes) => void;
  openBuilder?: (target: ThemeBuilderTarget) => void;
}

/** The team's themes and your own of one mode, as gallery cards. */
export function ExtraThemeCards({ mode, compact, ctx }: { mode: Theme; compact: boolean; ctx: ThemeGalleryCtx }) {
  const { t } = useTranslation('settings');
  const team = useMemo(() => teamThemeEntries(), []);
  const own = useMemo(() => customThemeEntries(ctx.customThemes), [ctx.customThemes]);
  const [deleting, setDeleting] = useState<CustomThemeEntry | null>(null);
  const active = mode === 'dark' ? ctx.darkTheme : ctx.lightTheme;
  const entries = [...team, ...own].filter((e) => e.snapshot.mode === mode);

  function copyCode(entry: CustomThemeEntry) {
    void navigator.clipboard?.writeText(entry.snapshot.code).then(() => ctx.onCopied(entry.theme.name));
  }

  function openMenu(e: MouseEvent<HTMLButtonElement>, entry: CustomThemeEntry) {
    const copyItems: ContextMenuItem[] = [
      {
        label: t('appearance.custom.makeCopy'),
        icon: <PencilSimple size={14} />,
        onSelect: () => ctx.openBuilder?.({ code: serializeThemeCode({ ...entry.theme, name: ctx.copyName(entry.theme.name) }) }),
      },
      { label: t('appearance.custom.copyCode'), icon: <Copy size={14} />, onSelect: () => copyCode(entry) },
    ];
    if (entry.team) {
      ctx.openMenu(e, copyItems);
      return;
    }
    ctx.openMenu(e, [
      {
        label: t('common:actions.edit'),
        icon: <PencilSimple size={14} />,
        onSelect: () => ctx.openBuilder?.({ id: entry.id, code: entry.snapshot.code }),
      },
      ...copyItems,
      { type: 'separator' },
      { label: t('common:actions.delete'), icon: <Trash size={14} />, destructive: true, onSelect: () => setDeleting(entry) },
    ]);
  }

  function remove(entry: CustomThemeEntry) {
    ctx.onChange?.((prev) => deleteCustomTheme(prev, entry.id));
    if (active === customChoice(entry.id)) ctx.setColorTheme(mode, 'default');
  }

  return (
    <>
      {entries.map((entry) => (
        <CustomThemeCard
          key={entry.id}
          entry={entry}
          active={active === customChoice(entry.id)}
          compact={compact}
          locked={!ctx.isPro}
          onPick={() => ctx.pick(mode, customChoice(entry.id), entry.snapshot)}
          onMenu={!compact && ctx.openBuilder ? (e) => openMenu(e, entry) : undefined}
        />
      ))}
      {deleting && (
        <ConfirmModal
          title={t('appearance.custom.deleteTitle', { name: deleting.theme.name })}
          confirmLabel={t('common:actions.delete')}
          variant="danger"
          onConfirm={() => { remove(deleting); setDeleting(null); }}
          onClose={() => setDeleting(null)}
        >
          {t('appearance.custom.deleteBody')}
        </ConfirmModal>
      )}
    </>
  );
}

/**
 * The card of a team theme or of a theme a person made: the same three
 * stripes as a built-in card, the name, and on your own a "yours" label.
 */
function CustomThemeCard({
  entry,
  active,
  compact,
  locked,
  onPick,
  onMenu,
}: {
  entry: CustomThemeEntry;
  active: boolean;
  compact: boolean;
  /** Pro badge, keyed off isPro like every other card. */
  locked: boolean;
  onPick: () => void;
  onMenu?: (e: MouseEvent<HTMLButtonElement>) => void;
}) {
  const { t } = useTranslation('settings');
  const c = entry.snapshot.colors;
  return (
    <div className="relative min-w-0">
      <button
        type="button"
        onClick={onPick}
        aria-pressed={active}
        className={`w-full min-w-0 rounded-lg border transition flex flex-col items-center ${compact ? 'p-1.5 gap-1' : 'p-2 gap-1.5'} ${
          active ? 'border-accent ring-1 ring-accent/30' : 'border-divider hover:border-pn-muted'
        }`}
      >
        <span className={`relative w-full ${compact ? 'h-6' : 'h-9'} rounded overflow-hidden flex`}>
          <span className="flex-1" style={{ backgroundColor: c['surface-0'] }} />
          <span className="flex-1" style={{ backgroundColor: c.accent }} />
          <span className="flex-1" style={{ backgroundColor: c.text }} />
          {locked && <ProCorner />}
        </span>
        <span className={`${compact ? 'text-[10px]' : 'text-[11px]'} font-medium text-pn-muted flex items-center gap-1 max-w-full`}>
          <span className="line-clamp-2 text-center break-words" dir="auto">{entry.theme.name}</span>
          {!compact && !entry.team && (
            <span className="shrink-0 rounded-full bg-pn/10 px-1.5 text-[10px] leading-4 text-pn-soft">
              {t('appearance.custom.yours')}
            </span>
          )}
        </span>
      </button>
      {onMenu && <CardMenuButton name={entry.theme.name} onClick={onMenu} />}
    </div>
  );
}

/** The built-in palette a code is the exact code of, if any. */
function builtinOf(code: string): { mode: Theme; choice: ColorTheme } | null {
  for (const mode of ['light', 'dark'] as const) {
    for (const [choice, builtinCode] of Object.entries(BUILTIN_THEME_CODES[mode])) {
      if (builtinCode === code) return { mode, choice: choice as ColorTheme };
    }
  }
  return null;
}

/**
 * Paste theme code: the field reads a code as it arrives and shows the theme
 * at once; Save keeps it. A code that is already a built-in, team or saved
 * theme picks that one. A code with colors that fail a check cannot be saved
 * from here, only opened in the builder, where Fix repairs it.
 */
export function ThemePasteField({ ctx, onClose }: { ctx: ThemeGalleryCtx; onClose: () => void }) {
  const { t } = useTranslation('settings');
  const [text, setText] = useState('');
  const idRef = useRef(newCustomThemeId());
  const shown = useRef<CustomSnapshot | null>(null);
  const theme = text.trim() ? parseThemeCode(text) : null;
  const entry = theme ? { id: idRef.current, theme, snapshot: snapshotOf(idRef.current, theme) } : null;
  const passes = theme ? themePasses(theme) : false;
  const code = entry?.snapshot.code ?? null;
  const builtin = code ? builtinOf(code) : null;
  // Default is free, so its code is too.
  const savable = ctx.canSave || (builtin !== null && isFreeTheme(builtin.choice));

  // Show the pasted theme while it is in the field, and stop showing it when
  // the field changes or closes without a save. Only a code that passes is
  // painted: a failing one can make this pane unreadable, so it opens in the
  // builder, whose panel keeps its own colors.
  // The mode is asked for on every code, never compared with the mode the
  // pane was rendered in: the cleanup of the code before has just ended its
  // peek, so a second code of the same mode found the old value and showed
  // nothing.
  useEffect(() => {
    if (!entry || !passes) return;
    shown.current = entry.snapshot;
    peekThemeMode(entry.snapshot.mode);
    previewCustomTheme(entry.snapshot.mode, entry.snapshot);
    return () => {
      if (shown.current) {
        previewCustomTheme(shown.current.mode, null);
        peekThemeMode(null);
      }
      shown.current = null;
    };
    // Keyed on the canonical code, which carries every color.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [code, passes]);

  function save() {
    if (!entry) return;
    const painted = shown.current;
    shown.current = null;
    if (builtin) {
      // The preview showed the code; the pick is the palette itself.
      if (painted) previewCustomTheme(painted.mode, null);
      ctx.pick(builtin.mode, builtin.choice);
      onClose();
      return;
    }
    const existing = [...teamThemeEntries(), ...customThemeEntries(ctx.customThemes)].find(
      (e) => e.snapshot.code === entry.snapshot.code,
    );
    const target = existing ?? entry;
    if (!existing) ctx.onChange?.((prev) => saveCustomTheme(prev, entry.id, entry.snapshot.code));
    ctx.pick(target.snapshot.mode, customChoice(target.id), target.snapshot);
    onClose();
  }

  const button = 'rounded-md px-3 py-1.5 text-xs font-medium transition';
  return (
    <div className="mt-3 rounded-lg border border-divider bg-track p-3">
      <label className="block text-xs font-medium text-pn-soft" htmlFor="pn-theme-code">
        {t('appearance.custom.pasteLabel')}
      </label>
      <input
        id="pn-theme-code"
        type="text"
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder={t('appearance.custom.pastePlaceholder')}
        spellCheck={false}
        autoComplete="off"
        autoFocus
        dir="ltr"
        className="mt-1 w-full rounded-md border border-divider bg-surface-2 px-2 py-1.5 font-mono text-xs text-pn placeholder:text-pn-muted"
      />
      {text.trim() && !theme && <p className="mt-2 text-xs text-danger">{t('appearance.custom.pasteInvalid')}</p>}
      {entry && passes && (
        <p className="mt-2 text-xs text-pn-soft">
          {t(entry.snapshot.mode === 'dark' ? 'appearance.custom.pasteDark' : 'appearance.custom.pasteLight', {
            name: entry.theme.name,
          })}
        </p>
      )}
      {entry && !passes && <p className="mt-1 text-xs text-warning">{t('appearance.custom.pasteHard')}</p>}
      <div className="mt-2 flex flex-wrap gap-2">
        {entry && passes && savable && (
          <button type="button" onClick={save} className={`${button} bg-accent-fill text-white hover:bg-accent-fill-hover`}>
            {t('common:actions.save')}
          </button>
        )}
        {entry && passes && !savable && (
          <button
            type="button"
            onClick={ctx.openUpgrade}
            className={`${button} inline-flex items-center gap-1.5 bg-accent-fill text-white hover:bg-accent-fill-hover`}
          >
            <IconUpgrade size={12} onFill /> {t('appearance.custom.saveWithPro')}
          </button>
        )}
        {entry && !passes && (
          <button
            type="button"
            onClick={() => ctx.openBuilder?.({ code: entry.snapshot.code })}
            className={`${button} bg-accent-fill text-white hover:bg-accent-fill-hover`}
          >
            {t('appearance.custom.openInBuilder')}
          </button>
        )}
        <button type="button" onClick={onClose} className={`${button} border border-divider text-pn-soft hover:text-pn`}>
          {t('common:actions.cancel')}
        </button>
      </div>
    </div>
  );
}
