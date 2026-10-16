import { toggleQuickTheme } from './quickThemes';
import { useEffect, useMemo, useRef, useState, type MouseEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { parseThemeCode, resolveTheme, serializeThemeCode, themePasses, withoutAuthor, type CustomTheme } from './themeCode';
import { canSaveCustomTheme, CUSTOM_THEME_MAX, deleteCustomTheme, liveCustomThemes, newCustomThemeId, saveCustomTheme, type CustomThemes } from './customThemes';
import { TEAM_THEMES } from './teamThemes';
import { COMMUNITY_THEMES, THEME_DISCUSSIONS_URL } from './communityThemes';
import { COMMUNITY_VOTES } from './communityVotes';
import { pickCommunity, type CommunitySort } from './communityShown';
import { openExternal } from './openExternal';
import { customChoice, isFreeTheme, peekThemeMode, previewCustomTheme, type ColorTheme, type CustomSnapshot, type Theme, type ThemeChoice } from './theme';
import { BUILTIN_THEME_CODES } from './builtinThemeCodes';
import type { ContextMenuItem } from './ContextMenu';
import type { ThemeBuilderTarget } from './notesView/useThemeBuilder';
import { ConfirmModal } from './ConfirmModal';
import { CardMenuButton, CommunityCorner, ProCorner, QuickCorner, QuickStarButton } from './ThemeCardMenuButton';
import { IconUpgrade } from './UpgradeModal';
import { ArrowSquareOut, Copy, PencilSimple, Trash } from './icons';
import { HoverLabel } from './HoverLabel';

/**
 * The team and custom theme UI of Settings > Design and of
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
  /** A theme the app ships (the team's or the community's), which a person
   *  copies but never edits or deletes; absent on a theme of your own. */
  team?: boolean;
  /** One of the community themes, credited by its code's `by=`. */
  community?: boolean;
  /** A community theme's day of adding (YYYY-MM-DD). */
  added?: string;
  /** A community theme's discussion thread, and its upvotes there. */
  discussion?: number;
  votes?: number;
}



/** Who made a theme, for the gallery's Made by filter. */
export type MadeBy = 'all' | 'community' | 'team' | 'yours';

/** What a slot paints for a theme: its resolved colors, under its id. */
export function snapshotOf(id: string, theme: CustomTheme): CustomSnapshot {
  const resolved = resolveTheme(theme);
  const colors: Record<string, string> = { ...resolved.colors, label: resolved.label, paper: resolved.paper };
  return { id, code: serializeThemeCode(theme), mode: resolved.mode, colors, ...(theme.logo ? { logo: theme.logo } : {}) };
}

/** The themes the app ships: the team's, then the community's, each in the
 *  order of its list. A build takes in every community theme added before it;
 *  /themes may list newer ones. An entry is never removed: a slot that names
 *  a theme this version does not list goes back to Default (reconcileCustomSlots). */
export function teamThemeEntries(): CustomThemeEntry[] {
  const read = (list: { id: string; code: string; added?: string; discussion?: number }[], community: boolean) =>
    list.flatMap(({ id, code, added, discussion }) => {
      const theme = parseThemeCode(code);
      const votes = discussion ? (COMMUNITY_VOTES[discussion] ?? 0) : 0;
      return theme
        ? [{ id, theme, snapshot: snapshotOf(id, theme), team: true, ...(community ? { community, added, discussion, votes } : {}) }]
        : [];
    });
  // Community themes newest first.
  const community = [...COMMUNITY_THEMES].sort((a, b) => b.added.localeCompare(a.added));
  return [...read(TEAM_THEMES, false), ...read(community, true)];
}

/** The name of a custom, team or community theme, by its id. */
export function themeNameOf(id: string, themes: CustomThemes): string | null {
  const entry = [...customThemeEntries(themes), ...teamThemeEntries()].find((e) => e.id === id);
  return entry?.theme.name ?? null;
}

/** Whether a gallery entry passes the Made by filter. */
export function madeByShows(entry: CustomThemeEntry, filter: MadeBy): boolean {
  if (filter === 'all') return true;
  if (filter === 'yours') return !entry.team;
  if (filter === 'community') return !!entry.community;
  return !!entry.team && !entry.community;
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
  /** The themes marked for the Design quick menu, and the menu row's action. */
  quickMarks: Record<Theme, ThemeChoice[]>;
  /** The card's star: add the theme to the quick menu or take it out. */
  star: (mode: Theme, choice: ThemeChoice) => void;
  /** Embedded pane only. */
  onChange?: (update: (prev: CustomThemes) => CustomThemes) => void;
  openBuilder?: (target: ThemeBuilderTarget) => void;
}

/** The team's themes and your own of one mode, as gallery cards. */
export function ExtraThemeCards({ mode, compact, ctx, madeBy = 'all', sort = 'newest', only }: {
  mode: Theme;
  compact: boolean;
  ctx: ThemeGalleryCtx;
  madeBy?: MadeBy;
  /** The order of the community themes under Community. */
  sort?: CommunitySort;
  /** One theme by id, for the quick menu; it draws nothing when the theme is gone. */
  only?: string;
}) {
  const { t } = useTranslation('settings');
  const team = useMemo(() => teamThemeEntries(), []);
  const own = useMemo(() => customThemeEntries(ctx.customThemes), [ctx.customThemes]);
  const [deleting, setDeleting] = useState<CustomThemeEntry | null>(null);
  const active = mode === 'dark' ? ctx.darkTheme : ctx.lightTheme;
  const entries = useMemo(() => {
    if (only !== undefined) return [...team, ...own].filter((e) => e.id === only);
    const shown = [...team, ...own].filter((e) => e.snapshot.mode === mode && madeByShows(e, madeBy));
    const community = shown.filter((e) => e.community);
    if (community.length === 0 || (madeBy !== 'all' && madeBy !== 'community')) return shown;
    // The picked community themes, plus the one this slot shows.
    const picked = pickCommunity(community.map((e) => ({ e, added: e.added ?? '', votes: e.votes ?? 0 })), madeBy, sort).map((p) => p.e);
    const current = community.find((e) => active === customChoice(e.id));
    if (current && !picked.includes(current)) picked.push(current);
    return [...shown.filter((e) => !e.community), ...picked];
  }, [team, own, only, mode, madeBy, sort, active]);

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
      const thread = entry.discussion;
      ctx.openMenu(
        e,
        thread
          ? [
              ...copyItems,
              { type: 'separator' },
              {
                label: t('appearance.custom.vote'),
                icon: <ArrowSquareOut size={14} />,
                onSelect: () => openExternal(`${THEME_DISCUSSIONS_URL}/${thread}`),
              },
            ]
          : copyItems,
      );
      return;
    }
    const credit: ContextMenuItem[] = entry.theme.author
      ? [{ type: 'header', label: t('appearance.custom.madeBy', { author: entry.theme.author }), keepCase: true }]
      : [];
    ctx.openMenu(e, [
      ...credit,
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
    if (ctx.quickMarks[mode].includes(customChoice(entry.id))) toggleQuickTheme(mode, customChoice(entry.id));
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
          marked={!compact && ctx.quickMarks[mode].includes(customChoice(entry.id))}
          onStar={!compact && ctx.openBuilder ? () => ctx.star(mode, customChoice(entry.id)) : undefined}
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
 * stripes as a built-in card and the name. A theme whose code credits its
 * author carries a people mark on the swatch and names the author on hover.
 */
function CustomThemeCard({
  entry,
  active,
  compact,
  locked,
  marked,
  onStar,
  onPick,
  onMenu,
}: {
  entry: CustomThemeEntry;
  active: boolean;
  compact: boolean;
  /** Pro badge, keyed off isPro like every other card. */
  locked: boolean;
  /** Shown in the Design quick menu. */
  marked: boolean;
  /** The star quick action, in Settings > Design. */
  onStar?: () => void;
  onPick: () => void;
  onMenu?: (e: MouseEvent<HTMLButtonElement>) => void;
}) {
  const { t } = useTranslation('settings');
  const c = entry.snapshot.colors;
  const author = entry.theme.author;
  return (
    <div className="group/card relative min-w-0">
      <HoverLabel label={author ? t('appearance.custom.madeBy', { author }) : ''} disabled={!author} position="below">
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
          {author && <CommunityCorner />}
          {marked && !onStar && <QuickCorner />}
        </span>
        <span className={`${compact ? 'text-[10px]' : 'text-[11px]'} font-medium text-pn-muted flex items-center gap-1 max-w-full`}>
          <span className="line-clamp-2 text-center break-words" dir="auto">{entry.theme.name}</span>
        </span>
      </button>
      </HoverLabel>
      {onStar && <QuickStarButton name={entry.theme.name} marked={marked} onToggle={onStar} />}
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
  const [full, setFull] = useState(false);
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
    // The colors decide, not the credit: a shipped theme pasted without its
    // `by=` (or with another one) is still that theme, credit included.
    const colorsOf = (th: CustomTheme) => serializeThemeCode(withoutAuthor(th));
    const existing = [...teamThemeEntries(), ...customThemeEntries(ctx.customThemes)].find(
      (e) => colorsOf(e.theme) === colorsOf(entry.theme),
    );
    if (!existing && !canSaveCustomTheme(ctx.customThemes, entry.id)) {
      shown.current = painted;
      setFull(true);
      return;
    }
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
      {full && <p className="mt-2 text-xs text-danger" role="alert">{t('appearance.custom.themeLimit', { max: CUSTOM_THEME_MAX })}</p>}
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
