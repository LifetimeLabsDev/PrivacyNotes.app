import { useEffect, useMemo, useRef, useState, type CSSProperties } from 'react';
import { useTranslation } from 'react-i18next';
import { paintedSlot, peekThemeMode, previewCustomTheme, useTheme, type Theme } from './theme';
import { BUILTIN_THEME_CODES } from './builtinThemeCodes';
import { CUSTOM_THEME_MAX, newCustomThemeId } from './customThemes';
import { snapshotOf } from './customThemeUI';
import type { ThemeBuilderTarget } from './notesView/useThemeBuilder';
import * as tc from './themeCode';
import { SettingsCallout } from './settingsUI';
import type { CheckId, CustomTheme, MoreKey, SeedKey, ThemeCheck } from './themeCode';
import { useEscapeToClose } from './useEscapeToClose';
import { IconUpgrade } from './UpgradeModal';
import { HoverLabel } from './HoverLabel';
import { ArrowCounterClockwise, CaretDown, CaretRight, Check, Copy, Eye, FloppyDisk, MagicWand, Warning, X } from './icons';

/**
 * The theme builder: a small panel that floats over the app while the app
 * itself is the preview, repainted on every change. Settings is closed while
 * it is open. Nothing is stored until Save; Cancel, Escape and closing put
 * the saved slots back.
 *
 * The panel keeps the colors the app had when it opened, so an experiment
 * that makes the app unreadable never hides Save or Cancel: it sets the
 * resolved `--color-*` values, which every color utility reads, on itself.
 * Spec: ops/docs/color-themes.md (section 6)
 */

const PINNED = [
  '--color-accent', '--color-accent-hover', '--color-accent-strong', '--color-accent-fill',
  '--color-accent-fill-hover', '--color-danger', '--color-warning', '--color-success', '--color-pro',
  '--color-warm', '--color-surface-0', '--color-surface-1', '--color-surface-2', '--color-divider',
  '--color-track', '--color-pn-soft', '--color-pn', '--color-pn-muted',
];

// The tile order. The accent leads, because every suggestion and Fill the
// rest start from it; a code still writes the seeds in SEED_KEYS order.
const SEEDS: SeedKey[] = ['accent', 'background', 'sidebar', 'border', 'text', 'muted'];
const MORE: MoreKey[] = ['list', 'paper', 'well', 'soft', 'hover', 'fill', 'fillhover', 'danger', 'warning', 'success', 'label'];

/** The exact code of the theme on screen in a mode, as a starting point. */
function paintedCode(mode: Theme): string {
  const { choice, snapshot } = paintedSlot(mode);
  return snapshot?.code ?? BUILTIN_THEME_CODES[mode][choice] ?? BUILTIN_THEME_CODES[mode]['default']!;
}

/** `#abc123`, `abc123` or `ABC123` as `#ABC123`; anything else is null. */
function readHex(input: string): string | null {
  const m = /^#?([0-9A-Fa-f]{6})$/.exec(input.trim());
  return m ? `#${m[1]!.toUpperCase()}` : null;
}

export function ThemeBuilder({
  target,
  canSave,
  hasRoom,
  onSave,
  onClose,
  onOpenUpgrade,
}: {
  target: ThemeBuilderTarget;
  /** Pro, or the demo. */
  canSave: boolean;
  /** Whether a save under this id fits the limit of your own themes. */
  hasRoom: (id: string) => boolean;
  onSave: (id: string, code: string) => void;
  onClose: () => void;
  /** Save with Pro: hands over the draft's code, so it opens again after the upgrade. */
  onOpenUpgrade: (code: string) => void;
}) {
  const { t } = useTranslation('settings');
  const { theme: paintedMode, themeMode, setThemeMode, setCustomTheme } = useTheme();
  const idRef = useRef(target.id ?? newCustomThemeId());
  const [pinned] = useState<CSSProperties>(() => {
    const cs = getComputedStyle(document.documentElement);
    return Object.fromEntries(PINNED.map((v) => [v, cs.getPropertyValue(v).trim()])) as CSSProperties;
  });
  const [draft, setDraft] = useState<CustomTheme | null>(null);
  const [nameText, setNameText] = useState('');
  const [authorText, setAuthorText] = useState('');
  // The credit the opened code carried. A change of any color drops it from
  // the draft (withValue), and the field empties with it once: the colors are
  // the editor's now, and they may credit themselves.
  const inherited = useRef<string | undefined>(undefined);
  const [moreOpen, setMoreOpen] = useState(false);
  const [allChecks, setAllChecks] = useState(false);
  const [copied, setCopied] = useState(false);
  // Save keeps the builder open: the button shows a check for a moment, and
  // Cancel reads Close while nothing is unsaved.
  const [justSaved, setJustSaved] = useState(0);
  const [full, setFull] = useState(false);
  const [savedCode, setSavedCode] = useState<string | null>(null);
  const shownMode = useRef<Theme | null>(null);

  // The draft starts from the theme being edited, copied or pasted, or as an
  // exact copy of the theme on screen, so opening the builder changes nothing
  // on screen until a color does.
  useEffect(() => {
    if (draft) return;
    let start = target.code ? tc.parseThemeCode(target.code) : null;
    // A new theme starts with an empty name field: the placeholder shows the
    // name it gets when the person types none.
    const fresh = !start;
    // A new theme copies the colors on screen, never their credit.
    if (!start) start = { ...tc.withoutAuthor(tc.parseThemeCode(paintedCode(paintedMode))!), name: t('appearance.custom.namePlaceholder') };
    if (target.name) start = { ...start, name: target.name };
    setDraft(start);
    setNameText(fresh && !target.name ? '' : start.name);
    inherited.current = start.author;
    setAuthorText(start.author ?? '');
    // The target is fixed for the builder's life (NotesView keys it).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draft]);

  useEffect(() => {
    if (!draft || draft.author !== undefined || inherited.current === undefined) return;
    if (authorText === inherited.current) setAuthorText('');
    inherited.current = undefined;
    // Only a dropped credit matters here, not every keystroke in the field.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draft]);

  const name = tc.cleanThemeName(nameText.trim() ? nameText : t('appearance.custom.namePlaceholder'));
  const authorRaw = authorText.trim().replace(/^@/, '');
  const authorOk = authorRaw === '' || tc.AUTHOR.test(authorRaw);
  const author = authorOk && authorRaw ? authorRaw : undefined;
  const theme = draft && name ? { ...tc.withoutAuthor(draft), name, ...(author ? { author } : {}) } : draft;
  const resolved = useMemo(() => (theme ? tc.resolveTheme(theme) : null), [theme]);
  const checks = useMemo(() => (theme ? tc.checkTheme(theme) : []), [theme]);
  const failing = checks.filter((c) => !c.pass);
  const snapshot = theme ? snapshotOf(idRef.current, theme) : null;
  const code = snapshot?.code ?? '';

  // Paint the draft on every change, in the slot of its mode, without the
  // crossfade. A draft that changes mode leaves the slot it was in.
  useEffect(() => {
    if (!snapshot) return;
    if (shownMode.current && shownMode.current !== snapshot.mode) previewCustomTheme(shownMode.current, null);
    shownMode.current = snapshot.mode;
    if (snapshot.mode !== paintedMode) peekThemeMode(snapshot.mode);
    previewCustomTheme(snapshot.mode, snapshot);
    // The canonical code carries every color the snapshot paints.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [code]);

  // Closing in any way puts the saved slots and the stored mode back.
  useEffect(
    () => () => {
      if (shownMode.current) previewCustomTheme(shownMode.current, null);
      peekThemeMode(null);
    },
    [],
  );

  useEscapeToClose(onClose, true);

  if (!draft || !resolved || !snapshot) return null;

  const set = (key: SeedKey | MoreKey, hex: string) => setDraft((d) => (d ? tc.withValue(d, key, hex) : d));
  const reset = (key: MoreKey) =>
    setDraft((d) => {
      if (!d || d.overrides[key] === undefined) return d;
      const overrides = { ...d.overrides };
      delete overrides[key];
      return { ...tc.withoutAuthor(d), overrides };
    });
  const fix = (key: SeedKey | MoreKey) => setDraft((d) => (d ? tc.fixTheme(d, key) : d));
  const value = (key: SeedKey | MoreKey) =>
    (SEEDS as string[]).includes(key)
      ? draft.seeds[key as SeedKey]
      : draft.overrides[key as MoreKey] ?? resolved.suggested[key as MoreKey];
  const ready = name !== null && authorOk && failing.length === 0;

  function save() {
    if (!ready || !snapshot) return;
    if (!hasRoom(idRef.current)) {
      setFull(true);
      return;
    }
    // A pinned mode moves to the theme's mode, as a click on a theme card
    // does; under Auto the theme shows whenever the system is in its mode.
    if (themeMode !== 'auto' && themeMode !== snapshot.mode) setThemeMode(snapshot.mode);
    setCustomTheme(snapshot);
    shownMode.current = null;
    onSave(idRef.current, snapshot.code);
    setSavedCode(snapshot.code);
    const at = Date.now();
    setJustSaved(at);
    window.setTimeout(() => setJustSaved((v) => (v === at ? 0 : v)), 1400);
  }

  function copy() {
    if (name === null || !authorOk) return;
    void navigator.clipboard?.writeText(code).then(() => {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    });
  }

  const checkLabel = (id: CheckId) => t(`appearance.custom.check.${id}`);
  const advice = (c: ThemeCheck) =>
    c.id === 'sides'
      ? t('appearance.custom.sides')
      : resolved.mode === 'dark'
        ? t('appearance.custom.darker')
        : t('appearance.custom.lighter');

  const summary = tc.contrastSummary(checks);
  const isSeedKey = (k: SeedKey | MoreKey | null): k is SeedKey => k !== null && (SEEDS as string[]).includes(k);
  const moreFails = failing.some((c) => c.fix !== null && !isSeedKey(c.fix));
  const title = target.id ? t('appearance.custom.builderEdit') : t('appearance.custom.builderNew');

  // A tile is the color picker itself: the input covers the tile, so the
  // picker opens from a tap anywhere on it and anchors where the tile is.
  // The badge sits on a chip of the panel's own surface, where the success
  // and danger colors are measured, so it reads on a tile of any color.
  const tile = (key: SeedKey) => {
    const hex = draft.seeds[key];
    const label = t(`appearance.custom.seed.${key}`);
    const owned = checks.filter((c) => c.fix === key || (key === 'background' && c.fix === null));
    const fails = owned.some((c) => !c.pass);
    return (
      <div key={key} className="min-w-0">
        <label
          className={`relative block h-12 cursor-pointer rounded-lg border focus-within:ring-2 focus-within:ring-accent ${fails ? 'border-warning' : 'border-divider'}`}
          style={{ backgroundColor: hex }}
        >
          <input
            type="color"
            value={hex.toLowerCase()}
            onChange={(e) => set(key, e.target.value.toUpperCase())}
            aria-label={t('appearance.custom.colorField', { label })}
            className="absolute inset-0 h-full w-full cursor-pointer opacity-0"
          />
          {owned.length > 0 && (
            <span className="pointer-events-none absolute top-1 end-1 flex rounded bg-surface-2/90 p-0.5">
              {fails ? (
                <Warning size={10} weight="fill" className="text-warning" aria-hidden="true" />
              ) : (
                <Check size={10} weight="bold" className="text-success" aria-hidden="true" />
              )}
            </span>
          )}
        </label>
        <p className="mt-1 text-[11px] text-pn-soft">{label}</p>
        <HexField value={hex} label={label} onChange={(h) => set(key, h)} wide />
      </div>
    );
  };

  // The nine suggested colors keep the row layout: these are the advanced
  // ones, and Reset sits before the hex field so every hex field lines up.
  const row = (key: MoreKey, label: string, overridden: boolean) => (
    <div key={key} className="flex items-center gap-2 py-0.5">
      <input
        type="color"
        value={value(key).toLowerCase()}
        onChange={(e) => set(key, e.target.value.toUpperCase())}
        aria-label={t('appearance.custom.colorField', { label })}
        className="h-6 w-6 shrink-0 cursor-pointer rounded border border-divider bg-transparent p-0"
      />
      <span className="min-w-0 flex-1 truncate text-xs text-pn-soft">{label}</span>
      <HoverLabel label={t('appearance.custom.reset')} position="above" disabled={!overridden} className="shrink-0">
        <button
          type="button"
          onClick={() => reset(key)}
          disabled={!overridden}
          aria-label={t('appearance.custom.reset')}
          className="flex rounded p-0.5 text-accent hover:bg-pn/5 disabled:invisible"
        >
          <ArrowCounterClockwise size={14} aria-hidden="true" />
        </button>
      </HoverLabel>
      <HexField value={value(key)} label={label} onChange={(hex) => set(key, hex)} />
    </div>
  );

  const fixButton = 'rounded border border-divider px-2 py-0.5 text-[11px] font-medium text-accent hover:bg-pn/5';
  const summaryText =
    summary.state === 'pass'
      ? t('appearance.custom.contrastPass')
      : summary.state === 'one'
        ? t('appearance.custom.contrastOne', { label: checkLabel(summary.check.id) })
        : summary.state === 'many'
          ? t('appearance.custom.contrastMany', { count: summary.count })
          : advice(summary.check);

  return (
    <div
      role="dialog"
      aria-label={title}
      style={pinned}
      className="fixed z-50 inset-x-2 bottom-2 max-h-[60dvh] sm:inset-x-auto sm:bottom-4 sm:end-4 sm:w-[340px] sm:max-h-[calc(100dvh-2rem)] overflow-y-auto rounded-xl border border-divider bg-surface-2 text-pn shadow-xl"
    >
      <div className="p-3 pb-0">
        <div className="flex items-center gap-2">
          <h2 className="flex-1 text-sm font-semibold">{title}</h2>
          <HoverLabel label={t('appearance.custom.modeHint')} position="below-end" multiline>
            <span className="rounded-full bg-pn/10 px-2 py-0.5 text-[11px] text-pn-soft">
              {resolved.mode === 'dark' ? t('appearance.custom.modeDark') : t('appearance.custom.modeLight')}
            </span>
          </HoverLabel>
          <HoverLabel label={copied ? t('appearance.custom.copiedShort') : t('appearance.custom.copyCode')} position="below-end">
            <button
              type="button"
              onClick={copy}
              disabled={name === null}
              aria-label={copied ? t('appearance.custom.copiedShort') : t('appearance.custom.copyCode')}
              className="flex rounded p-1 text-pn-muted hover:text-pn disabled:opacity-50"
            >
              <Copy size={16} aria-hidden="true" />
            </button>
          </HoverLabel>
          <button type="button" onClick={onClose} aria-label={t('common:actions.close')} className="rounded p-1 text-pn-muted hover:text-pn">
            <X size={16} />
          </button>
        </div>
        <p className="mt-1 flex items-center gap-1 text-[11px] text-pn-muted">
          <Eye size={12} aria-hidden="true" className="shrink-0" /> {t('appearance.custom.previewHint')}
        </p>

        {/* For a person with no palette in mind: keep the accent, and let the
            app pick the other five for a light or a dark theme. */}
        <div className="mt-3 flex items-center gap-2 rounded-md bg-pn/5 px-2 py-1.5 text-[11px] text-pn-soft">
          <MagicWand size={14} aria-hidden="true" className="shrink-0 text-accent" />
          <span className="min-w-0 flex-1">{t('appearance.custom.suggestTitle')}</span>
          {(['light', 'dark'] as const).map((m) => (
            <button
              key={m}
              type="button"
              onClick={() => setDraft((d) => (d ? tc.suggestFromAccent(d, m) : d))}
              className="shrink-0 rounded border border-divider px-2 py-0.5 font-medium text-pn hover:border-accent hover:text-accent"
            >
              {m === 'light' ? t('appearance.custom.suggestLight') : t('appearance.custom.suggestDark')}
            </button>
          ))}
        </div>

        <div className="mt-2 grid grid-cols-3 gap-2">{SEEDS.map(tile)}</div>

        <button
          type="button"
          onClick={() => setMoreOpen((o) => !o)}
          aria-expanded={moreOpen}
          className="mt-3 flex w-full items-center gap-1 border-t border-divider pt-2 text-xs font-medium text-pn-soft hover:text-pn"
        >
          {moreOpen ? <CaretDown size={12} /> : <CaretRight size={12} />}
          {t('appearance.custom.more')}
          {!moreOpen && moreFails && <Warning size={12} weight="fill" className="ms-auto text-warning" aria-hidden="true" />}
        </button>
        {moreOpen && (
          <>
            <p className="mt-1 text-[11px] text-pn-muted">{t('appearance.custom.moreHelp')}</p>
            <div className="mt-1">{MORE.map((k) => row(k, t(`appearance.custom.moreKey.${k}`), draft.overrides[k] !== undefined))}</div>
          </>
        )}

        {/* The theme decides the logo: the accent, as every palette but
            Default, or the original colors, saved in its code as
            logo=original. Spec: ops/docs/color-themes.md (section 6) */}
        <div className="mt-3 border-t border-divider pt-2">
          <div className="flex items-center gap-2">
            <span className="min-w-0 flex-1 text-xs font-medium text-pn-soft">{t('appearance.custom.logoTitle')}</span>
            <div role="group" aria-label={t('appearance.custom.logoTitle')} className="flex flex-wrap gap-0.5 rounded-md p-0.5 bg-track">
              {([undefined, 'original'] as const).map((v) => (
                <button
                  key={v ?? 'tint'}
                  type="button"
                  aria-pressed={draft.logo === v}
                  onClick={() => setDraft((d) => (d ? tc.withLogo(d, v) : d))}
                  className={`px-2 py-0.5 rounded text-[11px] transition ${draft.logo === v ? 'bg-surface-2 shadow-sm text-pn font-semibold' : 'text-pn-soft hover:text-pn font-medium'}`}
                >
                  {t(v === 'original' ? 'appearance.custom.logoOriginal' : 'appearance.custom.logoTint')}
                </button>
              ))}
            </div>
          </div>
          <p className="mt-1 text-[11px] text-pn-muted">{t('appearance.custom.logoHelp')}</p>
        </div>

        <div className="mt-3 border-t border-divider pt-2">
          <div className="flex items-center gap-2 text-xs">
            <span className={`flex min-w-0 flex-1 items-center gap-1 ${summary.state === 'pass' ? 'text-success' : 'text-warning'}`}>
              {summary.state === 'pass' ? (
                <Check size={12} weight="bold" aria-hidden="true" className="shrink-0" />
              ) : (
                <Warning size={12} weight="fill" aria-hidden="true" className="shrink-0" />
              )}
              <span className="min-w-0">{summaryText}</span>
            </span>
            {summary.state === 'one' && (
              <button type="button" onClick={() => fix(summary.check.fix!)} className={fixButton}>
                {t('appearance.custom.fix')}
              </button>
            )}
            {summary.state === 'many' && (
              <button type="button" onClick={() => setDraft((d) => (d ? tc.fixAll(d) : d))} className={fixButton}>
                {t('appearance.custom.fixAll')}
              </button>
            )}
            <button type="button" onClick={() => setAllChecks((o) => !o)} aria-expanded={allChecks} className="shrink-0 text-[11px] text-accent hover:underline">
              {allChecks ? t('appearance.custom.hideDetails') : t('appearance.custom.details')}
            </button>
          </div>
          {allChecks && (
            <>
              <SettingsCallout className="mt-1.5 mb-1">{t('appearance.custom.contrastHelp')}</SettingsCallout>
              <ul className="mt-1 space-y-1">
                {checks.map((c) => (
                  <li key={c.id} className="text-xs">
                    <div className="flex items-center gap-2">
                      <span className="min-w-0 flex-1 truncate text-pn-soft">{checkLabel(c.id)}</span>
                      {c.ratio !== null ? (
                        <span className={`tabular-nums ${c.pass ? 'text-success' : 'text-danger'}`}>
                          {c.ratio.toFixed(1)}:1
                        </span>
                      ) : (
                        c.pass && <Check size={12} weight="bold" aria-hidden="true" className="shrink-0 text-success" />
                      )}
                      {!c.pass && c.fix && (
                        <button type="button" onClick={() => fix(c.fix!)} className={fixButton}>
                          {t('appearance.custom.fix')}
                        </button>
                      )}
                    </div>
                    {!c.pass && !c.fix && <p className="mt-0.5 text-[11px] text-pn-muted">{advice(c)}</p>}
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      </div>

      {/* The footer stays in view while the tiles and the Details list scroll
          on a phone sheet, so Save and Cancel never leave the screen. One grid
          keeps the two fields the same width, and Save is an icon, so the row
          keeps its shape in every language. */}
      <div className="sticky bottom-0 mt-3 border-t border-divider bg-surface-2 px-3 py-2.5">
        <div className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-x-2 gap-y-2">
          <button type="button" onClick={onClose} className="rounded-md px-2 py-1.5 text-start text-xs font-medium text-pn-muted hover:text-pn">
            {code === savedCode ? t('common:actions.close') : t('common:actions.cancel')}
          </button>
          <input
            value={nameText}
            onChange={(e) => setNameText(e.target.value)}
            maxLength={tc.THEME_NAME_INPUT_MAX}
            dir="auto"
            aria-label={t('appearance.custom.name')}
            placeholder={t('appearance.custom.namePlaceholder')}
            className="min-w-0 rounded-md border border-divider bg-track px-2 py-1.5 text-sm text-pn"
          />
          {canSave ? (
            <HoverLabel label={t('common:actions.save')} position="above-end">
              <button
                type="button"
                onClick={save}
                disabled={!ready}
                aria-label={t('common:actions.save')}
                className="flex h-8 w-9 items-center justify-center rounded-md bg-accent-fill text-white hover:bg-accent-fill-hover disabled:opacity-50"
              >
                {justSaved ? (
                  <Check key={justSaved} size={16} weight="bold" aria-hidden="true" className="pn-pop" />
                ) : (
                  <FloppyDisk size={16} aria-hidden="true" />
                )}
              </button>
            </HoverLabel>
          ) : (
            <HoverLabel label={t('appearance.custom.saveWithPro')} position="above-end">
              <button
                type="button"
                onClick={() => onOpenUpgrade(code)}
                aria-label={t('appearance.custom.saveWithPro')}
                className="flex h-8 w-9 items-center justify-center gap-0.5 rounded-md bg-accent-fill text-white hover:bg-accent-fill-hover"
              >
                <IconUpgrade size={12} onFill />
                <FloppyDisk size={14} aria-hidden="true" />
              </button>
            </HoverLabel>
          )}
          {/* Optional credit, written into the code as `by=`, so a code shared
              with friends names its maker and tells us how to credit it on
              /themes. A GitHub username, because that page links to it. */}
          <label htmlFor="pn-theme-credit" className="px-2 text-xs font-medium text-pn-muted">
            {t('appearance.custom.credit')}
          </label>
          <div className="flex min-w-0 items-center rounded-md border border-divider bg-track ps-2 text-sm text-pn" dir="ltr">
            <span className="text-pn-muted" aria-hidden="true">@</span>
            <input
              id="pn-theme-credit"
              value={authorText}
              onChange={(e) => setAuthorText(e.target.value)}
              maxLength={40}
              autoComplete="off"
              spellCheck={false}
              placeholder={t('appearance.custom.creditPlaceholder')}
              aria-invalid={!authorOk}
              className="min-w-0 flex-1 bg-transparent px-1 py-1.5 outline-none"
            />
          </div>
        </div>
        {!authorOk && <p className="mt-1 text-[11px] text-danger">{t('appearance.custom.creditInvalid')}</p>}
        {full && <p className="mt-1 text-[11px] text-danger" role="alert">{t('appearance.custom.themeLimit', { max: CUSTOM_THEME_MAX })}</p>}
        {name === null && <p className="mt-1 text-[11px] text-danger">{t('appearance.custom.nameInvalid')}</p>}
        {name !== null && canSave && !ready && <p className="mt-1 text-[11px] text-pn-muted">{t('appearance.custom.saveHint')}</p>}
      </div>
    </div>
  );
}

/** A hex field that takes what is typed and commits once it is a color. */
function HexField({ value, label, onChange, wide = false }: { value: string; label: string; onChange: (hex: string) => void; wide?: boolean }) {
  const { t } = useTranslation('settings');
  const [text, setText] = useState(value);
  const [focused, setFocused] = useState(false);
  useEffect(() => {
    if (!focused) setText(value);
  }, [value, focused]);
  return (
    <input
      value={focused ? text : value}
      onChange={(e) => {
        setText(e.target.value);
        const hex = readHex(e.target.value);
        if (hex) onChange(hex);
      }}
      onFocus={() => { setFocused(true); setText(value); }}
      onBlur={() => setFocused(false)}
      maxLength={7}
      spellCheck={false}
      dir="ltr"
      aria-label={t('appearance.custom.hexField', { label })}
      className={`${wide ? 'mt-0.5 w-full' : 'w-[76px]'} shrink-0 rounded border bg-track px-1.5 py-0.5 font-mono text-[11px] text-pn ${
        focused && !readHex(text) ? 'border-red-500/60' : 'border-divider'
      }`}
    />
  );
}
