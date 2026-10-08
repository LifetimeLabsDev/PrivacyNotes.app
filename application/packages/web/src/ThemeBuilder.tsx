import { useEffect, useMemo, useRef, useState, type CSSProperties } from 'react';
import { useTranslation } from 'react-i18next';
import { paintedSlot, peekThemeMode, previewCustomTheme, useTheme, type Theme } from './theme';
import { BUILTIN_THEME_CODES } from './builtinThemeCodes';
import { newCustomThemeId } from './customThemes';
import { snapshotOf } from './customThemeUI';
import type { ThemeBuilderTarget } from './notesView/useThemeBuilder';
import * as tc from './themeCode';
import type { CheckId, CustomTheme, MoreKey, SeedKey, ThemeCheck } from './themeCode';
import { useEscapeToClose } from './useEscapeToClose';
import { IconUpgrade } from './UpgradeModal';
import { HoverLabel } from './HoverLabel';
import { ArrowCounterClockwise, CaretDown, CaretRight, Check, Copy, Eye, Warning, X } from './icons';

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

const SEEDS: SeedKey[] = ['background', 'sidebar', 'border', 'text', 'muted', 'accent'];
const MORE: MoreKey[] = ['list', 'well', 'soft', 'hover', 'fill', 'fillhover', 'danger', 'warning', 'success'];

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
  onSave,
  onClose,
  onOpenUpgrade,
}: {
  target: ThemeBuilderTarget;
  /** Pro, or the demo. */
  canSave: boolean;
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
  const [moreOpen, setMoreOpen] = useState(false);
  const [allChecks, setAllChecks] = useState(false);
  const [copied, setCopied] = useState(false);
  const shownMode = useRef<Theme | null>(null);

  // The draft starts from the theme being edited, copied or pasted, or as an
  // exact copy of the theme on screen, so opening the builder changes nothing
  // on screen until a color does.
  useEffect(() => {
    if (draft) return;
    let start = target.code ? tc.parseThemeCode(target.code) : null;
    if (!start) start = { ...tc.parseThemeCode(paintedCode(paintedMode))!, name: t('appearance.custom.namePlaceholder') };
    if (target.name) start = { ...start, name: target.name };
    setDraft(start);
    setNameText(start.name);
    // The target is fixed for the builder's life (NotesView keys it).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draft]);

  const name = tc.cleanThemeName(nameText);
  const theme = draft && name ? { ...draft, name } : draft;
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
      if (!d) return d;
      const overrides = { ...d.overrides };
      delete overrides[key];
      return { ...d, overrides };
    });
  const fix = (key: SeedKey | MoreKey) => setDraft((d) => (d ? tc.fixTheme(d, key) : d));
  const value = (key: SeedKey | MoreKey) =>
    (SEEDS as string[]).includes(key)
      ? draft.seeds[key as SeedKey]
      : draft.overrides[key as MoreKey] ?? resolved.suggested[key as MoreKey];
  const ready = name !== null && failing.length === 0;

  function save() {
    if (!ready || !snapshot) return;
    // A pinned mode moves to the theme's mode, as a click on a theme card
    // does; under Auto the theme shows whenever the system is in its mode.
    if (themeMode !== 'auto' && themeMode !== snapshot.mode) setThemeMode(snapshot.mode);
    setCustomTheme(snapshot);
    shownMode.current = null;
    onSave(idRef.current, snapshot.code);
  }

  function copy() {
    if (name === null) return;
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

        <div className="mt-3 grid grid-cols-3 gap-2">{SEEDS.map(tile)}</div>

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
              <p className="mt-1 text-[11px] text-pn-muted">{t('appearance.custom.contrastHelp')}</p>
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
          on a phone sheet, so Save and Cancel never leave the screen. */}
      <div className="sticky bottom-0 mt-3 border-t border-divider bg-surface-2 px-3 py-2.5">
        <div className="flex items-center gap-2">
          <button type="button" onClick={onClose} className="shrink-0 rounded-md px-2 py-1.5 text-xs font-medium text-pn-muted hover:text-pn">
            {t('common:actions.cancel')}
          </button>
          <input
            value={nameText}
            onChange={(e) => setNameText(e.target.value)}
            maxLength={64}
            dir="auto"
            aria-label={t('appearance.custom.name')}
            placeholder={t('appearance.custom.namePlaceholder')}
            className="min-w-0 flex-1 rounded-md border border-divider bg-track px-2 py-1.5 text-sm text-pn"
          />
          {canSave ? (
            <button
              type="button"
              onClick={save}
              disabled={!ready}
              className="shrink-0 rounded-md bg-accent-fill px-3 py-1.5 text-xs font-semibold text-white hover:bg-accent-fill-hover disabled:opacity-50"
            >
              {t('common:actions.save')}
            </button>
          ) : (
            <button
              type="button"
              onClick={() => onOpenUpgrade(code)}
              className="inline-flex shrink-0 items-center gap-1.5 rounded-md bg-accent-fill px-3 py-1.5 text-xs font-semibold text-white hover:bg-accent-fill-hover"
            >
              <IconUpgrade size={12} onFill /> {t('appearance.custom.saveWithPro')}
            </button>
          )}
        </div>
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
