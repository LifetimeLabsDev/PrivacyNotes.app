import { useEffect, useLayoutEffect, useRef, useState, type HTMLAttributes, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { ClockClockwise, type Icon } from './icons';
import { Callout } from './ui/feedback';

/**
 * Settings pane typography tokens - the single source of truth.
 * See ops/docs/archive/ui-patterns.md section 36. Every pane rendered inside
 * SettingsShell uses these so section headers and helper text can never
 * drift back into per-pane styles.
 *
 * The ladder: accent = structure (eyebrows, functional icons), soft =
 * supporting prose (descriptions, helpers, hints), muted = metadata only
 * (timestamps, counts, price fine print, legal footers - inline
 * `text-pn-muted`, deliberately not a token here).
 *
 * - SETTINGS_EYEBROW: the one uppercase section-header style.
 * - SETTINGS_EYEBROW_DANGER: the red variant (e.g. the danger zone).
 * - SETTINGS_HELP: the one helper / description / footnote style.
 * - SettingsCallout: the one container for important notes that must not
 *   read as a footnote (limits, bonuses, anything involving money).
 *
 * Use the SectionEyebrow component for plain section headers. For an
 * eyebrow that is not a plain <div> (a <span>, a centered field label,
 * a shared row label), keep the element and apply the constant.
 */
export const SETTINGS_EYEBROW =
  'text-[11px] font-semibold uppercase tracking-wide text-accent';
const SETTINGS_EYEBROW_DANGER =
  'text-[11px] font-semibold uppercase tracking-wide text-danger';
export const SETTINGS_HELP = 'text-xs text-pn-soft';

/** A section heading's glyph: 13px, in the heading's own color. The heading
 *  takes `EYEBROW_ICON_ROW` so the glyph and the words sit on one line. */
export const EYEBROW_ICON_ROW = 'flex items-center gap-1.5';
export function EyebrowGlyph({ icon: Glyph }: { icon: Icon }) {
  return <Glyph size={13} className="shrink-0" aria-hidden="true" />;
}

/** A setting row's title with its glyph: a 14px accent icon before the
 *  words. Every row title in Settings carries one. */
export const ROW_TITLE = 'text-sm font-medium flex items-center gap-1.5';
export function RowTitle({ icon: Glyph, children }: { icon: Icon; children: ReactNode }) {
  return (
    <p className={ROW_TITLE}>
      <Glyph size={14} className="text-accent shrink-0" aria-hidden="true" />
      {children}
    </p>
  );
}

/** A setting row in a pane: label and helper on the left, the control on the
 *  right from lg up, stacked below lg. The Date pane uses it; the Design,
 *  Editor and Lists panes build the same row in AppearanceSheet.tsx. */
export const SETTINGS_ROW =
  'flex flex-col gap-2 lg:flex-row lg:flex-wrap lg:items-center lg:justify-between lg:gap-x-5 lg:gap-y-2 py-3';
/** A segmented track and its two option states, as in Settings > Design. */
export const SETTINGS_TRACK = 'flex gap-1 rounded-md p-1 bg-track';
/** `fill` keeps the options sharing the track at every width; without it a
 *  wide pane lets them hug their labels. */
export const settingsSegClass = (on: boolean, fill = false) =>
  `flex-1 ${fill ? '' : 'lg:flex-none '}px-3 text-xs py-1.5 rounded transition ${on ? 'bg-surface-2 shadow-sm text-pn font-semibold' : 'text-pn-soft hover:text-pn font-medium'}`;

/** A segmented control: the track and option states above, for a choice
 *  that sits in a chart header or a toolbar instead of a setting row. The
 *  options hug their labels; a setting row keeps `SETTINGS_TRACK` and
 *  `settingsSegClass`, which split the track on a narrow pane. */
export function SettingsSegmented<T extends string>({
  value,
  options,
  onChange,
  label,
  className = '',
}: {
  value: T;
  options: readonly { value: T; label: ReactNode; title?: string }[];
  onChange: (value: T) => void;
  /** The group's accessible name. */
  label: string;
  /** Layout-only classes (spacing, wrapping). */
  className?: string;
}) {
  return (
    <div role="group" aria-label={label} className={`inline-flex flex-wrap gap-1 rounded-md p-1 bg-track ${className}`}>
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          aria-pressed={o.value === value}
          title={o.title}
          onClick={() => onChange(o.value)}
          className={`px-3 text-xs py-1.5 rounded transition ${o.value === value ? 'bg-surface-2 shadow-sm text-pn font-semibold' : 'text-pn-soft hover:text-pn font-medium'}`}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

/** Buttons in a settings pane. One height (`py-1.5`, 14px text) for all
 *  four; width is the caller's (add `w-full` for a full-width action).
 *  Upgrade is the upgrade window's own amber, so a door to it and the
 *  window read as one action. */
const BTN_BASE = 'inline-flex items-center justify-center gap-1.5 rounded-md px-3 py-1.5 text-sm transition disabled:opacity-40 disabled:cursor-not-allowed';
export const SETTINGS_BTN = `${BTN_BASE} border border-divider font-medium text-pn-soft hover:text-pn hover:bg-surface-1`;
export const SETTINGS_BTN_PRIMARY = `${BTN_BASE} border border-transparent bg-accent-fill hover:bg-accent-fill-hover font-semibold text-white`;
export const SETTINGS_BTN_UPGRADE = `${BTN_BASE} border border-transparent bg-amber-700 hover:bg-amber-800 font-semibold text-white`;
export const SETTINGS_BTN_DANGER = `${BTN_BASE} border border-transparent bg-danger hover:opacity-90 font-semibold text-white`;

/** A select or a short text field in a settings pane. */
export const SETTINGS_SELECT = 'rounded-md bg-track border border-divider ps-2.5 pe-3.5 py-1.5 text-sm text-pn focus:border-accent focus:outline-none';

/** One number with its label, as the Statistics tabs show a summary: a card,
 *  the label above, the value below, an optional line under it. */
export function StatTile({ label, value, sub, children }: { label: ReactNode; value: ReactNode; sub?: ReactNode; children?: ReactNode }) {
  return (
    <div className="min-w-0 rounded-lg border border-divider bg-surface-2 px-3 py-2.5">
      <div className="text-[11px] text-pn-muted truncate">{label}</div>
      <div className="text-xl font-semibold tabular-nums mt-0.5 truncate">{value}</div>
      {children}
      {sub && <div className="text-[11px] text-pn-soft mt-1">{sub}</div>}
    </div>
  );
}

/**
 * "Reset to defaults" at the foot of a pane. Armed, not immediate: the first
 * click turns it into a confirm for three seconds, because one stray click
 * would otherwise undo every choice on the pane at once.
 */
export function ResetDefaultsButton({ onReset, className = 'pt-4' }: { onReset: () => void; /** Layout-only classes; the default spaces it under a pane's last row. */ className?: string }) {
  const { t } = useTranslation('settings');
  const [armed, setArmed] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => { if (timer.current) clearTimeout(timer.current); }, []);

  function click() {
    if (timer.current) clearTimeout(timer.current);
    if (armed) {
      setArmed(false);
      onReset();
      return;
    }
    setArmed(true);
    timer.current = setTimeout(() => setArmed(false), 3000);
  }

  return (
    <div className={className}>
      <button
        type="button"
        onClick={click}
        className={`inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm font-medium transition ${
          armed
            ? 'border-red-500/40 text-danger'
            : 'border-divider text-pn-soft hover:text-pn'
        }`}
      >
        <ClockClockwise size={15} aria-hidden="true" />
        {armed ? t('appearance.resetDefaultsConfirm') : t('appearance.resetDefaults')}
      </button>
    </div>
  );
}

const SETTINGS_TAB_STRIP = 'pn-tab-strip grid grid-flow-col auto-cols-fr border-b border-divider';
/** Must match `.pn-tab-strip[data-row] > .pn-tab` in index.css. */
const ROW_GAP = 6;
const ROW_PAD = 8;

/**
 * Equal-width settings tabs. Callers own spacing, semantics and navigation;
 * each child is a button styled by settingsTabClass, with an icon and a
 * <span> label.
 *
 * A tab stacks its icon over the label, and the strip puts them side by side
 * only when EVERY label fits on one line beside its icon. That depends on the
 * pane width, the tab count and the language, so it is measured rather than
 * set at a breakpoint: a viewport breakpoint switched a narrow pane to the
 * row layout and broke long labels mid-word. Below 640px the strip always
 * stacks (index.css).
 */
export function SettingsTabStrip({ className = '', children, ...rest }: HTMLAttributes<HTMLDivElement>) {
  const ref = useRef<HTMLDivElement>(null);
  const [row, setRow] = useState(false);

  // No dependency list: a re-render can carry new labels (a language change),
  // and the check is a handful of text measurements.
  useLayoutEffect(() => {
    const strip = ref.current;
    if (!strip || typeof ResizeObserver === 'undefined') return;
    const ctx = document.createElement('canvas').getContext('2d');
    if (!ctx) return;
    const check = () => {
      const fits = Array.from(strip.children).every((tab) => {
        const label = tab.querySelector('span');
        if (!label) return true;
        const cs = getComputedStyle(label);
        ctx.font = `${cs.fontWeight} ${cs.fontSize} ${cs.fontFamily}`;
        const icon = tab.querySelector('svg')?.getBoundingClientRect().width ?? 0;
        const text = ctx.measureText(label.textContent ?? '').width;
        return icon + ROW_GAP + text + ROW_PAD * 2 <= tab.clientWidth;
      });
      setRow(fits);
    };
    check();
    const observer = new ResizeObserver(check);
    observer.observe(strip);
    return () => observer.disconnect();
  });

  return (
    <div ref={ref} {...rest} data-row={row || undefined} className={`${SETTINGS_TAB_STRIP} ${className}`}>
      {children}
    </div>
  );
}

export function settingsTabClass(active: boolean) {
  return `pn-tab inline-flex flex-col items-center justify-start gap-1 min-w-0 px-1 max-[400px]:px-0 py-2 -mb-px text-sm max-[400px]:text-[11px] leading-tight font-medium border-b-2 transition [overflow-wrap:anywhere] hyphens-auto [&>span]:min-w-0 [&>svg]:shrink-0 [&>svg]:text-accent ${active ? 'border-accent text-pn' : 'border-transparent text-pn-soft hover:text-pn'}`;
}

/** Standard uppercase section header for a settings pane. */
export function SectionEyebrow({
  children,
  className,
  danger = false,
  setting,
  icon,
}: {
  children: ReactNode;
  /** A glyph before the words; every section heading in Settings takes one. */
  icon?: Icon;
  /** Layout-only classes (spacing), e.g. "mb-2". */
  className?: string;
  danger?: boolean;
  /** The settings search id of the section this header names. */
  setting?: string;
}) {
  const base = `${danger ? SETTINGS_EYEBROW_DANGER : SETTINGS_EYEBROW}${icon ? ` ${EYEBROW_ICON_ROW}` : ''}`;
  return (
    <div data-setting={setting} className={className ? `${base} ${className}` : base}>
      {icon && <EyebrowGlyph icon={icon} />}
      {children}
    </div>
  );
}

/**
 * Accent bar that prefixes a floating headline. Always paired with
 * HeadlineRule in the same `flex items-center gap-2.5` row:
 * bar, title, rule.
 */
export function AccentBar() {
  return <span className="w-[3px] h-4 rounded-full bg-accent-fill shrink-0" aria-hidden="true" />;
}

/**
 * Hairline that extends a floating headline to the row's end. Place it
 * after the title inside a `flex items-center gap-2.5` row, with an
 * AccentBar before the title. Only for headlines with no bordered bar
 * of their own - inside a `border-b` header bar it would read as a
 * doubled line.
 */
export function HeadlineRule() {
  return <div className="h-px flex-1 bg-divider" aria-hidden="true" />;
}

/**
 * Important note row - accent-tinted so it can never be mistaken for a
 * muted footnote. For copy the user must not skim past: limits, plan
 * perks, anything that affects what they pay or lose.
 */
export function SettingsCallout({
  children,
  className,
}: {
  children: ReactNode;
  /** Layout-only classes (spacing), e.g. "mb-4". */
  className?: string;
}) {
  return <Callout className={className}>{children}</Callout>;
}

/** A chip in Settings (a tracker, a factor, a custom tracker's type, a
 *  medication's form): on takes the accent tint every selected option in
 *  Settings takes, not the logged green of the journal pills. */
export function settingsChipClass(on: boolean): string {
  return `inline-flex items-center h-7 px-2.5 rounded-md border text-xs font-medium transition-colors ${
    on ? 'border-accent/30 bg-accent/10 text-accent-strong' : 'border-transparent bg-surface-0 text-pn-soft hover:bg-pn/10 hover:text-pn'
  }`;
}
