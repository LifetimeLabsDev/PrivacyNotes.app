import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Minus, Plus } from '@phosphor-icons/react';
import { useCommitOnCollapse } from './PillShell';

/**
 * The one language of every tracker panel, in the check-in card and in the
 * journal entry: a question, then one input. A single-value input (a tile, a
 * choice) commits on the tap and the pass moves on; a many-value or a typed
 * input (chips, a number) commits as it changes and the pass moves on with
 * Next. The scale tiles live in `MoodScale.tsx` (`ScaleTiles`).
 * Spec: ops/docs/archive/ui-patterns.md section 141
 */

/** A chip in a many-value panel (emotions, factors): the tag chip's shape at
 *  the pill row's height. `on` takes the logged look of the pills. */
export function chipClass(on: boolean): string {
  return `inline-flex items-center h-7 px-2.5 rounded-md border text-[12px] font-medium transition-colors ${
    on ? 'border-success/25 bg-success/15 text-success' : 'border-transparent bg-surface-0 text-pn-soft hover:bg-pn/10 hover:text-pn'
  }`;
}

/** A chip that adds something: dashed, with a plus. */
export const CHIP_ADD = 'inline-flex items-center gap-1 h-7 px-2.5 rounded-md border border-dashed border-pn-muted/50 text-[12px] font-medium text-pn-muted hover:border-pn-muted hover:text-pn-soft transition-colors';

/** The question over an input. */
export function PanelQuestion({ children, className = 'mb-2' }: { children: ReactNode; className?: string }) {
  return <p className={`text-[13px] font-semibold text-pn ${className}`}>{children}</p>;
}

/**
 * One choice out of a few, as equal tiles across the row: sleep quality,
 * activity, yes or no. A long word wraps inside its tile rather than
 * widening it, so five Czech levels fit where five English ones do.
 */
export function ChoiceGrid<T extends string | boolean>({ options, value, onPick, size = 'md' }: {
  options: readonly { key: T; label: string }[];
  value: T | null | undefined;
  onPick: (key: T) => void;
  size?: 'md' | 'lg';
}) {
  return (
    // Equal tiles that wrap to a second row before a word is squeezed: a
    // tile is never narrower than its longest built-in word needs.
    <div role="radiogroup" className="grid gap-1.5" style={{ gridTemplateColumns: `repeat(auto-fit, minmax(min(100%, ${options.length > 2 ? 84 : 120}px), 1fr))` }}>
      {options.map((o) => {
        const on = value === o.key;
        return (
          <button
            key={String(o.key)}
            type="button"
            role="radio"
            aria-checked={on}
            onClick={() => onPick(o.key)}
            className={`min-w-0 flex items-center justify-center rounded-lg px-1 text-center text-[12px] font-medium leading-tight transition outline-none focus-visible:ring-2 focus-visible:ring-accent ${
              size === 'lg' ? 'h-12' : 'h-10 [@media(hover:none)]:h-11'
            } ${on ? 'bg-accent-fill text-white' : 'bg-surface-0 text-pn-soft hover:bg-accent/15 hover:text-accent'}`}
          >
            <span className="min-w-0 break-words hyphens-auto">{o.label}</span>
          </button>
        );
      })}
    </div>
  );
}

/** A pair or a trio of joined segments: Taken | Skipped, kg | lb. */
export function Segmented<T extends string>({ options, value, onPick, tone = 'accent', ariaLabel, size = 'md', className = '' }: {
  options: readonly { key: T; label: string }[];
  value: T | null | undefined;
  onPick: (key: T) => void;
  tone?: 'accent' | 'status';
  ariaLabel?: string;
  /** `sm`: a unit picker beside a question. */
  size?: 'sm' | 'md';
  /** Placement; a full-width pair shares the width between its segments. */
  className?: string;
}) {
  return (
    <div role="group" aria-label={ariaLabel} className={`inline-flex shrink-0 rounded-lg border border-divider overflow-hidden ${className}`}>
      {options.map((o, i) => {
        const on = value === o.key;
        const fill = tone === 'status' && i > 0 ? 'bg-warning text-white' : 'bg-accent-fill text-white';
        return (
          <button
            key={o.key}
            type="button"
            aria-pressed={on}
            onClick={() => onPick(o.key)}
            className={`flex-1 ${size === 'sm' ? 'px-2.5 h-7 text-[11.5px]' : 'px-3 h-8 [@media(hover:none)]:h-9 text-[12px]'} font-medium transition-colors ${i > 0 ? 'border-s border-divider' : ''} ${
              on ? fill : 'bg-surface-2 text-pn-muted hover:bg-pn/5 hover:text-pn'
            }`}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

const stepDecimals = (step: number) => (String(step).split('.')[1] ?? '').length;

/** Snap `n` to the step grid anchored at `min`, trimmed to the step's own
 *  decimals so float noise never reaches the field. */
function snap(n: number, min: number | undefined, step: number): number {
  if (step <= 0) return n;
  const base = min ?? 0;
  return Number((base + Math.round((n - base) / step) * step).toFixed(stepDecimals(step)));
}

/**
 * A number, big enough to read across the room: minus and plus step it, a
 * row of quick picks sets the usual values with one tap, and a tap on the
 * number itself opens the keyboard. Minus, plus and a quick pick save at
 * once; a typed number saves on Enter, on blur and when the panel closes,
 * so nothing typed is lost to a tap elsewhere.
 */
export function NumberStepper({ value, onChange, min, max, step = 1, unit, unitKey, quick, placeholder, start, expanded, autoFocus, freeDecimals = false }: {
  value: number | null | undefined;
  onChange: (n: number) => void;
  min?: number;
  max?: number;
  step?: number;
  /** The unit after the number, or a segmented unit picker. */
  unit?: ReactNode;
  /** The unit the number is in. A change saves a typed number first, under
   *  the unit it was typed in, so it is never read as the new unit. */
  unitKey?: string;
  /** The values the quick picks offer, fixed per tracker. */
  quick?: readonly number[];
  placeholder?: string;
  /** The last value logged: shown in an empty field, and where minus and
   *  plus start. Never written by itself. */
  start?: number;
  expanded: boolean;
  autoFocus?: boolean;
  /** A typed number keeps every decimal, not only the step's. */
  freeDecimals?: boolean;
}) {
  const [draft, setDraft] = useState(value != null ? String(value) : '');
  const typed = useRef(false);
  // A value set from outside (a quick pick, a unit change) refreshes the field.
  useEffect(() => {
    if (!typed.current) setDraft(value != null ? String(value) : '');
  }, [value]);

  const bound = (s: number) => {
    if (min != null && s < min) return min;
    if (max != null && s > max) return max;
    return s;
  };
  const clamp = (n: number) => bound(freeDecimals ? n : snap(n, min, step));
  // A typed number keeps its value at the step's precision: 8234 steps stay
  // 8234, never the 8000 of a 500 step that only moves the buttons.
  const typedValue = (n: number) => bound(freeDecimals ? n : Number(n.toFixed(stepDecimals(step))));
  const commitDraft = () => {
    if (!typed.current) return;
    typed.current = false;
    const n = parseFloat(draft.replace(',', '.'));
    if (isNaN(n)) { setDraft(value != null ? String(value) : ''); return; }
    onChange(typedValue(n));
  };
  useCommitOnCollapse(expanded, commitDraft);
  // The commit of the render before: its onChange still converts from the
  // unit the number was typed in. This effect runs before the one that
  // moves the ref on.
  const lastCommit = useRef(commitDraft);
  const lastUnit = useRef(unitKey);
  useEffect(() => {
    if (lastUnit.current === unitKey) return;
    lastUnit.current = unitKey;
    lastCommit.current();
    // The field shows the number in the new unit. A commit that changes the
    // stored number refreshes it again through the value effect above.
    setDraft(value != null ? String(value) : '');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [unitKey]);
  useEffect(() => { lastCommit.current = commitDraft; });

  const nudge = (dir: 1 | -1) => {
    const base = value ?? (parseFloat(draft) || (start ?? quick?.[Math.floor((quick.length - 1) / 2)] ?? min ?? 0));
    typed.current = false;
    onChange(clamp(base + dir * step));
  };

  // One joined control: minus, the number with its unit, plus. The field
  // grows with what it holds, so the unit always sits right after the number.
  const hint = start !== undefined ? String(start) : placeholder;
  const shown = draft || hint || '';
  const btn = 'inline-flex shrink-0 items-center justify-center w-8 @[16rem]/stepper:w-11 h-full text-pn-soft hover:bg-accent/10 hover:text-accent transition outline-none focus-visible:bg-accent/10';
  return (
    // Under 256 px (the narrowest list pane) the buttons, the number and the
    // quick picks shrink, so the number never runs under a button.
    <div className="@container/stepper flex flex-col gap-2">
      <div className="flex items-stretch h-12 rounded-lg border border-divider bg-surface-2 overflow-hidden focus-within:border-accent">
        <button type="button" onClick={() => nudge(-1)} aria-label="-" className={`${btn} border-e border-divider`}><Minus size={16} aria-hidden="true" /></button>
        <label className="flex flex-1 min-w-0 items-baseline justify-center gap-1 @[16rem]/stepper:gap-1.5 cursor-text pt-1.5">
          <input
            type="text"
            inputMode="decimal"
            value={draft}
            placeholder={hint}
            autoFocus={autoFocus}
            onChange={(e) => { typed.current = true; setDraft(e.target.value.slice(0, 10)); }}
            onBlur={commitDraft}
            onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); commitDraft(); } }}
            aria-label={placeholder}
            style={{ width: `${Math.max(1, shown.length) + 0.4}ch` }}
            className="max-w-full bg-transparent text-center text-[18px] @[16rem]/stepper:text-[24px] font-semibold tabular-nums text-pn placeholder:text-pn-muted/60 outline-none"
          />
          {unit && <span className="text-[11px] @[16rem]/stepper:text-[13px] font-medium text-pn-muted">{unit}</span>}
        </label>
        <button type="button" onClick={() => nudge(1)} aria-label="+" className={`${btn} border-s border-divider`}><Plus size={16} aria-hidden="true" /></button>
      </div>
      {quick && quick.length > 0 && (
        <div className="grid gap-1.5" style={{ gridTemplateColumns: `repeat(${quick.length}, minmax(0, 1fr))` }}>
          {quick.map((q) => {
            const on = value === q;
            return (
              <button
                key={q}
                type="button"
                aria-pressed={on}
                onClick={() => { typed.current = false; onChange(q); }}
                className={`h-8 min-w-0 rounded-md text-[11px] @[16rem]/stepper:text-[12.5px] font-medium tabular-nums transition ${on ? 'bg-accent-fill text-white' : 'bg-surface-0 text-pn-soft hover:bg-accent/15 hover:text-accent'}`}
              >
                {q}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
