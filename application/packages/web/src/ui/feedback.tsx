import type { ComponentProps, ReactNode } from 'react';
import { CheckCircle, CircleNotch, Info, Warning, WarningCircle } from '../icons';
import { Button } from './Button';

/**
 * @catalog FeedbackButton
 * use: recovery, navigation and dismissal actions inside Callout or Banner. A neutral surface and theme-text border keep the same outline visible on every feedback tone. Pass the canonical Button action or icon.
 * never: separate Retry and banner-action border styles; a primary fill for routine feedback recovery.
 */
export function FeedbackButton(props: ComponentProps<typeof Button>) {
  return <Button {...props} variant="secondary" className={`!border-pn/25 bg-surface-1 hover:!border-pn/50${props.className ? ` ${props.className}` : ''}`} />;
}

export type Tone = 'info' | 'warning' | 'danger' | 'success';

const BOX: Record<Tone, string> = {
  info: 'border-accent/30 bg-accent/10',
  warning: 'border-warning/40 bg-warning/10',
  danger: 'border-danger/40 bg-danger/10',
  success: 'border-success/30 bg-success/10',
};
const INK: Record<Tone, string> = { info: 'text-accent', warning: 'text-warning', danger: 'text-danger', success: 'text-success' };
const GLYPH = { info: Info, warning: Warning, danger: WarningCircle, success: CheckCircle };

/**
 * @catalog Callout
 * use: persistent feedback inside a pane, window or form: info for a fact, warning for a risk requiring attention, danger for a failed action with a recovery instruction, success for a confirmed result. Each tone owns its Phosphor icon. Danger announces an alert. Optional title and action (a Button with the matching action icon). Keep form errors beside the actions until corrected; never auto-dismiss them.
 * never: an amber, red or green box of your own; a red border-red-300 bg-red-50 box; a warning as a grey helper line.
 */
export function Callout({ tone = 'info', title, action, className = '', children }: {
  tone?: Tone;
  title?: ReactNode;
  action?: ReactNode;
  className?: string;
  children?: ReactNode;
}) {
  const Glyph = GLYPH[tone];
  return (
    <div role={tone === 'danger' ? 'alert' : undefined} className={`flex flex-wrap items-center gap-2 rounded-md border px-3 py-2 text-xs leading-relaxed text-pn ${BOX[tone]}${className ? ` ${className}` : ''}`}>
      <div className="flex min-w-0 flex-[1_1_12rem] items-start gap-2">
        <Glyph size={15} className={`mt-0.5 shrink-0 ${INK[tone]}`} aria-hidden="true" />
        <div className="min-w-0 flex-1">
          {title && <p className="font-semibold">{title}</p>}
          {children}
        </div>
      </div>
      {action && <div className="ms-6 flex max-w-full flex-wrap items-center gap-2 sm:ms-auto">{action}</div>}
    </div>
  );
}

/**
 * @catalog Banner
 * use: a strip across the top of a pane for a state of the whole app or account (storage full, sync paused, a pending Pro activation, a move): the tone's icon, one sentence, an optional `action` (a `Button`) and an optional dismiss (`onDismiss`).
 * never: a strip of your own with an underlined text link; a banner inside a window (use Callout).
 */
export function Banner({ tone = 'warning', action, onDismiss, dismissLabel, children }: {
  tone?: Tone;
  action?: ReactNode;
  onDismiss?: () => void;
  dismissLabel?: string;
  children: ReactNode;
}) {
  const Glyph = GLYPH[tone];
  return (
    <div role="status" className={`flex flex-wrap items-center gap-3 border-b px-4 py-2 text-[13px] text-pn ${BOX[tone]}`}>
      <div className="flex min-w-0 flex-[1_1_12rem] items-start gap-3">
        <Glyph size={16} className={`mt-0.5 shrink-0 ${INK[tone]}`} aria-hidden="true" />
        <div className="min-w-0 flex-1">{children}</div>
      </div>
      {(action || onDismiss) && <div className="ms-auto flex max-w-full flex-wrap items-center gap-2">
        {onDismiss && (
          <FeedbackButton action="cancel" onClick={onDismiss}>{dismissLabel}</FeedbackButton>
        )}
        {action}
      </div>}
    </div>
  );
}

/**
 * @catalog Snackbar
 * use: a short message after an action, at the bottom centre, in the accent: "Moved to Work", with an optional action ("Undo"). The caller shows it and hides it after a few seconds.
 * never: a pill of your own; a toast card for a one-line message (UpdateToast is for an update or a reminder).
 */
export function Snackbar({ actionLabel, onAction, children }: { actionLabel?: string; onAction?: () => void; children: ReactNode }) {
  return (
    <div
      role="status"
      className={`fixed bottom-6 left-1/2 -translate-x-1/2 rtl:translate-x-1/2 z-50 flex max-w-[calc(100vw-2rem)] items-center gap-3 rounded-full bg-accent-fill py-1.5 ps-4 text-sm font-medium text-white shadow-lg ${actionLabel ? 'pe-1.5' : 'pe-4'}`}
    >
      <span className="min-w-0 truncate">{children}</span>
      {actionLabel && (
        <button type="button" onClick={onAction} className="shrink-0 rounded-full bg-white/20 px-3 py-1 hover:bg-white/30 transition">
          {actionLabel}
        </button>
      )}
    </div>
  );
}

const BADGE: Record<Tone | 'neutral', string> = {
  neutral: 'bg-track text-pn-muted',
  info: 'bg-accent/10 text-accent',
  warning: 'bg-warning/10 text-warning',
  danger: 'bg-danger/10 text-danger',
  success: 'bg-success/10 text-success',
};

/**
 * @catalog Badge
 * use: a short status or count beside a name: "Default", "Stronger", "Not backed up", "3". One size (11px), round ends, a tone. For Pro use ProMark.
 * never: a pill of your own in 9, 10 or 12px; an uppercase badge; a grey "Pro" badge.
 */
export function Badge({ tone = 'neutral', icon, children }: { tone?: Tone | 'neutral'; icon?: ReactNode; children: ReactNode }) {
  return (
    <span className={`inline-flex shrink-0 items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium leading-tight ${BADGE[tone]}`}>
      {icon}
      {children}
    </span>
  );
}

/**
 * @catalog Spinner
 * use: something is running and its length is unknown: a 16px accent circle that turns (`size` for a bigger one in an empty pane). Give it a `label` for screen readers when no text says what runs.
 * never: a spinning ArrowsClockwise or a pulse of your own.
 */
export function Spinner({ size = 16, label, className = '' }: { size?: number; label?: string; className?: string }) {
  return <CircleNotch size={size} className={`shrink-0 animate-spin text-accent ${className}`} role={label ? 'img' : undefined} aria-label={label} aria-hidden={label ? undefined : true} />;
}

/**
 * @catalog ProgressBar
 * use: how far a known job has come: a 6px accent fill on the track, `value` from 0 to 1; no `value` draws the running state. `tone` follows the result (info, success, warning or danger); it is not a substitute for a visible status. `label` names it for screen readers.
 * never: a fill bar of your own in another height or track color.
 */
export function ProgressBar({ value, label, tone = 'info' }: { value?: number; label: string; tone?: Tone }) {
  const fill = { info: 'bg-accent-fill', success: 'bg-success', warning: 'bg-warning', danger: 'bg-danger' }[tone];
  const pct = value === undefined ? undefined : Math.round(Math.min(1, Math.max(0, value)) * 100);
  return (
    <div role="progressbar" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct} className="h-1.5 w-full overflow-hidden rounded-full bg-track">
      <div className={`h-full rounded-full ${fill} transition-[width] duration-300 ${pct === undefined ? 'w-1/3 animate-pulse' : ''}`} style={pct === undefined ? undefined : { width: `${pct}%` }} />
    </div>
  );
}

/**
 * @catalog StatusLine
 * use: one line that says what a running step does or how it ended: "Downloading pictures, 1 of 2", "Saved". `busy` adds the Spinner; `tone="danger"` for a failure. It is announced to screen readers.
 * never: a status sentence in the helper style with no role; a busy label of your own.
 */
export function StatusLine({ busy = false, tone, children }: { busy?: boolean; tone?: 'danger' | 'success'; children: ReactNode }) {
  return (
    <p role="status" className={`flex items-center gap-2 text-xs ${tone === 'danger' ? 'text-danger' : tone === 'success' ? 'text-success' : 'text-pn-muted'}`}>
      {busy && <Spinner size={14} />}
      <span className="min-w-0">{children}</span>
    </p>
  );
}

/**
 * @catalog EmptyState
 * use: a list, a pane or a picker with nothing in it: a 48px duotone glyph in a round tile, a title, one line that says what goes here, and the actions (`Button`s: the primary, then Import). `compact` is one muted line, for a short list inside a pane.
 * never: a grey line of your own; a 64px circle of your own.
 */
export function EmptyState({ icon, title, children, actions, compact = false }: {
  icon?: ReactNode;
  title?: ReactNode;
  children?: ReactNode;
  actions?: ReactNode;
  compact?: boolean;
}) {
  if (compact) return <p className="px-4 py-6 text-center text-[13px] text-pn-muted">{children ?? title}</p>;
  return (
    <div className="flex flex-col items-center px-6 py-10 text-center">
      {icon && <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-track text-accent [&>svg]:h-8 [&>svg]:w-8">{icon}</div>}
      {title && <p className="text-base font-semibold text-pn">{title}</p>}
      {children && <p className="mt-1 max-w-xs text-sm text-pn-muted">{children}</p>}
      {actions && <div className="mt-4 flex flex-wrap justify-center gap-2">{actions}</div>}
    </div>
  );
}
