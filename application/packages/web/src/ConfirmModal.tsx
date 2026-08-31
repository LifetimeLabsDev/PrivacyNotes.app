import { useTranslation } from 'react-i18next';
import { useEscapeToClose } from './useEscapeToClose';
import { type ReactNode } from 'react';
import { Info, Trash, Warning, X } from './icons';

type ConfirmVariant = 'danger' | 'warning' | 'info';

type Props = {
  title: string;
  /** Body content - string or JSX. */
  children: ReactNode;
  /** Label for the primary action button. */
  confirmLabel: string;
  /** Optional label for the cancel button. Defaults to "Cancel".
   *  Pass null to hide the cancel button entirely (notice-style modals
   *  with a single acknowledge action). */
  cancelLabel?: string | null;
  variant?: ConfirmVariant;
  onConfirm: () => void;
  /** Fires on backdrop click, X button, or Escape - true dismiss. */
  onClose: () => void;
  /** If provided, the cancel *button* calls this instead of onClose.
   *  Useful when the cancel button represents an explicit action
   *  (e.g. "Store as files") that differs from simply dismissing. */
  onCancel?: () => void;
};

/* ── Icon per variant ──────────────────────────────────── */

function VariantIcon({ variant }: { variant: ConfirmVariant }) {
  if (variant === 'danger')
    return (
      <div className="flex items-center justify-center w-10 h-10 rounded-full bg-red-500/10">
        <Trash size={20} className="text-red-500" />
      </div>
    );
  if (variant === 'warning')
    return (
      <div className="flex items-center justify-center w-10 h-10 rounded-full bg-amber-500/10">
        <Warning size={20} className="text-amber-500" />
      </div>
    );
  // info
  return (
    <div className="flex items-center justify-center w-10 h-10 rounded-full bg-accent/10">
      <Info size={20} className="text-accent" />
    </div>
  );
}

/* ── Confirm button class per variant ──────────────────── */

// amber-950 on amber-500, not white: amber is a light hue, and white on
// it measures 2.15:1. Dark text takes the same swatch to 6.97:1. Danger
// and info are dark hues and keep white. Spec: ops/docs/ui-patterns.md
// (section 89, ask before you show it).
const confirmBtnClass: Record<ConfirmVariant, string> = {
  danger: 'bg-red-600 text-white hover:bg-red-700',
  warning: 'bg-amber-500 text-amber-950 hover:bg-amber-600',
  info: 'bg-accent text-white hover:bg-accent-hover',
};

/* ── Component ─────────────────────────────────────────── */

export function ConfirmModal({
  title,
  children,
  confirmLabel,
  cancelLabel,
  variant = 'danger',
  onConfirm,
  onClose,
  onCancel,
}: Props) {
  const { t } = useTranslation('common');
  useEscapeToClose(onClose);
  // undefined -> default "Cancel" label; null -> hide the cancel button.
  const resolvedCancelLabel =
    cancelLabel === null ? null : cancelLabel ?? t('actions.cancel');
  return (
    <div
      className="fixed inset-0 bg-black/50 dark:bg-black/70 flex items-center justify-center p-4 sm:p-6 z-50"
      onClick={onClose}
    >
      <div
        className="bg-surface-2 border border-divider text-pn rounded-lg max-w-sm w-full p-6 space-y-4"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            <VariantIcon variant={variant} />
            <h2 className="text-lg font-semibold">{title}</h2>
          </div>
          <button
            onClick={onClose}
            className="text-neutral-400 hover:text-neutral-600 dark:hover:text-neutral-300 transition p-1 -m-1"
            aria-label={t('actions.close')}
          >
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div className="text-sm text-neutral-600 dark:text-neutral-400 leading-relaxed">
          {children}
        </div>

        {/* Actions */}
        <div className="flex gap-2 pt-2">
          {resolvedCancelLabel !== null && (
            <button
              onClick={onCancel ?? onClose}
              className="flex-1 rounded-md border border-neutral-300 hover:bg-neutral-100 dark:border-neutral-800 dark:hover:bg-neutral-900 px-4 py-2 text-sm transition"
            >
              {resolvedCancelLabel}
            </button>
          )}
          <button
            onClick={() => { onConfirm(); onClose(); }}
            className={`flex-1 rounded-md px-4 py-2 text-sm font-medium transition ${confirmBtnClass[variant]}`}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
