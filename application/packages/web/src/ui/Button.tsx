import type { ButtonHTMLAttributes, ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { HoverLabel } from '../HoverLabel';
import { X } from '../icons';
import { ACTIONS, type ActionName } from './actions';
import { IconUpgrade } from '../UpgradeModal';
import { SETTINGS_BTN, SETTINGS_BTN_DANGER, SETTINGS_BTN_PRIMARY, SETTINGS_BTN_UPGRADE } from '../settingsUI';

type Variant = 'secondary' | 'accent' | 'primary' | 'danger' | 'upgrade';

// Settings callouts also use Button; read their tokens after modules initialize.
function buttonLook(variant: Variant): string {
  switch (variant) {
    case 'secondary': return SETTINGS_BTN;
    case 'accent': return `${SETTINGS_BTN} !border-accent/35 bg-accent/10 !text-accent-strong hover:!bg-accent/15`;
    case 'primary': return SETTINGS_BTN_PRIMARY;
    case 'danger': return SETTINGS_BTN_DANGER;
    case 'upgrade': return SETTINGS_BTN_UPGRADE;
  }
}

/**
 * @catalog Button
 * use: every labeled action. Name it with `action` (save, add, create, done, confirm, apply, next, restore, delete, remove, cancel, back, edit, rename, copy, search, open): that brings the one icon, the label and the look of that action (`ui/actions.ts`), so a Save is the same everywhere. Words that say more ("Add medication") go in `children`; the icon stays. `icon` and `variant` only for an action the map does not have. One size for every button, everywhere; `pro` adds the rocket. The accent variant is a soft tint for a prominent secondary action beside a primary Save.
 * never: a <button> with its own border, fill or padding classes; a Save, Add or Remove without its icon; a second icon for an action the map has; a smaller or larger button.
 */
export function Button({
  action,
  variant,
  icon,
  pro = false,
  className = '',
  type = 'button',
  children,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: Variant;
  /** Shows the Pro rocket after the label (a free account's Pro door). */
  pro?: boolean;
  children?: ReactNode;
} & (
  /** The action this button does: its icon, label and look come from the map. */
  | { action: ActionName; icon?: never }
  /** A 15px glyph before the label, for an action the map does not have; give it `aria-hidden`. */
  | { action?: never; icon: ReactNode }
)) {
  const { t } = useTranslation('common');
  const spec = action ? ACTIONS[action] : null;
  const look = variant ?? spec?.variant ?? 'secondary';
  const Glyph = spec?.icon;
  return (
    <button type={type} {...rest} className={`${buttonLook(look)}${className ? ` ${className}` : ''}`}>
      {Glyph ? <Glyph size={15} aria-hidden="true" className="shrink-0" /> : icon}
      {children ?? (spec?.label ? t(`actions.${spec.label}`) : null)}
      {pro && <IconUpgrade size={12} onFill={look !== 'secondary'} />}
    </button>
  );
}

/**
 * @catalog IconButton
 * use: a tool on a row or a bar (edit, delete, more, close), where words do not fit. The label is required: it names the button for screen readers and shows as the tooltip.
 * never: a primary action (Save, Add, Remove); a <button> with only an icon and no label.
 */
export function IconButton({
  label,
  tone = 'quiet',
  position = 'above',
  className = '',
  type = 'button',
  children,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  label: string;
  /** `danger` turns the glyph red on hover (delete). */
  tone?: 'quiet' | 'danger' | 'accent';
  position?: 'above' | 'below' | 'above-end' | 'below-end' | 'above-start' | 'below-start' | 'start' | 'end';
  children: ReactNode;
}) {
  const toneClass = tone === 'danger' ? 'hover:text-danger' : tone === 'accent' ? 'text-accent hover:text-accent' : 'hover:text-pn';
  return (
    <HoverLabel label={label} position={position}>
      <button
        type={type}
        aria-label={label}
        {...rest}
        className={`inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-md text-pn-muted transition hover:bg-pn/10 disabled:opacity-40 ${toneClass}${className ? ` ${className}` : ''}`}
      >
        {children}
      </button>
    </HoverLabel>
  );
}

/**
 * @catalog CloseButton
 * use: the one X that closes a window, a panel, a popover or a sheet, at its top end: the 18px X, the quiet IconButton look, "Close" as its label and tooltip. Modal and Popover draw it themselves; a surface that is not one of them places it.
 * never: an X button of your own (its own size, padding, hover or color); a second close control in the footer.
 */
export function CloseButton({ onClick, disabled, className = '' }: { onClick: () => void; disabled?: boolean; className?: string }) {
  const { t } = useTranslation('common');
  return (
    <IconButton label={t('actions.close')} position="below-end" onClick={onClick} disabled={disabled} className={className} data-close-button="">
      <X size={18} aria-hidden="true" />
    </IconButton>
  );
}
