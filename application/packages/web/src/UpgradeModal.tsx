import { useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { useEscapeToClose } from './useEscapeToClose';
import { ArrowsOutSimple, ClockCounterClockwise, Columns, Database, FileArrowUp, Folder, Key, Lock, MagnifyingGlass, Monitor, Palette, Password, Shapes, BellSimple, RocketLaunch } from './icons';
import { isPaddleConfigured, isBetaPricing } from './paddle';
import { startProCheckout, PRO_PRODUCT_ID, isNativeStoreBuild } from './billing';
import { PRO_PRICE, EARLY_PRICE, COMPARE_YEARS, COMPETITOR_YEARLY } from './pricing';
import { useStorePrices } from './storePrices';
import { isDemoMode, DEMO_APP_URL } from './demo';
import { withSource } from './campaignSource';
import { HelpChip } from './HelpChip';
import { CloseButton } from './ui/Button';

type Props = {
  onClose: () => void;
  /** The user's hex pubkey - forwarded to Paddle as customData. */
  pubkey: string;
  /** Called after a successful checkout to refresh pro status. `silent` skips
   *  the "payment received, activation pending" banner (desktop return path,
   *  which fires whether or not the user actually paid). */
  onCheckoutComplete: (opts?: { silent?: boolean }) => void;
  /**
   * Optional context - which Pro feature triggered the upsell. Used
   * to bias the intro copy so the user doesn't feel like they clicked
   * a random Pro button.
   */
  trigger?: UpgradeTrigger;
};

/** Which Pro feature opened the modal; picks the intro line. */
export type UpgradeTrigger =
  | 'lock' | 'protect' | 'history' | 'devices' | 'zen' | 'theme' | 'storage'
  | 'fileSize' | 'folders' | 'looks' | 'noteIcon' | 'spaces' | 'formatBar' | 'totp' | 'replace' | 'passphrase' | 'alerts' | null;

const FEATURES: Array<{ icon: React.JSX.Element; labelKey: string }> = [
  { icon: <IconDevices />, labelKey: 'upgrade.features.devices' },
  { icon: <IconFolders />, labelKey: 'upgrade.features.folders' },
  { icon: <Columns size={18} aria-hidden="true" />, labelKey: 'upgrade.features.spaces' },
  { icon: <IconLock />, labelKey: 'upgrade.features.lock' },
  { icon: <IconHistory />, labelKey: 'upgrade.features.history' },
  { icon: <IconPalette />, labelKey: 'upgrade.features.themes' },
  { icon: <IconZen />, labelKey: 'upgrade.features.zen' },
  { icon: <IconStorage />, labelKey: 'upgrade.features.storage' },
];

function introKey(trigger: Props['trigger']): string {
  switch (trigger) {
    case 'lock':
      return 'upgrade.intro.lock';
    case 'protect':
      return 'upgrade.intro.protect';
    case 'history':
      return 'upgrade.intro.history';
    case 'devices':
      return 'upgrade.intro.devices';
    case 'zen':
      return 'upgrade.intro.zen';
    case 'theme':
      return 'upgrade.intro.theme';
    case 'storage':
      return 'upgrade.intro.storage';
    case 'folders':
      return 'upgrade.intro.folders';
    case 'looks':
      return 'upgrade.intro.looks';
    case 'noteIcon':
      return 'upgrade.intro.noteIcon';
    case 'spaces':
      return 'upgrade.intro.spaces';
    case 'formatBar':
      return 'upgrade.intro.formatBar';
    case 'totp':
      return 'upgrade.intro.totp';
    case 'replace':
      return 'upgrade.intro.replace';
    case 'passphrase':
      return 'upgrade.intro.passphrase';
    case 'alerts':
      return 'upgrade.intro.alerts';
    case 'fileSize':
      // Reuse the already-translated upload upsell string (importExport ns)
      // so the file-size context doesn't need its own billing copy.
      return 'importExport:upload.proPitch';
    default:
      return 'upgrade.intro.default';
  }
}

/** The glyph in the tile beside the intro line: the feature the person
 *  tapped, drawn the way the app draws it elsewhere, so the modal answers
 *  "what did I just open?" before it names a price. */
function triggerIcon(trigger: Props['trigger']): React.JSX.Element {
  const size = 22;
  switch (trigger) {
    case 'lock':
    case 'protect':
      return <Lock size={size} aria-hidden="true" />;
    case 'history':
      return <ClockCounterClockwise size={size} aria-hidden="true" />;
    case 'devices':
      return <Monitor size={size} aria-hidden="true" />;
    case 'zen':
      return <ArrowsOutSimple size={size} aria-hidden="true" />;
    case 'theme':
    case 'looks':
      return <Palette size={size} aria-hidden="true" />;
    case 'noteIcon':
      return <Shapes size={size} aria-hidden="true" />;
    case 'storage':
      return <Database size={size} aria-hidden="true" />;
    case 'fileSize':
      return <FileArrowUp size={size} aria-hidden="true" />;
    case 'folders':
      return <Folder size={size} aria-hidden="true" />;
    case 'spaces':
      return <Columns size={size} aria-hidden="true" />;
    case 'totp':
      return <Key size={size} aria-hidden="true" />;
    case 'replace':
      return <MagnifyingGlass size={size} aria-hidden="true" />;
    case 'passphrase':
      return <Password size={size} aria-hidden="true" />;
    case 'alerts':
      return <BellSimple size={size} aria-hidden="true" />;
    default:
      return <IconUpgrade size={size} />;
  }
}

export function UpgradeModal({ onClose, pubkey, onCheckoutComplete, trigger = null }: Props) {
  const { t } = useTranslation('billing');
  useEscapeToClose(onClose);
  const [loading, setLoading] = useState(false);
  const [purchaseError, setPurchaseError] = useState<string | null>(null);
  const configured = isPaddleConfigured();
  const beta = isBetaPricing();

  const nativeStore = isNativeStoreBuild();
  const storePrices = useStorePrices();
  const storePro = storePrices?.[PRO_PRODUCT_ID]?.formatted ?? null;

  const demo = isDemoMode();

  const ourPrice = beta ? EARLY_PRICE : PRO_PRICE;
  const compareRows = [
    { name: 'PrivacyNotes', total: ourPrice, us: true },
    ...COMPETITOR_YEARLY.map((c) => ({ name: c.name, total: c.perYear * COMPARE_YEARS, us: false })),
  ];
  const compareMax = Math.max(...compareRows.map((r) => r.total));

  async function handleUpgrade() {
    // Demo has no account to attach a purchase to - send the user to
    // sign up on the real app instead of opening checkout.
    if (demo) {
      window.location.href = withSource(DEMO_APP_URL);
      return;
    }
    if (!configured) return;
    setLoading(true);
    setPurchaseError(null);
    try {
      await startProCheckout(
        pubkey,
        () => {
          onCheckoutComplete();
          onClose();
        },
        () => {
          // Desktop return from the browser checkout: re-check Pro silently
          // (the user may have cancelled), then close. No payment banner.
          onCheckoutComplete({ silent: true });
          onClose();
        },
        // Native IAP failure: keep the modal open and say what happened. A
        // silent failure makes the buy button look dead (Play internal test).
        (reason) => setPurchaseError(t(`purchaseError.${reason}`)),
      );
    } catch (err) {
      console.error('Paddle checkout error:', err);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div
      /* Stacked overlay, not the standard one: a Pro gate can sit inside
         another modal, and the pitch is always the thing to read on top.
         Spec: ops/docs/archive/ui-patterns.md (z-index tier system) */
      className="fixed inset-0 bg-black/40 dark:bg-black/40 flex items-center justify-center p-4 sm:p-6 z-[55]"
      onClick={onClose}
    >
      <div
        className="bg-surface-2/85 backdrop-blur-xl border border-divider/80 text-pn rounded-lg max-w-lg w-full max-h-[90vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Celebration header - one-time payment is good news, so this
            reads as a win, not an error. */}
        <div className="relative bg-amber-50/80 dark:bg-amber-950/50 rounded-t-lg px-6 pt-5 pb-5">
          <CloseButton onClick={onClose} className="absolute top-4 end-4" />

          <div className="flex items-center gap-2 text-[13px] font-semibold text-amber-700 dark:text-amber-300">
            <IconUpgrade size={16} />
            {t('upgrade.header')}
          </div>

          {beta ? (
            <div className="flex items-baseline gap-2 mt-2.5">
              <span className="text-4xl font-bold tracking-tight text-amber-900 dark:text-amber-100">{storePro ?? (nativeStore ? '…' : `$${EARLY_PRICE}`)}</span>
              {/* The struck-through full price is a Paddle web figure. The stores
                  have no "was" price and sell on their own fixed tiers, so on a
                  native build it would compare the real charge against a number
                  the user can never be billed. Badge stays: the price genuinely
                  does rise later. */}
              {!nativeStore && (
                <span className="text-lg font-semibold line-through text-warning">${PRO_PRICE}</span>
              )}
              <span className="text-[11px] font-semibold text-amber-900 dark:text-amber-100 bg-amber-200 dark:bg-amber-800 rounded-md px-2 py-0.5">{t('upgrade.earlyAdopterBadge')}</span>
            </div>
          ) : (
            <div className="flex items-baseline gap-2 mt-2.5">
              <span className="text-4xl font-bold tracking-tight text-amber-900 dark:text-amber-100">{storePro ?? (nativeStore ? '…' : `$${PRO_PRICE}`)}</span>
              <span className="text-sm font-medium text-amber-700/70 dark:text-amber-300/70">{t('upgrade.oneTime')}</span>
            </div>
          )}

          {/* Web and desktop only, like the comparison sentence it replaced:
              the fees are USD figures and a store build shows a localized
              price with nothing to chart against it. */}
          {!nativeStore && (
            <div className="mt-4 space-y-1.5">
              {compareRows.map((row) => (
                <div key={row.name} className="grid grid-cols-[6.5rem_1fr_3.5rem] items-center gap-2 text-[12px]">
                  <span className="truncate text-amber-700 dark:text-amber-300">{row.name}</span>
                  <div className="h-2.5 rounded-sm bg-amber-900/10 dark:bg-amber-100/10">
                    <div
                      className={row.us ? 'h-full rounded-sm bg-pro' : 'h-full rounded-sm bg-amber-800/30 dark:bg-amber-200/20'}
                      style={{ width: `${Math.max(4, Math.round((row.total / compareMax) * 100))}%` }}
                    />
                  </div>
                  <span className="text-end font-semibold text-amber-900 dark:text-amber-100">${row.total}</span>
                </div>
              ))}
              <p className="text-[12px] text-amber-700 dark:text-amber-300 pt-1">
                {t('upgrade.compareCaption', { years: COMPARE_YEARS })}
              </p>
            </div>
          )}
        </div>

        <div className="p-6 space-y-5">
          {trigger && (
            <div className="flex items-start gap-3">
              <span className="shrink-0 w-11 h-11 rounded-md bg-amber-50 dark:bg-amber-950/50 text-pro flex items-center justify-center">
                {triggerIcon(trigger)}
              </span>
              <p className="text-sm font-semibold text-pn leading-relaxed">
                {/* The Spaces pitch reuses the Settings description, so the
                    sentence is written and translated once. */}
                {t(introKey(trigger), { desc: t('settings:appearance.spacesDesc') })}
              </p>
            </div>
          )}

          {purchaseError && (
            <div className="rounded-md border border-red-300 bg-red-50 dark:border-red-900/60 dark:bg-red-950/30 text-red-700 dark:text-red-300 text-sm p-3">
              {purchaseError}
            </div>
          )}

          <div className="space-y-2">
            <button
              type="button"
              disabled={(!configured && !demo) || loading}
              onClick={handleUpgrade}
              className="w-full rounded-md bg-amber-700 text-white hover:bg-amber-800 disabled:opacity-60 disabled:cursor-not-allowed inline-flex items-center justify-center gap-2 px-3 py-2.5 text-sm font-semibold transition"
            >
              <IconUpgrade size={16} onFill />
              {demo
                ? t('upgrade.ctaSignUp')
                : loading
                  ? t('upgrade.ctaOpening')
                  : t('upgrade.ctaUnlockPrice', { price: storePro ?? (nativeStore ? '…' : `$${ourPrice}`) })}
            </button>
            <p className="text-[11px] text-pn-muted text-center">{t('upgrade.subscriptionPitch')}</p>
          </div>

          <ul className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3">
            {FEATURES.map((f) => (
              <li key={f.labelKey} className="flex items-start gap-3 text-sm">
                <span className="shrink-0 mt-0.5 text-warning">{f.icon}</span>
                <span className="text-pn">{t(f.labelKey)}</span>
              </li>
            ))}
          </ul>

          {/* After the pitch, not before it: two outbound links above a
              payment CTA move a deciding reader off the decision. */}
          <HelpChip surface="upgrade" />

          {/* Legal links on the purchase surface. App Review guideline
              3.1.2 demands these for AUTO-RENEWABLE subscriptions, and Pro
              is a one-time non-consumable, so this is not strictly
              required here - it is on the Storage screen, which does sell
              subscriptions. Carried anyway: it costs one line, the two
              purchase surfaces should not disagree about where the terms
              are, and a reviewer looking for the links on the screen with
              the price finds them. Same labels as the About modal rather
              than a second pair of strings. */}
          <p className="text-[11px] text-pn-muted leading-relaxed">
            <a
              href="https://lifetimelabs.dev/terms/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-accent hover:underline"
            >
              {t('landing:about.termsOfService')}
            </a>
            {' · '}
            <a
              href="https://lifetimelabs.dev/privacy/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-accent hover:underline"
            >
              {t('landing:about.privacyPolicy')}
            </a>
          </p>
        </div>
      </div>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────
 * Icons
 * The shared upgrade icon is a simple rocket - reads as "ascend",
 * works at 16px in a button or 28px in a header.
 * ──────────────────────────────────────────────────────────────── */

export function IconUpgrade({ size = 18, onFill = false }: { size?: number; onFill?: boolean }) {
  // The rocket is the Pro mark and must read as "upgrade" whatever text
  // it sits next to, so its colour comes from the theme's own `--pn-pro`
  // token and NEVER from the surrounding text: `text-pro` is a fixed
  // per-theme value, not `currentColor`. Bronze on every LIGHT theme and
  // gold on every DARK one - the token is keyed to mode, because gold is
  // a light colour and measured 1.63:1 on plain white.
  //
  // The one exception is `onFill`: on a solid button or a hovered menu band
  // no Pro colour carries against the fill, so the rocket is white like the
  // button's own text.
  //
  // FILLED, not outline. A hairline of a light colour has almost no ink
  // in it at 11px; the solid body is what makes the mark legible.
  // Spec: ops/docs/design-decisions.md (Pro mark colour)
  return <RocketLaunch size={size} weight="fill" className={onFill ? 'text-white' : 'text-pro'} aria-hidden="true" />;
}

/** An icon-only Pro door's glyph with the rocket on its top-end corner (the
 *  collapsed rail's Folders button, the Work icon of the space switch). The
 *  rocket is anchored to the glyph, not the button, so it sits on the icon's
 *  own corner at every button size, and the glyph never moves. */
export function ProGlyph({ pro, children }: { pro: boolean; children: ReactNode }) {
  if (!pro) return <>{children}</>;
  return (
    <span className="relative flex">
      {children}
      <span className="pointer-events-none absolute -top-1.5 -end-1.5 flex" aria-hidden="true">
        <IconUpgrade size={9} />
      </span>
    </span>
  );
}

/** The rocket and the word, at the end of a menu row that opens a Pro
 *  feature: the mark `ContextMenu` draws for an item with `pro`. It keys off
 *  `!isPro`, never `proUnlocked`, so the demo still labels what it unlocks. */
export function ProMark() {
  return (
    <span className="shrink-0 inline-flex items-center gap-1 text-[11px] font-semibold normal-case tracking-normal text-accent">
      <IconUpgrade size={12} /> Pro
    </span>
  );
}

function IconDevices() {
  return <Monitor size={18} aria-hidden="true" />;
}

function IconStorage() {
  return <Database size={18} aria-hidden="true" />;
}

function IconLock() {
  return <Lock size={18} aria-hidden="true" />;
}

function IconPalette() {
  return <Palette size={18} aria-hidden="true" />;
}

function IconHistory() {
  return <ClockCounterClockwise size={18} aria-hidden="true" />;
}

function IconZen() {
  return <ArrowsOutSimple size={18} aria-hidden="true" />;
}

function IconFolders() {
  return <Folder size={18} aria-hidden="true" />;
}
