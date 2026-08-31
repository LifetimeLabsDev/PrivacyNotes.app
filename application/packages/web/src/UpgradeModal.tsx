import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useEscapeToClose } from './useEscapeToClose';
import {
  ArrowsOutSimple,
  ClockCounterClockwise,
  Database,
  Folder,
  Lock,
  Monitor,
  Palette,
  RocketLaunch,
  X,
} from './icons';
import { isPaddleConfigured, isBetaPricing } from './paddle';
import { startProCheckout, PRO_PRODUCT_ID } from './billing';
import { PRO_PRICE, EARLY_PRICE } from './pricing';
import { useStorePrices } from './storePrices';
import { isDemoMode, DEMO_APP_URL } from './demo';
import { withSource } from './campaignSource';
import { HelpChip } from './HelpChip';

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
  trigger?: 'lock' | 'protect' | 'history' | 'devices' | 'zen' | 'theme' | 'storage' | 'callout' | 'fileSize' | 'folders' | 'totp' | null;
};

const FEATURES: Array<{ icon: React.JSX.Element; labelKey: string }> = [
  { icon: <IconDevices />, labelKey: 'upgrade.features.devices' },
  { icon: <IconFolders />, labelKey: 'upgrade.features.folders' },
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
    case 'callout':
      return 'upgrade.intro.callout';
    case 'totp':
      return 'upgrade.intro.totp';
    case 'fileSize':
      // Reuse the already-translated upload upsell string (importExport ns)
      // so the file-size context doesn't need its own billing copy.
      return 'importExport:upload.proPitch';
    default:
      return 'upgrade.intro.default';
  }
}

export function UpgradeModal({ onClose, pubkey, onCheckoutComplete, trigger = null }: Props) {
  const { t } = useTranslation('billing');
  useEscapeToClose(onClose);
  const [loading, setLoading] = useState(false);
  const [purchaseError, setPurchaseError] = useState<string | null>(null);
  const configured = isPaddleConfigured();
  const beta = isBetaPricing();

  // What the App Store / Play will actually charge, already localized to the
  // user's storefront. Null on web, desktop, and any native build where the
  // lookup fails, in which case the Paddle USD figure below is rendered exactly
  // as it always was. Spec: ops/docs/design-decisions.md (fair global pricing)
  const storePrices = useStorePrices();
  const storePro = storePrices?.[PRO_PRODUCT_ID]?.formatted ?? null;

  const demo = isDemoMode();

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
      className="fixed inset-0 bg-black/40 dark:bg-black/40 flex items-center justify-center p-4 sm:p-6 z-50"
      onClick={onClose}
    >
      <div
        className="bg-surface-2/85 backdrop-blur-xl border border-divider/80 text-pn rounded-lg max-w-lg w-full max-h-[90vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Celebration header - one-time payment is good news, so this
            reads as a win, not an error. */}
        <div className="relative bg-amber-50/80 dark:bg-amber-950/50 rounded-t-lg px-6 pt-5 pb-5">
          <button
            onClick={onClose}
            aria-label={t('common:actions.close')}
            className="absolute top-4 end-4 text-amber-700/70 hover:text-amber-800 dark:text-amber-300/70 dark:hover:text-amber-200 transition p-1 -m-1"
          >
            <X size={18} />
          </button>

          <div className="flex items-center gap-2 text-[13px] font-semibold text-amber-700 dark:text-amber-300">
            <IconUpgrade size={16} />
            {t('upgrade.header')}
          </div>

          {beta ? (
            <div className="flex items-baseline gap-2 mt-2.5">
              <span className="text-4xl font-bold tracking-tight text-amber-900 dark:text-amber-100">{storePro ?? `$${EARLY_PRICE}`}</span>
              {/* The struck-through full price is a Paddle web figure. The stores
                  have no "was" price and sell on their own fixed tiers, so on a
                  native build it would compare the real charge against a number
                  the user can never be billed. Badge stays: the price genuinely
                  does rise later. */}
              {!storePro && (
                <span className="text-lg font-semibold line-through text-amber-400 dark:text-amber-600">${PRO_PRICE}</span>
              )}
              <span className="text-[11px] font-semibold text-amber-900 dark:text-amber-100 bg-amber-200 dark:bg-amber-800 rounded-md px-2 py-0.5">{t('upgrade.earlyAdopterBadge')}</span>
            </div>
          ) : (
            <div className="flex items-baseline gap-2 mt-2.5">
              <span className="text-4xl font-bold tracking-tight text-amber-900 dark:text-amber-100">{storePro ?? `$${PRO_PRICE}`}</span>
              <span className="text-sm font-medium text-amber-700/70 dark:text-amber-300/70">{t('upgrade.oneTime')}</span>
            </div>
          )}

          <p className="text-[13px] text-amber-700 dark:text-amber-300 mt-2">
            {t('upgrade.subscriptionPitch')}
          </p>
        </div>

        <div className="p-6 space-y-5">
          {trigger && (
            <p className="text-sm text-neutral-600 dark:text-neutral-400 leading-relaxed">
              {t(introKey(trigger))}
            </p>
          )}

          {purchaseError && (
            <div className="rounded-md border border-red-300 bg-red-50 dark:border-red-900/60 dark:bg-red-950/30 text-red-700 dark:text-red-300 text-sm p-3">
              {purchaseError}
            </div>
          )}

          <button
            type="button"
            disabled={(!configured && !demo) || loading}
            onClick={handleUpgrade}
            className="w-full rounded-md bg-amber-600 text-white hover:bg-amber-700 disabled:opacity-60 disabled:cursor-not-allowed inline-flex items-center justify-center gap-2 px-3 py-2.5 text-sm font-semibold transition"
          >
            <IconUpgrade size={16} />
            {demo ? t('upgrade.ctaSignUp') : loading ? t('upgrade.ctaOpening') : t('upgrade.ctaUnlock')}
          </button>

          <ul className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3">
            {FEATURES.map((f) => (
              <li key={f.labelKey} className="flex items-start gap-3 text-sm">
                <span className="shrink-0 mt-0.5 text-amber-600 dark:text-amber-400">{f.icon}</span>
                <span className="text-neutral-800 dark:text-neutral-200">{t(f.labelKey)}</span>
              </li>
            ))}
          </ul>

          {/* Web/desktop only. Both variants state OUR price in USD ("Pay $48
              once", "before it rises to $89"), which is the Paddle figure and
              not what a store charges, and the template hardcodes the dollar
              sign outside the interpolation so it cannot carry a storefront
              currency either. Showing it next to a real store price would put
              two different prices for the same product in one modal. Native
              gets its own comparison copy when localization lands. */}
          {!storePro && (
            <p className="text-[11px] text-neutral-500 dark:text-neutral-500 leading-relaxed border-t border-divider pt-3">
              {beta
                ? t('upgrade.comparisonBeta', { earlyPrice: EARLY_PRICE, proPrice: PRO_PRICE })
                : t('upgrade.comparison', { proPrice: PRO_PRICE })}
            </p>
          )}

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
          <p className="text-[11px] text-neutral-500 dark:text-neutral-500 leading-relaxed">
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

export function IconUpgrade({ size = 18 }: { size?: number }) {
  // The rocket is the Pro mark and must read as "upgrade" whatever text
  // it sits next to, so its colour comes from the theme's own `--pn-pro`
  // token and NEVER from the surrounding text: `text-pro` is a fixed
  // per-theme value, not `currentColor`. Bronze on every LIGHT theme and
  // gold on every DARK one - the token is keyed to mode, because gold is
  // a light colour and measured 1.63:1 on plain white.
  //
  // FILLED, not outline. A hairline of a light colour has almost no ink
  // in it at 11px; the solid body is what makes the mark legible.
  // Spec: ops/docs/design-decisions.md (Pro mark colour)
  return <RocketLaunch size={size} weight="fill" className="text-pro" aria-hidden="true" />;
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
