/**
 * Standalone /checkout page. The native (desktop) app can't run the Paddle
 * overlay in its webview (CSP blocks Paddle's CDN script - see billing.ts), so
 * it opens this page in the system browser, where Paddle works normally.
 *
 * Reads the purchase from the URL: `?product=pro&pubkey=...` or
 * `?product=storage&gb=2&pubkey=...`. The pubkey is forwarded to Paddle as
 * customData so the webhook attaches the purchase to the right account. We take
 * GB (not a price ID) for storage and resolve it to this build's live price ID,
 * so a sandbox-built desktop app can't push a sandbox ID into live Paddle.
 *
 * Rendered outside AuthProvider (main.tsx pathname routing) - it needs no
 * session, only the pubkey from the URL.
 *
 * Also Paddle's default-payment-link target: Paddle-sent emails (update
 * payment method, dunning for the storage subs) append `?_ptxn=<txn>`,
 * and Paddle.js auto-opens that transaction's checkout once initialized.
 * Spec: ops/docs/domain-split.md (Paddle default payment link -> /checkout)
 */

import { Children, useEffect, useState, type ReactNode } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import { Brand } from './Brand';
import { ArrowRight, CheckFat, Confetti, Sparkle } from './icons';
import {
  openProCheckout,
  openStorageCheckout,
  getStoragePackages,
  initPaddleForTransaction,
  isBetaPricing,
} from './paddle';
import { EARLY_PRICE, PRO_PRICE } from './pricing';

type State = 'confirm' | 'opening' | 'done' | 'error';

/** Query parameters an auth server's answer can carry. The page reads none of them. */
const AUTH_RESPONSE_PARAMS = [
  'code',
  'access_token',
  'refresh_token',
  'expires_in',
  'expires_at',
  'token_type',
  'provider_token',
  'provider_refresh_token',
  'type',
  'error',
  'error_code',
  'error_description',
  'state',
];

/**
 * The address this page may hold while Paddle's script runs, or null when
 * `href` already is that address. This is the one page that loads a payment
 * script, and that script never runs while the address holds a fragment or
 * the query parameters of a sign-in response, which is where an auth server
 * puts tokens and codes. Everything else in the query stays: `_ptxn` is how
 * Paddle.js finds its transaction, and the purchase parameters are read below.
 */
export function scrubbedCheckoutUrl(href: string): string | null {
  const url = new URL(href);
  const present = AUTH_RESPONSE_PARAMS.filter((name) => url.searchParams.has(name));
  if (present.length === 0 && !href.includes('#')) return null;
  for (const name of present) url.searchParams.delete(name);
  url.hash = '';
  return url.href;
}

/** What the link asks to buy, once the URL has been read and checked. */
type Purchase =
  | { kind: 'pro'; pubkey: string; price: number }
  | { kind: 'storage'; pubkey: string; gb: number; price: number; priceId: string };

export default function CheckoutLauncher() {
  const { t } = useTranslation('billing');
  const [state, setState] = useState<State>('opening');
  const [purchase, setPurchase] = useState<Purchase | null>(null);

  const onDone = () => setState('done');

  useEffect(() => {
    // First, before any branch below can load Paddle.
    const scrubbed = scrubbedCheckoutUrl(window.location.href);
    if (scrubbed) window.history.replaceState(null, '', scrubbed);

    const params = new URLSearchParams(window.location.search);
    const product = params.get('product');
    const pubkey = params.get('pubkey') ?? '';

    // Paddle-sent payment links land here with `?_ptxn=<transaction id>`
    // - no product, no pubkey, no session. Paddle.js auto-opens the
    // checkout for that transaction once initialized, so initialize and
    // get out of the way. Until the Paddle dashboard's default payment
    // link points at /checkout, these emails dead-ended on the homepage.
    // No confirm step here: the person is answering their own dunning
    // email about a subscription they already hold, and the transaction
    // names the account rather than the URL.
    // Spec: ops/docs/domain-split.md (Paddle default payment link -> /checkout)
    if (params.get('_ptxn')) {
      initPaddleForTransaction(onDone).catch(() => setState('error'));
      return;
    }

    if (!pubkey || (product !== 'pro' && product !== 'storage')) {
      setState('error');
      return;
    }

    // Nothing here proves the link came from the reader's own app: the
    // pubkey is a URL parameter, so a link somebody else wrote pays for
    // somebody else's account with this card. So the page names what is
    // being bought, at what price, and which account it lands on, and
    // waits for a click before any payment window opens.
    if (product === 'pro') {
      setPurchase({ kind: 'pro', pubkey, price: isBetaPricing() ? EARLY_PRICE : PRO_PRICE });
      setState('confirm');
      return;
    }

    const gb = Number(params.get('gb'));
    const pkg = getStoragePackages().find((p) => p.gb === gb);
    if (!pkg) {
      setState('error');
      return;
    }
    setPurchase({
      kind: 'storage',
      pubkey,
      gb: pkg.gb,
      price: pkg.pricePerYear,
      priceId: pkg.priceId,
    });
    setState('confirm');
  }, []);

  function start(): void {
    if (!purchase) return;
    setState('opening');
    const opened =
      purchase.kind === 'pro'
        ? openProCheckout(purchase.pubkey, onDone)
        : openStorageCheckout(purchase.pubkey, purchase.priceId, onDone);
    opened.catch(() => setState('error'));
  }

  // The page is always the cream paper of the homepage, whatever the system
  // theme: a purchase should read as a welcome, and the dark neutral of the
  // app shell read as a warning. The values are the washi light set.
  // Spec: ops/docs/design-decisions.md (washi landing palette)
  return (
    <div className="min-h-screen flex items-center justify-center bg-[#F7F1E1] text-[#1C1917] [--brand-ink:#1C1917] [--color-accent:#1E40AF] p-6">
      {state === 'confirm' && purchase ? (
        <div className="max-w-sm w-full overflow-hidden rounded-2xl border border-[#E0D7BD] bg-[#F7F1E1] text-center">
          <div className="relative bg-[#1E40AF] px-4 pt-5 pb-4 text-white">
            <Sprinkles />
            <div className="flex items-start justify-center gap-1" aria-hidden="true">
              <Confetti size={34} weight="fill" className="text-[#5DCAA5]" />
              <Sparkle size={20} weight="fill" className="text-[#ED93B1]" />
            </div>
            <h1 className="mt-1.5 text-xl font-semibold">
              {t('checkout.title')}
            </h1>
          </div>

          <div className="px-4 py-4">
            <p className="text-sm">
              <Trans
                t={t}
                i18nKey={purchase.kind === 'pro' ? 'checkout.proLine' : 'checkout.storageLine'}
                values={
                  purchase.kind === 'pro'
                    ? { price: purchase.price }
                    : { gb: purchase.gb, price: purchase.price.toFixed(2) }
                }
                components={{ brand: <Brand /> }}
              />
            </p>

            <ul className="mt-3 inline-flex flex-col gap-2 text-start">
              {purchase.kind === 'pro' ? (
                <>
                  <Benefit title={t('checkout.benefitDevices')} sub={t('checkout.benefitDevicesSub')} />
                  <Benefit title={t('checkout.benefitStorage')} sub={t('checkout.benefitStorageSub')} />
                  <Benefit title={t('checkout.benefitMore')} sub={t('checkout.benefitMoreSub')} />
                </>
              ) : (
                <>
                  <Benefit title={t('checkout.benefitRoom', { gb: purchase.gb })} sub={t('checkout.benefitRoomSub')} />
                  <Benefit title={t('checkout.benefitFileSize')} sub={t('checkout.benefitFileSizeSub')} />
                  <Benefit title={t('checkout.benefitCancel')} sub={t('checkout.benefitCancelSub')} />
                </>
              )}
            </ul>

            <div className="mt-4 border-t border-[#E0D7BD] pt-3 text-start text-xs leading-relaxed text-[#6A6152]">
              <p className="flex items-center gap-2">
                {t('checkout.yourAccount')}
                <span className="rounded-md bg-[#E8EAF2] px-2 py-0.5 font-mono text-sm text-[#1E40AF]">
                  {purchase.pubkey.slice(0, 8)}
                </span>
              </p>
              <p className="mt-1.5">
                <Trans
                  t={t}
                  i18nKey="checkout.matchAccount"
                  components={{ b: <MenuPath /> }}
                />
              </p>
              <details className="mt-1.5">
                <summary className="cursor-pointer text-[#1E40AF]">{t('checkout.showFullId')}</summary>
                <code className="mt-1.5 block break-all rounded-md bg-[#FCF8EC] px-2 py-1.5 font-mono text-[#1C1917]">
                  {purchase.pubkey}
                </code>
              </details>
            </div>
          </div>

          <div className="bg-[#1E40AF] px-4 pt-4 pb-3">
            <button
              type="button"
              onClick={start}
              className="group flex w-full items-center justify-center gap-2.5 rounded-xl bg-white px-4 py-3 text-[15px] font-semibold text-[#1E40AF] transition duration-200 hover:-translate-y-0.5 hover:ring-[3px] hover:ring-[#5DCAA5] focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-[#5DCAA5] active:translate-y-0 active:scale-[0.98] motion-reduce:transition-none motion-reduce:hover:translate-y-0"
            >
              {t('checkout.confirmButton')}
              <span className={ARROW_NUDGE}>
                <ArrowRight size={14} weight="bold" aria-hidden="true" />
              </span>
            </button>
            <ol aria-label={t('checkout.stepsLabel')} className="mt-2.5 flex items-center justify-center gap-1.5 text-xs text-[#B5D4F4]">
              <li className="text-white" aria-current="step">1 {t('checkout.stepCheck')}</li>
              <li aria-hidden="true">›</li>
              <li>2 {t('checkout.stepPay')}</li>
              <li aria-hidden="true">›</li>
              <li>3 {t('checkout.stepPro')}</li>
            </ol>
          </div>
        </div>
      ) : (
        <div className="max-w-sm w-full text-center space-y-3">
          {state === 'error' ? (
            <>
              <h1 className="text-lg font-semibold">{t('checkout.invalidTitle')}</h1>
              <p className="text-sm text-[#6A6152]">{t('checkout.invalidBody')}</p>
            </>
          ) : state === 'done' ? (
            <>
              <h1 className="text-lg font-semibold">{t('checkout.completeTitle')}</h1>
              <p className="text-sm text-[#6A6152]">{t('checkout.completeBody')}</p>
            </>
          ) : (
            <>
              <h1 className="text-lg font-semibold">{t('checkout.openingTitle')}</h1>
              <p className="text-sm text-[#6A6152]">{t('checkout.openingBody')}</p>
            </>
          )}
        </div>
      )}
    </div>
  );
}

// The arrow nudges toward the reading direction on hover; the rtl variant
// flips it, so the physical axis is deliberate.
const ARROW_NUDGE =
  'flex size-6 items-center justify-center rounded-full bg-[#1E40AF] text-white transition-transform duration-300 ease-[cubic-bezier(.34,1.56,.64,1)] ' +
  'group-hover:translate-x-1 rtl:group-hover:-translate-x-1 motion-reduce:group-hover:translate-x-0'; // rtl-ok: flipped by the rtl variant

/**
 * A menu path in bold, drawn with the chevron the settings breadcrumbs use.
 * The catalog keeps the plain " > " form, because that is the form the
 * menu-path check reads in every locale.
 */
function MenuPath({ children }: { children?: ReactNode }) {
  return (
    <strong className="font-semibold text-[#1C1917]">
      {Children.map(children, (c) => (typeof c === 'string' ? c.replaceAll(' > ', ' \u203A ') : c))}
    </strong>
  );
}

function Benefit({ title, sub }: { title: string; sub: string }) {
  return (
    <li className="flex items-start gap-2">
      <span className="mt-0.5 flex size-[18px] shrink-0 items-center justify-center rounded-full bg-[#10B981] text-white" aria-hidden="true">
        <CheckFat size={11} weight="fill" />
      </span>
      <span className="text-sm leading-snug">
        <span className="block font-semibold">{title}</span>
        <span className="block text-xs text-[#6A6152]">{sub}</span>
      </span>
    </li>
  );
}

/** A few pieces of confetti in the header. Decoration only. */
const SPRINKLES = [
  'top-3 start-4 h-2.5 w-1.5 rotate-[25deg] bg-[#5DCAA5]',
  'top-11 start-11 size-1.5 rounded-full bg-[#ED93B1]',
  'top-4 end-5 h-2.5 w-1.5 -rotate-[30deg] bg-white',
  'top-12 end-11 size-1.5 rounded-full bg-[#5DCAA5]',
  'top-16 start-6 h-2 w-1 rotate-[60deg] bg-white/70',
  'top-16 end-6 h-2 w-1 rotate-[15deg] bg-[#ED93B1]',
];

function Sprinkles() {
  return (
    <>
      {SPRINKLES.map((c) => (
        <span key={c} aria-hidden="true" className={`absolute rounded-[2px] ${c}`} />
      ))}
    </>
  );
}
