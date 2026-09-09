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

import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  openProCheckout,
  openStorageCheckout,
  getStoragePackages,
  initPaddleForTransaction,
  isBetaPricing,
} from './paddle';
import { EARLY_PRICE, PRO_PRICE } from './pricing';

type State = 'confirm' | 'opening' | 'done' | 'error';

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

  return (
    <div className="min-h-screen flex items-center justify-center bg-neutral-50 dark:bg-neutral-950 text-neutral-900 dark:text-neutral-100 p-6">
      <div className="max-w-sm w-full text-center space-y-3">
        {state === 'confirm' && purchase ? (
          <>
            <h1 className="text-lg font-semibold">{t('checkout.confirmTitle')}</h1>
            <p className="text-sm">
              {purchase.kind === 'pro'
                ? t('checkout.confirmPro', { price: purchase.price })
                : t('checkout.confirmStorage', { gb: purchase.gb, price: purchase.price })}
            </p>
            <p className="text-sm text-neutral-500 dark:text-neutral-400">
              {t('checkout.confirmAccount')}
            </p>
            <code className="block rounded bg-neutral-100 dark:bg-neutral-900 px-2.5 py-1.5 text-xs font-mono break-all">
              {purchase.pubkey}
            </code>
            <p className="text-sm text-neutral-500 dark:text-neutral-400">
              {t('checkout.confirmCheck')}
            </p>
            <button
              type="button"
              onClick={start}
              className="w-full rounded-lg bg-accent px-4 py-2.5 text-sm font-semibold text-white"
            >
              {t('checkout.confirmButton')}
            </button>
          </>
        ) : state === 'error' ? (
          <>
            <h1 className="text-lg font-semibold">{t('checkout.invalidTitle')}</h1>
            <p className="text-sm text-neutral-500 dark:text-neutral-400">
              {t('checkout.invalidBody')}
            </p>
          </>
        ) : state === 'done' ? (
          <>
            <h1 className="text-lg font-semibold">{t('checkout.completeTitle')}</h1>
            <p className="text-sm text-neutral-500 dark:text-neutral-400">
              {t('checkout.completeBody')}
            </p>
          </>
        ) : (
          <>
            <h1 className="text-lg font-semibold">{t('checkout.openingTitle')}</h1>
            <p className="text-sm text-neutral-500 dark:text-neutral-400">
              {t('checkout.openingBody')}
            </p>
          </>
        )}
      </div>
    </div>
  );
}
