/** Store prices use the same offer as checkout; web prices are not store quotes. */
import { useEffect, useState } from 'react';
import { isNativeStoreBuild, PRO_PRODUCT_ID, storageProductId } from './billing';
import { STORAGE_PACKAGES } from './pricing';

export type StorePrice = {
  /** Store-formatted and already localized, e.g. "$17.99", "18,99 €", "¥2,800". */
  formatted: string;
  /** Numeric amount in the store's currency, for derived math (per GB, savings). */
  amount: number;
  /** ISO 4217 code, so derived amounts can be formatted in the same currency. */
  currency: string;
};

export type StorePriceMap = Record<string, StorePrice>;

/** Resolved once per session - store prices do not change mid-run. */
let cache: StorePriceMap | null = null;
let inflight: Promise<StorePriceMap | null> | null = null;

function toStorePrice(p: {
  formattedPrice?: string;
  priceAmountMicros?: number;
  priceCurrencyCode?: string;
  subscriptionOfferDetails?: Array<{ pricingPhases: Array<{ formattedPrice: string; priceAmountMicros: number; priceCurrencyCode: string }> }>;
}): StorePrice | null {
  // Android subscriptions quote their recurring price in the last phase of
  // the first offer, which is the offer billing.ts passes to checkout.
  const phases = p.subscriptionOfferDetails?.[0]?.pricingPhases;
  const quote = phases?.[phases.length - 1] ?? p;
  // A product with no formatted price is useless to us: the whole point is to
  // render exactly what the store will charge, never a reconstruction of it.
  if (!quote.formattedPrice) return null;
  return {
    formatted: quote.formattedPrice,
    amount: typeof quote.priceAmountMicros === 'number' ? quote.priceAmountMicros / 1_000_000 : 0,
    currency: quote.priceCurrencyCode || 'USD',
  };
}

/**
 * Fetch every product's price in one pass. Two calls because Pro is a
 * non-consumable (`inapp`) and the storage tiers are subscriptions (`subs`);
 * the stores will not return them together.
 */
async function loadStorePrices(): Promise<StorePriceMap | null> {
  if (cache && Object.keys(cache).length === STORAGE_PACKAGES.length + 1) return cache;
  if (inflight) return inflight;
  if (!isNativeStoreBuild()) return null;

  inflight = (async () => {
    try {
      const iap = await import('@choochmeque/tauri-plugin-iap-api');
      const storageIds = STORAGE_PACKAGES.map((p) => storageProductId(p.gb));
      // Settled rather than all: a storage-tier outage must not blank the Pro
      // price, and vice versa. Each half can resolve independently.
      const [pro, storage] = await Promise.allSettled([
        iap.getProducts([PRO_PRODUCT_ID], 'inapp'),
        iap.getProducts(storageIds, 'subs'),
      ]);

      const map: StorePriceMap = { ...cache };
      for (const settled of [pro, storage]) {
        if (settled.status !== 'fulfilled') continue;
        for (const product of settled.value.products ?? []) {
          const price = toStorePrice(product);
          if (price) map[product.productId] = price;
        }
      }

      if (Object.keys(map).length === 0) {
        return null;
      }
      cache = map;
      return map;
    } catch {
      // Keep unknown prices absent; callers must not substitute a web quote.
      return null;
    } finally {
      inflight = null;
    }
  })();

  return inflight;
}

/**
 * Store prices, or null while loading and on every non-store platform.
 * Native callers leave unknown prices blank; only non-store builds use web prices.
 */
export function useStorePrices(): StorePriceMap | null {
  const [prices, setPrices] = useState<StorePriceMap | null>(cache);

  useEffect(() => {
    if (!isNativeStoreBuild()) return;
    let alive = true;
    const refresh = () => {
      if (document.hidden) return;
      void loadStorePrices().then((loaded) => {
        if (alive && loaded) setPrices(loaded);
      });
    };
    refresh();
    window.addEventListener('focus', refresh);
    document.addEventListener('visibilitychange', refresh);
    return () => {
      alive = false;
      window.removeEventListener('focus', refresh);
      document.removeEventListener('visibilitychange', refresh);
    };
  }, []);

  return prices;
}

/**
 * DELIBERATELY NO MONEY FORMATTER HERE. Every currency string the user sees on
 * a store build is `StorePrice.formatted`, exactly as Apple or Google produced
 * it. Rebuilding one with Intl means choosing a symbol, its placement and its
 * rounding for a charge the store is quoting two lines below, and any
 * disagreement between the two is precisely the bug this module exists to
 * remove. Derived figures that have no store product behind them (per-GB rate,
 * "save X/yr") are therefore not rendered on store builds at all; the discount
 * is shown as a percentage, which needs no currency.
 */
