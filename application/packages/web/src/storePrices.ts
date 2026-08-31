/**
 * Localized store prices for native (App Store / Google Play) builds.
 *
 * WHY THIS EXISTS. `pricing.ts` holds the Paddle web prices, and the stores
 * charge different figures because their price points are fixed tiers: Pro is
 * $48 on Paddle and $49.99 on Apple, and storage is $4.80 / $8.40 / $18.00 on
 * Paddle against $4.99 / $8.99 / $17.99 on Apple. Rendering `pricing.ts` inside
 * a native build therefore puts one number on the tile and a different one in
 * the purchase sheet the tile opens, which is both a trust problem and a
 * plausible App Review rejection. The store is the only honest source of truth
 * for what a native user will actually be charged.
 *
 * WHY IT IS ALSO THE REGIONAL-PRICING GROUNDWORK. Apple and Google already
 * return `formattedPrice` converted to the user's storefront currency and
 * region. Once fair global pricing ships, native builds need no further work:
 * they follow the store automatically. Only web/desktop (Paddle) needs its own
 * currency handling. Spec: ops/docs/design-decisions.md (fair global pricing)
 *
 * FALLBACK IS ALWAYS SAFE. On web and desktop, and on any native build where
 * the lookup fails (offline, store unreachable, product not yet approved), this
 * module returns null and every caller falls back to the `pricing.ts` USD
 * figures it rendered before. Nothing here can leave a price blank.
 */

import { useEffect, useState } from 'react';
import { detectPlatform } from './devices';
import { PRO_PRODUCT_ID, storageProductId } from './billing';
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
let failed = false;

/** Only the two store platforms have an IAP plugin to ask. */
function isNativeStore(): boolean {
  const platform = detectPlatform();
  return platform === 'ios' || platform === 'android';
}

function toStorePrice(p: {
  formattedPrice?: string;
  priceAmountMicros?: number;
  priceCurrencyCode?: string;
}): StorePrice | null {
  // A product with no formatted price is useless to us: the whole point is to
  // render exactly what the store will charge, never a reconstruction of it.
  if (!p.formattedPrice) return null;
  return {
    formatted: p.formattedPrice,
    amount: typeof p.priceAmountMicros === 'number' ? p.priceAmountMicros / 1_000_000 : 0,
    currency: p.priceCurrencyCode || 'USD',
  };
}

/**
 * Fetch every product's price in one pass. Two calls because Pro is a
 * non-consumable (`inapp`) and the storage tiers are subscriptions (`subs`);
 * the stores will not return them together.
 */
async function loadStorePrices(): Promise<StorePriceMap | null> {
  if (cache) return cache;
  if (failed) return null;
  if (inflight) return inflight;
  if (!isNativeStore()) return null;

  inflight = (async () => {
    try {
      const iap = await import('@choochmeque/tauri-plugin-iap-api');
      const storageIds = STORAGE_PACKAGES.map((p) => storageProductId(p.gb));
      // Settled rather than all: a storage-tier outage must not blank the Pro
      // price, and vice versa. Each half degrades to its pricing.ts fallback.
      const [pro, storage] = await Promise.allSettled([
        iap.getProducts([PRO_PRODUCT_ID], 'inapp'),
        iap.getProducts(storageIds, 'subs'),
      ]);

      const map: StorePriceMap = {};
      for (const settled of [pro, storage]) {
        if (settled.status !== 'fulfilled') continue;
        for (const product of settled.value.products ?? []) {
          const price = toStorePrice(product);
          if (price) map[product.productId] = price;
        }
      }

      if (Object.keys(map).length === 0) {
        failed = true;
        return null;
      }
      cache = map;
      return map;
    } catch {
      // Never surface this: the fallback renders correct USD figures, and a
      // price lookup is not something the user asked for or can act on.
      failed = true;
      return null;
    } finally {
      inflight = null;
    }
  })();

  return inflight;
}

/**
 * Store prices, or null while loading and on every non-store platform.
 * Callers must treat null as "use the pricing.ts fallback", never as an error.
 */
export function useStorePrices(): StorePriceMap | null {
  const [prices, setPrices] = useState<StorePriceMap | null>(cache);

  useEffect(() => {
    if (cache || !isNativeStore()) return;
    let alive = true;
    void loadStorePrices().then((loaded) => {
      if (alive && loaded) setPrices(loaded);
    });
    return () => {
      alive = false;
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
