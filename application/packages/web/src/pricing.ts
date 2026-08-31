/**
 * Central pricing constants.
 * Update HERE when prices change - all UI references import from this file.
 *
 * Server-side mirrors (require manual migration / edge-function redeploy):
 *   - quota_limits_for_pubkey(): 50 MB free / 500 MB Pro (schema.sql)
 *   - admin_dashboard_overview(): early_supporters < threshold, remaining = limit - count
 *   - paddle-webhook/index.ts: ?? PRO_PRICE_CENTS fallback
 */

export const PRO_PRICE = 89;
export const EARLY_PRICE = 48;
export const EARLY_SUPPORTER_LIMIT = 480;
export const STORAGE_ADDON_PRICE = 4.80;   // per GB per year (base / 1 GB)

/**
 * Storage add-on packages. Pro-only, recurring yearly, additive to the
 * 500 MB Pro base. Bigger packages carry a built-in volume discount.
 * Spec: ops/docs/design-decisions.md (storage add-on packages)
 */
export type StoragePackage = { gb: number; pricePerYear: number };
export const STORAGE_PACKAGES: StoragePackage[] = [
  { gb: 1, pricePerYear: 4.80 },  // $4.80/GB
  { gb: 2, pricePerYear: 8.40 },  // $4.20/GB (~12% off)
  { gb: 5, pricePerYear: 18.00 }, // $3.60/GB (25% off)
];

/** Pro full price in cents - used to detect early supporters (amount_cents < this). */
// Spec: ops/docs/design-decisions.md (Pro full price = $89 = 8900 cents)
export const PRO_PRICE_CENTS = PRO_PRICE * 100;
