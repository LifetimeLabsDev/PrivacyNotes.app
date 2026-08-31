/**
 * Paddle.js checkout integration.
 *
 * Loads the Paddle SDK, initialises it with the correct environment
 * (sandbox vs production), and opens the checkout overlay.
 *
 * The user's pubkey is passed as customData so the paddle-webhook edge
 * function can write it to pro_pubkeys on transaction.completed.
 *
 * After a successful checkout, the callback triggers a pro-status
 * re-check so the UI updates without requiring a page reload.
 */

import { STORAGE_PACKAGES, type StoragePackage } from './pricing';

// Paddle.js types (subset we use)
interface PaddleInstance {
  Environment: { set: (env: 'sandbox' | 'production') => void };
  Setup: (opts: { token: string }) => void;
  Checkout: {
    open: (opts: {
      items: Array<{ priceId: string; quantity: number }>;
      discountId?: string;
      customData?: Record<string, string>;
      successCallback?: (data: unknown) => void;
      closeCallback?: () => void;
    }) => void;
  };
  Initialize: (opts: {
    token: string;
    environment?: 'sandbox' | 'production';
    eventCallback?: (event: PaddleEvent) => void;
  }) => void;
}

interface PaddleEvent {
  name: string;
  data?: {
    status?: string;
    transaction_id?: string;
  };
}

declare global {
  interface Window {
    Paddle?: PaddleInstance;
  }
}

const PADDLE_SANDBOX = import.meta.env.VITE_PADDLE_SANDBOX === 'true';
const PADDLE_CLIENT_TOKEN = import.meta.env.VITE_PADDLE_CLIENT_TOKEN ?? '';
const PADDLE_PRO_PRICE_ID = import.meta.env.VITE_PADDLE_PRO_PRICE_ID ?? '';
const PADDLE_BETA_DISCOUNT_ID = import.meta.env.VITE_PADDLE_BETA_DISCOUNT_ID ?? '';
const PADDLE_STORAGE_1GB_PRICE_ID = import.meta.env.VITE_PADDLE_STORAGE_1GB_PRICE_ID ?? '';
const PADDLE_STORAGE_2GB_PRICE_ID = import.meta.env.VITE_PADDLE_STORAGE_2GB_PRICE_ID ?? '';
const PADDLE_STORAGE_5GB_PRICE_ID = import.meta.env.VITE_PADDLE_STORAGE_5GB_PRICE_ID ?? '';

const STORAGE_PRICE_IDS: Record<number, string> = {
  1: PADDLE_STORAGE_1GB_PRICE_ID,
  2: PADDLE_STORAGE_2GB_PRICE_ID,
  5: PADDLE_STORAGE_5GB_PRICE_ID,
};

export type StoragePackageOption = StoragePackage & { priceId: string };

/** Configured storage packages (those with a price ID set), smallest first. */
export function getStoragePackages(): StoragePackageOption[] {
  return STORAGE_PACKAGES
    .map((p) => ({ ...p, priceId: STORAGE_PRICE_IDS[p.gb] ?? '' }))
    .filter((p) => p.priceId);
}

let paddleLoaded = false;
let loadPromise: Promise<void> | null = null;

// Mutable ref so the eventCallback always calls the latest handler,
// even though Paddle.Initialize only runs once.
let latestOnComplete: (() => void) | null = null;

/** Load the Paddle.js SDK script. Idempotent. */
function loadPaddleScript(): Promise<void> {
  if (paddleLoaded && window.Paddle) return Promise.resolve();
  if (loadPromise) return loadPromise;

  loadPromise = new Promise<void>((resolve, reject) => {
    // Check if already in DOM (e.g. from a previous attempt)
    if (document.querySelector('script[src*="paddle.com"]')) {
      if (window.Paddle) {
        paddleLoaded = true;
        resolve();
      } else {
        // Script tag exists but Paddle isn't ready yet - wait for it
        const check = setInterval(() => {
          if (window.Paddle) {
            clearInterval(check);
            paddleLoaded = true;
            resolve();
          }
        }, 100);
        setTimeout(() => {
          clearInterval(check);
          reject(new Error('Paddle.js load timeout'));
        }, 10000);
      }
      return;
    }

    const script = document.createElement('script');
    script.src = 'https://cdn.paddle.com/paddle/v2/paddle.js';
    script.async = true;
    script.onload = () => {
      paddleLoaded = true;
      resolve();
    };
    script.onerror = () => reject(new Error('Failed to load Paddle.js'));
    document.head.appendChild(script);
  });

  return loadPromise;
}

/** Initialise Paddle with the client token. Must be called after loadPaddleScript. */
function initPaddle() {
  if (!window.Paddle) throw new Error('Paddle.js not loaded');

  // Environment must be set BEFORE Initialize - it's a separate call.
  if (PADDLE_SANDBOX) {
    window.Paddle.Environment.set('sandbox');
  }

  window.Paddle.Initialize({
    token: PADDLE_CLIENT_TOKEN,
    eventCallback: (event) => {
      if (import.meta.env.DEV) console.log('[paddle] event:', event.name);
      if (event.name === 'checkout.completed') {
        latestOnComplete?.();
      }
    },
  });
}

let initialized = false;

/**
 * Open the Paddle checkout overlay for the Pro one-time purchase.
 *
 * @param pubkey - the user's hex pubkey, forwarded as customData
 * @param onSuccess - called when the checkout completes successfully
 */
export async function openProCheckout(
  pubkey: string,
  onSuccess: () => void,
): Promise<void> {
  if (!PADDLE_CLIENT_TOKEN || !PADDLE_PRO_PRICE_ID) {
    console.error('Paddle env vars not configured');
    return;
  }

  await loadPaddleScript();

  if (!initialized) {
    initPaddle();
    initialized = true;
  }

  // Always update so the callback is fresh for this checkout session.
  latestOnComplete = onSuccess;

  // No attribution field here, deliberately. The source is cleared from
  // sessionStorage the moment it reaches the server at signup, and a
  // purchase always happens after signup - usually months later, in a
  // different tab - so anything read here would be null every time.
  // Reviving it would mean either keeping a marketing tag alive on the
  // app host (the one thing the design refuses) or letting the client
  // read its own account_origin row. Neither is worth it: revenue per
  // placement already falls out of account_origin joined to pro_pubkeys,
  // which is what admin_account_origin_summary() returns.
  // Spec: ops/docs/plans/partner-attribution.md (section 3, layer 3)
  window.Paddle!.Checkout.open({
    items: [{ priceId: PADDLE_PRO_PRICE_ID, quantity: 1 }],
    ...(PADDLE_BETA_DISCOUNT_ID ? { discountId: PADDLE_BETA_DISCOUNT_ID } : {}),
    customData: { pubkey },
  });
}

/**
 * Load + initialize Paddle.js WITHOUT opening a checkout ourselves.
 *
 * Used by the /checkout page when a Paddle-sent payment link lands
 * there with `?_ptxn=<transaction id>` (update-payment-method and
 * dunning emails for the storage subscriptions). Paddle.js watches the
 * URL for `_ptxn` and auto-opens the checkout for that transaction as
 * soon as it is initialized - our only job is to be initialized.
 * onComplete fires on checkout.completed, same as a normal checkout.
 * Spec: ops/docs/domain-split.md (Paddle default payment link -> /checkout)
 */
export async function initPaddleForTransaction(
  onComplete: () => void,
): Promise<void> {
  if (!PADDLE_CLIENT_TOKEN) {
    throw new Error('Paddle env vars not configured');
  }

  await loadPaddleScript();

  // Set the completion handler BEFORE initialize: Paddle.js may open
  // the _ptxn checkout the moment Initialize runs.
  latestOnComplete = onComplete;

  if (!initialized) {
    initPaddle();
    initialized = true;
  }
}

/** Whether Paddle checkout is configured (env vars present). */
export function isPaddleConfigured(): boolean {
  return !!(PADDLE_CLIENT_TOKEN && PADDLE_PRO_PRICE_ID);
}

/** Whether beta/early-supporter pricing is active. */
export function isBetaPricing(): boolean {
  return !!PADDLE_BETA_DISCOUNT_ID;
}

/** Whether the storage add-on checkout is configured (at least one package). */
export function isStorageConfigured(): boolean {
  return !!(PADDLE_CLIENT_TOKEN && getStoragePackages().length > 0);
}

/**
 * Open the Paddle checkout overlay for a storage add-on package.
 *
 * Used for the first storage purchase. Switching packages later goes
 * through the manage-storage-sub edge function, not a new checkout.
 *
 * @param pubkey - the user's hex pubkey, forwarded as customData
 * @param priceId - the chosen package's Paddle price ID
 * @param onSuccess - called when the checkout completes successfully
 */
export async function openStorageCheckout(
  pubkey: string,
  priceId: string,
  onSuccess: () => void,
): Promise<void> {
  if (!PADDLE_CLIENT_TOKEN || !priceId) {
    console.error('Paddle storage env vars not configured');
    return;
  }

  await loadPaddleScript();

  if (!initialized) {
    initPaddle();
    initialized = true;
  }

  latestOnComplete = onSuccess;

  window.Paddle!.Checkout.open({
    items: [{ priceId, quantity: 1 }],
    customData: { pubkey },
  });
}
