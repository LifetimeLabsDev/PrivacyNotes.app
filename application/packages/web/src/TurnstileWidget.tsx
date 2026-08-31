import { useEffect, useRef } from 'react';

/**
 * Cloudflare Turnstile widget - silent/low-friction bot challenge.
 * Loads the CF script lazily, renders a managed widget, and calls back
 * with the one-shot token.
 *
 * Mounted ON DEMAND only: callers attempt a tokenless sign-in first and
 * render this after the server refuses for want of a token. Nothing
 * here runs - and challenges.cloudflare.com is never contacted - until
 * the link-pubkey gate (web origins only) actually refuses one.
 * Spec: ops/docs/design-decisions.md (Turnstile is web-only, enforced at link-pubkey)
 *
 * Site key comes from `VITE_TURNSTILE_SITE_KEY`. If unset (local
 * preview without CF configured), the widget short-circuits to a
 * synthetic "dev-bypass" token, which callers must never forward as a
 * captchaToken - under enforced Supabase Auth CAPTCHA a keyless build
 * fails closed. Dev runs the REAL widget: `localhost` and
 * `tauri.localhost` are in the widget's hostname allowlist
 * (2026-08-01), so both `pnpm dev` and the Tauri wrappers get genuine
 * challenges and tokens.
 *
 * Usage:
 *   <TurnstileWidget onToken={setToken} />
 *   // token === null → not solved yet
 *   // token === 'dev-bypass' → dev mode, backend will reject
 *   // token === '<jwt-like>' → ready to submit
 */

declare global {
  interface Window {
    turnstile?: {
      render: (
        container: HTMLElement,
        opts: {
          sitekey: string;
          callback: (token: string) => void;
          /** Cloudflare passes its error code as the first argument
           *  (e.g. 110200 domain-not-allowed, 600xxx challenge could not
           *  execute). Without capturing it a failed challenge is
           *  indistinguishable from any other. */
          'error-callback'?: (code?: string) => void;
          'expired-callback'?: () => void;
          theme?: 'light' | 'dark' | 'auto';
          size?: 'normal' | 'compact' | 'flexible';
          /** Echoed by siteverify; the server refuses tokens minted for
           *  any other action, binding a token to the sign-in flow. */
          action?: string;
        },
      ) => string;
      remove: (widgetId: string) => void;
      reset: (widgetId?: string) => void;
    };
  }
}

const TURNSTILE_SCRIPT_URL =
  'https://challenges.cloudflare.com/turnstile/v0/api.js';

let scriptPromise: Promise<void> | null = null;

/**
 * Start loading the Cloudflare Turnstile script. Idempotent - only
 * fetches once per app load, so a widget that remounts for a fresh
 * challenge reuses the script already in the document.
 */
function loadTurnstileScript(): Promise<void> {
  if (scriptPromise) return scriptPromise;
  scriptPromise = new Promise((resolve, reject) => {
    if (typeof window === 'undefined') {
      reject(new Error('Turnstile requires a browser environment'));
      return;
    }
    if (window.turnstile) {
      resolve();
      return;
    }
    const existing = document.querySelector<HTMLScriptElement>(
      `script[src^="${TURNSTILE_SCRIPT_URL}"]`,
    );
    if (existing) {
      existing.addEventListener('load', () => resolve());
      existing.addEventListener('error', () =>
        reject(new Error('Turnstile script failed to load')),
      );
      return;
    }
    const script = document.createElement('script');
    script.src = `${TURNSTILE_SCRIPT_URL}?render=explicit`;
    script.async = true;
    script.defer = true;
    script.onload = () => resolve();
    script.onerror = () => {
      // Drop the dead element so a retry injects a fresh one instead of
      // listening on a script that will never fire again.
      script.remove();
      reject(new Error('Turnstile script failed to load'));
    };
    document.head.appendChild(script);
  });
  // A failed load must not poison every later mount (sign-in becomes
  // impossible until full reload / app restart): clear the cache on
  // rejection so the next call refetches.
  scriptPromise.catch(() => {
    scriptPromise = null;
  });
  return scriptPromise;
}

/**
 * How long a challenge may run before the caller is told it is not
 * coming. Cloudflare can hand a client an interactive challenge it
 * cannot complete (embedded webviews are the known case - see
 * ops/docs/supabase.md), and without a deadline the caller waits on a
 * token forever with no error and no way out. Generous: a real
 * interactive solve on a slow link takes a few seconds. Backlog #120.
 */
const CHALLENGE_TIMEOUT_MS = 20_000;

export function TurnstileWidget({
  onToken,
  onTimeout,
  className,
}: {
  onToken: (token: string | null) => void;
  /** Fired once if no token has arrived within CHALLENGE_TIMEOUT_MS.
   *  The widget keeps trying; this only lets the caller surface a
   *  recoverable error instead of an indefinite spinner. */
  onTimeout?: () => void;
  className?: string;
}) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const widgetIdRef = useRef<string | null>(null);
  const solvedRef = useRef(false);

  useEffect(() => {
    // Turnstile cannot complete a challenge on a non-http(s) origin
    // (Tauri's tauri:// protocol - the macOS, iOS and Linux wrappers):
    // the widget renders and spins forever with no callback and no
    // error. The web-only link-pubkey gate never challenges a native
    // client, so reaching this means the Supabase Auth CAPTCHA toggle
    // was flipped on by mistake - fail honestly and immediately instead
    // of hanging (#120's failure mode).
    const proto = window.location.protocol;
    if (proto !== 'http:' && proto !== 'https:') {
      console.error(
        '[TurnstileWidget] cannot run a challenge on origin',
        window.location.origin,
      );
      onToken(null);
      onTimeout?.();
      return;
    }

    const siteKey = import.meta.env.VITE_TURNSTILE_SITE_KEY as
      | string
      | undefined;

    // Keyless fallback only (env not configured). Dev is NOT special-
    // cased anymore: the old endless-loop-on-localhost issue was the
    // hostname allowlist missing `localhost`, fixed 2026-08-01.
    if (!siteKey) {
      console.warn(
        '[TurnstileWidget] No site key - emitting dev-bypass token.',
      );
      onToken('dev-bypass');
      return;
    }

    let cancelled = false;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    const deadline = setTimeout(() => {
      if (!cancelled && !solvedRef.current) {
        console.error('[TurnstileWidget] no token after', CHALLENGE_TIMEOUT_MS, 'ms');
        onTimeout?.();
      }
    }, CHALLENGE_TIMEOUT_MS);

    const attemptLoad = () => {
      loadTurnstileScript()
        .then(() => {
          if (cancelled || !containerRef.current || !window.turnstile) return;
          widgetIdRef.current = window.turnstile.render(containerRef.current, {
            sitekey: siteKey,
            callback: (token) => {
              solvedRef.current = true;
              onToken(token);
            },
            'error-callback': (code) => {
              // Surface the code: a silent failure here is the difference
              // between "this browser/origin cannot run the challenge"
              // (110xxx configuration, 600xxx execution) and a transient
              // network blip, and the user-visible symptom is identical.
              console.error('[TurnstileWidget] challenge error:', code ?? '(no code)');
              onToken(null);
              // Auto-retry: reset the widget so a fresh challenge starts
              // instead of leaving the user stuck on a dead widget.
              if (widgetIdRef.current && window.turnstile) {
                try { window.turnstile.reset(widgetIdRef.current); } catch { /* ignore */ }
              }
            },
            'expired-callback': () => {
              onToken(null);
              // Token expired (user took too long on PIN setup etc.) -
              // reset the widget to get a fresh challenge automatically.
              if (widgetIdRef.current && window.turnstile) {
                try { window.turnstile.reset(widgetIdRef.current); } catch { /* ignore */ }
              }
            },
            theme: 'auto',
            size: 'flexible',
            // Must match the gate's expected action in
            // supabase/functions/link-pubkey (captchaGate).
            action: 'link',
          });
        })
        .catch((err) => {
          console.error('[TurnstileWidget] load failed:', err);
          // Fail closed - no token is emitted, the caller's submit stays
          // disabled - but keep retrying while mounted so a transient
          // network drop self-heals instead of stranding sign-in until a
          // full reload (or app restart in the wrappers).
          onToken(null);
          if (!cancelled) {
            retryTimer = setTimeout(attemptLoad, 5000);
          }
        });
    };
    attemptLoad();

    return () => {
      cancelled = true;
      clearTimeout(deadline);
      if (retryTimer) clearTimeout(retryTimer);
      if (widgetIdRef.current && window.turnstile) {
        try {
          window.turnstile.remove(widgetIdRef.current);
        } catch {
          /* widget already gone; ignore */
        }
      }
    };
    // We intentionally only run this effect once - re-rendering would
    // tear down and recreate the widget, which kills an in-flight challenge.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return <div ref={containerRef} className={className} />;
}
