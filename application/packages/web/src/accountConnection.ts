import { detectPlatform, type Platform } from './devices';
import { isDemoMode } from './demo';
import { OAUTH_APP_LINK_REDIRECT } from './authStorage';
import { APP_ORIGIN } from './hosts';
import type { ConnectedAccountProvider } from './ConnectedAccounts';

type Proof = { code: string; codeVerifier: string };
type Failure = 'connectCancelled' | 'connectExpired' | 'popupBlocked' | 'connectFailed';
export class AccountConnectionError extends Error {
  constructor(readonly reason: Failure) { super(reason); }
}

export type AccountConnection = {
  platform: Platform;
  result: Promise<Proof>;
  acceptReturn: (url: string) => boolean;
  cancel: () => void;
};

const FLOW_TTL = 10 * 60 * 1000;

function base64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

/** This proof flow has no SDK client, session write, or persistent verifier.
 * An interrupted native process leaves the old account intact and costs one
 * retry. tests/accountConnection.test.ts exercises both callback transports. */
export function beginAccountConnection(provider: ConnectedAccountProvider, options: {
  signal: AbortSignal;
  /** Capture and check the actor before opening a provider page. The blank
   * popup itself opens synchronously so browsers retain the user gesture. */
  prepare: () => Promise<void>;
}): AccountConnection {
  const platform = detectPlatform();
  let settled = false;
  let verifier = '';
  let redirect: URL | null = null;
  let state = '';
  const cleanups: Array<() => void> = [];
  let resolve!: (proof: Proof) => void;
  let reject!: (error: Error) => void;
  const result = new Promise<Proof>((yes, no) => { resolve = yes; reject = no; });
  let popup: Window | null = null;
  function finish(proof?: Proof, error = new AccountConnectionError('connectFailed')) {
    if (settled) return;
    settled = true;
    for (const clean of cleanups) clean();
    verifier = '';
    try { popup?.close(); } catch { /* cross-origin window already closed */ }
    if (proof) resolve(proof);
    else reject(error);
  }
  function cancel() { finish(undefined, new AccountConnectionError('connectCancelled')); }
  function acceptReturn(raw: string): boolean {
    if (settled || !redirect || !verifier || !state || raw.length > 16384) return false;
    let incoming: URL;
    try { incoming = new URL(raw); } catch { return false; }
    if (incoming.origin !== redirect.origin || incoming.pathname !== redirect.pathname || incoming.hash
      || incoming.username || incoming.password || incoming.searchParams.getAll('pn_connect').length !== 1
      || incoming.searchParams.get('pn_connect') !== state) return false;
    if (incoming.searchParams.has('error')) {
      finish(undefined, new AccountConnectionError(incoming.searchParams.get('error') === 'access_denied' ? 'connectCancelled' : 'connectFailed'));
      return true;
    }
    const code = incoming.searchParams.get('code');
    if (incoming.searchParams.getAll('code').length !== 1 || !code || code.length > 8192 || /\s/.test(code)) return false;
    finish({ code, codeVerifier: verifier });
    return true;
  }
  const handle = { platform, result, acceptReturn, cancel };
  if (isDemoMode() || options.signal.aborted) { cancel(); return handle; }
  options.signal.addEventListener('abort', cancel, { once: true });
  cleanups.push(() => options.signal.removeEventListener('abort', cancel));
  const timer = setTimeout(() => finish(undefined, new AccountConnectionError('connectExpired')), FLOW_TTL);
  cleanups.push(() => clearTimeout(timer));

  if (platform === 'web') {
    // A fresh unnamed window cannot reuse another tab's account flow.
    try { popup = window.open('about:blank', '_blank', 'popup,width=520,height=720'); }
    catch { finish(undefined, new AccountConnectionError('popupBlocked')); return handle; }
    if (!popup) { finish(undefined, new AccountConnectionError('popupBlocked')); return handle; }
    const onMessage = (event: MessageEvent) => {
      if (!redirect || event.origin !== redirect.origin || event.source !== popup
        || !event.data || typeof event.data !== 'object' || event.data.type !== 'pn-account-connect'
        || typeof event.data.url !== 'string') return;
      acceptReturn(event.data.url);
    };
    window.addEventListener('message', onMessage);
    cleanups.push(() => window.removeEventListener('message', onMessage));
  }

  void (async () => {
    try {
      await options.prepare();
      if (settled) return;
      verifier = base64Url(crypto.getRandomValues(new Uint8Array(32)));
      state = base64Url(crypto.getRandomValues(new Uint8Array(32)));
      const challenge = base64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
      if (settled) return;
      redirect = new URL(platform === 'web' ? `${window.location.origin}/auth/connect`
        : platform === 'desktop' ? `${APP_ORIGIN}/auth/connect` : OAUTH_APP_LINK_REDIRECT);
      redirect.searchParams.set('pn_connect', state);
      const authorize = new URL(`${import.meta.env.VITE_SUPABASE_URL.replace(/\/$/, '')}/auth/v1/authorize`);
      if (authorize.protocol !== 'https:') throw new Error('invalid_auth_origin');
      authorize.searchParams.set('provider', provider);
      authorize.searchParams.set('redirect_to', redirect.toString());
      authorize.searchParams.set('code_challenge', challenge);
      authorize.searchParams.set('code_challenge_method', 's256');
      if (provider === 'google') authorize.searchParams.set('prompt', 'select_account');
      if (platform === 'web') {
        popup!.location.replace(authorize.toString());
      } else if (platform === 'ios') {
        const { invoke } = await import('@tauri-apps/api/core');
        if (settled) return;
        try {
          const callback = await invoke<string>('plugin:auth-session|start', {
            authUrl: authorize.toString(), callbackHost: redirect.hostname, callbackPath: redirect.pathname,
          });
          if (!settled && !acceptReturn(callback)) finish();
        } catch (error) {
          finish(undefined, new AccountConnectionError(error === 'user_cancelled' ? 'connectCancelled' : 'connectFailed'));
        }
      } else {
        if (platform === 'android') {
          const { onOpenUrl, getCurrent } = await import('@tauri-apps/plugin-deep-link');
          if (settled) return;
          const unlisten = await onOpenUrl((urls) => { for (const url of urls) if (acceptReturn(url)) break; });
          if (settled) { unlisten(); return; }
          cleanups.push(unlisten);
          const onResume = () => {
            if (document.hidden || settled) return;
            void getCurrent().then((urls) => { for (const url of urls ?? []) if (acceptReturn(url)) break; }).catch(() => {});
          };
          window.addEventListener('focus', onResume);
          document.addEventListener('visibilitychange', onResume);
          cleanups.push(() => { window.removeEventListener('focus', onResume); document.removeEventListener('visibilitychange', onResume); });
        }
        const { openUrl } = await import('@tauri-apps/plugin-opener');
        if (!settled) await openUrl(authorize.toString());
      }
    } catch {
      finish();
    }
  })();
  return handle;
}
