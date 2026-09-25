import {
  useEffect,
  type Dispatch,
  type SetStateAction,
} from 'react';
import {
  bytesToHex,
  deriveSigningKey,
  isValidPhrase,
  phraseToSeed,
  type SupabaseClient,
} from '@notes/shared';
import {
  trustAwareStorage,
  setTrustedDevice,
} from './trustStorage';
import { detectPlatform, invokeFnWithRetry, type Platform } from './devices';
import { appLockArmed, isWrappedEnvelope, persistStoredPhrase } from './phraseAtRest';
import { APP_ORIGIN, isApexHost } from './hosts';
import {
  PHRASE_STORAGE_KEY,
  OAUTH_FLAG_KEY,
  OAUTH_APP_LINK_REDIRECT,
  OAUTH_DESKTOP_RETURN,
  switchWouldWipe,
} from './authStorage';
import { logAuthEvent } from './authDiag';
import { consumeOAuthPending, markOAuthPending } from './oauthPending';
import type { AuthState, AuthMethod, OAuthProvider } from './auth';

/**
 * A signed-in install holds a phrase under PHRASE_STORAGE_KEY, either plain
 * or as a wrapped envelope. Presence and shape only; the value never opens
 * here. Shared by the native deep-link gate and the cold-start replay skip,
 * so both answer "is someone signed in" the same way.
 */
function hasStoredPhrase(): boolean {
  const stored = trustAwareStorage.getItem(PHRASE_STORAGE_KEY);
  return !!stored && (isWrappedEnvelope(stored) || isValidPhrase(stored));
}

/**
 * True when `phrase` derives `expectedPubkey`, i.e. the phrase provably
 * belongs to the account that carries that key. A value the derivation
 * refuses - the wrong word count throws in phraseToSeed - is not a match
 * either, so anything unprovable answers false.
 */
export async function custodialPhraseMatchesAccount(
  phrase: string,
  expectedPubkey: string,
): Promise<boolean> {
  try {
    const { publicKey } = await deriveSigningKey(phraseToSeed(phrase));
    return bytesToHex(publicKey) === expectedPubkey;
  } catch {
    return false;
  }
}

/**
 * The redirect a native build asks the auth server to return to.
 *
 * Android and iOS get the same https address: on Android an App Link, which
 * the operating system hands only to the package and signing certificate
 * named in assetlinks.json; on iOS the callback the in-app auth sheet
 * completes on, which iOS grants only to the app whose entitlement names the
 * host. Desktop gets a page on our own origin, because no desktop operating
 * system can say which application owns a custom scheme; the person carries
 * the code back from there.
 *
 * Every one of these is a return address that no other application can
 * silently receive. No native build asks for the custom scheme.
 * Spec: ops/docs/plans/oauth-redirect-binding-handoff.md (section 8)
 */
export function nativeOAuthRedirect(platform: Platform): string {
  if (platform === 'desktop') return OAUTH_DESKTOP_RETURN;
  return OAUTH_APP_LINK_REDIRECT;
}

/**
 * True when a URL the OS handed the app is the OAuth callback this platform
 * asked for.
 *
 * The deep-link plugin emits every opened URL, and the desktop build claims
 * Markdown files, so a note opened during a pending sign-in arrives at the
 * same handler. The expected form comes from the redirect the app gives
 * providers, so the two cannot drift apart: one exact https origin and path,
 * with the code in the query. A custom-scheme URL has no origin and never
 * matches, so the scheme the builds still register cannot reach the exchange
 * on any platform. Desktop asks for a page rather than a deep link, so no
 * callback URL reaches this function there at all.
 */
export function isOAuthCallbackUrl(rawUrl: string, platform: Platform): boolean {
  try {
    const url = new URL(rawUrl);
    const expected = new URL(nativeOAuthRedirect(platform));
    return url.origin === expected.origin && url.pathname === expected.pathname;
  } catch {
    return false;
  }
}

export function useOAuthFlows({
  authenticateWithPhrase,
  askAccountSwitch,
  setAuth,
  supabase,
  authInFlight,
  userAuthGen,
  vaultOpenRef,
}: {
  authenticateWithPhrase: (
    phrase: string,
    method: AuthMethod,
    custodial?: boolean,
    oauthSession?: { accessToken: string; authUid: string },
    freshVault?: boolean,
    captchaToken?: string,
  ) => Promise<boolean>;
  /**
   * Asks the person whether the account already on this device may be
   * cleared. The provider renders it, because this hook runs inside an
   * OAuth callback and has no screen of its own.
   */
  askAccountSwitch: () => Promise<boolean>;
  setAuth: Dispatch<SetStateAction<AuthState>>;
  supabase: SupabaseClient;
  authInFlight: { current: boolean };
  userAuthGen: { current: number };
  /** True while the vault is open on this install. See auth.tsx. */
  vaultOpenRef: { current: boolean };
}) {
  function registerOAuthListener(): () => void {
    // No stored phrase - listen for an OAuth redirect-return session.
    // With detectSessionInUrl: true, supabase-js exchanges the PKCE
    // ?code= (and still consumes a legacy #access_token fragment)
    // asynchronously during _initialize(). A one-shot getSession() call
    // races with that and often returns null. onAuthStateChange fires
    // reliably once the return is consumed.
    let handled = false;
    // Armed when INITIAL_SESSION(null) arrives while an access_token hash
    // is still unconsumed (see that branch below). If the token turns out
    // to be dead (expired redirect, replayed link), supabase-js finishes
    // its init with an error and never fires another event - without a
    // fallback the user hangs on the loading screen forever. Any later
    // auth event clears the timer.
    let callbackFallbackTimer: ReturnType<typeof setTimeout> | null = null;
    // Must exceed the worst realistic token-validation round-trip: cold
    // connections to the sync API were measured at ~3.5 s, so give the
    // pending validation a generous margin before declaring it dead.
    // 12s -> 20s at the 2026-08-25 session audit: on high-latency lossy
    // links (satellite, throttled mobile) a merely slow validation was
    // demoted to the sign-in options mid-flow, which reads as a failed
    // sign-in. A dead token costs 8 more seconds of loading screen; a
    // false demote costs the user's confidence. `handled` stays false
    // either way, so a late SIGNED_IN still wins after the demote.
    const OAUTH_CALLBACK_FALLBACK_MS = 20_000;
    const { data: { subscription } } = supabase.auth.onAuthStateChange(
      (event, session) => {
        // Any auth event means supabase-js is alive and progressing, so
        // the pending-callback fallback is no longer needed. The branch
        // that arms it re-arms on every run.
        if (callbackFallbackTimer) {
          clearTimeout(callbackFallbackTimer);
          callbackFallbackTimer = null;
        }
        // Re-arm on sign-out. Without this, the `handled` latch below stays
        // true for the whole session, so switching accounts (sign out, then
        // sign in with a different provider/account) drops the second
        // SIGNED_IN and the user is stuck on "Redirecting". Native OAuth
        // surfaces this hardest because each sign-in is a fresh deep link.
        if (event === 'SIGNED_OUT') {
          handled = false;
          return;
        }
        if (handled) return;
        const provider = session?.user?.app_metadata?.provider;
        const eligible = provider === 'google' || provider === 'apple' || provider === 'github';
        if (event === 'SIGNED_IN' && session && eligible) {
          // Native owns OAuth hydration in the deep-link handler
          // (handleNativeOAuthCallback), which is always registered even
          // when this boot-path listener is not. Web hydrates here.
          if (detectPlatform() !== 'web') return;
          handled = true;
          // Strip OAuth hash fragment - supabase-js usually consumes it
          // to a bare "#", but on slow connections or browser quirks the
          // full #access_token=... can persist. See gap #59.
          const h = window.location.hash;
          if (h === '' || h === '#' || h.includes('access_token=')) {
            history.replaceState(null, '', window.location.pathname + window.location.search || '/');
          }
          hydrateFromOAuthSession(session.access_token, /*trust*/ true).catch(
            (err) => {
              console.error('OAuth session hydrate failed:', err);
              // Re-arm so a retry can hydrate without restarting.
              handled = false;
              // Loud, not silent: falling back to onboarding here made
              // an unexpected hydrate failure look like a signed-out
              // state. Spec: ops/docs/domain-split.md (pre-cutover gate)
              setAuth({ status: 'oauth_hydrate_failed', trust: true });
            },
          );
        } else if (event === 'INITIAL_SESSION' && !session) {
          // A PKCE ?code= still in the URL here is dead: supabase-js
          // exchanges it during init, before this event, so a code that
          // survived was refused (no verifier for it in this storage, or
          // the server rejected it) and no SIGNED_IN follows. Drop it from
          // the address bar and say so, loudly: the user came back from
          // the provider, and a silent sign-in screen reads as "nothing
          // happened".
          if (typeof window !== 'undefined' && new URLSearchParams(window.location.search).has('code')) {
            logAuthEvent('auth:oauth-code-unexchanged');
            const url = new URL(window.location.href);
            url.searchParams.delete('code');
            history.replaceState(null, '', url.pathname + url.search + url.hash);
            handled = true;
            setAuth({ status: 'oauth_hydrate_failed', trust: true });
            return;
          }
          // supabase-js finished init with no session - but if the URL
          // hash still has `access_token=...`, the OAuth fragment hasn't
          // been consumed yet. SIGNED_IN will fire shortly. Don't lock
          // the handler with `handled = true` here, otherwise the user
          // gets stranded on onboarding until they refresh manually.
          // See gap #20.
          if (typeof window !== 'undefined' && window.location.hash.includes('access_token=')) {
            // ...unless SIGNED_IN never comes: an expired or replayed
            // token makes supabase-js finish init with an error and go
            // silent, which used to strand the user on the loading
            // screen indefinitely. Fall back to onboarding after a
            // deadline. `handled` stays false so a miraculously late
            // SIGNED_IN can still hydrate and win.
            callbackFallbackTimer = setTimeout(() => {
              callbackFallbackTimer = null;
              if (handled) return;
              console.warn('[auth] OAuth callback never produced a session - showing sign-in options.');
              if (window.location.hash.includes('access_token=')) {
                history.replaceState(null, '', window.location.pathname + window.location.search || '/');
              }
              setAuth({ status: 'onboarding' });
            }, OAUTH_CALLBACK_FALLBACK_MS);
            return;
          }
          // Native (Tauri): the OAuth token never rides in
          // window.location.hash - it arrives later via the
          // privacynotes:// deep link as a SIGNED_IN event. Show the login
          // screen now, but do NOT lock `handled`, or that later SIGNED_IN
          // hits the `if (handled) return` guard above and the user stays
          // stuck on "Redirecting..." (session saved, UI never advances
          // until a manual restart).
          if (detectPlatform() !== 'web') {
            setAuth({ status: 'onboarding' });
            return;
          }
          handled = true;
          setAuth({ status: 'onboarding' });
        } else if (event === 'INITIAL_SESSION' && session && eligible) {
          // Session was already in storage (e.g. second reload after
          // OAuth). Process it the same way.
          handled = true;
          const h2 = window.location.hash;
          if (h2 === '' || h2 === '#' || h2.includes('access_token=')) {
            history.replaceState(null, '', window.location.pathname + window.location.search || '/');
          }
          hydrateFromOAuthSession(session.access_token, /*trust*/ true).catch(
            (err) => {
              console.error('OAuth session hydrate failed:', err);
              // Re-arm so a retry can hydrate without restarting.
              handled = false;
              // Loud, not silent: falling back to onboarding here made
              // an unexpected hydrate failure look like a signed-out
              // state. Spec: ops/docs/domain-split.md (pre-cutover gate)
              setAuth({ status: 'oauth_hydrate_failed', trust: true });
            },
          );
        } else if (event === 'INITIAL_SESSION') {
          // Non-OAuth session (e.g. stale anonymous session with no
          // stored phrase). Treat as onboarding.
          handled = true;
          setAuth({ status: 'onboarding' });
        }
      },
    );

    return () => {
      subscription.unsubscribe();
      if (callbackFallbackTimer) clearTimeout(callbackFallbackTimer);
    };
  }

  /**
   * Handle a Supabase OAuth session returned by Google/Apple redirect.
   *
   * Three branches:
   *
   *   (a) Existing OAuth user with custodial phrase stored on server:
   *       fetch the phrase via get-custodial-phrase, authenticate
   *       automatically. 1-click sign-in on any device.
   *
   *   (b) Existing OAuth user without custodial phrase (self-custody):
   *       route to phrase entry / QR sign-in. Legacy oauth-phrase
   *       fallback for pre-v0.152.0 users still applies during the
   *       migration window.
   *
   *   (c) New OAuth user (no pubkey on file): park in the
   *       `oauth_custody_choice` state so the onboarding UI can
   *       present the custodial vs self-custody choice.
   *
   * Spec: ops/docs/custodial-key-spec.md, ops/docs/oauth-zk-fix.md
   */
  async function hydrateFromOAuthSession(accessToken: string, trust: boolean) {
    // Abort marker: true once the user has started their own phrase
    // sign-in (or one is mid-flight). Checked before every side effect
    // below - a superseded hydration must neither sign out the session
    // the user's handshake is riding on, nor stomp the auth state their
    // flow is about to set. See userAuthGen above.
    const genAtStart = userAuthGen.current;
    const superseded = () =>
      authInFlight.current || userAuthGen.current !== genAtStart;

    setTrustedDevice(trust);

    // Existing user? Check app_metadata.pubkey, written by link-pubkey
    // on first signup. This claim is service-role-only (not user-
    // writable) so it's trustworthy.
    const { data: { session } } = await supabase.auth.getSession();
    const existingPubkey = session?.user?.app_metadata?.pubkey;
    const authUid = session?.user?.id;

    if (existingPubkey && authUid) {
      // --- Branch (a): try custodial phrase retrieval first ---
      // Spec: ops/docs/custodial-key-spec.md (custodial to self-custody is one-way, never back)
      //
      // Failure discipline, because the silent fall-through orphaned
      // real accounts: only a SUCCESSFUL `custodial: false`
      // answer may fall through to branches (b)/(c). A failed lookup
      // means we cannot know whether this user is custodial, and a
      // failed custodial authentication means we KNOW they are - in
      // both cases falling through offers an existing user a fresh
      // account (custody choice) or a phrase they never saw. Surface
      // the loud, retryable oauth_hydrate_failed state instead.
      let custodialResult: { custodial?: boolean; phrase?: string } | null =
        null;
      try {
        const { data: custodialData, error: custodialErr } =
          await invokeFnWithRetry(supabase, 'get-custodial-phrase', {
            headers: { Authorization: `Bearer ${accessToken}` },
          });
        if (superseded()) {
          console.info('[oauth] hydrate superseded by manual sign-in, aborting');
          return;
        }
        if (custodialErr) throw custodialErr;
        custodialResult = custodialData as { custodial?: boolean; phrase?: string } | null;
      } catch (err) {
        console.warn('get-custodial-phrase failed:', err);
        if (superseded()) {
          console.info('[oauth] hydrate superseded by manual sign-in, aborting');
          return;
        }
        setAuth({ status: 'oauth_hydrate_failed', trust });
        return;
      }
      if (custodialResult?.custodial && custodialResult.phrase) {
        const custodialPhrase = custodialResult.phrase;
        try {
          // The phrase has to be THIS account's phrase, and nothing in the
          // answer says so: derive its pubkey and require it to equal the
          // claim read above. A foreign phrase takes the handshake through
          // the owner mismatch, which removes the PIN-wrapped blob that is
          // an app-lock device's only copy of the real phrase, and then
          // lands on disk as this install's identity. A genuine custodial
          // phrase always derives its own account key, so the check costs
          // that user nothing.
          if (!(await custodialPhraseMatchesAccount(custodialPhrase, existingPubkey))) {
            console.warn('[oauth] custodial phrase does not derive this account key');
            if (superseded()) {
              console.info('[oauth] hydrate superseded by manual sign-in, aborting');
              return;
            }
            setAuth({ status: 'oauth_hydrate_failed', trust });
            return;
          }
          // One click signs in, and on a device holding somebody else's
          // account that click also clears it. Ask first, and treat a
          // no as a return to the sign-in options rather than an error:
          // nothing failed, the person declined.
          if (await switchWouldWipe(custodialPhrase) && !(await askAccountSwitch())) {
            setAuth({ status: 'onboarding' });
            return;
          }
          // Custodial user - 1-click sign-in! Pass the OAuth session
          // explicitly so _authenticateWithPhrase never falls through
          // to signInAnonymously (#131).
          const ran = await authenticateWithPhrase(custodialPhrase, 'oauth', true, {
            accessToken,
            authUid,
          });
          // A swallowed call (mutex held by a concurrent handshake)
          // must not persist anything: the phrase write below lands in
          // shared storage and would stomp the account the OTHER
          // handshake is signing in. That flow owns the UI - stand
          // down. Same discipline as completeCustodyChoice (v0.262.3).
          if (!ran) {
            console.warn('[oauth] custodial sign-in skipped: another sign-in is in progress');
            return;
          }
          // Arming the app lock strips the stored phrase on purpose, so
          // that the PIN or the fingerprint really is the only door.
          // Writing it back here would re-open that door on a device
          // whose owner closed it, and nothing would say so. The phrase
          // sign-in has always asked; this path reaches the same write.
          if (appLockArmed()) {
            logAuthEvent('auth:phrase-persist-skipped-applock');
          } else {
            logAuthEvent('auth:phrase-persisted', { by: 'oauth-hydrate' });
            await persistStoredPhrase(custodialPhrase);
          }
          trustAwareStorage.setItem(OAUTH_FLAG_KEY, '1');
        } catch (err) {
          // The server just proved this user IS custodial - a failure
          // here (register-device, link-pubkey, network) must NEVER
          // fall through to custody choice or phrase entry.
          console.warn('[oauth] custodial authentication failed:', err);
          if (superseded()) {
            console.info('[oauth] hydrate superseded by manual sign-in, aborting');
            return;
          }
          // device_limit_reached is a legitimate terminal state that
          // authentication may have set before throwing - keep it.
          setAuth((prev) =>
            prev.status === 'device_limit_reached'
              ? prev
              : { status: 'oauth_hydrate_failed', trust },
          );
        }
        return;
      }

      // --- Branch (b): self-custody existing user ---
      // Before routing to phrase entry, verify the user actually has
      // data. Supabase may soft-delete auth.users and resurrect the row
      // (with its app_metadata.pubkey) when the same OAuth identity re-
      // signs up. A resurrected user has a pubkey but zero notes/devices
      // - showing "enter your phrase" would be a dead end. Treat them as
      // a new user instead.
      const { count: noteCount, error: countErr } = await supabase
        .from('notes')
        .select('*', { count: 'exact', head: true })
        .eq('user_pubkey', existingPubkey);
      // Fail closed: only take the zombie branch on a SUCCESSFUL count
      // of zero. A transient error (Cloudflare 503, timeout) makes the
      // count null, and treating that as zombie routed a returning
      // self-custody user to "start fresh" - misleading and scary. On
      // error, fall through to phrase entry: the pubkey claim already
      // says this user is established, and a genuine zombie landing on
      // phrase entry is a recoverable dead end (Back button), unlike a
      // real user landing on custody choice.
      if (countErr) {
        console.warn('[oauth] zombie-check count failed, assuming existing user:', countErr.message);
      }
      if (superseded()) {
        console.info('[oauth] hydrate superseded by manual sign-in, aborting');
        return;
      }
      // noteCount === null is NOT a successful zero: postgrest-js fills
      // count only from the content-range header, and a 2xx with that
      // header missing or mangled (proxy, HEAD-request quirk) yields
      // {count: null, error: null}. Routing null to the zombie branch
      // contradicted the fail-closed comment above and sent an EXISTING
      // self-custody user to the fresh-account screen - the
      // data-orphaning footgun this block exists to prevent. Session
      // audit 2026-08-25.
      if (!countErr && noteCount === 0) {
        // Zombie account: pubkey on file but no data to unlock.
        // Redirect to custody choice so they can start fresh.
        setAuth({
          status: 'oauth_custody_choice',
          accessToken,
          authUid,
        });
        return;
      }

      // Genuine self-custody user on a new device - route to phrase entry.
      //
      // The OAuth session is deliberately KEPT alive here. It used to be
      // torn down with signOut({scope:'local'}) before handing off, and
      // that one line littered `auth.users` with orphaned anonymous
      // rows, many per affected vault: with no session left,
      // signInWithPhrase fell through to signInAnonymously(),
      // link-pubkey bound the user's pubkey to a brand new anonymous
      // row, and the Google row they actually signed in with was
      // abandoned. Every one of those rows is a live credential for the
      // same vault, and none of them can reach custodial mode, because
      // store-custodial-phrase requires a provider. Backlog #115.
      //
      // Do not "clean this up" by restoring the signOut. A local
      // sign-out revokes the session server-side (GoTrue
      // /logout?scope=local), so the token cannot be captured and
      // reused either - keeping the session is the only option that
      // lands the user back on their own account.
      //
      // signInWithPhrase reuses this session ONLY when the typed phrase
      // derives the pubkey the session already carries, so a different
      // vault's phrase entered here still takes the anonymous path
      // rather than re-pointing this Google account at another vault.
      try {
        sessionStorage.setItem('privacynotes.oauth.handoffPending', '1');
      } catch { /* ignore */ }
      setAuth({ status: 'onboarding' });
      return;
    }

    // --- Branch (c): new OAuth user ---
    // Park in custody choice state. The onboarding UI renders the
    // "Keep it simple" vs "Maximum privacy" choice screen.
    // Spec: ops/docs/custodial-key-spec.md (later upgradable to self-custody in settings, never back)
    if (superseded()) {
      console.info('[oauth] hydrate superseded by manual sign-in, aborting');
      return;
    }
    if (authUid) {
      setAuth({
        status: 'oauth_custody_choice',
        accessToken,
        authUid,
      });
      return;
    }

    // Fallback: no auth.uid (shouldn't happen, but be safe)
    setAuth({ status: 'onboarding' });
  }

  /**
   * Kick off a Google/Apple OAuth flow via Supabase. This redirects the
   * browser away; the return trip lands back on the app's origin with
   * an active Supabase session, which the mount effect picks up and
   * hands to `hydrateFromOAuthSession` to derive the phrase.
   *
   * Note: we can't await this in a meaningful way - `signInWithOAuth`
   * resolves once the redirect URL is built, but the actual sign-in
   * completes on the other side of a full page navigation. Error
   * returns here only cover the "failed to start the redirect" case.
   */
  async function signInWithOAuth(provider: OAuthProvider) {
    try {
      // Trust the device for OAuth flows - the whole point of OAuth is
      // re-authentication convenience, so persisting across reloads is
      // the expected UX. Users who want session-only behaviour should
      // use the phrase path with the "trust this device" box unticked.
      setTrustedDevice(true);

      // Native (Tauri) apps cannot run OAuth inside the embedded webview -
      // Google rejects it as a "disallowed_useragent". Open the provider
      // outside it and take the return this platform asked for: the App Link
      // on Android (handled by the effect below), the auth sheet's own
      // callback on iOS, the return page on desktop.
      const platform = detectPlatform();
      if (platform !== 'web') {
        const { data, error } = await supabase.auth.signInWithOAuth({
          provider,
          options: {
            redirectTo: nativeOAuthRedirect(platform),
            skipBrowserRedirect: true,
          },
        });
        if (error) return { ok: false as const, error: error.message };
        if (!data?.url) {
          return { ok: false as const, error: 'Could not start sign-in.' };
        }
        // The callback handler trusts a callback URL only while this marker
        // is fresh and unconsumed, so it must exist before the browser or the
        // iOS sheet can send one back. One call covers every platform: the
        // iOS branch below feeds the same handler.
        // Spec: ops/docs/plans/deep-link-callback-hardening.md (section 2.2)
        markOAuthPending();
        // iOS presents the flow in-app (ASWebAuthenticationSession) instead
        // of bouncing to Safari: App Review guideline 4 rejects the external
        // browser for sign-in (rejected 2026-08-22). The sheet completes on
        // the https return address above, which iOS grants only to the app
        // whose associated-domains entitlement names that host, and resolves
        // with the callback URL, so the deep-link listener below never fires
        // for it and the same handler runs either way. The host and path are
        // read off the address the provider was given, so the two cannot
        // drift. Android and desktop keep the system browser: Custom Tabs is
        // not required there, and desktop has no in-app equivalent.
        // Spec: ops/docs/plans/oauth-redirect-binding-handoff.md (section 8.2)
        if (platform === 'ios') {
          const { invoke } = await import('@tauri-apps/api/core');
          const returnTo = new URL(nativeOAuthRedirect(platform));
          try {
            const callbackUrl = await invoke<string>(
              'plugin:auth-session|start',
              {
                authUrl: data.url,
                callbackHost: returnTo.hostname,
                callbackPath: returnTo.pathname,
              },
            );
            void handleNativeOAuthCallback(callbackUrl);
            return { ok: true as const };
          } catch (e) {
            // The plugin rejects with the plain string 'user_cancelled' when
            // the user dismisses the sheet. That is not an error: reset the
            // buttons silently (empty string renders no error line).
            if (e === 'user_cancelled') {
              return { ok: false as const, error: '' };
            }
            return { ok: false as const, error: String(e) };
          }
        }
        const { openUrl } = await import('@tauri-apps/plugin-opener');
        await openUrl(data.url);
        // Desktop gets no callback back: the browser stops on our return
        // page and the person carries the code across. Say so, or the
        // sign-in screen sits on "Redirecting..." for ever waiting for a
        // deep link that is never coming.
        // Spec: ops/docs/plans/oauth-redirect-binding-handoff.md (section 8.3)
        return { ok: true as const, awaitPastedCode: platform === 'desktop' };
      }

      const { error } = await supabase.auth.signInWithOAuth({
        provider,
        options: {
          // Land back on the same origin. The mount effect handles the
          // session hydration, so we don't need a bespoke callback URL.
          // Except on the apex: sessions live on the app host since the
          // domain-split retirement, so any OAuth that still starts
          // from an apex context must land on use.privacynotes.app -
          // otherwise the return mints a session onto the origin we
          // just retired (the auth logs caught exactly that on
          // 2026-08-24, hours after the landing CTAs were redirected).
          // Spec: ops/docs/domain-split.md (retirement phase)
          redirectTo: isApexHost() ? APP_ORIGIN : window.location.origin,
        },
      });
      if (error) return { ok: false as const, error: error.message };
      return { ok: true as const };
    } catch (err) {
      return { ok: false as const, error: (err as Error).message };
    }
  }

  // Receives the OAuth redirect on native (Tauri) after the system browser
  // completes sign-in. Exchanges the PKCE ?code= off the deep link for a
  // session, then hydrates directly (this handler owns native OAuth
  // hydration). Tokens in the URL fragment are never read: the
  // client runs PKCE, so a real return never carries them, and a URL that
  // does is not ours.
  //
  // The scheme is open to the world: on Android any app or web page can send
  // a privacynotes:// URL with no permission, and desktop and iOS ask only
  // "Open PrivacyNotes?". Two locks keep a foreign URL out. The pending-
  // sign-in marker: the URL is acted on only when signInWithOAuth started a
  // flow within the marker's time limit, at most once per flow, and never
  // while a signed-in phrase is stored; anything else is dropped before it
  // is parsed, with a breadcrumb and no other side effect, because silence
  // gives a rogue link no oracle. And PKCE: a code is single-use and
  // exchangeable only with the verifier this install stored when it built
  // the authorize URL, so a code minted for anyone else fails the exchange.
  // Either failure lands a legitimate flow on the retry screen instead of a
  // hang. What both locks protect is the owner-mismatch wipe in
  // authenticateWithPhrase: a URL that installs another account's session
  // would otherwise destroy this device's local data and stored phrase.
  // Spec: ops/docs/plans/deep-link-callback-hardening.md (sections 2.2 and 3)
  async function handleNativeOAuthCallback(rawUrl: string) {
    // Anything that is not the callback this platform asked for is somebody
    // else's URL, and the marker is worth one acceptance per flow: spending
    // it on an opened Markdown file strands the sign-in that follows.
    if (!isOAuthCallbackUrl(rawUrl, detectPlatform())) {
      logAuthEvent('auth:oauth-callback-refused', { reason: 'scheme' });
      return;
    }
    // Consumed synchronously, before the first await: two deliveries of one
    // URL (onOpenUrl and the resume check can both fire) cannot both pass.
    const gate = consumeOAuthPending();
    // Signed in means the vault is open, not merely that a phrase sits on
    // disk. A session the library ends on its own leaves the phrase behind
    // and lands the person on the sign-in screen, and reading the blob alone
    // refused every provider button there for ever, in silence.
    // Spec: ops/docs/plans/oauth-redirect-binding-handoff.md (section 8.8)
    const signedIn = hasStoredPhrase() && vaultOpenRef.current;
    if (gate !== 'ok' || signedIn) {
      const reason = signedIn ? 'signed-in' : gate;
      logAuthEvent('auth:oauth-callback-refused', { reason });
      // A marker that was present proves THIS install started the flow, so
      // the person is watching a button that reads "Redirecting..." and
      // `Onboarding` resets it only on an error return. Refusing in silence
      // there strands them for ever: the button stays disabled and the only
      // way out is restarting the app. Observed on a signed-out phone whose
      // stored phrase had outlived its session, where the refusal was
      // `signed-in` and the screen never moved again. A missing marker is
      // the opposite case, a URL this install never asked for, and it stays
      // silent, because an answer hands an unsolicited link an oracle.
      // Spec: ops/docs/plans/oauth-redirect-binding-handoff.md (section 8.8)
      if (gate !== 'missing') {
        setAuth({ status: 'oauth_hydrate_failed', trust: true });
      }
      return;
    }
    logAuthEvent('auth:oauth-callback-accepted');
    try {
      const u = new URL(rawUrl);
      // A provider refusal (the user cancelled at the account picker, or
      // the provider errored) comes back as error parameters; GoTrue has
      // placed them in either part of the URL over time, so read both.
      const hash = new URLSearchParams(u.hash.replace(/^#/, ''));
      const err =
        u.searchParams.get('error_description') ||
        hash.get('error_description') ||
        u.searchParams.get('error') ||
        hash.get('error');
      if (err) {
        console.error('OAuth callback error:', err);
        setAuth({ status: 'oauth_hydrate_failed', trust: true });
        return;
      }
      const code = u.searchParams.get('code');
      if (!code) {
        logAuthEvent('auth:oauth-callback-no-code');
        setAuth({ status: 'oauth_hydrate_failed', trust: true });
        return;
      }
      await exchangeAndHydrate(code);
    } catch (e) {
      console.error('Failed to handle OAuth deep link:', e);
      setAuth({ status: 'oauth_hydrate_failed', trust: true });
    }
  }

  /**
   * Turn a one-time code into a signed-in session.
   *
   * Shared by the two ways a code reaches a native build: a deep link the
   * operating system delivered, and a code the person pasted from the
   * desktop return page. The exchange reads the verifier `signInWithOAuth`
   * stored in this install's auth storage and deletes it, so a replayed
   * code, a foreign code, or a code meant for another install fails here.
   */
  async function exchangeAndHydrate(code: string): Promise<boolean> {
    const { data, error } = await supabase.auth.exchangeCodeForSession(code);
    const token = data?.session?.access_token;
    if (error || !token) {
      logAuthEvent('auth:oauth-code-exchange-failed', {
        name: error?.name,
        status: (error as { status?: number } | null)?.status,
      });
      setAuth({ status: 'oauth_hydrate_failed', trust: true });
      return false;
    }
    // Drive hydration here rather than leaning on onAuthStateChange. That
    // listener is only registered on the logged-out boot path, so after a
    // logged-in boot and a sign-out it does not exist and the sign-in hangs
    // until a manual reload. This module owns native OAuth hydration.
    await hydrateFromOAuthSession(token, /*trust*/ true);
    return true;
  }

  /**
   * Finish a desktop sign-in from the code the person pasted back.
   *
   * The pending marker is spent here for the same reason the deep-link
   * handler spends it: it proves this install started a sign-in recently,
   * and it is worth one acceptance, so a code pasted twice cannot run the
   * hydration twice. A code that was never ours fails the exchange anyway,
   * because the verifier is this install's.
   *
   * Errors are returned rather than thrown so the sign-in screen can show
   * them beside the box the person typed into, which is where they are
   * looking.
   * Spec: ops/docs/plans/oauth-redirect-binding-handoff.md (section 8.3)
   */
  async function completeDesktopOAuth(
    rawCode: string,
  ): Promise<{ ok: true } | { ok: false; error: string }> {
    const code = rawCode.trim();
    if (!code) return { ok: false as const, error: 'Paste the code from the browser first.' };
    const gate = consumeOAuthPending();
    if (gate !== 'ok') {
      logAuthEvent('auth:oauth-paste-refused', { reason: gate });
      return {
        ok: false as const,
        error:
          gate === 'stale'
            ? 'That sign-in took too long. Start it again.'
            : 'Start the sign-in from this app first, then paste the code.',
      };
    }
    logAuthEvent('auth:oauth-paste-accepted');
    try {
      return (await exchangeAndHydrate(code))
        ? { ok: true as const }
        : { ok: false as const, error: 'That code did not work. Start the sign-in again.' };
    } catch (e) {
      console.error('Failed to complete the desktop sign-in:', e);
      setAuth({ status: 'oauth_hydrate_failed', trust: true });
      return { ok: false as const, error: (e as Error).message };
    }
  }

  // Register the deep-link listener once, on native only. Covers both a warm
  // callback (app already open) and a cold start launched by the link.
  useEffect(() => {
    if (detectPlatform() === 'web') return;
    let unlisten: (() => void) | undefined;
    let stopResumeCheck: (() => void) | undefined;
    let cancelled = false;
    // Every deep link this effect has accounted for, whether it was processed
    // or deliberately skipped. getCurrent() keeps handing back the same URL,
    // so the resume check below needs this to tell a genuinely new callback
    // from one that has already had its turn.
    let seen: string | undefined;
    void (async () => {
      try {
        const { onOpenUrl, getCurrent } = await import(
          '@tauri-apps/plugin-deep-link'
        );
        const initial = await getCurrent();
        const initialUrl = initial?.[0];
        // getCurrent() returns the deep link that launched the activity, and
        // it keeps returning that same launch URL on every cold start AND on
        // every Android dev-mode reload/rebuild - the webview reloads but the
        // launch intent is unchanged. The handler's pending-sign-in gate
        // refuses that replay by construction (the marker was consumed the
        // first time), and it refuses any link while a phrase is stored. The
        // skip here stays as a second line: a signed-in install never hands
        // the launch URL over at all, and the stored-phrase fast boot
        // restores the session instead.
        // Mark the launch URL seen even when the guard skips it, or the
        // resume check below would process the very link this guard exists
        // to avoid.
        if (initialUrl) seen = initialUrl;
        if (initialUrl && !hasStoredPhrase()) {
          await handleNativeOAuthCallback(initialUrl);
        }
        const un = await onOpenUrl((urls) => {
          const url = urls?.[0];
          if (!url) return;
          seen = url;
          void handleNativeOAuthCallback(url);
        });
        if (cancelled) un();
        else unlisten = un;

        // Android never fires onOpenUrl for a callback that returns to an
        // already-running app. The intent IS delivered - getCurrent() returns
        // it with its token fragment intact - but the event never reaches the
        // webview, so sign-in hangs on "Redirecting..." forever with no error
        // and no failed request. Retrying appears to fix it only because a
        // relaunch takes the getCurrent() path above instead. Diagnosed on a
        // Pixel 10 against v0.404.0 on 2026-08-16 (CDP showed zero webview
        // activity while logcat showed the intent arriving 1.4s after the tap).
        // So: on resume, ask for the current link rather than waiting to be
        // told. Idempotent via `seen`, and a no-op on platforms where
        // onOpenUrl already delivered it.
        const checkOnResume = () => {
          if (document.hidden) return;
          void (async () => {
            try {
              const cur = await getCurrent();
              const url = cur?.[0];
              if (!url || url === seen) return;
              seen = url;
              await handleNativeOAuthCallback(url);
            } catch {
              // Transient plugin/IPC failure: the next resume tries again.
            }
          })();
        };
        if (!cancelled) {
          window.addEventListener('focus', checkOnResume);
          document.addEventListener('visibilitychange', checkOnResume);
          stopResumeCheck = () => {
            window.removeEventListener('focus', checkOnResume);
            document.removeEventListener('visibilitychange', checkOnResume);
          };
        }
      } catch (e) {
        console.error('Deep-link listener setup failed:', e);
      }
    })();
    return () => {
      cancelled = true;
      unlisten?.();
      stopResumeCheck?.();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /**
   * Retry a failed OAuth hydration with whatever session supabase-js
   * currently holds (it refreshes the token if it can). A missing
   * session cannot be retried - local sign-out, back to the sign-in
   * options. A dead-but-present session fails hydration again and
   * lands back on oauth_hydrate_failed, honestly.
   * Spec: ops/docs/domain-split.md (pre-cutover gate)
   */
  async function retryOAuthHydration(trust: boolean) {
    setAuth({ status: 'loading' });
    try {
      const { data: { session } } = await supabase.auth.getSession();
      if (session?.access_token) {
        await hydrateFromOAuthSession(session.access_token, trust);
        return;
      }
    } catch (err) {
      console.warn('[oauth] retry hydrate failed:', err);
      setAuth({ status: 'oauth_hydrate_failed', trust });
      return;
    }
    // No session left to retry against.
    await supabase.auth.signOut({ scope: 'local' }).catch(() => { /* ignore */ });
    setAuth({ status: 'onboarding' });
  }

  /** Give up on a failed hydration: local sign-out, back to sign-in options. */
  async function abandonOAuthHydration() {
    await supabase.auth.signOut({ scope: 'local' }).catch(() => { /* ignore */ });
    setAuth({ status: 'onboarding' });
  }

  return {
    registerOAuthListener,
    signInWithOAuth,
    completeDesktopOAuth,
    retryOAuthHydration,
    abandonOAuthHydration,
  };
}
