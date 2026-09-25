import { lazy, Suspense, useEffect, useRef, useState, type ReactNode } from 'react';
import { useAuth } from './auth';
import { consumePhraseFragment } from './qrSignIn';
import { QrSignInPrompt } from './QrSignInPrompt';
import { LoadingScreen } from './LoadingScreen';
import { LockScreen } from './LockScreen';
import { OAuthRetryScreen } from './OAuthRetryScreen';
import { VersionUpdateToast } from './VersionUpdateToast';
import { DesktopUpdater } from './DesktopUpdater';
import { AndroidUpdateToast } from './AndroidUpdateToast';
import { StoreUpdateToast } from './StoreUpdateToast';
import {
  hasBiometricCredential,
  hasPinWrappedPhrase,
  hasStoredPhrase,
  onWrappedBlobChange,
  type PinWrapBlob,
} from './biometric';
import { shouldPromptForPin, markPinUnlocked } from './pin';
import { clearPin, phraseMatches } from './pinRecovery';
import { phraseOwnsThisDevice } from './authStorage';
import { startReLockWatch } from './appReLock';
import { applyPrivacyScreen } from './privacyScreen';
import { loadLocalSettings, saveLocalSettings } from './userSettings';
import { hasStoredSession, isTrustedDevice } from './trustStorage';
import { isDemoMode } from './demo';
import { detectPlatform, warmAuthEdgeFunctions } from './devices';
import { isApexHost } from './hosts';
import { isTouchPointer } from './useIsMobile';
import { localeFromPath } from './localeRoutes';
import { setLanguage } from './languages';
import { applyMarketingSeo } from './seo';
import i18n from './i18n';

/** Native (Tauri) apps never show the marketing page; see LandingPage. */
const IS_DESKTOP = detectPlatform() !== 'web';

// Apex retirement (domain-split, executed 2026-08-25): the web apex no
// longer boots the notes app. A signed-in straggler gets the MoveScreen
// (one job: send the person to sign in at use.privacynotes.app) instead of
// NotesView; the only way back into NotesView on the apex is the
// MoveScreen's stuck-state escape hatch, so the retirement metric
// (NotesView-chunk fetches on the apex) counts only sessions that
// genuinely cannot move yet. Demo (?demo=1) keeps its own behavior.
// Spec: ops/docs/domain-split.md (retirement phase)
const APEX_APP_RETIRED =
  isApexHost() && !isDemoMode() && detectPlatform() === 'web';

// True when this page load is an OAuth redirect return: the URL still carries
// what supabase-js is about to consume, a PKCE `?code=` in the query (the
// legacy implicit return carried `#access_token=` in the hash). Captured at
// module eval, before supabase-js strips it (it reads window.location.href
// asynchronously behind navigator.locks - see the boot effect in auth.tsx).
// Used to hold the loading screen through callback processing instead of
// flashing the landing page.

const OAUTH_CALLBACK_AT_BOOT =
  typeof window !== 'undefined' &&
  (window.location.hash.includes('access_token=') ||
    new URLSearchParams(window.location.search).has('code'));

// Code-split the two big halves of the app: visitors never parse the
// notes app (TipTap, sync, modals) and returning users never parse the
// marketing page + onboarding flow. Each lazy chunk is fetched on demand
// and served immutable from the browser cache on repeat visits, so the
// extra request is only paid cold. vite:preloadError in main.tsx covers
// the stale-chunk-after-deploy case.
const Onboarding = lazy(() =>
  import('./Onboarding').then((m) => ({ default: m.Onboarding })),
);
const NotesView = lazy(() =>
  import('./NotesView').then((m) => ({ default: m.NotesView })),
);
// Lazy despite being a small component: it pulls PhraseView -> qrcode.react
// and billing.ts -> paddle.ts into whatever chunk holds it, and the free-tier
// device cap is a state almost no session ever reaches. Rendered inside the
// same <Suspense> as the other two.
const DeviceLimitModal = lazy(() =>
  import('./DeviceLimitModal').then((m) => ({ default: m.DeviceLimitModal })),
);
const MoveScreen = lazy(() =>
  import('./MoveScreen').then((m) => ({ default: m.MoveScreen })),
);

// Start downloading the chunk this user will need immediately at
// module-eval time, so on a cold cache the fetch overlaps key derivation
// and auth instead of waiting for the first render. The module cache
// dedups this against the lazy() load above. On the retired apex a
// session leads to the MoveScreen, never NotesView - preloading the
// NotesView chunk there would also poison the retirement metric.
if (hasStoredSession()) {
  if (APEX_APP_RETIRED) {
    void import('./MoveScreen');
  } else {
    void import('./NotesView');
  }
} else {
  void import('./Onboarding');
}

export default function App() {
  const { auth, signInWithPhrase, unlockLocally } = useAuth();

  // Explicit per-language marketing URL (/de, /en, ...). Locale slugs are the
  // public marketing site and stay browsable at that URL for everyone -
  // signed-out visitors, crawlers, and signed-in users who open one (e.g. via
  // an in-app "Website" link). Held in state so entering the app can strip the
  // slug without a full reload (which would drop an in-memory, untrusted-device
  // session).
  const [marketingSlug, setMarketingSlug] = useState<string | null>(() =>
    localeFromPath()
  );

  // A fresh sign-in (or vault creation) on a locale-slug page lands in the app
  // at the clean apex URL, carrying the slug's language forward so it survives
  // the dropped slug. Guarded to a genuine sign-in here (no stored session at
  // mount): a returning session that just opens /en stays on the browsable
  // marketing page - that visitor is moved on by the landing CTAs instead (the
  // handler passed to Onboarding below).
  const hadSessionAtMount = useRef(hasStoredSession());
  useEffect(() => {
    if (
      marketingSlug &&
      !hadSessionAtMount.current &&
      (auth.status === 'authenticated' ||
        auth.status === 'device_limit_reached')
    ) {
      setLanguage(marketingSlug);
      window.history.replaceState(null, '', '/');
      setMarketingSlug(null);
    }
  }, [marketingSlug, auth.status]);

  // Marketing pages own their localized SEO (title, description, canonical,
  // hreflang, html lang); the authenticated app just uses the short brand title.
  useEffect(() => {
    const marketing =
      marketingSlug !== null ||
      (auth.status !== 'authenticated' && auth.status !== 'device_limit_reached');
    if (!marketing) {
      document.title = 'PrivacyNotes';
      return;
    }
    applyMarketingSeo();
    const onChange = () => applyMarketingSeo();
    i18n.on('languageChanged', onChange);
    return () => {
      i18n.off('languageChanged', onChange);
    };
  }, [auth.status, marketingSlug]);

  // External links are dead in the native (Tauri) webview: an
  // <a target="_blank"> click is silently swallowed by WKWebView (no new
  // window, no navigation), and a same-tab href would replace the app
  // itself. So on desktop we intercept clicks on external links in the
  // capture phase and hand them to the system browser via the opener
  // plugin. Web is untouched - the listener is never installed. OAuth
  // (auth.tsx) and the updater (DesktopUpdater.tsx) already call openUrl
  // directly; this covers every other link (note content, footer,
  // About/Feedback/Donation modals, etc.).
  // Spec: ops/docs/macos-ios-setup.md (native flows use the same opener plugin)
  useEffect(() => {
    if (!IS_DESKTOP) return;
    const onClick = (e: MouseEvent) => {
      if (e.defaultPrevented || e.button !== 0) return;
      const anchor = (e.target as Element | null)?.closest('a');
      const href = anchor?.getAttribute('href');
      // tel: and sms: ride along with mailto:: a contact's number is a
      // handoff to the dialer, which the WebView cannot make on its own.
      // Spec: ops/docs/plans/contacts-pillar.md (section 9, tap to call)
      if (!href || !/^(https?:|mailto:|tel:|sms:)/i.test(href)) return;
      // A link inside a note being written belongs to the caret, and a
      // mouse says so by clicking it: the cursor goes in the link and the
      // browser stays closed. Handing that click over instead moves the
      // person to another application and costs them the cursor, which is
      // the only thing the toolbar's Remove acts on (GitHub #293).
      // `editorLinks.ts` owns what a mouse click does there, including
      // Cmd/Ctrl-click to open. A finger keeps this route, because it has
      // no modifier to say "follow it" with.
      if (!isTouchPointer() && anchor?.closest('[contenteditable="true"]')) return;
      e.preventDefault();
      // iOS presents web links in an in-app SFSafariViewController sheet
      // ('inAppBrowser' is built into the opener plugin) instead of
      // switching to the Safari app - the same keep-the-user-in-app rule
      // App Review applied to sign-in (guideline 4, 2026-08-22), and the
      // API their letter suggests for web content. mailto: cannot render
      // in a browser sheet and keeps the plain path. Android/desktop keep
      // the system browser.
      const openWith =
        detectPlatform() === 'ios' && /^https?:/i.test(href)
          ? ('inAppBrowser' as const)
          : undefined;
      void import('@tauri-apps/plugin-opener').then(async ({ openUrl }) => {
        try {
          await openUrl(href, openWith);
        } catch (err) {
          // Never let a link do nothing. `with` is part of the opener's ACL
          // check - a scope that does not grant an explicit application
          // rejects with ForbiddenUrl - and this call had no catch when the
          // sheet first shipped, so a capability gap silently killed EVERY
          // external link in the app (2026-08-26). Retry without the sheet:
          // the system browser is a worse experience than the sheet and a
          // far better one than a dead tap.
          if (openWith) {
            console.warn('[links] in-app sheet refused, using the browser', err);
            await openUrl(href);
            return;
          }
          console.error('[links] could not open', href, err);
        }
      });
    };
    document.addEventListener('click', onClick, true);
    return () => document.removeEventListener('click', onClick, true);
  }, []);

  // Show the loading screen only when there's a stored phrase (a session
  // to restore). The trust flag survives sign-out, so gating on
  // isTrustedDevice() would show a loading screen to signed-out users on
  // a previously-trusted device while Supabase initializes. A stored
  // phrase is the honest signal: no phrase = nothing to restore = skip
  // straight to onboarding/landing page.
  //
  // No artificial minimum display time: the local-first fast boot in
  // auth.tsx flips to 'authenticated' as soon as keys are derived and
  // local notes are confirmed, so the goal is to get OFF this screen as
  // fast as possible. The typewriter screen still covers the slow path
  // (first sync on a fresh device).
  const hasSession = hasStoredSession();
  // Native apps hold the loading screen through the whole auth-resolve
  // window (even with no stored phrase) so an incoming OAuth session
  // restore doesn't flash the onboarding auth card first. Web keeps the
  // old behaviour: show onboarding immediately when there's nothing to
  // restore.
  //
  // Exception on web: an OAuth redirect return (access_token in the hash)
  // also holds the loading screen. Without it, the landing page renders
  // for the several seconds hydrateFromOAuthSession spends on its edge
  // function round-trips - which reads as a silently failed sign-in, and
  // invites the user into a manual phrase entry that races the pending
  // hydration (its branch-b signOut then tears down the in-flight
  // handshake - the "Session is missing the account link" error). If the
  // callback token is dead, the 12 s fallback in auth.tsx flips the state
  // to 'onboarding' and dismisses this screen.
  const showLoading =
    auth.status === 'loading' &&
    (hasSession || IS_DESKTOP || OAUTH_CALLBACK_AT_BOOT);

  // ── Lock screen state ─────────────────────────────────────────
  // The lock screen gates the entire app when a wrapped phrase blob
  // exists (biometric or PIN) and either appLockEnabled is true or no
  // phrase is at rest. The phrase is only in memory after a successful
  // unlock - and stays there while the lock is armed: the post-unlock
  // sign-in deliberately skips the storage persist then (see
  // signInWithPhrase), so the unlock can never quietly write the
  // phrase back to disk (pre-launch audit 2026-08-28, finding 8).
  const [locked, setLocked] = useState<boolean>(() => {
    const hasWrapped = hasBiometricCredential() || hasPinWrappedPhrase();
    if (!hasWrapped) return false;
    // Wrapped-only state: enabling app lock strips the stored
    // phrase, so after a reload the ONLY path back into the session
    // runs through an unlock - the phrase exists nowhere else. That
    // holds whatever the flag says. The flag is synced, and switching
    // the lock off on another device writes the phrase back there, not
    // here; unlocked, this device would boot to the sign-in screen with
    // a wrap on disk that nothing opens. Locked, the unlock's sign-in
    // finds the lock no longer armed and writes the phrase back, so the
    // next start is a normal one. The re-lock window must not excuse
    // the prompt either: with locked=false and no stored phrase, boot
    // found nothing to restore and landed a fully healthy account on
    // the signed-out landing page with no way back in (session audit
    // 2026-08-25). The flag and the window apply while a stored phrase
    // exists, where skipping the prompt is recoverable.
    // Pinned by tests/sync/scenarios-app-lock-remote-off.test.ts.
    if (!hasStoredPhrase()) return true;
    const settings = loadLocalSettings();
    if (!settings.appLockEnabled) return false;
    return shouldPromptForPin(settings.appLockTimeoutMinutes);
  });

  // Arm the native cover the operating system photographs in place of the
  // notes. Settings writes carry it from then on (writeLocal in
  // userSettings.ts); a cold start writes nothing, so it starts here.
  // Spec: ops/docs/plans/app-switcher-privacy-screen.md
  useEffect(() => {
    applyPrivacyScreen(loadLocalSettings().appLockEnabled);
  }, []);

  // Re-lock after the idle window the user picked. Armed only while the app is
  // open and signed in: locking a lock screen is a no-op, and locking a
  // half-booted session would fight the boot check above. The watch itself
  // decides whether this device has a door back in.
  // Spec: ops/docs/biometric-unlock.md (section 3.3 re-lock)
  useEffect(() => {
    if (locked || auth.status !== 'authenticated') return;
    return startReLockWatch(() => setLocked(true));
  }, [locked, auth.status]);

  // Listen for cross-tab changes to wrapped blobs (e.g. biometric
  // disabled in another tab).
  useEffect(() => {
    return onWrappedBlobChange(() => {
      // A sign-out in another tab removes these same wrapped blobs AND
      // clears the settings blob, so both unlock branches below would
      // otherwise fire on a signal that has nothing to do with this user
      // turning app lock off - dropping a locked, unattended tab straight
      // into the notes. A stored phrase means this browser is still
      // signed in, which is the only state where a blob change is a real
      // app-lock config change.
      if (!hasStoredPhrase()) return;
      const settings = loadLocalSettings();
      if (!settings.appLockEnabled) {
        setLocked(false);
        return;
      }
      const hasWrapped = hasBiometricCredential() || hasPinWrappedPhrase();
      if (!hasWrapped) setLocked(false);
    });
  }, []);

  // The post-unlock sign-in state, rendered by LockScreen. The lock holds
  // until the sign-in resolves, with a status line and a retry: dropping
  // it on a fire-and-forget signInWithPhrase lets a transient failure
  // (offline, rate limit, slow link) silently land a user who had just
  // proven their PIN on the signed-out landing page (session audit
  // 2026-08-25). The unwrapped phrase is held in a ref for the retry
  // only; it is cleared the moment the sign-in succeeds.
  const [unlockSignIn, setUnlockSignIn] = useState<'idle' | 'busy' | 'error'>('idle');
  const unlockPhraseRef = useRef<string | null>(null);
  // Held beside the phrase so the retry button keeps the intent.
  const unlockRecoverRef = useRef(false);

  /**
   * Take the PIN off, from the lock screen's "Forgot your PIN?" door.
   *
   * Runs only after the unlock proves the phrase, so a phrase that passes
   * its checksum but belongs elsewhere cannot cost this device the PIN it
   * still remembers. NotesView is unmounted while the lock is up and reads
   * this cache in its own initializer, so writing it here is what carries
   * the removal to the other devices on the next sync.
   *
   * clearPin answers null, having removed nothing, when the PIN wrap is the
   * last door and the phrase did not read back at rest. The PIN then stays
   * and the unlock goes ahead: the phrase has already proved itself, and
   * the next lock screen offers the same door.
   * Spec: ops/docs/plans/pin-recovery.md
   */
  async function applyPinRecovery(phrase: string) {
    const cleared = await clearPin(loadLocalSettings(), phrase);
    if (cleared) saveLocalSettings(cleared);
    unlockRecoverRef.current = false;
  }

  /**
   * Carry a re-wrapped legacy PIN blob to the account, the same way as the
   * recovery above: the lock screen holds no settings, NotesView is
   * unmounted while the lock is up, and this cache is what the next pass
   * pushes. Every device replaces a wrap that differs from the account's,
   * so an upgrade the account never learned of would be undone on the next
   * pass and redone on the next unlock.
   * Spec: ops/docs/archive/sec-65-pin-change-follows.md
   */
  function applyPinWrapUpgrade(blob: PinWrapBlob) {
    saveLocalSettings({ ...loadLocalSettings(), ...blob });
  }

  async function runUnlockSignIn(phrase: string) {
    setUnlockSignIn('busy');
    // No Turnstile widget here, so no captchaToken: if the link-pubkey
    // gate demands one on this rare path (session lost while the
    // phrase sat wrapped, web origin only), fall through to
    // onboarding, which has the widget. Deliberate - not worth a
    // challenge on every lock-screen unlock.
    const result = await signInWithPhrase(phrase, isTrustedDevice());
    if (result.ok) {
      if (unlockRecoverRef.current) await applyPinRecovery(phrase);
      unlockPhraseRef.current = null;
      setUnlockSignIn('idle');
      setLocked(false);
      return;
    }
    if (result.captchaRequired) {
      unlockPhraseRef.current = null;
      setUnlockSignIn('idle');
      setLocked(false);
      return;
    }
    setUnlockSignIn('error');
  }

  /**
   * Every door on the lock screen lands here. The fingerprint and the PIN
   * unwrap a blob this device holds, so their phrase is this account's by
   * construction. The third door is typed, and a BIP-39 checksum says only
   * that the words are well formed, never whose they are.
   *
   * Answers false when the phrase does not belong to the session behind the
   * lock, so the screen can say so rather than appear to hang.
   */
  async function handleLockScreenUnlock(phrase: string, recover = false): Promise<boolean> {
    // The lock screen is not a sign-in screen. It is up because this device
    // armed an app lock, so the phrase typed into it has to be the phrase of
    // the account behind that lock, and the refusal comes before anything
    // here has a side effect, markPinUnlocked included.
    //
    // Two questions, because the two branches below know the account in two
    // different ways. A re-lock leaves the session, the phrase and the seal
    // key live behind the curtain, so there the phrase itself is the
    // comparison. A cold start has no session, so the owner marker is - and
    // that half is load-bearing: `tryFastBoot` refuses a foreign phrase but
    // the branch below then falls through to a full sign-in, which signs the
    // holder into their own account and takes the local vault with it on the
    // owner-mismatch wipe. Signing in as somebody else stays available from
    // the signed-out screen, where it is the deliberate act it looks like.
    const belongsHere =
      auth.status === 'authenticated'
        ? phraseMatches(phrase, auth.phrase)
        : await phraseOwnsThisDevice(phrase);
    if (!belongsHere) return false;
    markPinUnlocked();
    unlockRecoverRef.current = recover;
    if (auth.status === 'authenticated') {
      if (recover) await applyPinRecovery(phrase);
      setLocked(false);
      return true;
    }
    // Local-first, for the same reason the boot path is. Enabling app
    // lock strips the stored phrase, so a cold start has no session and
    // this unlock is the sign-in - which made a reachable server the
    // price of opening notes that are already on this disk, under the
    // very phrase the PIN or biometric just unwrapped. Render them, then
    // establish the session behind the app. A device whose access was
    // revoked is still caught by the heartbeat on the first sync; it
    // sees its own local data a moment sooner, which is the trade
    // `tryFastBoot` already makes on every normal boot.
    if (await unlockLocally(phrase)) {
      // Before the sign-in, not after: it reads app lock's armed state to
      // decide whether to write the phrase back at rest, and after a
      // recovery the lock is off and that write is the right one.
      if (recover) await applyPinRecovery(phrase);
      unlockPhraseRef.current = null;
      setUnlockSignIn('idle');
      setLocked(false);
      // Not awaited and not surfaced: the user is in, and sync owns its
      // own error reporting from here. signInWithPhrase skips the phrase
      // persist while the lock is armed, so this cannot write the phrase
      // back to disk and undo the lock.
      void signInWithPhrase(phrase, isTrustedDevice());
      return true;
    }
    // Nothing local to render (a wiped or brand-new device), so the
    // network sign-in is the only door, exactly as before.
    unlockPhraseRef.current = phrase;
    void runUnlockSignIn(phrase);
    return true;
  }

  // Consume any `#phrase=…` fragment exactly once on mount. This also
  // blanks the fragment out of the address bar immediately - we don't
  // want the master secret sitting in the URL longer than needed.
  const [pendingSignIn, setPendingSignIn] = useState<string | null>(
    () => consumePhraseFragment()
  );
  const [promptBusy, setPromptBusy] = useState(false);
  const [promptError, setPromptError] = useState<string | null>(null);
  // Set only after the server refuses a tokenless confirm for want of a
  // challenge token. Until then the prompt runs no Turnstile at all -
  // the link-pubkey gate's enforcement mode is not readable from the
  // client, so its refusal is the only honest signal that a challenge
  // is due.
  const [promptCaptchaRequired, setPromptCaptchaRequired] = useState(false);
  const [promptTrustDevice, setPromptTrustDevice] = useState(true);

  // QR sign-in lands with a phrase fragment on a device that usually has
  // no cached chunks. Warm the NotesView chunk and the sign-in edge
  // functions while the user reads the confirm prompt, mirroring what
  // Onboarding does for its auth flows, so the confirm hits warm isolates
  // and the post-auth <Suspense> fallback resolves instantly.
  useEffect(() => {
    if (pendingSignIn) {
      void import('./NotesView');
      warmAuthEdgeFunctions();
    }
  }, [pendingSignIn]);

  // Edge case: if the user arrives with a fragment while already
  // authenticated (e.g. they scanned their own QR on a device that was
  // still signed in), we just drop the fragment silently. Switching
  // accounts from a QR is too risky without a proper "switch account"
  // flow that also wipes local data first.
  useEffect(() => {
    if (pendingSignIn && auth.status === 'authenticated') {
      setPendingSignIn(null);
    }
  }, [pendingSignIn, auth.status]);

  async function handleConfirmPendingPhrase(captchaToken?: string) {
    if (!pendingSignIn) return;
    setPromptBusy(true);
    setPromptError(null);
    const result = await signInWithPhrase(pendingSignIn, promptTrustDevice, false, captchaToken);
    if (!result.ok) {
      // The server wants a challenge token: put the widget on screen
      // instead of an error the user cannot act on. Guarded on the flag
      // so a token the server then rejects surfaces as a real error
      // rather than re-arming a challenge that will refuse again.
      if (result.captchaRequired && !promptCaptchaRequired) {
        setPromptCaptchaRequired(true);
        setPromptBusy(false);
        return;
      }
      // A second challenge refusal carries the internal 'session_expired'
      // taxonomy string as its message - show the generic failure copy
      // instead of that raw token.
      setPromptError(
        result.captchaRequired
          ? i18n.t('auth:signIn.failedUnexpectedly')
          : result.error,
      );
      setPromptBusy(false);
      return;
    }
    setPendingSignIn(null);
    setPromptBusy(false);
  }

  function handleCancelPendingPhrase() {
    setPendingSignIn(null);
    setPromptError(null);
  }

  // Retired apex only: the MoveScreen's stuck-state escape hatch. One
  // legacy boot of NotesView so a sync error or conflict can be fixed
  // where the tools live (ConflictModal, push-error banner, and the
  // MoveBanner to try the move again). Session-scoped on purpose - the
  // next visit lands on the MoveScreen again.
  const [legacyNotesOpen, setLegacyNotesOpen] = useState(false);

  // Lock screen - shown over everything when app lock is active.
  // Must come before the loading check so a locked app stays locked
  // even during auth restoration. Exception: explicit locale slugs
  // (/en, /de, ...) are the public marketing site - they render no
  // notes, so the lock must not gate them (it would fire a biometric
  // prompt on a plain website visit). Entering the app from a slug
  // page clears the slug, and the locked branch then takes over
  // before any notes render.
  let screen: ReactNode;
  if (marketingSlug) {
    // Locale slug: the public marketing site, browsable in every language by
    // everyone - signed-out visitors, crawlers, and signed-in users who open an
    // in-app "Website" link here. A fresh sign-in strips the slug (effect
    // above); an already-signed-in visitor who taps a landing CTA is sent to
    // the app via onAuthedEnterApp.
    screen = (
      <Onboarding
        onAuthedEnterApp={() => {
          window.history.replaceState(null, '', '/');
          setMarketingSlug(null);
        }}
      />
    );
  } else if (locked) {
    screen = (
      <LockScreen
        onUnlock={handleLockScreenUnlock}
        onWrapUpgraded={applyPinWrapUpgrade}
        signInState={unlockSignIn}
        onRetrySignIn={() => {
          if (unlockPhraseRef.current) void runUnlockSignIn(unlockPhraseRef.current);
        }}
      />
    );
  } else if (auth.status === 'oauth_hydrate_failed') {
    // OAuth hydration failed - loud, retryable error instead of the old
    // silent fall-through to custody choice (data-orphaning footgun).
    screen = <OAuthRetryScreen trust={auth.trust} />;
  } else if (showLoading || (isDemoMode() && auth.status === 'loading')) {
    // Demo seeds + key derivation happen async on mount; hold the loading
    // screen until authenticated so the landing page never flashes.
    screen = <LoadingScreen />;
  } else if (auth.status === 'onboarding' || auth.status === 'oauth_custody_choice' || (!hasSession && auth.status === 'loading')) {
    // No stored phrase: treat 'loading' as 'onboarding' - show the
    // landing page immediately while Supabase resolves getSession() in
    // the background. The result will be 'onboarding' anyway; no point
    // showing a loading animation.
    screen = (
      <>
        <Onboarding />
        {pendingSignIn && (
          <QrSignInPrompt
            phrase={pendingSignIn}
            onConfirm={handleConfirmPendingPhrase}
            onCancel={handleCancelPendingPhrase}
            busy={promptBusy}
            error={promptError}
            captchaRequired={promptCaptchaRequired}
            trustDevice={promptTrustDevice}
            onTrustDeviceChange={setPromptTrustDevice}
          />
        )}
      </>
    );
  } else if (auth.status === 'device_limit_reached') {
    // Free-tier device cap hit - block the whole app until the user
    // either revokes a device or signs out. No notes rendered behind it.
    screen = <DeviceLimitModal />;
  } else if (APEX_APP_RETIRED && !legacyNotesOpen) {
    // Apex retirement: a signed-in apex session gets the move screen,
    // not the notes app. See the constant above for the full story.
    screen = <MoveScreen onOpenNotes={() => setLegacyNotesOpen(true)} />;
  } else {
    screen = <NotesView />;
  }

  // Suspense fallback while a lazy chunk (Onboarding / NotesView) loads.
  // The typewriter LoadingScreen is right for a RETURNING user waiting on
  // the NotesView chunk ("your notes are coming back"), but wrong for a
  // first-time visitor waiting on the Onboarding chunk: it flashed the
  // typewriter on the marketing homepage for the chunk-fetch window
  // (~250 ms on fast links, seconds on slow ones) before the hero
  // painted. Gate it on the same condition as showLoading - a session to
  // restore, native, or an OAuth return - and give the signed-out
  // marketing path a plain surface splash instead.
  const suspenseFallback =
    !marketingSlug && (hasSession || IS_DESKTOP || OAUTH_CALLBACK_AT_BOOT) ? (
      <LoadingScreen />
    ) : (
      <div className="min-h-dvh bg-surface-0" />
    );

  return (
    <>
      <VersionUpdateToast />
      <DesktopUpdater />
      <AndroidUpdateToast />
      <StoreUpdateToast />
      <Suspense fallback={suspenseFallback}>{screen}</Suspense>
    </>
  );
}
