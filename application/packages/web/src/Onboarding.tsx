import { useState, useEffect, useRef, type ReactNode } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import { generatePhrase, isValidPhrase } from '@notes/shared';
import { ArrowLeft, ArrowRight, CaretDown, Check, Copy, FileText, KeyReturn, Lock, Password, QrCode, Scales, Scan, Upload, Warning } from './icons';
import { QRCodeCanvas } from 'qrcode.react';
import { buildPhraseFile, PHRASE_FILE_NAME } from './phraseFile';
import { buildSignInUrl, extractPhraseFromScan } from './qrSignIn';
import { saveBlob } from './saveFile';
import { useAuth } from './auth';
import type { OAuthProvider } from './auth';
import { QrScannerModal } from './QrScannerModal';
import { TurnstileWidget } from './TurnstileWidget';
import { detectPlatform, isLinuxNative } from './devices';
import { isDemoMode } from './demo';
import { isAppHost } from './hosts';
import { applyStoredTheme } from './theme';
import { ConfirmModal } from './ConfirmModal';
import { switchWouldWipe } from './authStorage';
import { LoadingScreen } from './LoadingScreen';
import { LandingPage, FX_CSS } from './LandingPage';
import { LogoIcon } from './LogoIcon';
import { Brand } from './Brand';
import { PrivacyLadder } from './PrivacyLadder';

/** Native (Tauri) build - desktop or mobile wrapper, not the web app. */
const IS_DESKTOP = detectPlatform() !== 'web';

/** Native iOS app: surface Sign in with Apple above Google (App Store expectation). */
const IS_IOS = detectPlatform() === 'ios';

// One-shot per app load: the isolates stay warm for minutes once
// booted, so re-warming on StrictMode remounts or back-and-forth
// onboarding navigation would only waste requests.
let edgeWarmupFired = false;

/**
 * Boot the sign-in edge functions' isolates while the user is still
 * reading the onboarding screens. Cold starts cost 1-3.5s each and sit
 * exactly on the sign-in critical path (link-pubkey, then
 * register-device). A bare OPTIONS
 * request only runs each function's CORS branch: no auth, no body, no
 * database - it exists purely to spin up the isolate so the real calls
 * during sign-in hit warm instances. Fire-and-forget; failures are
 * expected offline and must never affect onboarding.
 */
function warmAuthEdgeFunctions(): void {
  if (edgeWarmupFired || isDemoMode()) return;
  edgeWarmupFired = true;
  const base = import.meta.env.VITE_SUPABASE_URL as string | undefined;
  if (!base) return;
  const fns = ['link-pubkey', 'register-device'];
  for (const fn of fns) {
    void fetch(`${base}/functions/v1/${fn}`, { method: 'OPTIONS' }).catch(() => {});
  }
}

type Mode = 'choose' | 'create' | 'import' | 'signin';


/**
 * Minimal full-screen wrapper for post-OAuth steps (custody choice,
 * phrase entry for returning users). Shows only the logo + a centered
 * card - no hero text, feature pillars, or pricing. Gives the user a
 * clear visual break after the Google redirect.
 */
function OAuthSetupScreen({ children }: { children: ReactNode }) {
  return (
    <div className="pn-washi min-h-screen bg-[var(--wl-bg)] text-[var(--wl-ink)] flex flex-col items-center justify-center px-5 py-10">
      {/* The washi variables live in FX_CSS; this screen renders without
          the LandingPage shell, so it brings the style tag itself. */}
      <style>{FX_CSS}</style>
      {/* Logo */}
      <div className="flex items-center gap-3 mb-8">
        <LogoIcon size={56} className="text-accent w-14 h-14" />
        <span className="text-3xl tracking-tight">
          <Brand />
        </span>
      </div>
      {/* Step card */}
      <div className="w-full max-w-md">
        <div className="rounded-2xl border border-[var(--wl-line)] bg-[var(--wl-card)] shadow-sm p-5 sm:p-6">
          {children}
        </div>
      </div>
    </div>
  );
}


/** Detect OAuth redirect tokens in the URL hash on mount. */
function hasOAuthHashTokens(): boolean {
  try {
    return window.location.hash.includes('access_token=');
  } catch { return false; }
}

export function Onboarding({ onAuthedEnterApp }: { onAuthedEnterApp?: () => void } = {}) {
  const { auth, signOut } = useAuth();
  const [mode, setMode] = useState<Mode>('choose');
  const [pendingPhrase, setPendingPhrase] = useState<string | null>(null);
  // When false, session data goes into sessionStorage (cleared on tab close).
  const [trustDevice, setTrustDevice] = useState(true);

  // True while hydration is still running after an OAuth redirect. Shows
  // the setup screen with a spinner immediately so the user doesn't stare
  // at the marketing page wondering if the sign-in worked.
  const [oauthLoading, setOauthLoading] = useState(hasOAuthHashTokens);
  useEffect(() => {
    // Once auth resolves past 'loading', hydration is done.
    if (auth.status !== 'loading') setOauthLoading(false);
  }, [auth.status]);

  // Pre-warm the sign-in edge functions - see warmAuthEdgeFunctions.
  useEffect(() => {
    warmAuthEdgeFunctions();
  }, []);

  // Returning OAuth users: hydrate sets this flag so we show a focused
  // "enter your phrase" screen instead of the full landing page.
  // Once set, stays true through the entire import->signin flow so the
  // user never sees the marketing page mid-auth.
  const [oauthHandoff, setOauthHandoff] = useState(false);
  useEffect(() => {
    if (auth.status !== 'onboarding') return;
    try {
      if (sessionStorage.getItem('privacynotes.oauth.handoffPending') === '1') {
        setOauthHandoff(true);
        sessionStorage.removeItem('privacynotes.oauth.handoffPending');
      }
    } catch { /* ignore */ }
    // Depend on the whole `auth` object, not just `auth.status`: a native
    // OAuth handoff that lands while we are ALREADY on 'onboarding' (sign
    // out, then sign in again) re-runs setAuth('onboarding') with a fresh
    // object but an unchanged status string. Keying on the status string
    // alone would miss it and never show the phrase-entry handoff.
  }, [auth]);

  // Force light theme on the landing page - the marketing copy and brand
  // palette are designed for light mode. The OAuth setup screens (redirect
  // spinner, custody choice, returning-user phrase handoff) never show the
  // landing page, so they adopt the stored/system theme like the rest of
  // the app. On unmount (sign-in), restore the user's stored preference
  // from localStorage so the app gets the right theme even before
  // NotesView's useTheme hook runs.
  const inOAuthFlow = oauthLoading || oauthHandoff || auth.status === 'oauth_custody_choice';

  // Warm the NotesView chunk as soon as the visitor commits to an auth
  // flow (any phrase step, or any OAuth setup screen). The chunk then
  // downloads in parallel with the sign-in round-trips, so the post-auth
  // <Suspense> fallback in App.tsx resolves instantly instead of showing
  // a second full-screen typewriter while the notes app downloads.
  // Pure marketing visitors never trigger this, so the code-split still
  // pays off where it matters. Repeat calls hit the module cache.
  useEffect(() => {
    if (inOAuthFlow || mode !== 'choose') {
      void import('./NotesView');
    }
  }, [inOAuthFlow, mode]);
  useEffect(() => {
    // The marketing page and the auth screens all follow the stored/system
    // theme, like the rest of the app; the landing header's ThemeToggle
    // pins an explicit choice. The landing was pinned light until the washi
    // redesign shipped a real dark palette for it (LandingPage FX_CSS).
    // This call still matters: it re-resolves the mode on entry, so a stale
    // paint from a previous view cannot survive into this one.
    applyStoredTheme();
  }, [inOAuthFlow]);

  // Re-resolve the stored theme on unmount as well. The Turnstile script is
  // deliberately not preloaded: it is fetched only if the server actually
  // asks for a challenge, so onboarding hits challenges.cloudflare.com only
  // when there is something to solve.
  useEffect(() => {
    return () => {
      applyStoredTheme();
    };
  }, []);

  // Track which mode spawned the sign-in step so Back returns there.
  const [preSignInMode, setPreSignInMode] = useState<'create' | 'import'>('import');

  function onPhraseReady(phrase: string) {
    setPreSignInMode(mode as 'create' | 'import');
    // Record whether this phrase came from "Sign in with existing
    // phrase" (import) vs a freshly generated one (create). NotesView's
    // welcome-note seed gate reads this: when an *imported* phrase turns
    // out to have no server data, the user expected an existing vault,
    // so we skip the onboarding seed and surface a "new vault created"
    // notice instead of silently fabricating content.
    try {
      if (mode === 'import') {
        sessionStorage.setItem('privacynotes.phraseImport', '1');
      } else {
        sessionStorage.removeItem('privacynotes.phraseImport');
      }
    } catch { /* ignore */ }
    setPendingPhrase(phrase);
    setMode('signin');
  }

  function handleSignInBack() {
    setPendingPhrase(null);
    setMode(preSignInMode);
  }

  // --- OAuth flows: full-screen setup screen, no marketing content ---

  // OAuth redirect in progress: show spinner immediately so the user
  // sees the setup screen instead of the marketing page during hydration.
  if (oauthLoading) {
    return (
      <OAuthSetupScreen>
        <LoadingScreen inline />
      </OAuthSetupScreen>
    );
  }

  // New OAuth user: custody choice
  if (auth.status === 'oauth_custody_choice') {
    return (
      <OAuthSetupScreen>
        <KeyCustodyChoice onBack={() => { void signOut(); }} />
      </OAuthSetupScreen>
    );
  }

  // Returning OAuth user: handoff screen or subsequent phrase entry/signin
  if (oauthHandoff) {
    let content: ReactNode;
    if (mode === 'choose') {
      // Initial handoff: "Google verified, enter your phrase"
      content = <OAuthHandoffStep onEnterPhrase={() => setMode('import')} onBack={() => setOauthHandoff(false)} />;
    } else if (mode === 'import') {
      content = (
        <ImportPhrase
          onReady={onPhraseReady}
          onBack={() => setMode('choose')}
          trustDevice={trustDevice}
          onTrustDeviceChange={setTrustDevice}
        />
      );
    } else if (mode === 'signin' && pendingPhrase) {
      content = <SignInStep phrase={pendingPhrase} trustDevice={trustDevice} freshVault={preSignInMode === 'create'} onBack={handleSignInBack} />;
    } else {
      content = null;
    }
    return (
      <OAuthSetupScreen>
        {content}
      </OAuthSetupScreen>
    );
  }

  // --- Normal (non-OAuth) onboarding: full landing page ---
  return (
    <LandingPage onAuthedEnterApp={onAuthedEnterApp}>
      {mode === 'choose' ? (
        <ChooseMode onPick={setMode} />
      ) : mode === 'create' ? (
        <CreatePhrase
          onReady={onPhraseReady}
          onBack={() => setMode('choose')}
          trustDevice={trustDevice}
          onTrustDeviceChange={setTrustDevice}
        />
      ) : mode === 'import' ? (
        <ImportPhrase
          onReady={onPhraseReady}
          onBack={() => setMode('choose')}
          trustDevice={trustDevice}
          onTrustDeviceChange={setTrustDevice}
        />
      ) : pendingPhrase ? (
        <SignInStep phrase={pendingPhrase} trustDevice={trustDevice} freshVault={preSignInMode === 'create'} onBack={handleSignInBack} />
      ) : null}
    </LandingPage>
  );
}


/**
 * Shown inside OAuthSetupScreen for returning OAuth users whose data
 * is locked behind a phrase. Extracted from ChooseMode so the handoff
 * flow lives entirely at the Onboarding level.
 */
function OAuthHandoffStep({ onEnterPhrase, onBack }: { onEnterPhrase: () => void; onBack: () => void }) {
  const { t } = useTranslation('auth');
  return (
    <div className="space-y-5">
      {/* Success confirmation */}
      <div className="text-center space-y-1">
        <div className="flex items-center justify-center w-10 h-10 rounded-full bg-green-500 mx-auto">
          <Check size={18} className="text-white" aria-hidden="true" />
        </div>
        <h3 className="text-lg font-bold text-[var(--wl-ink)] mt-3">
          {t('oauthHandoff.verifiedTitle')}
        </h3>
        <p className="text-sm text-[var(--wl-sub)] leading-relaxed">
          {t('oauthHandoff.verifiedBody')}
        </p>
      </div>

      <button
        type="button"
        onClick={onEnterPhrase}
        className="w-full rounded-lg bg-[var(--wl-pro)] text-white hover:bg-[var(--wl-pro)]/90 px-4 py-3 font-medium transition shadow-sm"
      >
        {t('oauthHandoff.enterPhrase')}
      </button>

      <p className="text-sm text-[var(--wl-sub)] text-center leading-relaxed">
        <Trans i18nKey="auth:oauthHandoff.noPhraseHint" components={{ strong: <strong /> }} />
      </p>

      <button
        type="button"
        onClick={onBack}
        className="w-full text-sm text-[var(--wl-sub)] hover:text-[var(--wl-ink)] transition py-1"
      >
        {t('oauthHandoff.backToOptions')}
      </button>
    </div>
  );
}


function ChooseMode({ onPick }: { onPick: (m: Mode) => void }) {
  const { t } = useTranslation('auth');
  const { signInWithOAuth } = useAuth();
  const [oauthPending, setOauthPending] = useState<null | 'google' | 'apple' | 'github'>(
    null
  );
  const [oauthError, setOauthError] = useState<string | null>(null);
  const [ladderOpen, setLadderOpen] = useState(false);

  // Reset "Redirecting..." state when the user navigates back via browser
  // Back button. The OAuth redirect navigates away entirely; if the user
  // hits Back, the browser restores this page from bfcache (pageshow with
  // persisted=true) or re-renders it (popstate). Without this reset the
  // button stays stuck on "Redirecting..." until a manual refresh.
  // See: github.com/LifetimeLabsDev/PrivacyNotes.app/issues/123
  useEffect(() => {
    function reset() { setOauthPending(null); }
    function handlePageShow(e: PageTransitionEvent) {
      if (e.persisted) reset();
    }
    window.addEventListener('pageshow', handlePageShow);
    window.addEventListener('popstate', reset);
    return () => {
      window.removeEventListener('pageshow', handlePageShow);
      window.removeEventListener('popstate', reset);
    };
  }, []);

  async function handleOAuth(provider: 'google' | 'apple' | 'github') {
    setOauthError(null);
    setOauthPending(provider);
    const result = await signInWithOAuth(provider);
    // On success the browser navigates away; on failure we surface the
    // error inline and clear the pending state so the user can retry.
    if (!result.ok) {
      setOauthError(result.error);
      setOauthPending(null);
    }
  }

  // ---------- Default: normal login options ----------
  return (
    <div className="space-y-6">
      <h3 className="text-3xl sm:text-4xl font-black tracking-tight text-[var(--wl-ink)]">
        {t('chooseMode.welcomeBack')}
      </h3>

      <div className="grid sm:grid-cols-2 gap-4">
        {/* Easy & Convenient - OAuth providers */}
        <div className="rounded-2xl border border-[var(--wl-line)] bg-[var(--wl-bg)] shadow-sm p-5 flex flex-col gap-3">
          <div className="flex-1">
            <div className="text-sm font-semibold text-[var(--wl-ink)]">
              {t('chooseMode.easyTitle')}
            </div>
            <div className="text-xs text-[var(--wl-sub)] mt-0.5">
              {t('chooseMode.easySubtitle')}
            </div>
          </div>
          <div className="space-y-2">
            {OAUTH_ORDER.map((p) => {
              const { Icon, labelKey } = OAUTH_META[p];
              return (
                <button
                  key={p}
                  type="button"
                  disabled={oauthPending !== null}
                  onClick={() => handleOAuth(p)}
                  className="w-full rounded-lg border border-[var(--wl-line)] bg-[var(--wl-card)] px-4 py-3 font-medium text-[var(--wl-ink)] flex items-center justify-center gap-2.5 hover:bg-[var(--wl-tint)] transition disabled:opacity-60 disabled:cursor-not-allowed"
                >
                  <Icon />
                  {oauthPending === p ? t('chooseMode.redirecting') : t(labelKey)}
                </button>
              );
            })}
          </div>
          {oauthError && (
            <p className="text-sm text-red-500 dark:text-red-400">{oauthError}</p>
          )}
        </div>

        {/* Anonymous & Uncompromising - phrase auth */}
        <div className="rounded-2xl border border-[var(--wl-line)] bg-[var(--wl-bg)] shadow-sm p-5 flex flex-col gap-3">
          <div className="flex-1">
            <div className="text-sm font-semibold text-[var(--wl-ink)]">
              {t('chooseMode.anonymousTitle')}
            </div>
            <div className="text-xs text-[var(--wl-sub)] mt-0.5">
              {t('chooseMode.anonymousSubtitle')}
            </div>
          </div>
          <div className="space-y-2">
            <button
              onClick={() => onPick('create')}
              className="w-full rounded-lg bg-[var(--wl-pro)] text-white hover:bg-[var(--wl-pro)]/90 px-4 py-3 font-medium transition shadow-sm flex items-center justify-center gap-2.5"
            >
              <Password size={16} aria-hidden="true" />
              {t('chooseMode.generatePhrase')}
            </button>
            <button
              onClick={() => onPick('import')}
              className="w-full rounded-lg border border-[var(--wl-line)] hover:bg-[var(--wl-tint)] px-4 py-3 font-medium transition flex items-center justify-center gap-2.5"
            >
              <KeyReturn size={16} aria-hidden="true" />
              {t('chooseMode.signInExisting')}
            </button>
            {/* Third row on this side, so the two cards stay the same height
                once GitHub makes three buttons of the other one. Deliberately
                quieter than its neighbours - it is not a way to sign in, and
                at equal weight it read as one. */}
            <button
              type="button"
              onClick={() => setLadderOpen((v) => !v)}
              aria-expanded={ladderOpen}
              aria-controls="pn-signin-ladder"
              className="w-full rounded-lg border border-[var(--wl-line)] hover:bg-[var(--wl-tint)] px-4 py-3 text-[var(--wl-sub)] flex items-center justify-center gap-2 transition"
            >
              <Scales size={16} aria-hidden="true" />
              {t('chooseMode.compareOptions')}
              <CaretDown
                size={13}
                aria-hidden="true"
                className={`transition-transform ${ladderOpen ? 'rotate-180' : ''}`}
              />
            </button>
          </div>
        </div>
      </div>

      {ladderOpen && <PrivacyLadder id="pn-signin-ladder" tone="washi" />}

      {/* Trust signals */}
      <div className="pt-4 border-t border-[var(--wl-line)] flex flex-col sm:flex-row sm:flex-wrap items-center justify-center gap-x-6 gap-y-1.5 text-[11px] text-[var(--wl-sub)]">
        <span className="inline-flex items-center gap-1.5">
          <svg width="11" height="11" viewBox="0 0 32 32" aria-hidden="true" className="shrink-0 rounded-[2px]">
            <rect width="32" height="32" fill="#da291c" />
            <rect x="13" y="6" width="6" height="20" fill="#fff" />
            <rect x="6" y="13" width="20" height="6" fill="#fff" />
          </svg>
          {t('chooseMode.trustSwitzerland')}
        </span>
        <span className="inline-flex items-center gap-1.5">
          <Lock size={12} />
          {t('chooseMode.trustEncrypted')}
        </span>
        <span className="inline-flex items-center gap-1.5">
          <Check size={12} className="text-emerald-500" />
          {t('chooseMode.trustAuditable')}
        </span>
      </div>
    </div>
  );
}

function AppleIcon() {
  return (
    <svg width="16" height="18" viewBox="0 0 384 512" aria-hidden="true" className="shrink-0">
      <path
        fill="currentColor"
        d="M318.7 268.7c-.2-36.7 16.4-64.4 50-84.8-18.8-26.9-47.2-41.7-84.7-44.6-35.5-2.8-74.3 20.7-88.5 20.7-15 0-49.4-19.7-76.4-19.7C63.3 141.2 4 184.8 4 273.5q0 39.3 14.4 81.2c12.8 36.7 59 126.7 107.2 125.2 25.2-.6 43-17.9 75.8-17.9 31.8 0 48.3 17.9 76.4 17.9 48.6-.7 90.4-82.5 102.6-119.3-65.2-30.7-61.7-90-61.7-91.9zm-56.6-164.2c27.3-32.4 24.8-61.9 24-72.5-24.1 1.4-52 16.4-67.9 34.9-17.5 19.8-27.8 44.3-25.6 71.9 26.1 2 49.9-11.4 69.5-34.3z"
      />
    </svg>
  );
}

function GoogleIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 48 48" aria-hidden="true" className="shrink-0">
      <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z" />
      <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z" />
      <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z" />
      <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z" />
    </svg>
  );
}

function GithubIcon() {
  return (
    <svg width="17" height="17" viewBox="0 0 16 16" aria-hidden="true" className="shrink-0">
      <path
        fill="currentColor"
        d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.6 7.6 0 0 1 2-.27c.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"
      />
    </svg>
  );
}

/**
 * Sign-in order. Native iOS surfaces Sign in with Apple first (App Store
 * expectation); everywhere else Google leads. GitHub is last on both, and
 * `OAuthProvider` keys the map so adding a fourth provider is one entry
 * here plus one label in the catalog.
 */
const OAUTH_ORDER: readonly OAuthProvider[] = IS_IOS
  ? ['apple', 'google', 'github']
  : ['google', 'apple', 'github'];

const OAUTH_META: Record<OAuthProvider, { Icon: () => ReactNode; labelKey: string }> = {
  google: { Icon: GoogleIcon, labelKey: 'chooseMode.continueGoogle' },
  apple: { Icon: AppleIcon, labelKey: 'chooseMode.continueApple' },
  github: { Icon: GithubIcon, labelKey: 'chooseMode.continueGithub' },
};

/**
 * Key custody choice screen for new OAuth users.
 * "Keep it simple & convenient" (custodial) vs "Maximum security & privacy" (self-custody).
 * Spec: ops/docs/custodial-key-spec.md (one-way: custodial can upgrade later, self-custody cannot downgrade)
 */
function KeyCustodyChoice({ onBack }: { onBack: () => void }) {
  const { t } = useTranslation('auth');
  const { completeCustodyChoice } = useAuth();
  const [choice, setChoice] = useState<'custodial' | 'self-custody'>('custodial');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleContinue() {
    if (choice === 'self-custody') {
      // Generate phrase and authenticate, then show backup screen.
      setBusy(true);
      setError(null);
      const result = await completeCustodyChoice('self-custody');
      setBusy(false);
      if (!result.ok) {
        setError(result.error);
        return;
      }
      // User is now authenticated but we want them to see their phrase.
      // The auth state is 'authenticated' with showPhraseOnce flag set.
      // NotesView will pop the phrase tab. Nothing more to do here.
      return;
    }

    // Custodial path: authenticate + store phrase server-side.
    setBusy(true);
    setError(null);
    const result = await completeCustodyChoice('custodial');
    setBusy(false);
    if (!result.ok) {
      setError(result.error);
    }
    // On success, auth state transitions to 'authenticated' and
    // App.tsx renders NotesView. No phrase reveal needed.
  }

  if (busy) {
    return <LoadingScreen inline />;
  }

  const tradeoffText = choice === 'custodial'
    ? t('custody.tradeoffCustodial')
    : t('custody.tradeoffSelfCustody');

  return (
    <div className="space-y-5">
      {/* Welcome header */}
      <div className="text-center space-y-1">
        <div className="flex items-center justify-center w-10 h-10 rounded-full bg-green-500 mx-auto">
          <Check size={18} className="text-white" aria-hidden="true" />
        </div>
        <h3 className="text-lg font-bold text-[var(--wl-ink)] mt-3">
          {t('custody.signedInGoogle')}
        </h3>
        <p className="text-sm text-[var(--wl-sub)]">
          {t('custody.intro')}
        </p>
      </div>

      {/* Custodial option */}
      <button
        type="button"
        onClick={() => setChoice('custodial')}
        className={`w-full text-start rounded-xl p-4 transition ${
          choice === 'custodial'
            ? 'border-2 border-accent bg-[var(--wl-bg)]'
            : 'border border-[var(--wl-line)] bg-[var(--wl-bg)]'
        }`}
      >
        <div className="flex items-start gap-3">
          <div className={`w-5 h-5 rounded-full border-2 mt-0.5 flex items-center justify-center shrink-0 ${
            choice === 'custodial' ? 'border-accent' : 'border-[var(--wl-muted)]/60'
          }`}>
            {choice === 'custodial' && (
              <div className="w-2.5 h-2.5 rounded-full bg-accent" />
            )}
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between gap-2">
              <div className="font-medium text-sm text-[var(--wl-ink)]">
                {t('custody.simpleTitle')}
              </div>
              {choice === 'custodial' && (
                <span className="text-[11px] font-medium bg-accent/10 text-accent px-2.5 py-0.5 rounded-md shrink-0">
                  {t('custody.recommended')}
                </span>
              )}
            </div>
            <div className="text-xs text-[var(--wl-sub)] mt-1 leading-relaxed">
              {t('custody.simpleBody')}
            </div>
          </div>
        </div>
      </button>

      {/* Self-custody option */}
      <button
        type="button"
        onClick={() => setChoice('self-custody')}
        className={`w-full text-start rounded-xl p-4 transition ${
          choice === 'self-custody'
            ? 'border-2 border-accent bg-[var(--wl-bg)]'
            : 'border border-[var(--wl-line)] bg-[var(--wl-bg)]'
        }`}
      >
        <div className="flex items-start gap-3">
          <div className={`w-5 h-5 rounded-full border-2 mt-0.5 flex items-center justify-center shrink-0 ${
            choice === 'self-custody' ? 'border-accent' : 'border-[var(--wl-muted)]/60'
          }`}>
            {choice === 'self-custody' && (
              <div className="w-2.5 h-2.5 rounded-full bg-accent" />
            )}
          </div>
          <div>
            <div className="font-medium text-sm text-[var(--wl-ink)]">
              {t('custody.maxSecurityTitle')}
            </div>
            <div className="text-xs text-[var(--wl-sub)] mt-1 leading-relaxed">
              {t('custody.maxSecurityBody')}
            </div>
          </div>
        </div>
      </button>

      {error && (
        <p className="text-sm text-red-500 dark:text-red-400">{error}</p>
      )}

      <button
        type="button"
        onClick={handleContinue}
        className="w-full rounded-lg bg-[var(--wl-pro)] text-white hover:bg-[var(--wl-pro)]/90 px-4 py-3 font-medium transition shadow-sm"
      >
        {t('continue')}
      </button>

      <p className="text-xs text-[var(--wl-muted)] text-center leading-relaxed">
        {tradeoffText}
      </p>

      <button
        type="button"
        onClick={onBack}
        className="w-full text-sm text-[var(--wl-sub)] hover:text-[var(--wl-ink)] transition py-1"
      >
        {t('oauthHandoff.backToOptions')}
      </button>
    </div>
  );
}


function TrustDeviceCheckbox({
  trustDevice,
  onTrustDeviceChange,
}: {
  trustDevice: boolean;
  onTrustDeviceChange: (v: boolean) => void;
}) {
  const { t } = useTranslation('auth');
  return (
    <label className="flex items-start gap-2 text-sm text-[var(--wl-ink)] cursor-pointer rounded-md border border-[var(--wl-line)] bg-[var(--wl-bg)] p-3">
      <input
        type="checkbox"
        checked={trustDevice}
        onChange={(e) => onTrustDeviceChange(e.target.checked)}
        className="mt-0.5 h-4 w-4 shrink-0 accent-accent"
      />
      <span>
        <span className="font-medium">{t('trustDevice.label')}</span>
        <span className="block text-xs text-[var(--wl-sub)] mt-0.5 leading-relaxed">
          {t('trustDevice.description')}
        </span>
      </span>
    </label>
  );
}

function CreatePhrase({
  onReady,
  onBack,
  trustDevice,
  onTrustDeviceChange,
}: {
  onReady: (phrase: string) => void;
  onBack: () => void;
  trustDevice: boolean;
  onTrustDeviceChange: (v: boolean) => void;
}) {
  const { t } = useTranslation('auth');
  const [phrase] = useState(() => generatePhrase());
  const [confirmed, setConfirmed] = useState(false);
  const [copied, setCopied] = useState(false);
  const qrWrapperRef = useRef<HTMLDivElement | null>(null);

  const words = phrase.split(' ');

  async function copyPhrase() {
    try {
      await navigator.clipboard.writeText(phrase);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      /* ignore */
    }
  }

  // Download only. Never route the phrase through `navigator.share` -
  // it decrypts the entire vault. Direct local save only (same rule as
  // PhraseView's Save QR).
  function downloadBlob(blob: Blob, filename: string) {
    // Direct local save only (web download / native Save As).
    void saveBlob(blob, filename);
  }

  function handleDownloadTxt() {
    const text = buildPhraseFile(phrase, {
      title: t('createPhrase.txtTitle'),
      oneLine: t('createPhrase.txtOneLine'),
      footer: t('createPhrase.txtFooter'),
    });
    downloadBlob(new Blob([text], { type: 'text/plain' }), PHRASE_FILE_NAME);
  }

  async function handleDownloadQR() {
    const canvas = qrWrapperRef.current?.querySelector('canvas');
    if (!canvas) return;
    const blob = await new Promise<Blob | null>((resolve) => {
      try {
        canvas.toBlob((b) => resolve(b), 'image/png');
      } catch {
        resolve(null);
      }
    });
    if (!blob) return;
    downloadBlob(blob, 'privacynotes-phrase-qr.png');
  }

  return (
    <div className="space-y-4">
      <div className="rounded-md border border-[var(--wl-line)] bg-[var(--wl-bg)] p-3 text-sm leading-relaxed text-[var(--wl-ink)] flex items-start gap-2.5">
        <Warning size={18} aria-hidden="true" className="shrink-0 mt-0.5 text-amber-500 dark:text-amber-400" />
        <span>
          <Trans i18nKey="auth:createPhrase.warning" components={{ strong: <strong /> }} />
        </span>
      </div>

      {/* Two columns below sm: at 375px a three-column cell holds 69px of
          content, and an eight-letter word plus its index needs 87px, so
          the longest words in the BIP-39 list painted over the cell border
          and into the next one. */}
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-2" dir="ltr">
        {/* rtl-ok: BIP-39 phrase words, always LTR */}
        {words.map((w, i) => (
          <div
            key={i}
            className="rounded-md bg-[var(--wl-bg)] border border-[var(--wl-line)] text-[var(--wl-ink)] px-3 py-2 text-sm font-mono"
          >
            <span className="text-[var(--wl-muted)] text-xs me-1">{i + 1}.</span>
            {w}
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
        <button
          onClick={copyPhrase}
          className={`inline-flex items-center justify-center gap-1.5 rounded-md border px-3 py-2 text-sm transition ${
            copied
              ? 'border-accent bg-accent/10 text-accent'
              : 'border-[var(--wl-line)] hover:bg-[var(--wl-tint)]'
          }`}
        >
          {copied ? (
            <>
              <Check aria-hidden="true" />
              {t('createPhrase.copied')}
            </>
          ) : (
            <>
              <Copy aria-hidden="true" />
              {t('common:actions.copy')}
            </>
          )}
        </button>
        <button
          onClick={handleDownloadTxt}
          className="inline-flex items-center justify-center gap-1.5 rounded-md border border-[var(--wl-line)] hover:bg-[var(--wl-tint)] px-3 py-2 text-sm transition"
        >
          <FileText aria-hidden="true" />
          {t('createPhrase.downloadTxt')}
        </button>
        <button
          onClick={() => { void handleDownloadQR(); }}
          className="inline-flex items-center justify-center gap-1.5 rounded-md border border-[var(--wl-line)] hover:bg-[var(--wl-tint)] px-3 py-2 text-sm transition"
        >
          <QrCode aria-hidden="true" />
          {t('createPhrase.downloadQr')}
        </button>
      </div>

      {/* Hidden QR canvas: stays mounted so Download QR can always read
          it. marginSize=4 bakes a spec-compliant quiet zone into the
          canvas pixels (see PhraseView for the full rationale). */}
      <div className="hidden" ref={qrWrapperRef} aria-hidden="true">
        <QRCodeCanvas value={buildSignInUrl(phrase)} size={320} level="M" marginSize={4} />
      </div>

      <label className="flex items-start gap-2 text-sm text-[var(--wl-ink)] cursor-pointer rounded-md border border-[var(--wl-line)] bg-[var(--wl-bg)] p-3">
        <input
          type="checkbox"
          checked={confirmed}
          onChange={(e) => setConfirmed(e.target.checked)}
          className="mt-0.5 h-4 w-4 shrink-0 accent-accent"
        />
        <span className="font-medium">
          {t('createPhrase.stored')}
        </span>
      </label>

      <TrustDeviceCheckbox
        trustDevice={trustDevice}
        onTrustDeviceChange={onTrustDeviceChange}
      />

      <div className="grid grid-cols-2 gap-2">
        <button
          onClick={onBack}
          className="inline-flex items-center justify-center gap-1.5 rounded-md border border-[var(--wl-line)] hover:bg-[var(--wl-tint)] px-4 py-2 text-sm transition"
        >
          <ArrowLeft aria-hidden="true" />
          {t('createPhrase.oneClickInstead')}
        </button>
        <button
          onClick={() => onReady(phrase)}
          disabled={!confirmed}
          className="inline-flex items-center justify-center gap-1.5 rounded-md bg-[var(--wl-pro)] text-white hover:bg-[var(--wl-pro)]/90 px-4 py-2 text-sm font-medium disabled:opacity-40 disabled:cursor-not-allowed transition"
        >
          {t('continue')}
          <ArrowRight aria-hidden="true" />
        </button>
      </div>

    </div>
  );
}

function ImportPhrase({
  onReady,
  onBack,
  trustDevice,
  onTrustDeviceChange,
}: {
  onReady: (phrase: string) => void;
  onBack: () => void;
  trustDevice: boolean;
  onTrustDeviceChange: (v: boolean) => void;
}) {
  const { t } = useTranslation('auth');
  const [input, setInput] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [showScanner, setShowScanner] = useState(false);
  const [scanning, setScanning] = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  function handleSubmit() {
    const trimmed = input.trim().toLowerCase();
    if (!isValidPhrase(trimmed)) {
      setError(t('importPhrase.invalidPhrase'));
      return;
    }
    onReady(trimmed);
  }

  // Scanner success path: fill the textarea instead of auto-advancing,
  // so the user can eyeball the phrase before committing. A surprise
  // auto-sign-in would make scan-a-wrong-QR mistakes invisible.
  function handleScanned(phrase: string) {
    setInput(phrase);
    setError(null);
    setShowScanner(false);
  }

  // Upload path: decode a QR out of a chosen image file and fill the
  // textarea (same review-before-commit rationale as handleScanned). No
  // camera needed, so this also covers Linux native, where getUserMedia
  // is dead. Reuses the same qr-scanner scanImage decode the modal uses.
  async function handleUploadFile(file: File) {
    setScanning(true);
    setError(null);
    try {
      const mod = await import('qr-scanner');
      const QrScanner: any = (mod as any).default ?? mod;
      const decoded: string = await QrScanner.scanImage(file);
      const phrase = extractPhraseFromScan(decoded);
      if (!phrase) {
        setError(t('qrScanner.imageNotSignInCode'));
        return;
      }
      setInput(phrase);
    } catch {
      setError(t('qrScanner.imageUnreadable'));
    } finally {
      setScanning(false);
      // Reset so picking the same file again still fires onChange.
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-[var(--wl-sub)]">
        {t('importPhrase.instructions')}
      </p>
      <textarea
        value={input}
        onChange={(e) => {
          setInput(e.target.value);
          setError(null);
        }}
        placeholder={t('importPhrase.placeholder')}
        rows={3}
        dir="ltr" // rtl-ok: BIP-39 phrase words, always LTR
        className="w-full rounded-md bg-[var(--wl-bg)] border border-[var(--wl-line)] text-[var(--wl-ink)] focus:border-accent p-3 text-sm font-mono focus:outline-none placeholder:text-[var(--wl-muted)]"
        autoFocus
      />
      <div
        className={`grid gap-2 ${
          isLinuxNative() ? 'grid-cols-1' : 'grid-cols-1 sm:grid-cols-2'
        }`}
      >
        <button
          type="button"
          onClick={() => fileInputRef.current?.click()}
          disabled={scanning}
          className="w-full rounded-md border border-[var(--wl-line)] hover:bg-[var(--wl-tint)] px-3 py-2 text-sm transition flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <Upload size={16} />
          {scanning ? t('qrScanner.readingImage') : t('importPhrase.uploadQr')}
        </button>
        {!isLinuxNative() && (
          <button
            type="button"
            onClick={() => setShowScanner(true)}
            className="w-full rounded-md border border-[var(--wl-line)] hover:bg-[var(--wl-tint)] px-3 py-2 text-sm transition flex items-center justify-center gap-2"
          >
            <Scan size={16} />
            {t('importPhrase.scanQr')}
          </button>
        )}
      </div>
      <input
        ref={fileInputRef}
        type="file"
        accept="image/*"
        className="hidden"
        onChange={(e) => {
          const file = e.target.files?.[0];
          if (file) void handleUploadFile(file);
        }}
      />
      {error && <p className="text-sm text-red-500 dark:text-red-400">{error}</p>}
      <TrustDeviceCheckbox
        trustDevice={trustDevice}
        onTrustDeviceChange={onTrustDeviceChange}
      />
      <div className="flex gap-2">
        <button
          onClick={onBack}
          className="rounded-md border border-[var(--wl-line)] hover:bg-[var(--wl-tint)] px-4 py-2 text-sm transition"
        >
          {t('common:actions.back')}
        </button>
        <button
          onClick={handleSubmit}
          disabled={!input.trim()}
          className="flex-1 rounded-md bg-[var(--wl-pro)] text-white hover:bg-[var(--wl-pro)]/90 px-4 py-2 text-sm font-medium disabled:opacity-40 disabled:cursor-not-allowed transition"
        >
          {t('continue')}
        </button>
      </div>

      {showScanner && (
        <QrScannerModal
          onScanned={handleScanned}
          onClose={() => setShowScanner(false)}
        />
      )}
    </div>
  );
}

/** Lean sign-in step: signInWithPhrase straight away, with a Turnstile
 *  challenge only if the server refuses for want of one. Supabase Auth
 *  CAPTCHA is a dashboard toggle nothing in the client can read, so the
 *  refusal IS the signal - a challenge nobody asked for is friction on
 *  every signup and, in a mobile webview, a hard block (#120).
 *  The one-shot Turnstile token is passed through to Supabase Auth as
 *  `captchaToken` on the anonymous sign-in - GoTrue verifies it against
 *  siteverify itself once Attack Protection CAPTCHA is enabled, so the
 *  token must NOT be spent on any other siteverify call first.
 *  PIN and biometric setup are deliberately not part of onboarding - both
 *  are available later from Security settings. */
function SignInStep({
  phrase,
  trustDevice,
  freshVault,
  onBack,
}: {
  phrase: string;
  trustDevice: boolean;
  /** True when this phrase was generated by the create flow, so the
   *  vault is provably new and may seed its onboarding notes. */
  freshVault: boolean;
  onBack: () => void;
}) {
  const { t } = useTranslation('auth');
  const { signInWithPhrase } = useAuth();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Signing in with a phrase this device does not own destroys what is
  // on it. The question is asked here rather than inside the sign-in,
  // which also runs on boot paths with no screen to ask from, and only a
  // person on the signed-out screen ever sees it - which is where
  // switching accounts is the deliberate act it looks like.
  const [askSwitch, setAskSwitch] = useState(false);
  const switchConfirmed = useRef(false);

  const [turnstileOk, setTurnstileOk] = useState(false);
  const [turnstileKey, setTurnstileKey] = useState(0);
  const autoFired = useRef(false);
  const captchaTokenRef = useRef<string | null>(null);
  // Set only after the server has actually refused a tokenless sign-in.
  // Until then no challenge is rendered and nothing is fetched from
  // Cloudflare - and under the web-only link-pubkey gate, native
  // clients are never refused, so the widget below is web-only in
  // practice. Spec: ops/docs/design-decisions.md (Turnstile is
  // web-only, enforced at link-pubkey)
  const [needsChallenge, setNeedsChallenge] = useState(false);

  // Warm the NotesView chunk while authentication runs. Without this, the
  // app's <Suspense> fallback paints a SECOND full-screen loading screen
  // after sign-in while the heavy chunk loads cold. Preloading here (the
  // user has already committed a phrase) means the app appears instantly
  // when auth resolves, so phrase sign-in shows exactly one loading state.
  useEffect(() => {
    void import('./NotesView');
  }, []);

  // Network timeout for sign-in - matches the 15s used by the
  // auto-sign-in-on-mount path in auth.tsx. Without this, a hanging
  // network call traps the user on the loading screen indefinitely.
  const SIGNIN_TIMEOUT_MS = 15_000;

  function handleToken(token: string | null) {
    // Missing-site-key builds emit the synthetic 'dev-bypass'
    // token. Never forward it as a captchaToken: with CAPTCHA off
    // GoTrue ignores tokens anyway, and with CAPTCHA on a bogus token
    // and a missing token fail identically - so dev keeps working
    // against a CAPTCHA-off project and fails closed otherwise. The
    // retry it triggers lands on the error screen, which is the honest
    // outcome for a keyless build against an enforcing server.
    if (token === 'dev-bypass') {
      setTurnstileOk(true);
      return;
    }
    if (!token) {
      // Challenge errored or the token expired; the widget resets
      // itself for a fresh challenge (see TurnstileWidget callbacks).
      // Gate closes with the token: turnstileOk must never be true
      // while the ref is empty, or the retry submits tokenless again.
      captchaTokenRef.current = null;
      setTurnstileOk(false);
      return;
    }
    captchaTokenRef.current = token;
    // No setError(null) here: after a failed sign-in the error view
    // keeps a live widget whose managed challenge auto-solves within
    // seconds - clearing the error would dismiss the retry screen into
    // a dead "Signing you in" state before the user can read it (the
    // auto-fire latch is still set, so nothing would re-run finish()).
    setTurnstileOk(true);
  }

  async function finish() {
    // Before the loading screen, which would cover the question.
    if (!switchConfirmed.current && (await switchWouldWipe(phrase))) {
      setAskSwitch(true);
      return;
    }
    setBusy(true);
    setError(null);

    try {
      const result = await Promise.race([
        signInWithPhrase(
          phrase,
          trustDevice,
          freshVault,
          captchaTokenRef.current ?? undefined,
        ),
        new Promise<{ ok: false; error: string; captchaRequired?: boolean }>((resolve) =>
          setTimeout(
            () => resolve({ ok: false, error: t('signIn.timedOut') }),
            SIGNIN_TIMEOUT_MS,
          ),
        ),
      ]);
      if (!result.ok) {
        // The token is single-use and now spent (or stale) - drop it so
        // the retry path gets a fresh challenge instead of resubmitting
        // a dead token.
        captchaTokenRef.current = null;
        setBusy(false);
        // The server refused for want of a challenge token: show the
        // challenge and re-arm the latch so its token fires the retry.
        // Not an error state - nothing has gone wrong yet. Guarded on
        // needsChallenge so a token the server rejects surfaces as an
        // error on the second pass instead of looping the user through
        // solve-submit-refuse forever.
        if (result.captchaRequired && !needsChallenge) {
          setNeedsChallenge(true);
          autoFired.current = false;
          return;
        }
        // Latch stays set: a widget already on screen re-solves within
        // seconds, and auto-firing on that token would replace the
        // error with another attempt before the user can read it. Try
        // again is the way out. A second challenge refusal carries the
        // internal 'session_expired' taxonomy string as its message -
        // show the generic failure copy instead of that raw token.
        setError(
          result.captchaRequired ? t('signIn.failedUnexpectedly') : result.error,
        );
      }
    } catch (err) {
      captchaTokenRef.current = null;
      setError((err as Error).message || t('signIn.failedUnexpectedly'));
      setBusy(false);
    }
  }

  // Sign-in is attempted with no token, on every platform: only the
  // server knows whether the link-pubkey gate is enforcing, so the user
  // is shown a challenge only once it actually refuses one. That keeps
  // the TURNSTILE_WEB_ENFORCE secret the single source of truth -
  // flipping it takes effect with no release - and means a vault signup
  // runs zero Turnstile code while enforcement is off or the caller is
  // not a web origin. Re-runs when a challenge token lands (see
  // finish()).
  useEffect(() => {
    if (autoFired.current) return;
    autoFired.current = true;
    void finish();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [turnstileOk]);

  if (askSwitch) {
    return (
      <ConfirmModal
        title={t('signIn.switchTitle')}
        confirmLabel={t('signIn.switchConfirm')}
        variant="warning"
        onConfirm={() => {
          switchConfirmed.current = true;
          setAskSwitch(false);
          void finish();
        }}
        onClose={onBack}
      >
        {t('signIn.switchBody')}
      </ConfirmModal>
    );
  }

  if (busy) {
    return <LoadingScreen inline />;
  }

  // Error state: show the error with retry + back buttons so the user
  // isn't stranded - without them the only escape from a failed sign-in
  // is reloading the entire page and re-entering the phrase.
  if (error) {
    return (
      <div className="space-y-4">
        <div className="rounded-md border border-red-300 dark:border-red-800 bg-red-50 dark:bg-red-950/20 p-3 text-sm text-red-700 dark:text-red-300 leading-relaxed">
          {error}
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={onBack}
            className="rounded-md border border-[var(--wl-line)] hover:bg-[var(--wl-tint)] px-4 py-2 text-sm transition"
          >
            {t('common:actions.back')}
          </button>
          <button
            type="button"
            onClick={() => {
              setError(null);
              autoFired.current = false;
              if (needsChallenge) {
                // A spent token cannot be resubmitted: re-key Turnstile
                // so a fresh challenge issues a fresh one, which
                // triggers finish() via the effect.
                setTurnstileOk(false);
                setTurnstileKey((k) => k + 1);
              } else {
                // No challenge on screen (ordinary failure - offline,
                // timeout): nothing will flip turnstileOk, so fire the
                // retry directly.
                autoFired.current = true;
                void finish();
              }
            }}
            className="flex-1 rounded-md bg-[var(--wl-pro)] text-white hover:bg-[var(--wl-pro)]/90 px-4 py-2 text-sm font-medium transition"
          >
            {t('signIn.tryAgain')}
          </button>
        </div>
        {needsChallenge && (
          <TurnstileWidget
            key={turnstileKey}
            onToken={handleToken}
            // Without this the user waits on "Signing you in..." forever
            // when a challenge cannot complete (#120). Reuses the existing
            // timeout copy; the error branch gives Back + Try again.
            onTimeout={() => setError(t('signIn.timedOut'))}
            className="flex justify-center"
          />
        )}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-[var(--wl-sub)] text-center py-4">
        {t('signIn.signingIn')}
      </p>
      {/* Until the server actually refuses a tokenless sign-in there is
          nothing for the user to do, so show them nothing to do. */}
      {needsChallenge && (
        <TurnstileWidget
          key={turnstileKey}
          onToken={handleToken}
          // Without this a challenge that never completes strands the
          // user on "Signing in..." with no error and no way out - the
          // #120 fix landed on the error branch above and missed this
          // one, which is the path a first sign-in actually takes.
          onTimeout={() => setError(t('signIn.timedOut'))}
          className="flex justify-center"
        />
      )}
    </div>
  );
}
