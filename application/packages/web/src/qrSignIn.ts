import { isValidPhrase } from '@notes/shared';
import { detectPlatform } from './devices';
import { APEX_ORIGIN, APP_ORIGIN, isApexHost } from './hosts';

/**
 * QR sign-in flow helpers.
 *
 * How this fits together:
 *
 * 1. PhraseModal renders a QR whose value is `<origin>/#phrase=word+word…`.
 *    We embed the master secret in the URL FRAGMENT (the bit after `#`),
 *    not as a query string, because fragments are NEVER transmitted to
 *    the server by the browser. They stay entirely client-side - no
 *    access logs, no CDN logs, no WAF logs, no Referer header leaks.
 *
 * 2. The user scans the QR with their phone's native camera app. iOS
 *    Camera (and every other modern scanner) recognizes a URL and
 *    offers "Open in Safari" - one tap to get to PrivacyNotes.
 *
 * 3. When the app loads, `consumePhraseFragment()` runs once. It
 *    extracts the phrase, immediately blanks the fragment out of the
 *    URL via `history.replaceState`, and returns the phrase so the
 *    caller can prompt the user. Blanking clears the address bar and
 *    the current history entry, not the browser's own history, which
 *    keeps the visited URL. That is why no other URL in the app carries
 *    the phrase.
 *
 * 4. The caller (App) shows a confirmation modal - we NEVER sign in
 *    automatically from a fragment. Auto-sign-in from URL would be a
 *    phishing vector: a malicious QR in the wild could silently replace
 *    a user's session with an attacker's phrase and trick them into
 *    writing notes into an account the attacker controls.
 */

/** Encode a phrase into a sign-in URL. */
export function buildSignInUrl(phrase: string): string {
  // The QR is scanned by a phone camera and opened in a browser, so the URL
  // must be a public https origin. On web use the live origin (works on
  // localhost in dev, preview deploys, try.* and use.* - no env var, no
  // stale URL baked into the QR); on native window.location.origin is
  // tauri://localhost, which no scanner can open, so a constant is the only
  // option. Strip www to avoid a redirect hop.
  //
  // The apex is the ONE origin we never mint: sessions live on the app
  // host, and the apex drops a phrase fragment instead of signing in with
  // it (dropApexPhraseFragment). The downloadable phrase-backup QR is a
  // paper credential with no expiry, so it has to name the host that signs
  // in. The apex (and www, which is why this compares origins rather than
  // calling isApexHost) mints the app host instead, and native does the
  // same. An older QR that names the apex still signs in through "Scan QR
  // with camera": `extractPhraseFromScan` accepts any http(s) URL carrying
  // `#phrase=`.
  // Spec: ops/docs/domain-split.md (retirement + sunset)
  const webOrigin =
    typeof window === 'undefined'
      ? ''
      : window.location.origin.replace('://www.', '://');
  const base =
    typeof window === 'undefined'
      ? ''
      : detectPlatform() === 'web'
        ? webOrigin === APEX_ORIGIN
          ? APP_ORIGIN
          : webOrigin
        : APP_ORIGIN;
  // BIP-39 words are all lowercase ASCII a-z; spaces are the only thing
  // we need to escape. `+` is URL-safe and URLSearchParams decodes it
  // back to a space for us, so the QR stays human-readable.
  const encoded = phrase.trim().replace(/\s+/g, '+');
  return `${base}/#phrase=${encoded}`;
}

/** True when a fragment carries a phrase the way consumePhraseFragment reads one. */
function hasPhraseFragment(hash: string): boolean {
  return hash.includes('phrase=');
}

/**
 * If the current URL has a `#phrase=…` fragment, extract the phrase,
 * validate it, blank the fragment out of the URL, and return it. Returns
 * null otherwise. Anything else the fragment carries is ignored. Safe to
 * call unconditionally on every mount.
 *
 * The fragment is cleared REGARDLESS of whether the phrase is valid, so
 * a malformed or attacker-crafted fragment still doesn't stick around
 * in the address bar.
 */
export function consumePhraseFragment(): string | null {
  if (typeof window === 'undefined') return null;
  const hash = window.location.hash;
  if (!hasPhraseFragment(hash)) return null;

  // Parse properly via URLSearchParams so future fragment additions
  // (e.g. `#phrase=…&source=onboarding`) don't break the simple case.
  const params = new URLSearchParams(hash.replace(/^#/, ''));
  const raw = params.get('phrase');

  // Blank the fragment ASAP - before validating, before returning.
  // replaceState keeps us on the same URL minus the hash and without
  // adding a history entry. Some sandboxed iframes (notably iOS in-app
  // webviews) block replaceState. If that happens we MUST force a
  // real navigation instead of swallowing the throw - leaving the
  // phrase in the URL is worse than aborting sign-in. The user will
  // need to re-scan, but the master secret stays out of the address bar
  // and the Referer header on outbound link clicks. See gap #21.
  const cleanUrl =
    window.location.pathname +
    window.location.search;
  try {
    history.replaceState(null, '', cleanUrl || '/');
  } catch {
    window.location.replace(cleanUrl || '/');
    return null;
  }

  if (!raw) return null;
  // BIP-39 words are lowercase, space-separated. Normalize whitespace
  // so we tolerate `+`, `%20`, or accidental double-spaces.
  const phrase = raw.trim().toLowerCase().replace(/\s+/g, ' ');
  return isValidPhrase(phrase) ? phrase : null;
}

/**
 * The apex never signs in from a phrase fragment and never passes one on:
 * sessions live on the app host, and the browser keeps any URL it visits,
 * so a forwarded phrase would be written into its history a second time.
 * The fragment is cleared and the page leaves for the app host's sign-in
 * screen with no fragment. Returns true when it is leaving, so the caller
 * renders nothing.
 */
export function dropApexPhraseFragment(): boolean {
  if (typeof window === 'undefined' || !isApexHost()) return false;
  if (!hasPhraseFragment(window.location.hash)) return false;
  try {
    window.history.replaceState(null, '', window.location.pathname + window.location.search);
  } catch {
    /* the navigation below replaces this entry anyway */
  }
  window.location.replace(`${APP_ORIGIN}/`);
  return true;
}

/**
 * Try to extract a BIP-39 phrase from whatever the QR scanner decoded.
 * Accepts:
 *   - A URL with `#phrase=…` fragment (current format).
 *   - A raw 12-word phrase (legacy format - old QRs generated before
 *     we switched to URL-encoded ones).
 * Returns null if neither matches.
 *
 * Used by the in-app camera scanner so users can sign in on a new
 * device by scanning either their current QR or an old one they
 * downloaded months ago.
 */
export function extractPhraseFromScan(decoded: string): string | null {
  if (!decoded) return null;
  const trimmed = decoded.trim();

  // URL format - parse the fragment the same way consumePhraseFragment does.
  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
    try {
      const url = new URL(trimmed);
      const hash = url.hash;
      if (hash && hash.includes('phrase=')) {
        const params = new URLSearchParams(hash.replace(/^#/, ''));
        const raw = params.get('phrase');
        if (raw) {
          const phrase = raw.trim().toLowerCase().replace(/\s+/g, ' ');
          if (isValidPhrase(phrase)) return phrase;
        }
      }
    } catch {
      /* not a parseable URL - fall through to raw-phrase check */
    }
  }

  // Raw phrase format (legacy) - normalize and validate directly.
  const phrase = trimmed.toLowerCase().replace(/\s+/g, ' ');
  if (isValidPhrase(phrase)) return phrase;

  return null;
}
