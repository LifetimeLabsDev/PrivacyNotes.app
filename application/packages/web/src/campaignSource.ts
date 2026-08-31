/**
 * Partner and campaign attribution: the two words an account is born with.
 *
 * `source` is WHERE the account came from - a partner placement we paid for,
 * or a site we recognise as a source of arrivals. `channel` is HOW the app
 * was installed. Both are written once at account creation and never updated.
 *
 * This module's job is narrow on purpose: carry a well-formed word across an
 * origin hop without keeping anything durable. It decides nothing about
 * membership. Two rules it does enforce:
 *
 *   1. Nothing durable, anywhere. The word rides in sessionStorage, which
 *      dies with the tab, and is cleared the moment it reaches the server. A
 *      localStorage tag on use.privacynotes.app is the artifact a hostile
 *      reader would screenshot.
 *   2. First touch wins. A tab keeps the word it arrived with, so a visitor
 *      who lands via a partner and then wanders through a search engine is
 *      still credited to the partner.
 *
 * Two things live elsewhere, and both are deliberate. The allowlist is
 * managed from the admin panel and checked by `link-pubkey` at the one moment
 * the word is written, so nothing here needs to know it. The referring-site
 * map lives in the Worker, which resolves the Referer header server-side and
 * injects the result, so the raw referrer never reaches the browser's own
 * code and never leaves it - a referrer origin can name a person's employer.
 *
 * Spec: ops/docs/plans/partner-attribution.md (sections 3b and 3c)
 */

import { detectPlatform } from './devices';
import { detectDeviceOs } from './deviceFingerprint';

/** sessionStorage key - never localStorage, so the word dies with the tab. */
const KEY = 'privacynotes.src';

/** Max stored length. Mirrors the check constraint on account_origin. */
const MAX_LEN = 32;

/**
 * Shape check for a word arriving in a URL, or null.
 *
 * Membership is not decided here: an unknown word travels and is dropped at
 * the write, which is what lets a slug added in the admin panel work without
 * a deploy. What this rejects is anything that is not a short plain word, so
 * a crafted URL cannot put arbitrary text into a request body or into a
 * redirect this code builds.
 */
export function normalizeSource(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const v = raw.trim().toLowerCase();
  if (v.length === 0 || v.length > MAX_LEN) return null;
  return /^[a-z0-9-]+$/.test(v) ? v : null;
}

/**
 * How this build was installed. Baked in, never observed about the user.
 *
 * Coarse ON PURPOSE. Unlike `source`, the channel can be sharpened later
 * with nothing lost, as long as today's value stays a correct prefix: a
 * row written `mac` is still true when `mac-appstore` arrives. What is
 * NOT recoverable is an account created before any of this shipped, so
 * shipping a coarse value now beats shipping a precise one later.
 *
 * VITE_ANDROID_DIST is the existing build-time stamp that already drives
 * the billing path, the update toasts and the Gradle signing config.
 */
export function detectChannel(): string {
  const platform = detectPlatform();
  if (platform === 'web') return 'web';
  if (platform === 'ios') return 'ios';
  if (platform === 'android') {
    return import.meta.env.VITE_ANDROID_DIST === 'direct' ? 'android-direct' : 'android-play';
  }
  const os = detectDeviceOs();
  if (os === 'macOS') return 'mac';
  if (os === 'Windows') return 'windows';
  if (os === 'Linux') return 'linux';
  return 'desktop';
}

/** The slug worker.ts injected after resolving the Referer header, if any. */
function injectedSource(): string | null {
  try {
    return document.querySelector('meta[name="pn-src"]')?.getAttribute('content') ?? null;
  } catch {
    return null;
  }
}

function session(): Storage | null {
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

/** The source held for this tab session, or null. */
export function getStoredSource(): string | null {
  const s = session();
  if (!s) return null;
  try {
    return normalizeSource(s.getItem(KEY));
  } catch {
    return null;
  }
}

/** Forget it. Called the moment the value reaches the server. */
export function clearStoredSource(): void {
  try {
    session()?.removeItem(KEY);
  } catch {
    /* private mode, or storage disabled - nothing to clear */
  }
}

/**
 * Read `?ref=` (falling back to the referring site), store it, and strip
 * the parameter from the address bar.
 *
 * Runs on all three hosts. The apex captures the arrival, the demo captures
 * it too, and the app host captures what the other two forward across the
 * origin hop. Idempotent and first-touch-wins, so the mount effect can re-run
 * and a later page view cannot overwrite the arrival.
 *
 * Runs in demo as well. The sandbox creates no account itself, but its
 * "Sign up to unlock" button hands the visitor to the app host, so a partner
 * who routes a reader through the demo is still credited when that reader
 * signs up. The word lives in demo sessionStorage, which dies with the tab
 * like everything else there, and the demo makes no server call for it.
 * Spec: ops/docs/plans/partner-attribution.md (section 3c)
 */
export function captureSource(): void {
  const s = session();
  if (!s) return;

  let url: URL;
  try {
    url = new URL(window.location.href);
  } catch {
    return;
  }

  const fromQuery = normalizeSource(url.searchParams.get('ref'));

  // Strip it whether or not it resolved, so a crafted or stale ref is
  // never shared, bookmarked or re-read on the next mount.
  if (url.searchParams.has('ref')) {
    url.searchParams.delete('ref');
    const qs = url.searchParams.toString();
    try {
      window.history.replaceState(
        window.history.state,
        '',
        `${url.pathname}${qs ? `?${qs}` : ''}${url.hash}`,
      );
    } catch {
      /* replaceState can throw in exotic embeddings; the value is captured either way */
    }
  }

  // First touch wins: never overwrite what this tab already holds.
  if (getStoredSource()) return;

  // The referring site is resolved in the Worker and injected as a meta tag,
  // so the raw referrer never reaches this code and never leaves the browser.
  const resolved = fromQuery ?? normalizeSource(injectedSource());
  if (!resolved) return;
  try {
    s.setItem(KEY, resolved);
  } catch {
    /* storage full or blocked - attribution is best-effort by design */
  }
}

/**
 * Append the held source to the apex-to-app-host handoff URL.
 *
 * The two origins do not share storage, so this is the only way the
 * value crosses. Returns the URL unchanged when there is nothing to
 * carry, which is the common case.
 */
export function withSource(targetOrigin: string): string {
  const src = getStoredSource();
  return src ? `${targetOrigin}/?ref=${encodeURIComponent(src)}` : targetOrigin;
}
