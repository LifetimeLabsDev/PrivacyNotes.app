import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { UpdateToast } from './UpdateToast';
import { detectPlatform } from './devices';
import { APP_STORE_URL } from './hosts';
import { reportVersionFloor, useBelowVersionFloor } from './versionFloor';

/**
 * Release-floor check for the STORE builds (Google Play, iOS App Store).
 *
 * The stores own ordinary updates (auto-update is their whole job), so unlike
 * the direct APK there is no "newer version available" manifest and no
 * optional toast: this channel is floor-only. The policy file carries just
 * `minVersion`, published from the tracked packages/desktop/update-policy.json
 * by publish-store-policy.sh AFTER the release is live in that store at 100%.
 * Below the floor the shared required toast renders (amber, no dismiss) and
 * versionFloor.ts pauses server writes; the action opens the store listing.
 *
 * Deliberately NOT set: updateAvailable.ts (the rail's Downloads dot links
 * the downloads page, which is a lie on a store install - same reason web
 * never sets it).
 *
 * Fail open: an unreachable policy means no floor. A 404 means the policy was
 * withdrawn (or never published), so it also clears any persisted floor.
 *
 * Spec: ops/docs/android-update-check.md (store builds)
 */
const PLATFORM = detectPlatform();
const IS_PLAY =
  PLATFORM === 'android' && import.meta.env.VITE_ANDROID_DIST !== 'direct';
const IS_IOS = PLATFORM === 'ios';
const IS_STORE_BUILD = IS_PLAY || IS_IOS;

const POLICY_URL = IS_IOS
  ? 'https://releases.privacynotes.app/ios/update-policy.json'
  : 'https://releases.privacynotes.app/play/update-policy.json';

// Store listing URLs. The https forms route straight into the store apps on
// device (verified app links), so no market:// / itms-apps:// schemes needed.
// Package id + Apple ID: ops/docs/mobile-release-status.md (app records).
const STORE_URL = IS_IOS
  ? APP_STORE_URL
  : 'https://play.google.com/store/apps/details?id=app.privacynotes';

// Same cadence as AndroidUpdateToast: mobile OSes freeze webview timers in
// the background, so the visibilitychange re-check (throttled by the same
// floor) is what actually keeps a daily-opened-never-closed app current.
const POLL_INTERVAL_MS = 6 * 60 * 60 * 1000; // 6h
const INITIAL_DELAY_MS = 20 * 1000;

export function StoreUpdateToast() {
  const { t } = useTranslation('common');
  const belowFloor = useBelowVersionFloor();
  // Dev-only escape hatch to render the toast in a browser (see below).
  const [forced, setForced] = useState(false);
  const lastCheckRef = useRef(0);

  useEffect(() => {
    // Dev-only console hook, same family as __pnUpdateToast: the toast is
    // gated on a store build and can never render in a browser. Presentation
    // only - pair with __pnVersionFloor('999.0.0') to exercise the sync
    // pause. Folded out of shipped builds by import.meta.env.DEV.
    if (import.meta.env.DEV) {
      (window as unknown as Record<string, unknown>).__pnStoreUpdateToast = () =>
        setForced(true);
    }

    if (!IS_STORE_BUILD) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;

    async function check(): Promise<void> {
      if (cancelled) return;
      lastCheckRef.current = Date.now();
      try {
        const res = await fetch(`${POLICY_URL}?t=${Date.now()}`, { cache: 'no-store' });
        if (cancelled) return;
        if (res.status === 404) {
          // Policy not published (or withdrawn): explicitly no floor.
          reportVersionFloor(null);
          return;
        }
        if (!res.ok) return;
        const p = (await res.json()) as { minVersion?: string };
        if (cancelled) return;
        reportVersionFloor(typeof p?.minVersion === 'string' ? p.minVersion : null);
      } catch {
        // Offline or blocked: keep whatever versionFloor.ts already holds.
      }
    }

    const initial = setTimeout(function run(): void {
      void check();
      timer = setTimeout(run, POLL_INTERVAL_MS);
    }, INITIAL_DELAY_MS);

    // No latch, unlike AndroidUpdateToast: the toast here is a pure render of
    // floor state, so polling stays on for the whole session and a floor that
    // gets LOWERED (a rollback) un-pauses within one poll instead of waiting
    // for a relaunch.
    const onVisible = (): void => {
      if (document.hidden) return;
      if (Date.now() - lastCheckRef.current < POLL_INTERVAL_MS) return;
      void check();
    };
    document.addEventListener('visibilitychange', onVisible);

    return () => {
      cancelled = true;
      clearTimeout(initial);
      if (timer) clearTimeout(timer);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, []);

  if (!((IS_STORE_BUILD && belowFloor) || forced)) return null;

  return (
    <UpdateToast
      actionLabel={t('updateToast.update')}
      required
      onAction={async () => {
        const { openUrl } = await import('@tauri-apps/plugin-opener');
        await openUrl(STORE_URL);
      }}
      // No version (we only know the floor, not what the store will install),
      // no changelog, no dismiss: required is the only shape this toast has.
    />
  );
}
