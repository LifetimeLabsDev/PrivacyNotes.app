import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { UpdateToast } from './UpdateToast';
import { compareSemver } from './versionCheck';
import { VERSION } from './version';
import { detectPlatform } from './devices';
import { isUpdateSnoozed, snoozeUpdate } from './updateSnooze';
import { setUpdateAvailable } from './updateAvailable';
import { reportVersionFloor } from './versionFloor';

/**
 * Update prompt for the direct-download Android APK (the off-store channel for
 * users who avoid Play). A sideloaded APK has no store auto-update and Tauri's
 * updater is desktop-only, so this polls a small manifest on R2 and, when a
 * newer APK exists, shows the shared UpdateToast with a Download action that
 * opens the APK URL in the system browser (the user then taps it to install).
 *
 * Severity comes from the RELEASE, not from the channel. The manifest carries
 * `minVersion`, the oldest client we still tolerate, published from the tracked
 * packages/desktop/update-policy.json. Below it the toast is what it always
 * was: no dismiss, no changelog, up until the user installs. At or above it the
 * update is ordinary, so it dismisses for 48h (updateSnooze.ts) and links the
 * changelog. Every release used to inherit the protocol-break treatment, which
 * is what issue #224 reported: an unskippable nag on the one platform where
 * updating costs the user mobile data.
 *
 * Only the direct-APK build runs this, gated on VITE_ANDROID_DIST=direct. The
 * Play build (the default, flag unset) auto-updates through the store, so it
 * must never show this. The bundled frontend ships inside the APK, so a UI
 * change needs a new APK, not a page refresh - hence "download", not "reload".
 *
 * Spec: ops/docs/android-update-check.md
 */
const IS_DIRECT_APK =
  detectPlatform() === 'android' && import.meta.env.VITE_ANDROID_DIST === 'direct';

const MANIFEST_URL = 'https://releases.privacynotes.app/android/latest.json';
const POLL_INTERVAL_MS = 6 * 60 * 60 * 1000; // 6h; direct APK releases are infrequent
const INITIAL_DELAY_MS = 20 * 1000;

type AndroidManifest = {
  version: string;
  url: string;
  /** Oldest tolerated client. Absent (older manifests) means nothing is forced. */
  minVersion?: string;
  /** APK download size, so the user can judge the cost before spending it. */
  sizeBytes?: number;
};

/** True when the running build is below the release floor. */
function isRequired(m: AndroidManifest): boolean {
  return typeof m.minVersion === 'string' && compareSemver(VERSION, m.minVersion) < 0;
}

export function AndroidUpdateToast() {
  const { t } = useTranslation('common');
  const [update, setUpdate] = useState<AndroidManifest | null>(null);
  const lastCheckRef = useRef(0);
  const foundRef = useRef(false);

  useEffect(() => {
    // Dev-only console hook. The toast is gated on the direct-APK build, so it
    // can never render in a browser - this fires either variant by hand against
    // `pnpm dev`. import.meta.env.DEV folds to false in every shipped build, so
    // the whole block is dropped at bundle time.
    if (import.meta.env.DEV) {
      (window as unknown as Record<string, unknown>).__pnUpdateToast = (opts?: {
        required?: boolean;
      }) => {
        setUpdateAvailable('999.0.0');
        setUpdate({
          version: '999.0.0',
          url: 'https://releases.privacynotes.app/latest/PrivacyNotes.apk',
          minVersion: opts?.required ? '999.0.0' : undefined,
          sizeBytes: 24_100_000,
        });
      };
    }

    if (!IS_DIRECT_APK) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;

    async function check(): Promise<void> {
      if (cancelled || foundRef.current) return;
      lastCheckRef.current = Date.now();
      try {
        const res = await fetch(`${MANIFEST_URL}?t=${Date.now()}`, { cache: 'no-store' });
        if (!res.ok) return;
        const m = (await res.json()) as AndroidManifest;
        if (cancelled || typeof m?.version !== 'string' || typeof m?.url !== 'string') return;
        // The manifest is this channel's floor source whether or not a newer
        // APK exists - report before the version early-return so the sync
        // pause (versionFloor.ts) always tracks the latest published floor.
        reportVersionFloor(typeof m.minVersion === 'string' ? m.minVersion : null);
        if (compareSemver(m.version, VERSION) <= 0) return;
        // Badge the rail's Downloads button first, so the dot stays put even
        // when the toast below is snoozed away.
        setUpdateAvailable(m.version);
        // Dismissed within the last 48h: stay quiet, but do NOT set foundRef -
        // polling has to continue so the toast returns once the snooze lapses.
        if (!isRequired(m) && isUpdateSnoozed(m.version)) return;
        foundRef.current = true;
        setUpdate(m);
      } catch {
        // Offline or manifest missing - ignore and try again next poll.
      }
    }

    const initial = setTimeout(function run(): void {
      void check();
      timer = setTimeout(run, POLL_INTERVAL_MS);
    }, INITIAL_DELAY_MS);

    // Android freezes the WebView's timers while the app is backgrounded, so the 6h poll
    // above drifts arbitrarily far on an app that is opened daily but never closed - the
    // user then sits on a stale APK until a cold start. Re-check on resume, throttled by
    // the same 6h floor, mirroring the focus re-check in DesktopUpdater.tsx. Uses
    // visibilitychange rather than focus: Android WebView fires it reliably on
    // background/resume, while window focus does not.
    const onVisible = (): void => {
      if (document.hidden || foundRef.current) return;
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

  if (!update) return null;

  const required = isRequired(update);

  return (
    <UpdateToast
      version={update.version}
      actionLabel={t('updateToast.download')}
      required={required}
      sizeBytes={update.sizeBytes}
      onAction={async () => {
        const { openUrl } = await import('@tauri-apps/plugin-opener');
        await openUrl(update.url);
      }}
      // No changelog link on Android, deliberately: at 375px the meta line only
      // fits two of {version, size, changelog} next to the Download button and
      // the dismiss X, and the download size is the one that answers the
      // question the user actually has before spending mobile data on it.
      onDismiss={
        required
          ? undefined
          : () => {
              snoozeUpdate(update.version);
              setUpdate(null);
              // Let polling resume so the toast can return after the snooze.
              foundRef.current = false;
            }
      }
    />
  );
}
