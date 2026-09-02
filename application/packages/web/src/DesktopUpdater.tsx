import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { UpdateToast } from './UpdateToast';
import { detectPlatform } from './devices';
import { marketingHomeHref } from './siteLinks';
import { compareSemver } from './versionCheck';
import { VERSION } from './version';
import { isUpdateSnoozed, snoozeUpdate } from './updateSnooze';
import { setUpdateAvailable } from './updateAvailable';
import { reportVersionFloor } from './versionFloor';

const IS_DESKTOP = detectPlatform() === 'desktop';

// Re-check at most once per this window while the app stays open. A fresh
// launch always checks; refocusing the window re-checks only after the floor
// elapses, so a user who never quits still gets updates without hammering the
// endpoint on every focus event.
const CHECK_FLOOR_MS = 12 * 60 * 60 * 1000; // 12h

// Public changelog, opened in the system browser (a /changelog tab cannot
// open inside the Tauri webview). Canonical no-www domain. Spec:
// ops/docs/gotchas.md (canonical domain).
const CHANGELOG_URL = 'https://privacynotes.app/changelog';

// The release floor for the .deb, the one desktop format that cannot self-update.
// Published per platform, from the tracked packages/desktop/update-policy.json:
// a global floor would let a Linux release force Android clients toward an APK
// that does not satisfy it yet. Spec: ops/docs/android-update-check.md (floors are published per platform, never globally).
const LINUX_POLICY_URL = 'https://releases.privacynotes.app/linux/update-policy.json';

// The command a Scoop user runs to move to the version this toast names. Scoop's
// bucket carries each release within hours of it shipping, so there is always
// something for this to fetch by the time the toast appears.
const SCOOP_UPDATE_CMD = 'scoop update privacynotes';

// What the launch check found. `restart` is a staged install awaiting a relaunch.
// The other two cannot self-update and want opposite advice: a Linux .deb is
// replaced from the downloads page, while a Scoop install must NOT be, because the
// download there is the installer that leaves a second copy behind.
// `required` is set only in download mode, when this build is below the floor.
type UpdateReady = { version: string; mode: 'restart' | 'download' | 'scoop'; required?: boolean };

/**
 * Desktop self-updater (macOS/Windows/Linux only).
 *
 * On launch it checks the updater endpoint; if a newer build exists it
 * downloads + installs it in the background, then surfaces the shared
 * "Update available" toast with a Restart action. Updates are never applied
 * silently-on-next-launch, because a user who never quits would never
 * receive them. Restart relaunches into the freshly installed build. A
 * Linux `.deb` can't self-update (it lives in root-owned `/usr`), so its toast
 * is instead a nudge to the downloads page to grab the newer package by hand -
 * non-dismissible only when the build is below the release floor, otherwise
 * dismissible for 48h like any ordinary update (issue #224).
 * iOS/Android update through their app stores, so this is gated on
 * detectPlatform() === 'desktop'. Spec: ops/docs/macos-ios-setup.md (iOS updates through App Store review, not this updater).
 */
async function fetchLinuxMinVersion(): Promise<string | null> {
  try {
    const res = await fetch(`${LINUX_POLICY_URL}?t=${Date.now()}`, { cache: 'no-store' });
    if (!res.ok) return null;
    const p = (await res.json()) as { minVersion?: string };
    return typeof p?.minVersion === 'string' ? p.minVersion : null;
  } catch {
    // Offline or policy missing: treat the update as optional. Failing open
    // costs one dismissible toast; failing closed would nag users we never
    // meant to force.
    return null;
  }
}

async function runUpdateCheck(): Promise<UpdateReady | null> {
  try {
    const { invoke } = await import('@tauri-apps/api/core');
    const canSelfUpdate = await invoke<boolean>('can_self_update').catch(() => true);

    const { check } = await import('@tauri-apps/plugin-updater');
    const update = await check();
    if (!update) return null;

    // Badge the rail's Downloads button first, so the dot survives a dismissed
    // toast and an un-restarted staged install alike.
    setUpdateAvailable(update.version);

    // A Linux .deb can't self-update (it lives in root-owned /usr). Don't
    // install; the toast points the user at the downloads page to fetch the
    // newer .deb by hand. Spec: ops/docs/linux-release.md (.deb lives in root-owned /usr, excluded from the updater manifest).
    if (!canSelfUpdate) {
      // Both blocked formats arrive here, so ask which one before choosing the
      // nudge. Defaulting to the .deb path on an error keeps the existing
      // behaviour for the platform that has had this toast all along.
      const scoop = await invoke<boolean>('is_scoop_install').catch(() => false);
      if (scoop) {
        // No release floor is consulted: the floor is published for Linux only,
        // and a Scoop user is never more than one bucket poll behind anyway, so
        // this toast is always dismissible.
        if (isUpdateSnoozed(update.version)) return null;
        return { version: update.version, mode: 'scoop' };
      }

      const minVersion = await fetchLinuxMinVersion();
      // Feed the sync pause (versionFloor.ts). Only ever runs when an update
      // exists, which is sufficient: the floor is never above the newest
      // published .deb, so a below-floor build always has an update pending.
      // A null here (policy missing OR a network blip) clears the persisted
      // floor - fail open, the 12h re-check self-heals a blip.
      reportVersionFloor(minVersion);
      const required = !!minVersion && compareSemver(VERSION, minVersion) < 0;
      // Dismissed within the last 48h: stay quiet. The 12h focus re-check keeps
      // running, so the toast returns on its own once the snooze lapses.
      if (!required && isUpdateSnoozed(update.version)) return null;
      return { version: update.version, mode: 'download', required };
    }

    // macOS/Windows/AppImage: download + install in the background; the toast's
    // Restart button relaunches into the freshly installed build.
    await update.downloadAndInstall();
    return { version: update.version, mode: 'restart' };
  } catch (e) {
    // Offline, endpoint down, or signature mismatch. Never surface; retry next launch.
    console.warn('[updater] update check failed', e);
    return null;
  }
}

async function relaunchApp(): Promise<void> {
  try {
    const { relaunch } = await import('@tauri-apps/plugin-process');
    await relaunch();
  } catch (e) {
    console.warn('[updater] relaunch failed', e);
  }
}

async function openChangelog(): Promise<void> {
  try {
    const { openUrl } = await import('@tauri-apps/plugin-opener');
    await openUrl(CHANGELOG_URL);
  } catch (e) {
    console.warn('[updater] open changelog failed', e);
  }
}

async function copyScoopCommand(): Promise<void> {
  try {
    await navigator.clipboard.writeText(SCOOP_UPDATE_CMD);
  } catch (e) {
    // Denied or unavailable. The toast still named the new version, and the
    // command is on the homepage, so this is a lost convenience rather than a
    // dead end.
    console.warn('[updater] clipboard write failed', e);
  }
}

async function openDownloads(): Promise<void> {
  try {
    const { openUrl } = await import('@tauri-apps/plugin-opener');
    // Locale-aware, matching the in-app Downloads button: on desktop
    // marketingHomeHref() is the absolute /<lang> homepage, and #downloads
    // reveals both Linux formats. Spec: ops/docs/linux-release.md (homepage carries both AppImage and .deb buttons).
    await openUrl(`${marketingHomeHref()}#downloads`);
  } catch (e) {
    console.warn('[updater] open downloads failed', e);
  }
}

export function DesktopUpdater() {
  const { t } = useTranslation('common');
  const [ready, setReady] = useState<UpdateReady | null>(null);
  const lastCheckRef = useRef(0);
  const stagedRef = useRef(false);

  useEffect(() => {
    // Dev-only console hook, same shape as AndroidUpdateToast's: the toast is
    // gated on the desktop build and can never render in a browser. Folded out
    // of every shipped build by import.meta.env.DEV.
    if (import.meta.env.DEV) {
      (window as unknown as Record<string, unknown>).__pnDesktopUpdateToast = (opts?: {
        required?: boolean;
        mode?: 'restart' | 'download' | 'scoop';
      }) => {
        setUpdateAvailable('999.0.0');
        setReady({
          version: '999.0.0',
          mode: opts?.mode ?? 'download',
          required: !!opts?.required,
        });
      };
    }

    if (!IS_DESKTOP) return;

    const maybeCheck = (force: boolean) => {
      // Once we've surfaced a result we stop checking for the session; the toast
      // is up (a staged install awaiting Restart, or a .deb download nudge), so
      // re-checking would just re-surface the same thing.
      if (stagedRef.current) return;
      const now = Date.now();
      if (!force && now - lastCheckRef.current < CHECK_FLOOR_MS) return;
      lastCheckRef.current = now;
      void runUpdateCheck().then((res) => {
        if (res) {
          stagedRef.current = true;
          setReady(res);
        }
      });
    };

    // Always check on launch; then re-check when the window regains focus,
    // throttled by the 12h floor (covers the never-quit user).
    maybeCheck(true);
    const onFocus = () => maybeCheck(false);
    window.addEventListener('focus', onFocus);
    return () => window.removeEventListener('focus', onFocus);
  }, []);

  if (!ready) return null;

  // Only a staged install offers Restart. A .deb is sent to the downloads page,
  // and a Scoop install is handed the command instead, since the download it
  // would otherwise be pointed at is what creates the second copy. Only a
  // below-the-floor .deb loses its dismiss and changelog; every other update
  // behaves like an ordinary one.
  const isStaged = ready.mode === 'restart';
  const isScoop = ready.mode === 'scoop';
  const required = ready.mode === 'download' && !!ready.required;
  return (
    <UpdateToast
      version={ready.version}
      actionLabel={t(
        isStaged ? 'updateToast.restart' : isScoop ? 'updateToast.copyCommand' : 'updateToast.download',
      )}
      required={required}
      onAction={() => {
        if (isStaged) return void relaunchApp();
        if (isScoop) return void copyScoopCommand();
        void openDownloads();
      }}
      onChangelog={required ? undefined : () => void openChangelog()}
      onDismiss={
        required
          ? undefined
          : () => {
              // Only the nudge paths snooze: a staged install costs nothing
              // to re-offer on the next focus check, and Restart is one click.
              // Re-arm the checker there too, so the toast can return once the
              // 48h lapses on an app that is never quit. The restart path stays
              // latched - re-checking would re-run downloadAndInstall.
              if (!isStaged) {
                snoozeUpdate(ready.version);
                stagedRef.current = false;
              }
              setReady(null);
            }
      }
    />
  );
}
