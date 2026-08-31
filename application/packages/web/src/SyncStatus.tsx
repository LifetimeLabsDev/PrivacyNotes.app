import { useTranslation } from 'react-i18next';
import { Check, CircleNotch, CloudArrowUp, CloudSlash, Pause, Warning } from './icons';
import { exemptOpts } from './i18nExempt';
import { useOnlineStatus } from './useOnlineStatus';
import { usePendingUploads } from './usePendingUploads';
import { useSyncing } from './syncingStore';
import { HoverLabel } from './HoverLabel';
import { isDemoMode } from './demo';
import { useBelowVersionFloor } from './versionFloor';
import { useSyncPaused } from './syncPause';
import { useFilesWifiOnly } from './wifiOnly';

interface SyncStatusProps {
  /** Icon size in px - 14 for mobile header, 13 for footers. */
  size?: number;
  /**
   * Opens ID & Sync, which is where the detail lives: what is still
   * waiting to upload, and the check of this device against the server.
   * Wired on every state, not just "Synced" - a stalled upload or an
   * offline spell is exactly when you want that panel, and a control
   * that only responds in one of three states reads as broken.
   * Omitted where there is nowhere to navigate to (lock screen, demo).
   */
  onOpen?: () => void;
}

/**
 * Sync status indicator with offline awareness.
 * Four states: Offline (amber) > Syncing (accent spinner) > Uploading
 * (accent spinner, blobs still queued) > Synced (green check).
 *
 * The green check is a promise that nothing is still on its way up, so
 * it must not show while blobs wait in the upload queue - "Synced" next
 * to ID & Sync's "58 files waiting to upload" is a contradiction, and a
 * user who trusts the check closes the app before the files ever leave.
 *
 * Deliberately just an icon and one word. The footer slots this into a
 * sidebar-width zone next to "Settings", so anything longer than a label
 * overruns the zone and paints over the footer's next control - which is
 * what an added "N files waiting to upload" line did. That count now
 * lives in ID & Sync, one click away.
 */
export function SyncStatus({ size = 13, onOpen }: SyncStatusProps) {
  const { t } = useTranslation('settings');
  const online = useOnlineStatus();
  const pendingUploads = usePendingUploads();
  // Subscribed here, at the leaf, so a sync-pass status flip renders only
  // this pill instead of the whole NotesView tree (backlog #141).
  const syncing = useSyncing();
  const belowFloor = useBelowVersionFloor();
  const paused = useSyncPaused();
  const wifi = useFilesWifiOnly();

  // Demo mode never saves anything - don't show a green "Synced" check
  // that implies durability. Say so plainly instead.
  if (isDemoMode()) {
    return (
      <HoverLabel label={t('syncStatus.demoTooltip')} position="above-start" multiline>
        <span
          className="inline-flex items-center gap-1.5"
          aria-live="polite"
          aria-label={t('syncStatus.demoAria')}
        >
          <CloudSlash size={size} className="text-amber-500 dark:text-amber-400" />
          <span className="text-amber-600 dark:text-amber-400">{t('syncStatus.notSaved', exemptOpts('settings:syncStatus.notSaved'))}</span>
        </span>
      </HoverLabel>
    );
  }

  // "Synced" is a claim this component cannot actually substantiate: it
  // only knows whether a pass is running, not whether this device holds
  // what the server holds. Clicking it opens ID & Sync and runs the
  // verification, so the claim is at least one click from being tested.
  // Below the release floor sync is PAUSED (versionFloor.ts gates every
  // server write), so this outranks every other state: a green check or a
  // spinner would claim work that is deliberately not happening. The pill is
  // the permanent carrier of that truth, same job it does for demo's "Not
  // saved" - the required update toast can cover content, this cannot.
  const state = belowFloor
    ? {
        body: (
          <>
            <Warning size={size} className="text-amber-500 dark:text-amber-400" />
            <span className="text-amber-600 dark:text-amber-400">{t('syncStatus.updateRequired')}</span>
          </>
        ),
        tip: t('syncStatus.updateRequiredTooltip'),
        aria: t('syncStatus.updateRequiredAria'),
        needsOpenHint: true,
      }
    : paused
    ? {
        // The user's own pause (syncPause.ts). Outranks everything below:
        // offline, spinners and the green check all describe work that is
        // deliberately not happening. Never auto-clears, so the pill is
        // the permanent carrier of the paused state.
        body: (
          <>
            <Pause size={size} weight="bold" className="text-amber-500 dark:text-amber-400" />
            <span className="text-amber-600 dark:text-amber-400">{t('syncStatus.paused')}</span>
          </>
        ),
        tip: t('syncStatus.pausedTooltip'),
        aria: t('syncStatus.pausedAria'),
        needsOpenHint: true,
      }
    : !online
    ? {
        body: (
          <>
            <CloudSlash size={size} className="text-amber-500 dark:text-amber-400" />
            <span className="text-amber-600 dark:text-amber-400">{t('syncStatus.offline', exemptOpts('settings:syncStatus.offline'))}</span>
          </>
        ),
        tip: t('syncStatus.offlineTooltip'),
        aria: t('syncStatus.offline'),
        /** The synced tooltip spells out its own click target; these two don't. */
        needsOpenHint: true,
      }
    : syncing
      ? {
          body: (
            <>
              <CircleNotch size={size} className="text-accent animate-spin [animation-duration:1.2s]" />
              <span>{t('syncStatus.syncing', exemptOpts('settings:syncStatus.syncing'))}</span>
            </>
          ),
          tip: t('syncStatus.syncing'),
          aria: t('syncStatus.syncingAria'),
          needsOpenHint: true,
        }
      : pendingUploads.count > 0 && wifi.held
        ? {
            // "Files on wifi only" is holding the queue on cellular. Not an
            // error: say what is waited for, not that something is wrong.
            body: (
              <>
                <CloudArrowUp size={size} className="text-amber-500 dark:text-amber-400" />
                <span className="text-amber-600 dark:text-amber-400">{t('syncStatus.wifiHold')}</span>
              </>
            ),
            tip: t('syncStatus.wifiHoldTooltip'),
            aria: t('syncStatus.wifiHold'),
            needsOpenHint: true,
          }
      : pendingUploads.count > 0 && pendingUploads.blocked >= pendingUploads.count
        ? {
            // Every pending blob is quota-blocked: nothing is actually
            // uploading, so a spinner + "Uploading..." would be a lie
            // (backlog #143). Amber warning instead.
            body: (
              <>
                <Warning size={size} className="text-amber-500 dark:text-amber-400" />
                <span>{t('syncStatus.storageFull', exemptOpts('settings:syncStatus.storageFull'))}</span>
              </>
            ),
            tip: t('syncStatus.pendingBlobsBlocked', { count: pendingUploads.blocked }),
            aria: t('syncStatus.pendingBlobsBlocked', { count: pendingUploads.blocked }),
            needsOpenHint: true,
          }
      : pendingUploads.count > 0
        ? {
            body: (
              <>
                <CircleNotch size={size} className="text-accent animate-spin [animation-duration:1.2s]" />
                <span>{t('syncStatus.uploading', exemptOpts('settings:syncStatus.uploading'))}</span>
              </>
            ),
            tip: t('syncStatus.pendingBlobs', { count: pendingUploads.count }),
            aria: t('syncStatus.pendingBlobs', { count: pendingUploads.count }),
            needsOpenHint: true,
          }
        : {
            body: (
              <>
                <Check size={size} className="text-emerald-500 dark:text-emerald-400" />
                <span>{t('syncStatus.synced', exemptOpts('settings:syncStatus.synced'))}</span>
              </>
            ),
            tip: onOpen ? t('syncStatus.syncedVerifyTooltip') : t('syncStatus.syncedTooltip'),
            aria: onOpen ? t('syncStatus.syncedVerifyAria') : t('syncStatus.synced'),
            needsOpenHint: false,
          };

  const tip = onOpen && state.needsOpenHint
    ? `${state.tip} ${t('syncStatus.openHint')}`
    : state.tip;

  return (
    <HoverLabel label={tip} position="above-start" multiline={!!onOpen}>
      {onOpen ? (
        <button
          type="button"
          onClick={onOpen}
          className="inline-flex items-center gap-1.5 rounded hover:opacity-80 transition"
          aria-live="polite"
          aria-label={state.aria}
        >
          {state.body}
        </button>
      ) : (
        <span
          className="inline-flex items-center gap-1.5"
          aria-live="polite"
          aria-label={state.aria}
        >
          {state.body}
        </span>
      )}
    </HoverLabel>
  );
}
