import { useEffect, useReducer, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  ArrowsClockwise,
  CaretDown,
  Check,
  CircleNotch,
  CloudArrowUp,
  CloudCheck,
  CloudSlash,
  Copy,
  Lock,
  Pause,
  SealCheck,
  Warning,
  WifiSlash,
} from './icons';
import { type SupabaseClient } from '@notes/shared';
import { isDemoMode } from './demo';
import { formatRelative } from './intlFormat';
import { verifySync, resetSyncCursor, type SyncReport } from './syncVerify';
import { recordCleanVerify } from './verifyStamp';
import { buildDeviceName } from './devices';
import { countUnsyncedNotes } from './notesRepo';
import { useOnlineStatus } from './useOnlineStatus';
import { usePendingUploads } from './usePendingUploads';
import { useSyncing } from './syncingStore';
import { useBelowVersionFloor } from './versionFloor';
import { setSyncPaused, useSyncPaused } from './syncPause';
import { setFilesWifiOnly, useFilesWifiOnly, wifiOnlyAvailable } from './wifiOnly';
import { useSyncLog, lastOkSyncAt, type SyncPassEntry } from './syncLog';
import { usePushFailures, type PushFailure } from './pushFailures';
import { db } from './db';
import { readAuthLog } from './authDiag';
import { deriveDisplayTitle } from './notesViewUtils';
import { useVerifyStamp } from './verifyStamp';
import { SETTINGS_EYEBROW } from './settingsUI';
import { VERSION } from './version';

/**
 * The redesigned sync readout: one status word with its age, the recent
 * pass bars, the pause and wifi switches, the device and data-path
 * cards, and the activity list. Replaces the old five-row table
 * (SyncStatusRows). Shared by the Sync tab and ID & Sync; `pubkey` adds
 * the compact Account ID row.
 *
 * State precedence mirrors SyncStatus.tsx exactly - the pill sends
 * people here, so this panel must never answer a different question
 * than the thing they clicked.
 */
export function SyncPanel({
  pubkey,
  onSyncNow,
  supabase,
  autoVerify = false,
  onOpenNote,
}: {
  pubkey?: string;
  onSyncNow?: () => void | Promise<void>;
  /** Enables the Verify button - the read-only local-vs-server compare. */
  supabase?: SupabaseClient;
  /** Run the verify on mount - set when the footer pill's click IS the
   *  question (was SyncVerifyBlock's autoRun). */
  autoVerify?: boolean;
  /** Opens a note from the not-backed-up list. Absent where there is no
   *  editor to open it in. */
  onOpenNote?: (id: string) => void;
}) {
  const { t } = useTranslation('settings');
  const online = useOnlineStatus();
  const syncing = useSyncing();
  const pending = usePendingUploads();
  const belowFloor = useBelowVersionFloor();
  const paused = useSyncPaused();
  const wifi = useFilesWifiOnly();
  const log = useSyncLog();
  const stamp = useVerifyStamp();
  const failures = usePushFailures();

  // Titles for the not-backed-up list, read on demand: the failing notes
  // are the few the last pass refused, never the whole vault.
  const [failedNotes, setFailedNotes] = useState<Array<{ id: string; title: string; failure: PushFailure; chars: number }>>([]);
  useEffect(() => {
    if (failures.size === 0) {
      setFailedNotes([]);
      return;
    }
    let cancelled = false;
    const ids = [...failures.keys()];
    void db.notes.bulkGet(ids).then((rows) => {
      if (cancelled) return;
      setFailedNotes(
        ids.map((id, i) => {
          const row = rows[i];
          return { id, title: row ? deriveDisplayTitle(row) : id.slice(0, 8), failure: failures.get(id)!, chars: row ? row.body.length : 0 };
        }),
      );
    });
    return () => {
      cancelled = true;
    };
  }, [failures]);

  // Re-render every 30 s so "2 min ago" ages without interaction.
  const [, tick] = useReducer((x: number) => x + 1, 0);
  useEffect(() => {
    const id = setInterval(tick, 30_000);
    return () => clearInterval(id);
  }, []);

  // Dirty note count for the waiting line. Recomputed when a pass ends
  // or the pause flips - the two moments the number can move.
  const [unsynced, setUnsynced] = useState(0);
  useEffect(() => {
    if (!syncing) void countUnsyncedNotes().then(setUnsynced);
  }, [syncing, paused]);

  // ── Verify (moved in from the deleted SyncVerifyBlock) ──────────
  // Exists because the pill and hero only know whether a pass RAN, not
  // whether this device holds what the server holds. See syncVerify.ts.
  const [verifyBusy, setVerifyBusy] = useState(false);
  const [report, setReport] = useState<SyncReport | null>(null);
  const [repaired, setRepaired] = useState(false);

  async function runVerify() {
    if (!supabase) return;
    setVerifyBusy(true);
    setRepaired(false);
    try {
      const r = await verifySync(supabase);
      setReport(r);
      // Stamp only a CLEAN result - the hero's "Verified ... items
      // match" line is a claim of full agreement (verifyStamp.ts).
      if (r.verdict === 'in_sync' && pending.count === 0) {
        recordCleanVerify(r.serverLive);
      }
    } finally {
      setVerifyBusy(false);
    }
  }

  function repair() {
    resetSyncCursor();
    setRepaired(true);
    setReport(null);
  }

  useEffect(() => {
    if (autoVerify && supabase && navigator.onLine) void runVerify();
    // Mount-only: re-running on every online flip would fire the check
    // again each time the network blips.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // The demo never contacts a server, so every readout below that
  // describes a server - the state word, the timestamps, the pass bars,
  // the two actions, the activity list - would be a claim about work
  // that does not happen. It outranks every other state, same as the
  // pill (SyncStatus.tsx), and carries the same words the pill does.
  const demo = isDemoMode();

  const state: 'demo' | 'floor' | 'paused' | 'offline' | 'syncing' | 'notBackedUp' | 'wifiHold' | 'storageFull' | 'uploading' | 'synced' =
    demo ? 'demo'
    : belowFloor ? 'floor'
    : paused ? 'paused'
    : !online ? 'offline'
    : syncing ? 'syncing'
    : failures.size > 0 ? 'notBackedUp'
    : pending.count > 0 && wifi.held ? 'wifiHold'
    : pending.count > 0 && pending.blocked >= pending.count ? 'storageFull'
    : pending.count > 0 ? 'uploading'
    : 'synced';

  const amber = 'text-amber-600 dark:text-amber-400';
  const green = 'text-emerald-600 dark:text-emerald-400';
  const heads: Record<typeof state, { icon: React.ReactNode; word: string; cls: string }> = {
    demo: { icon: <CloudSlash size={17} />, word: t('syncStatus.notSaved'), cls: amber },
    floor: { icon: <Warning size={17} />, word: t('syncStatus.updateRequired'), cls: amber },
    paused: { icon: <Pause size={17} weight="bold" />, word: t('syncStatus.paused'), cls: amber },
    offline: { icon: <WifiSlash size={17} />, word: t('syncStatus.offline'), cls: amber },
    syncing: { icon: <CircleNotch size={17} className="animate-spin" />, word: t('syncStatus.syncing'), cls: 'text-accent' },
    notBackedUp: { icon: <Warning size={17} />, word: t('syncStatus.notBackedUp'), cls: amber },
    wifiHold: { icon: <CloudArrowUp size={17} />, word: t('syncStatus.wifiHold'), cls: amber },
    storageFull: { icon: <Warning size={17} />, word: t('syncStatus.storageFull'), cls: amber },
    uploading: { icon: <CircleNotch size={17} className="animate-spin" />, word: t('syncStatus.uploading'), cls: 'text-accent' },
    synced: { icon: <Check size={17} weight="bold" />, word: t('syncStatus.synced'), cls: green },
  };
  const head = heads[state];

  const lastOk = lastOkSyncAt();
  const waiting = unsynced + pending.count;

  // One state-specific subline, nothing more (translation diet).
  const subline =
    state === 'demo' ? t('syncStatus.demoTooltip')
    : state === 'floor' ? t('syncStatus.updateRequiredTooltip')
    : state === 'paused' ? t('syncPanel.pausedBody')
    : state === 'offline' ? t('syncStatus.offlineTooltip')
    : state === 'notBackedUp' ? t('syncStatus.notBackedUpAria', { count: failures.size })
    : state === 'wifiHold' ? t('syncStatus.wifiHoldTooltip')
    : state === 'storageFull' ? t('syncStatus.pendingBlobsBlocked', { count: pending.blocked })
    : state === 'uploading' ? t('syncStatus.pendingBlobs', { count: pending.count })
    : null;

  const showWaiting = (state === 'paused' || state === 'floor' || state === 'offline') && waiting > 0;

  return (
    <div className="space-y-3">
      {/* ── Status hero ── */}
      <div
        className={`rounded-lg border border-divider border-s-[3px] px-3.5 py-3 ${
          state === 'synced'
            ? 'border-s-emerald-500 bg-[linear-gradient(100deg,rgba(16,185,129,0.07),transparent_65%)]'
            : state === 'syncing' || state === 'uploading'
              ? 'border-s-accent bg-[linear-gradient(100deg,rgb(var(--pn-accent)/0.07),transparent_65%)]'
              : 'border-s-amber-500 bg-[linear-gradient(100deg,rgba(245,158,11,0.07),transparent_65%)]'
        }`}
      >
        <div className="flex items-center gap-2">
          <span className={`inline-flex ${head.cls}`}>{head.icon}</span>
          <span className={`text-base font-semibold ${head.cls}`}>{head.word}</span>
          {!demo && (
            <span className="ms-auto text-xs text-pn-muted whitespace-nowrap">
              {lastOk !== null
                ? t('syncPanel.lastSync', { ago: formatRelative(new Date(lastOk).toISOString()) })
                : t('syncPanel.neverSynced')}
            </span>
          )}
        </div>

        {/* One line, one slot: while a pass runs it narrates, otherwise it
            carries the last clean verify. Same element and size either way,
            so the hero never changes height when Sync now is clicked. */}
        {state === 'syncing' ? (
          <p className="mt-1.5 text-sm text-pn-soft">
            {t('syncPanel.passRunning')}
          </p>
        ) : verifyBusy ? (
          // The compare narrates in the same slot the sync does - a
          // click on either action always answers in this line.
          <p className="mt-1.5 text-sm text-pn-soft">
            {t('syncPanel.compareRunning')}
          </p>
        ) : stamp && !demo ? (
          // Soft text, green seal only: the state word above owns the
          // color, this line is a fact with a small anchor, not a second
          // green claim.
          <p className="mt-1.5 text-sm text-pn-soft inline-flex items-center gap-1.5">
            {t('syncPanel.verified', {
              ago: formatRelative(new Date(stamp.at).toISOString()),
              count: stamp.items,
            })}
            <SealCheck size={15} weight="fill" className="text-emerald-500 dark:text-emerald-400" />
          </p>
        ) : null}
        {subline && <p className="mt-1.5 text-sm text-pn-soft">{subline}</p>}
        {showWaiting && (
          <p className="mt-1.5 text-sm text-pn-soft">
            {t('syncPanel.waitingNotes', { count: unsynced })}
            {pending.count > 0 && <>{' · '}{t('syncPanel.waitingFiles', { count: pending.count })}</>}
          </p>
        )}

        {!demo && <PassBars log={log} />}
      </div>

      {/* ── Not backed up: the notes the last pass could not push, with the
          reason each one was refused. Persistent by design - it clears only
          when a pass pushes them. */}
      {failedNotes.length > 0 && !demo && (
        <div className="rounded-lg border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/30 p-3">
          <p className="text-sm font-medium text-amber-800 dark:text-amber-300">
            {t('syncPanel.notBackedUpHeading', { count: failedNotes.length })}
          </p>
          <ul className="mt-2 space-y-1.5">
            {failedNotes.map(({ id, title, failure }) => (
              <li key={id} className="flex items-center gap-2 text-sm">
                <span className="min-w-0 flex-1 truncate" dir="auto">{title}</span>
                <span className="shrink-0 text-xs text-amber-700 dark:text-amber-400">
                  {failure.reason === 'too_large'
                    ? t('syncPanel.reasonTooLarge')
                    : t('syncPanel.reasonFailed', { message: failure.message })}
                </span>
                {onOpenNote && (
                  <button
                    type="button"
                    onClick={() => onOpenNote(id)}
                    className="shrink-0 rounded-md border border-amber-300 dark:border-amber-700 px-2 py-0.5 text-xs font-medium hover:bg-amber-100 dark:hover:bg-amber-900/40 transition"
                  >
                    {t('syncPanel.openNote')}
                  </button>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* ── Controls: the two actions side by side, settings rows under ── */}
      <div className="grid gap-3 sm:grid-cols-2">
        {onSyncNow && !demo && (
          <button
            type="button"
            onClick={() => void onSyncNow()}
            disabled={!online || syncing || belowFloor || paused || verifyBusy}
            className="inline-flex items-center justify-center gap-2 rounded-lg border border-divider hover:bg-surface-1 px-3 py-2.5 text-sm font-medium transition disabled:opacity-50"
          >
            <ArrowsClockwise size={15} className={syncing ? 'animate-spin' : 'text-accent'} />
            {t('syncPanel.syncNow')}
          </button>
        )}
        {supabase && !demo && (
          <button
            type="button"
            onClick={() => void runVerify()}
            disabled={verifyBusy || !online || syncing}
            className="inline-flex items-center justify-center gap-2 rounded-lg border border-divider hover:bg-surface-1 px-3 py-2.5 text-sm font-medium transition disabled:opacity-50"
          >
            {/* Keyed spans: the busy swap must REPLACE these nodes, not
                mutate them - the iOS/Android webviews fold the spinner
                swap into one paint otherwise (see the old block). */}
            {verifyBusy ? (
              <span key="busy" className="inline-flex items-center gap-2">
                <CloudCheck size={15} className="animate-spin" />
                {t('sync.verifyRunning')}
              </span>
            ) : (
              <span key="idle" className="inline-flex items-center gap-2">
                <CloudCheck size={15} className="text-accent" />
                {t('sync.verifyAction')}
              </span>
            )}
          </button>
        )}
      </div>

      {/* ── Verify outcome - only the answers the hero line cannot carry:
          divergence, busy, failed, files still queued, the repair. ── */}
      {repaired && (
        <p className="text-sm text-pn-soft leading-relaxed">{t('sync.verifyRepairQueued')}</p>
      )}
      {report && (
        <div className="text-sm leading-relaxed">
          {report.verdict === 'in_sync' && (
            pending.count > 0 && pending.blocked >= pending.count ? (
              <p className="inline-flex items-center gap-1.5 text-amber-600 dark:text-amber-400">
                <Warning size={14} />
                {t('sync.verifyInSyncBlockedBlobs', { count: pending.blocked })}
              </p>
            ) : pending.count > 0 ? (
              <p className="inline-flex items-center gap-1.5">
                <ArrowsClockwise size={14} className="animate-spin" />
                {t('sync.verifyInSyncPendingBlobs', { count: pending.count })}
              </p>
            ) : (
              // Clean: the hero line just refreshed - saying it twice is
              // the redundancy this panel exists to remove.
              null
            )
          )}
          {/* Not a verdict: another device was mid-write, so any gap we
              measured is probably just data in flight. */}
          {report.verdict === 'busy' && <p className="text-pn-soft">{t('sync.verifyBusy')}</p>}
          {report.verdict === 'failed' && (
            <p className="inline-flex items-center gap-1.5 text-amber-600 dark:text-amber-400">
              <WifiSlash size={14} />
              {t('sync.verifyFailed')}
            </p>
          )}
          {report.verdict === 'diverged' && (
            <div className="space-y-2">
              <p className="text-amber-600 dark:text-amber-400">{t('sync.verifyDiverged')}</p>
              <ul className="text-pn-soft space-y-0.5">
                {report.missingLocally.length > 0 && (
                  <li>{t('sync.verifyMissing', { count: report.missingLocally.length })}</li>
                )}
                {report.staleLocally.length > 0 && (
                  <li>{t('sync.verifyStale', { count: report.staleLocally.length })}</li>
                )}
                {report.pendingTombstones.length > 0 && (
                  <li>{t('sync.verifyPendingDelete', { count: report.pendingTombstones.length })}</li>
                )}
                {report.neverPushed.length > 0 && (
                  <li>{t('sync.verifyNeverPushed', { count: report.neverPushed.length })}</li>
                )}
              </ul>
              {report.missingLocally.length + report.staleLocally.length + report.pendingTombstones.length > 0 && (
                <button
                  type="button"
                  onClick={repair}
                  className="rounded-md bg-accent text-white hover:bg-accent-hover px-3 py-1.5 text-sm font-medium transition"
                >
                  {t('sync.verifyRepairAction')}
                </button>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── Device + data path ── */}
      <div className="grid gap-3 sm:grid-cols-5">
        <div className="flex flex-col rounded-lg border border-divider px-3.5 py-3 sm:col-span-2">
          <span className={`${SETTINGS_EYEBROW} block mb-2`}>{t('syncPanel.thisDevice')}</span>
          <div className="flex items-center gap-2 text-sm font-medium">
            <span className="relative flex h-2 w-2" aria-hidden="true">
              {state !== 'floor' && state !== 'offline' && state !== 'demo' && (
                <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-40 ${state === 'paused' ? 'bg-amber-400' : 'bg-emerald-400'}`} />
              )}
              <span className={`relative inline-flex rounded-full h-2 w-2 ${state === 'paused' || state === 'demo' ? 'bg-amber-500' : 'bg-emerald-500'}`} />
            </span>
            {buildDeviceName()} - v{VERSION}
          </div>
          <p className={`mt-1 mb-2.5 text-xs ${state === 'paused' || state === 'floor' || state === 'demo' ? amber : 'text-pn-muted'}`}>
            {state === 'demo' ? t('syncPanel.rhythmDemo')
              : state === 'paused' ? t('syncPanel.rhythmPaused')
              : state === 'floor' ? t('syncPanel.rhythmFloor')
              : state === 'offline' ? t('syncPanel.rhythmOffline')
              : t('syncPanel.rhythm')}
          </p>
          {/* Both switches govern a server conversation the demo never
              has, so they would be controls over nothing. */}
          {!demo && (
            <SwitchRow
              className="mt-auto border-t border-divider pt-2.5"
              label={t('syncPanel.pauseSync')}
              checked={paused}
              onChange={(v) => setSyncPaused(v)}
            />
          )}
          {!demo && wifiOnlyAvailable() && (
            <SwitchRow
              className="border-t border-divider pt-2.5 mt-2.5"
              label={t('syncPanel.filesWifiOnly')}
              checked={wifi.enabled}
              onChange={(v) => setFilesWifiOnly(v)}
            />
          )}
        </div>

        <div className="flex flex-col rounded-lg border border-divider px-3.5 py-3 sm:col-span-3">
          <span className={`${SETTINGS_EYEBROW} block mb-2`}>{t('syncPanel.whereTitle')}</span>
          <div className="flex items-center gap-1.5 flex-wrap text-xs text-pn-soft">
            <span className="rounded-md border border-divider bg-track px-2 py-1 whitespace-nowrap">{t('syncPanel.nodeDevice')}</span>
            <Lock size={12} className="text-pn-muted shrink-0" aria-hidden="true" />
            <span className="rounded-md border border-divider bg-track px-2 py-1 whitespace-nowrap">{t('syncPanel.nodeEncrypted')}</span>
            <CloudArrowUp size={13} className="text-pn-muted shrink-0" aria-hidden="true" />
            <span className="rounded-md border border-emerald-600/40 bg-track px-2 py-1 whitespace-nowrap">{t('syncPanel.nodeRegion')} {'\u{1F1E8}\u{1F1ED}'}</span>
          </div>
          {/* No local-at-rest line here: the seal's residuals need
              caveats a settings card has no room for. This card only
              makes the claim the product advertises; THREAT_MODEL.md
              carries the honest detail. */}
          <p className="mt-2 mb-2.5 text-xs text-pn-muted">{t('syncPanel.sealed')}</p>
          <p className="mt-auto border-t border-divider pt-2.5 text-xs text-pn-muted">
            {t('syncPanel.offlineFact')}
          </p>
        </div>
      </div>

      {/* ── Account ID (ID & Sync only) ── */}
      {pubkey && <AccountIdRow pubkey={pubkey} unsynced={unsynced} pendingCount={pending.count} log={log} failed={failedNotes} />}

      {/* ── Recent activity ── */}
      {!demo && <ActivityList log={log} />}
    </div>
  );
}

function SwitchRow({
  label,
  checked,
  onChange,
  className = '',
}: {
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  className?: string;
}) {
  return (
    <div className={`flex items-center gap-3 ${className}`}>
      <span className="flex-1 text-[13px] font-medium">{label}</span>
      {/* Same switch idiom as ListPrefsPopover / NotesList - one design. */}
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={label}
        onClick={() => onChange(!checked)}
        className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition ${
          checked ? 'bg-accent' : 'bg-neutral-300 dark:bg-neutral-700'
        }`}
      >
        <span
          className={`inline-block h-4 w-4 transform rounded-full bg-white transition ${
            checked ? 'translate-x-4 rtl:-translate-x-4' : 'translate-x-0.5 rtl:-translate-x-0.5'
          }`}
        />
      </button>
    </div>
  );
}

/**
 * The last passes as small bars, oldest first. Green ran clean, red
 * failed; height tracks how much the pass moved. Purely glanceable -
 * the exact numbers live in the activity list below.
 */
function PassBars({ log }: { log: SyncPassEntry[] }) {
  if (log.length < 2) return null;
  const bars = log.slice(-12);
  return (
    <div className="mt-2.5 flex items-end gap-[3px] h-5" aria-hidden="true">
      {bars.map((e, i) => {
        const h = 30 + Math.min(70, (e.up + e.down + (e.failed ?? 0)) * 7);
        // Older passes fade: the newest bar is fully opaque, the oldest
        // sits at 45%, so a red failure from hours ago reads as history
        // instead of a live alarm.
        const age = bars.length > 1 ? i / (bars.length - 1) : 1;
        return (
          <span
            key={`${e.at}-${i}`}
            className={`flex-1 rounded-[2px] ${!e.ok ? 'bg-red-500/60' : e.failed ? 'bg-amber-500/60' : 'bg-emerald-500/50'}`}
            style={{ height: `${e.ok ? h : 60}%`, opacity: 0.45 + 0.55 * age }}
          />
        );
      })}
    </div>
  );
}

function AccountIdRow({
  pubkey,
  unsynced,
  pendingCount,
  log,
  failed,
}: {
  pubkey: string;
  unsynced: number;
  pendingCount: number;
  /** The recent passes, newest last (syncLog.ts). */
  log: SyncPassEntry[];
  /** The notes the last pass could not push. */
  failed: ReadonlyArray<{ id: string; failure: PushFailure; chars: number }>;
}) {
  const { t } = useTranslation('settings');
  const [copied, setCopied] = useState<'id' | 'report' | null>(null);

  async function copy(kind: 'id' | 'report') {
    // The support report is deliberately English: it is written for our
    // support inbox, not for the user, and a fixed shape greps well.
    const text =
      kind === 'id'
        ? pubkey
        : [
            'PrivacyNotes support report',
            `Account: ${pubkey}`,
            `Device: ${buildDeviceName()}`,
            `Version: ${VERSION}`,
            `Unsynced notes: ${unsynced}`,
            `Pending file uploads: ${pendingCount}`,
            `Last sync: ${lastOkSyncAt() !== null ? new Date(lastOkSyncAt() as number).toISOString() : 'never'}`,
            // The three things the 2026-09-04 case needed a dashboard for:
            // which notes are stuck and why, whether passes run, and what
            // the session did. Ids are prefixes, titles never appear.
            ...(failed.length > 0
              ? ['', 'Not backed up:', ...failed.map((f) => `  ${f.id.slice(0, 8)}  ${f.failure.reason}  ${f.chars} chars  ${f.failure.message}`)]
              : []),
            '',
            'Recent passes (newest first):',
            ...[...log].reverse().map((e) =>
              `  ${new Date(e.at).toISOString()}  ${e.ok ? 'ok' : 'FAILED'}  up=${e.up} down=${e.down}${e.failed ? ` failed=${e.failed}` : ''}${(e.n ?? 1) > 1 ? ` x${e.n}` : ''}  ${e.ms}ms`,
            ),
            '',
            'Auth breadcrumbs (newest first):',
            ...readAuthLog(20).reverse().map((b) => {
              const { t: at, event, ...rest } = b;
              const detail = Object.keys(rest).length > 0 ? `  ${JSON.stringify(rest)}` : '';
              return `  ${at}  ${event}${detail}`;
            }),
          ].join('\n');
    try {
      await navigator.clipboard.writeText(text);
      setCopied(kind);
      setTimeout(() => setCopied(null), 1800);
    } catch {
      /* clipboard not available */
    }
  }

  return (
    // pn-account-id: container-query pair in index.css, same pattern as
    // pn-storage (ui-patterns section 48). The PANE's width decides the
    // form: narrow panes give the ID the whole line with the two buttons
    // in a 2-column row beneath (a one-line squeeze truncated the ID to
    // four characters on phones); wide panes keep everything on one line.
    <div className="pn-account-id rounded-lg border border-divider px-3.5 py-3">
      <span className={`${SETTINGS_EYEBROW} block mb-2`}>{t('accountId.heading')}</span>
      <div className="pn-account-id-row">
        <code className="min-w-0 rounded bg-track px-2.5 py-1.5 text-xs font-mono truncate">{pubkey}</code>
        {/* Labels never change - only the icon flips to a check - so the
            buttons cannot resize under the click. */}
        <CopyButton
          label={t('accountId.copyId')}
          copied={copied === 'id'}
          onClick={() => void copy('id')}
        />
        <CopyButton
          label={t('accountId.report')}
          copied={copied === 'report'}
          onClick={() => void copy('report')}
        />
      </div>
    </div>
  );
}

function CopyButton({
  label,
  copied,
  onClick,
}: {
  label: string;
  copied: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`inline-flex items-center justify-center gap-1.5 rounded border px-2.5 py-1.5 text-xs whitespace-nowrap transition ${
        copied ? 'border-accent bg-accent/10 text-accent' : 'border-divider hover:bg-surface-1'
      }`}
    >
      {copied ? <Check size={12} weight="bold" /> : <Copy size={12} />}
      {label}
    </button>
  );
}

function ActivityList({ log }: { log: SyncPassEntry[] }) {
  const { t } = useTranslation('settings');
  // Open on desktop, folded on phones - the one section long enough to
  // earn a fold (the mobile panel scrolls otherwise).
  const [open, setOpen] = useState(
    () => typeof window !== 'undefined' && window.matchMedia('(min-width: 640px)').matches,
  );
  if (log.length === 0) return null;
  const rows = [...log].reverse().slice(0, 6);
  return (
    <div className="rounded-lg border border-divider overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="w-full flex items-center gap-2 px-3.5 py-2.5 hover:bg-surface-1 transition"
      >
        <span className={SETTINGS_EYEBROW}>{t('syncPanel.activity')}</span>
        <CaretDown size={16} className={`ms-auto text-pn-muted transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && (
        <table className="w-full text-xs text-pn-soft">
          <tbody>
            {rows.map((e, i) => (
              <tr key={`${e.at}-${i}`} className="border-t border-divider">
                <td className="px-3.5 py-1.5 tabular-nums text-pn-muted">
                  {new Date(e.at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </td>
                <td className={`px-2 py-1.5 ${!e.ok ? 'text-red-500 dark:text-red-400' : e.failed ? 'text-amber-600 dark:text-amber-400' : ''}`}>
                  {!e.ok
                    ? t('syncPanel.passFailed')
                    : e.up === 0 && e.down === 0 && !e.failed
                      ? (e.n ?? 1) > 1
                        ? t('syncPanel.passNothingRepeat', { count: e.n })
                        : t('syncPanel.passNothing')
                      : [
                          e.up > 0 ? t('syncPanel.passUp', { count: e.up }) : null,
                          e.down > 0 ? t('syncPanel.passDown', { count: e.down }) : null,
                          e.failed ? t('syncPanel.passPushFailed', { count: e.failed }) : null,
                        ].filter(Boolean).join(', ')}
                </td>
                <td className="px-3.5 py-1.5 text-end tabular-nums text-pn-muted">
                  {(e.ms / 1000).toFixed(1)}s
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
