import { useEffect, useState } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import { useAuth } from './auth';
import { deleteAccountServer } from './devices';
import { deleteEntireLocalDatabase } from './notesRepo';
import { setDeletingAccount } from './sync';
import { SectionEyebrow } from './settingsUI';
import { isDemoMode, isDemoOwnedKey } from './demo';
import { settingsLocalKey } from './settingsLocalKey';
import { HelpChip } from './HelpChip';

// ------------------------------------------------------------------
// Danger zone - account & data deletion
// ------------------------------------------------------------------

/**
 * Wipe this session's keys from both localStorage and sessionStorage.
 * Catches per-key to avoid one bad key blocking the rest.
 *
 * The demo runs on the SAME origin as a real install whenever the URL
 * carries `?demo=1`, and it renders this panel with the local half
 * already ticked. A prefix sweep there removes the real account's phrase
 * envelope, PIN wrap, biometric wrap and Supabase session, none of which
 * the demo owns: every credential the demo writes goes into a `.demo`
 * bucket for exactly this reason, and this was the one sweep that did
 * not respect it. So in demo the sweep is the bucket plus the demo
 * settings key, which is the same set clearFreshDemoCredentials drops on
 * a fresh tab, and nothing else is touched.
 */
function clearAllStorageKeys(): void {
  const demo = isDemoMode();
  const demoSettings = settingsLocalKey();
  for (const store of [localStorage, sessionStorage]) {
    const keys: string[] = [];
    for (let i = 0; i < store.length; i++) {
      const k = store.key(i);
      if (!k) continue;
      // Clear app keys AND Supabase auth session keys. Without the
      // sb- prefix, a stale OAuth session survives account deletion
      // and hydrateFromOAuthSession treats the deleted user as
      // existing on the next page load.
      const owned = demo
        ? isDemoOwnedKey(k) || k === demoSettings
        : k.startsWith('privacynotes.') || k.startsWith('sb-');
      if (owned) keys.push(k);
    }
    for (const k of keys) {
      try { store.removeItem(k); } catch { /* ignore */ }
    }
  }
}

export function DangerZone({ onDeleteStarted }: { onDeleteStarted: () => void }) {
  const { t } = useTranslation('settings');
  const { auth, supabase } = useAuth();
  const [expanded, setExpanded] = useState(false);
  const [deleteLocal, setDeleteLocal] = useState(true);
  // Demo mode has no server-side account to delete, so the option is
  // neither offered nor pre-selected - local wipe is the only real action.
  const [deleteServer, setDeleteServer] = useState(!isDemoMode());
  const [confirmText, setConfirmText] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // null = unchecked, true/false = result of has_active_storage_sub RPC.
  // We block server-side deletion until the user cancels their storage
  // sub in Paddle (surface-and-defer per gap #8).
  const [hasActiveSub, setHasActiveSub] = useState<boolean | null>(null);

  const authed = auth.status === 'authenticated' ? auth : null;

  // Preflight when the danger zone expands. Cheap RPC, returns boolean.
  useEffect(() => {
    if (!expanded || !authed) return;
    // Demo mode makes zero server calls - there is no account and no
    // storage sub, so answer the preflight locally.
    if (isDemoMode()) { setHasActiveSub(false); return; }
    let cancelled = false;
    void (async () => {
      const { data, error: rpcErr } = await supabase.rpc(
        'has_active_storage_sub',
      );
      if (cancelled) return;
      if (rpcErr) {
        // RPC unavailable (migration not applied) → fail open. Server
        // still preflights, so this only affects the warning surface.
        console.warn('[DangerZone] has_active_storage_sub failed', rpcErr);
        setHasActiveSub(false);
        return;
      }
      setHasActiveSub(data === true);
    })();
    return () => { cancelled = true; };
  }, [expanded, authed, supabase]);

  if (!authed) return null;

  // Deleting the server account always implies wiping local state too -
  // without a valid auth.users row the local session is dead anyway.
  const effectiveDeleteLocal = deleteLocal || deleteServer;
  const blockedByStorageSub = deleteServer && hasActiveSub === true;
  const canDelete =
    confirmText.toUpperCase() === 'DELETE' &&
    (deleteLocal || deleteServer) &&
    !blockedByStorageSub;

  async function handleDelete() {
    if (!authed || !canDelete) return;
    setBusy(true);
    setError(null);

    try {
      // Server deletion first (while we still have credentials).
      if (deleteServer) {
        // Re-poll storage sub status right before deleting - the user may
        // have cancelled their sub in another tab since the DangerZone
        // expanded. Catches multi-tab races before the 409. See gap #44.
        const { data: subNow } = await supabase.rpc('has_active_storage_sub');
        if (subNow === true) {
          setHasActiveSub(true);
          setBusy(false);
          return;
        }
        const { data: sessData } = await supabase.auth.getSession();
        const session = sessData.session;
        if (!session?.access_token || !session.user?.id) {
          throw new Error(t('danger.noSession'));
        }

        // Block any further sync calls before we kick off deletion. An
        // in-flight `sync()` started before this click can still land
        // upserts after the server delete - we can't abort it from out
        // here, but we can prevent NEW syncs and re-delete afterward.
        // See gap #3.
        setDeletingAccount(true);

        const deleteArgs = {
          supabase,
          accessToken: session.access_token,
          authUid: session.user.id,
          signingPrivateKey: authed.signingPrivateKey,
        };
        // Timeout guard: if the edge function hangs, don't leave sync
        // paused indefinitely. 60s is generous for a cold-start + DB ops.
        // See gap #43.
        const DELETE_TIMEOUT_MS = 60_000;
        await Promise.race([
          deleteAccountServer(deleteArgs),
          new Promise<never>((_, reject) =>
            setTimeout(() => reject(new Error(t('danger.deleteTimeout'))), DELETE_TIMEOUT_MS),
          ),
        ]);

        // Belt-and-suspenders: any sync that was already in flight when
        // we set the flag may have landed an upsert seconds after the
        // edge function finished. Sleep briefly, then re-delete to mop
        // up. Best-effort - auth.users is gone so this 401s, which is
        // fine; what matters is that the server's idempotent table
        // deletes (run before auth deletion) catch any sneaked-in rows.
        await new Promise((resolve) => setTimeout(resolve, 2000));
        try {
          await deleteAccountServer(deleteArgs);
        } catch (e) {
          // Expected: 401 because auth.users is gone, or quiet success.
          console.log('[DangerZone] re-delete returned (expected):', (e as Error).message);
        }
      }

      // Local wipe - always runs when server is deleted (the session
      // is gone), and optionally runs on its own ("wipe this device").
      if (effectiveDeleteLocal) {
        // Zero key material.
        authed.encryptionKey.fill(0);
        authed.signingPrivateKey.fill(0);
        // Kill the Supabase session before wiping storage. The server-
        // side user is already gone so we only clear locally; without
        // this the sb-* session key survives and hydrateFromOAuthSession
        // treats a re-signup as a returning user.
        //
        // Not in demo: the demo holds no session of its own, so the only
        // row this could clear belongs to the real account signed in on
        // the same origin.
        if (!isDemoMode()) {
          await supabase.auth.signOut({ scope: 'local' }).catch(() => {});
        }
        // Nuke IndexedDB (notes, images, attachments, dedup tables).
        await deleteEntireLocalDatabase();
        // Wipe all localStorage/sessionStorage privacynotes.* + sb-* keys.
        clearAllStorageKeys();
      }

      onDeleteStarted();

      // Hard reload to onboarding. Both phrase and OAuth users land on
      // the clean signup page and can create a fresh account.
      window.location.replace('/');
    } catch (err) {
      // Roll back the deletion flag - the user is still authenticated
      // and may want to keep using the app, so let sync resume.
      setDeletingAccount(false);
      const msg = (err as Error).message;
      // Server-side fallback when the preflight didn't catch an
      // active storage sub (stale client, RPC unavailable, etc.).
      if (msg.includes('active_storage_sub')) {
        setHasActiveSub(true);
        setError(t('danger.activeSubError'));
      } else {
        setError(msg);
      }
      setBusy(false);
    }
  }

  if (!expanded) {
    return (
      <div>
        <button
          type="button"
          onClick={() => setExpanded(true)}
          className="w-full rounded-md bg-red-500/10 hover:bg-red-500/20 text-red-600 dark:text-red-400 text-xs font-medium px-3 py-2.5 transition"
        >
          {t('danger.deleteCta')}
        </button>
      </div>
    );
  }

  return (
    <div className="rounded-md border border-red-300 dark:border-red-900/60 p-4 space-y-3">
      <SectionEyebrow danger>
        {t('danger.heading')}
      </SectionEyebrow>

      <p className="text-xs text-pn-soft leading-relaxed">
        {t('danger.warning')}
      </p>

      <HelpChip surface="deleteAccount" />

      {blockedByStorageSub && (
        <div className="rounded-md border border-amber-400/40 bg-amber-50 dark:border-amber-600/30 dark:bg-amber-950/20 text-amber-700 dark:text-amber-400 text-xs leading-relaxed px-3 py-2">
          {t('danger.blockedByStorage')}
        </div>
      )}

      <label className="flex items-start gap-2 text-sm cursor-pointer">
        <input
          type="checkbox"
          checked={effectiveDeleteLocal}
          onChange={(e) => setDeleteLocal(e.target.checked)}
          disabled={busy || deleteServer}
          className="mt-0.5 accent-red-600"
        />
        <span className={`${deleteServer && !deleteLocal ? 'text-pn-muted/75' : 'text-pn-soft'}`}>
          {t('danger.localLabel')}
          <span className="block text-xs text-pn-soft">
            {t('danger.localDesc')}
            {deleteServer && !deleteLocal && ` ${t('danger.localRequired')}`}
          </span>
        </span>
      </label>

      {!isDemoMode() && (
      <label className="flex items-start gap-2 text-sm cursor-pointer">
        <input
          type="checkbox"
          checked={deleteServer}
          onChange={(e) => setDeleteServer(e.target.checked)}
          disabled={busy}
          className="mt-0.5 accent-red-600"
        />
        <span className="text-pn-soft">
          {t('danger.cloudLabel')}
          <span className="block text-xs text-pn-soft">
            {t('danger.cloudDesc')}
          </span>
        </span>
      </label>
      )}

      <div>
        <label className="block text-xs text-pn-soft mb-1">
          <Trans
            i18nKey="settings:danger.confirmPrompt"
            components={{ kbd: <span className="font-mono font-semibold text-red-600 dark:text-red-400" /> }}
          />
        </label>
        <input
          type="text"
          value={confirmText}
          onChange={(e) => setConfirmText(e.target.value)}
          disabled={busy}
          placeholder="DELETE"
          autoComplete="off"
          spellCheck={false}
          className="w-full rounded-md border border-divider bg-surface-2 text-sm px-3 py-1.5 focus:outline-none focus:ring-1 focus:ring-red-500 dark:focus:ring-red-600 placeholder:text-pn-muted"
        />
      </div>

      {error && (
        <div className="rounded-md border border-red-300 bg-red-50 dark:border-red-900/60 dark:bg-red-950/30 text-red-700 dark:text-red-300 text-xs p-2">
          {error}
        </div>
      )}

      <div className="flex gap-2">
        <button
          type="button"
          onClick={() => {
            setExpanded(false);
            setConfirmText('');
            setError(null);
          }}
          disabled={busy}
          className="flex-1 rounded-md border border-divider hover:bg-surface-1 px-3 py-2 text-sm transition"
        >
          {t('common:actions.cancel')}
        </button>
        <button
          type="button"
          onClick={() => void handleDelete()}
          disabled={!canDelete || busy}
          className="flex-1 rounded-md bg-red-600 hover:bg-red-700 disabled:bg-red-600/50 text-white px-3 py-2 text-sm font-semibold transition disabled:cursor-not-allowed"
        >
          {busy ? t('danger.deleting') : t('danger.deletePermanently')}
        </button>
      </div>
    </div>
  );
}
