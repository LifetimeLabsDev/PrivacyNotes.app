import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { CaretDown, Check, FloppyDisk, Scales, Warning } from '../icons';
import { PrivacyLadder } from '../PrivacyLadder';
import { useAuth } from '../auth';
import { SETTINGS_HELP, SectionEyebrow } from '../settingsUI';
import { isDemoMode } from '../demo';
import { MfaCancelledError } from '../mfaStep';
import { useAccountLogins } from '../accountLogins';

type Mode = 'custodial' | 'self-custody';

type OAuthProviderName = 'google' | 'apple' | 'github';
type CustodySession = {
  access_token: string;
  user: { id: string; app_metadata: Record<string, unknown> };
};
type SessionState =
  | { kind: 'loading' | 'error' | 'signedOut' | 'wrongVault' }
  | { kind: 'ready'; provider: OAuthProviderName | null; identity: string };

function sessionIdentity(session: CustodySession): string | null {
  try {
    const body = session.access_token.split('.')[1];
    if (!body) return null;
    const payload = JSON.parse(atob(body.replace(/-/g, '+').replace(/_/g, '/'))) as { session_id?: unknown };
    return typeof payload.session_id === 'string' ? `${session.user.id}:${payload.session_id}` : null;
  } catch { return null; }
}

function classifySession(session: CustodySession | null, pubkey: string | null): SessionState {
  if (!session) return { kind: 'signedOut' };
  if (!pubkey || session.user.app_metadata.pubkey !== pubkey) return { kind: 'wrongVault' };
  const identity = sessionIdentity(session);
  if (!identity) return { kind: 'error' };
  const p = session.user.app_metadata.provider;
  return { kind: 'ready', identity, provider: p === 'google' || p === 'apple' || p === 'github' ? p : null };
}

/** Brand names, deliberately not translated. */
const PROVIDER_LABEL: Record<OAuthProviderName, string> = {
  google: 'Google',
  apple: 'Apple',
  github: 'GitHub',
};

/**
 * Key custody, both directions, in Settings > Account > Key custody.
 *
 * The section stays visible when a provider session is unavailable.
 * Phrase reveal lives on a separate page from the saved-copy challenge.
 *
 * Presentation is a symmetric comparison, deliberately. An earlier
 * draft put an amber hazard panel in front of the custodial option
 * only, which meant the UI argued a position instead of describing
 * one. Both cards now carry the same three rows - new device, losing
 * the words, who can read your notes - so the trade is legible at a
 * glance and neither side is decorated as the wrong answer. The titles
 * are the same two the user already picked between at signup (auth
 * namespace), so the choice is recognizably the same choice.
 *
 * Amber survives in exactly one place: moving to self-custody, where
 * losing the words afterwards means permanent, unrecoverable loss.
 * That is a fact about the user's data, not a verdict on their
 * decision, and it is paired with a three-word possession challenge.
 * Going the other way has no such precondition and gets no alarm.
 *
 * Provider linking is a separate action. Storing a phrase still needs
 * explicit consent and an eligible session for this exact vault.
 *
 * Spec: ops/docs/custodial-key-spec.md. Backlog #112.
 */
export function CustodyPanel({ phrase, onReleaseCheckChange, onOpenConnectedAccounts }: {
  phrase: string;
  onReleaseCheckChange: (checking: boolean) => void;
  onOpenConnectedAccounts?: () => void;
}) {
  const { t } = useTranslation('security');
  const { t: tAuth } = useTranslation('auth');
  const { auth, supabase, releaseCustody, adoptCustody } = useAuth();
  const accountLogins = useAccountLogins();

  const [selected, setSelected] = useState<Mode | null>(null);
  const [answers, setAnswers] = useState<string[]>(['', '', '']);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<Mode | null>(null);
  const [ladderOpen, setLadderOpen] = useState(false);
  const [sessionState, setSessionState] = useState<SessionState>({ kind: 'loading' });
  const [releaseCheck, setReleaseCheck] = useState(false);
  const sessionRead = useRef(0);
  const actionEpoch = useRef(0);
  const activeIdentity = useRef<string | null>(null);
  const alive = useRef(false);
  const working = useRef(false);
  const pubkey = auth.status === 'authenticated' ? auth.pubkey : null;
  const provider = sessionState.kind === 'ready' ? sessionState.provider : null;
  const canAdopt = sessionState.kind === 'ready' && accountLogins.canAdopt === true
    && !accountLogins.loading && !accountLogins.error;
  const adoptionBlocked = auth.status !== 'authenticated' || (!auth.isCustodial && !canAdopt);

  useEffect(() => {
    if (adoptionBlocked) setSelected((previous) => previous === 'custodial' ? null : previous);
  }, [adoptionBlocked]);

  const resetRelease = useCallback(() => {
    setReleaseCheck(false);
    setAnswers(['', '', '']);
    onReleaseCheckChange(false);
  }, [onReleaseCheckChange]);

  const acceptSession = useCallback((session: CustodySession | null) => {
    const next = classifySession(session, pubkey);
    const identity = next.kind === 'ready' ? next.identity : null;
    if (activeIdentity.current !== identity) {
      actionEpoch.current++;
      working.current = false;
      setBusy(false);
      setSelected(null);
      setDone(null);
      setError(null);
      resetRelease();
    }
    activeIdentity.current = identity;
    setSessionState(next);
  }, [pubkey, resetRelease]);

  const readSession = useCallback(async () => {
    const read = ++sessionRead.current;
    setSessionState({ kind: 'loading' });
    if (isDemoMode()) { acceptSession(null); return; }
    try {
      const { data, error: sessionError } = await supabase.auth.getSession();
      if (!alive.current || read !== sessionRead.current) return;
      if (sessionError) throw sessionError;
      acceptSession(data.session);
    } catch {
      if (alive.current && read === sessionRead.current) setSessionState({ kind: 'error' });
    }
  }, [acceptSession, supabase]);

  const words = useMemo(() => phrase.trim().split(/\s+/), [phrase]);

  // Three distinct 1-based positions, drawn once per mount so the
  // challenge cannot be rerolled by closing and reopening the panel.
  const positions = useMemo(() => {
    const pool = words.map((_, i) => i + 1);
    const picked: number[] = [];
    while (picked.length < 3 && pool.length > 0) {
      const idx = Math.floor(Math.random() * pool.length);
      picked.push(pool.splice(idx, 1)[0]!);
    }
    return picked.sort((a, b) => a - b);
  }, [words]);

  useEffect(() => {
    alive.current = true;
    if (isDemoMode()) { setSessionState({ kind: 'signedOut' }); return () => { alive.current = false; }; }
    // Subscribe before the initial read. Auth events outrank older reads,
    // and the callback never enters another SDK call under its auth lock.
    const beforeSubscription = sessionRead.current;
    const { data } = supabase.auth.onAuthStateChange((_event, session) => {
      sessionRead.current++;
      if (alive.current) acceptSession(session);
    });
    if (sessionRead.current === beforeSubscription) void readSession();
    return () => {
      alive.current = false;
      sessionRead.current++;
      actionEpoch.current++;
      data.subscription.unsubscribe();
    };
  }, [acceptSession, readSession, supabase]);

  if (auth.status !== 'authenticated') return null;

  const current: Mode = auth.isCustodial ? 'custodial' : 'self-custody';

  const pick = selected === 'custodial' && adoptionBlocked ? current : selected ?? current;
  const changing = pick !== current;
  const allCorrect = positions.every(
    (pos, i) =>
      answers[i]!.trim().toLowerCase() === words[pos - 1]!.toLowerCase(),
  );
  // Adoption needs a confirmed connected account; release needs the saved phrase.
  const canConfirm = changing && words.length === 12 && sessionState.kind === 'ready'
    && (pick === 'custodial' ? canAdopt : releaseCheck && allCorrect);

  function reset() {
    setSelected(null);
    resetRelease();
    setError(null);
  }

  async function handleConfirm() {
    if (!canConfirm || working.current || sessionState.kind !== 'ready' || isDemoMode()) return;
    const identity = sessionState.identity;
    const requested = pick;
    const epoch = ++actionEpoch.current;
    working.current = true;
    setBusy(true);
    setError(null);
    const checkSession = async () => {
      const { data, error: sessionError } = await supabase.auth.getSession();
      const latest = classifySession(data.session, pubkey);
      if (!alive.current || epoch !== actionEpoch.current || sessionError || latest.kind !== 'ready'
        || latest.identity !== identity) throw new MfaCancelledError();
      return latest;
    };
    try {
      await checkSession();
      if (requested === 'custodial') {
        const eligibility = await accountLogins.refresh();
        const currentSession = await checkSession();
        const canStore = !eligibility.deleted && !eligibility.wrong_login && (eligibility.managed
          ? eligibility.connections.some((entry) => entry.active) : Boolean(currentSession.provider));
        if (!canStore) throw new MfaCancelledError();
      }
      // The custody action owns the fresh MFA step and rechecks this binding
      // immediately before its server call, including non-UI callers.
      const result = requested === 'custodial' ? await adoptCustody() : await releaseCustody();
      if (!alive.current || epoch !== actionEpoch.current) return;
      if (result.ok) {
        setDone(requested);
        reset();
      } else setError(result.error);
    } catch (failure) {
      if (alive.current && epoch === actionEpoch.current && !(failure instanceof MfaCancelledError)) setError(t('custody.changeFailed'));
    } finally {
      if (alive.current && epoch === actionEpoch.current) { working.current = false; setBusy(false); }
    }
  }

  const ROWS: { label: string; custodial: string; self: string }[] = [
    {
      label: t('custody.rowDevice'),
      // Legacy sessions name their provider. Managed vaults may have several
      // connected accounts and use the generic account wording instead.
      custodial: provider
        ? t('custody.rowDeviceCustodialSafe', { provider: PROVIDER_LABEL[provider] })
        : t('custody.rowDeviceCustodialSafeGeneric'),
      self: accountLogins.status?.managed && accountLogins.status.connections.some((entry) => entry.active)
        ? t('custody.rowDeviceSelfConnected')
        : provider ? t('custody.rowDeviceSelfProvider', { provider: PROVIDER_LABEL[provider] }) : t('custody.rowDeviceSelf'),
    },
    {
      label: t('custody.rowLost'),
      custodial: t('custody.rowLostCustodial'),
      self: t('custody.rowLostSelf'),
    },
    {
      // Where the key sits, not who can read the notes. "Who can read
      // your notes" is present tense and asks about people, so it
      // reads as a roster of readers and invites the assumption that
      // someone is browsing. Nobody is, in either mode. The honest
      // difference is where the key is stored, and "only" carries the
      // consequence without threat language.
      label: t('custody.rowKey'),
      custodial: t('custody.rowKeyCustodial'),
      self: t('custody.rowKeySelf'),
    },
  ];

  function card(mode: Mode) {
    const active = pick === mode;
    const disabled = busy || (mode === 'custodial' && adoptionBlocked);
    return (
      <button
        type="button"
        onClick={() => {
          setSelected(mode);
          setDone(null);
          resetRelease();
          setError(null);
        }}
        disabled={disabled}
        aria-pressed={active}
        className={`text-start rounded-lg border p-3 transition disabled:opacity-50 disabled:cursor-not-allowed ${
          active
            ? 'border-accent ring-1 ring-accent/30 bg-surface-2'
            : 'border-divider bg-surface-2 enabled:hover:bg-surface-1'
        }`}
      >
        {/* items-start, not items-center: at narrow widths the titles
            wrap to two lines and a vertically centred dot floats
            between them. mt-0.5 lines it up with the first line. */}
        <div className="flex items-start gap-2 mb-2">
          <span
            aria-hidden="true"
            className={`w-3.5 h-3.5 mt-0.5 rounded-full border-2 shrink-0 flex items-center justify-center ${
              active ? 'border-accent' : 'border-pn-muted'
            }`}
          >
            {active && <span className="w-1.5 h-1.5 rounded-full bg-accent" />}
          </span>
          <span className="text-sm font-medium text-pn min-w-0">
            {mode === 'custodial'
              ? tAuth('custody.simpleTitle')
              : tAuth('custody.maxSecurityTitle')}
          </span>
          {current === mode && (
            <span className="ml-auto mt-0.5 text-[11px] text-pn-muted shrink-0">
              {t('custody.current')}
            </span>
          )}
        </div>
        {/* Plain divs rather than dl/dt/dd: a definition list is flow
            content and this sits inside a <button>. Matches the option
            cards in Onboarding.tsx. */}
        <div className="space-y-1.5">
          {ROWS.map((row) => (
            <div key={row.label}>
              <span className="block text-[11px] text-pn-muted">{row.label}</span>
              <span className="block text-xs text-pn-soft leading-snug">
                {mode === 'custodial' ? row.custodial : row.self}
              </span>
            </div>
          ))}
        </div>
      </button>
    );
  }

  return (
    // @container, not a viewport breakpoint. What constrains these
    // cards is the settings pane (622px inside a 1470px window), so
    // `sm:` fired on viewport width while the pane was still far too
    // tight and every title wrapped.
    //
    // Measured in Chrome: each card needs 281px to hold its longest
    // ROW VALUE on one line, so two columns need ~570px. @xl is 36rem
    // = 576px, which at the real 622px pane yields 307px cards.
    //
    // Longer locales were checked rather than guessed at. German row
    // values top out at 227px against 283px of usable card width, so
    // they never wrap. Only the card TITLE overflows (340px needed for
    // "Maximale Sicherheit und Privatsphare" plus the radio and the
    // Current label), which costs one extra line and nothing else -
    // the radio is top-aligned precisely so a two-line title still
    // looks deliberate. Do not raise this to @2xl to prevent that: it
    // forces the common desktop case to stack in order to tidy a
    // cosmetic wrap in some languages.
    <div className="@container space-y-2.5">
      <SectionEyebrow setting="security.custody">{t('custody.eyebrow')}</SectionEyebrow>

      {sessionState.kind === 'loading' && <p className={SETTINGS_HELP} role="status">{t('custody.checkingSession')}</p>}
      {sessionState.kind === 'error' && (
        <div className="space-y-2">
          <p className={SETTINGS_HELP} role="alert">{t('custody.sessionUnavailable')}</p>
          <button type="button" onClick={() => void readSession()} disabled={busy} className="text-sm text-accent">{t('custody.retrySession')}</button>
        </div>
      )}
      {(sessionState.kind === 'signedOut' || sessionState.kind === 'wrongVault') && (
        <p className={SETTINGS_HELP}>{t(sessionState.kind === 'wrongVault' ? 'custody.wrongVaultSession' : 'custody.signInToChange')}</p>
      )}
      {sessionState.kind === 'ready' && !auth.isCustodial && !canAdopt && (
        <p className={SETTINGS_HELP}>{t('custody.connectToStore')}</p>
      )}
      {!isDemoMode() && sessionState.kind === 'ready' && (accountLogins.loading || accountLogins.error || accountLogins.canAdopt === null) && (
        <div className="space-y-2">
          <p className={SETTINGS_HELP}>{t(accountLogins.error === 'account_setup_unavailable'
            ? 'connectedAccounts.unavailable'
            : accountLogins.error ? 'custody.connectionsUnavailable' : 'custody.checkingConnections')}</p>
          {accountLogins.error && <button type="button" className="text-sm text-accent" disabled={busy || accountLogins.loading}
            onClick={() => void accountLogins.refresh().catch(() => {})}>{t('connectedAccounts.retry')}</button>}
        </div>
      )}
      <p className={SETTINGS_HELP}>{t('custody.connectingIsSeparate')}</p>
      <p className={SETTINGS_HELP}>{t('custody.mfaStillApplies')}</p>
      {onOpenConnectedAccounts && (
        <button type="button" className="text-sm text-accent" disabled={busy} onClick={onOpenConnectedAccounts}>{t('custody.connectedAccounts')}</button>
      )}

      {done && (
        <p className="text-[13px] leading-relaxed text-pn flex items-start gap-2">
          <Check aria-hidden="true" className="shrink-0 mt-0.5 text-accent" />
          <span>
            {done === 'custodial'
              ? t('custody.adoptDone')
              : t('custody.releaseDone')}
          </span>
        </p>
      )}

      <>
          {/* Always open. This setting existed but was unreachable,
              which is the whole reason for #112; putting it behind a
              disclosure click would reproduce that in miniature. */}
          <div className="grid grid-cols-1 @xl:grid-cols-2 gap-2">
            {card('custodial')}
            {card('self-custody')}
          </div>

          {changing && pick === 'self-custody' && (
            <>
              <div className="rounded-md border border-amber-400/40 bg-amber-50 dark:border-amber-600/30 dark:bg-amber-950/20 px-3 py-2.5 text-[13px] leading-relaxed text-amber-700 dark:text-amber-400 flex items-start gap-2.5">
                <Warning size={16} aria-hidden="true" className="shrink-0 mt-0.5" />
                <span>{t('custody.releaseWarning')}</span>
              </div>
              {!releaseCheck ? (
                <button
                  type="button"
                  disabled={busy || words.length !== 12}
                  onClick={() => { setReleaseCheck(true); onReleaseCheckChange(true); setAnswers(['', '', '']); }}
                  className="rounded-md border border-divider px-3 py-2 text-sm text-pn-soft hover:bg-surface-1 transition"
                >
                  {t('custody.checkSavedPhrase')}
                </button>
              ) : (
                <>
                <p className={`${SETTINGS_HELP} leading-relaxed`}>{t('custody.hiddenChallengePrompt')}</p>
                <div className="grid grid-cols-3 gap-2">
                {positions.map((pos, i) => (
                  <label key={pos} className="block">
                    <span className={`block ${SETTINGS_HELP} mb-1`}>
                      {t('custody.wordLabel', { position: pos })}
                    </span>
                    <input
                      type="text"
                      value={answers[i]}
                      onChange={(e) => {
                        const next = [...answers];
                        next[i] = e.target.value;
                        setAnswers(next);
                        setError(null);
                      }}
                      disabled={busy}
                      autoComplete="off"
                      autoCapitalize="none"
                      spellCheck={false}
                      className="w-full rounded-md border border-divider bg-track text-sm font-mono px-2 py-1.5 focus:outline-none focus:ring-1 focus:ring-accent"
                    />
                  </label>
                ))}
                </div>
                <button type="button" disabled={busy} className="text-sm text-accent" onClick={resetRelease}>{t('common:actions.cancel')}</button>
                </>
              )}
            </>
          )}

          {error && (
            <div role="alert" className="rounded-md border border-red-300 bg-red-50 dark:border-red-900/60 dark:bg-red-950/30 text-red-700 dark:text-red-300 text-xs p-2">
              {error}
            </div>
          )}

          {/* No Cancel. With the section always open there is nothing
              to cancel back to: re-picking the card marked Current
              undoes the selection and disables this again.

              Two columns, and the second one is why: the sign-in card
              offers this comparison before signup and nothing offered it
              afterwards, so the one screen where a signed-in user can
              actually act on it could not show it. Same component, same
              strings - see PrivacyLadder.tsx. The row is @xl like the
              cards above it, so the pane's width decides, not the
              viewport's. */}
          <div className="grid grid-cols-1 @xl:grid-cols-2 gap-2">
            <button
              type="button"
              onClick={() => void handleConfirm()}
              disabled={!canConfirm || busy}
              className="inline-flex items-center justify-center gap-1.5 rounded-md bg-accent text-white hover:bg-accent-hover px-3 py-2 text-sm font-medium transition disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {/* Neutral label until a different option is actually
                  picked. Naming the destructive direction while the
                  button is disabled and nothing is pending reads as a
                  threat rather than a description. The disk stays put
                  through all three: it marks the control, the label says
                  which way the save goes. */}
              <FloppyDisk aria-hidden="true" />
              {busy
                ? t('custody.busy')
                : !changing
                  ? t('common:actions.save')
                  : pick === 'custodial'
                    ? t('custody.adoptConfirm')
                    : t('custody.releaseConfirm')}
            </button>
            <button
              type="button"
              onClick={() => setLadderOpen((v) => !v)}
              aria-expanded={ladderOpen}
              aria-controls="pn-custody-ladder"
              className="inline-flex items-center justify-center gap-1.5 rounded-md border border-divider px-3 py-2 text-sm text-pn-soft hover:bg-surface-2 transition"
            >
              <Scales aria-hidden="true" />
              {tAuth('chooseMode.compareOptions')}
              <CaretDown
                aria-hidden="true"
                className={`transition-transform ${ladderOpen ? 'rotate-180' : ''}`}
              />
            </button>
          </div>

          {ladderOpen && <PrivacyLadder id="pn-custody-ladder" />}
      </>
    </div>
  );
}
