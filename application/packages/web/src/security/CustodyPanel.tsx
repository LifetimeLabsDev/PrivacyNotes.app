import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { CaretDown, Check, FloppyDisk, Scales, Warning } from '../icons';
import { PrivacyLadder } from '../PrivacyLadder';
import { useAuth } from '../auth';
import { SETTINGS_HELP, SectionEyebrow } from '../settingsUI';

type Mode = 'custodial' | 'self-custody';

type OAuthProviderName = 'google' | 'apple' | 'github';

/** Brand names, deliberately not translated. */
const PROVIDER_LABEL: Record<OAuthProviderName, string> = {
  google: 'Google',
  apple: 'Apple',
  github: 'GitHub',
};

/**
 * Key custody, both directions, in Settings > Security > Your Phrase.
 *
 * Mounted by PhraseTab BELOW PhraseView, never above: the self-custody
 * challenge is answered from the word grid, so the words have to be on
 * screen first.
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
 * The custodial direction requires a live OAuth session: a device
 * reached by typing the phrase has no session for the endpoint to
 * authorize against, and provider-only sign-in is the entire point of
 * custodial mode, so offering it there would be offering nothing.
 *
 * Spec: ops/docs/custodial-key-spec.md. Backlog #112.
 */
export function CustodyPanel({ phrase }: { phrase: string }) {
  const { t } = useTranslation('security');
  const { t: tAuth } = useTranslation('auth');
  const { auth, supabase, releaseCustody, adoptCustody } = useAuth();

  const [selected, setSelected] = useState<Mode | null>(null);
  const [answers, setAnswers] = useState<string[]>(['', '', '']);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<Mode | null>(null);
  const [ladderOpen, setLadderOpen] = useState(false);
  // undefined while we are still asking; null means no provider session.
  // We keep the provider NAME rather than a boolean so the card can say
  // "One click with Google" instead of "your provider only" - the word
  // "provider" is our jargon, not the user's.
  const [provider, setProvider] = useState<OAuthProviderName | null | undefined>(
    undefined,
  );

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
    let cancelled = false;
    void (async () => {
      try {
        const { data } = await supabase.auth.getSession();
        const p = data.session?.user?.app_metadata?.provider;
        if (cancelled) return;
        setProvider(
          p === 'google' || p === 'apple' || p === 'github' ? p : null,
        );
      } catch {
        if (!cancelled) setProvider(null);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [supabase]);

  if (auth.status !== 'authenticated') return null;
  if (words.length !== 12) return null;

  const current: Mode = auth.isCustodial ? 'custodial' : 'self-custody';
  // Nothing to offer: not custodial, and no provider session to become
  // custodial with.
  if (current === 'self-custody' && !provider) return null;

  const pick = selected ?? current;
  const changing = pick !== current;
  const allCorrect = positions.every(
    (pos, i) =>
      answers[i]!.trim().toLowerCase() === words[pos - 1]!.toLowerCase(),
  );
  // Leaving custodial mode is the only direction with a precondition.
  const canConfirm = changing && (pick === 'custodial' || allCorrect);

  function reset() {
    setSelected(null);
    setAnswers(['', '', '']);
    setError(null);
  }

  async function handleConfirm() {
    if (!canConfirm || busy) return;
    setBusy(true);
    setError(null);
    const result = pick === 'custodial' ? await adoptCustody() : await releaseCustody();
    if (result.ok) {
      setDone(pick);
      reset();
    } else {
      setError(result.error);
    }
    setBusy(false);
  }

  const ROWS: { label: string; custodial: string; self: string }[] = [
    {
      label: t('custody.rowDevice'),
      // Name the actual provider. "Your provider" is our word for it,
      // not the user's, and they only ever have one. Falls back to a
      // phrase-free wording when there is no live session to read it
      // from (a custodial account reached by typing the phrase).
      custodial: provider
        ? t('custody.rowDeviceCustodial', { provider: PROVIDER_LABEL[provider] })
        : t('custody.rowDeviceCustodialGeneric'),
      self: t('custody.rowDeviceSelf'),
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
    return (
      <button
        type="button"
        onClick={() => {
          setSelected(mode);
          setError(null);
        }}
        disabled={busy}
        aria-pressed={active}
        className={`text-start rounded-lg border p-3 transition ${
          active
            ? 'border-accent ring-1 ring-accent/30 bg-surface-2'
            : 'border-divider bg-surface-2 hover:bg-surface-1'
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
    <div className="@container border-t border-divider pt-4 space-y-2.5">
      <SectionEyebrow>{t('custody.eyebrow')}</SectionEyebrow>

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

      {!done && (
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
              <p className={`${SETTINGS_HELP} leading-relaxed`}>
                {t('custody.challengePrompt')}
              </p>
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
            </>
          )}

          {error && (
            <div className="rounded-md border border-red-300 bg-red-50 dark:border-red-900/60 dark:bg-red-950/30 text-red-700 dark:text-red-300 text-xs p-2">
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
      )}
    </div>
  );
}
