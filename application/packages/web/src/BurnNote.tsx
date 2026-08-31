import { useState, useEffect, useCallback, useMemo } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import { Fire, Lock, Moon, Sun } from './icons';
import { RevealGate } from './RevealGate';
import { useTheme } from './theme';
import { decryptJson, hexToBytes, createSupabaseClient } from '@notes/shared';
import { renderMarkdown, prepareRender } from './markdownRender';
import { marketingHomeHref } from './siteLinks';
import { Brand } from './Brand';

/**
 * Burn-After-Reading viewer - renders at /burn.
 *
 * URL format: /burn#id=<uuid>&k=<hex>
 *
 * The encrypted payload lives server-side in `burn_notes`. On reveal the
 * client calls the `consume_burn_note` RPC which atomically returns the
 * ciphertext AND deletes the row - one read, then it's gone forever.
 * The decryption key stays in the fragment (never sent to the server).
 *
 * Legacy v1/v2 links that embedded the ciphertext in the URL fragment
 * are no longer supported - they can't be server-burned.
 */

// Lightweight anon client - burn pages are unauthenticated.
// persistSession: false avoids creating a duplicate GoTrueClient
// instance that shares the same storage key as the main auth client.
const supabase = createSupabaseClient(
  import.meta.env.VITE_SUPABASE_URL,
  import.meta.env.VITE_SUPABASE_ANON_KEY,
  { persistSession: false, storageKey: 'sb-burn-view-auth' },
);

type Phase = 'sealed' | 'revealing' | 'revealed' | 'destroyed' | 'gone' | 'error';

/**
 * A vault item arrives as labelled rows rather than as its JSON body: this
 * page carries no vault code (see createBurnLink), so the sender's client
 * does the reading and sends the labels along in the sender's language.
 */
interface BurnField {
  label: string;
  value: string;
  mono?: boolean;
}

/**
 * The payload is written by whoever made the link, so nothing in it is
 * trusted to have the shape it claims - a row that is not two strings is
 * dropped rather than handed to React.
 */
function readFields(raw: unknown): BurnField[] {
  if (!Array.isArray(raw)) return [];
  const rows: BurnField[] = [];
  for (const item of raw) {
    if (!item || typeof item !== 'object') continue;
    const { label, value, mono } = item as Record<string, unknown>;
    if (typeof label !== 'string' || typeof value !== 'string') continue;
    rows.push({ label, value, mono: mono === true });
  }
  return rows;
}

export default function BurnNote() {
  const { t } = useTranslation('notesChrome');
  const { theme, setTheme } = useTheme();
  const [phase, setPhase] = useState<Phase>('sealed');
  const [note, setNote] = useState<{ title: string; body: string; fields: BurnField[] } | null>(null);
  const [countdown, setCountdown] = useState<number | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Parse the fragment on mount.
  const fragment = window.location.hash.slice(1);
  const params = new URLSearchParams(fragment);
  const noteId = params.get('id');
  const keyHex = params.get('k');
  const hasPayload = Boolean(noteId && keyHex);
  const [checking, setChecking] = useState(hasPayload);

  // On mount: quick existence check so we don't show a sealed UI for
  // a note that's already been consumed or expired. Uses the
  // SECURITY DEFINER `burn_note_exists` RPC instead of a SELECT on the
  // table or a view - single-ID lookup only, no enumeration surface.
  useEffect(() => {
    if (!noteId) { setChecking(false); return; }
    supabase
      .rpc('burn_note_exists', { p_id: noteId })
      .then(({ data, error }) => {
        // On error (RPC missing pre-migration, network blip), assume
        // the note exists and let the consume path handle the rest.
        if (error) {
          setChecking(false);
          return;
        }
        if (data === false) {
          window.history.replaceState(null, '', window.location.pathname);
          setPhase('gone');
        }
        setChecking(false);
      });
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const handleReveal = useCallback(async () => {
    if (!noteId || !keyHex) return;
    setPhase('revealing');

    // Blank the fragment immediately so the key doesn't linger in the URL bar.
    window.history.replaceState(null, '', window.location.pathname);

    try {
      // Atomic fetch-and-delete - the row is gone after this call.
      const { data, error } = await supabase.rpc('consume_burn_note', {
        note_id: noteId,
      });

      if (error) {
        setErrorMsg(t('burnView.error.server'));
        setPhase('error');
        return;
      }

      if (!data) {
        // Row didn't exist - already consumed or expired.
        setPhase('gone');
        return;
      }

      // data is the ciphertext (base64-encoded nonce + ciphertext).
      const raw = Uint8Array.from(atob(data), (c) => c.charCodeAt(0));
      const key = hexToBytes(keyHex);
      const nonce = raw.slice(0, 24);
      const ciphertext = raw.slice(24);
      const result = decryptJson<{ title?: unknown; body?: unknown; fields?: unknown }>(
        ciphertext,
        nonce,
        key,
      );

      if (!result) {
        setErrorMsg(t('burnView.error.decryption'));
        setPhase('error');
        return;
      }

      setNote({
        title: typeof result.title === 'string' ? result.title : '',
        body: typeof result.body === 'string' ? result.body : '',
        fields: readFields(result.fields),
      });
      setPhase('revealed');
      setCountdown(120);
    } catch {
      setErrorMsg(t('burnView.error.network'));
      setPhase('error');
    }
  }, [noteId, keyHex, t]);

  // Countdown timer - ticks every second while the note is visible.
  useEffect(() => {
    if (phase !== 'revealed' || countdown === null) return;
    if (countdown <= 0) {
      setNote(null);
      setPhase('destroyed');
      return;
    }
    const id = window.setTimeout(() => setCountdown((c) => (c ?? 1) - 1), 1000);
    return () => window.clearTimeout(id);
  }, [phase, countdown]);

  // Manual self-destruct - note is already deleted server-side, this
  // just clears the in-memory plaintext.
  function handleDestroy() {
    setNote(null);
    setPhase('destroyed');
  }

  const formatTime = (s: number) => {
    const m = Math.floor(s / 60);
    const sec = s % 60;
    return `${m}:${sec.toString().padStart(2, '0')}`;
  };

  const [renderReady, setRenderReady] = useState(false);

  // Memoize rendered markdown so the 1Hz countdown tick doesn't
  // re-render the body HTML every second.
  const bodyHtml = useMemo(
    () => (note?.body ? renderMarkdown(note.body) : ''),
    [note?.body, renderReady],
  );

  // A shared note can contain math or fenced code, and rendering those needs
  // KaTeX / lowlight, both fetched on demand: this page is the one a stranger
  // opens from a link, so it must not carry either renderer for the notes
  // that need neither. The first pass prints the plain source, the fetch
  // flips renderReady, and the memo above re-renders with real MathML and
  // highlighted tokens - which is why renderReady is in its deps despite not
  // being read in the body.
  useEffect(() => {
    if (!note?.body) return;
    let live = true;
    void prepareRender(note.body).then(() => { if (live) setRenderReady(true); });
    return () => { live = false; };
  }, [note?.body]);

  return (
    <div className="min-h-screen bg-surface-2 text-pn flex flex-col items-center justify-center px-6 py-12">
      <div className="max-w-2xl w-full">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-3">
            {/* Flame icon */}
            <Fire size={28} className="text-orange-500" />
            <div>
              <h1 className="text-xl font-bold tracking-tight">Burn After Reading</h1>
              <p className="text-xs text-neutral-500">{t('burnView.tagline')}</p>
            </div>
          </div>
          <button
            onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
            className="text-neutral-400 hover:text-neutral-600 dark:hover:text-neutral-300 transition"
            aria-label={t('burnView.toggleTheme')}
          >
            {theme === 'dark' ? (
              <Sun size={16} />
            ) : (
              <Moon size={16} />
            )}
          </button>
        </div>

        {/* Loading - checking if the note still exists */}
        {checking && (
          <div className="rounded-lg border border-divider bg-neutral-50 dark:bg-neutral-900 p-8 text-center">
            <p className="text-neutral-500 animate-pulse">{t('burnView.checking')}</p>
          </div>
        )}

        {/* Sealed state - waiting for user to click reveal */}
        {!checking && phase === 'sealed' && hasPayload && (
          <RevealGate
            tone="danger"
            glyph={Lock}
            heading={t('burnView.sealed.heading')}
            body={t('burnView.sealed.subheading')}
            actionLabel={t('burnView.sealed.reveal')}
            footnote={t('burnView.sealed.warning')}
            onReveal={() => void handleReveal()}
          />
        )}

        {/* Revealing - brief loading state */}
        {phase === 'revealing' && (
          <div className="rounded-lg border border-divider bg-neutral-50 dark:bg-neutral-900 p-8 text-center">
            <p className="text-neutral-500 animate-pulse">{t('burnView.revealing')}</p>
          </div>
        )}

        {/* Revealed - note content with self-destruct timer */}
        {phase === 'revealed' && note && (
          <div className="space-y-4">
            {/* Self-destruct banner */}
            <div className="flex items-center justify-between rounded-lg bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900 px-4 py-2.5">
              <span className="text-sm text-red-600 dark:text-red-400 font-mono">
                {t('burnView.revealed.countdown', { time: formatTime(countdown ?? 0) })}
              </span>
              <button
                onClick={handleDestroy}
                className="text-xs font-medium text-red-500 hover:text-red-700 dark:hover:text-red-300 transition"
              >
                {t('burnView.revealed.clearNow')}
              </button>
            </div>

            {/* Note content */}
            <div className="rounded-lg border border-divider bg-surface-2 overflow-hidden">
              {note.title && (
                <div className="px-6 pt-5 pb-2">
                  <h2 className="text-xl font-bold tracking-tight">{note.title}</h2>
                </div>
              )}
              <div className="px-6 py-4 space-y-4">
                {/* Vault rows first, then whatever notes the item carries -
                    the same order the HTML and PDF exports print. */}
                {note.fields.length > 0 && (
                  <table className="w-full table-fixed border border-divider text-sm">
                    <tbody>
                      {note.fields.map((f, i) => (
                        <tr key={i} className={i > 0 ? 'border-t border-divider' : undefined}>
                          <th
                            scope="row"
                            dir="auto"
                            className="w-28 sm:w-36 border-e border-divider bg-surface-1 px-3 py-2 text-start align-top font-medium text-pn-muted"
                          >
                            {f.label}
                          </th>
                          <td
                            dir="auto"
                            className={`px-3 py-2 align-top whitespace-pre-wrap break-words ${f.mono ? 'font-mono text-xs' : ''}`}
                          >
                            {f.value}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
                {note.body ? (
                  <div
                    className="prose prose-neutral dark:prose-invert max-w-none prose-headings:tracking-tight prose-p:leading-relaxed prose-img:rounded-md"
                    dangerouslySetInnerHTML={{ __html: bodyHtml }}
                  />
                ) : note.fields.length === 0 ? (
                  <span className="text-neutral-400 italic">{t('burnView.revealed.emptyNote')}</span>
                ) : null}
              </div>
            </div>

            {/* Self-destruct footer */}
            <p className="text-center text-xs text-neutral-500 dark:text-neutral-600 italic">
              {t('burnView.revealed.deletedNotice')}
            </p>
          </div>
        )}

        {/* Destroyed - plaintext cleared from memory */}
        {phase === 'destroyed' && (
          <div className="rounded-lg border border-divider bg-neutral-50 dark:bg-neutral-900 p-8 text-center space-y-4">
            <div className="text-neutral-400 mx-auto">
              <Fire size={48} weight="duotone" className="mx-auto" />
            </div>
            <p className="text-lg font-semibold">{t('burnView.destroyed.heading')}</p>
            <p className="text-sm text-neutral-500">
              {t('burnView.destroyed.body')}
            </p>
            <a
              href={marketingHomeHref()}
              className="inline-block mt-2 text-sm text-accent hover:underline"
            >
              <Trans
                i18nKey="notesChrome:burnView.goToApp"
                components={{ brand: <Brand suffix=".app" /> }}
              />
            </a>
          </div>
        )}

        {/* Gone - already consumed or expired */}
        {phase === 'gone' && (
          <div className="rounded-lg border border-divider bg-neutral-50 dark:bg-neutral-900 p-8 text-center space-y-4">
            <div className="text-neutral-400 mx-auto">
              <Fire size={48} weight="duotone" className="mx-auto" />
            </div>
            <p className="text-lg font-semibold">{t('burnView.gone.heading')}</p>
            <p className="text-sm text-neutral-500">
              {t('burnView.gone.body')}
            </p>
            <a
              href={marketingHomeHref()}
              className="inline-block mt-2 text-sm text-accent hover:underline"
            >
              <Trans
                i18nKey="notesChrome:burnView.goToApp"
                components={{ brand: <Brand suffix=".app" /> }}
              />
            </a>
          </div>
        )}

        {/* Error state */}
        {phase === 'error' && (
          <div className="rounded-lg border border-red-200 dark:border-red-900 bg-red-50 dark:bg-red-950/30 p-8 text-center space-y-3">
            <p className="text-lg font-semibold text-red-600 dark:text-red-400">
              {t('burnView.error.heading')}
            </p>
            <p className="text-sm text-neutral-600 dark:text-neutral-400">
              {errorMsg || t('burnView.error.fallback')}
            </p>
          </div>
        )}

        {/* No payload in the URL */}
        {!checking && phase === 'sealed' && !hasPayload && (
          <div className="rounded-lg border border-divider bg-neutral-50 dark:bg-neutral-900 p-8 text-center space-y-3">
            <p className="text-lg font-semibold">{t('burnView.noPayload.heading')}</p>
            <p className="text-sm text-neutral-500">
              {t('burnView.noPayload.body')}
            </p>
            <a
              href={marketingHomeHref()}
              className="inline-block mt-2 text-sm text-accent hover:underline"
            >
              <Trans
                i18nKey="notesChrome:burnView.goToApp"
                components={{ brand: <Brand suffix=".app" /> }}
              />
            </a>
          </div>
        )}

        {/* Footer */}
        <div className="mt-8 text-center text-xs text-neutral-400 dark:text-neutral-600">
          {/* Every link on this page, this one and the "go to PrivacyNotes"
              links above, lands on the localized marketing homepage: a burn
              reader is a stranger who followed a shared link, so the app host
              would drop them on a sign-in wall for an account they don't have.
              Never the bare apex either - that is the smart entry, so it opens
              the app on the OLD origin and greets a signed-in reader with the
              move banner. Spec: ops/docs/domain-split.md */}
          <a href={marketingHomeHref()} className="text-pn transition">
            <Brand suffix=".app" />
          </a>
          {' '}{t('burnView.footerTagline')}
        </div>
      </div>
    </div>
  );
}
