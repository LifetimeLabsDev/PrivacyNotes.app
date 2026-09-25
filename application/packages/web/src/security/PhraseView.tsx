import { QRCodeCanvas } from 'qrcode.react';
import { useEffect, useRef, useState } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import { CaretDown, Check, EyeSlash, FileText, Warning, iconCopy, iconDownload } from '../icons';
import { buildPhraseFile, PHRASE_FILE_NAME } from '../phraseFile';
import { buildSignInUrl } from '../qrSignIn';
import { RevealGate } from '../RevealGate';
import { saveBlob, type SaveResult } from '../saveFile';

/**
 * Phrase display - words-first layout: a full-width 2-column word grid
 * on top, the QR collapsed behind a Show/Hide toggle, two action
 * buttons (Save QR / Copy), and a single dismiss button. Stacking
 * vertically keeps the words readable on narrow phone screens, where
 * the old side-by-side QR + grid clipped longer words.
 *
 * Single source of truth for showing a recovery phrase. Used by:
 *  - SecurityModal -> PhraseTab (full screen, no callout)
 *  - DeviceLimitModal (embedded in OAuth amber warning, no callout)
 *
 * `showCallout` and `cancelLabel` let callers tweak chrome without
 * duplicating the QR + grid + button logic.
 */

/**
 * How long the words stay on screen once the reader asks for them.
 * Spec: ops/docs/design-decisions.md (recovery phrase: reveal gate and auto-hide)
 */
const AUTO_HIDE_SECONDS = 60;
export function PhraseView({
  phrase,
  onCancel,
  showCallout = false,
  cancelLabel,
  hideDismiss = false,
  gated = false,
  hasPin = false,
}: {
  phrase: string;
  onCancel: () => void;
  showCallout?: boolean;
  cancelLabel?: string;
  /**
   * Drop the trailing dismiss button. PhraseTab sets this because the
   * settings modal already closes via its own X and back arrow, and a
   * third dismiss sitting between the words and the custody section
   * reads as the end of the pane when it is not.
   */
  hideDismiss?: boolean;
  /**
   * Cover the phrase, and every control that can put it on screen or in
   * a file, behind a RevealGate until the reader asks for it. The reveal
   * lasts AUTO_HIDE_SECONDS and then covers itself again. Callers that
   * already gate their own reveal (DeviceLimitModal) leave this off.
   */
  gated?: boolean;
  /**
   * Picks the gate's footnote. Someone without a PIN is offered one;
   * someone who has already answered a PIN to get here is told what the
   * timer does instead.
   */
  hasPin?: boolean;
}) {
  const { t } = useTranslation('security');
  const words = phrase.split(' ');
  const [copied, setCopied] = useState(false);
  // The phrase files whose last save failed. A failed native save can leave an
  // empty or partial file, so a file's message stays until that same file
  // saves; a dismissed dialog changes nothing.
  const [failedFiles, setFailedFiles] = useState<ReadonlySet<string>>(() => new Set());
  const [showQR, setShowQR] = useState(false);
  // Starts covered whenever the caller gates it. Everything that can put
  // the phrase on screen, in the clipboard or in a file hangs off this.
  const [sealed, setSealed] = useState(gated);
  const [secondsLeft, setSecondsLeft] = useState(AUTO_HIDE_SECONDS);
  const qrWrapperRef = useRef<HTMLDivElement | null>(null);

  // The deadline is a wall-clock time, not a count of ticks: a browser
  // throttles the interval of a background tab to about one call a
  // minute, and a counter that only moves when the tick fires would
  // leave the words up for as long as the tab stays hidden.
  useEffect(() => {
    if (!gated || sealed) return;
    const deadline = Date.now() + AUTO_HIDE_SECONDS * 1000;
    setSecondsLeft(AUTO_HIDE_SECONDS);
    const id = setInterval(() => {
      const left = Math.ceil((deadline - Date.now()) / 1000);
      if (left > 0) {
        setSecondsLeft(left);
        return;
      }
      clearInterval(id);
      setShowQR(false);
      setSealed(true);
    }, 1000);
    return () => clearInterval(id);
  }, [gated, sealed]);

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(phrase);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable */
    }
  }

  function reportSave(filename: string, saved: SaveResult) {
    if (!saved.ok && saved.reason === 'cancelled') return;
    setFailedFiles((files) => {
      const next = new Set(files);
      if (saved.ok) next.delete(filename);
      else next.add(filename);
      return next;
    });
  }

  async function handleDownloadQR() {
    const canvas = qrWrapperRef.current?.querySelector('canvas');
    if (!canvas) return;

    // canvas.toBlob is async; wrap so we can await it.
    const blob = await new Promise<Blob | null>((resolve) => {
      try {
        canvas.toBlob((b) => resolve(b), 'image/png');
      } catch {
        resolve(null);
      }
    });
    if (!blob) return;

    const filename = 'privacynotes-phrase-qr.png';

    // Download only. Never route this through `navigator.share` - the
    // QR decrypts the entire vault, and the system share sheet would
    // happily hand it to WhatsApp, Teams, AirDrop, nearby Bluetooth
    // devices, etc. Direct local save only.
    // saveBlob is a direct local save (web download / native Save As); it never
    // touches navigator.share, so the vault-decrypting QR can't reach a share sheet.
    reportSave(filename, await saveBlob(blob, filename));
  }

  // Same file the onboarding screen offers; its strings live in the auth catalog.
  async function handleDownloadTxt() {
    const text = buildPhraseFile(phrase, {
      title: t('auth:createPhrase.txtTitle'),
      oneLine: t('auth:createPhrase.txtOneLine'),
      footer: t('auth:createPhrase.txtFooter'),
    });
    // Direct local save, never navigator.share: the file decrypts the vault.
    const saved = await saveBlob(new Blob([text], { type: 'text/plain' }), PHRASE_FILE_NAME);
    reportSave(PHRASE_FILE_NAME, saved);
  }

  return (
    <div className="space-y-3">
      {showCallout && (
        <div className="rounded-md border border-divider bg-track p-3 text-sm leading-relaxed text-pn flex items-start gap-2.5">
          <Warning size={18} aria-hidden="true" className="shrink-0 mt-0.5 text-amber-500 dark:text-amber-400" />
          <span>
            <Trans i18nKey="security:phraseView.calloutWords" components={{ strong: <strong /> }} />
          </span>
        </div>
      )}

      {sealed ? (
        <RevealGate
          compact
          tone="warning"
          glyph={EyeSlash}
          heading={t('phraseView.sealedHeading')}
          body={t('phraseView.sealedBody')}
          actionLabel={t('phraseView.sealedReveal')}
          footnote={hasPin ? t('phraseView.sealedFootnotePin') : t('phraseView.sealedFootnote')}
          onReveal={() => setSealed(false)}
        />
      ) : (
        /* Nothing below the gate exists while the phrase is covered. The
           grid and the QR show the words; Copy, Save QR and the .txt
           download hand them to the clipboard or to a file, which the
           reader is just as entitled to be asked about first. */
        <>
          {/* Words first: full-width 2-column grid so longer words never clip */}
          <div dir="ltr" className="grid grid-cols-2 gap-1.5"> {/* rtl-ok: BIP-39 phrase is English, order is safety-critical, always LTR */}
            {words.map((w, i) => (
              <div
                key={i}
                className="rounded bg-track border border-divider text-pn px-2 py-1 text-xs font-mono"
              >
                <span className="text-pn-muted me-1">
                  {i + 1}.
                </span>
                {w}
              </div>
            ))}
          </div>

          {/* Cover them again, by hand or when the minute runs out. Sits
              directly under the grid rather than at the end of the pane: a
              full-width button below the last control reads as the end of
              the pane, which is the reason PhraseTab suppresses the dismiss
              button (see hideDismiss). The label carries the seconds and
              the bar drains alongside it, so the reader can see the reveal
              expiring without reading a number. */}
          {gated && (
            <button
              onClick={() => {
                setShowQR(false);
                setSealed(true);
              }}
              className="w-full overflow-hidden rounded-md border border-divider hover:bg-surface-1 text-sm text-pn-soft transition"
            >
              <span className="flex items-center justify-center gap-1.5 px-3 py-2">
                <EyeSlash aria-hidden="true" />
                {t('phraseView.hidePhraseIn', { seconds: secondsLeft })}
              </span>
              <span className="block h-0.5 bg-divider">
                <span
                  className="block h-full bg-amber-500 transition-[width] duration-1000 ease-linear"
                  style={{ width: `${(secondsLeft / AUTO_HIDE_SECONDS) * 100}%` }}
                />
              </span>
            </button>
          )}

          {/* QR collapsed behind a toggle - most people read or copy the
              words; the QR is only for device-to-device migration via scan. */}
          <div className="grid grid-cols-2 gap-2">
            <button
              data-setting="security.qrCode"
              onClick={() => setShowQR((s) => !s)}
              aria-expanded={showQR}
              className="inline-flex items-center justify-center gap-1.5 rounded-md border border-divider hover:bg-surface-1 px-2 py-2 text-sm text-pn-soft transition"
            >
              <CaretDown aria-hidden="true" className={`transition-transform ${showQR ? 'rotate-180' : ''}`} />
              {showQR ? t('phraseView.hideQr') : t('phraseView.showQr')}
            </button>
            <button
              onClick={() => { void handleDownloadTxt(); }}
              className="inline-flex items-center justify-center gap-1.5 rounded-md border border-divider hover:bg-surface-1 px-2 py-2 text-sm text-pn-soft transition"
            >
              <FileText aria-hidden="true" />
              {t('auth:createPhrase.downloadTxt')}
            </button>
          </div>

          {/*
            The canvas stays mounted even when collapsed (hidden via CSS, not
            unmounted) so handleDownloadQR can always read it - Save QR works
            whether or not the QR is on screen.

            marginSize=4 bakes a spec-compliant quiet zone into the canvas
            pixels - NOT just CSS padding around the wrapper. The wrapper's
            p-2 only shows on screen; once the user downloads the canvas or
            screenshots it for sharing, only the canvas bytes travel. With
            marginSize=0 (qrcode.react v4 default) WhatsApp / gallery
            fullscreen viewers display the image edge-to-edge, swallow the
            finder patterns into the screen border, and scanners fail.
          */}
          <div className={showQR ? 'flex justify-center' : 'hidden'}>
            <div
              ref={qrWrapperRef}
              className="flex items-center justify-center bg-white p-2 rounded-lg border border-divider dark:border-transparent"
            >
              <QRCodeCanvas value={buildSignInUrl(phrase)} size={180} level="M" marginSize={4} />
            </div>
          </div>

          {/* Save QR + Copy - 2-column */}
          <div className="grid grid-cols-2 gap-2">
            <button
              onClick={handleDownloadQR}
              className="inline-flex items-center justify-center gap-1.5 rounded-md border border-divider hover:bg-surface-1 px-2 py-2 text-sm transition"
            >
              {iconDownload()}
              {t('phraseView.saveQr')}
            </button>

            <button
              onClick={handleCopy}
              data-setting="security.copyPhrase"
              className={`inline-flex items-center justify-center gap-1.5 rounded-md border px-2 py-2 text-sm transition ${
                copied
                  ? 'bg-accent/10 text-accent border-accent'
                  : 'border-divider hover:bg-surface-1'
              }`}
            >
              {copied ? (
                <>
                  <Check aria-hidden="true" />
                  {t('phraseView.copied')}
                </>
              ) : (
                <>
                  {iconCopy()}
                  {t('phraseView.copyPhrase')}
                </>
              )}
            </button>
          </div>

          {failedFiles.size > 0 && (
            <p className="text-sm text-red-500 dark:text-red-400">{t('auth:createPhrase.saveFailed')}</p>
          )}

          {!hideDismiss && (
            <button
              onClick={onCancel}
              className="w-full rounded-md border border-divider hover:bg-surface-1 px-3 py-2 text-sm transition"
            >
              {cancelLabel ?? t('common:actions.done')}
            </button>
          )}
        </>
      )}
    </div>
  );
}
