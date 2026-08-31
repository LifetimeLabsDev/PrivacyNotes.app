import { QRCodeCanvas } from 'qrcode.react';
import { useRef, useState } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import { CaretDown, Check, EyeSlash, Warning, iconCopy, iconDownload } from '../icons';
import { buildSignInUrl } from '../qrSignIn';
import { RevealGate } from '../RevealGate';
import { saveBlob } from '../saveFile';

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
export function PhraseView({
  phrase,
  onCancel,
  showCallout = false,
  cancelLabel,
  hideDismiss = false,
  gated = false,
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
   * Cover the words behind a RevealGate until the user asks for them.
   * PhraseTab passes this when no PIN is set, so opening the tab no
   * longer puts the phrase on screen by itself (GitHub #245). Callers
   * that already gate their own reveal (DeviceLimitModal) leave it off.
   */
  gated?: boolean;
}) {
  const { t } = useTranslation('security');
  const words = phrase.split(' ');
  const [copied, setCopied] = useState(false);
  const [showQR, setShowQR] = useState(false);
  // Starts covered whenever the caller gates it. Both things that can
  // reveal the words on screen - the grid and the QR - hang off this.
  const [sealed, setSealed] = useState(gated);
  const qrWrapperRef = useRef<HTMLDivElement | null>(null);

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(phrase);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable */
    }
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
    await saveBlob(blob, filename);
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
          footnote={t('phraseView.sealedFootnote')}
          onReveal={() => setSealed(false)}
        />
      ) : (
        /* Words first: full-width 2-column grid so longer words never clip */
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
      )}

      {/* Cover them again on demand. Sits directly under the grid rather
          than at the end of the pane: a full-width button below the last
          control reads as the end of the pane, which is the reason
          PhraseTab suppresses the dismiss button (see hideDismiss). */}
      {gated && !sealed && (
        <button
          onClick={() => {
            setShowQR(false);
            setSealed(true);
          }}
          className="w-full inline-flex items-center justify-center gap-1.5 rounded-md border border-divider hover:bg-surface-1 px-3 py-2 text-sm text-pn-soft transition"
        >
          <EyeSlash aria-hidden="true" />
          {t('phraseView.hidePhrase')}
        </button>
      )}

      {/* QR collapsed behind a toggle - most people read/copy words; the
          QR is only for device-to-device migration via scan. Hidden while
          sealed: the QR carries the phrase, so it is a second way to put
          it on screen. Save QR and Copy stay, because neither shows it. */}
      {!sealed && (
        <button
          onClick={() => setShowQR((s) => !s)}
          aria-expanded={showQR}
          className="w-full inline-flex items-center justify-center gap-1.5 rounded-md border border-divider hover:bg-surface-1 px-3 py-2 text-sm text-pn-soft transition"
        >
          <CaretDown aria-hidden="true" className={`transition-transform ${showQR ? 'rotate-180' : ''}`} />
          {showQR ? t('phraseView.hideQr') : t('phraseView.showQr')}
        </button>
      )}

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

      {!hideDismiss && (
        <button
          onClick={onCancel}
          className="w-full rounded-md border border-divider hover:bg-surface-1 px-3 py-2 text-sm transition"
        >
          {cancelLabel ?? t('common:actions.done')}
        </button>
      )}
    </div>
  );
}
