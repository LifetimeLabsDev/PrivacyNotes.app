import { useEffect, useRef, useState } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import { Upload, X } from './icons';
import { useEscapeToClose } from './useEscapeToClose';
import { extractPhraseFromScan } from './qrSignIn';
import { isLinuxNative } from './devices';
import { Brand } from './Brand';

/** Camera QR scanner for sign-in. Dynamically imports `qr-scanner`. */
export function QrScannerModal({
  onScanned,
  onClose,
}: {
  onScanned: (phrase: string) => void;
  onClose: () => void;
}) {
  const { t } = useTranslation('auth');
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const scannerRef = useRef<{ stop: () => void; destroy: () => void } | null>(
    null
  );
  // Cache the qr-scanner module after first dynamic import so the
  // "upload image" path doesn't re-import (and so it works even when
  // the live camera path errored out).
  const qrScannerModRef = useRef<any>(null);
  // Native Linux (WebKitGTK) never grants getUserMedia, so skip the camera
  // entirely and open straight into the upload-only path. See ops/docs/gotchas.md.
  const linuxNative = isLinuxNative();
  const [status, setStatus] = useState<
    'loading' | 'running' | 'error' | 'uploadOnly'
  >(linuxNative ? 'uploadOnly' : 'loading');
  const [error, setError] = useState<string | null>(null);
  // Non-fatal hint shown under the viewfinder. Used for two cases:
  //   - "We saw a QR but it isn't a PrivacyNotes sign-in code"
  //   - "Couldn't read that image"
  // Cleared whenever we go back to a clean scanning state.
  const [hint, setHint] = useState<string | null>(null);
  const [scanningImage, setScanningImage] = useState(false);

  async function loadQrScanner(): Promise<any> {
    if (qrScannerModRef.current) return qrScannerModRef.current;
    const mod = await import('qr-scanner');
    const QrScanner: any = (mod as any).default ?? mod;
    qrScannerModRef.current = QrScanner;
    return QrScanner;
  }

  useEffect(() => {
    let cancelled = false;

    async function boot() {
      // Linux native: camera is dead at the webview layer, so don't even
      // try - the upload-image path below works without it.
      if (linuxNative) return;
      try {
        // Dynamic import so the ~30KB scanner + worker aren't pulled
        // into the critical onboarding bundle.
        const QrScanner = await loadQrScanner();
        if (cancelled) return;

        if (!videoRef.current) return;

        // Fail loudly if the device has no camera at all (desktop
        // without webcam, iframe with camera permission blocked, etc).
        // We still surface the upload-image fallback in this case so
        // the user isn't fully stranded.
        if (typeof QrScanner.hasCamera === 'function') {
          const hasCamera = await QrScanner.hasCamera();
          if (!hasCamera) {
            throw new Error(t('qrScanner.noCamera'));
          }
        }

        const scanner = new QrScanner(
          videoRef.current,
          (result: { data: string } | string) => {
            // Older builds pass the raw string; newer ones pass a
            // { data } object when `returnDetailedScanResult: true`.
            const decoded =
              typeof result === 'string' ? result : result?.data ?? '';
            const phrase = extractPhraseFromScan(decoded);
            if (!phrase) {
              // Decoded *something* but it isn't ours. Tell the user
              // so they don't sit there silently failing - e.g. they
              // scanned a wifi QR, a vCard, etc. The library will
              // keep firing callbacks for every successful decode so
              // we don't need to do anything else here.
              setHint(t('qrScanner.notSignInCode'));
              return;
            }
            // Got a valid PrivacyNotes phrase. Stop the camera
            // immediately (don't wait for unmount) so the camera LED
            // turns off the instant we have what we need, then hand
            // the phrase up to the parent.
            try {
              scanner.stop();
            } catch {
              /* ignore - destroy() in cleanup will finish the job */
            }
            onScanned(phrase);
          },
          {
            returnDetailedScanResult: true,
            highlightScanRegion: true,
            highlightCodeOutline: true,
            preferredCamera: 'environment',
          }
        );

        scannerRef.current = scanner;
        await scanner.start();
        if (cancelled) {
          scanner.destroy();
          return;
        }
        setStatus('running');
      } catch (err) {
        if (cancelled) return;
        const message =
          err instanceof Error ? err.message : t('qrScanner.startFailed');
        // Friendlier copy for the common cases.
        const friendly =
          /permission|denied|NotAllowedError/i.test(message)
            ? t('qrScanner.permissionDenied')
            : /NotFoundError|no camera|hasCamera/i.test(message)
              ? t('qrScanner.cameraNotFound')
              : /Failed to fetch dynamically imported module|Importing a module script failed/i.test(message)
                ? t('qrScanner.staleTab')
                : message;
        setError(friendly);
        setStatus('error');
      }
    }

    boot();

    return () => {
      cancelled = true;
      const s = scannerRef.current;
      if (s) {
        try {
          s.stop();
        } catch {
          /* ignore */
        }
        try {
          s.destroy();
        } catch {
          /* ignore */
        }
      }
      scannerRef.current = null;
    };
  }, [onScanned, linuxNative]);

  useEscapeToClose(onClose);

  async function handleImageFile(file: File) {
    setHint(null);
    setScanningImage(true);
    try {
      const QrScanner = await loadQrScanner();
      // scanImage accepts File/Blob/HTMLImageElement and returns either
      // a string or { data } depending on options. We don't request the
      // detailed result here - a raw string is all we need.
      const decoded: string = await QrScanner.scanImage(file);
      const phrase = extractPhraseFromScan(decoded);
      if (!phrase) {
        setHint(t('qrScanner.imageNotSignInCode'));
        return;
      }
      // Stop the live camera before handing off, same reason as the
      // live path: turn the camera LED off the instant we don't need it.
      try {
        scannerRef.current?.stop();
      } catch {
        /* ignore */
      }
      onScanned(phrase);
    } catch {
      // qr-scanner throws a plain Error when no code is found. Don't
      // surface the raw library message - it isn't user-friendly.
      setHint(t('qrScanner.imageUnreadable'));
    } finally {
      setScanningImage(false);
      // Reset the input so picking the same file again still fires onChange.
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  }

  return (
    <div
      className="fixed inset-0 bg-black/50 dark:bg-black/70 z-50 flex items-center justify-center p-4"
      onClick={onClose}
    >
      <div
        className="bg-surface-2 border border-divider rounded-lg max-w-md w-full overflow-hidden text-pn"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-6 py-4 border-b border-neutral-200 dark:border-neutral-900">
          <h2 className="text-lg font-semibold">{t('qrScanner.title')}</h2>
          <button
            onClick={onClose}
            aria-label={t('common:actions.close')}
            className="text-neutral-400 hover:text-neutral-600 dark:hover:text-neutral-300 transition p-1 -m-1"
          >
            <X size={18} />
          </button>
        </div>

        <div className="relative bg-black aspect-square flex items-center justify-center">
          <video
            ref={videoRef}
            className="w-full h-full object-cover"
            playsInline
            muted
          />
          {status === 'loading' && (
            <div className="absolute inset-0 flex items-center justify-center text-white text-xs">
              {t('qrScanner.startingCamera')}
            </div>
          )}
          {status === 'error' && (
            <div className="absolute inset-0 bg-neutral-900 flex flex-col items-center justify-center text-center p-6 text-sm text-neutral-200">
              <div className="mb-2 text-red-400 font-medium">
                {t('qrScanner.cameraUnavailable')}
              </div>
              <div className="text-xs text-neutral-400">{error}</div>
            </div>
          )}
          {status === 'uploadOnly' && (
            <div className="absolute inset-0 bg-neutral-900 flex flex-col items-center justify-center text-center p-6 text-sm text-neutral-200">
              <div className="mb-2 font-medium">
                {t('qrScanner.uploadOnlyTitle')}
              </div>
              <div className="text-xs text-neutral-400">
                {t('qrScanner.uploadOnlyBody')}
              </div>
            </div>
          )}
          {scanningImage && (
            <div className="absolute inset-0 bg-black/70 flex items-center justify-center text-white text-xs">
              {t('qrScanner.readingImage')}
            </div>
          )}
        </div>

        {hint && (
          <div className="px-5 py-2 text-xs text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/30 border-t border-amber-200/50 dark:border-amber-900/40">
            {hint}
          </div>
        )}

        <div className="px-5 py-3 border-t border-neutral-200 dark:border-neutral-900 flex items-center justify-between gap-3">
          <div className="text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed">
            {t('qrScanner.uploadHint')}
          </div>
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            disabled={scanningImage}
            className="shrink-0 inline-flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded border border-neutral-300 dark:border-neutral-700 hover:bg-surface-1 disabled:opacity-50 transition"
          >
            <Upload size={14} />
            {t('qrScanner.uploadImage')}
          </button>
          <input
            ref={fileInputRef}
            type="file"
            accept="image/*"
            className="hidden"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) void handleImageFile(file);
            }}
          />
        </div>

        <div className="px-5 py-3 border-t border-neutral-200 dark:border-neutral-900 text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed">
          <Trans
            i18nKey="auth:qrScanner.footer"
            components={{ brand: <Brand /> }}
          />
        </div>
      </div>
    </div>
  );
}
