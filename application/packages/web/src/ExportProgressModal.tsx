/**
 * Export progress modal - shows status during full backup export.
 *
 * Mirrors the visual style of UploadProgressModal (same width, backdrop,
 * borders, progress bar treatment) but simpler: single status line +
 * one progress bar, since export is a sequential pipeline.
 */

import { useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { useEscapeToClose } from './useEscapeToClose';
import { Button, Callout, CloseButton, ProgressBar } from './ui';

interface Props {
  /** Human-readable status from the export pipeline. Empty once an export
   *  finishes whole; a finished export whose file lacks a picture or a file
   *  its notes refer to carries the sentence that says so. */
  status: string;
  /** True once the export has finished (downloaded or errored). */
  done: boolean;
  /** Optional error message if the export failed. */
  error?: string;
  onClose: () => void;
}

export function ExportProgressModal({ status, done, error, onClose }: Props) {
  const { t } = useTranslation('importExport');
  useEscapeToClose(onClose, done || !!error);
  const overlayRef = useRef<HTMLDivElement | null>(null);
  // The file was saved, short of something. It never reads as complete.
  const incomplete = done && !error && status !== '';

  return (
    <div
      ref={overlayRef}
      className="fixed inset-0 z-[100] flex items-center justify-center bg-black/50 dark:bg-black/70"
      onClick={(e) => { if (done && e.target === overlayRef.current) onClose(); }}
    >
      <div
        className="w-[360px] bg-surface-2 rounded-lg border border-divider flex flex-col overflow-hidden text-pn"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="px-6 py-4 border-b border-divider flex items-center justify-between gap-2">
          <h2 className="text-lg font-semibold">
            {error
              ? t('exportProgress.failedTitle')
              : incomplete
                ? t('exportProgress.incompleteTitle')
                : done ? t('exportProgress.completeTitle') : t('exportProgress.exportingTitle')}
          </h2>
          {/* Only once there is something to close. A running export has no
              way to stop, which is why Escape and the footer button are shut
              too: an X that dismissed the window would leave the work going
              with nothing on screen reporting it. */}
          {(done || error) && (
            <CloseButton onClick={onClose} />
          )}
        </div>

        {/* Body */}
        <div className="px-6 py-5">
          {error ? (
            <Callout tone="danger">{error}</Callout>
          ) : (
            <>
              {/* While it runs, the progress line. A clean finish has no
                  status, and the title and the full green bar say it is done;
                  an incomplete one keeps the sentence that says what the file
                  lacks. */}
              {(!done || incomplete) && (
                <p className="text-sm text-pn-muted mb-3">
                  {status || t('exportProgress.preparing')}
                </p>
              )}
              {/* Progress bar */}
              <ProgressBar
                label={incomplete ? t('exportProgress.incompleteTitle') : done ? t('exportProgress.completeTitle') : t('exportProgress.exportingTitle')}
                value={done ? 1 : undefined}
                tone={incomplete ? 'warning' : done ? 'success' : 'info'}
              />
            </>
          )}
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-divider flex justify-end">
          <Button action="done" onClick={onClose} disabled={!done && !error}>
            {done || error ? t('common:actions.done') : t('exportProgress.exporting')}
          </Button>
        </div>
      </div>
    </div>
  );
}
