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

interface Props {
  /** Human-readable status from the export pipeline. */
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
        <div className="px-6 py-4 border-b border-divider">
          <h2 className="text-lg font-semibold">
            {error ? t('exportProgress.failedTitle') : done ? t('exportProgress.completeTitle') : t('exportProgress.exportingTitle')}
          </h2>
        </div>

        {/* Body */}
        <div className="px-6 py-5">
          {error ? (
            <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
          ) : (
            <>
              <p className="text-sm text-neutral-600 dark:text-neutral-400 mb-3">
                {status || t('exportProgress.preparing')}
              </p>
              {/* Progress bar */}
              <div className="h-1.5 rounded-full bg-neutral-100 dark:bg-neutral-800 overflow-hidden">
                <div className={`h-full rounded-full transition-all duration-300 ${
                  done
                    ? 'w-full bg-emerald-500 dark:bg-emerald-400'
                    : 'w-2/3 bg-accent animate-pulse'
                }`} />
              </div>
            </>
          )}
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-divider flex justify-end">
          <button
            type="button"
            onClick={onClose}
            disabled={!done && !error}
            className={`text-[13px] font-medium px-4 py-1.5 rounded-md transition ${
              done || error
                ? 'bg-accent text-white hover:bg-accent-hover'
                : 'bg-neutral-100 dark:bg-neutral-800 text-neutral-400 dark:text-neutral-600 cursor-not-allowed'
            }`}
          >
            {done || error ? t('common:actions.done') : t('exportProgress.exporting')}
          </button>
        </div>
      </div>
    </div>
  );
}
