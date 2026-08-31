/**
 * Upload progress modal - shows per-file status during batch uploads.
 *
 * States per file: validating → uploading → done | failed
 * Summary line at the bottom: "X done, Y uploading, Z failed"
 * Supported types + size limit shown as a footer hint.
 */

import { useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { useEscapeToClose } from './useEscapeToClose';
import { formatFileSize } from './attachmentValidation';
import { IconUpgrade } from './UpgradeModal';
import { isStorageConfigured } from './paddle';
import { proUnlocked } from './demo';
import { X } from './icons';

type FileUploadStatus = 'pending' | 'uploading' | 'done' | 'failed';

export interface FileUploadEntry {
  name: string;
  size: number;
  status: FileUploadStatus;
  error?: string;
  /** Structured failure class - preferred over sniffing `error` text.
   *  'storage-full' = refused up-front, nothing was created;
   *  'storage-full-kept' = server rejected mid-race, blob + note stay
   *  on this device until space frees (backlog #143). */
  errorCode?: 'storage-full' | 'storage-full-kept';
}

interface Props {
  entries: FileUploadEntry[];
  isPro: boolean;
  hasStorageSub: boolean;
  onOpenUpgrade: () => void;
  onManageStorage: () => void;
  onClose: () => void;
}

export function UploadProgressModal({ entries, isPro, hasStorageSub, onOpenUpgrade, onManageStorage, onClose }: Props) {
  const { t } = useTranslation('importExport');
  const overlayRef = useRef<HTMLDivElement | null>(null);
  const allDone = entries.length > 0 && entries.every((e) => e.status === 'done' || e.status === 'failed');

  useEscapeToClose(onClose, allDone);

  // Click outside to close (only when all done)
  useEffect(() => {
    if (!allDone) return;
    function handler(e: PointerEvent) {
      if (e.target === overlayRef.current) onClose();
    }
    window.addEventListener('pointerdown', handler);
    return () => window.removeEventListener('pointerdown', handler);
  }, [allDone, onClose]);

  const counts = { done: 0, uploading: 0, failed: 0, pending: 0 };
  for (const e of entries) counts[e.status]++;
  const active = counts.uploading + counts.pending;

  return (
    <div
      ref={overlayRef}
      className="fixed inset-0 z-[100] flex items-center justify-center bg-black/50 dark:bg-black/70"
    >
      <div className="w-[360px] max-h-[80vh] bg-surface-2 rounded-lg border border-divider flex flex-col overflow-hidden text-pn">
        {/* Header */}
        <div className="px-6 py-4 border-b border-divider flex items-center justify-between gap-3">
          <h2 className="text-lg font-semibold">
            {allDone
              ? counts.failed > 0
                ? counts.done > 0
                  ? t('upload.partialTitle', { done: counts.done, failed: counts.failed })
                  : t('upload.failedTitle')
                : t('upload.completeTitle')
              : t('upload.uploadingTitle', { count: entries.length })}
          </h2>
          <button
            type="button"
            onClick={onClose}
            disabled={!allDone}
            aria-label={t('common:actions.close')}
            className={`shrink-0 -m-1 p-1 transition ${
              allDone
                ? 'text-neutral-400 hover:text-neutral-600 dark:hover:text-neutral-300'
                : 'text-neutral-300 dark:text-neutral-700 cursor-not-allowed'
            }`}
          >
            <X size={18} />
          </button>
        </div>

        {/* File list */}
        <div className="flex-1 overflow-y-auto px-5 py-3 space-y-3">
          {entries.map((entry, i) => (
            <div key={`${entry.name}-${i}`}>
              <div className="flex items-center justify-between gap-2 mb-1">
                <span className={`text-[13px] truncate flex-1 ${
                  entry.status === 'failed'
                    ? 'text-red-600 dark:text-red-400'
                    : 'text-neutral-800 dark:text-neutral-200'
                }`}>
                  {entry.name}
                </span>
                <span className={`text-[12px] shrink-0 ${
                  entry.status === 'done'
                    ? 'text-emerald-600 dark:text-emerald-400'
                    : entry.status === 'failed'
                      ? 'text-red-500 dark:text-red-400'
                      : entry.status === 'uploading'
                        ? 'text-accent'
                        : 'text-neutral-400 dark:text-neutral-600'
                }`}>
                  {entry.status === 'done' && t('upload.statusDone')}
                  {entry.status === 'failed' && t('upload.statusFailed')}
                  {entry.status === 'uploading' && t('upload.statusUploading')}
                  {entry.status === 'pending' && t('upload.statusWaiting')}
                </span>
              </div>
              {/* Progress bar */}
              <div className="h-1 rounded-full bg-neutral-100 dark:bg-neutral-800 overflow-hidden">
                <div className={`h-full rounded-full transition-all duration-300 ${
                  entry.status === 'done'
                    ? 'w-full bg-emerald-500 dark:bg-emerald-400'
                    : entry.status === 'failed'
                      ? 'w-full bg-red-400 dark:bg-red-500'
                      : entry.status === 'uploading'
                        ? 'w-2/3 bg-accent animate-pulse'
                        : 'w-0'
                }`} />
              </div>
              {entry.status === 'failed' && (entry.errorCode || entry.error) && (
                <p className="text-[11px] text-red-500 dark:text-red-400 mt-0.5 leading-tight">
                  {/* Structured codes first; the raw-text quota sniff stays as
                      a backstop because server accounting strings ("image
                      storage N bytes > limit M bytes") must never reach the
                      user (backlog #138, #143). */}
                  {entry.errorCode === 'storage-full'
                    ? t('upload.errorStorageFull')
                    : entry.errorCode === 'storage-full-kept'
                      ? t('upload.errorStorageFullKept')
                      : entry.error && /quota exceeded/i.test(entry.error)
                        ? t('upload.errorStorageFullKept')
                        : entry.error}
                </p>
              )}
            </div>
          ))}
        </div>

        {/* Footer - summary + close */}
        <div className="px-5 py-3 border-t border-divider">
          <div className="flex items-center justify-between gap-2">
            <span className="text-[12px] text-neutral-500 dark:text-neutral-400">
              {counts.done > 0 && t('upload.summaryDone', { count: counts.done })}
              {counts.done > 0 && (active > 0 || counts.failed > 0) && ', '}
              {active > 0 && t('upload.summaryUploading', { count: active })}
              {active > 0 && counts.failed > 0 && ', '}
              {counts.failed > 0 && t('upload.summaryFailed', { count: counts.failed })}
            </span>
            <button
              type="button"
              onClick={onClose}
              disabled={!allDone}
              className={`text-[13px] font-medium px-4 py-1.5 rounded-md transition ${
                allDone
                  ? 'bg-accent text-white hover:bg-accent-hover'
                  : 'bg-neutral-100 dark:bg-neutral-800 text-neutral-400 dark:text-neutral-600 cursor-not-allowed'
              }`}
            >
              {t('common:actions.done')}
            </button>
          </div>
          {/* Upsell - tier-aware, minimal inline. Free -> Pro (50 MB),
              Pro without a storage sub -> storage add-on (100 MB); at the
              ceiling (storage sub, or storage not sold) just show the limit. */}
          {/* proUnlocked, not isPro: the pitch names a 50 MB ceiling the
              demo already uploads at, so demo falls through to the storage
              tier below rather than claiming a limit it doesn't have. */}
          {!proUnlocked(isPro) ? (
            <div className="mt-2 flex items-center gap-2 rounded-md bg-accent/10 px-2.5 py-1.5">
              <span className="shrink-0"><IconUpgrade size={13} /></span>
              <span className="flex-1 text-[11.5px] text-neutral-600 dark:text-neutral-300 leading-tight">
                {t('upload.proPitch')}
              </span>
              <button type="button" onClick={onOpenUpgrade} className="shrink-0 text-[11.5px] font-medium text-accent hover:underline">
                {t('upload.proPitchCta')}
              </button>
            </div>
          ) : !hasStorageSub && isStorageConfigured() ? (
            <div className="mt-2 flex items-center gap-2 rounded-md bg-accent/10 px-2.5 py-1.5">
              <span className="shrink-0"><IconUpgrade size={13} /></span>
              <span className="flex-1 text-[11.5px] text-neutral-600 dark:text-neutral-300 leading-tight">
                {t('upload.storagePitch')}
              </span>
              <button type="button" onClick={onManageStorage} className="shrink-0 text-[11.5px] font-medium text-accent hover:underline">
                {t('upload.storagePitchCta')}
              </button>
            </div>
          ) : (
            <p className="text-[11px] text-neutral-400 dark:text-neutral-600 mt-2 leading-relaxed">
              {t('upload.typesHint', { limit: hasStorageSub ? '100' : '50' })}
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
