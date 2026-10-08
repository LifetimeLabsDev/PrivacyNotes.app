import { useTranslation } from 'react-i18next';
import { ConfirmModal } from './ConfirmModal';
import { formatFileSize } from './attachmentValidation';
import { iconBookmark, iconFile, iconNote } from './icons';
import type { SharedItem } from './useShareInbox';

/**
 * The question the Android app asks before it saves what other apps shared
 * into it. Any installed app can send a share with no step by the person, so
 * nothing is saved until they choose: Save all, Discard, or neither (the
 * window closed), which leaves the items for the next time the app opens.
 * Spec: ops/docs/plans/share-into-app.md
 */
/** Text from another app, with the direction controls that could make it
 *  show something other than what it holds taken out. */
function stripBidiControls(text: string | undefined): string {
  return (text ?? '').replace(/[\u202A-\u202E\u2066-\u2069\u200E\u200F]/g, '');
}

export function ShareApprovalModal({ items, onChoice }: {
  items: SharedItem[];
  onChoice: (choice: 'save' | 'discard' | 'later') => void;
}) {
  const { t } = useTranslation('importExport');
  return (
    <ConfirmModal
      title={t('shareSheet.title', { count: items.length })}
      confirmLabel={t('shareSheet.saveAll')}
      variant="info"
      cancelLabel={t('upload.discard')}
      onConfirm={() => onChoice('save')}
      onCancel={() => onChoice('discard')}
      onClose={() => onChoice('later')}
    >
      <p className="text-[13px] text-pn-muted mb-2">{t('shareSheet.line')}</p>
      <ul className="max-h-60 overflow-y-auto divide-y divide-divider border-y border-divider">
        {items.map((item) => (
          <li key={item.id} className="flex items-center gap-2 py-1.5 text-[13px] text-pn min-w-0">
            <span className="shrink-0 text-pn-muted" aria-hidden="true">
              {item.kind === 'url' ? iconBookmark() : item.kind === 'file' ? iconFile() : iconNote()}
            </span>
            <span className="truncate flex-1" dir="auto">
              {stripBidiControls(item.kind === 'url' ? item.url : item.kind === 'file' ? item.name : item.text)}
            </span>
            {item.kind === 'file' && item.size !== undefined && (
              <span className="shrink-0 text-[12px] text-pn-muted tabular-nums">{formatFileSize(item.size)}</span>
            )}
          </li>
        ))}
      </ul>
    </ConfirmModal>
  );
}
