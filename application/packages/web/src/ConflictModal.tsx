import { useState } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import { ArrowsClockwise, CaretRight } from './icons';
import { formatInstant } from './intlFormat';
import { firstBodyLine } from './notesViewUtils';
import { Modal } from './ui';
import type { NoteConflict } from './sync';

type Props = {
  conflict: NoteConflict;
  onResolve: (resolution: 'local' | 'server' | 'both') => void;
  onClose: () => void;
};

export function ConflictModal({ conflict, onResolve, onClose }: Props) {
  const { t } = useTranslation('settings');
  const [showLocal, setShowLocal] = useState(false);

  // The body falls back through the same strip the notes list uses. A raw
  // slice printed the markdown and HTML of the first line at the user, which
  // is the one place it must not: this row is how they choose a version.
  const preview = (title: string, body: string) =>
    title.trim() || firstBodyLine(body).slice(0, 80) || t('common:state.untitled');
  const serverPreview = preview(conflict.serverTitle, conflict.serverBody);
  const localPreview = preview(conflict.localNote.title, conflict.localNote.body);

  const localDate = formatInstant(conflict.localNote.updatedAt, 'dateTime');
  const serverDate = formatInstant(conflict.serverUpdatedAt, 'dateTime');

  return (
    <Modal onClose={onClose} title={t('conflict.title')} icon={<ArrowsClockwise size={16} />} className="max-w-md p-6 space-y-4">

        {/* Explanation */}
        <p className="text-sm text-pn-muted leading-relaxed">
          <Trans
            i18nKey="settings:conflict.explanation"
            values={{ date: serverDate }}
            components={{ em: <span className="font-medium text-pn" /> }}
          />
        </p>

        {/* Newer version card (will be kept) */}
        <div className="rounded-md border border-indigo-300 dark:border-indigo-800 bg-indigo-50 dark:bg-indigo-950/40 p-3 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-indigo-600 dark:text-indigo-400">{t('conflict.willBeKept')}</span>
            <span className="text-xs text-pn-muted">{serverDate}</span>
          </div>
          <p className="text-pn truncate text-sm">{serverPreview}</p>
        </div>

        {/* Expandable local version */}
        <button
          onClick={() => setShowLocal(!showLocal)}
          className="text-sm text-pn-muted hover:text-pn transition flex items-center gap-1"
        >
          <CaretRight className={`transition-transform ${showLocal ? 'rotate-90' : ''}`} />
          {t('conflict.showLocal', { date: localDate })}
        </button>
        {showLocal && (
          <div className="rounded-md border border-divider p-3 space-y-1">
            <p className="text-pn truncate text-sm">{localPreview}</p>
          </div>
        )}

        {/* Actions */}
        <div className="space-y-2 pt-2">
          <div className="flex gap-2">
            <button
              onClick={() => { onResolve('server'); onClose(); }}
              className="flex-[2] rounded-md bg-accent-fill text-white hover:bg-accent-fill-hover px-4 py-2 text-sm font-medium transition"
            >
              {t('conflict.useNewer')}
            </button>
            <button
              onClick={() => { onResolve('local'); onClose(); }}
              className="flex-1 rounded-md border border-divider hover:bg-pn/5 px-4 py-2 text-sm transition"
            >
              {t('conflict.useMine')}
            </button>
          </div>
          <button
            onClick={() => { onResolve('both'); onClose(); }}
            className="w-full text-sm text-pn-muted hover:text-pn transition py-1"
          >
            {t('conflict.keepBoth')}
          </button>
        </div>
    </Modal>
  );
}
