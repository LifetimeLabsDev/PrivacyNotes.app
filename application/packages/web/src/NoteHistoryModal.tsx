import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { SupabaseClient } from '@notes/shared';
import { useEscapeToClose } from './useEscapeToClose';
import { X } from './icons';
import { intlLocale } from './languages';
import { listNoteVersions, type NoteVersion } from './noteVersions';
import { Editor } from './Editor';

/**
 * Pro: browse + restore note versions.
 *
 * Versions are fetched and decrypted in a single round trip. The
 * user picks one from the list; the right pane previews the full
 * contents. Clicking Restore calls `onRestore` with the version's
 * title/body/tags - the parent writes them back to the live note,
 * which triggers a new version snapshot from the scheduled
 * debouncer. So restoring never loses the current state.
 */
type Props = {
  noteId: string;
  supabase: SupabaseClient;
  encryptionKey: Uint8Array;
  onClose: () => void;
  /** Apply the selected version's content to the live note. */
  onRestore: (v: NoteVersion) => Promise<void> | void;
};

export function NoteHistoryModal({
  noteId,
  supabase,
  encryptionKey,
  onClose,
  onRestore,
}: Props) {
  const { t } = useTranslation('billing');
  useEscapeToClose(onClose);
  const [versions, setVersions] = useState<NoteVersion[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const list = await listNoteVersions(supabase, encryptionKey, noteId);
        if (cancelled) return;
        setVersions(list);
        setSelectedId(list[0]?.id ?? null);
      } catch (e) {
        if (cancelled) return;
        setErr((e as Error).message);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [noteId, supabase, encryptionKey]);

  const selected = versions?.find((v) => v.id === selectedId) ?? null;

  async function handleRestore() {
    if (!selected || busy) return;
    setBusy(true);
    try {
      await onRestore(selected);
      onClose();
    } catch (e) {
      setErr((e as Error).message);
      setBusy(false);
    }
  }

  return (
    <div
      className="fixed inset-0 bg-black/50 dark:bg-black/70 flex items-center justify-center p-4 sm:p-6 z-50"
      onClick={onClose}
    >
      <div
        className="bg-surface-2 border border-divider text-pn rounded-lg w-full max-w-3xl h-[90vh] sm:h-[80vh] flex flex-col overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-4 sm:px-6 py-3 sm:py-4 border-b border-divider shrink-0">
          <div>
            <h2 className="text-lg font-semibold">{t('history.title')}</h2>
            <p className="text-[12px] text-neutral-500 mt-0.5">
              {t('history.subtitle')}
            </p>
          </div>
          <button
            onClick={onClose}
            aria-label={t('common:actions.close')}
            className="text-neutral-400 hover:text-neutral-600 dark:hover:text-neutral-300 transition p-1 -m-1"
          >
            <X size={18} />
          </button>
        </div>

        <div className="flex flex-col sm:flex-row flex-1 min-h-0">
          {/* Left pane: version list */}
          <div className="max-h-40 sm:max-h-none sm:w-56 shrink-0 border-b sm:border-b-0 sm:border-e border-divider overflow-y-auto">
            {versions === null && !err && (
              <div className="p-4 text-[13px] text-neutral-500">{t('common:state.loading')}</div>
            )}
            {err && (
              <div className="p-4 text-[13px] text-red-500">{err}</div>
            )}
            {versions && versions.length === 0 && (
              <div className="p-4 text-[13px] text-neutral-500 leading-relaxed">
                {t('history.empty')}
              </div>
            )}
            <ul>
              {versions?.map((v) => (
                <li key={v.id}>
                  <button
                    type="button"
                    onClick={() => setSelectedId(v.id)}
                    className={`w-full text-start px-4 py-3 border-b border-divider/50 transition ${
                      selectedId === v.id
                        ? 'bg-accent/10 border-s-2 border-s-accent dark:bg-accent/15'
                        : 'hover:bg-surface-1/60'
                    }`}
                  >
                    <div className="text-[13px] font-medium tabular-nums">
                      {formatTime(v.createdAt)}
                    </div>
                    <div className="text-[11px] text-neutral-500 mt-0.5 truncate">
                      {v.title.trim() || t('common:state.untitled')}
                    </div>
                    <div className="text-[11px] text-neutral-400 dark:text-neutral-600 tabular-nums mt-0.5">
                      {formatBytes(v.bodyBytes)}
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          </div>

          {/* Right pane: preview */}
          <div className="flex-1 min-w-0 flex flex-col">
            {selected ? (
              <>
                <div className="px-4 sm:px-6 py-3 sm:py-4 border-b border-divider shrink-0">
                  <div className="text-sm text-neutral-500">
                    {formatTime(selected.createdAt)}
                  </div>
                  <h3 className="text-base sm:text-lg font-semibold truncate mt-0.5">
                    {selected.title.trim() || t('common:state.untitled')}
                  </h3>
                  {selected.tags.length > 0 && (
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {selected.tags.map((t) => (
                        <span
                          key={t}
                          dir="auto"
                          className="text-[11px] px-1.5 py-0.5 rounded bg-neutral-200 text-neutral-600 dark:bg-neutral-800 dark:text-neutral-400"
                        >
                          #{t}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
                {/* Render with the same TipTap instance the live editor
                    uses - extensions, prose classes, task-list glyphs,
                    everything. Read-only guards every interactive path
                    inside Editor. `key` forces a remount on version
                    switch so TipTap re-parses the new markdown body
                    cleanly instead of trying to diff it. */}
                <div className="flex-1 overflow-y-auto px-4 sm:px-6 py-4">
                  {selected.body.trim() ? (
                    <Editor
                      key={selected.id}
                      value={selected.body}
                      onChange={() => {
                        /* readOnly - never fires */
                      }}
                      readOnly
                    />
                  ) : (
                    <div className="text-neutral-400 italic">{t('history.emptyBody')}</div>
                  )}
                </div>
                <div className="px-4 sm:px-6 py-3 border-t border-divider flex items-center justify-end gap-2 shrink-0">
                  <button
                    onClick={onClose}
                    className="rounded-md border border-neutral-300 hover:bg-neutral-100 dark:border-neutral-800 dark:hover:bg-neutral-900 px-3 py-2 text-sm transition"
                  >
                    {t('common:actions.cancel')}
                  </button>
                  <button
                    onClick={() => void handleRestore()}
                    disabled={busy}
                    className="rounded-md bg-accent text-white hover:bg-accent-hover disabled:opacity-50 px-3 py-2 text-sm font-medium transition whitespace-nowrap"
                  >
                    {busy ? t('history.restoring') : t('history.restore')}
                  </button>
                </div>
              </>
            ) : (
              <div className="flex-1 flex items-center justify-center text-[13px] text-neutral-500">
                {t('history.selectPrompt')}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function formatTime(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleString(intlLocale(), {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return iso;
  }
}

import { formatBytes } from './formatBytes';
