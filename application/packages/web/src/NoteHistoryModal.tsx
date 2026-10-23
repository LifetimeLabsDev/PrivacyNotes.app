import { Suspense, useEffect, useState } from 'react';
import { lazyPart } from './chunkLoad';
import { useTranslation } from 'react-i18next';
import type { Editor as TipTapEditor } from '@tiptap/react';
import { Plugin, PluginKey } from '@tiptap/pm/state';
import type { DecorationSet } from '@tiptap/pm/view';
import type { NoteType, SupabaseClient } from '@notes/shared';
import type { LocalNote } from './db';
import { Modal } from './ui';
import { formatInstant } from './intlFormat';
import { listNoteVersions, type NoteVersion } from './noteVersions';
import { Editor } from './Editor';
import { getNote } from './notesRepo';
import { computeNoteDiff, type NoteDiff } from './noteDiff';
import { vaultContent, vaultToMarkdown } from './vaultFields';
import { linkDomain, linkExportMarkdown, parseLinkBody } from './linkBody';
import { trackerHeading, trackerRows } from './trackerExport';
import { trackerContent } from './editStamp';
import { loadLocalSettings } from './userSettings';

// Its own chunk: the vault rows pull in the vault forms and the detail
// rows, which the plain note preview never needs.
const VaultVersionPreview = lazyPart(() => import('./VaultVersionPreview').then((m) => m.VaultVersionPreview));

/**
 * Pro: browse + restore note versions.
 *
 * Versions are fetched and decrypted in a single round trip. The
 * user picks one from the list; the right pane previews the full
 * contents. Clicking Restore calls `onRestore` with the version; the
 * parent saves the current state as a version first and refuses to
 * restore when that save fails.
 *
 * A login, card, SSH key or contact previews as labelled rows, never as
 * its raw JSON body: a secret value stays out of the DOM until its row is
 * revealed. The first three have no comparison, since a word list of their
 * body would show what the rows hide.
 */
const VAULT_TYPES: ReadonlySet<NoteType> = new Set(['login', 'card', 'ssh-key']);
const ROW_TYPES: ReadonlySet<NoteType> = new Set([...VAULT_TYPES, 'contact']);

/** A body as a person reads it: a contact as its fields in markdown, a
 *  bookmark as its link, a journal entry with its tracker values under the
 *  text, as an export prints them, anything else as written. */
function readableBody(type: NoteType, body: string, trackers?: Record<string, unknown>): string {
  if (type === 'contact') {
    const content = vaultContent({ type, body });
    return content ? vaultToMarkdown(content) : body;
  }
  if (type === 'journal' && trackers) {
    const settings = loadLocalSettings();
    const rows = trackerRows(trackers, settings.trackerSettings, settings.trackerSettings.customTrackers, settings.factors);
    if (rows.length === 0) return body;
    // A custom tracker's name is user input: keep it literal.
    const esc = (s: string) => s.replace(/[\\`*_[\]<>#|~]/g, '\\$&');
    const list = rows.map((r) => `- ${esc(r.label)}: ${esc(r.value)}`).join('\n');
    return `${body.trimEnd()}\n\n**${esc(trackerHeading())}**\n\n${list}`;
  }
  return linkExportMarkdown({ type, body }) ?? body;
}

/** The name a version goes by: its title, or for an unnamed bookmark its
 *  domain, the name the list gives it. */
function versionName(type: NoteType, v: NoteVersion): string {
  return v.title.trim() || (type === 'link' ? linkDomain(parseLinkBody(v.body).url) : '');
}

const DIFF_KEY = new PluginKey('pnHistoryDiff');

function showDiff(editor: TipTapEditor, set: DecorationSet) {
  editor.unregisterPlugin(DIFF_KEY);
  editor.registerPlugin(new Plugin({ key: DIFF_KEY, props: { decorations: () => set } }));
}

const noop = () => {
  /* readOnly - never fires */
};

type Props = {
  noteId: string;
  /** The live note's type: a snapshot does not record it. */
  noteType: NoteType;
  supabase: SupabaseClient;
  encryptionKey: Uint8Array;
  onClose: () => void;
  /** Apply the selected version's content to the live note. */
  onRestore: (v: NoteVersion) => Promise<void> | void;
};

export function NoteHistoryModal({
  noteId,
  noteType,
  supabase,
  encryptionKey,
  onClose,
  onRestore,
}: Props) {
  const { t } = useTranslation('billing');
  const [versions, setVersions] = useState<NoteVersion[] | null>(null);
  // A read that failed, kept apart from an empty history: listNoteVersions
  // throws on failure, and the panel says so in the reader's language
  // instead of showing either the error text or "No history yet".
  const [loadFailed, setLoadFailed] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const canCompare = !VAULT_TYPES.has(noteType);
  // On by default where the two sides fit next to each other (the lg width
  // the layout below switches at); a narrow screen opens on the preview.
  const [compare, setCompare] = useState(() => window.matchMedia?.('(min-width: 1024px)').matches ?? false);
  // The note as it is saved now, which is what Restore replaces.
  const [current, setCurrent] = useState<LocalNote | null>(null);
  // On a narrow screen one side shows at a time.
  const [side, setSide] = useState<'older' | 'current'>('current');
  const [olderEditor, setOlderEditor] = useState<TipTapEditor | null>(null);
  const [currentEditor, setCurrentEditor] = useState<TipTapEditor | null>(null);
  // undefined while it is computed, null when the note is too long.
  const [diff, setDiff] = useState<NoteDiff | null | undefined>(undefined);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const list = await listNoteVersions(supabase, encryptionKey, noteId);
        if (cancelled) return;
        setVersions(list);
        setSelectedId(list[0]?.id ?? null);
      } catch {
        if (cancelled) return;
        setLoadFailed(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [noteId, supabase, encryptionKey]);

  useEffect(() => {
    if (!compare || current) return;
    let cancelled = false;
    void getNote(noteId).then((n) => {
      if (!cancelled && n) setCurrent(n);
    });
    return () => {
      cancelled = true;
    };
  }, [compare, current, noteId]);

  useEffect(() => {
    if (!compare || !olderEditor || !currentEditor || olderEditor.isDestroyed || currentEditor.isDestroyed) return;
    const result = computeNoteDiff(olderEditor.state.doc, currentEditor.state.doc, t('history.formatChanged'));
    setDiff(result);
    if (!result) return;
    showDiff(olderEditor, result.older);
    showDiff(currentEditor, result.current);
    return () => {
      for (const ed of [olderEditor, currentEditor]) if (!ed.isDestroyed) ed.unregisterPlugin(DIFF_KEY);
    };
  }, [compare, olderEditor, currentEditor, t]);

  const selected = versions?.find((v) => v.id === selectedId) ?? null;
  const comparing = compare && canCompare && !!selected && !!current;
  const titleChanged = comparing && selected.title.trim() !== current.title.trim();
  const tagsChanged = comparing && [...selected.tags].sort().join('\n') !== [...current.tags].sort().join('\n');

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
    <Modal
      onClose={onClose}
      title={t('shell:noteOptionsMenu.noteHistory')}
      subtitle={t('history.subtitle')}
      header="bar"
      className={`max-w-3xl h-[90vh] sm:h-[80vh] flex flex-col overflow-hidden${compare && canCompare ? ' lg:max-w-6xl' : ''}`}
    >
        <div className="flex flex-col sm:flex-row flex-1 min-h-0">
          {/* Left pane: version list.
              The phone cap is set so the list ends PART WAY through a row:
              a row is about 82px, and 208px shows two of them plus half of
              the third, which is what tells a reader the list scrolls. A cap
              that lands on a row boundary reads as the whole history, and a
              160px cap did exactly that - it cut the second row by 3px and
              people reported a two-version limit. 208 sits as far from a
              boundary as the arithmetic allows, so the cut survives the row
              growing or shrinking with the script a locale is written in. */}
          <div className="max-h-52 sm:max-h-none sm:w-56 shrink-0 border-b sm:border-b-0 sm:border-e border-divider overflow-y-auto">
            {versions === null && !err && !loadFailed && (
              <div className="p-4 text-[13px] text-pn-muted">{t('common:state.loading')}</div>
            )}
            {loadFailed && (
              <div className="p-4 text-[13px] text-danger">{t('history.loadFailed')}</div>
            )}
            {err && (
              <div className="p-4 text-[13px] text-danger">{err}</div>
            )}
            {versions && versions.length === 0 && (
              <div className="p-4 text-[13px] text-pn-muted leading-relaxed">
                {t('history.empty')}
              </div>
            )}
            <ul>
              {versions?.map((v) => (
                <li key={v.id}>
                  <button
                    type="button"
                    onClick={() => {
                      if (v.id === selectedId) return;
                      setSelectedId(v.id);
                      setDiff(undefined);
                    }}
                    className={`w-full text-start px-4 py-3 border-b border-divider/50 transition ${
                      selectedId === v.id
                        ? 'bg-accent/10 border-s-2 border-s-accent dark:bg-accent/15'
                        : 'hover:bg-surface-1/60'
                    }`}
                  >
                    <div className="text-[13px] font-medium tabular-nums">
                      {formatInstant(v.createdAt, 'dateTime')}
                    </div>
                    <div className="text-[11px] text-pn-muted mt-0.5 truncate">
                      {versionName(noteType, v) || t('common:state.untitled')}
                    </div>
                    <div className="text-[11px] text-pn-muted tabular-nums mt-0.5">
                      {formatBytes(v.bodyBytes)}
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          </div>

          {/* Right pane: preview.
              min-h-0 as well as min-w-0, because the parent above stacks
              this pane on a phone and lays it beside the list only from
              sm up. A flex item defaults to min-height:auto and so refuses
              to shrink under its own content: without this the pane grows
              past the modal, the modal clips it, and the scroller below
              never gets a bounded height to scroll inside. */}
          <div className="flex-1 min-w-0 min-h-0 flex flex-col">
            {selected ? (
              <>
                <div className="px-4 sm:px-6 py-3 sm:py-4 border-b border-divider shrink-0">
                  <div className="flex items-start justify-between gap-3">
                    <div className="text-sm text-pn-muted">
                      {formatInstant(selected.createdAt, 'dateTime')}
                    </div>
                    {canCompare && (
                      <button
                        type="button"
                        aria-pressed={compare}
                        onClick={() => {
                          setCompare(!compare);
                          setDiff(undefined);
                        }}
                        className={`shrink-0 rounded-md border px-2.5 py-1 text-[12px] transition ${
                          compare ? 'border-accent bg-accent/10 text-pn' : 'border-divider hover:bg-pn/5 text-pn-soft'
                        }`}
                      >
                        {t('history.compare')}
                      </button>
                    )}
                  </div>
                  <h3 className="text-base sm:text-lg font-semibold truncate mt-0.5">
                    {versionName(noteType, selected) || t('common:state.untitled')}
                  </h3>
                  {selected.tags.length > 0 && (
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {selected.tags.map((t) => (
                        <span
                          key={t}
                          dir="auto"
                          className="text-[11px] px-1.5 py-0.5 rounded bg-pn/10 text-pn-soft"
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
                {comparing ? (
                  <>
                    <div className="px-4 sm:px-6 py-2 border-b border-divider shrink-0 flex flex-wrap items-center gap-x-3 gap-y-1.5 text-[12px]">
                      <div role="group" className="lg:hidden inline-flex rounded-md border border-divider overflow-hidden">
                        {(['older', 'current'] as const).map((s) => (
                          <button
                            key={s}
                            type="button"
                            aria-pressed={side === s}
                            onClick={() => setSide(s)}
                            className={`px-2.5 py-1 transition ${side === s ? 'bg-accent/10 text-pn' : 'text-pn-soft hover:bg-pn/5'}`}
                          >
                            {s === 'older' ? t('history.thisVersion') : t('history.currentNote')}
                          </button>
                        ))}
                      </div>
                      <span role="status" className="text-pn-muted">
                        {diff === null
                          ? t('history.tooLong')
                          : diff === undefined
                            ? ''
                            : diff.changes === 0
                              ? t('history.noChanges')
                              : t('history.changeCount', { count: diff.changes })}
                      </span>
                      {titleChanged && <span className="rounded bg-pn/10 px-1.5 py-0.5 text-pn-soft">{t('history.titleChanged')}</span>}
                      {tagsChanged && <span className="rounded bg-pn/10 px-1.5 py-0.5 text-pn-soft">{t('history.tagsChanged')}</span>}
                      {noteType === 'journal' && selected.trackers === undefined && <span className="text-pn-muted">{t('history.trackersNotRecorded')}</span>}
                      <span className="ms-auto inline-flex flex-wrap gap-x-3 gap-y-1 text-pn-muted">
                        <span><del className="pn-diff-del">{t('history.onlyInVersion')}</del></span>
                        <span><ins className="pn-diff-ins">{t('history.onlyInCurrent')}</ins></span>
                      </span>
                    </div>
                    <div className="flex-1 min-h-0 flex">
                      <section
                        aria-label={t('history.thisVersion')}
                        className={`${side === 'older' ? 'flex' : 'hidden'} lg:flex flex-col flex-1 min-w-0 lg:border-e border-divider`}
                      >
                        <div className="hidden lg:block px-6 pt-3 text-[12px] font-medium text-pn-muted">
                          {t('history.thisVersion')}
                        </div>
                        <div className="flex-1 overflow-y-auto px-4 sm:px-6 py-4">
                          <Editor key={selected.id} value={readableBody(noteType, selected.body, selected.trackers)} onChange={noop} readOnly preview onReady={setOlderEditor} />
                        </div>
                      </section>
                      <section
                        aria-label={t('history.currentNote')}
                        className={`${side === 'current' ? 'flex' : 'hidden'} lg:flex flex-col flex-1 min-w-0`}
                      >
                        <div className="hidden lg:block px-6 pt-3 text-[12px] font-medium text-pn-muted">
                          {t('history.currentNote')}
                        </div>
                        <div className="flex-1 overflow-y-auto px-4 sm:px-6 py-4">
                          <Editor key="current" value={readableBody(noteType, current.body, selected.trackers && trackerContent(current.trackers))} onChange={noop} readOnly preview onReady={setCurrentEditor} />
                        </div>
                      </section>
                    </div>
                  </>
                ) : (
                <div className="flex-1 overflow-y-auto px-4 sm:px-6 py-4">
                  {ROW_TYPES.has(noteType) ? (
                    <Suspense fallback={null}>
                      <VaultVersionPreview key={selected.id} version={selected} type={noteType} />
                    </Suspense>
                  ) : readableBody(noteType, selected.body, selected.trackers).trim() ? (
                    <Editor key={selected.id} value={readableBody(noteType, selected.body, selected.trackers)} onChange={noop} readOnly preview />
                  ) : (
                    <div className="text-pn-muted italic">{t('history.emptyBody')}</div>
                  )}
                  {noteType === 'journal' && selected.trackers === undefined && (
                    <p className="mt-3 text-[12px] text-pn-muted">{t('history.trackersNotRecorded')}</p>
                  )}
                </div>
                )}
                <div className="px-4 sm:px-6 py-3 border-t border-divider flex items-center justify-end gap-2 shrink-0">
                  <button
                    onClick={onClose}
                    className="rounded-md border border-divider hover:bg-pn/5 px-3 py-2 text-sm transition"
                  >
                    {t('common:actions.cancel')}
                  </button>
                  <button
                    onClick={() => void handleRestore()}
                    disabled={busy}
                    className="rounded-md bg-accent-fill text-white hover:bg-accent-fill-hover disabled:opacity-50 px-3 py-2 text-sm font-medium transition whitespace-nowrap"
                  >
                    {busy ? t('history.restoring') : t('history.restore')}
                  </button>
                </div>
              </>
            ) : (
              <div className="flex-1 flex items-center justify-center text-[13px] text-pn-muted">
                {t('history.selectPrompt')}
              </div>
            )}
          </div>
        </div>
    </Modal>
  );
}

import { formatBytes } from './formatBytes';
