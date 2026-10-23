/**
 * The web clipper inside the app: Save as note on a bookmark, and the Clip
 * page window of the + menu. It holds the running clips (one per bookmark),
 * finds the note each bookmark was clipped into, and writes the bookmark and
 * the note through the ordinary note path.
 * Spec: ops/docs/archive/web-clipper-stage1.md (section 5)
 */
import { useCallback, useMemo, useState } from 'react';
import type { SupabaseClient } from '@notes/shared';
import i18n from '../i18n';
import type { LocalNote } from '../db';
import { buildClipNoteMap, clipTrackers } from '../clipLink';
import { buildLinkBody, buildLinkKeyMap, linkDedupeKey, parseLinkBody } from '../linkBody';
import { createNote, updateNote } from '../notesRepo';
import type { ClipErrorReason } from '../clipDownload';
import type { ClipDraft, SavedClip } from '../clipPage';
import { clipLabels, noticeFor, readClipPictures, resultText, type ClipJob, type ClipNotice } from '../clipMessages';

export type { ClipJob, ClipNotice } from '../clipMessages';

export function useClipper({
  supabase,
  notes,
  refresh,
  runSync,
  folderForNew,
  flashToast,
  revealNote,
}: {
  supabase: SupabaseClient;
  /** Every note that is not deleted, trashed ones included. */
  notes: readonly LocalNote[];
  refresh: () => Promise<unknown>;
  runSync: () => Promise<void>;
  /** The folder a new item goes into: the open space's, or none. */
  folderForNew: () => string | null;
  flashToast: (message: string) => void;
  revealNote: (note: LocalNote) => void;
}) {
  const [jobs, setJobs] = useState<Record<string, ClipJob>>({});
  const [notices, setNotices] = useState<Record<string, ClipNotice>>({});
  const [windowOpen, setWindowOpen] = useState(false);
  // The address the window opens with: the quick add's "Clip a page" hands
  // over the link it was given, every other door opens it empty.
  const [windowUrl, setWindowUrl] = useState('');

  const clipNotes = useMemo(() => buildClipNoteMap(notes), [notes]);
  const clipNoteFor = useCallback(
    (bookmark: LocalNote): LocalNote | undefined => {
      const { url } = parseLinkBody(bookmark.body);
      return url ? clipNotes.get(linkDedupeKey(url)) : undefined;
    },
    [clipNotes],
  );

  /** The note an address was clipped into, when there is one. */
  const clipNoteForUrl = useCallback(
    (url: string): LocalNote | undefined => clipNotes.get(linkDedupeKey(url)),
    [clipNotes],
  );

  const token = useCallback(async () => (await supabase.auth.getSession()).data.session?.access_token ?? null, [supabase]);

  /** The bookmark for `url`, made when none is saved, as New Bookmark makes one. */
  const ensureBookmark = useCallback(async (url: string): Promise<void> => {
    const keys = buildLinkKeyMap(notes.filter((n) => n.trashed !== 1));
    if (keys.has(linkDedupeKey(url))) return;
    await createNote('', buildLinkBody(url), [], false, 'link', folderForNew());
  }, [notes, folderForNew]);

  /** Write the clipped note for the bookmark at `url`, then say how it went. */
  const writeNote = useCallback(async (url: string, saved: SavedClip): Promise<LocalNote> => {
    const note = await createNote(saved.title, saved.body, [], false, 'note', folderForNew());
    await updateNote(note.id, { trackers: clipTrackers(url) }, undefined, { edit: false });
    await refresh();
    void runSync();
    flashToast(resultText(saved));
    return note;
  }, [folderForNew, refresh, runSync, flashToast]);

  const setJob = (id: string, job: ClipJob | null) =>
    setJobs((all) => {
      const next = { ...all };
      if (job) next[id] = job;
      else delete next[id];
      return next;
    });

  /** Save as note on a bookmark: the main text, with its pictures unless
   *  the person switched them off. The bookmark is the fallback: when the
   *  page cannot be clipped, it stays as it is and its pane says why. */
  const saveBookmarkAsNote = useCallback(async (bookmark: LocalNote) => {
    const { url } = parseLinkBody(bookmark.body);
    if (!url || jobs[bookmark.id]) return;
    setNotices((all) => {
      const next = { ...all };
      delete next[bookmark.id];
      return next;
    });
    setJob(bookmark.id, { step: 'page', done: 0, total: 0 });
    try {
      const clip = await import('../clipPage');
      const source = await clip.downloadPage(url, token);
      const found = await clip.clipOf(source, 'main');
      if (!found || !(await clip.clipFitsNote(found))) {
        const notice = { text: i18n.t(found ? 'shell:clipper.tooLong' : 'shell:clipper.noMainText') };
        setNotices((all) => ({ ...all, [bookmark.id]: notice }));
        flashToast(notice.text);
        return;
      }
      const progress = (done: number, total: number) => setJob(bookmark.id, { step: 'pictures', done, total });
      const draft: ClipDraft = await clip.downloadPictures(found, source, token, progress, readClipPictures());
      const saved = await clip.finishClip(draft, clipLabels(), progress);
      await writeNote(url, saved);
      // No window asked first: the pane says what the window would have.
      const { isShortText } = await import('@notes/clipper');
      if (isShortText(found.markdown)) {
        setNotices((all) => ({ ...all, [bookmark.id]: { text: i18n.t('shell:clipper.shortTextSaved') } }));
      }
    } catch (err) {
      const reason = (err as { reason?: ClipErrorReason }).reason ?? 'failed';
      const notice = noticeFor(reason);
      setNotices((all) => ({ ...all, [bookmark.id]: notice }));
      // The menu path has no pane open to show the line, so it is said here too.
      flashToast(notice.text);
    } finally {
      setJob(bookmark.id, null);
    }
  }, [jobs, token, writeNote, flashToast]);

  /** The window saved a clip: its bookmark first, so the pair is linked. */
  const saveFromWindow = useCallback(async (url: string, saved: SavedClip): Promise<void> => {
    await ensureBookmark(url);
    const note = await writeNote(url, saved);
    revealNote(note);
  }, [ensureBookmark, writeNote, revealNote]);

  /** The page could not be clipped: the bookmark is kept as the fallback. */
  const keepBookmark = useCallback(async (url: string): Promise<void> => {
    await ensureBookmark(url);
    await refresh();
    void runSync();
  }, [ensureBookmark, refresh, runSync]);

  return {
    jobs,
    notices,
    clipNoteFor,
    clipNoteForUrl,
    saveBookmarkAsNote,
    windowOpen,
    windowUrl,
    openClipWindow: (url = '') => {
      setWindowUrl(url);
      setWindowOpen(true);
    },
    closeClipWindow: () => setWindowOpen(false),
    saveFromWindow,
    keepBookmark,
    token,
  };
}
