import { useEffect, useState, type Dispatch, type MutableRefObject, type SetStateAction } from 'react';
import type { TFunction } from 'i18next';
import { createNote, updateNote } from '../notesRepo';
import { parseMarkdownFile } from '../import/markdown';
import type { LocalNote } from '../db';
import type { View } from '../views';
import type { OpenedMarkdownFile, OpenedMarkdownDir } from '../markdownFolder/types';
import { useTagIndex } from '../markdownFolder/useTagIndex';
import { usePendingFileOpens } from '../markdownFolder/usePendingFileOpens';
import { useFolderRestore } from '../markdownFolder/useFolderRestore';
import { useFolderRefresh } from '../markdownFolder/useFolderRefresh';

/**
 * The Markdown pillar's state and actions: the open folder and file, the rail
 * filters, saving files into the encrypted notes, and moving files to the
 * folder's `.trash/`. The panes themselves stay static imports of NotesView,
 * for the reason the comment on those imports gives.
 * Spec: ops/docs/archive/markdown-folder.md
 */
export function useMarkdownPillar({
  view,
  setView,
  notes,
  setNotes,
  setSelectedId,
  t,
  flashToast,
  spaceFolderForNew,
  fileFocusRef,
  notesListCollapsed,
  setSidebarCollapsed,
  setNotesListCollapsed,
}: {
  view: View;
  setView: Dispatch<SetStateAction<View>>;
  notes: LocalNote[];
  setNotes: Dispatch<SetStateAction<LocalNote[]>>;
  setSelectedId: Dispatch<SetStateAction<string | null>>;
  t: TFunction;
  flashToast: (message: string) => void;
  /** The folder a new item lands in, so a saved file follows the open space. */
  spaceFolderForNew: () => string | null;
  fileFocusRef: MutableRefObject<boolean | null>;
  notesListCollapsed: boolean;
  setSidebarCollapsed: Dispatch<SetStateAction<boolean>>;
  setNotesListCollapsed: Dispatch<SetStateAction<boolean>>;
}) {
  /** The Markdown pillar's open file. Lives here rather than inside the pane
   *  because both columns need it: the list column shows its name and tags, the
   *  editor column shows its contents. Session-only and never persisted - it is
   *  a handle on a file the user picked, not app data. */
  const [markdownFile, setMarkdownFile] = useState<OpenedMarkdownFile | null>(null);
  /** The Markdown pillar's open folder and its scanned entries. Session-only
   *  and never persisted: on the web these are handles the browser will not let
   *  us re-acquire without another user gesture, so remembering them across a
   *  reload would promise something we cannot deliver. */
  const [markdownDir, setMarkdownDir] = useState<OpenedMarkdownDir | null>(null);
  /** Rail filters for the Markdown pillar. Both narrow the same list; neither
   *  touches note state, so they live here purely because the rail and the list
   *  are rendered from two different places in this shell. */
  const [markdownDirFilter, setMarkdownDirFilter] = useState<string | null>(null);
  const [markdownTagFilter, setMarkdownTagFilter] = useState<string | null>(null);
  /** The filter the Markdown pane opens with, set by the All list's Markdown
   *  entry and read once when the pane mounts. */
  const [markdownFilterSeed, setMarkdownFilterSeed] = useState('');
  useEffect(() => {
    if (view !== 'markdown') setMarkdownFilterSeed('');
  }, [view]);
  /** The Markdown reference card, opened by the `?` on the folder row. Was also
   *  a first-run gate in front of the picker until 2026-08-14; that mode went
   *  when the empty state started carrying the same pitch.
   *  Spec: ops/docs/archive/markdown-folder.md (section 12) */
  const [markdownExplain, setMarkdownExplain] = useState(false);
  const [markdownDelete, setMarkdownDelete] = useState<OpenedMarkdownFile | null>(null);
  const [markdownDeleteMany, setMarkdownDeleteMany] = useState<string[] | null>(null);

  /**
   * Bodies already sitting in the encrypted notes, for "have I saved this file
   * before?".
   *
   * The file's whole raw text IS the note body - `handleImportMarkdown` passes
   * `raw` straight through - so an exact body match is a precise answer to that
   * question rather than a heuristic. Two notes with byte-identical bodies are
   * the same note by any definition a user would recognise.
   *
   * Matching on content and not on the source path is a deliberate choice, not a
   * shortcut. A path would need a new field on `LocalNote`, which is a synced
   * shape, so every note in every account would start carrying a filesystem path
   * from whichever machine touched it last - a sync-protocol change and a pile of
   * local path metadata crossing between devices, to answer a question the
   * content already answers.
   *
   * Trashed notes deliberately do not count: someone who threw the note away and
   * saves again means it.
   */
  function savedNoteBodies(): Set<string> {
    const bodies = new Set<string>();
    for (const n of notes) {
      if (n.trashed === 0 && n.type === 'note') bodies.add(n.body);
    }
    return bodies;
  }

  /** Copy a plaintext file into the encrypted notes. One-way on purpose: the
   *  original file is left exactly where it is, so nobody loses a copy they
   *  still rely on in another editor.
   *  Spec: ops/docs/archive/markdown-folder.md (section 10) */
  async function handleImportMarkdown(filename: string, raw: string) {
    // Converted the way a DROPPED .md is converted: front matter becomes the
    // title, the tags and the trackers, and the body arrives without it. It
    // used to be the raw file text, so the same file became two different
    // notes depending on whether it was dropped on the app or saved from the
    // folder view - and the saved one showed its YAML as a heading.
    const parsed = parseMarkdownFile(filename, raw);
    // Saving the same unchanged file twice used to make a second note, every
    // time, with nothing on screen to say the first one existed. Open the one
    // that is already there instead, which is what the second click was for.
    //
    // Matched against BOTH shapes: a note saved before the conversion above
    // holds the file's raw text, so comparing only the converted body would
    // read every one of them as new and duplicate it on the next click.
    const already = notes.find(
      (n) => n.trashed === 0 && (n.body === parsed.body || n.body === raw),
    );
    if (already) {
      setView('all');
      setSelectedId(already.id);
      flashToast(t('shell:markdown.alreadySavedToast', { title: parsed.title }));
      return;
    }
    const created = await createNote(
      parsed.title,
      parsed.body,
      parsed.tags,
      false,
      parsed.type ?? 'note',
      spaceFolderForNew(),
      { counted: false },
    );
    // Trackers have no `createNote` parameter, and a journal file that lost
    // them would look identical and silently be a different note.
    if (parsed.trackers) await updateNote(created.id, { trackers: parsed.trackers });
    setNotes((prev) => [created, ...prev]);
    setView('all');
    setSelectedId(created.id);
    flashToast(t('shell:markdown.importedToast', { title: parsed.title }));
  }

  /** Copy several plaintext files into the encrypted notes at once. Reads run
   *  in sequence rather than in parallel: each one is a note write plus a state
   *  update, and a burst of them starves the editor for no gain. */
  async function handleImportMarkdownMany(paths: string[]) {
    if (!markdownDir) return;
    const byPath = new Map(markdownDir.entries.map((e) => [e.relPath, e.ref]));
    // Seeded from what is already saved and then added to as we go, so the skip
    // covers both "saved on an earlier run" and two identical files inside THIS
    // selection. `notes` cannot do the second job on its own: `setNotes` has not
    // applied yet by the time the next file is read.
    const seen = savedNoteBodies();
    // Once for the batch: a second call would not yet see a folder the first
    // one made.
    const folderId = spaceFolderForNew();
    let done = 0;
    let skipped = 0;
    for (const path of paths) {
      const ref = byPath.get(path);
      if (!ref) continue;
      try {
        const raw = await ref.read();
        // Same conversion and the same both-shapes check as the single save
        // above, for the same two reasons.
        const parsed = parseMarkdownFile(ref.name, raw);
        if (seen.has(parsed.body) || seen.has(raw)) { skipped++; continue; }
        seen.add(parsed.body);
        const created = await createNote(
          parsed.title,
          parsed.body,
          parsed.tags,
          false,
          parsed.type ?? 'note',
          folderId,
          { counted: false },
        );
        if (parsed.trackers) await updateNote(created.id, { trackers: parsed.trackers });
        setNotes((prev) => [created, ...prev]);
        done++;
      } catch { /* one unreadable file must not abort the rest */ }
    }
    // Bulk gets a count, never a prompt: a modal per already-saved file in a
    // fifty-file selection is worse than the duplicates were.
    flashToast(
      skipped > 0
        ? t('shell:markdown.importedManySkippedToast', { saved: done, skipped })
        : t('shell:markdown.importedManyToast', { count: done }),
    );
  }

  /** Move several files to `.trash/`, then rescan once at the end. */
  async function handleMarkdownDeleteMany(paths: string[]) {
    setMarkdownDeleteMany(null);
    if (!markdownDir) return;
    // One unwritable file must not abort the rest, but it must not pass in
    // silence either: the rescan below simply leaves that row in place, which
    // on its own reads as the delete never having been asked for.
    let failed = 0;
    for (const path of paths) {
      try { await markdownDir.ref.trashFile(path); } catch { failed++; }
    }
    setMarkdownFile(null);
    setMarkdownDir({ ref: markdownDir.ref, entries: await markdownDir.ref.scan() });
    if (failed > 0) flashToast(t('shell:markdown.deleteFailed'));
  }

  /** Move a plaintext file to `.trash/` inside the user's own folder - never an
   *  unlink, so a regretted delete is recoverable in their file manager. */
  async function handleMarkdownDelete(file: OpenedMarkdownFile) {
    setMarkdownDelete(null);
    if (!markdownDir) return;
    try {
      await markdownDir.ref.trashFile(file.ref.location);
      setMarkdownFile(null);
      setMarkdownDir({ ref: markdownDir.ref, entries: await markdownDir.ref.scan() });
    } catch {
      flashToast(t('shell:markdown.deleteFailed'));
    }
  }
  // Tags live inside files, so they need a read of every one - a background
  // pass, deliberately not part of the scan, so the list is usable immediately.
  const markdownTags = useTagIndex(markdownDir?.entries ?? null);
  // Restored at app start rather than when the pillar is first opened, so the
  // sidebar's file count is there on launch instead of only after a visit.
  const markdownRestore = useFolderRestore(markdownDir, setMarkdownDir);
  // Nothing watches the folder, so this is what notices a file added or removed
  // by Obsidian, git or Finder while the app was in the background. Straight to
  // `setMarkdownDir` and not through the list's `onDir`, which also clears the
  // rail filters: the user did not change folder, and having their subfolder
  // selection dropped by a background refresh would be its own bug.
  useFolderRefresh(markdownDir, setMarkdownDir);
  // A double-click in Finder or Explorer lands here, once auth and the app lock
  // are behind us. Switching the view is part of honouring it: opening a file
  // into a pillar the user cannot see would look like nothing happened.
  usePendingFileOpens(
    (file, launched) => {
      setMarkdownFile(file);
      setView('markdown');
      // Started by the file: the window takes the file window size too. An app
      // that was already open keeps its size; only the panes fold.
      if (launched) void import('../markdownFolder/fileWindow').then((m) => m.enterFileWindow());
      // A file opened from the file manager gets the window to itself, the way
      // a Markdown editor opens one: the sidebar and the list fold away. The
      // list's saved state is kept aside and comes back when the reader leaves
      // the Markdown view; the expand handles bring either one back sooner.
      if (fileFocusRef.current === null) fileFocusRef.current = notesListCollapsed;
      setSidebarCollapsed(true);
      setNotesListCollapsed(true);
    },
    // The window came forward because the user double-clicked something. Saying
    // nothing at that point is indistinguishable from the app ignoring them.
    () => flashToast(t('shell:markdown.openFailed')),
  );

  return {
    markdownFile, setMarkdownFile,
    markdownDir, setMarkdownDir,
    markdownDirFilter, setMarkdownDirFilter,
    markdownTagFilter, setMarkdownTagFilter,
    markdownFilterSeed, setMarkdownFilterSeed,
    markdownExplain, setMarkdownExplain,
    markdownDelete, setMarkdownDelete,
    markdownDeleteMany, setMarkdownDeleteMany,
    handleImportMarkdown, handleImportMarkdownMany,
    handleMarkdownDelete, handleMarkdownDeleteMany,
    markdownTags, markdownRestore,
  };
}
