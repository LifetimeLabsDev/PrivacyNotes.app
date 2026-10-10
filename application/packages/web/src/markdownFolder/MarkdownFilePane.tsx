/**
 * The wide pane: one file's text, editable, saved straight back to disk.
 *
 * The two safety rules live in `save` and `scheduleSave` rather than in a
 * comment somewhere: nothing is written unless the user actually typed, and
 * nothing is written over a file that changed underneath us.
 *
 * Spec: ops/docs/plans/markdown-folder.md (section 7)
 */
import { useContext, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { MarkdownSourceEditor } from '../MarkdownSourceEditor';
import { WordCount } from '../WordCount';
import { Editor, type EditorHandle } from '../Editor';
import { FormatBarContext } from '../formatBarContext';
import { setWikiLinkNavigator } from '../NoteLink';
import { setWikiLinkNoteContext, setWikiLinkNoteTitles } from '../NoteLinkSuggestion';
import { setLocalLinkOpener } from '../editorLinks';
import { ArrowLeft, FileMd, FileTxt, Lock, MagnifyingGlass, Swap, Trash, X } from '../icons';
import { EditorSlotPill } from '../EditorSlotPill';
import { editorCommands } from '../editorCommands';
import { HoverLabel } from '../HoverLabel';
import { adaptFile, isTextFile, tidyRichSave } from './adapter';
import { stampsMatch } from './fileAccess';
import { applyAssets, restoreAssets, useAssets } from './useAssets';
import { isLocalHref, noteLinkPathFor, resolveNoteLinkPath, resolveRelativeLinkPath } from './links';
import type { OpenedMarkdownDir, OpenedMarkdownFile, SaveState } from './types';

/** Idle gap before an edit reaches the disk. Longer than the encrypted
 *  editor's 300ms on purpose: this folder is very likely watched by git,
 *  Dropbox or Obsidian, and a write per keystroke would have all three
 *  reindexing continuously. */
const SAVE_DEBOUNCE_MS = 900;
/** Source mode swaps nothing in, so it has nothing to put back. Shared rather
 *  than built per render so it cannot churn the editor's props. */
const EMPTY_ASSETS: Map<string, string> = new Map();
// The pillar is free, all of it, so the editor runs with every feature open:
// callouts, find and replace. Nothing here prices anything, and no upgrade
// pitch can open from this pane.
// Spec: ops/docs/pro-features.md (Markdown folder)
const SOURCE_SEARCH = { isPro: true };
// The find pill shows only on a file longer than the pane, with a line of
// slack so it does not blink while a line wraps. The notes pane's value.
// Spec: ops/docs/design-decisions.md (the editor corner holds only controls that can hide themselves)
const OVERFLOW_SLACK_PX = 40;

/** The reading column, the same one the encrypted editor uses. `NoteEditorPane`
 *  holds its own copy of this string and importing it from there would drag the
 *  encrypted note editor - and the store behind it - into this module, which the
 *  one-way boundary forbids. Both rows below reference this constant so the
 *  header and the body cannot drift apart.
 *  Spec: ops/docs/design-decisions.md (editor content column max-width) */

/**
 * A buffered edit and the file it was typed into, travelling together.
 *
 * The pairing is the whole point. The flush effect below runs during the render
 * that swaps files, AFTER React has repointed `openedRef` at the next file, so
 * anything that resolved its target at flush time would write one file's text
 * into another one - silently, because the editor is already showing the new
 * file's text and nothing on screen would change.
 */
type PendingWrite = { target: OpenedMarkdownFile; text: string };

export function MarkdownFilePane({
  opened,
  onUpdated,
  dir,
  onDelete,
  onImportToNotes,
  onClose,
  gridMode,
  onNotice,
}: {
  opened: OpenedMarkdownFile;
  onUpdated: (next: OpenedMarkdownFile) => void;
  /** The open folder, when there is one. Images resolve against it; a file
   *  opened on its own has no folder to look in and shows its links as text. */
  dir: OpenedMarkdownDir | null;
  onDelete: (() => void) | null;
  /**
   * Put the file down and go back to the list.
   *
   * Not optional, and not cosmetic: both surfaces that hide the list column
   * while this pane is up - grid mode below 1400px, and any mode below md -
   * leave the pane as the only thing on screen, so without this control there
   * is no way back to the files at all. Closing is safe mid-edit; the flush
   * effect writes the buffered edit on the way out.
   */
  onClose: () => void;
  /** Which control says "back": the grid's X, or the list's arrow. Mirrors
   *  `NoteEditorPane`'s pair so the two editors close the same way. */
  gridMode: boolean;
  /**
   * Copy this file into the encrypted notes. A callback rather than a direct
   * write, so nothing in this module can reach the encrypted store - the
   * boundary stays one-way by construction, not by care.
   */
  onImportToNotes: (filename: string, raw: string) => void;
  /** A short message for the app's toast: a link that leads nowhere. */
  onNotice: (message: string) => void;
}) {
  const { t } = useTranslation('shell');
  const [state, setState] = useState<SaveState>({ kind: 'idle' });
  /**
   * Rich (TipTap) or raw source, defaulting to what the extension implies:
   * markdown gets the real editor, `.txt` gets the textarea because it is not
   * markdown and a parse-serialize round trip would rewrite it.
   *
   * The toggle is not a convenience. Rich mode reaches disk through TipTap's
   * markdown serializer, so anything our parser does not model comes back
   * changed - Dataview blocks, Templater syntax, unusual footnotes. Source mode
   * is the escape hatch that touches nothing but what the user typed, and it is
   * the mode to reach for the moment a file looks reformatted.
   */
  const [mode, setMode] = useState<'rich' | 'source'>(opened.adapted.editorMode);
  // The format bar at the bottom gets a row under the scrolling column,
  // as in the note editor (see Editor's toolbarSlot).
  const barBelow = useContext(FormatBarContext).position === 'bottom' && mode === 'rich';
  const [barSlot, setBarSlot] = useState<HTMLDivElement | null>(null);
  /** Mirrors the editor's current text so the counter moves while typing,
   *  rather than only after a save lands. Same job as NotesView's `wcBody`. */
  // Seeded from the BODY: the rich editor shows exactly that, and counting a
  // file's front matter as prose was never meaningful. Source mode replaces it
  // with the whole file on the first keystroke, which is what that mode shows.
  const [liveBody, setLiveBody] = useState(opened.adapted.body);
  const timer = useRef<number | null>(null);
  const pending = useRef<PendingWrite | null>(null);
  // Relative image paths become loadable URLs on the way in, and are put back
  // verbatim on the way out - the file must keep saying what it said.
  const noteDir = opened.ref.location.includes('/')
    ? opened.ref.location.slice(0, opened.ref.location.lastIndexOf('/') + 1)
    : '';
  const assets = useAssets(opened.raw, dir?.ref ?? null, noteDir);
  // `opened` as of the last render, for the handlers that act on whatever file
  // is on screen right now - a paste, a drop, a reload. It is deliberately NOT
  // what a save writes through: React repoints this during the render that
  // swaps files, which happens BEFORE the flush effect's cleanup runs, so a
  // write that read it there would land in the wrong file. Saves carry their
  // own target instead (see `PendingWrite`).
  const openedRef = useRef(opened);
  openedRef.current = opened;
  const onUpdatedRef = useRef(onUpdated);
  onUpdatedRef.current = onUpdated;
  const editorRef = useRef<EditorHandle>(null);
  const contentRef = useRef<HTMLDivElement>(null);
  const scrollerRef = useRef<HTMLDivElement>(null);
  // The scroller for a pane resize, the content for the text growing. The
  // column is `min-h-full` under a header that scrolls with it, so its own
  // height overflows on every file; what counts is what its children need.
  const [bodyOverflows, setBodyOverflows] = useState(false);
  useEffect(() => {
    const node = scrollerRef.current;
    if (!node) return;
    const measure = () => {
      const col = contentRef.current;
      if (!col) return;
      const style = getComputedStyle(col);
      const needed = [...col.children].reduce((h, c) => h + (c as HTMLElement).offsetHeight, 0)
        + parseFloat(style.paddingTop) + parseFloat(style.paddingBottom);
      setBodyOverflows(node.scrollHeight - col.offsetHeight + needed - node.clientHeight > OVERFLOW_SLACK_PX);
    };
    const ro = new ResizeObserver(measure);
    ro.observe(node);
    if (contentRef.current) ro.observe(contentRef.current);
    measure();
    return () => ro.disconnect();
  }, []);
  /** Blob URLs of files just pasted, dropped or picked in rich mode, by the
   *  relative path the file is written under. The editor shows the blob until
   *  the save lands and `useAssets` resolves the path itself; until then this
   *  is what turns the blob back into the path on the way to disk. */
  const pastedAssets = useRef(new Map<string, string>());
  useEffect(() => {
    const urls = pastedAssets.current;
    return () => {
      for (const url of urls.values()) URL.revokeObjectURL(url);
      urls.clear();
    };
  }, [opened.ref.location]);

  // Links resolve inside this folder and nowhere else: a local file never
  // names an encrypted note, and an encrypted note never names a file.
  // Spec: ops/docs/plans/markdown-folder.md (section 3, note-links)
  const relPaths = useMemo(() => (dir?.entries ?? []).map((e) => e.relPath), [dir]);
  const linkTitles = useMemo(
    () => relPaths.map((rel) => ({ id: rel, title: noteLinkPathFor(rel) })),
    [relPaths],
  );

  /** Open another file of the folder in this pane. A pending edit to the
   *  file on screen still lands in it: the flush below names its own file. */
  async function openLinked(relPath: string) {
    const entry = dir?.entries.find((e) => e.relPath === relPath);
    if (!entry || entry.ref.location === openedRef.current.ref.location) return;
    try {
      const raw = await entry.ref.read();
      onUpdatedRef.current({ ref: entry.ref, raw, stamp: await entry.ref.stamp(), adapted: adaptFile(entry.ref.name, raw), reloadToken: 0 });
    } catch {
      onNotice(t('markdown.openFailed'));
    }
  }

  /** The file on screen as a path in the scan, or null for a lone file. */
  function currentRelPath(): string | null {
    const loc = openedRef.current.ref.location;
    return dir?.entries.some((e) => e.relPath === loc) ? loc : null;
  }

  /** A heading to scroll to once the linked file is on screen. */
  const pendingHeadingRef = useRef<{ relPath: string; heading: string } | null>(null);

  function scrollToHeading(heading: string) {
    editorRef.current?.scrollToHeading(heading, () => onNotice(t('editor:noteLink.headingNotFound')));
  }

  function followNoteLink(target: string) {
    // `[[bar#Part]]` opens bar at the heading Part; `[[#Part]]` is the
    // heading in the file on screen, which needs no folder.
    const hash = target.indexOf('#');
    const heading = hash >= 0 ? target.slice(hash + 1).trim() : '';
    if (hash >= 0 && !target.slice(0, hash).trim() && heading) {
      scrollToHeading(heading);
      return;
    }
    const from = currentRelPath();
    if (from === null) {
      onNotice(t('markdown.linkNeedsFolder'));
      return;
    }
    const hit = resolveNoteLinkPath(relPaths, target);
    if (!hit) {
      onNotice(t('markdown.linkNotFound', { target: target.split('#')[0]!.trim() }));
      return;
    }
    if (hit === from) {
      if (heading) scrollToHeading(heading);
      return;
    }
    pendingHeadingRef.current = heading ? { relPath: hit, heading } : null;
    void openLinked(hit);
  }

  function followRelativeLink(href: string): boolean {
    if (!isLocalHref(href)) return false;
    const from = currentRelPath();
    if (from === null) {
      onNotice(t('markdown.linkNeedsFolder'));
      return true;
    }
    const hit = resolveRelativeLinkPath(relPaths, from, href);
    if (hit) void openLinked(hit);
    else onNotice(t('markdown.linkNotFound', { target: href }));
    return true;
  }

  // Re-installed on every render, because the handlers close over the
  // current folder and file. The editor reads them at click time.
  useEffect(() => {
    const ed = editorRef.current?.getEditor() ?? null;
    setWikiLinkNavigator(ed, followNoteLink);
    setWikiLinkNoteTitles(ed, linkTitles);
    setLocalLinkOpener(ed, followRelativeLink);
    const rel = currentRelPath();
    setWikiLinkNoteContext(ed, rel === null ? null : { id: rel, title: noteLinkPathFor(rel) });
    const pending = pendingHeadingRef.current;
    if (ed && pending && pending.relPath === rel) {
      pendingHeadingRef.current = null;
      scrollToHeading(pending.heading);
    }
  });

  // A different file is a different save state, and a different default mode.
  // Without this, opening a second file from the list inherits the first one's
  // "Saved to disk" and its rich/source choice - which matters, because that
  // choice is `.txt`-versus-markdown safety, not a preference.
  useEffect(() => {
    setState({ kind: 'idle' });
    setMode(openedRef.current.adapted.editorMode);
    setLiveBody(openedRef.current.adapted.body);
  }, [opened.ref.location]);

  /**
   * Write one buffered edit back to the file it came from.
   *
   * Every step reads `target`, never the file currently on screen: this also
   * runs from the flush below, which fires while the pane is switching to a
   * different file.
   */
  async function save({ target, text }: PendingWrite) {
    // Whether the file being written is still the one the pane is showing.
    // The write itself is safe either way - the stamp check guards it - but
    // nothing may be REPORTED for a file the user has already left: the header
    // and `onUpdated` both describe what is on screen, so a late "Saved to
    // disk", or an `onUpdated` carrying file A's text, would overwrite the
    // pane's state for file B. Dropping the callback loses nothing, because
    // reopening a file always re-reads and re-stamps it from disk.
    const stillOpen = () => openedRef.current.ref.location === target.ref.location;
    try {
      // Rule 1, never clobber. Re-read the fingerprint immediately before
      // writing: anything could have touched the file since we opened it, and a
      // stamp we cannot read counts as changed (see `stampsMatch`).
      //
      // Checked BEFORE announcing 'saving' so a blocked write reads as one
      // steady "not saved" rather than flickering through a claim that a save
      // is in progress when none will happen.
      if (!stampsMatch(await target.ref.stamp(), target.stamp)) {
        if (stillOpen()) setState({ kind: 'stale' });
        return;
      }
      if (stillOpen()) setState({ kind: 'saving' });
      await target.ref.write(text);
      // `reloadToken` is deliberately carried over unchanged: the editor is
      // already showing this exact text, and remounting it here would drop the
      // caret mid-sentence on every save.
      const written = {
        ...target,
        raw: text,
        stamp: await target.ref.stamp(),
        adapted: adaptFile(target.ref.name, text),
      };
      if (!stillOpen()) return;
      onUpdatedRef.current(written);
      setState({ kind: 'saved' });
    } catch {
      if (stillOpen()) setState({ kind: 'error', message: t('markdown.saveFailed') });
    }
  }

  /**
   * Buffer one edit for the file it was typed into.
   *
   * `target` and `assetMap` are passed in by the caller from the RENDER CLOSURE,
   * and must never be re-derived from `openedRef` or the current `assets`. The
   * editor's own flush-on-unmount (`useFlushOnExitEffects`) fires this with the
   * outgoing file's markdown AFTER the render that switched to the next file,
   * so at that moment both refs already point at the wrong file. Reading them
   * here wrote file A's text into file B and destroyed it - silently, because
   * the pane was showing B's stale in-memory copy the whole time.
   *
   * The render closure is the correct source because the editors are keyed on
   * `opened.ref.location`: a file switch unmounts the old instance rather than
   * updating its props, so its handler is still the one built when its own file
   * was on screen.
   */
  function scheduleSave(
    shown: string,
    target: OpenedMarkdownFile,
    assetMap: Map<string, string>,
    /** True when `shown` is the BODY only, so the file's front matter has to
     *  go back on the front before this reaches disk. The rich editor is never
     *  shown the front-matter block; source mode is shown the whole file and
     *  must not have it prepended twice. */
    bodyOnly: boolean,
  ) {
    // Only the file on screen owns the live counters; a late flush from the
    // file we just left must not relabel them.
    const isCurrent = openedRef.current.ref.location === target.ref.location;
    if (isCurrent) setLiveBody(shown);
    // Undo the display-only swap FIRST, using the map built for THIS file. A
    // blob URL reaching disk would be a dead link the moment the tab closed,
    // having replaced a path that was correct in every other editor the user
    // owns - and the next file's map cannot resolve this file's references.
    const restored = restoreAssets(shown, assetMap);
    // Put the front matter back, from the bytes it arrived as. `target`, never
    // `openedRef`: this also runs from the outgoing editor's flush, when the
    // pane has already moved to a different file with different front matter.
    const text = bodyOnly ? target.adapted.frontMatterRaw + tidyRichSave(restored, target.adapted.body) : restored;
    // Rule 2 holds by construction: this only ever runs from an editor change
    // event, so a file that is merely opened and read is never written.
    //
    // Say "not saved" the instant a key lands, not when the debounce fires.
    // A stale file keeps its own warning: typing does not make it less stale,
    // and replacing that label would hide the reason the write is refused.
    if (isCurrent) setState((s) => (s.kind === 'stale' ? s : { kind: 'dirty' }));
    pending.current = { target, text };
    if (timer.current) window.clearTimeout(timer.current);
    // A flush arriving from the outgoing editor has no debounce left to wait
    // for - the pane is already on the next file and this cleanup is the last
    // moment the text exists. Write it now rather than parking it in a timer
    // the next switch would clear.
    if (!isCurrent) {
      timer.current = null;
      const next = pending.current;
      pending.current = null;
      if (next) void save(next);
      return;
    }
    timer.current = window.setTimeout(() => {
      timer.current = null;
      const next = pending.current;
      pending.current = null;
      if (next) void save(next);
    }, SAVE_DEBOUNCE_MS);
  }

  // Flush a pending edit when the file is closed or swapped. Without this the
  // last keystrokes before a close are silently dropped - the same class of bug
  // as #81 in the encrypted editor, and worse here because the user can see the
  // file did not change on disk. The buffered edit names its own file, so this
  // still lands in the file that was being edited even though it runs after the
  // render that moved on to the next one.
  useEffect(() => {
    return () => {
      if (timer.current) {
        window.clearTimeout(timer.current);
        timer.current = null;
        const next = pending.current;
        pending.current = null;
        if (next) void save(next);
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [opened.ref.location]);

  /**
   * A pasted or dropped file becomes a real file next to the note, referenced
   * by a relative path - which is what makes the folder portable. The encrypted
   * side's `pn:img/<uuid>` scheme is meaningless outside our app and must never
   * appear in somebody's vault.
   *
   * One body for both entry points on purpose: paste and drop reach the same
   * TipTap plugins and would otherwise be two chances to get this wrong.
   */
  async function attachFiles(files: File[], at?: { x: number; y: number }) {
    const dirRef = dir?.ref;
    // Nothing to write into: a lone file opened without a folder has nowhere to
    // put an attachment. The handlers have already blocked the event by the time
    // we get here, so the paste is refused rather than quietly encrypted.
    if (!dirRef || files.length === 0) return;
    const current = openedRef.current;
    const noteFolder = current.ref.location.includes('/')
      ? current.ref.location.slice(0, current.ref.location.lastIndexOf('/') + 1)
      : '';
    // Named from the note, so the folder stays legible to a human browsing it
    // in Finder rather than filling with opaque ids.
    const stem = current.adapted.title.replace(/[^\p{L}\p{N}_-]+/gu, '-').slice(0, 40) || 'image';
    // Seeded from the scan and added to as we go: files dropped together are
    // not in `entries` yet, and would otherwise all claim the same name.
    const taken = new Set((dir?.entries ?? []).map((x) => x.relPath));
    // The scan lists notes only, so an image already in `attachments/` is not
    // in `taken`: ask the folder too, or a second paste into the same note
    // overwrites the first picture under the same name.
    const isFree = async (path: string) => {
      if (taken.has(path)) return false;
      const url = await dirRef.resolveAsset(path).catch(() => null);
      if (url?.startsWith('blob:')) URL.revokeObjectURL(url);
      return url === null;
    };
    const refs: string[] = [];
    // The same references as the editor shows them: an image by a blob URL,
    // because the editor cannot load a path from the folder itself.
    const shown: string[] = [];
    try {
      for (const file of files) {
        const fromName = file.name.includes('.') ? file.name.slice(file.name.lastIndexOf('.') + 1) : '';
        const ext = (fromName || file.type.split('/')[1] || 'bin').replace('jpeg', 'jpg');
        let rel = `attachments/${stem}.${ext}`;
        for (let i = 2; !(await isFree(`${noteFolder}${rel}`)); i++) rel = `attachments/${stem}-${i}.${ext}`;
        taken.add(`${noteFolder}${rel}`);
        await dirRef.writeAsset(`${noteFolder}${rel}`, new Uint8Array(await file.arrayBuffer()));
        // An image embeds, anything else becomes a plain link - both are ordinary
        // markdown that any other editor resolves the same way we do.
        if (file.type.startsWith('image/')) {
          const url = URL.createObjectURL(file);
          pastedAssets.current.set(rel, url);
          refs.push(`![${stem}](${rel})`);
          shown.push(`![${stem}](${url})`);
        } else {
          refs.push(`[${file.name}](${rel})`);
          shown.push(`[${file.name}](${rel})`);
        }
      }
      // At the caret, or where the files were dropped, through the editor on
      // screen, so its own change event saves the file with every edit still
      // waiting in the debounce. Building the file from `raw` instead put the
      // files at the end and, in source mode, behind a textarea that never
      // showed them, so the next keystroke saved them away again.
      if (current.ref.location === openedRef.current.ref.location) {
        const ed = mode === 'rich' ? editorRef.current?.getEditor() : null;
        if (ed && !ed.isDestroyed) {
          const pos = at ? ed.view.posAtCoords({ left: at.x, top: at.y })?.pos : undefined;
          const chain = ed.chain().focus();
          if (pos !== undefined) chain.setTextSelection(pos);
          // On a line of its own, as the notes editor places a picture: a
          // line with text in it is split at the caret first.
          chain.command(({ state, commands }) => (state.selection.$from.parent.content.size > 0 ? commands.splitBlock() : true));
          chain.insertContent(shown.join('\n\n')).run();
          return;
        }
        const area = mode === 'source' ? contentRef.current?.querySelector<HTMLTextAreaElement>('textarea[data-pn-source]') : null;
        if (area) {
          // A blank line on each side, unless the caret already has one.
          const before = area.value.slice(0, area.selectionStart);
          const after = area.value.slice(area.selectionEnd);
          const lead = before === '' || before.endsWith('\n\n') ? '' : before.endsWith('\n') ? '\n' : '\n\n';
          const trail = after === '' || after.startsWith('\n\n') ? '' : after.startsWith('\n') ? '\n' : '\n\n';
          const text = lead + refs.join('\n\n') + trail;
          area.focus();
          if (!document.execCommand?.('insertText', false, text)) {
            area.setRangeText(text, area.selectionStart, area.selectionEnd, 'end');
            area.dispatchEvent(new Event('input', { bubbles: true }));
          }
          return;
        }
      }
      // No editor to take them (the file was switched away mid-write): one save
      // for the whole batch at the end of the file. A save per file would each
      // start from the same unchanged `raw` and only the last reference would
      // survive.
      //
      // `current` is the target because this text was built from ITS `raw`; a
      // paste is synchronous with the file on screen, so the two agree today,
      // but naming it keeps that true if this ever awaits across a switch. The
      // refs are already relative paths, so there is nothing to restore.
      // Built from `raw`, so it is already a whole file, front matter included:
      // `bodyOnly` is false or the block would be prepended a second time.
      scheduleSave(`${current.raw.replace(/\n*$/, '')}\n\n${refs.join('\n\n')}\n`, current, EMPTY_ASSETS, false);
    } catch {
      setState({ kind: 'error', message: t('markdown.saveFailed') });
    }
  }

  /**
   * CAPTURE phase, and both stopped BEFORE anything can fail or return early:
   * TipTap's own paste plugin listens on the inner contentEditable and would
   * otherwise see this first, encrypt the bytes into blob storage and insert a
   * `pn:img/` reference - meaningless in a folder that has to stay readable by
   * Obsidian and git. Blocking has to happen even when we cannot write the file,
   * because refusing a paste is recoverable and handing it to the encrypted
   * store is not.
   *
   * Only FILE payloads are taken. A plain text paste carries no files and is
   * left entirely alone, which is the overwhelmingly common case.
   */
  function handlePasteFile(e: React.ClipboardEvent) {
    const files = Array.from(e.clipboardData.files);
    if (files.length === 0) return;
    e.preventDefault();
    e.stopPropagation();
    void attachFiles(files);
  }

  /** The same interception for a drag from Finder or a browser. Without it a
   *  dropped image goes straight to the encrypted image plugin, which uploads
   *  it to blob storage and writes a `pn:img/` reference into the user's own
   *  file. Dragging text WITHIN the editor carries no files and falls through
   *  to ProseMirror untouched. */
  function handleDropFile(e: React.DragEvent) {
    const files = Array.from(e.dataTransfer.files);
    if (files.length === 0) return;
    e.preventDefault();
    e.stopPropagation();
    void attachFiles(files, { x: e.clientX, y: e.clientY });
  }

  async function reloadFromDisk() {
    const current = openedRef.current;
    try {
      const raw = await current.ref.read();
      // The one place the token moves: the text on screen is now wrong and the
      // editor has to be rebuilt from what is actually on disk.
      onUpdatedRef.current({
        ...current,
        raw,
        stamp: await current.ref.stamp(),
        adapted: adaptFile(current.ref.name, raw),
        reloadToken: current.reloadToken + 1,
      });
      setState({ kind: 'idle' });
    } catch {
      setState({ kind: 'error', message: t('markdown.openFailed') });
    }
  }

  return (
    <div className="flex-1 min-h-0 flex flex-col">
    <div ref={scrollerRef} className="flex-1 min-h-0 overflow-y-auto">
      {state.kind === 'stale' && (
        <div className="flex items-center gap-3 px-6 py-2 text-[12.5px] bg-amber-50 dark:bg-amber-950/40 text-amber-900 dark:text-amber-200 border-b border-amber-200 dark:border-amber-900">
          <span>{t('markdown.changedOnDisk')}</span>
          <button type="button" onClick={() => void reloadFromDisk()} className="underline underline-offset-2">
            {t('markdown.reload')}
          </button>
        </div>
      )}
      {/* Same header as the encrypted editor: fixed h-14 so its bottom border
          lines up with the sidebar brand row and the list header across all
          three columns, same content column, same responsive title type scale.
          The title is a span rather than that pane's textarea - a filename is
          renamed on disk, not typed over here - so it truncates instead of
          scroll-fading. The only addition is the open padlock, which is the
          whole point of this pillar.
          Spec: ops/docs/ui-patterns.md (editor header) */}
      <div className="flex justify-center min-h-11 sm:min-h-14 py-1.5 sm:py-0 sm:h-14 border-b border-divider shrink-0">
        <div className="flex items-center gap-2 px-4 sm:px-6 pn-content-col">
          {/* The way back, in the one slot every editor in this app puts it.
              Both variants are `NoteEditorPane`'s, class for class: below md the
              list column is `hidden`, and in grid mode the grid is hidden below
              1400px, so in both cases this pane is the whole window and the
              control is the only exit. */}
          {gridMode ? (
            <HoverLabel label={t('notes:editor.backToGrid')} position="below-start">
              <button
                type="button"
                onClick={onClose}
                aria-label={t('notes:editor.backToGrid')}
                className="rounded p-1.5 -ms-1 text-pn-muted hover:bg-pn/10 hover:text-accent transition shrink-0"
              >
                <X size={18} />
              </button>
            </HoverLabel>
          ) : (
            <button
              type="button"
              onClick={onClose}
              aria-label={t('notes:editor.backToList')}
              className="md:hidden rounded p-1.5 -ms-1 text-pn-muted hover:bg-pn/10 transition shrink-0"
            >
              <ArrowLeft size={18} />
            </button>
          )}
          <span
            className="flex-1 min-w-0 truncate text-base sm:text-xl lg:text-2xl font-semibold tracking-tight text-pn"
            title={opened.ref.location}
          >
            {opened.adapted.title}
          </span>
          <span className="shrink-0 text-[12px] text-pn-muted">{statusLabel(state, t)}</span>
          {/* The file's type, at the head of the action group rather than in
              front of the title: that slot belongs to the way back, which every
              other editor in the app puts there and which a reader looks for
              first. Extension, not editor mode - see `isTextFile`. */}
          {isTextFile(opened.ref.name)
            ? <FileTxt size={18} className="shrink-0 text-pn-muted" />
            : <FileMd size={18} className="shrink-0 text-pn-muted" />}
          {/* Find and replace has no "..." menu to live in here, so it sits in
              the header, for both modes. Cmd/Ctrl+F and Option+Cmd+F reach the
              same bars. */}
          <HoverLabel label={t('noteOptionsMenu.findReplace')} position="below">
            <button
              type="button"
              onClick={() => (mode === 'rich' ? editorRef.current?.toggleReplace() : editorCommands.findReplace?.())}
              aria-label={t('noteOptionsMenu.findReplace')}
              className="rounded-md p-2.5 text-pn-muted hover:text-accent hover:bg-accent/10 transition shrink-0"
            >
              <Swap size={20} />
            </button>
          </HoverLabel>
          <HoverLabel label={t('markdown.saveToNotes')} position="below">
            <button
              type="button"
              onClick={() => onImportToNotes(opened.ref.name, opened.raw)}
              aria-label={t('markdown.saveToNotes')}
              className="rounded-md p-2.5 text-accent hover:bg-accent/10 transition shrink-0"
            >
              <Lock size={20} />
            </button>
          </HoverLabel>
          {onDelete && (
            <HoverLabel label={t('markdown.delete')} position="below">
              <button
                type="button"
                onClick={onDelete}
                aria-label={t('markdown.delete')}
                className="rounded-md p-2.5 text-red-500 hover:text-red-600 hover:bg-red-500/10 dark:text-red-400 dark:hover:text-red-300 transition shrink-0"
              >
                <Trash size={20} />
              </button>
            </HoverLabel>
          )}
          {/* Segmented toggle AND the footer link below both drive `mode` -
              two affordances, one state. The footer link is the app's existing
              pattern and stays for consistency; this one is here because the
              choice matters more in a folder of foreign files than it does for
              a note, and having it in reach beats remembering it exists. */}
          <span className="shrink-0 inline-flex h-10 items-stretch rounded-md border border-divider overflow-hidden">
            {(['rich', 'source'] as const).map((m) => (
              <button
                key={m}
                type="button"
                onClick={() => setMode(m)}
                className={`px-2.5 text-[12px] transition ${mode === m ? 'bg-track text-pn' : 'text-pn-muted hover:text-pn'}`}
              >
                {m === 'rich' ? t('markdown.modeRich') : t('markdown.modeSource')}
              </button>
            ))}
          </span>
        </div>
      </div>
      {/* flex-col + min-h-full so the footer's `mt-auto` reaches the bottom of
          the pane on a short file, exactly as it does in the encrypted editor.
          The dragover default is prevented across the whole column, not just
          over the editor's contentEditable: without it a file dropped on the
          padding or the footer is handled by the browser, which navigates the
          webview to the dropped file and takes the pane with it. */}
      <div
        ref={contentRef}
        className="pn-content-col px-4 sm:px-6 py-4 flex flex-col min-h-full"
        onPasteCapture={handlePasteFile}
        onDragOverCapture={(e) => { if (e.dataTransfer.types.includes('Files')) e.preventDefault(); }}
        onDropCapture={handleDropFile}
      >
        {mode === 'rich' ? (
          <Editor
            ref={editorRef}
            key={`rich:${opened.ref.location}:${opened.reloadToken}:${assets.size}`}
            // The BODY, not the raw file. A front-matter block rendered as
            // body text comes out as a horizontal rule followed by a setext
            // heading - four lines of YAML in 24px bold at the top of every
            // Obsidian file. Every other editor hides it (Obsidian shows a
            // Properties panel, Typora a collapsed YAML box, iA Writer and
            // VS Code's preview drop it). It is HIDDEN, never stripped:
            // `scheduleSave` puts `frontMatterRaw` back on every write, and
            // source mode below still shows the whole file.
            value={applyAssets(opened.adapted.body, assets)}
            // `opened` and `assets` from THIS render, not from a ref - see
            // `scheduleSave`. The editor flushes on unmount, which happens after
            // the pane has already moved to the next file.
            // A file just pasted shows by its own blob URL until `assets`
            // resolves it, so that map is undone first; one merged map would
            // lose a URL whenever both name the same path.
            onChange={(text) => scheduleSave(restoreAssets(text, pastedAssets.current), opened, assets, true)}
            hideEncryptedMedia
            // The magnifier beside the outline pill, as on a note.
            bodyControls={bodyOverflows ? (
              <EditorSlotPill label={t('notes:editor.findInNote')} onClick={() => editorRef.current?.toggleFind()}>
                <MagnifyingGlass size={17} />
              </EditorSlotPill>
            ) : null}
            onInsertFiles={(files) => void attachFiles(files)}
            isPro
            toolbarSlot={barSlot}
          />
        ) : (
          // Source mode shows the file's real text, images included. Swapping
          // paths for blob URLs here would be showing the user something their
          // file does not say, which is the opposite of what source mode is for.
          <MarkdownSourceEditor
            key={`src:${opened.ref.location}:${opened.reloadToken}`}
            value={opened.raw}
            // Source mode never swapped anything in, so an empty map restores
            // nothing - the text is already exactly what the file says.
            onChange={(text) => scheduleSave(text, opened, EMPTY_ASSETS, false)}
            search={SOURCE_SEARCH}
          />
        )}
        {/* Same footer row as the encrypted editor: counts on the left, the
            mode link on the right, same two strings. It is the app's familiar
            mode control and stays exactly where a reader of notes expects it;
            the header's segmented control is the second affordance on the same
            `mode` state, for the reason given up there.
            Spec: ops/specs/editor-mode-toggle.md */}
        <div className="mt-auto pt-4 shrink-0 flex items-start justify-between gap-3">
          <WordCount body={liveBody} />
          <button
            type="button"
            onClick={() => setMode(mode === 'source' ? 'rich' : 'source')}
            className="shrink-0 select-none text-xs text-pn-muted hover:text-pn-soft hover:underline transition"
          >
            {/* The notes namespace, because this is the encrypted editor's own
                link and its wording must not fork from it. */}
            {mode === 'source' ? t('notes:editor.showFormatted') : t('notes:editor.showMarkdown')}
          </button>
        </div>
      </div>
    </div>
    {barBelow && (
      <div className="shrink-0 border-t border-divider bg-surface-2">
        <div ref={setBarSlot} className="pn-content-col" />
      </div>
    )}
    </div>
  );
}

function statusLabel(state: SaveState, t: (k: string) => string): string {
  if (state.kind === 'dirty') return t('markdown.unsaved');
  if (state.kind === 'saving') return t('markdown.saving');
  if (state.kind === 'saved') return t('markdown.savedToDisk');
  if (state.kind === 'error') return state.message;
  if (state.kind === 'stale') return t('markdown.notSaved');
  return '';
}
