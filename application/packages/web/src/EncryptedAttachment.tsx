/**
 * Custom TipTap extension for encrypted file attachments.
 *
 * Renders as a one-line chip: [preview tile] filename, type and size
 * [actions]. A chip that holds a picture or a PDF shows it in the tile, and a
 * click on the tile opens the shared viewer. In a note the Files pillar made
 * that holds one file, a picture or a PDF renders as a card with the file
 * itself on it instead (the `filePreview` option, `showsFileCard`). Files are
 * encrypted client-side and stored in the same Supabase Storage bucket as
 * images.
 *
 * URI scheme: pn:file/<uuid> in markdown link syntax:
 *   [filename](pn:file/<uuid>)
 *
 * Markdown roundtrip is handled by custom serialize/parse hooks.
 */

import { lazy, Suspense, useState, useCallback, useRef, useEffect } from 'react';
import { estimateBlobBytes, mimeToLabel } from './notesViewUtils';
import { useTranslation } from 'react-i18next';
import { saveBlob } from './saveFile';
import { Node, mergeAttributes, type Editor as TipTapEditor } from '@tiptap/core';
import { ReactNodeViewRenderer, NodeViewWrapper } from '@tiptap/react';
import { Plugin, PluginKey } from '@tiptap/pm/state';
import type { EditorView } from '@tiptap/pm/view';
import type { Node as ProseMirrorNode } from '@tiptap/pm/model';
import { AttachmentStore, type AttachmentMeta, type DecryptedAttachment } from './attachmentStore';
import { validateAttachment, isImageFile, formatFileSize } from './attachmentValidation';
import { currentImageOptions, isSupportedImage, processImage } from './imageProcessing';
import { isPdf, isPictureMime, openMediaViewerInDoc } from './mediaRefs';
import { HoverLabel } from './HoverLabel';
import { ContextMenu, useContextMenu, type ContextMenuItem } from './ContextMenu';
import { suppressSoftKeyboard } from './softKeyboard';
import { useNearScreen } from './useNearScreen';
import { useBlobQuotaBlocked } from './usePendingUploads';
import { MusicNotes, VideoCamera, Image, Archive, File as FileGlyph, Pause, Play, Trash, Check, Download, DotsThree, Eye, X, iconCopy, iconEditPencil, iconTrash } from './icons';
import { formatDuration } from './formatDuration';
import {
  FILE_NAME_MAX_LENGTH,
  cleanFileName,
  escapeMarkdownText,
  joinFileName,
  splitFileName,
} from './fileNames';
import i18n from './i18n';
import { isImeComposing } from './imeComposing';

// ------------------------------------------------------------------
// Constants
// ------------------------------------------------------------------

const FILE_URI_PREFIX = 'pn:file/';

/** The narrowest the chip menu draws (ContextMenu's floor), so a menu opened
 *  from the chip's end lines its end edge up with the button. */
const MENU_MIN_WIDTH_PX = 160;

// The glyph inside a chip button takes no pointer events, so a press on it
// lands on the button itself. The editor ignores a press on a button and
// handles one on anything else, so a press on a bare glyph would also select
// the chip under the button's own action.
const BUTTON_CONTENT = '[&>*]:pointer-events-none';

// ------------------------------------------------------------------
// Rename requests from outside the editor
// ------------------------------------------------------------------

type RenameListener = (uuid: string) => void;
const renameListeners = new Set<RenameListener>();

/**
 * The most recent request, kept for a moment after it is made. A chip's node
 * view mounts asynchronously, so a request that arrives with the note - which
 * is how the Files pillar sends one - reaches no listener at all. The chip
 * claims it on mount instead.
 */
let pendingRename: { uuid: string; at: number } | null = null;

/** How long a request waits for its chip to appear. */
// Spec: ops/docs/plans/file-rename-and-audio-seek.md (where the control lives)
const RENAME_REQUEST_TTL_MS = 4000;

/**
 * Ask the chip holding `uuid` to open its rename field.
 *
 * The Files pillar's Rename row opens the parent note and then calls this,
 * so the name is only ever written by the chip inside the live editor. A
 * list that rewrote the note body itself would lose the race against a
 * debounced edit still pending in that editor.
 */
export function requestAttachmentRename(uuid: string) {
  pendingRename = { uuid, at: Date.now() };
  for (const listener of renameListeners) listener(uuid);
}

function subscribeToRenameRequests(listener: RenameListener): () => void {
  renameListeners.add(listener);
  return () => { renameListeners.delete(listener); };
}

/** True once, for the chip a live request was aimed at. */
function claimPendingRename(uuid: string | null): boolean {
  if (!uuid || !pendingRename || pendingRename.uuid !== uuid) return false;
  if (Date.now() - pendingRename.at > RENAME_REQUEST_TTL_MS) {
    pendingRename = null;
    return false;
  }
  pendingRename = null;
  return true;
}

/** Extract UUIDs of all pn:file/ references in a markdown body. */
export function extractAttachmentIds(body: string): Set<string> {
  const ids = new Set<string>();
  const re = /pn:file\/([0-9a-f-]{36})/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(body)) !== null) {
    ids.add(match[1]!);
  }
  return ids;
}

// ------------------------------------------------------------------
// File type icon helper
// ------------------------------------------------------------------

/** SVG icon for file type - replaces emoji for a cleaner look. */
function FileTypeIcon({ mime, size = 18 }: { mime: string; size?: number }) {
  // Audio
  if (mime.startsWith('audio/')) {
    return <MusicNotes size={size} />;
  }
  // Video
  if (mime.startsWith('video/')) {
    return <VideoCamera size={size} />;
  }
  // Image
  if (mime.startsWith('image/')) {
    return <Image size={size} />;
  }
  // Archive
  if (mime === 'application/zip' || mime.includes('compressed') || mime.includes('archive')) {
    return <Archive size={size} />;
  }
  // Default: generic file
  return <FileGlyph size={size} />;
}

// ------------------------------------------------------------------
// The file card's preview
// ------------------------------------------------------------------

/** Answered once per document: every chip in a note asks after each edit,
 *  and a document is never changed in place. */
const oneFileDocs = new WeakMap<ProseMirrorNode, boolean>();

/**
 * Whether a document holds exactly one file chip. A picture placed from Files
 * is a picture node, not a chip, so it is not one of the note's files.
 */
export function holdsOneFile(doc: ProseMirrorNode): boolean {
  let one = oneFileDocs.get(doc);
  if (one === undefined) {
    let chips = 0;
    doc.descendants((node) => {
      if (node.type.name === 'attachment') chips += 1;
      // A chip is a block, so the inside of a paragraph never holds one.
      return !node.isTextblock;
    });
    one = chips === 1;
    oneFileDocs.set(doc, one);
  }
  return one;
}

/**
 * Whether a note's picture or PDF draws as the file card: only in a note the
 * Files pillar made, and only while that note holds one file. A note of
 * several files reads as a list, and a card per file would make it a gallery.
 * Spec: ops/docs/ui-patterns.md (section 107, the file card)
 */
export function showsFileCard(fileNote: boolean, doc: ProseMirrorNode): boolean {
  return fileNote && holdsOneFile(doc);
}

// pdf.js is fetched the first time a PDF card or the viewer needs it, never
// on the way to the first render.
const PdfCover = lazy(() => import('./PdfPages').then((m) => ({ default: m.PdfCover })));

/**
 * The file itself, on the card a Files upload opens as: a picture at its
 * stored size, never scaled up, or a PDF's first page with its page count.
 * The whole area opens the viewer, which is where the arrows and the pages
 * are; the card previews, it does not read.
 *
 * Spans rather than divs throughout, because this is the content of a button.
 */
function FilePreview({ uuid, pdf, name, onOpen }: {
  uuid: string;
  pdf: boolean;
  name: string;
  onOpen: () => void;
}) {
  const { t } = useTranslation('media');
  const [url, setUrl] = useState<string | null>(() => (pdf ? null : cachedAttachmentUrl(uuid)));
  const [missing, setMissing] = useState(false);

  useEffect(() => {
    if (pdf || url) return;
    let alive = true;
    void loadAttachmentUrl(uuid).then((loaded) => {
      if (!alive) return;
      if (loaded) setUrl(loaded);
      else setMissing(true);
    });
    return () => { alive = false; };
  }, [uuid, pdf, url]);

  return (
    <button
      type="button"
      onMouseDown={(e) => { e.preventDefault(); e.stopPropagation(); }}
      onClick={(e) => { e.stopPropagation(); onOpen(); }}
      aria-label={t('attachment.view')}
      className={`block w-full bg-surface-1 cursor-zoom-in outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent ${BUTTON_CONTENT}`}
    >
      {pdf ? (
        <Suspense fallback={<span className="block py-16" />}>
          <PdfCover uuid={uuid} name={name} />
        </Suspense>
      ) : url ? (
        <span className="flex justify-center p-3">
          <img
            src={url}
            alt={name}
            draggable={false}
            className="block max-w-full max-h-[60vh] !my-0 rounded-md"
          />
        </span>
      ) : (
        <span className="block px-4 py-16 text-sm text-center text-neutral-400 dark:text-neutral-500">
          {missing ? t('image.notFound') : t('image.loading')}
        </span>
      )}
    </button>
  );
}

// ------------------------------------------------------------------
// Action buttons
// ------------------------------------------------------------------

/** Icon-only, no border, hover background. The last one in a chip takes
 *  `tip="above-end"`, because the chip's end can be the screen's edge. */
function ActionButton({ onClick, label, disabled, tip = 'above', children }: {
  onClick: (e: React.MouseEvent<HTMLButtonElement>) => void;
  label: string;
  disabled?: boolean;
  tip?: 'above' | 'above-end';
  children: React.ReactNode;
}) {
  return (
    <HoverLabel label={label} position={tip}>
    <button
      type="button"
      onMouseDown={(e) => { e.preventDefault(); e.stopPropagation(); }}
      onClick={(e) => { e.stopPropagation(); onClick(e); }}
      disabled={disabled}
      aria-label={label}
      className={`shrink-0 w-[30px] h-[30px] rounded-md flex items-center justify-center transition cursor-pointer select-none text-neutral-400 dark:text-neutral-500 hover:text-accent hover:bg-neutral-100 dark:hover:bg-neutral-800 ${BUTTON_CONTENT} ${
        disabled ? 'opacity-50 pointer-events-none' : ''
      }`}
    >
      {children}
    </button>
    </HoverLabel>
  );
}

/**
 * The chip's one labelled action: View for what the viewer shows, Download
 * for every other file. A label reads as the thing to press where a row of
 * grey glyphs does not.
 */
function LabelledAction({ onClick, disabled, children }: {
  onClick: () => void;
  disabled?: boolean;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onMouseDown={(e) => { e.preventDefault(); e.stopPropagation(); }}
      onClick={(e) => { e.stopPropagation(); onClick(); }}
      disabled={disabled}
      className={`shrink-0 inline-flex items-center gap-1.5 h-[30px] px-2.5 me-1 rounded-lg bg-accent/10 dark:bg-accent/20 text-accent text-xs font-medium transition cursor-pointer select-none hover:bg-accent/15 dark:hover:bg-accent/30 ${BUTTON_CONTENT} ${
        disabled ? 'opacity-50 pointer-events-none' : ''
      }`}
    >
      {children}
    </button>
  );
}

// ------------------------------------------------------------------
// Audio length
// ------------------------------------------------------------------

/**
 * The playable length of a loaded audio element, in seconds, or 0 when the
 * browser will not say.
 *
 * A recording made in the app carries no length in its header, because
 * MediaRecorder writes MP4 and OGG as it goes and never returns to fill the
 * field in, so `duration` reads Infinity. Seeking far past the end makes the
 * browser scan to the real end and report it through `durationchange`; the
 * position is put back before anything plays. A file that still will not
 * answer gets 0, which leaves the slider disabled and the total hidden - an
 * elapsed-only readout is honest, a slider that cannot know where it is is
 * not.
 */
function resolveDuration(audio: HTMLAudioElement): Promise<number> {
  if (Number.isFinite(audio.duration) && audio.duration > 0) {
    return Promise.resolve(audio.duration);
  }
  return new Promise<number>((resolve) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const finish = () => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      audio.removeEventListener('durationchange', onDurationChange);
      try { audio.currentTime = 0; } catch { /* not seekable */ }
      resolve(Number.isFinite(audio.duration) && audio.duration > 0 ? audio.duration : 0);
    };
    const onDurationChange = () => {
      if (Number.isFinite(audio.duration)) finish();
    };
    audio.addEventListener('durationchange', onDurationChange);
    timer = setTimeout(finish, 1500);
    try {
      audio.currentTime = 1e101;
    } catch {
      finish();
    }
  });
}

// ------------------------------------------------------------------
// React NodeView - renders attachment chip with download
// ------------------------------------------------------------------

type AttachmentNodeViewProps = {
  node: { attrs: { src: string; filename: string; filesize: string; mimetype: string } };
  selected: boolean;
  deleteNode: () => void;
  updateAttributes: (attrs: Record<string, unknown>) => void;
  editor: TipTapEditor;
  /** Document position of this chip, or undefined once the node is gone. */
  getPos: () => number | undefined;
  extension: { options: AttachmentOptions };
};

function EncryptedAttachmentView({
  node,
  selected,
  deleteNode,
  updateAttributes,
  editor,
  getPos,
  extension,
}: AttachmentNodeViewProps) {
  const { t } = useTranslation('media');
  const { src, filename, filesize, mimetype } = node.attrs;
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // The blob is referenced by the note but absent from the server: it
  // never uploaded from its origin device (usually a full vault there).
  // Rendered as an amber explanation, not a red error (backlog #151).
  const [missingRemote, setMissingRemote] = useState(false);
  const [copied, setCopied] = useState(false);
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [playing, setPlaying] = useState(false);
  /**
   * Whether this note can be edited, tracked rather than read once.
   * `readOnly` toggles WITHOUT remounting the editor - it is keyed by note
   * id - and `editor.isEditable` is a plain getter, so a chip that read it
   * at render time went on offering Rename and Delete on a locked note.
   * Neither would have saved: the debounced write refuses a read-only note,
   * so the buttons removed a chip on screen and lost the change on the next
   * load. `setEditable` emits an update, which is what this listens for.
   */
  const [editable, setEditable] = useState(editor.isEditable);
  useEffect(() => {
    const sync = () => setEditable(editor.isEditable);
    sync();
    editor.on('update', sync);
    return () => { editor.off('update', sync); };
  }, [editor]);
  const [renaming, setRenaming] = useState(false);
  const [renameValue, setRenameValue] = useState('');
  // Playback position and length, both in seconds. `duration` stays 0 until
  // a real length is known, which is what disables the slider - see
  // resolveDuration for why a recording does not report one at first.
  const [position, setPosition] = useState(0);
  const [duration, setDuration] = useState(0);
  const [formatUnsupported, setFormatUnsupported] = useState(false);
  const [thumbnailUrl, setThumbnailUrl] = useState<string | null>(null);
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const audioUrlRef = useRef<string | null>(null);
  const deleteTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const uuid = src?.startsWith(FILE_URI_PREFIX)
    ? src.slice(FILE_URI_PREFIX.length)
    : null;

  // Amber "on this device only" chip while the blob cannot fit the
  // storage quota (backlog #143) - clears itself once space frees and
  // the retry sweep uploads it.
  const localOnly = useBlobQuotaBlocked(uuid);

  const isAudio = mimetype?.startsWith('audio/') ?? false;
  const isImage = mimetype?.startsWith('image/') ?? false;
  // What the shared viewer can open. A HEIC stored before the upload pipeline
  // re-encoded pictures keeps its thumbnail attempt but opens nothing.
  const isPicture = Boolean(uuid) && isPictureMime(mimetype || '');
  const isPdfFile = Boolean(uuid) && isPdf(mimetype || '', filename || '');
  const viewable = isPicture || isPdfFile;
  // A Files note that holds one file shows that file, not only its name, and
  // reads as a list once it holds a second. The count follows every edit, so
  // a file dropped into the note turns the card back into a row at once.
  const fileNote = extension.options.filePreview;
  const [cardNote, setCardNote] = useState(() => showsFileCard(fileNote, editor.state.doc));
  useEffect(() => {
    if (!fileNote) return;
    const sync = () => setCardNote(showsFileCard(fileNote, editor.state.doc));
    sync();
    editor.on('update', sync);
    return () => { editor.off('update', sync); };
  }, [editor, fileNote]);
  const showPreview = viewable && cardNote;

  const openViewer = useCallback(() => {
    const pos = getPos();
    if (typeof pos === 'number') openMediaViewerInDoc(editor.state.doc, pos);
  }, [editor, getPos]);

  // A PDF's tile shows its first page, drawn once the chip comes near the
  // screen, so a note of many PDFs reads only the ones somebody scrolls to.
  const tileRef = useRef<HTMLDivElement>(null);
  const [pdfCover, setPdfCover] = useState<PdfCoverImage | null>(() =>
    isPdfFile && uuid ? cachedPdfCover(uuid) : null,
  );
  const pdfNear = useNearScreen(tileRef, isPdfFile && !showPreview && !pdfCover);
  useEffect(() => {
    if (!pdfNear || !uuid || pdfCover) return;
    let alive = true;
    // A PDF that cannot be drawn keeps the file glyph.
    loadPdfCover(uuid).then((cover) => { if (alive) setPdfCover(cover); }, () => {});
    return () => { alive = false; };
  }, [pdfNear, uuid, pdfCover]);

  const menu = useContextMenu();

  // Load thumbnail for image attachments. The URL belongs to the shared
  // cache, which the Files grid and the viewer read too, so it outlives this
  // chip and is not revoked here.
  useEffect(() => {
    if (!isImage || !uuid) return;
    let cancelled = false;
    void loadAttachmentUrl(uuid).then((url) => {
      if (!cancelled && url) setThumbnailUrl(url);
    });
    return () => { cancelled = true; };
  }, [isImage, uuid]);

  // Stop audio and free its blob URL on unmount (e.g. navigating to another note)
  useEffect(() => {
    return () => {
      if (audioRef.current) {
        audioRef.current.pause();
        audioRef.current.src = '';
        audioRef.current = null;
      }
      if (audioUrlRef.current) {
        URL.revokeObjectURL(audioUrlRef.current);
        audioUrlRef.current = null;
      }
      if (deleteTimerRef.current) {
        clearTimeout(deleteTimerRef.current);
      }
    };
  }, []);

  // Pause audio when app is backgrounded (home button, browser minimized)
  useEffect(() => {
    const onVisibilityChange = () => {
      if (document.hidden && audioRef.current && playing) {
        audioRef.current.pause();
        setPlaying(false);
      }
    };
    document.addEventListener('visibilitychange', onVisibilityChange);
    return () => document.removeEventListener('visibilitychange', onVisibilityChange);
  }, [playing]);

  const fetchBlobUrl = useCallback(async (): Promise<string | null> => {
    if (!uuid) return null;
    const store = getAttachmentStore();
    if (!store) return null;
    const attachment = await store.getAttachment(uuid);
    if (!attachment) return null;
    const mime = attachment.meta.mime || 'application/octet-stream';
    const blob = new Blob([attachment.data as BlobPart], { type: mime });
    return URL.createObjectURL(blob);
  }, [uuid]);

  const handleDownload = useCallback(async () => {
    if (!uuid || downloading) return;
    setDownloading(true);
    setError(null);
    try {
      const store = getAttachmentStore();
      if (!store) { setError(t('attachment.fileNotFound')); return; }
      const attachment = await store.getAttachment(uuid);
      // Not cached and not on the server: the blob never uploaded from
      // its origin device. Explain instead of "File not found" (#151).
      if (!attachment) { setMissingRemote(true); return; }
      setMissingRemote(false);
      const mime = attachment.meta.mime || 'application/octet-stream';
      const blob = new Blob([attachment.data as BlobPart], { type: mime });
      const saved = await saveBlob(blob, filename || 'download');
      // The catch below turns the reason into the message; a dismissed dialog
      // is not a failure.
      if (!saved.ok && saved.reason === 'failed') throw saved.error;
    } catch (err) {
      setError(err instanceof Error ? err.message : t('attachment.downloadFailed'));
    } finally {
      setDownloading(false);
    }
  }, [uuid, filename, downloading, t]);

  const handleCopy = useCallback(() => {
    // Copy the markdown link so it can be pasted into another note. The name
    // is escaped the way the serializer escapes it, so a name holding a
    // bracket or an asterisk pastes back as itself rather than as emphasis.
    const name = escapeMarkdownText(filename || 'Attachment');
    const size = filesize || '';
    const mime = mimetype || '';
    const md = `[${name}|${size}|${mime}](${src})`;
    void navigator.clipboard.writeText(md).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }, [src, filename, filesize, mimetype]);

  // ---- Rename ----

  const currentName = filename || t('attachment.fallbackName');
  const { ext: nameExt } = splitFileName(currentName);

  const startRename = useCallback(() => {
    if (!editor.isEditable) return;
    if (renaming) return;
    setRenameValue(splitFileName(filename || t('attachment.fallbackName')).base);
    setRenaming(true);
  }, [editor, filename, t]);

  const cancelRename = useCallback(() => {
    setRenaming(false);
  }, []);

  // A note locked while the field is open drops the field with it, rather
  // than leaving a control the save path would refuse.
  useEffect(() => {
    if (!editable) setRenaming(false);
  }, [editable]);

  const commitRename = useCallback(() => {
    setRenaming(false);
    const before = filename || '';
    const { ext } = splitFileName(before);
    const base = cleanFileName(renameValue, '');
    // Nothing but dots and spaces is a cancel, not a request for a file
    // called `.` - and it covers the empty field too.
    if (!/[^.]/.test(base)) return;
    const next = joinFileName(base, ext);
    if (next === before) return;
    updateAttributes({ filename: next });
    extension.options.onRename?.(next);
  }, [filename, renameValue, updateAttributes, extension]);

  // The Files pillar's Rename row lands here. A request made while this chip
  // was already on screen arrives through the listener; one made as the note
  // opened is waiting to be claimed, because this node view did not exist
  // when it was sent.
  useEffect(() => {
    if (claimPendingRename(uuid)) startRename();
    return subscribeToRenameRequests((requested) => {
      if (requested === uuid) {
        claimPendingRename(uuid);
        startRename();
      }
    });
  }, [uuid, startRename]);

  const handlePlayPause = useCallback(async () => {
    if (playing && audioRef.current) {
      audioRef.current.pause();
      setPlaying(false);
      return;
    }
    if (audioRef.current && audioUrlRef.current) {
      void audioRef.current.play();
      setPlaying(true);
      return;
    }
    setError(null);
    try {
      const url = await fetchBlobUrl();
      if (!url) { setMissingRemote(true); return; }
      setMissingRemote(false);
      audioUrlRef.current = url;
      const audio = document.createElement('audio');
      audio.preload = 'auto';
      audioRef.current = audio;
      audio.onended = () => { setPlaying(false); setPosition(0); };
      // A recording's own header can understate its length - a three-second
      // one made here reported 1.52 - and the browser only corrects that as
      // it plays. Take every correction, and never let the thumb sit past
      // the end of its own track.
      audio.ondurationchange = () => {
        if (Number.isFinite(audio.duration) && audio.duration > 0) setDuration(audio.duration);
      };
      audio.ontimeupdate = () => {
        setPosition(audio.currentTime);
        setDuration((known) => (audio.currentTime > known ? audio.currentTime : known));
      };
      await new Promise<void>((resolve, reject) => {
        audio.oncanplaythrough = () => resolve();
        audio.onerror = () => reject(new Error('format'));
        audio.src = url;
        audio.load();
      });
      const known = await resolveDuration(audio);
      setDuration(known);
      await audio.play();
      setPlaying(true);
    } catch (err) {
      const msg = err instanceof Error ? err.message : '';
      if (msg === 'format') { setFormatUnsupported(true); setError(null); }
      else { setError(msg || t('attachment.playbackFailed')); }
      setPlaying(false);
    }
  }, [playing, mimetype, fetchBlobUrl, t]);

  const sizeStr = filesize || '';
  // The type, then a PDF's page count once its first page is drawn, then the size.
  const metaStr = [
    mimeToLabel(isPdfFile ? 'application/pdf' : mimetype || ''),
    pdfCover ? t('viewer.pageCount', { count: pdfCover.pages }) : '',
    sizeStr,
  ].filter(Boolean).join(' · ');
  const playable = isAudio && !formatUnsupported;
  // The tile opens the viewer, and the rest of the chip stays the editor's to
  // select, drag and delete. On the file card the picture above is the trigger.
  const tileOpens = viewable && !showPreview;

  const armDelete = useCallback(() => {
    if (deleteTimerRef.current) clearTimeout(deleteTimerRef.current);
    setConfirmingDelete(true);
    deleteTimerRef.current = setTimeout(() => setConfirmingDelete(false), 3000);
  }, []);

  // Rename, copy and delete are wanted now and then, so they wait in a menu
  // and the row keeps one labelled action.
  const openMenu = (e: React.MouseEvent<HTMLButtonElement>) => {
    const items: ContextMenuItem[] = [];
    if (editable) items.push({ label: t('attachment.rename'), icon: iconEditPencil(), onSelect: startRename });
    items.push({ label: t('common:actions.copy'), icon: iconCopy(), onSelect: handleCopy });
    if (editable) {
      items.push({ type: 'separator' });
      items.push({ label: t('common:actions.delete'), icon: iconTrash(), destructive: true, onSelect: armDelete });
    }
    const r = e.currentTarget.getBoundingClientRect();
    const rtl = document.documentElement.dir === 'rtl';
    menu.open(
      {
        clientX: rtl ? r.left : r.right - MENU_MIN_WIDTH_PX,
        clientY: r.bottom + 4,
        preventDefault: () => {},
        stopPropagation: () => {},
      },
      items,
    );
  };

  // On the file card the frame carries the border and the row becomes its
  // footer; everywhere else the row is the whole chip.
  const frameTone = selected
    ? 'border-accent'
    : error ? 'border-red-300 dark:border-red-800' : 'border-divider';
  const rowClass = showPreview
    ? `flex flex-wrap items-center gap-2.5 gap-y-1 px-3.5 py-2.5 border-t transition ${
        selected ? 'border-accent bg-accent/10 dark:bg-accent/20' : 'border-divider'
      }`
    : `flex flex-wrap items-center gap-3 gap-y-1 ps-2 pe-3 py-2 rounded-xl border transition ${
        selected
          ? 'border-accent bg-accent/10 dark:bg-accent/20'
          : 'border-divider bg-surface-2'
      } ${error ? 'border-red-300 dark:border-red-800' : ''}`;

  const tileContent = isImage && thumbnailUrl && !showPreview ? (
    <img
      src={thumbnailUrl}
      // The name stands beside it, so a picture that opens needs no alt of its own.
      alt={isPicture ? '' : filename || t('attachment.imageAlt')}
      draggable={false}
      className="block w-full h-full rounded-lg object-cover !m-0"
    />
  ) : pdfCover && !showPreview ? (
    <img
      src={pdfCover.url}
      alt=""
      draggable={false}
      className="block max-w-[40px] max-h-[40px] !m-0 bg-white border border-divider"
    />
  ) : playable ? (
    <HoverLabel label={playing ? t('attachment.pause') : t('attachment.play')} position="above">
    <button
      type="button"
      onMouseDown={(e) => { e.preventDefault(); e.stopPropagation(); }}
      onClick={(e) => { e.stopPropagation(); handlePlayPause(); }}
      aria-label={playing ? t('attachment.pause') : t('attachment.play')}
      className={`rounded p-0.5 text-accent hover:text-accent-hover transition ${BUTTON_CONTENT}`}
    >
      {playing ? (
        <Pause size={20} />
      ) : (
        <Play size={20} weight="fill" />
      )}
    </button>
    </HoverLabel>
  ) : (
    <FileTypeIcon
      mime={mimetype || (isPdfFile ? 'application/pdf' : 'application/octet-stream')}
      size={showPreview ? 18 : 20}
    />
  );
  const tileFace = 'w-full h-full rounded-lg bg-neutral-100 dark:bg-neutral-800 flex items-center justify-center text-neutral-500 dark:text-neutral-400';

  const row = (
      <div
        // Wrapping, with a floor under the name block and another under the
        // action cluster: on a chip too narrow for one row the cluster drops
        // to a second line and the name takes the full width, rather than
        // truncating to nothing behind the buttons. The floors measure the
        // CHIP, so an editor pane dragged narrow wraps at the same point a
        // phone does, and the cluster's floor is what stops the chip
        // un-wrapping mid-edit when its three actions become two.
        className={rowClass}
      >
        {/* ---- Preview tile ----
            A picture or a PDF opens from here, the way a thumbnail does
            everywhere. The View button beside the name is the same action
            for the keyboard and a screen reader, so the tile keeps out of
            the tab order and out of the accessibility tree. */}
        <div
          ref={tileRef}
          aria-hidden={tileOpens ? 'true' : undefined}
          className={`shrink-0 ${showPreview ? 'w-9 h-9' : 'w-12 h-12'}`}
        >
          {tileOpens ? (
            <HoverLabel label={t('attachment.view')} position="above" className="w-full h-full">
              <button
                type="button"
                tabIndex={-1}
                // A tap must not raise the keyboard on its way into the
                // viewer: the same suppression the picture node arms.
                onPointerDown={(e) => { if (e.pointerType !== 'mouse') suppressSoftKeyboard(editor.view.dom); }}
                onMouseDown={(e) => { e.preventDefault(); e.stopPropagation(); }}
                onClick={(e) => { e.stopPropagation(); openViewer(); }}
                className={`${tileFace} cursor-zoom-in transition hover:ring-2 hover:ring-accent/60 ${BUTTON_CONTENT}`}
              >
                {tileContent}
              </button>
            </HoverLabel>
          ) : (
            <div className={tileFace}>{tileContent}</div>
          )}
        </div>

        {/* ---- Filename + meta ---- */}
        <div className="flex-1 min-w-[170px]">
          {renaming ? (
            <div className="flex items-baseline gap-1">
              <input
                autoFocus
                dir="auto"
                value={renameValue}
                onChange={(e) => setRenameValue(e.target.value)}
                onKeyDown={(e) => {
                  if (isImeComposing(e)) return;
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    commitRename();
                  } else if (e.key === 'Escape') {
                    // Escape belongs to the field while it is open; without
                    // the stop it reaches the editor's own handlers.
                    e.preventDefault();
                    e.stopPropagation();
                    cancelRename();
                  }
                }}
                onBlur={commitRename}
                onClick={(e) => e.stopPropagation()}
                // Stop the press reaching the chip WITHOUT preventing it: the
                // sibling buttons prevent their mousedown to keep the node
                // from being dragged, and doing that here would kill the
                // caret. The drag is refused at dragstart instead.
                onPointerDown={(e) => e.stopPropagation()}
                onMouseDown={(e) => e.stopPropagation()}
                draggable={false}
                onDragStart={(e) => { e.preventDefault(); e.stopPropagation(); }}
                maxLength={FILE_NAME_MAX_LENGTH}
                placeholder={t('attachment.renamePlaceholder')}
                aria-label={t('attachment.renamePlaceholder')}
                enterKeyHint="done"
                className="min-w-0 flex-1 bg-transparent border-b border-accent/50 focus:border-accent outline-none text-sm font-medium text-neutral-800 dark:text-neutral-200"
              />
              {nameExt && (
                <span className="shrink-0 text-sm text-neutral-400 dark:text-neutral-500">
                  .{nameExt}
                </span>
              )}
            </div>
          ) : (
            <div className="text-sm font-medium text-neutral-800 dark:text-neutral-200 truncate" dir="auto">
              {filename || t('attachment.fallbackName')}
            </div>
          )}
          <div className="text-xs text-neutral-400 dark:text-neutral-500 truncate">
            {formatUnsupported && (
              <span className="text-amber-600 dark:text-amber-400">{t('attachment.cantPlay')}</span>
            )}
            {!formatUnsupported && metaStr}
            {localOnly && (
              <span className="text-amber-600 dark:text-amber-400 ms-1">
                {t('attachment.localOnly')}
              </span>
            )}
            {missingRemote && (
              <span className="text-amber-600 dark:text-amber-400 ms-1">
                {t('attachment.notUploaded')}
              </span>
            )}
            {downloading && <span className="text-accent ms-1">{t('attachment.downloadingStatus')}</span>}
            {error && <span className="text-red-500 ms-1">{error}</span>}
          </div>
          {/* The WHY, always visible - a tooltip is unreachable on touch,
              and this sits outside the truncating meta line so it can wrap. */}
          {localOnly && (
            <div className="text-[11px] text-amber-600 dark:text-amber-400 mt-0.5 leading-tight">
              {t('attachment.localOnlyTip')}
            </div>
          )}
          {/* Other-device counterpart of localOnlyTip: same always-visible
              amber line, same reasons (no hover on touch, truncation). */}
          {missingRemote && (
            <div className="text-[11px] text-amber-600 dark:text-amber-400 mt-0.5 leading-tight">
              {t('attachment.notUploadedTip')}
            </div>
          )}

          {/* ---- Seek (audio only) ----
              Rendered at rest rather than on first play, so the note does
              not reflow under the reader. It is inert until the file is
              loaded, because filling it in advance would mean decrypting
              every recording in the note on open. */}
          {playable && (
            <div className="flex items-center gap-2 mt-1.5">
              <span className="shrink-0 text-[11px] text-neutral-400 dark:text-neutral-500 tabular-nums">
                {formatDuration(position)}
              </span>
              <input
                type="range"
                min={0}
                max={duration || 1}
                step={0.1}
                value={duration > 0 ? Math.min(position, duration) : 0}
                disabled={duration <= 0}
                onChange={(e) => {
                  const next = parseFloat(e.target.value);
                  setPosition(next);
                  if (audioRef.current) audioRef.current.currentTime = next;
                }}
                onClick={(e) => e.stopPropagation()}
                // Same reasoning as the rename field: stop the press without
                // preventing it, or the thumb cannot be grabbed at all.
                onPointerDown={(e) => e.stopPropagation()}
                onMouseDown={(e) => e.stopPropagation()}
                draggable={false}
                onDragStart={(e) => { e.preventDefault(); e.stopPropagation(); }}
                aria-label={t('attachment.seek')}
                aria-valuetext={formatDuration(position)}
                className="flex-1 h-1.5 cursor-pointer disabled:cursor-default disabled:opacity-50"
                style={{ accentColor: 'rgb(var(--pn-accent))' }}
              />
              <span className="shrink-0 text-[11px] text-neutral-400 dark:text-neutral-500 tabular-nums">
                {duration > 0 ? formatDuration(duration) : '--:--'}
              </span>
            </div>
          )}
        </div>

        {/* ---- Actions ----
            One labelled action (View, or Download for a file the viewer
            cannot show; a recording plays from its tile), Download beside
            it, and the menu. The minimum width holds the wrap decision
            steady while the rename field is open with two buttons. */}
        <div className="shrink-0 flex items-center justify-end gap-0.5 min-w-[126px] ms-auto">
          {renaming ? (
            <>
              <ActionButton onClick={commitRename} label={t('attachment.saveName')}>
                <Check size={15} className="text-accent" />
              </ActionButton>
              <ActionButton onClick={cancelRename} label={t('common:actions.cancel')} tip="above-end">
                <X size={15} />
              </ActionButton>
            </>
          ) : confirmingDelete ? (
            <button
              type="button"
              onMouseDown={(e) => { e.preventDefault(); e.stopPropagation(); }}
              onClick={(e) => {
                e.stopPropagation();
                if (deleteTimerRef.current) clearTimeout(deleteTimerRef.current);
                setConfirmingDelete(false);
                deleteNode();
              }}
              className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-red-50 dark:bg-red-950/30 text-red-600 dark:text-red-400 text-xs font-medium transition hover:bg-red-100 dark:hover:bg-red-950/50 cursor-pointer select-none ${BUTTON_CONTENT}`}
            >
              <Trash size={13} />
              {t('attachment.deleteConfirm')}
            </button>
          ) : (
            <>
              {viewable ? (
                <LabelledAction onClick={openViewer}>
                  <Eye size={15} />
                  {t('attachment.view')}
                </LabelledAction>
              ) : playable ? null : (
                <LabelledAction onClick={() => void handleDownload()} disabled={downloading}>
                  <Download size={15} />
                  {t('attachment.download')}
                </LabelledAction>
              )}
              {(viewable || playable) && (
                <ActionButton onClick={() => void handleDownload()} disabled={downloading} label={t('attachment.download')}>
                  <Download size={15} />
                </ActionButton>
              )}
              <ActionButton onClick={openMenu} label={copied ? t('attachment.copied') : t('attachment.more')} tip="above-end">
                {copied ? (
                  <Check size={15} className="text-green-500" />
                ) : (
                  <DotsThree size={18} weight="bold" />
                )}
              </ActionButton>
            </>
          )}
        </div>
      </div>
  );

  return (
    <NodeViewWrapper
      // my-6 (24px) is one line of body copy (15px x 1.7). With the ghost
      // paragraph gone, this margin IS the gap between stacked chips - 12px
      // read as a solid block, and the old two-line crater was 75px.
      className="encrypted-attachment-wrapper my-6 leading-none"
      // Same defect as EncryptedImage: the node spec sets draggable: true, but
      // a React node view also needs this attribute or TipTap never starts the
      // drag. Fixed together because the two are the media-block pair
      // everywhere else (MEDIA_NODE_NAMES, MediaGapCleaner), and an attachment
      // chip that cannot be reordered is the same bug.
      data-drag-handle
    >
      {showPreview && uuid ? (
        <div className={`rounded-xl border overflow-hidden bg-surface-2 transition ${frameTone}`}>
          <FilePreview uuid={uuid} pdf={isPdfFile} name={filename || ''} onOpen={openViewer} />
          {row}
        </div>
      ) : row}
      <ContextMenu state={menu.state} onClose={menu.close} />
    </NodeViewWrapper>
  );
}

// ------------------------------------------------------------------
// Global store registry - set by NotesView when auth is ready
// ------------------------------------------------------------------

let _attachmentStore: AttachmentStore | null = null;

export function setAttachmentStore(store: AttachmentStore | null) {
  _attachmentStore = store;
}

function getAttachmentStore(): AttachmentStore | null {
  return _attachmentStore;
}

/** A decrypted attachment, or null when it is neither here nor on the server. */
export async function loadAttachmentData(uuid: string): Promise<DecryptedAttachment | null> {
  const store = getAttachmentStore();
  if (!store) return null;
  try {
    return await store.getAttachment(uuid);
  } catch {
    return null;
  }
}

/**
 * Attachment pictures as object URLs, kept for the session the way the
 * picture cache in EncryptedImage.tsx is, so a chip, a Files tile, a picture
 * placed from Files and the viewer that show one file decrypt it once.
 */
const attachmentUrlCache = new Map<string, string>();

/**
 * An object URL for an attachment's bytes, or null when it cannot be read.
 * Typed by the stored MIME, because an SVG in an untyped blob does not draw.
 */
export async function loadAttachmentUrl(uuid: string): Promise<string | null> {
  const cached = attachmentUrlCache.get(uuid);
  if (cached) return cached;
  const att = await loadAttachmentData(uuid);
  if (!att) return null;
  const existing = attachmentUrlCache.get(uuid);
  if (existing) return existing;
  const url = URL.createObjectURL(new Blob([att.data as BlobPart], { type: att.meta.mime || '' }));
  attachmentUrlCache.set(uuid, url);
  return url;
}

/** The cached URL, without reading anything. Lets a node view paint on its first frame. */
export function cachedAttachmentUrl(uuid: string): string | null {
  return attachmentUrlCache.get(uuid) ?? null;
}

/** A PDF's first page as a picture, with the document's page count. */
export type PdfCoverImage = { url: string; pages: number };

/** Draws in flight or done, by attachment uuid. A chip mounts again on every
 *  edit near it, and re-reading a large PDF each time would show; holding the
 *  promise also lets the chip, the card and a Files tile share one draw. */
const pdfCoverDraws = new Map<string, Promise<PdfCoverImage>>();
/** The same covers once drawn, so a remount paints on its first frame. */
const pdfCovers = new Map<string, PdfCoverImage>();

/**
 * The first page of a stored PDF, drawn once per session per file. pdf.js is
 * fetched by the first call. Rejects when the file cannot be read or opened,
 * and a failure is not remembered: the file may arrive with the next sync.
 */
export function loadPdfCover(uuid: string): Promise<PdfCoverImage> {
  let pending = pdfCoverDraws.get(uuid);
  if (!pending) {
    pending = (async () => {
      const [{ drawCover }, att] = await Promise.all([import('./PdfPages'), loadAttachmentData(uuid)]);
      if (!att) throw new Error('missing');
      // pdf.js takes ownership of the bytes it is given, so it gets a copy.
      const cover = await drawCover(new Uint8Array(att.data));
      pdfCovers.set(uuid, cover);
      return cover;
    })();
    pdfCoverDraws.set(uuid, pending);
    pending.catch(() => pdfCoverDraws.delete(uuid));
  }
  return pending;
}

/** The drawn cover, without reading anything. */
export function cachedPdfCover(uuid: string): PdfCoverImage | null {
  return pdfCovers.get(uuid) ?? null;
}

// ------------------------------------------------------------------
// Upload handler
// ------------------------------------------------------------------

export type AttachmentUploadContext = {
  isPro: boolean;
  attachmentStore: AttachmentStore;
  onQuotaExceeded?: () => void;
  getQuota?: () => { usedBytes: number; maxBytes: number } | null;
};

let _uploadContext: AttachmentUploadContext | null = null;

export function setAttachmentUploadContext(ctx: AttachmentUploadContext | null) {
  _uploadContext = ctx;
}

async function handleAttachmentUpload(
  file: File,
  view: EditorView,
): Promise<void> {
  if (!_uploadContext) return;

  // Validate file size (storage-sub holders get a larger per-file cap).
  const maxBytes = _uploadContext.getQuota?.()?.maxBytes ?? 0;
  const validation = validateAttachment(file, _uploadContext.isPro, maxBytes > 500 * 1000 * 1000);
  if (!validation.ok) {
    alert(validation.error);
    return;
  }

  // An image through the paperclip is still a file chip, but its bytes
  // obey the image switches like every other door, and the chip then names
  // the stored format so a download opens. A picture the module cannot
  // read is stored as it arrived, the way every non-image is.
  let upload = file;
  if (isSupportedImage(file)) {
    const processed = await processImage(file, currentImageOptions());
    if (processed.ok) {
      upload = new File([processed.image.data as BlobPart], processed.image.name, { type: processed.image.mime });
    }
  }

  // Pre-flight quota check, incoming file included: the bytes about to be
  // stored plus encryption overhead are the exact cost.
  if (_uploadContext.getQuota) {
    const q = _uploadContext.getQuota();
    if (q && q.usedBytes + estimateBlobBytes(upload.size) > q.maxBytes) {
      _uploadContext.onQuotaExceeded?.();
      return;
    }
  }

  let uuid: string;
  let meta: AttachmentMeta;
  let uploaded: Promise<void>;
  try {
    const result = await _uploadContext.attachmentStore.uploadAttachment(upload);
    uuid = result.uuid;
    meta = result.meta;
    uploaded = result.uploaded;
  } catch (err) {
    const msg = err instanceof Error ? err.message : '';
    if (msg.includes('Quota exceeded')) {
      _uploadContext.onQuotaExceeded?.();
    } else {
      alert(i18n.t('media:attachment.uploadFailed', { message: msg || i18n.t('media:attachment.unknownError') }));
    }
    return;
  }

  // Insert attachment node. If the cursor is in an empty paragraph,
  // replace it; otherwise insert after the current block. Avoids the
  // "phantom empty paragraph above" that happens when a block node
  // gets inserted at an inline position.
  const { schema } = view.state;
  const attachmentNode = schema.nodes['attachment'];
  if (!attachmentNode) return;

  const attachmentSrc = `${FILE_URI_PREFIX}${uuid}`;
  const node = attachmentNode.create({
    src: attachmentSrc,
    filename: meta.name,
    filesize: formatFileSize(meta.size),
    mimetype: meta.mime,
  });
  const $pos = view.state.doc.resolve(view.state.selection.to);
  const parentNode = $pos.parent;
  if (
    parentNode.type.name === 'paragraph' &&
    parentNode.content.size === 0 &&
    $pos.depth > 0
  ) {
    const start = $pos.before($pos.depth);
    const end = $pos.after($pos.depth);
    const tr = view.state.tr.replaceWith(start, end, node);
    view.dispatch(tr.scrollIntoView());
  } else {
    const insertAfter = $pos.depth > 0 ? $pos.after($pos.depth) : $pos.pos;
    const tr = view.state.tr.insert(insertAfter, node);
    view.dispatch(tr.scrollIntoView());
  }

  // If the background upload fails permanently, remove the ghost node
  // from the editor so it doesn't persist in the saved note.
  uploaded.catch(() => {
    if (view.isDestroyed) return;
    const { doc, tr } = view.state;
    let found = false;
    doc.descendants((n, pos) => {
      if (found) return false;
      if (n.type.name === 'attachment' && n.attrs.src === attachmentSrc) {
        tr.delete(pos, pos + n.nodeSize);
        found = true;
        return false;
      }
    });
    if (found) view.dispatch(tr);
  });
}

/** Public entry point for toolbar file picker. */
export async function triggerAttachmentUpload(
  file: File,
  view: EditorView,
): Promise<void> {
  return handleAttachmentUpload(file, view);
}

// ------------------------------------------------------------------
// ProseMirror plugin for paste/drop interception (non-image files)
// ------------------------------------------------------------------

const attachmentUploadPluginKey = new PluginKey('attachmentUpload');

function createAttachmentUploadPlugin() {
  return new Plugin({
    key: attachmentUploadPluginKey,
    props: {
      handleDrop(view, event) {
        if (!event.dataTransfer?.files?.length) return false;
        // Only handle non-image files. Images are handled by the
        // EncryptedImage plugin.
        const files = Array.from(event.dataTransfer.files).filter(
          (f) => !isImageFile(f),
        );
        if (files.length === 0) return false;

        event.preventDefault();
        for (const file of files) {
          void handleAttachmentUpload(file, view);
        }
        return true;
      },

      handlePaste(view, event) {
        const items = event.clipboardData?.items;
        if (!items) return false;

        const files: File[] = [];
        for (const item of Array.from(items)) {
          if (item.kind === 'file') {
            const file = item.getAsFile();
            if (file && !isImageFile(file)) files.push(file);
          }
        }

        if (files.length === 0) return false;
        event.preventDefault();
        for (const file of files) {
          void handleAttachmentUpload(file, view);
        }
        return true;
      },
    },
  });
}

// ------------------------------------------------------------------
// TipTap Extension
// ------------------------------------------------------------------

export type AttachmentOptions = {
  /**
   * Called with the new name after a chip is renamed. The editor decides
   * whether anything outside the document should follow; see the wiring in
   * `Editor.tsx`.
   */
  onRename: ((name: string) => void) | null;
  /**
   * The note is one the Files pillar made. While it holds one file, that file
   * is the whole note and its name alone previews nothing, so a picture or a
   * PDF draws as a card with the file itself on it instead of a one-line
   * chip. A note of several files keeps its chips (`showsFileCard`).
   */
  filePreview: boolean;
};

export const EncryptedAttachment = Node.create<AttachmentOptions>({
  name: 'attachment',
  group: 'block',
  atom: true,
  draggable: true,

  addOptions() {
    return { onRename: null, filePreview: false };
  },

  addAttributes() {
    return {
      src: { default: null },
      filename: { default: null },
      filesize: { default: null },
      mimetype: { default: null },
    };
  },

  parseHTML() {
    return [
      // Explicit data-attachment tag (from renderHTML).
      {
        tag: 'a[data-attachment]',
        getAttrs(dom) {
          const el = dom as HTMLAnchorElement;
          return {
            src: el.getAttribute('href'),
            filename: el.getAttribute('data-filename'),
            filesize: el.getAttribute('data-filesize'),
            mimetype: el.getAttribute('data-mimetype'),
          };
        },
      },
      // markdown-it produces <a href="pn:file/uuid">name|size|mime</a>
      // from [name|size|mime](pn:file/uuid). Detect via href prefix.
      {
        tag: 'a[href^="pn:file/"]',
        getAttrs(dom) {
          const el = dom as HTMLAnchorElement;
          const href = el.getAttribute('href') || '';
          // Parse pipe-delimited text: "filename|size|mime"
          const text = el.textContent || '';
          const parts = text.split('|');
          return {
            src: href,
            filename: parts[0] || 'Attachment',
            filesize: parts[1] || '',
            mimetype: parts[2] || '',
          };
        },
        // Higher priority than the Link extension so we intercept first.
        priority: 60,
      },
    ];
  },

  renderHTML({ HTMLAttributes }: { HTMLAttributes: Record<string, string> }) {
    return [
      'a',
      mergeAttributes(HTMLAttributes, {
        'data-attachment': 'true',
        'data-filename': HTMLAttributes.filename,
        'data-filesize': HTMLAttributes.filesize,
        'data-mimetype': HTMLAttributes.mimetype,
        href: HTMLAttributes.src,
      }),
      HTMLAttributes.filename || 'Attachment',
    ];
  },

  addNodeView() {
    return ReactNodeViewRenderer(EncryptedAttachmentView as never);
  },

  addProseMirrorPlugins() {
    return [createAttachmentUploadPlugin()];
  },

  addStorage() {
    return {
      markdown: {
        serialize(
          state: {
            write: (s: string) => void;
            esc: (s: string) => string;
            closeBlock: (n: unknown) => void;
          },
          node: { attrs: { src: string; filename: string; filesize: string; mimetype: string } },
        ) {
          // Serialize as: [filename|size|mime](pn:file/<uuid>)
          // The pipe-delimited format packs metadata into the link text
          // so it survives markdown roundtrip without needing extra syntax.
          const name = state.esc(node.attrs.filename || 'Attachment');
          const size = state.esc(node.attrs.filesize || '');
          const mime = state.esc(node.attrs.mimetype || '');
          const src = state.esc(node.attrs.src || '');
          state.write(`[${name}|${size}|${mime}](${src})`);
          // closeBlock, NOT a trailing "\n". This is a BLOCK node, and only
          // closeBlock leaves the blank line that makes the next block its own
          // paragraph. With a bare newline, two chips landed on consecutive
          // lines, markdown-it (breaks: true) turned the softbreak into <br>,
          // and ProseMirror lifted each block chip out of that paragraph -
          // leaving a <br>-only paragraph between every pair. That ghost
          // paragraph is two lines tall (measured: a 12px gap became 75px) and
          // came back on every reload, because nothing could tell it apart from
          // a line the user typed. It also glued the paragraph AFTER a chip
          // onto the chip's own line.
          state.closeBlock(node);
        },
        parse: {
          // markdown-it parses [text](href) → <a href="...">text</a>
          // We need a custom rule to detect pn:file/ links and convert
          // them into our attachment node.
        },
      },
    };
  },
});
