/**
 * Custom TipTap extension for encrypted file attachments.
 *
 * Renders as an inline chip: [icon] filename - size [download].
 * Files are encrypted client-side and stored in the same Supabase
 * Storage bucket as images. Never renders file content inline.
 *
 * URI scheme: pn:file/<uuid> in markdown link syntax:
 *   [filename](pn:file/<uuid>)
 *
 * Markdown roundtrip is handled by custom serialize/parse hooks.
 */

import { useState, useCallback, useRef, useEffect } from 'react';
import { estimateBlobBytes } from './notesViewUtils';
import { useTranslation } from 'react-i18next';
import { saveBlob } from './saveFile';
import { Node, mergeAttributes } from '@tiptap/core';
import { ReactNodeViewRenderer, NodeViewWrapper } from '@tiptap/react';
import { Plugin, PluginKey } from '@tiptap/pm/state';
import type { EditorView } from '@tiptap/pm/view';
import { AttachmentStore, type AttachmentMeta } from './attachmentStore';
import { validateAttachment, isImageFile, formatFileSize } from './attachmentValidation';
import { currentImageOptions, isSupportedImage, processImage } from './imageProcessing';
import { HoverLabel } from './HoverLabel';
import { useBlobQuotaBlocked } from './usePendingUploads';
import { MusicNotes, VideoCamera, Image, Archive, File as FileGlyph, Pause, Play, Trash, Check, Copy, Download } from './icons';
import i18n from './i18n';

// ------------------------------------------------------------------
// Constants
// ------------------------------------------------------------------

const FILE_URI_PREFIX = 'pn:file/';

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
function FileTypeIcon({ mime }: { mime: string }) {
  // Audio
  if (mime.startsWith('audio/')) {
    return <MusicNotes size={18} />;
  }
  // Video
  if (mime.startsWith('video/')) {
    return <VideoCamera size={18} />;
  }
  // Image
  if (mime.startsWith('image/')) {
    return <Image size={18} />;
  }
  // Archive
  if (mime === 'application/zip' || mime.includes('compressed') || mime.includes('archive')) {
    return <Archive size={18} />;
  }
  // Default: generic file
  return <FileGlyph size={18} />;
}

// ------------------------------------------------------------------
// Shared action button - icon-only, no border, hover bg
// ------------------------------------------------------------------

function ActionButton({ onClick, label, disabled, danger, children }: {
  onClick: () => void;
  label: string;
  disabled?: boolean;
  danger?: boolean;
  children: React.ReactNode;
}) {
  return (
    <HoverLabel label={label} position="above">
    <button
      type="button"
      onMouseDown={(e) => { e.preventDefault(); e.stopPropagation(); }}
      onClick={(e) => { e.stopPropagation(); onClick(); }}
      disabled={disabled}
      aria-label={label}
      className={`shrink-0 w-[30px] h-[30px] rounded-md flex items-center justify-center transition cursor-pointer select-none ${
        disabled ? 'opacity-50 pointer-events-none' : ''
      } ${
        danger
          ? 'text-neutral-400 dark:text-neutral-500 hover:text-red-500 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/30'
          : 'text-neutral-400 dark:text-neutral-500 hover:text-accent hover:bg-neutral-100 dark:hover:bg-neutral-800'
      }`}
    >
      {children}
    </button>
    </HoverLabel>
  );
}

// ------------------------------------------------------------------
// React NodeView - renders attachment chip with download
// ------------------------------------------------------------------

type AttachmentNodeViewProps = {
  node: { attrs: { src: string; filename: string; filesize: string; mimetype: string } };
  selected: boolean;
  deleteNode: () => void;
};

function EncryptedAttachmentView({ node, selected, deleteNode }: AttachmentNodeViewProps) {
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
  const [formatUnsupported, setFormatUnsupported] = useState(false);
  const [thumbnailUrl, setThumbnailUrl] = useState<string | null>(null);
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const audioUrlRef = useRef<string | null>(null);
  const thumbnailUrlRef = useRef<string | null>(null);
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

  // Load thumbnail for image attachments.
  useEffect(() => {
    if (!isImage || !uuid) return;
    let cancelled = false;
    const store = getAttachmentStore();
    if (!store) return;
    store.getAttachment(uuid).then((att) => {
      if (cancelled || !att) return;
      const blob = new Blob([att.data as BlobPart], { type: att.meta.mime || 'image/*' });
      const url = URL.createObjectURL(blob);
      thumbnailUrlRef.current = url;
      setThumbnailUrl(url);
    }).catch(() => {});
    return () => { cancelled = true; };
  }, [isImage, uuid]);

  // Stop audio and free blob URLs on unmount (e.g. navigating to another note)
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
      if (thumbnailUrlRef.current) {
        URL.revokeObjectURL(thumbnailUrlRef.current);
        thumbnailUrlRef.current = null;
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
      await saveBlob(blob, filename || 'download');
    } catch (err) {
      setError(err instanceof Error ? err.message : t('attachment.downloadFailed'));
    } finally {
      setDownloading(false);
    }
  }, [uuid, filename, downloading, t]);

  const handleCopy = useCallback(() => {
    // Copy the markdown link so it can be pasted into another note.
    const name = filename || 'Attachment';
    const size = filesize || '';
    const mime = mimetype || '';
    const md = `[${name}|${size}|${mime}](${src})`;
    void navigator.clipboard.writeText(md).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }, [src, filename, filesize, mimetype]);

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
      audio.onended = () => setPlaying(false);
      await new Promise<void>((resolve, reject) => {
        audio.oncanplaythrough = () => resolve();
        audio.onerror = () => reject(new Error('format'));
        audio.src = url;
        audio.load();
      });
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
      <div
        className={`flex items-center gap-2.5 px-3.5 py-2.5 rounded-xl border transition ${
          selected
            ? 'border-accent bg-accent/10 dark:bg-accent/20'
            : 'border-divider bg-surface-2'
        } ${error ? 'border-red-300 dark:border-red-800' : ''}`}
      >
        {/* ---- Icon / thumbnail box ---- */}
        {isImage && thumbnailUrl ? (
          <img
            src={thumbnailUrl}
            alt={filename || t('attachment.imageAlt')}
            className="shrink-0 w-9 h-9 rounded-lg object-cover bg-neutral-100 dark:bg-neutral-800 !m-0"
          />
        ) : (
        <div className="shrink-0 w-9 h-9 rounded-lg bg-neutral-100 dark:bg-neutral-800 flex items-center justify-center text-neutral-500 dark:text-neutral-400">
          {isAudio && !formatUnsupported ? (
            <HoverLabel label={playing ? t('attachment.pause') : t('attachment.play')} position="above">
            <button
              type="button"
              onMouseDown={(e) => { e.preventDefault(); e.stopPropagation(); }}
              onClick={(e) => { e.stopPropagation(); handlePlayPause(); }}
              aria-label={playing ? t('attachment.pause') : t('attachment.play')}
              className="rounded p-0.5 text-accent hover:text-accent-hover transition"
            >
              {playing ? (
                <Pause size={18} />
              ) : (
                <Play size={18} weight="fill" />
              )}
            </button>
            </HoverLabel>
          ) : (
            <FileTypeIcon mime={mimetype || 'application/octet-stream'} />
          )}
        </div>
        )}

        {/* ---- Filename + meta ---- */}
        <div className="flex-1 min-w-0">
          <div className="text-sm font-medium text-neutral-800 dark:text-neutral-200 truncate">
            {filename || t('attachment.fallbackName')}
          </div>
          <div className="text-xs text-neutral-400 dark:text-neutral-500 truncate">
            {formatUnsupported && (
              <span className="text-amber-600 dark:text-amber-400">{t('attachment.cantPlay')}</span>
            )}
            {!formatUnsupported && sizeStr}
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
        </div>

        {/* ---- Actions ---- */}
        <div className="shrink-0 flex items-center gap-0.5">
          {confirmingDelete ? (
            <button
              type="button"
              onMouseDown={(e) => { e.preventDefault(); e.stopPropagation(); }}
              onClick={(e) => {
                e.stopPropagation();
                if (deleteTimerRef.current) clearTimeout(deleteTimerRef.current);
                setConfirmingDelete(false);
                deleteNode();
              }}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-red-50 dark:bg-red-950/30 text-red-600 dark:text-red-400 text-xs font-medium transition hover:bg-red-100 dark:hover:bg-red-950/50 cursor-pointer select-none"
            >
              <Trash size={13} />
              {t('attachment.deleteConfirm')}
            </button>
          ) : (
            <>
              <ActionButton onClick={handleCopy} label={copied ? t('attachment.copied') : t('common:actions.copy')}>
                {copied ? (
                  <Check size={15} className="text-green-500" />
                ) : (
                  <Copy size={15} />
                )}
              </ActionButton>
              <ActionButton onClick={handleDownload} disabled={downloading} label={formatUnsupported ? t('attachment.downloadToPlay') : t('attachment.download')}>
                <Download size={15} />
              </ActionButton>
              <ActionButton onClick={() => {
                setConfirmingDelete(true);
                deleteTimerRef.current = setTimeout(() => setConfirmingDelete(false), 3000);
              }} label={t('common:actions.delete')} danger>
                <Trash size={15} />
              </ActionButton>
            </>
          )}
        </div>
      </div>
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

export const EncryptedAttachment = Node.create({
  name: 'attachment',
  group: 'block',
  atom: true,
  draggable: true,

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
