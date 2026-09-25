/**
 * Custom TipTap Image extension for encrypted images.
 *
 * Built from scratch on @tiptap/core (the stock image extension is not used), with:
 * - A React nodeView that resolves `pn:img/<uuid>` URIs by fetching
 *   encrypted blobs from Supabase Storage, decrypting, and rendering. A
 *   `pn:file/<uuid>` source is a picture placed from the Files pillar: it
 *   points at that upload's attachment blob instead of storing a copy.
 * - Paste/drop/upload interception that processes images client-side
 *   (resize, WebP encode, EXIF strip) then encrypts + uploads.
 *
 * Markdown roundtrip is handled by this file's own storage.markdown
 * serializer (see addStorage) - it outputs `![alt](pn:img/<uuid>){width=N}`
 * which markdown-it parses back into an <img> tag on load, with a custom
 * core rule recovering the width suffix.
 */

import { useState, useEffect, useRef, useCallback, memo } from 'react';
import { estimateBlobBytes } from './notesViewUtils';
import { useTranslation } from 'react-i18next';
import { Node, mergeAttributes } from '@tiptap/core';
import { ReactNodeViewRenderer, NodeViewWrapper } from '@tiptap/react';
import { Plugin, PluginKey } from '@tiptap/pm/state';
import type { EditorView } from '@tiptap/pm/view';
import type { Node as ProseMirrorNode } from '@tiptap/pm/model';
import { Decoration, DecorationSet } from '@tiptap/pm/view';
import { ArrowsOutSimple, Download, Trash } from './icons';
import { currentImageOptions, processImage } from './imageProcessing';
import { cachedAttachmentUrl, loadAttachmentData, loadAttachmentUrl } from './EncryptedAttachment';
import { FILE_REF_PREFIX, openMediaViewerInDoc, type MediaRef } from './mediaRefs';
import { validateAttachment } from './attachmentValidation';
import { suppressSoftKeyboard } from './softKeyboard';
import type { ImageStore } from './imageStore';
import { saveBlob, type SaveResult } from './saveFile';
import i18n from './i18n';

/** Prefix for our custom image URIs. */
const IMAGE_URI_PREFIX = 'pn:img/';

/**
 * Where the `pn:img/<uuid>` ref rides in the DOM, since `src` is overwritten
 * with a placeholder on render. The clipboard is a DOM round-trip, so this
 * is what makes copy and paste of an image inside a note work at all.
 */
const IMAGE_REF_ATTR = 'data-pn-src';

/**
 * In-memory blob URL cache - survives component remounts so images
 * don't flash through a "Loading..." state on every TipTap re-render
 * (e.g. checkbox toggles). Entries persist for the session; URLs are
 * only revoked when the cache is explicitly cleared.
 */
const blobUrlCache = new Map<string, string>();

/**
 * IDs of images that exhausted their initial retry window but may
 * appear on the server later (the uploading device's background
 * upload was slow). Components watching these IDs re-attempt a
 * download on the next `privacynotes:sync-complete` event.
 */
const pendingRetryIds = new Set<string>();

/** Check if a src attribute is one of our encrypted image refs. */
export function isEncryptedImageSrc(src: string): boolean {
  return src.startsWith(IMAGE_URI_PREFIX);
}

/** A source that names one of our encrypted blobs, as opposed to a path. */
function isBlobRef(src: string): boolean {
  return src.startsWith(IMAGE_URI_PREFIX) || src.startsWith(FILE_REF_PREFIX);
}

/**
 * Which store a picture's bytes live in. `img` is the picture store; `file`
 * is an upload's attachment blob, which a picture placed from Files points at
 * so the one upload is stored once however many notes show it.
 */
type BlobSource = { store: 'img' | 'file'; uuid: string };

function blobSource(src: string): BlobSource | null {
  if (src.startsWith(IMAGE_URI_PREFIX)) return { store: 'img', uuid: src.slice(IMAGE_URI_PREFIX.length) };
  if (src.startsWith(FILE_REF_PREFIX)) return { store: 'file', uuid: src.slice(FILE_REF_PREFIX.length) };
  return null;
}

function cachedSourceUrl(source: BlobSource | null): string | null {
  if (!source) return null;
  return source.store === 'img'
    ? (blobUrlCache.get(source.uuid) ?? null)
    : cachedAttachmentUrl(source.uuid);
}

/**
 * Read a picture's bytes into a cached object URL. Null means "not here and
 * not on the server yet", which the node view retries; a throw is an error.
 */
async function fetchSourceUrl(source: BlobSource): Promise<string | null> {
  if (source.store === 'file') return loadAttachmentUrl(source.uuid);
  const store = getImageStore();
  if (!store) throw new Error(i18n.t('media:image.storeUnavailable'));
  const bytes = await store.getImage(source.uuid);
  if (!bytes) return null;
  const existing = blobUrlCache.get(source.uuid);
  if (existing) return existing;
  const url = URL.createObjectURL(new Blob([bytes as BlobPart]));
  blobUrlCache.set(source.uuid, url);
  return url;
}

// ------------------------------------------------------------------
// React NodeView - renders encrypted images with loading/error states
// ------------------------------------------------------------------

/** Valid image width presets (percentage of container). */
type ImageWidth = 25 | 50 | 75 | 100;
const IMAGE_WIDTHS: ImageWidth[] = [25, 50, 75, 100];
const IMAGE_WIDTH_LABEL_KEYS: Record<ImageWidth, string> = {
  25: 'image.widthXs',
  50: 'image.widthS',
  75: 'image.widthM',
  100: 'image.widthL',
};

type ImageNodeViewProps = {
  node: {
    attrs: { src: string; alt: string; title: string; width: ImageWidth; textAlign?: string | null };
  };
  selected: boolean;
  editor: {
    isEditable: boolean;
    commands: { setNodeSelection: (pos: number) => boolean };
    view: { focus: () => void; dom: HTMLElement };
    state: { doc: ProseMirrorNode };
  };
  /** Document position of this image, or undefined once the node is gone. */
  getPos: () => number | undefined;
  updateAttributes: (attrs: Record<string, unknown>) => void;
  deleteNode: () => void;
};

/**
 * Floating toolbar shown above a selected image.
 * Provides size presets (25/50/75/100%), view, download, and delete.
 */
function ImageToolbar({
  width,
  onResize,
  onView,
  onDownload,
  onDelete,
}: {
  width: ImageWidth;
  onResize: (w: ImageWidth) => void;
  onView: () => void;
  onDownload: () => void;
  onDelete: () => void;
}) {
  const { t } = useTranslation('media');
  return (
    <div
      className="pn-image-toolbar"
      contentEditable={false}
      suppressContentEditableWarning
    >
      <span className="pn-image-toolbar-label">{t('image.sizeLabel')}</span>
      <div className="pn-image-toolbar-sizes">
        {IMAGE_WIDTHS.map((w) => (
          <button
            key={w}
            type="button"
            className={`pn-image-toolbar-size${w === width ? ' active' : ''}`}
            onPointerDown={(e) => { e.preventDefault(); e.stopPropagation(); }}
            onClick={(e) => { e.preventDefault(); e.stopPropagation(); onResize(w); }}
          >
            {t(IMAGE_WIDTH_LABEL_KEYS[w])}
          </button>
        ))}
      </div>
      <div className="pn-image-toolbar-divider" />
      <button
        type="button"
        className="pn-image-toolbar-btn"
        aria-label={t('image.viewAria')}
        onPointerDown={(e) => { e.preventDefault(); e.stopPropagation(); }}
        onClick={(e) => { e.preventDefault(); e.stopPropagation(); onView(); }}
      >
        <ArrowsOutSimple size={16} />
      </button>
      <div className="pn-image-toolbar-divider" />
      <button
        type="button"
        className="pn-image-toolbar-btn"
        aria-label={t('image.downloadAria')}
        onPointerDown={(e) => { e.preventDefault(); e.stopPropagation(); }}
        onClick={(e) => { e.preventDefault(); e.stopPropagation(); onDownload(); }}
      >
        <Download size={16} />
      </button>
      <div className="pn-image-toolbar-divider" />
      <button
        type="button"
        className="pn-image-toolbar-btn pn-image-toolbar-danger"
        aria-label={t('image.deleteAria')}
        onPointerDown={(e) => { e.preventDefault(); e.stopPropagation(); }}
        onClick={(e) => { e.preventDefault(); e.stopPropagation(); onDelete(); }}
      >
        <Trash size={16} />
      </button>
    </div>
  );
}

/**
 * Memoized so that keystrokes in adjacent paragraphs don't trigger a
 * re-render. Without this, React reconciliation on every TipTap
 * transaction causes a DOM mutation that resets the iOS keyboard's
 * composition state - breaking double-tap-space-for-period and other
 * input-method features.
 */
const EncryptedImageView = memo(function EncryptedImageView({
  node,
  selected,
  editor,
  getPos,
  updateAttributes,
  deleteNode,
}: ImageNodeViewProps) {
  const { t } = useTranslation('media');
  const { src, alt, width, textAlign } = node.attrs;
  const source = blobSource(src);
  // One key per blob, whichever store holds it: the retry set below is shared.
  const imageId = source ? `${source.store}:${source.uuid}` : null;
  const cachedUrl = cachedSourceUrl(source);
  const [objectUrl, setObjectUrl] = useState<string | null>(cachedUrl);
  const [error, setError] = useState<string | null>(null);
  // A failed native save can leave an empty or partial file, so the message
  // stays until a save succeeds; a dismissed dialog changes nothing.
  const [saveFailed, setSaveFailed] = useState(false);
  const [loading, setLoading] = useState(!cachedUrl);
  // True once a person taps this image, and what the size/download/delete bar
  // hangs on. It separates an image someone chose from the one ProseMirror
  // seeds a note with when that note opens on an image.
  const [tapped, setTapped] = useState(false);
  // Was the press that is running right now made by a finger or a pen?
  // The question is whether THIS press can raise the on-screen keyboard, and
  // that is a property of the press, not of the machine. A media query answers
  // the wrong question: an Android phone with a stylus or a paired mouse
  // reports a hover-capable pointer and still has an on-screen keyboard, so it
  // took the desktop branch below and lost its selection to the keyboard.
  const softPress = useRef(false);
  const wrapperRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (cachedUrl) return;

    let cancelled = false;

    if (!source || !imageId) {
      setObjectUrl(src);
      setLoading(false);
      return;
    }

    if (source.store === 'img' && !getImageStore()) {
      setError(t('image.storeUnavailable'));
      setLoading(false);
      return;
    }

    // Retry with backoff: the image may still be uploading from
    // another device (note body syncs before blob upload completes).
    // Try 4 times: 0s, 2s, 5s, 10s. GitHub #48.
    const RETRY_DELAYS = [0, 2000, 5000, 10000];

    void (async () => {
      for (let attempt = 0; attempt < RETRY_DELAYS.length; attempt++) {
        if (cancelled) return;
        if (attempt > 0) {
          await new Promise((r) => setTimeout(r, RETRY_DELAYS[attempt]));
          if (cancelled) return;
        }

        try {
          const url = await fetchSourceUrl(source);
          if (cancelled) return;
          if (url) {
            setObjectUrl(url);
            setLoading(false);
            pendingRetryIds.delete(imageId);
            return;
          }
          // null - not on the server yet, retry if attempts remain
        } catch (err) {
          if (cancelled) return;
          // On last attempt, surface the error
          if (attempt === RETRY_DELAYS.length - 1) {
            setError(err instanceof Error ? err.message : t('image.loadFailed'));
            setLoading(false);
            pendingRetryIds.add(imageId);
            return;
          }
          // Otherwise retry
        }
      }
      // Exhausted initial retries - register for sync-triggered retry
      // so the image gets another chance when the uploading device's
      // background upload finishes and a subsequent sync completes.
      if (!cancelled) {
        setError(t('image.notFound'));
        setLoading(false);
        pendingRetryIds.add(imageId);
      }
    })();

    return () => { cancelled = true; };
  }, [src, imageId, cachedUrl]);

  // Re-attempt download when a sync completes - the uploading device's
  // background upload may have finished by now. The listener is installed
  // whenever the image has nothing to show, and the pending set is read when
  // the event fires: the ladder above adds this id only after its last
  // attempt, and React watches no dependency that changes at that moment, so
  // a listener gated at mount would never exist for the image that needs it.
  // GitHub #134.
  useEffect(() => {
    if (!source || !imageId || objectUrl) return;

    const onSyncComplete = async () => {
      if (!pendingRetryIds.has(imageId)) return;
      try {
        const url = await fetchSourceUrl(source);
        if (!url) return;
        setObjectUrl(url);
        setError(null);
        setLoading(false);
        pendingRetryIds.delete(imageId);
      } catch {
        // Still not available - stay in error state, try again next sync
      }
    };

    window.addEventListener('privacynotes:sync-complete', onSyncComplete);
    return () => window.removeEventListener('privacynotes:sync-complete', onSyncComplete);
  }, [imageId, objectUrl]);

  const handleResize = useCallback((w: ImageWidth) => {
    updateAttributes({ width: w });
  }, [updateAttributes]);

  const handleDownload = useCallback(async () => {
    if (!source) return;
    let saved: SaveResult | null;
    if (source.store === 'file') {
      // The upload keeps its own name and type; the alt text may be empty.
      const att = await loadAttachmentData(source.uuid);
      if (!att) return;
      saved = await saveBlob(new Blob([att.data as BlobPart], { type: att.meta.mime }), att.meta.name || alt || 'image');
    } else {
      saved = await saveStoredImage(source.uuid, alt);
    }
    if (saved?.ok) setSaveFailed(false);
    else if (saved?.reason === 'failed') setSaveFailed(true);
  }, [src, alt]);

  const handleView = useCallback(() => {
    const pos = getPos();
    if (typeof pos === 'number') openMediaViewerInDoc(editor.state.doc, pos);
  }, [editor, getPos]);

  const handleDelete = useCallback(() => {
    deleteNode();
  }, [deleteNode]);

  // Own the tap on the image instead of leaving it to ProseMirror.
  //
  // A tap answers two questions at once. The node selection is the one the
  // rest of the editor reads, for copy, cut and drag. Under a mouse it also
  // needs focus inside .ProseMirror, because a note that opens on an image is
  // given that selection before anyone touches anything, and an unfocused
  // editor must show no editing affordance (see index.css). A tap on a
  // contenteditable=false child delivers neither: the caret goes to the
  // nearest text, so an image with a paragraph under it selected nothing,
  // while the last image in a note - with no text to snap to - worked.
  //
  // `tapped` is the second, and it is what the size/download/delete bar hangs
  // on. Under a finger or a pen no focus is taken at all: focus is what
  // attaches the keyboard, and the keyboard puts the caret back in the
  // nearest text. It also means resizing a picture does not drag the keyboard
  // onto the screen.
  //
  // Under a mouse this is belt to ProseMirror's braces: a click fires after
  // mouseup, so this runs last and wins even when the browser re-normalizes
  // the selection behind us. Setting the same NodeSelection twice is a no-op,
  // so mouse behavior is unchanged.
  // Fix: GitHub #240 (image options do not appear on Android)
  const handleSelect = useCallback(() => {
    // A note nobody can edit has no caret for a click to place and no bar to
    // show, so the click is free to open the picture.
    if (!editor.isEditable) {
      handleView();
      return;
    }
    const pos = getPos();
    if (typeof pos !== 'number') return;
    if (softPress.current) setTapped(true);
    editor.commands.setNodeSelection(pos);
    // Focus only where focus is harmless. On Android the keyboard attaches to
    // the editor and puts the caret in the nearest text, which turns this node
    // selection into a text selection. The bar needs neither that selection
    // nor the editor's focus: `tapped` carries both, and index.css reads it to
    // tell an image a person chose from the one the initial selection landed
    // on.
    if (!softPress.current) editor.view.focus();
  }, [editor, getPos, handleView]);

  // Arm the keyboard suppression as the press starts, while there is still
  // time for it to count. Skipping focus below is not enough once the editor
  // already holds it: on Android the tap itself re-raises the keyboard, and
  // the keyboard takes the caret with it. See softKeyboard.ts.
  const handlePointerDown = useCallback((e: React.PointerEvent) => {
    softPress.current = e.pointerType !== 'mouse';
    if (softPress.current) suppressSoftKeyboard(editor.view.dom);
  }, [editor]);

  // Focus is the default action of mousedown, and under a finger it is what
  // raises the keyboard and lets the input method rewrite the selection.
  // Refusing it here keeps the keyboard down for a gesture that only resizes
  // or deletes a picture. The click still fires, and scrolling is unaffected
  // because the browser decides that from touch-action before this runs.
  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    if (softPress.current) e.preventDefault();
  }, []);

  // The bar belongs to the image a person tapped, and it stays until they
  // touch something else.
  //
  // The editor selection is the wrong thing to hang it on. A selection inside
  // a contenteditable belongs to the platform's input method, and on some
  // Android builds that method puts the caret back in the text beside the
  // image within a frame or two of the tap. That is #240: the bar flashes and
  // goes, and only on an image with text under it, because text is what a
  // caret can be moved into.
  //
  // Nothing the bar offers needs that selection: resize, download and delete
  // all act on this node's own position. So the tap holds it open and an
  // ordinary press or keystroke somewhere else closes it, both read in the
  // capture phase, because the toolbar's own buttons stop the press from
  // bubbling any further.
  useEffect(() => {
    if (!tapped) return;
    const close = (e: Event) => {
      // `globalThis` qualified because `Node` in this file is TipTap's.
      const target = e.target instanceof globalThis.Node ? e.target : null;
      if (!target || !wrapperRef.current?.contains(target)) setTapped(false);
    };
    document.addEventListener('pointerdown', close, true);
    document.addEventListener('keydown', close, true);
    return () => {
      document.removeEventListener('pointerdown', close, true);
      document.removeEventListener('keydown', close, true);
    };
  }, [tapped]);

  // Width style - percentage of container.
  const widthPercent = (width && IMAGE_WIDTHS.includes(width)) ? width : 100;
  // Alignment moves the whole box, the same way an aligned list item does
  // (ui-patterns.md section 65): the container is already capped by the
  // width preset, so auto margins are all it takes. At 100% there is no
  // slack to move into, which is why alignment reads as a no-op on L.
  // rtl-ok: textAlign is the persisted physical value from ALIGNMENT_VALUES
  // (editorExtensions.ts) - swapping these to logical margins is exactly the
  // open decision rtl-handoff.md section 3d flags as unresolved (does
  // textAlign:'left' mean "left" or "start"?), not a mechanical rename.
  const alignStyle =
    textAlign === 'center' ? { marginLeft: 'auto', marginRight: 'auto' } // rtl-ok: see above
    : textAlign === 'right' ? { marginLeft: 'auto', marginRight: '0' } // rtl-ok: see above
    : null;

  return (
    <NodeViewWrapper
      className={`pn-image-node ${selected || tapped ? 'ProseMirror-selectednode' : ''}${tapped ? ' pn-image-tapped' : ''}`}
      // `draggable: true` on the node spec is necessary but NOT sufficient for
      // a React node view: TipTap only starts a drag from an element carrying
      // data-drag-handle, and without one the spec flag does nothing at all.
      // That is why images could never be moved within a note despite being
      // declared draggable. The inner <img> keeps draggable={false} so the
      // browser's own image drag (which drags the blob URL, not the node) does
      // not pre-empt this one.
      data-drag-handle
    >
      <div
        ref={wrapperRef}
        className="pn-image-container"
        style={{ maxWidth: `${widthPercent}%`, ...alignStyle }}
      >
        {loading && (
          <div className="flex items-center justify-center bg-neutral-100 dark:bg-neutral-900 rounded-md p-8 text-neutral-400 dark:text-neutral-600 text-sm">
            {t('image.loading')}
          </div>
        )}
        {error && (
          <div className="flex items-center justify-center bg-red-50 dark:bg-red-950/20 border border-red-200 dark:border-red-900/40 rounded-md p-4 text-red-600 dark:text-red-400 text-sm">
            {error}
          </div>
        )}
        {objectUrl && !error && (
          <img
            src={objectUrl}
            alt={alt || ''}
            // Rounded in both states: the bar rests on the image rather than
            // under it, so there is no seam that would need the bottom corners
            // squared. See .pn-image-toolbar in index.css.
            className="rounded-md"
            draggable={false}
            // Click, not pointerdown: a drag of the image never produces one,
            // so grabbing the node to move it does not also select it.
            onClick={handleSelect}
            onPointerDown={handlePointerDown}
            onMouseDown={handleMouseDown}
          />
        )}
        {(selected || tapped) && objectUrl && !error && editor.isEditable && (
          <ImageToolbar
            width={widthPercent as ImageWidth}
            onResize={handleResize}
            onView={handleView}
            onDownload={handleDownload}
            onDelete={handleDelete}
          />
        )}
        {(selected || tapped) && saveFailed && (
          <p className="mt-1 text-xs text-red-600 dark:text-red-400">{t('image.saveFailed')}</p>
        )}
      </div>
    </NodeViewWrapper>
  );
}, (prev, next) =>
  prev.node.attrs.src === next.node.attrs.src &&
  prev.node.attrs.alt === next.node.attrs.alt &&
  prev.node.attrs.width === next.node.attrs.width &&
  prev.node.attrs.textAlign === next.node.attrs.textAlign &&
  prev.selected === next.selected,
);

// ------------------------------------------------------------------
// Global image store registry - set by NotesView when auth is ready
// ------------------------------------------------------------------

let _imageStore: ImageStore | null = null;

export function setImageStore(store: ImageStore | null) {
  _imageStore = store;
}

function getImageStore(): ImageStore | null {
  return _imageStore;
}

/**
 * Save a stored picture under its alt text, or its id when it has none. The
 * upload pipeline stores WebP, so a name without an extension gets that one.
 * Null when the picture cannot be read.
 */
export async function saveStoredImage(uuid: string, alt: string): Promise<SaveResult | null> {
  const store = getImageStore();
  if (!store) return null;
  const bytes = await store.getImage(uuid);
  if (!bytes) return null;
  const name = alt || uuid || 'image';
  const ext = name.includes('.') ? '' : '.webp';
  return saveBlob(new Blob([bytes as BlobPart]), `${name}${ext}`);
}

/**
 * Load an encrypted image by uuid to a cached object URL, for read-only
 * thumbnails outside the editor (e.g. the Files grid). Reuses the same
 * decrypt + blob-URL cache as the editor node view. Returns null if the
 * store isn't ready or the blob isn't available yet.
 */
export async function loadEncryptedImageUrl(uuid: string): Promise<string | null> {
  const cached = blobUrlCache.get(uuid);
  if (cached) return cached;
  const store = getImageStore();
  if (!store) return null;
  try {
    const blob = await store.getImage(uuid);
    if (!blob) return null;
    const existing = blobUrlCache.get(uuid);
    if (existing) return existing;
    const url = URL.createObjectURL(new Blob([blob as BlobPart]));
    blobUrlCache.set(uuid, url);
    return url;
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------
// Image upload handler - called on paste/drop/toolbar
// ------------------------------------------------------------------

export type ImageUploadContext = {
  imageStore: ImageStore;
  /** Picks the per-file tier cap for a picture stored as it arrived. */
  isPro: boolean;
  /** Called when an image upload would exceed the storage quota. */
  onQuotaExceeded?: () => void;
  /** Returns current quota usage + limits. Null if not available yet. */
  getQuota?: () => { usedBytes: number; maxBytes: number } | null;
  /** Called with a user-visible error message when upload fails. */
  onError?: (msg: string) => void;
};

let _uploadContext: ImageUploadContext | null = null;

export function setImageUploadContext(ctx: ImageUploadContext | null) {
  _uploadContext = ctx;
}

// ------------------------------------------------------------------
// Upload placeholder management via ProseMirror decorations
// ------------------------------------------------------------------

let _placeholderId = 0;

/** Dispatch a meta action to add/remove upload placeholders. */
function addPlaceholder(view: EditorView, pos: number, fileName: string): string {
  const id = `upload-${++_placeholderId}`;
  const tr = view.state.tr;
  tr.setMeta(imageUploadPluginKey, { type: 'add', id, pos, fileName });
  view.dispatch(tr);
  return id;
}

function removePlaceholder(view: EditorView, id: string) {
  const tr = view.state.tr;
  tr.setMeta(imageUploadPluginKey, { type: 'remove', id });
  view.dispatch(tr);
}

/** Find the current document position of a placeholder decoration. */
function findPlaceholderPos(view: EditorView, id: string): number | null {
  const decos = imageUploadPluginKey.getState(view.state) as DecorationSet | undefined;
  if (!decos) return null;
  const found = decos.find(undefined, undefined, (spec) => spec.id === id);
  return found.length > 0 ? found[0]!.from : null;
}

async function handleImageUpload(
  file: File,
  view: EditorView,
  pos: number,
): Promise<void> {
  if (!_uploadContext) {
    console.error('[image] No upload context - auth not ready?');
    return;
  }

  const reportError = (msg: string) => {
    console.error('[image]', msg);
    _uploadContext?.onError?.(msg);
  };

  // Pre-flight quota check.
  if (_uploadContext.getQuota) {
    const q = _uploadContext.getQuota();
    if (q && q.usedBytes >= q.maxBytes) {
      _uploadContext.onQuotaExceeded?.();
      return;
    }
  }

  // The per-file tier cap applies only to a picture stored as it arrived:
  // a space-saved image is a few hundred kilobytes whatever came in, and
  // the module's own ceiling guards that path.
  const opts = currentImageOptions();
  if (opts.fitBox === null) {
    const maxBytes = _uploadContext.getQuota?.()?.maxBytes ?? 0;
    const v = validateAttachment(file, _uploadContext.isPro, maxBytes > 500 * 1000 * 1000);
    if (!v.ok) {
      reportError(v.error);
      return;
    }
  }

  // Show placeholder immediately so the user knows something is happening.
  const placeholderId = addPlaceholder(view, pos, file.name);

  const result = await processImage(file, opts);
  if (!result.ok) {
    removePlaceholder(view, placeholderId);
    reportError(result.error);
    return;
  }

  // Quota gate with the INCOMING file counted, using the exact bytes about
  // to be stored (shrunk, stripped or kept, whichever the switches chose)
  // so a large paste into a nearly-full account is refused here instead
  // of by the server after a wasted upload. The early gate above only
  // catches accounts already at 100%.
  if (_uploadContext.getQuota) {
    const q = _uploadContext.getQuota();
    if (q && q.usedBytes + estimateBlobBytes(result.image.data.length) > q.maxBytes) {
      removePlaceholder(view, placeholderId);
      _uploadContext.onQuotaExceeded?.();
      return;
    }
  }

  let uuid: string;
  try {
    uuid = await _uploadContext.imageStore.uploadImage(result.image.data);
  } catch (err) {
    removePlaceholder(view, placeholderId);
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes('Quota exceeded')) {
      _uploadContext.onQuotaExceeded?.();
    } else {
      reportError(i18n.t('media:image.uploadFailed', { message: msg }));
    }
    return;
  }

  // Replace placeholder with the real image node.
  const placeholderPos = findPlaceholderPos(view, placeholderId);
  removePlaceholder(view, placeholderId);
  placeImage(view, `${IMAGE_URI_PREFIX}${uuid}`, result.image.name, placeholderPos ?? view.state.selection.to);
}

/**
 * Put a picture node at `targetPos`, by the rules every picture insert uses:
 * an empty paragraph is replaced rather than left above it, a table cell
 * keeps the picture inside the cell, and anywhere else it goes after the
 * current block.
 */
function placeImage(view: EditorView, src: string, alt: string, targetPos: number): void {
  const { schema, doc } = view.state;
  const imageNode = schema.nodes['image'];
  if (!imageNode) return;
  const node = imageNode.create({ src, alt });

  const $pos = doc.resolve(Math.min(targetPos, doc.content.size));

  // If the cursor is inside an empty paragraph, replace it with the
  // image so we don't leave a stray blank line above.
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
  } else if (
    parentNode.type.name === 'tableCell' ||
    parentNode.type.name === 'tableHeader'
  ) {
    // A block node (e.g. an existing image) is selected directly inside a
    // table cell, so $pos.parent is the cell itself. $pos.after($pos.depth)
    // would resolve to a position *after the cell*, where a block node is
    // illegal - ProseMirror then fabricates stray cells/rows/tables to fit
    // it. Insert the new image as a sibling inside the same cell instead. (#146)
    const insertAt = $pos.nodeAfter ? $pos.pos + $pos.nodeAfter.nodeSize : $pos.pos;
    const tr = view.state.tr.insert(insertAt, node);
    view.dispatch(tr.scrollIntoView());
  } else {
    // Insert after the current block.
    const insertAfter = $pos.depth > 0 ? $pos.after($pos.depth) : $pos.pos;
    const tr = view.state.tr.insert(insertAfter, node);
    view.dispatch(tr.scrollIntoView());
  }
}

/**
 * Show a picture that is already stored, at the caret. Nothing is uploaded:
 * the note points at the same blob the Files pillar holds, and the garbage
 * collector keeps a blob while any note still names it (imageGC.ts,
 * findRefsInOtherNotes). Issue #330.
 */
export function insertPictureRef(view: EditorView, ref: MediaRef): void {
  placeImage(view, ref.src, ref.name, view.state.selection.to);
  view.focus();
}

/**
 * Public entry point for the toolbar file picker. Same pipeline as
 * paste/drop - process, encrypt, upload, insert.
 */
export async function triggerImageUpload(
  file: File,
  view: EditorView,
  pos: number,
): Promise<void> {
  return handleImageUpload(file, view, pos);
}

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

/** Image extensions for fallback detection when file.type is empty (mobile). */
const IMAGE_EXTENSIONS = new Set([
  'jpg', 'jpeg', 'png', 'webp', 'gif', 'bmp', 'tiff', 'tif', 'heic', 'heif',
]);

/**
 * Check if a File looks like an image. On mobile browsers, file.type is
 * often empty even for photos picked from the gallery - fall back to
 * extension check.
 */
function looksLikeImage(file: File): boolean {
  if (file.type.startsWith('image/')) return true;
  if (!file.type && file.name) {
    const ext = file.name.split('.').pop()?.toLowerCase() ?? '';
    return IMAGE_EXTENSIONS.has(ext);
  }
  return false;
}

// ------------------------------------------------------------------
// Helpers for recovering images from pasted HTML
// ------------------------------------------------------------------

/** Extract src attributes from <img> tags in an HTML string. */
function extractImgSrcsFromHtml(html: string): string[] {
  const srcs: string[] = [];
  const re = /<img[^>]+src=["']([^"']+)["'][^>]*\/?>/gi;
  let match: RegExpExecArray | null;
  while ((match = re.exec(html)) !== null) {
    const src = match[1];
    // Only collect non-pn: sources - our own encrypted images are fine.
    if (src && !isBlobRef(src)) {
      srcs.push(src);
    }
  }
  return srcs;
}

/**
 * Try to fetch an image URL and convert it to a File object.
 * Works for data: URLs and same-origin/CORS-allowed https: URLs.
 * Returns null for cross-origin blob: URLs or any fetch failure.
 */
async function fetchImageFromUrl(url: string): Promise<File | null> {
  try {
    const res = await fetch(url);
    if (!res.ok) return null;
    const blob = await res.blob();
    if (!blob.type.startsWith('image/')) return null;
    const ext = blob.type.split('/')[1] ?? 'png';
    return new File([blob], `pasted-image.${ext}`, { type: blob.type });
  } catch {
    // Expected for cross-origin blob: URLs - fail silently.
    return null;
  }
}

/**
 * Elements that still put something on the page with no text of their own.
 * An ancestor holding one of these is NOT empty once an image leaves it -
 * `<br>` above all, which is how a deliberately blank line arrives.
 */
const CONTENT_TAGS = 'br,hr,img,svg,video,audio,iframe,input,table';

/** True when nothing visible is left in `el` after an image was removed from it. */
function isEmptyAfterStrip(el: Element): boolean {
  return el.textContent.trim() === '' && el.querySelector(CONTENT_TAGS) === null;
}

/**
 * Strip <img> tags with non-pn: sources from pasted HTML, along with any
 * wrapper they leave behind empty. This is the safety net that prevents
 * broken image placeholders when the paste handler can't recover the actual
 * image data (e.g. blob: URLs from WhatsApp or other cross-origin apps).
 *
 * Removing the tag alone is not enough, and that is GitHub #204: an image
 * that was the only thing in its block leaves `<p></p>` behind, ProseMirror
 * reads that as an empty paragraph, and ParagraphWithMarkdown then writes it
 * to the note as `&nbsp;` (the encoding that lets deliberate blank lines
 * survive the markdown round-trip - see #101). The reporter saw one extra
 * blank line per stripped image and had to delete them by hand. It looked
 * source-dependent and unreproducible because it needs an image ALONE in its
 * block: an inline image beside text leaves the text behind, and a tracking
 * pixel outside any block leaves nothing to empty.
 *
 * The walk up the ancestors matters as much as the removal: web content wraps
 * images in links (`<p><a><img></a></p>`), so stripping only the image leaves
 * an empty `<a>` inside the paragraph, which still parses as an empty
 * paragraph. Elements carrying `<br>` are deliberately left alone, so a blank
 * line the user actually copied is never eaten.
 *
 * Pastes with no strippable image return the original string untouched, which
 * keeps every other paste byte-identical to before.
 *
 * Spec: GitHub #67 (images pasted from WhatsApp show broken previews),
 * GitHub #204 (extra blank line per pasted image)
 */
export function sanitizePastedHtml(html: string): string {
  if (!/<img/i.test(html)) return html;
  const doc = new DOMParser().parseFromString(html, 'text/html');
  const strays = Array.from(doc.querySelectorAll('img')).filter((img) => {
    // Either carrier counts as ours: markdown-it hands us the ref in `src`,
    // while the clipboard carries it in the data attribute renderHTML wrote
    // (its `src` is the placeholder GIF). Reading only `src` made a copied
    // image a stray and dropped it on paste. Fix: GitHub #239
    const ref = img.getAttribute(IMAGE_REF_ATTR) ?? img.getAttribute('src') ?? '';
    if (isBlobRef(ref)) return false;
    // A root-relative path is ours too: that is how the starter notes ship
    // their pictures. It is same-origin and already on the page, so there is
    // nothing to recover and nothing to strip - and dropping it meant a seed
    // image could not be moved around its own note either. A copy from a web
    // page never looks like this: browsers absolutize every src on the way to
    // the clipboard.
    return !(ref.startsWith('/') && !ref.startsWith('//'));
  });
  if (strays.length === 0) return html;

  for (const img of strays) {
    let parent = img.parentElement;
    img.remove();
    while (parent && parent !== doc.body && isEmptyAfterStrip(parent)) {
      const next: HTMLElement | null = parent.parentElement;
      parent.remove();
      parent = next;
    }
  }
  return doc.body.innerHTML;
}

// ------------------------------------------------------------------
// ProseMirror plugin for paste/drop interception
// ------------------------------------------------------------------

const imageUploadPluginKey = new PluginKey('imageUpload');

function createPlaceholderWidget(fileName: string): HTMLElement {
  const el = document.createElement('div');
  el.className = 'image-upload-placeholder';
  el.setAttribute('style', [
    'display:flex', 'align-items:center', 'gap:8px',
    'padding:12px 16px', 'margin:4px 0',
    'border-radius:8px', 'font-size:14px',
    'background:var(--color-surface-2,#f5f5f5)',
    'color:var(--color-text-secondary,#888)',
    'border:1px dashed var(--color-border,#ddd)',
  ].join(';'));
  // Spinner
  const spinner = document.createElement('div');
  spinner.setAttribute('style', [
    'width:18px', 'height:18px', 'flex-shrink:0',
    'border:2px solid currentColor', 'border-top-color:transparent',
    'border-radius:50%', 'animation:pn-spin 0.8s linear infinite',
  ].join(';'));
  el.appendChild(spinner);
  // Label
  const label = document.createElement('span');
  const name = fileName.length > 30 ? fileName.slice(0, 27) + '...' : fileName;
  label.textContent = i18n.t('media:image.uploading', { name });
  el.appendChild(label);
  return el;
}

function createImageUploadPlugin() {
  return new Plugin({
    key: imageUploadPluginKey,

    state: {
      init() {
        return DecorationSet.empty;
      },
      apply(tr, decoSet) {
        // Map existing decorations through document changes.
        decoSet = decoSet.map(tr.mapping, tr.doc);
        const meta = tr.getMeta(imageUploadPluginKey) as
          | { type: 'add'; id: string; pos: number; fileName: string }
          | { type: 'remove'; id: string }
          | undefined;
        if (!meta) return decoSet;
        if (meta.type === 'add') {
          const widget = Decoration.widget(meta.pos, createPlaceholderWidget(meta.fileName), {
            id: meta.id,
            side: 1,
          });
          return decoSet.add(tr.doc, [widget]);
        }
        if (meta.type === 'remove') {
          const toRemove = decoSet.find(undefined, undefined, (spec) => spec.id === meta.id);
          if (toRemove.length) return decoSet.remove(toRemove);
        }
        return decoSet;
      },
    },

    props: {
      decorations(state) {
        return imageUploadPluginKey.getState(state) as DecorationSet;
      },

      handleDrop(view, event) {
        if (!event.dataTransfer?.files?.length) return false;
        const files = Array.from(event.dataTransfer.files).filter((f) =>
          looksLikeImage(f),
        );
        if (files.length === 0) return false;

        event.preventDefault();
        const pos = view.posAtCoords({
          left: event.clientX,
          top: event.clientY,
        });
        const insertPos = pos?.pos ?? view.state.selection.from;

        for (const file of files) {
          void handleImageUpload(file, view, insertPos);
        }
        return true;
      },

      handlePaste(view, event) {
        const items = event.clipboardData?.items;
        if (!items) return false;

        const imageFiles: File[] = [];
        for (const item of Array.from(items)) {
          if (item.type.startsWith('image/')) {
            const file = item.getAsFile();
            if (file) imageFiles.push(file);
          }
        }

        if (imageFiles.length > 0) {
          event.preventDefault();
          const pos = view.state.selection.from;
          for (const file of imageFiles) {
            void handleImageUpload(file, view, pos);
          }
          return true;
        }

        // No image/* clipboard items - check if the HTML contains <img>
        // tags (e.g. paste from WhatsApp, Telegram, or other chat apps
        // that put blob:/data: URLs in clipboard HTML). Try to fetch
        // each image and upload it through our pipeline.
        const html = event.clipboardData?.getData('text/html');
        if (html) {
          const imgSrcs = extractImgSrcsFromHtml(html);
          if (imgSrcs.length > 0) {
            const pos = view.state.selection.from;
            // Fire-and-forget: try to recover images from HTML URLs.
            // blob: URLs from other origins will fail silently - the
            // transformPastedHTML safety net strips those <img> tags
            // so they never become broken nodes.
            for (const src of imgSrcs) {
              void fetchImageFromUrl(src).then((file) => {
                if (file) void handleImageUpload(file, view, pos);
              });
            }
            // Don't prevent default - let the sanitized HTML (text
            // without images) paste normally via transformPastedHTML.
          }
        }

        return false;
      },
    },
  });
}

// ------------------------------------------------------------------
// TipTap Extension
// ------------------------------------------------------------------

export const EncryptedImage = Node.create({
  name: 'image',
  group: 'block',
  atom: true,
  draggable: true,

  addAttributes() {
    return {
      src: {
        default: null,
        // renderHTML below swaps our `pn:img/<uuid>` ref out of `src` for a
        // placeholder, so `src` alone cannot be trusted to round-trip. Read
        // the ref back from the attribute that kept it. Fix: GitHub #239
        parseHTML: (el: HTMLElement) =>
          el.getAttribute(IMAGE_REF_ATTR) || el.getAttribute('src'),
      },
      alt: { default: null },
      title: { default: null },
      width: {
        default: 100,
        parseHTML: (el: HTMLElement) => {
          // Parse from data attribute (set by our markdown-it plugin below)
          // or from inline style width percentage.
          const dataW = el.getAttribute('data-width');
          if (dataW) {
            const n = parseInt(dataW, 10);
            if (IMAGE_WIDTHS.includes(n as ImageWidth)) return n;
          }
          const style = el.getAttribute('style') || '';
          const match = style.match(/width:\s*(\d+)%/);
          if (match) {
            const n = parseInt(match[1]!, 10);
            if (IMAGE_WIDTHS.includes(n as ImageWidth)) return n;
          }
          return 100;
        },
        renderHTML: (attrs: Record<string, unknown>) => {
          if (!attrs['width'] || attrs['width'] === 100) return {};
          return { 'data-width': String(attrs['width']) };
        },
      },
    };
  },

  parseHTML() {
    return [{ tag: 'img[src]' }];
  },

  renderHTML({ HTMLAttributes }: { HTMLAttributes: Record<string, string> }) {
    const attrs = mergeAttributes(HTMLAttributes);
    // Emit a transparent placeholder in the DOM so the browser never
    // tries to load the custom pn:img/ or pn:file/ scheme (which CSP blocks).
    // The React NodeView replaces this with the decrypted blob: URL.
    //
    // Keep the real ref in a data attribute on the way out. This is also
    // what the clipboard carries: copying an image serializes the node
    // through here, so with the ref only in `src` the clipboard held a
    // 1x1 GIF, sanitizePastedHtml threw it out as a foreign image, and
    // cut-and-paste inside a note silently did nothing (GitHub #239).
    if (typeof attrs.src === 'string' && isBlobRef(attrs.src)) {
      attrs[IMAGE_REF_ATTR] = attrs.src;
      attrs.src = 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';
    }
    return ['img', attrs];
  },

  addNodeView() {
    return ReactNodeViewRenderer(EncryptedImageView as never);
  },

  addProseMirrorPlugins() {
    return [createImageUploadPlugin()];
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
          node: {
            attrs: { src: string; alt: string; title: string; width: number; textAlign?: string };
          },
        ) {
          const alt = state.esc(node.attrs.alt || '');
          const src = state.esc(node.attrs.src || '');
          const title = node.attrs.title
            ? ` "${state.esc(node.attrs.title)}"`
            : '';
          // Append a `{width=N align=X}` suffix for anything that is not the
          // default, so size and alignment survive the markdown roundtrip.
          // Markdown-it turns it into <img data-width="N" style="text-align:X">
          // and the two parseHTML rules pick them back off (see the core rule
          // below). Alignment stays IN the markdown rather than taking the
          // raw-HTML escape hatch aligned prose needs: an image is one
          // self-contained token, so there is no inline content to lose, and
          // the export renderer keeps working on plain markdown.
          const attrs: string[] = [];
          if (node.attrs.width && node.attrs.width !== 100) attrs.push(`width=${node.attrs.width}`);
          const align = node.attrs.textAlign;
          if (align && align !== 'left') attrs.push(`align=${align}`);
          const suffix = attrs.length > 0 ? `{${attrs.join(' ')}}` : '';
          state.write(`![${alt}](${src}${title})${suffix}`);
          // closeBlock, NOT a trailing "\n" - see the same call in
          // EncryptedAttachment.tsx for what the bare newline cost. Two images
          // in a row hit it identically: consecutive lines became one paragraph
          // with a <br>, and the ghost <br>-paragraph left between them was two
          // lines of empty space that survived every reload.
          state.closeBlock(node);
        },
        parse: {
          // Register a markdown-it core rule that extracts the `{...}`
          // attribute block from the text token immediately following an
          // image token. `width=N` moves into data-width, which this node's
          // own parseHTML reads; `align=X` becomes an inline text-align
          // style, which is what the TextAlign extension's global attribute
          // parses. Both are dropped from the text so the braces never show.
          setup(md: {
            core: { ruler: { push: (name: string, fn: (state: { tokens: Array<{ type: string; children: Array<{ type: string; content: string; attrSet: (k: string, v: string) => void }> | null }> }) => void) => void } };
          }) {
            md.core.ruler.push('image_attrs', (state) => {
              for (const blockToken of state.tokens) {
                const children = blockToken.children;
                if (!children) continue;
                for (let i = 0; i < children.length - 1; i++) {
                  const cur = children[i]!;
                  const next = children[i + 1]!;
                  if (cur.type !== 'image' || next.type !== 'text') continue;
                  const block = next.content.match(/^\{([^}]*)\}/);
                  if (!block) continue;
                  const width = block[1]!.match(/\bwidth=(\d+)\b/);
                  const align = block[1]!.match(/\balign=(left|center|right|justify)\b/);
                  if (!width && !align) continue;
                  if (width) cur.attrSet('data-width', width[1]!);
                  if (align) cur.attrSet('style', `text-align: ${align[1]!}`);
                  next.content = next.content.slice(block[0]!.length);
                }
              }
            });
          },
        },
      },
    };
  },
});
