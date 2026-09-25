/**
 * PDF rendering for the shared viewer and the file card, on pdf.js.
 *
 * This module is the only importer of pdf.js, and every caller reaches it
 * through a dynamic import, so the library is fetched the first time somebody
 * opens a PDF and never on the way to the first render.
 *
 * Three decisions, each measured against what the app ships on:
 * - The LEGACY build. The modern one calls newer built-ins than the WebKit on
 *   our oldest supported iOS and macOS provides.
 * - No WebAssembly. Our content security policy does not allow it, so the
 *   JBIG2 and JPEG 2000 decoders that scanned documents use run from the
 *   JavaScript fallbacks the build copies to `pdfjs/<version>/`
 *   (vite.config.ts, pdfjsDecoders).
 * - Pages are drawn onto canvases, one per page, only while a page is near
 *   the screen. No text or link layer: a PDF is read here, not clicked
 *   through, so nothing inside one can navigate the app.
 *
 * Spec: ops/docs/ui-patterns.md (section 98, the picture viewer)
 */
import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  GlobalWorkerOptions,
  PDFWorker,
  getDocument,
  version as pdfjsVersion,
  type PDFDocumentProxy,
  type RenderTask,
} from 'pdfjs-dist/legacy/build/pdf.mjs';
import workerUrl from 'pdfjs-dist/legacy/build/pdf.worker.min.mjs?url';
import { cachedPdfCover, loadPdfCover, type PdfCoverImage } from './EncryptedAttachment';
import { useNearScreen } from './useNearScreen';

GlobalWorkerOptions.workerSrc = workerUrl;

/**
 * One worker for every document, the viewer's and each cover's. Without it
 * each `getDocument` starts a worker of its own, so a note of many PDFs would
 * run one per file at once. Made on first use, so importing this module starts
 * nothing, and kept for the session: destroying a document leaves a worker it
 * was handed running.
 */
let sharedWorker: PDFWorker | null = null;

function pdfWorker(): PDFWorker {
  sharedWorker ??= new PDFWorker();
  return sharedWorker;
}

/** Where the build puts the image decoders. The version is in the path, so a
 *  new pdf.js never meets a decoder cached from the old one. */
function decoderDir(): string {
  return new URL(`pdfjs/${pdfjsVersion}/`, document.baseURI).href;
}

/**
 * The largest canvas one page may use, in device pixels. iOS refuses a canvas
 * much past this, and a zoomed page on a wide screen would otherwise ask for
 * several times the memory it can show.
 */
const MAX_CANVAS_PIXELS = 16_000_000;

export type PdfLoader = () => Promise<Uint8Array | null>;

type Opened =
  | { status: 'loading' }
  | { status: 'ready'; doc: PDFDocumentProxy }
  | { status: 'password' }
  | { status: 'failed' };

/**
 * Open a document. The bytes are handed to the worker, so pass a copy. One
 * that will not open is closed here, because its caller never receives the
 * task, and a locked PDF would otherwise stay in the shared worker for the
 * session, once for every chip that asks for its cover again.
 */
async function openPdf(bytes: Uint8Array) {
  const task = getDocument({
    data: bytes,
    worker: pdfWorker(),
    useWasm: false,
    wasmUrl: decoderDir(),
  });
  try {
    return { task, doc: await task.promise };
  } catch (err) {
    void task.destroy();
    throw err;
  }
}

function failureStatus(err: unknown): 'password' | 'failed' {
  return err instanceof Error && err.name === 'PasswordException' ? 'password' : 'failed';
}

/** Draw one page onto a canvas at `cssWidth` CSS pixels. */
function drawPage(
  doc: PDFDocumentProxy,
  pageNumber: number,
  canvas: HTMLCanvasElement,
  cssWidth: number,
  onAspect: (aspect: number) => void,
): { promise: Promise<void>; cancel: () => void } {
  let task: RenderTask | null = null;
  let cancelled = false;
  const promise = (async () => {
    const page = await doc.getPage(pageNumber);
    if (cancelled) return;
    const base = page.getViewport({ scale: 1 });
    onAspect(base.height / base.width);
    let scale = (cssWidth * (window.devicePixelRatio || 1)) / base.width;
    const area = base.width * base.height * scale * scale;
    if (area > MAX_CANVAS_PIXELS) scale *= Math.sqrt(MAX_CANVAS_PIXELS / area);
    const viewport = page.getViewport({ scale });
    canvas.width = Math.floor(viewport.width);
    canvas.height = Math.floor(viewport.height);
    task = page.render({ canvas, viewport });
    await task.promise;
  })();
  return {
    promise: promise.catch(() => {}),
    cancel: () => {
      cancelled = true;
      task?.cancel();
    },
  };
}

// ── The viewer: every page, drawn as it nears the screen ────────────

export function PdfPages({ load, zoom, fitMax = Infinity, label }: {
  load: PdfLoader;
  /** 1 fits the page to the pane; larger values scroll sideways. */
  zoom: number;
  /** The widest a page draws at zoom 1, in CSS pixels. */
  fitMax?: number;
  /** The file name, for each page's accessible label. */
  label: string;
}) {
  const { t } = useTranslation('media');
  const scrollRef = useRef<HTMLDivElement>(null);
  // The viewer mounts one of these per file (it is keyed by the file), so the
  // loader is read once; a ref keeps a new closure from reopening the file.
  const loadRef = useRef(load);
  loadRef.current = load;
  const [opened, setOpened] = useState<Opened>({ status: 'loading' });
  const [fitWidth, setFitWidth] = useState(0);
  // The first page's shape stands in for every page until each one is drawn,
  // so the scroll height is close to right before anything renders.
  const [firstAspect, setFirstAspect] = useState(Math.SQRT2);

  useEffect(() => {
    let alive = true;
    let destroy: (() => void) | null = null;
    void (async () => {
      try {
        const bytes = await loadRef.current();
        if (!alive) return;
        if (!bytes) { setOpened({ status: 'failed' }); return; }
        const { task, doc } = await openPdf(bytes);
        destroy = () => { void task.destroy(); };
        if (!alive) { destroy(); return; }
        const first = await doc.getPage(1);
        const base = first.getViewport({ scale: 1 });
        if (!alive) return;
        setFirstAspect(base.height / base.width);
        setOpened({ status: 'ready', doc });
      } catch (err) {
        if (alive) setOpened({ status: failureStatus(err) });
      }
    })();
    return () => {
      alive = false;
      destroy?.();
    };
  }, []);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const measure = () => setFitWidth(el.clientWidth);
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // 12px of gutter on each side at fit, so a page never touches the frame.
  const cssWidth = Math.max(0, Math.floor(Math.min(fitWidth - 24, fitMax) * zoom));

  // No background of its own: the pages sit on the viewer's dark stage.
  return (
    <div ref={scrollRef} className="h-full overflow-auto">
      {opened.status === 'ready' ? (
        <div className="flex flex-col items-center gap-3 p-3 w-max min-w-full">
          {Array.from({ length: opened.doc.numPages }, (_, i) => (
            <PdfPage
              key={i}
              doc={opened.doc}
              pageNumber={i + 1}
              cssWidth={cssWidth}
              initialAspect={firstAspect}
              root={scrollRef}
              label={t('viewer.pageLabel', { name: label, page: i + 1, count: opened.doc.numPages })}
            />
          ))}
        </div>
      ) : (
        <div className="h-full flex items-center justify-center p-6 text-sm text-white/70 text-center">
          {opened.status === 'loading'
            ? t('viewer.pdfLoading')
            : opened.status === 'password'
              ? t('viewer.pdfPassword')
              : t('viewer.pdfFailed')}
        </div>
      )}
    </div>
  );
}

function PdfPage({ doc, pageNumber, cssWidth, initialAspect, root, label }: {
  doc: PDFDocumentProxy;
  pageNumber: number;
  cssWidth: number;
  initialAspect: number;
  root: React.RefObject<HTMLDivElement | null>;
  label: string;
}) {
  const holderRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [aspect, setAspect] = useState(initialAspect);
  const [near, setNear] = useState(false);

  useEffect(() => {
    const el = holderRef.current;
    if (!el) return;
    // A screen's height of margin above and below: drawn just before it is
    // seen, and let go once it is a screen away.
    const io = new IntersectionObserver(
      (entries) => setNear(entries.some((e) => e.isIntersecting)),
      { root: root.current, rootMargin: '100% 0px' },
    );
    io.observe(el);
    return () => io.disconnect();
  }, [root]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    if (!near || cssWidth <= 0) {
      // Width 0 releases the backing store; an off-screen page costs nothing.
      canvas.width = 0;
      canvas.height = 0;
      return;
    }
    const draw = drawPage(doc, pageNumber, canvas, cssWidth, setAspect);
    return () => draw.cancel();
  }, [doc, pageNumber, cssWidth, near]);

  return (
    <div
      ref={holderRef}
      className="shrink-0 bg-white shadow-sm"
      style={{ width: cssWidth || undefined, aspectRatio: `1 / ${aspect}` }}
    >
      <canvas ref={canvasRef} role="img" aria-label={label} className="block w-full h-full" />
    </div>
  );
}

// ── The first page as a picture: the file card, the chip and Files ─────

/** Pixel width the cover is drawn at: sharp on a phone at 2x and on a
 *  desktop note column at 1x, and a fraction of a full page's memory. */
const COVER_WIDTH_PX = 900;

/** The first page as a PNG, with the page count. One per file per session:
 *  the cache lives beside the attachment URLs (`loadPdfCover`). */
export async function drawCover(bytes: Uint8Array): Promise<PdfCoverImage> {
  const { task, doc } = await openPdf(bytes);
  try {
    const page = await doc.getPage(1);
    const base = page.getViewport({ scale: 1 });
    const viewport = page.getViewport({ scale: COVER_WIDTH_PX / base.width });
    const canvas = document.createElement('canvas');
    canvas.width = Math.floor(viewport.width);
    canvas.height = Math.floor(viewport.height);
    await page.render({ canvas, viewport }).promise;
    const blob = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, 'image/png'));
    if (!blob) throw new Error('cover');
    return { url: URL.createObjectURL(blob), pages: doc.numPages };
  } finally {
    void task.destroy();
  }
}

export function PdfCover({ uuid, name }: { uuid: string; name: string }) {
  const { t } = useTranslation('media');
  const [cover, setCover] = useState<PdfCoverImage | null>(() => cachedPdfCover(uuid));
  const [failed, setFailed] = useState<'password' | 'failed' | null>(null);
  // Read and drawn once the card comes near the screen, like the chip's tile:
  // a card further down a long note may never be looked at.
  const placeholderRef = useRef<HTMLSpanElement>(null);
  const near = useNearScreen(placeholderRef, !cover && !failed);

  useEffect(() => {
    if (!near || cachedPdfCover(uuid)) return;
    let alive = true;
    loadPdfCover(uuid).then(
      (drawn) => { if (alive) setCover(drawn); },
      (err: unknown) => { if (alive) setFailed(failureStatus(err)); },
    );
    return () => { alive = false; };
  }, [near, uuid]);

  // Spans, because the file card renders this inside a button.
  if (failed) {
    return (
      <span className="block px-4 py-8 text-sm text-center text-neutral-500 dark:text-neutral-400">
        {failed === 'password' ? t('viewer.pdfPassword') : t('viewer.pdfFailed')}
      </span>
    );
  }
  if (!cover) {
    return (
      <span ref={placeholderRef} className="block px-4 py-16 text-sm text-center text-neutral-400 dark:text-neutral-500">
        {t('viewer.pdfLoading')}
      </span>
    );
  }
  return (
    <span className="relative flex justify-center p-3">
      <span className="relative block">
        <img
          src={cover.url}
          alt={name}
          draggable={false}
          className="block max-w-full max-h-[60vh] !my-0 bg-white shadow-sm"
        />
        <span className="absolute bottom-2 end-2 rounded-md bg-black/60 text-white text-[11px] font-medium px-1.5 py-0.5">
          {t('viewer.pageCount', { count: cover.pages })}
        </span>
      </span>
    </span>
  );
}
