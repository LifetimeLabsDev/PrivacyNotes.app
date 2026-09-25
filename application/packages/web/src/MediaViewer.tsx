/**
 * The shared viewer: one picture or PDF at a time, from the list that opened
 * it, on a stage that fills the window.
 *
 * Nothing on the stage takes its size from the item except the item itself.
 * The bar is pinned to the top of the window and the arrows to its sides, so
 * they hold still under the pointer while each picture or PDF takes the room
 * it needs. A picture is never scaled up, and no control sits on it: the
 * arrows have gutters of their own, and on a phone they move into the bar.
 *
 * Spec: ops/docs/ui-patterns.md (section 98, the picture viewer)
 */
import { lazy, Suspense, useCallback, useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { useTranslation } from 'react-i18next';
import { CaretLeft, CaretRight, Download, MagnifyingGlassMinus, MagnifyingGlassPlus, X } from './icons';
import { useEscapeToClose } from './useEscapeToClose';
import { HoverLabel, type positionClasses } from './HoverLabel';
import { loadAttachmentData } from './EncryptedAttachment';
import { canSaveMedia, loadPictureUrl, saveMedia } from './mediaUrls';
import { FILE_REF_PREFIX, isPdfRef, type MediaRef } from './mediaRefs';

const PdfPages = lazy(() => import('./PdfPages').then((m) => ({ default: m.PdfPages })));

/** PDF zoom steps, as multiples of the page at its fitted width. Pinch is off
 *  app-wide (`user-scalable=no`), so these are how a phone reads small print. */
const PDF_ZOOM_STEPS = [1, 1.5, 2, 3];

/** The widest a PDF page draws before any zoom, in CSS pixels: a page of text
 *  still reads in one glance, and the zoom steps go wider. */
const PDF_FIT_MAX = 872;

/** How far a finger travels sideways, in CSS pixels, before it is a swipe. */
const SWIPE_PX = 50;

/** How far a press may travel and still count as a tap on the backdrop. */
const TAP_SLOP_PX = 10;

function isRtl(): boolean {
  return document.documentElement.dir === 'rtl';
}

/** The empty stage around the item, marked `data-backdrop`. */
function isBackdrop(target: EventTarget | null): boolean {
  return target instanceof HTMLElement && target.dataset.backdrop !== undefined;
}

export function MediaViewer({ items, index: startIndex, onClose }: {
  items: MediaRef[];
  index: number;
  /** Told which item was on screen when the viewer closed. */
  onClose: (index: number) => void;
}) {
  const { t } = useTranslation('media');
  const [index, setIndex] = useState(startIndex);
  const [zoomStep, setZoomStep] = useState(0);
  const [saving, setSaving] = useState(false);
  // The item whose save failed. A failed native save can leave an empty or
  // partial file, so the message stays until a save succeeds; a dismissed
  // dialog changes nothing.
  const [failedSave, setFailedSave] = useState<string | null>(null);
  const stageRef = useRef<HTMLDivElement>(null);
  const backdropPress = useRef<{ x: number; y: number } | null>(null);
  const swipe = useRef<{ x: number; y: number; id: number } | null>(null);

  const item = items[index]!;
  const count = items.length;
  const pdf = isPdfRef(item);
  const title = item.name || (pdf ? 'PDF' : t('attachment.imageAlt'));

  const close = useCallback(() => onClose(index), [onClose, index]);
  useEscapeToClose(close);

  const go = useCallback((delta: number) => {
    setIndex((i) => Math.min(count - 1, Math.max(0, i + delta)));
    setZoomStep(0);
  }, [count]);

  // The arrow keys move through the list. In a right-to-left layout the list
  // runs leftward, so the keys follow the arrows drawn on screen.
  useEffect(() => {
    if (count < 2) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
      if (e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      e.preventDefault();
      e.stopPropagation();
      go((e.key === 'ArrowRight') !== isRtl() ? 1 : -1);
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [count, go]);

  // Focus moves into the dialog, and back to whatever held it on close.
  useEffect(() => {
    const before = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    stageRef.current?.focus({ preventScroll: true });
    return () => before?.focus({ preventScroll: true });
  }, []);

  // The neighbours decrypt in the background, so an arrow answers at once.
  useEffect(() => {
    for (const i of [index - 1, index + 1]) {
      const near = items[i];
      if (near && !isPdfRef(near)) void loadPictureUrl(near.src);
    }
  }, [index, items]);

  const loadPdf = useCallback(async () => {
    if (!item.src.startsWith(FILE_REF_PREFIX)) return null;
    const att = await loadAttachmentData(item.src.slice(FILE_REF_PREFIX.length));
    // pdf.js takes ownership of the bytes it is given, so it gets a copy.
    return att ? new Uint8Array(att.data) : null;
  }, [item.src]);

  const save = useCallback(async () => {
    setSaving(true);
    try {
      const saved = await saveMedia(item);
      if (saved?.ok) setFailedSave(null);
      else if (saved?.reason === 'failed') setFailedSave(item.src);
    } finally {
      setSaving(false);
    }
  }, [item]);

  // A swipe is a finger's gesture; a mouse drag over a picture is not one.
  const onPointerDown = (e: React.PointerEvent) => {
    swipe.current = e.pointerType === 'mouse' || count < 2
      ? null
      : { x: e.clientX, y: e.clientY, id: e.pointerId };
  };
  const onPointerUp = (e: React.PointerEvent) => {
    const start = swipe.current;
    swipe.current = null;
    if (!start || start.id !== e.pointerId) return;
    const dx = e.clientX - start.x;
    const dy = e.clientY - start.y;
    if (Math.abs(dx) < SWIPE_PX || Math.abs(dx) < Math.abs(dy)) return;
    // Pulling the picture leftward shows the next one, mirrored for RTL.
    go((dx < 0) !== isRtl() ? 1 : -1);
  };

  const previous = (tip: keyof typeof positionClasses, edge: boolean) => (
    <StageButton label={t('viewer.previous')} tip={tip} edge={edge} disabled={index === 0} onClick={() => go(-1)}>
      <CaretLeft size={edge ? 22 : 18} />
    </StageButton>
  );
  const next = (tip: keyof typeof positionClasses, edge: boolean) => (
    <StageButton label={t('viewer.next')} tip={tip} edge={edge} disabled={index === count - 1} onClick={() => go(1)}>
      <CaretRight size={edge ? 22 : 18} />
    </StageButton>
  );

  return createPortal(
    <div
      ref={stageRef}
      tabIndex={-1}
      role="dialog"
      aria-modal="true"
      aria-label={title}
      data-no-app-menu=""
      data-backdrop=""
      // A tap on the empty stage closes it, and only a tap: a swipe that
      // starts beside the picture, or a press that ends on a button, does not.
      onPointerDown={(e) => {
        backdropPress.current = isBackdrop(e.target) ? { x: e.clientX, y: e.clientY } : null;
      }}
      onClick={(e) => {
        const press = backdropPress.current;
        backdropPress.current = null;
        if (!press || !isBackdrop(e.target)) return;
        if (Math.hypot(e.clientX - press.x, e.clientY - press.y) > TAP_SLOP_PX) return;
        close();
      }}
      className="fixed inset-0 z-50 flex flex-col bg-black/95 text-white outline-none"
    >
      <div className="shrink-0 pt-[env(safe-area-inset-top)]">
        <div className="h-14 flex items-center gap-1 px-2 sm:px-4">
          <h2 className="flex-1 min-w-0 px-2 text-sm font-medium truncate" dir="auto">{title}</h2>
          {pdf && (
            <div className="shrink-0 flex items-center">
              <StageButton
                label={t('viewer.zoomOut')}
                disabled={zoomStep === 0}
                onClick={() => setZoomStep((z) => Math.max(0, z - 1))}
              >
                <MagnifyingGlassMinus size={18} />
              </StageButton>
              <StageButton
                label={t('viewer.zoomIn')}
                disabled={zoomStep === PDF_ZOOM_STEPS.length - 1}
                onClick={() => setZoomStep((z) => Math.min(PDF_ZOOM_STEPS.length - 1, z + 1))}
              >
                <MagnifyingGlassPlus size={18} />
              </StageButton>
            </div>
          )}
          {count > 1 && (
            <div className="shrink-0 flex items-center">
              <span className="sm:hidden">{previous('below', false)}</span>
              <span className="px-1.5 text-xs tabular-nums text-white/60 whitespace-nowrap">
                {t('viewer.position', { index: index + 1, count })}
              </span>
              <span className="sm:hidden">{next('below', false)}</span>
            </div>
          )}
          {canSaveMedia(item) && (
            <StageButton label={t('attachment.download')} disabled={saving} onClick={() => void save()}>
              <Download size={18} />
            </StageButton>
          )}
          <StageButton label={t('common:actions.close')} tip="below-end" onClick={close}>
            <X size={20} />
          </StageButton>
        </div>
        {failedSave === item.src && (
          <p className="px-4 pb-2 text-xs text-red-400">{t('viewer.saveFailed')}</p>
        )}
      </div>
      <div data-backdrop="" className="flex-1 min-h-0 flex pb-[max(1rem,env(safe-area-inset-bottom))]">
        <div data-backdrop="" className="hidden sm:flex w-16 shrink-0 items-center justify-center">
          {count > 1 && previous('end', true)}
        </div>
        <div data-backdrop="" className="flex-1 min-w-0 min-h-0">
          {pdf ? (
            <Suspense fallback={<Notice text={t('viewer.pdfLoading')} />}>
              <PdfPages
                key={item.src}
                load={loadPdf}
                zoom={PDF_ZOOM_STEPS[zoomStep]!}
                fitMax={PDF_FIT_MAX}
                label={title}
              />
            </Suspense>
          ) : (
            <Picture
              key={item.src}
              src={item.src}
              alt={title}
              swipeable={count > 1}
              onPointerDown={onPointerDown}
              onPointerUp={onPointerUp}
              onPointerCancel={() => { swipe.current = null; }}
            />
          )}
        </div>
        <div data-backdrop="" className="hidden sm:flex w-16 shrink-0 items-center justify-center">
          {count > 1 && next('start', true)}
        </div>
      </div>
    </div>,
    document.body,
  );
}

/** A control on the stage: a square in the bar, or a round arrow in a gutter. */
function StageButton({ label, tip = 'below', edge = false, disabled = false, onClick, children }: {
  label: string;
  tip?: keyof typeof positionClasses;
  edge?: boolean;
  disabled?: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <HoverLabel label={label} position={tip}>
      <button
        type="button"
        onClick={onClick}
        disabled={disabled}
        aria-label={label}
        className={`flex items-center justify-center text-white/80 hover:text-white transition outline-none focus-visible:ring-2 focus-visible:ring-white/70 disabled:opacity-30 disabled:pointer-events-none ${
          edge ? 'w-11 h-11 rounded-full bg-white/10 hover:bg-white/20' : 'w-9 h-9 rounded-md hover:bg-white/10'
        }`}
      >
        {children}
      </button>
    </HoverLabel>
  );
}

function Notice({ text }: { text: string }) {
  return (
    <div className="h-full flex items-center justify-center p-6 text-sm text-center text-white/70">
      {text}
    </div>
  );
}

/**
 * The picture at its stored size, shrunk to fit the stage and never scaled
 * up. The area around it is backdrop, so a tap beside a small picture closes
 * the viewer the way a tap on the stage does.
 */
function Picture({ src, alt, swipeable, onPointerDown, onPointerUp, onPointerCancel }: {
  src: string;
  alt: string;
  swipeable: boolean;
  onPointerDown: (e: React.PointerEvent) => void;
  onPointerUp: (e: React.PointerEvent) => void;
  onPointerCancel: () => void;
}) {
  const { t } = useTranslation('media');
  const [url, setUrl] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let alive = true;
    void loadPictureUrl(src).then((u) => {
      if (!alive) return;
      if (u) setUrl(u);
      else setFailed(true);
    });
    return () => { alive = false; };
  }, [src]);

  return (
    <div
      data-backdrop=""
      onPointerDown={onPointerDown}
      onPointerUp={onPointerUp}
      onPointerCancel={onPointerCancel}
      // touch-none hands every finger movement here to the swipe handler.
      className={`h-full flex items-center justify-center select-none ${swipeable ? 'touch-none' : ''}`}
    >
      {url ? (
        <img src={url} alt={alt} className="block max-w-full max-h-full" draggable={false} />
      ) : (
        <Notice text={failed ? t('image.notFound') : t('image.loading')} />
      )}
    </div>
  );
}
