/**
 * The geometry of a zoomed picture in the viewer. The picture is laid out
 * once at its largest size and shown through one transform, so a pinch frame
 * changes no layout and no scroll position; iOS shows those a frame late,
 * which made the scroll-based zoom jitter under the fingers.
 * Spec: ops/docs/plans/viewer-pinch-zoom.md
 */

/** Where the picture sits: its zoom, and the stage pixel of its top left corner. */
export type ZoomView = { zoom: number; tx: number; ty: number };
export type Size = { w: number; h: number };

/**
 * The layout size: the picture fitted to the stage, never scaled up, times
 * the largest zoom. Every zoom then scales it down, so it stays sharp.
 */
export function fittedBase(natural: Size, box: Size, maxZoom: number): Size {
  const fit = Math.min(1, box.w / natural.w, box.h / natural.h);
  return { w: natural.w * fit * maxZoom, h: natural.h * fit * maxZoom };
}

/** Zooms to `zoom`, keeping the picture point under stage pixel (px, py) still. */
export function zoomAround(v: ZoomView, px: number, py: number, zoom: number): ZoomView {
  const k = zoom / v.zoom;
  return { zoom, tx: px - (px - v.tx) * k, ty: py - (py - v.ty) * k };
}

/** Centers an axis the picture does not fill, and keeps every edge of one it overflows reachable. */
export function clampPan(v: ZoomView, box: Size, base: Size, maxZoom: number): ZoomView {
  const s = v.zoom / maxZoom;
  const w = base.w * s;
  const h = base.h * s;
  return {
    zoom: v.zoom,
    tx: w <= box.w ? (box.w - w) / 2 : Math.min(0, Math.max(box.w - w, v.tx)),
    ty: h <= box.h ? (box.h - h) / 2 : Math.min(0, Math.max(box.h - h, v.ty)),
  };
}

export function toTransform(v: ZoomView, maxZoom: number): string {
  return `translate3d(${v.tx}px, ${v.ty}px, 0) scale(${v.zoom / maxZoom})`;
}
