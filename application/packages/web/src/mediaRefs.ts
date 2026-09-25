/**
 * What the shared viewer can show, and the two requests that open it and the
 * Files picture picker.
 *
 * A reference is the `src` a note already stores: `pn:img/<uuid>` for a
 * picture written into a note, `pn:file/<uuid>` for an attachment, or a plain
 * path or URL, which is how the starter notes and a Markdown folder carry
 * their pictures. The viewer resolves it the same way the note does, so
 * nothing reaches the viewer that the note itself would not render.
 *
 * The viewer moves through the list that opened it, and that list holds only
 * what the viewer can show: pictures and PDFs. A recording keeps its player in
 * the chip, and any other file keeps its Download button.
 *
 * Spec: ops/docs/ui-patterns.md (section 98, the picture viewer)
 */
import type { Node as PMNode } from '@tiptap/pm/model';

export type MediaRef = {
  /** What the note stores: `pn:img/<uuid>`, `pn:file/<uuid>`, or a path. */
  src: string;
  /** Shown in the viewer header; empty when the note records none. */
  name: string;
  /** The recorded MIME type, or '' for a picture node, which carries none. */
  mime: string;
};

export const IMAGE_REF_PREFIX = 'pn:img/';
export const FILE_REF_PREFIX = 'pn:file/';

/**
 * Formats every browser we ship on draws in an `<img>`. HEIC and TIFF are not
 * here: Chromium cannot draw them, and the upload pipeline re-encodes both
 * before they are stored, so only a file stored before that pipeline existed
 * carries one.
 */
const PICTURE_MIMES = new Set([
  'image/jpeg',
  'image/png',
  'image/gif',
  'image/webp',
  'image/avif',
  'image/bmp',
  'image/svg+xml',
]);

export function isPictureMime(mime: string): boolean {
  return PICTURE_MIMES.has(mime.split(';')[0]!.trim().toLowerCase());
}

/** A PDF, by type, or by name when the platform stored no type. */
export function isPdf(mime: string, name: string): boolean {
  const type = mime.split(';')[0]!.trim().toLowerCase();
  if (type === 'application/pdf') return true;
  return (type === '' || type === 'application/octet-stream') && /\.pdf$/i.test(name.trim());
}

export function isPdfRef(ref: MediaRef): boolean {
  return ref.src.startsWith(FILE_REF_PREFIX) && isPdf(ref.mime, ref.name);
}

/**
 * Every picture and PDF in a note, in document order, beside the position of
 * each node. The position is what a node view knows about itself, and it tells
 * two references to one stored file apart, which the uuid cannot.
 */
export function mediaInDoc(doc: PMNode): { refs: MediaRef[]; positions: number[] } {
  const refs: MediaRef[] = [];
  const positions: number[] = [];
  doc.descendants((node, pos) => {
    const name = node.type.name;
    if (name === 'image') {
      const src = typeof node.attrs.src === 'string' ? node.attrs.src : '';
      if (src) {
        refs.push({ src, name: typeof node.attrs.alt === 'string' ? node.attrs.alt : '', mime: '' });
        positions.push(pos);
      }
      return false;
    }
    if (name === 'attachment') {
      const src = typeof node.attrs.src === 'string' ? node.attrs.src : '';
      const mime = typeof node.attrs.mimetype === 'string' ? node.attrs.mimetype : '';
      const file = typeof node.attrs.filename === 'string' ? node.attrs.filename : '';
      if (src.startsWith(FILE_REF_PREFIX) && (isPictureMime(mime) || isPdf(mime, file))) {
        refs.push({ src, name: file, mime });
        positions.push(pos);
      }
      return false;
    }
    return true;
  });
  return { refs, positions };
}

// ── Requests ────────────────────────────────────────────────────────
//
// A node view, the Files list and a contact all open the same viewer, and a
// node view can be torn down while its viewer is still open. So the viewer is
// not rendered by whoever asks for it: one host in NotesView listens here and
// owns it.

export type ViewerRequest = {
  items: MediaRef[];
  index: number;
  /** Told which item was on screen when the viewer closed. */
  onClose?: (index: number) => void;
};

export type PickerRequest = {
  onPick: (ref: MediaRef) => void;
};

let viewerListener: ((req: ViewerRequest) => void) | null = null;
let pickerListener: ((req: PickerRequest) => void) | null = null;

export function openMediaViewer(req: ViewerRequest): void {
  if (req.items.length === 0 || !req.items[req.index]) return;
  viewerListener?.(req);
}

/** Open the viewer on the node at `pos`, moving through the rest of its note. */
export function openMediaViewerInDoc(doc: PMNode, pos: number): void {
  const { refs, positions } = mediaInDoc(doc);
  const index = positions.indexOf(pos);
  if (index >= 0) openMediaViewer({ items: refs, index });
}

export function openPicturePicker(req: PickerRequest): void {
  pickerListener?.(req);
}

export function listenForMediaViewer(listener: (req: ViewerRequest) => void): () => void {
  viewerListener = listener;
  return () => {
    if (viewerListener === listener) viewerListener = null;
  };
}

export function listenForPicturePicker(listener: (req: PickerRequest) => void): () => void {
  pickerListener = listener;
  return () => {
    if (pickerListener === listener) pickerListener = null;
  };
}
