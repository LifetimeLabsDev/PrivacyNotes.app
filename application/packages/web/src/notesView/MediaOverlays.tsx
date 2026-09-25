import { useEffect, useRef, useState } from 'react';
import {
  listenForMediaViewer,
  listenForPicturePicker,
  type MediaRef,
  type PickerRequest,
  type ViewerRequest,
} from '../mediaRefs';
import { MediaViewer, PicturePicker } from './settingsCategories';

/**
 * The one place the picture viewer and the Files picture picker render.
 *
 * Whoever opens them - a chip, a picture in a note, a Files tile, a contact -
 * only sends a request (mediaRefs.ts). A node view can be torn down while its
 * viewer is still open, and a viewer owned by it would vanish mid-look.
 *
 * `getPickerItems` is read when the picker opens rather than passed as a
 * list, so the Files pictures are gathered only when somebody asks for them.
 */
export function MediaOverlays({ getPickerItems }: { getPickerItems: () => MediaRef[] }) {
  const [viewer, setViewer] = useState<{ req: ViewerRequest; id: number } | null>(null);
  const [picker, setPicker] = useState<{ req: PickerRequest; items: MediaRef[] } | null>(null);
  const getItemsRef = useRef(getPickerItems);
  getItemsRef.current = getPickerItems;

  // Each request gets its own viewer instance, so a second request starts at
  // its own item instead of inheriting the first one's position.
  useEffect(() => listenForMediaViewer((req) => setViewer((prev) => ({ req, id: (prev?.id ?? 0) + 1 }))), []);
  useEffect(() => listenForPicturePicker((req) => setPicker({ req, items: getItemsRef.current() })), []);

  return (
    <>
      {picker && (
        <PicturePicker
          items={picker.items}
          onPick={(ref) => {
            setPicker(null);
            picker.req.onPick(ref);
          }}
          onClose={() => setPicker(null)}
        />
      )}
      {viewer && (
        <MediaViewer
          key={viewer.id}
          items={viewer.req.items}
          index={viewer.req.index}
          onClose={(index) => {
            setViewer(null);
            viewer.req.onClose?.(index);
          }}
        />
      )}
    </>
  );
}
