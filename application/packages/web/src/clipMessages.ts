/**
 * The words of the web clipper that the bookmark pane, the Clip page window
 * and the clip hook share: the labels a clip writes into its note, the
 * result line and the message for each failure. A module of its own, so the
 * lazily loaded window does not pull the hook's chunk apart.
 * Spec: ops/docs/archive/web-clipper-stage1.md (section 5.4)
 */
import i18n from './i18n';
import { formatInstant } from './intlFormat';
import type { ClipErrorReason } from './clipDownload';
import type { SavedClip } from './clipPage';

/** A clip that is running: downloading the page, or saving its pictures. */
export interface ClipJob {
  step: 'page' | 'pictures';
  done: number;
  total: number;
}

/** A line a bookmark or the window shows after a clip. `signUp` adds the
 *  demo's sign-up button. */
export interface ClipNotice {
  text: string;
  signUp?: boolean;
}

/** Whether a clip saves the page's pictures. Remembered on this device, the
 *  way the outline panel is; on until the person switches it off. */
const PICTURES_KEY = 'privacynotes.clip.pictures';

export function readClipPictures(): boolean {
  try {
    return localStorage.getItem(PICTURES_KEY) !== '0';
  } catch {
    return true;
  }
}

export function writeClipPictures(on: boolean): void {
  try {
    localStorage.setItem(PICTURES_KEY, on ? '1' : '0');
  } catch {
    // The choice is not remembered; this clip still uses it.
  }
}

/** The words a clip's result and the date line use, in the reader's language. */
export function clipLabels() {
  return {
    source: i18n.t('shell:clipper.sourceLabel'),
    image: i18n.t('shell:clipper.imageLabel'),
    formatDate: (d: Date) => formatInstant(d, 'date'),
  };
}

export function resultText(saved: SavedClip): string {
  if (saved.storageFull > 0) return i18n.t('shell:clipper.storageFull', { count: saved.storageFull + saved.failed });
  if (saved.failed > 0) return i18n.t('shell:clipper.somePicturesFailed', { count: saved.failed });
  return i18n.t('shell:clipper.saved');
}

/** The message for a download that failed, on a bookmark or in the window. */
export function noticeFor(reason: ClipErrorReason): ClipNotice {
  switch (reason) {
    case 'blocked':
      return { text: i18n.t('shell:clipper.blocked') };
    case 'offline':
      return { text: i18n.t('shell:clipper.offline') };
    case 'timeout':
      return { text: i18n.t('shell:clipper.timeout') };
    case 'demo-limit':
      return { text: i18n.t('shell:clipper.demoLimit'), signUp: true };
    case 'limit':
      return { text: i18n.t('shell:clipper.rateLimit') };
    case 'too-large':
      return { text: i18n.t('shell:clipper.tooLong') };
    case 'wrong-type':
      return { text: i18n.t('shell:clipper.notAPage') };
    case 'refused':
      return { text: i18n.t('shell:clipper.refused') };
    default:
      return { text: i18n.t('shell:clipper.failed') };
  }
}
