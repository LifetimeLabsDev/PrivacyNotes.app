/**
 * Where the Markdown folder can actually work, and what to show where it cannot.
 *
 * Three states rather than a boolean, because "not supported" splits into two
 * genuinely different situations. A desktop browser that lacks the API has a
 * fix we want to sell (install the app); a phone does not, and dangling a
 * desktop download in front of a phone user is noise.
 *
 * Gate on the capability, never on the user agent. The File System Access API
 * is the whole feature on web, so asking whether it exists is both the honest
 * question and the one that stays correct when Safari or Firefox ship it.
 *
 * Spec: ops/docs/plans/markdown-folder.md (section 5, platform matrix)
 */
import { detectPlatform } from '../devices';

export type MarkdownSupport =
  /** Full feature: open a folder, open a file, save in place. */
  | 'supported'
  /** Brave desktop, which has the API and ships it switched off. One flag away
   *  from `supported`, so it gets the flag rather than a download pitch. */
  | 'needs-brave-flag'
  /** Desktop browser without the API. Show the entry and sell the app - hiding
   *  it just produces "where is it" tickets once one user tells another. */
  | 'needs-desktop-app'
  /** Phones. No API, and no desktop build to offer, so the entry is hidden. */
  | 'unavailable';

/**
 * Where Brave hides the switch. Not a link: Chromium refuses page-initiated
 * navigation to `brave://`, so an anchor here would look clickable and do
 * nothing. The UI renders it as text to copy.
 */
// Spec: ops/docs/plans/markdown-folder.md (section 5, the Brave row)
export const BRAVE_FLAG_URL = 'brave://flags/#file-system-access-api';

/**
 * What the switch is called on that page, verbatim.
 *
 * A constant rather than a translatable string, and interpolated into the copy
 * as `{{flag}}`, because Brave hardcodes this label as an English C++ literal
 * in `about_flags.cc` (`kFileSystemAccessAPIName`) rather than a translated
 * resource - flags are developer-facing and Chromium never localizes them. A
 * German user reading German instructions still hunts for these four English
 * words, so a translated form would send them looking for something that is not
 * there. `check:locales` enforces placeholder parity, which means no catalog can
 * drop or reword it without failing CI.
 */
// Spec: ops/docs/plans/markdown-folder.md (section 5, the Brave row)
export const BRAVE_FLAG_NAME = 'File System Access API';

export function markdownSupport(): MarkdownSupport {
  const platform = detectPlatform();

  // The native desktop app talks to the filesystem through Tauri's fs plugin,
  // so it never depends on a browser API.
  if (platform === 'desktop') return 'supported';

  // The mobile apps are sandboxed: iOS needs security-scoped bookmarks that the
  // fs plugin does not expose, and Android SAF is its own project.
  if (platform === 'ios' || platform === 'android') return 'unavailable';

  if (typeof window !== 'undefined' && 'showDirectoryPicker' in window) return 'supported';

  // Past this line the feature is off, and the only question left is which of
  // the three "no" messages to show. That is a question about the browser, not
  // about the capability, so the sniffing below does not weaken the gate above.

  // `showDirectoryPicker` has never existed on mobile, and Brave's flag is
  // desktop-only, so phones are settled before either check downstream.
  if (isLikelyMobileBrowser()) return 'unavailable';

  if (isBrave()) return 'needs-brave-flag';

  return 'needs-desktop-app';
}

/**
 * Brave, which is the one Chromium that fails the check above.
 *
 * It builds Blink with `kFileSystemAccessAPI` disabled by default and exposes
 * the switch as `brave://flags/#file-system-access-api`, so `window` has no
 * picker until the user flips it. Nothing about that is detectable from the
 * capability itself - a Brave with the flag off and a Firefox look identical
 * from here - and the remedies are opposites: twenty seconds in a flags page
 * versus a download. Hence the sniff.
 *
 * `navigator.brave` is Brave's own marker (it carries `isBrave()`, which is a
 * promise and so unusable in a synchronous gate; the object's presence says the
 * same thing). Brave deliberately keeps itself out of the UA and out of
 * `userAgentData.brands`, so there is no other signal. If they ever drop the
 * marker this returns false and Brave users get today's generic message back,
 * which is the right way for this to fail.
 */
function isBrave(): boolean {
  return typeof navigator !== 'undefined' && 'brave' in navigator;
}

/** True for a phone or tablet browser. Only used to decide between two empty
 *  states, so a wrong guess costs a slightly-off message and nothing else -
 *  which is why coarse UA sniffing is acceptable here and nowhere above. */
function isLikelyMobileBrowser(): boolean {
  if (typeof navigator === 'undefined') return false;
  return /android|iphone|ipad|ipod|mobile/i.test(navigator.userAgent);
}
