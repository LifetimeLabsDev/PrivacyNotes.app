/**
 * A calendar address (a `webcal://` link) for the calendar import. Webcal is
 * no format of its own: it is an `.ics` file at a web address, and the scheme
 * only asks a calendar app to open it. The file is downloaded once, through
 * the clipper's download path, and read by the Google Calendar importer.
 * Nothing is kept: a private calendar address is as secret as a password, so
 * it never goes into a log, a message or the import summary.
 * Spec: ops/issues/0548.md (Spec, design A)
 */
import { clipDownload, type TokenSource } from '../clipDownload';

/** The address to download, or null when it is not a calendar address.
 *  `webcal` and `webcals` become `https`; `http` and `https` stay. */
export function calendarFeedUrl(raw: string): string | null {
  const text = raw.trim();
  const m = /^(webcals?|https?):\/\//i.exec(text);
  if (!m) return null;
  const scheme = m[1]!.toLowerCase();
  const rest = text.slice(m[0].length);
  let url: URL;
  try {
    url = new URL(`${scheme === 'http' ? 'http' : 'https'}://${rest}`);
  } catch {
    return null;
  }
  if (url.username || url.password || !url.hostname.includes('.')) return null;
  return url.href;
}

/** The file name the import shows: the address's last segment, `.ics` added
 *  when it lacks one. The importer names the folder after the calendar's own
 *  name and falls back to this. */
export function calendarFeedName(url: string): string {
  const segment = new URL(url).pathname.split('/').filter(Boolean).pop() ?? '';
  let last = segment;
  try {
    last = decodeURIComponent(segment);
  } catch {
    // A stray % stays as it is.
  }
  last ||= 'calendar';
  return /\.ics$/i.test(last) ? last : `${last}.ics`;
}

/** Download the calendar at `url` (already passed through `calendarFeedUrl`)
 *  as a file the importer reads. Throws `ClipError` on a refusal. */
export async function downloadCalendarFeed(url: string, token: TokenSource): Promise<File> {
  const got = await clipDownload(url, 'calendar', token);
  const bytes = new Uint8Array(got.bytes.byteLength);
  bytes.set(got.bytes);
  return new File([bytes], calendarFeedName(got.url), { type: 'text/calendar' });
}
