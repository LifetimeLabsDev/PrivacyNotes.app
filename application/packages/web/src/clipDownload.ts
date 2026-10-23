/**
 * Download one web page or picture for the clipper, or one calendar file for
 * the calendar import, by the path this app has:
 * the native `clip_fetch` command on the desktop and the phones, the Worker's
 * `/clip-fetch` route on the web and in the demo. Both refuse the same things;
 * this module turns their refusals into the few reasons the screens explain.
 * Spec: ops/docs/archive/web-clipper-stage1.md (section 3.1)
 */
import { isDemoMode } from './demo';
import { detectPlatform } from './devices';

export type ClipKind = 'page' | 'image' | 'calendar';

export interface Downloaded {
  bytes: Uint8Array;
  /** The address after redirects. Relative links resolve against it. */
  url: string;
  contentType: string;
}

/** Why a download failed. `blocked`: the site refused it. `offline`: no
 *  network. `demo-limit`: the demo's clipping limit. `limit`: the account's
 *  rate limit. `refused`: the address is not one the clipper may open.
 *  `timeout`: the site did not answer within the deadline. `too-large`,
 *  `wrong-type`: the answer broke a limit. `failed`: anything else. */
export type ClipErrorReason = 'blocked' | 'offline' | 'timeout' | 'demo-limit' | 'limit' | 'refused' | 'too-large' | 'wrong-type' | 'failed';

export class ClipError extends Error {
  constructor(readonly reason: ClipErrorReason) {
    super(reason);
    this.name = 'ClipError';
  }
}

/** The session token a signed-in web app sends. Null outside a session. */
export type TokenSource = () => Promise<string | null>;

export async function clipDownload(url: string, kind: ClipKind, token: TokenSource): Promise<Downloaded> {
  if (typeof navigator !== 'undefined' && navigator.onLine === false) throw new ClipError('offline');
  return detectPlatform() === 'web' || isDemoMode() ? viaWorker(url, kind, token) : viaDevice(url, kind);
}

async function viaDevice(url: string, kind: ClipKind): Promise<Downloaded> {
  const { invoke } = await import('@tauri-apps/api/core');
  let framed: ArrayBuffer;
  try {
    framed = await invoke<ArrayBuffer>('clip_fetch', { url, kind });
  } catch (err) {
    throw new ClipError(reasonOf(typeof err === 'string' ? err : ''));
  }
  const view = new DataView(framed);
  const length = view.getUint32(0);
  const header = JSON.parse(new TextDecoder().decode(new Uint8Array(framed, 4, length))) as { url: string; contentType: string };
  return { bytes: new Uint8Array(framed, 4 + length), url: header.url, contentType: header.contentType };
}

async function viaWorker(url: string, kind: ClipKind, token: TokenSource): Promise<Downloaded> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (isDemoMode()) headers['X-PN-Demo'] = '1';
  else {
    const t = await token();
    if (!t) throw new ClipError('failed');
    headers.Authorization = `Bearer ${t}`;
  }
  let res: Response;
  try {
    res = await fetch('/clip-fetch', { method: 'POST', headers, body: JSON.stringify({ url, kind }), credentials: 'omit', cache: 'no-store' });
  } catch {
    throw new ClipError('offline');
  }
  if (!res.ok) {
    const code = res.headers.get('X-Clip-Error') ?? '';
    if (res.status === 429) throw new ClipError(isDemoMode() ? 'demo-limit' : 'limit');
    // A refusal names the site's choice; a server error is usually brief.
    if (code === 'status') {
      const upstream = Number(res.headers.get('X-Clip-Status'));
      throw new ClipError(isBlockedStatus(upstream) ? 'blocked' : 'failed');
    }
    // A 5xx with no code is not ours: the route is missing or broken (the
    // dev proxy answers so when no local Worker runs). The network is up,
    // so it is never reported as offline.
    if (!code && res.status >= 500) throw new ClipError('failed');
    throw new ClipError(reasonOf(code));
  }
  return {
    bytes: new Uint8Array(await res.arrayBuffer()),
    url: res.headers.get('X-Clip-Url') ?? url,
    contentType: res.headers.get('X-Clip-Type') ?? '',
  };
}

/** Whether a site's answer to a plain page request means it turns the
 *  clipper away. 405 belongs here: a page always takes a GET, so a site that
 *  refuses the method is refusing the client. */
export function isBlockedStatus(status: number): boolean {
  return [401, 403, 405, 429, 451].includes(status);
}

/** The reason for a refusal code of either path. */
function reasonOf(code: string): ClipErrorReason {
  if (code.startsWith('status:')) return isBlockedStatus(Number(code.slice(7))) ? 'blocked' : 'failed';
  switch (code) {
    case 'bad-url':
    case 'blocked-address':
    case 'bad-redirect':
    case 'too-many-redirects':
      return 'refused';
    case 'too-large':
      return 'too-large';
    case 'wrong-type':
      return 'wrong-type';
    case 'timeout':
      return 'timeout';
    default:
      return 'failed';
  }
}

/** The text of a downloaded page, decoded by the charset its header or its
 *  markup names, UTF-8 when it names none or one the browser lacks. */
export function decodePage(bytes: Uint8Array, contentType: string): string {
  const fromHeader = /charset\s*=\s*"?([\w-]+)/i.exec(contentType)?.[1];
  const head = new TextDecoder('latin1').decode(bytes.subarray(0, 2048));
  const fromMarkup = /<meta[^>]+charset\s*=\s*["']?([\w-]+)/i.exec(head)?.[1];
  for (const label of [fromHeader, fromMarkup, 'utf-8']) {
    if (!label) continue;
    try {
      return new TextDecoder(label).decode(bytes);
    } catch {
      // An unknown label: try the next one.
    }
  }
  return new TextDecoder().decode(bytes);
}
