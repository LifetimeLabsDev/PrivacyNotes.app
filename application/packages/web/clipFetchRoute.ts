/**
 * POST /clip-fetch: the web app's way to download a web page or a picture for
 * the clipper, or a calendar file for the calendar import (a webcal address). The desktop and phone apps download on the device instead
 * (the `clip_fetch` command); a browser cannot, because a page may not read
 * another site.
 *
 * Who may call it:
 * - a signed-in user, with a session token this Worker verifies against the
 *   project's public signing key, linked to an account key. An anonymous
 *   session that never linked one costs nothing to make, so it does not
 *   count; the limits are kept per account key;
 * - the demo, with no token, a request marked as demo and an Origin of the
 *   demo or the app, under tighter per-address limits and a global daily cap.
 *   The Origin check stops other websites from using the route through their
 *   visitors' browsers; the caps are what stop a script.
 * Anything else gets a 401 with no body.
 *
 * What it refuses, on every redirect hop: a scheme other than http or https,
 * a user name or password in the address, a host that names or resolves to a
 * private, local or reserved address. A Worker cannot pin its connection to
 * the address it looked up, so the lookup is a second fence; the first is
 * that Cloudflare's network does not route to private ranges.
 *
 * It keeps nothing: no cookie either way, no cache, and no log line that
 * holds an address or a size (tests/workerLogPrivacy.test.ts).
 * Spec: ops/docs/archive/web-clipper-stage1.md (section 3.1)
 */

/** One Durable Object per counted subject: an account, an address, or the
 *  demo as a whole. Typed by hand like the rest of the Worker's runtime. */
interface ClipLimitsNamespace {
  idFromName(name: string): unknown;
  get(id: unknown): { fetch(input: string, init?: RequestInit): Promise<Response> };
}

export interface ClipEnv {
  CLIP_LIMITS?: ClipLimitsNamespace;
  /** The Supabase project URL, without a trailing slash. */
  SUPABASE_URL?: string;
}

interface DurableObjectStorage {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  deleteAll(): Promise<void>;
  setAlarm(scheduledTime: number): Promise<void>;
}

interface DurableObjectState {
  storage: DurableObjectStorage;
  blockConcurrencyWhile<T>(fn: () => Promise<T>): Promise<T>;
}

const MAX_REDIRECTS = 5;
const DEADLINE_MS = 20_000;
/** Spec: ops/docs/archive/web-clipper-stage1.md (section 3.1, page: 5 MB) */
const PAGE_MAX_BYTES = 5 * 1024 * 1024;
/** One picture may be as large as the per-clip picture budget.
 *  Spec: ops/docs/archive/web-clipper-stage1.md (section 3.3, 10 MB per clip) */
const IMAGE_MAX_BYTES = 10_000_000;
/** A public calendar feed of several years is a few MB.
 *  Spec: ops/issues/0548.md (Spec, design A) */
const CALENDAR_MAX_BYTES = 10_000_000;
const USER_AGENT =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15';

/** The demo's hosts. The app host is allowed too, so a demo opened there
 *  with `?demo=1` works. */
const DEMO_ORIGINS = new Set(['https://try.privacynotes.app', 'https://use.privacynotes.app']);
/** The local dev server, accepted only when the Worker itself runs locally. */
const DEV_ORIGIN = 'http://localhost:5173';

/** A window in seconds and the most requests it holds. */
type Rule = { name: string; window: number; limit: number };

/** Spec: ops/docs/archive/web-clipper-stage1.md (section 3.1, rate limits) */
const LIMITS = {
  page: [
    { name: 'page-minute', window: 60, limit: 30 },
    { name: 'page-day', window: 86_400, limit: 600 },
  ],
  image: [{ name: 'image-minute', window: 60, limit: 300 }],
  badToken: [{ name: 'bad-token-minute', window: 60, limit: 20 }],
  demoPage: [{ name: 'demo-page-hour', window: 3_600, limit: 10 }],
  demoImage: [{ name: 'demo-image-hour', window: 3_600, limit: 100 }],
  demoGlobal: [{ name: 'demo-page-day', window: 86_400, limit: 5_000 }],
} satisfies Record<string, Rule[]>;

/** A calendar download counts against the page limits: one request each,
 *  started by a person. */
type Kind = 'page' | 'image' | 'calendar';

/** An empty answer with an opaque reason code; never the address asked for. */
function refuse(status: number, code: string, extra: Record<string, string> = {}): Response {
  return new Response(null, { status, headers: { 'X-Clip-Error': code, 'Cache-Control': 'no-store', ...extra } });
}

export async function handleClipFetch(request: Request, url: URL, env: ClipEnv): Promise<Response> {
  if (request.method !== 'POST') return refuse(405, 'method', { Allow: 'POST' });
  if (!env.CLIP_LIMITS || !env.SUPABASE_URL) return refuse(503, 'unavailable');

  const ip = clientAddress(request);
  const demo = request.headers.get('X-PN-Demo') === '1';
  const auth = request.headers.get('Authorization') ?? '';
  // A browser names the page that sent the request. One of ours, or none (a
  // script), may go on; another website may not, so it cannot spend the
  // counters of its visitors' addresses.
  const origin = request.headers.get('Origin');
  const local = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
  const ourOrigin = origin !== null && (DEMO_ORIGINS.has(origin) || (local && origin === DEV_ORIGIN));
  if (origin !== null && !ourOrigin) return new Response(null, { status: 401 });

  let subject: string;
  if (demo && !auth) {
    if (!ourOrigin) return new Response(null, { status: 401 });
    subject = `demo:${ip}`;
  } else {
    const user = auth.startsWith('Bearer ') ? await verifySession(auth.slice(7), env.SUPABASE_URL) : null;
    if (!user) {
      // Failures are counted, never checked before a token: a valid session
      // from a busy address is never refused for someone else's failures.
      const tooMany = !(await allowed(env.CLIP_LIMITS, `bad:${ip}`, LIMITS.badToken, true));
      return tooMany ? refuse(429, 'limit') : new Response(null, { status: 401 });
    }
    subject = `account:${user}`;
  }

  const raw = await readBody(request);
  if (raw === null) return refuse(413, 'too-large');
  let body: { url?: unknown; kind?: unknown };
  try {
    body = JSON.parse(raw);
  } catch {
    return refuse(400, 'bad-request');
  }
  const kind = body.kind === 'page' || body.kind === 'image' || body.kind === 'calendar' ? (body.kind as Kind) : null;
  if (!kind || typeof body.url !== 'string' || body.url.length > 4096) return refuse(400, 'bad-request');

  const isDemo = subject.startsWith('demo:');
  const pageLike = kind !== 'image';
  const rules = isDemo ? (pageLike ? LIMITS.demoPage : LIMITS.demoImage) : pageLike ? LIMITS.page : LIMITS.image;
  if (!(await allowed(env.CLIP_LIMITS, subject, rules, true))) return refuse(429, 'limit');
  if (isDemo && pageLike && !(await allowed(env.CLIP_LIMITS, 'demo-global', LIMITS.demoGlobal, true))) {
    return refuse(429, 'demo-cap');
  }

  try {
    return await download(body.url, kind);
  } catch (err) {
    if (err instanceof ClipRefusal) return refuse(err.status, err.code, err.headers);
    if (err instanceof Error && (err.name === 'TimeoutError' || err.name === 'AbortError')) return refuse(504, 'timeout');
    console.error(`clip-fetch: ${err instanceof Error ? err.name : 'error'}`);
    return refuse(502, 'network');
  }
}

/** The request body is one small JSON object; anything larger is refused
 *  before it is read whole. */
const MAX_REQUEST_BYTES = 8 * 1024;

async function readBody(request: Request): Promise<string | null> {
  const declared = Number(request.headers.get('Content-Length'));
  if (Number.isFinite(declared) && declared > MAX_REQUEST_BYTES) return null;
  const reader = request.body?.getReader();
  if (!reader) return '';
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_REQUEST_BYTES) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const all = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) {
    all.set(c, at);
    at += c.byteLength;
  }
  return new TextDecoder().decode(all);
}

class ClipRefusal extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly headers: Record<string, string> = {},
  ) {
    super(code);
  }
}

/** The caller's address, with an IPv6 address cut to its /64, the block one
 *  connection usually holds. */
export function clientAddress(request: Request): string {
  const raw = request.headers.get('CF-Connecting-IP') ?? 'unknown';
  const ip = parseIp(raw);
  if (!ip || ip.v === 4) return raw;
  return ip.parts.slice(0, 4).map((g) => g.toString(16)).join(':');
}

// ── Downloading ────────────────────────────────────────────────

async function download(raw: string, kind: Kind): Promise<Response> {
  const signal = AbortSignal.timeout(DEADLINE_MS);
  let target = checkUrl(raw);
  for (let hop = 0; ; hop++) {
    await checkHost(target, signal);
    const res = await fetch(target.href, {
      method: 'GET',
      redirect: 'manual',
      cache: 'no-store',
      signal,
      headers: {
        'User-Agent': USER_AGENT,
        Accept: kind === 'calendar' ? 'text/calendar,*/*;q=0.5' : 'text/html,application/xhtml+xml,image/*;q=0.9,*/*;q=0.5',
      },
    });
    if (res.status >= 300 && res.status < 400) {
      await res.body?.cancel();
      if (hop === MAX_REDIRECTS) throw new ClipRefusal(422, 'too-many-redirects');
      const location = res.headers.get('Location');
      if (!location) throw new ClipRefusal(502, 'bad-redirect');
      let next: URL;
      try {
        next = new URL(location, target);
      } catch {
        throw new ClipRefusal(502, 'bad-redirect');
      }
      target = checkUrl(next.href);
      continue;
    }
    if (!res.ok) {
      await res.body?.cancel();
      throw new ClipRefusal(502, 'status', { 'X-Clip-Status': String(res.status) });
    }
    const contentType = res.headers.get('Content-Type') ?? '';
    if (!accepts(kind, contentType)) {
      await res.body?.cancel();
      throw new ClipRefusal(422, 'wrong-type');
    }
    const bytes = await readCapped(res, MAX_BYTES[kind]);
    return new Response(bytes, {
      status: 200,
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Clip-Url': target.href,
        'X-Clip-Type': contentType.replace(/[^\x20-\x7e]/g, ''),
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': "default-src 'none'; sandbox",
        'Content-Disposition': 'attachment',
      },
    });
  }
}

export function checkUrl(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    throw new ClipRefusal(422, 'bad-url');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new ClipRefusal(422, 'bad-url');
  if (url.username || url.password || !url.hostname) throw new ClipRefusal(422, 'bad-url');
  if (url.port && BAD_PORTS.has(Number(url.port))) throw new ClipRefusal(422, 'blocked-address');
  return url;
}

const MAX_BYTES: Record<Kind, number> = { page: PAGE_MAX_BYTES, image: IMAGE_MAX_BYTES, calendar: CALENDAR_MAX_BYTES };

/** Many calendar servers send a generic type, so a calendar takes those too;
 *  the importer refuses a body that is not a calendar. An HTML page (a
 *  sign-in wall) is refused here. */
const CALENDAR_TYPES = new Set(['text/calendar', 'application/ics', 'text/plain', 'application/octet-stream', 'application/binary']);

function accepts(kind: Kind, contentType: string): boolean {
  const essence = contentType.split(';')[0]!.trim().toLowerCase();
  if (kind === 'calendar') return CALENDAR_TYPES.has(essence);
  return kind === 'page' ? essence === 'text/html' || essence === 'application/xhtml+xml' : essence.startsWith('image/');
}

async function readCapped(res: Response, limit: number): Promise<Uint8Array<ArrayBuffer>> {
  const declared = Number(res.headers.get('Content-Length'));
  if (Number.isFinite(declared) && declared > limit) {
    await res.body?.cancel();
    throw new ClipRefusal(413, 'too-large');
  }
  const reader = res.body?.getReader();
  if (!reader) return new Uint8Array(0);
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel();
      throw new ClipRefusal(413, 'too-large');
    }
    chunks.push(value);
  }
  const out = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.byteLength;
  }
  return out;
}

const LOCAL_NAMES = /(?:^|\.)(?:localhost|local|internal|intranet|lan|home|corp|home\.arpa|localdomain)$/i;

/** Refuse a host that is, or resolves to, an address outside the public web.
 *  Every answer of the lookup must be public. */
async function checkHost(url: URL, signal: AbortSignal): Promise<void> {
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  const literal = parseIp(host);
  if (literal) {
    if (isBlockedIp(literal)) throw new ClipRefusal(422, 'blocked-address');
    return;
  }
  if (!host.includes('.') || LOCAL_NAMES.test(host)) throw new ClipRefusal(422, 'blocked-address');
  const answers = await resolve(host, signal);
  if (answers.length === 0) throw new ClipRefusal(502, 'dns');
  for (const a of answers) {
    const ip = parseIp(a);
    if (!ip || isBlockedIp(ip)) throw new ClipRefusal(422, 'blocked-address');
  }
}

/** A and AAAA answers over DNS over HTTPS (Cloudflare's resolver). */
async function resolve(host: string, signal: AbortSignal): Promise<string[]> {
  const out: string[] = [];
  for (const type of ['A', 'AAAA'] as const) {
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`, {
      headers: { Accept: 'application/dns-json' },
      cache: 'no-store',
      signal,
    });
    if (!res.ok) throw new ClipRefusal(502, 'dns');
    const data = (await res.json()) as { Answer?: { type: number; data: string }[] };
    for (const answer of data.Answer ?? []) {
      if (answer.type === 1 || answer.type === 28) out.push(answer.data);
    }
  }
  return out;
}

type Ip = { v: 4; parts: number[] } | { v: 6; parts: number[] };

/** Parse a dotted IPv4 or a colon IPv6 address, or null. `URL` has already
 *  normalised every IPv4 spelling (octal, hex, short) to dotted decimal. */
export function parseIp(text: string): Ip | null {
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (v4) {
    const parts = v4.slice(1).map(Number);
    return parts.every((p) => p <= 255) ? { v: 4, parts } : null;
  }
  if (!text.includes(':')) return null;
  let s = text;
  const tailV4 = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(s);
  if (tailV4) {
    const t = parseIp(tailV4[1]!);
    if (!t || t.v !== 4) return null;
    const [a, b, c, d] = t.parts as [number, number, number, number];
    s = `${s.slice(0, -tailV4[1]!.length)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  if (fill < 0 || (halves.length === 1 && head.length !== 8)) return null;
  const groups = [...head, ...Array(fill).fill('0'), ...tail];
  if (groups.length !== 8 || !groups.every((g) => /^[0-9a-f]{1,4}$/i.test(g))) return null;
  return { v: 6, parts: groups.map((g) => parseInt(g, 16)) };
}

/** The ports the Fetch standard blocks, the same list `clip_fetch` refuses. */
const BAD_PORTS = new Set([
  0, 1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79, 87, 95, 101, 102, 103, 104, 109, 110,
  111, 113, 115, 117, 119, 123, 135, 137, 139, 143, 161, 179, 389, 427, 465, 512, 513, 514, 515, 526, 530, 531, 532,
  540, 548, 554, 556, 563, 587, 601, 636, 989, 990, 993, 995, 1719, 1720, 1723, 2049, 3659, 4045, 4190, 5060, 5061,
  6000, 6566, 6665, 6666, 6667, 6668, 6669, 6679, 6697, 10080,
]);

/** The same ranges `clip_fetch` refuses (clip_fetch.rs `is_blocked`). */
export function isBlockedIp(ip: Ip): boolean {
  if (ip.v === 4) {
    const [a, b, c] = ip.parts as [number, number, number, number];
    return (
      a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 0 && (c === 0 || c === 2)) ||
      (a === 198 && (b === 18 || b === 19)) ||
      (a === 198 && b === 51 && c === 100) ||
      (a === 203 && b === 0 && c === 113)
    );
  }
  const p = ip.parts as [number, number, number, number, number, number, number, number];
  const embedded = (hi: number, lo: number): Ip => ({ v: 4, parts: [hi >> 8, hi & 255, lo >> 8, lo & 255] });
  if (p.slice(0, 5).every((x) => x === 0) && p[5] === 0xffff) return isBlockedIp(embedded(p[6], p[7]));
  if (p.slice(0, 6).every((x) => x === 0)) return true; // ::, ::1 and the IPv4-compatible form
  if (p.slice(0, 4).every((x) => x === 0) && p[4] === 0xffff && p[5] === 0) return isBlockedIp(embedded(p[6], p[7]));
  if (p[0] === 0x64 && p[1] === 0xff9b && p[2] === 1) return true; // local NAT64 64:ff9b:1::/48, any layout
  if (p[0] === 0x64 && p[1] === 0xff9b && p.slice(2, 6).every((x) => x === 0)) return isBlockedIp(embedded(p[6], p[7]));
  if (p[0] === 0x2001 && p[1] === 0) return isBlockedIp(embedded(~p[6] & 0xffff, ~p[7] & 0xffff));
  if (p[0] === 0x2002) return isBlockedIp(embedded(p[1], p[2]));
  return (
    (p[0] & 0xfe00) === 0xfc00 ||
    (p[0] & 0xffc0) === 0xfe80 ||
    (p[0] & 0xffc0) === 0xfec0 ||
    (p[0] & 0xff00) === 0xff00 ||
    (p[0] === 0x2001 && p[1] === 0x0db8) ||
    (p[0] === 0x0100 && p[1] === 0 && p[2] === 0 && p[3] === 0)
  );
}

// ── Session tokens ─────────────────────────────────────────────

type Jwk = JsonWebKey & { kid?: string };
let keyCache: { at: number; base: string; keys: Map<string, CryptoKey> } | null = null;
const KEY_TTL_MS = 10 * 60 * 1000;

async function signingKey(base: string, kid: string): Promise<CryptoKey | null> {
  const age = keyCache && keyCache.base === base ? Date.now() - keyCache.at : Infinity;
  // An unknown key id fetches the keys again, at most once a minute, so a
  // made-up id cannot cost a download per request.
  if (age >= KEY_TTL_MS || (!keyCache!.keys.has(kid) && age >= 60_000)) {
    const res = await fetch(`${base}/auth/v1/.well-known/jwks.json`);
    if (!res.ok) return null;
    const { keys } = (await res.json()) as { keys?: Jwk[] };
    const map = new Map<string, CryptoKey>();
    for (const jwk of keys ?? []) {
      if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.kid) continue;
      const { kty, crv, x, y } = jwk;
      map.set(jwk.kid, await crypto.subtle.importKey('jwk', { kty, crv, x, y }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']));
    }
    keyCache = { at: Date.now(), base, keys: map };
  }
  return keyCache!.keys.get(kid) ?? null;
}

function base64url(text: string): Uint8Array<ArrayBuffer> {
  const b64 = text.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(text.length / 4) * 4, '=');
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

/** The account key of a valid session token for this project, or null:
 *  the `app_metadata.pubkey` that link-pubkey writes, which only the server
 *  can set. */
export async function verifySession(token: string, base: string): Promise<string | null> {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const header = JSON.parse(new TextDecoder().decode(base64url(parts[0]!))) as { alg?: string; kid?: string };
    if (header.alg !== 'ES256' || !header.kid) return null;
    const key = await signingKey(base, header.kid);
    if (!key) return null;
    const ok = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      base64url(parts[2]!),
      new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
    );
    if (!ok) return null;
    const claims = JSON.parse(new TextDecoder().decode(base64url(parts[1]!))) as {
      sub?: string; exp?: number; aud?: string | string[]; role?: string; app_metadata?: { pubkey?: unknown };
    };
    const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!audiences.includes('authenticated') || claims.role !== 'authenticated') return null;
    if (typeof claims.exp !== 'number' || claims.exp * 1000 <= Date.now()) return null;
    if (typeof claims.sub !== 'string' || !/^[0-9a-f-]{36}$/i.test(claims.sub)) return null;
    const pubkey = claims.app_metadata?.pubkey;
    if (typeof pubkey !== 'string' || !/^[0-9a-f]{64}$/i.test(pubkey)) return null;
    return pubkey.toLowerCase();
  } catch {
    return null;
  }
}

// ── Limits ─────────────────────────────────────────────────────

/** Ask the subject's counter whether `rules` allow one more request, and
 *  count it when `count` is true and every rule allows it. */
async function allowed(ns: ClipLimitsNamespace, subject: string, rules: Rule[], count: boolean): Promise<boolean> {
  const stub = ns.get(ns.idFromName(subject));
  const res = await stub.fetch('https://clip-limits/hit', { method: 'POST', body: JSON.stringify({ rules, count }) });
  return res.status === 200;
}

/** The fixed-window counters of one subject. 200 allows, 429 refuses. */
export class ClipLimits {
  constructor(private readonly state: DurableObjectState) {}

  async fetch(request: Request): Promise<Response> {
    const { rules, count } = (await request.json()) as { rules: Rule[]; count: boolean };
    const now = Math.floor(Date.now() / 1000);
    type Window = { start: number; n: number; window: number };
    const stored = (await this.state.storage.get<Record<string, Window>>('w')) ?? {};
    const windows: Record<string, Window> = {};
    for (const [name, w] of Object.entries(stored)) if (w.window && w.start + w.window > now) windows[name] = w;
    for (const rule of rules) {
      const start = now - (now % rule.window);
      const current = windows[rule.name];
      const n = current && current.start === start ? current.n : 0;
      if (n >= rule.limit) return new Response(null, { status: 429 });
      windows[rule.name] = { start, n: n + 1, window: rule.window };
    }
    if (count) {
      await this.state.storage.put('w', windows);
      // A subject that goes quiet is deleted once its last open window ends,
      // so the counters of a passing address do not stay forever.
      const end = Math.max(...Object.values(windows).map((w) => w.start + w.window));
      await this.state.storage.setAlarm(end * 1000);
    }
    return new Response(null, { status: 200 });
  }

  async alarm(): Promise<void> {
    await this.state.storage.deleteAll();
  }
}
