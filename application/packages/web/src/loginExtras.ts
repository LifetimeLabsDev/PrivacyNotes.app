/**
 * A login's custom fields and additional websites.
 *
 * They live in the note's encrypted `trackers` map under `login`, not in the
 * body: every installed client rewrites a login body from five named keys and
 * would drop any other key on its next save, while it carries the `trackers`
 * map through unchanged. The first website stays `body.url`, which every
 * client already reads.
 *
 * Only a field whose type is exactly `text` is public (searchable, shown
 * unmasked). Every other type, including one a newer client may add, is
 * treated as hidden.
 *
 * Spec: ops/issues/0289.md
 */

export interface LoginField {
  id: string;
  label: string;
  value: string;
  type: string;
}

export interface LoginExtras {
  extraUrls: string[];
  fields: LoginField[];
}

const EMPTY_LOGIN_EXTRAS: LoginExtras = { extraUrls: [], fields: [] };

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/** Read the extras from a stored `trackers.login` value. Anything malformed
 *  reads as absent rather than throwing. */
function parseLoginExtras(raw: unknown): LoginExtras {
  if (!isRecord(raw)) return EMPTY_LOGIN_EXTRAS;
  const extraUrls = Array.isArray(raw.extraUrls)
    ? raw.extraUrls.filter((u): u is string => typeof u === 'string')
    : [];
  const fields = Array.isArray(raw.fields)
    ? raw.fields.filter(
        (f): f is LoginField =>
          isRecord(f) &&
          typeof f.id === 'string' &&
          typeof f.label === 'string' &&
          typeof f.value === 'string' &&
          typeof f.type === 'string',
      )
    : [];
  return { extraUrls, fields };
}

export function loginExtrasOf(trackers: Record<string, unknown> | undefined): LoginExtras {
  return parseLoginExtras(trackers?.login);
}

export function hasLoginExtras(e: LoginExtras): boolean {
  return e.extraUrls.length > 0 || e.fields.length > 0;
}

/** Whether a field's value may be shown unmasked and indexed. */
export function isPublicField(f: LoginField): boolean {
  return f.type === 'text';
}

export function newLoginField(type: 'text' | 'hidden', label = '', value = ''): LoginField {
  return { id: crypto.randomUUID(), label, value, type };
}

/**
 * The tracker map with `login` set to these extras, keeping every other key
 * and any property of the stored login object this build does not model.
 * Empty extras remove the key.
 */
export function withLoginExtras(
  trackers: Record<string, unknown> | undefined,
  extras: LoginExtras,
): Record<string, unknown> {
  const { login: prev, ...rest } = trackers ?? {};
  if (!hasLoginExtras(extras)) return rest;
  const carried = isRecord(prev) ? prev : {};
  return { ...rest, login: { ...carried, extraUrls: extras.extraUrls, fields: extras.fields } };
}

/**
 * Two devices each changed the extras since they last agreed. Fields union
 * by id, and the same field edited on both sides takes this device's copy;
 * websites union as a set. A field or website deleted on one side can come
 * back: that is one tap to undo, where a lost credential is not noticed.
 */
export function mergeLoginExtras(local: unknown, remote: unknown): unknown {
  if (!isRecord(local)) return remote;
  if (!isRecord(remote)) return local;
  const l = parseLoginExtras(local);
  const r = parseLoginExtras(remote);
  const byId = new Map<string, LoginField>();
  for (const f of [...r.fields, ...l.fields]) byId.set(f.id, f);
  return {
    ...remote,
    ...local,
    extraUrls: [...new Set([...r.extraUrls, ...l.extraUrls])],
    fields: [...byId.values()],
  };
}

/** The address to open for a stored website, or null when it is not a web
 *  address (an app scheme such as `androidapp://`, or anything malformed). */
export function webHref(raw: string): string | null {
  const s = raw.trim();
  if (!s || /\s/.test(s)) return null;
  if (/^[a-z][a-z0-9+.-]*:/i.test(s) && !/^https?:\/\//i.test(s)) return null;
  const href = /^https?:\/\//i.test(s) ? s : `https://${s}`;
  try {
    const host = new URL(href).hostname;
    return host.includes('.') || host === 'localhost' ? href : null;
  } catch {
    return null;
  }
}
