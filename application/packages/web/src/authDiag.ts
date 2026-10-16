/**
 * Auth breadcrumb ring buffer.
 *
 * Diagnostic aid for the recurring "Session expired" reports: the modal
 * appears hours after the session actually died, so the console at that
 * point shows symptoms (RPC 400s, "pubkey not linked") but never the
 * cause. Every session-lifecycle event lands here with a timestamp and
 * the online flag, so the buffer answers "what killed the session, and
 * when" after the fact.
 *
 * Read it in the devtools console:
 *   JSON.parse(localStorage.getItem('privacynotes.authlog'))
 *
 * Never stores tokens, phrases, emails or note data - event names,
 * error names/codes/statuses, and 8-char uid/pubkey prefixes only.
 * The support report prints every field but `message` and is pasted in
 * public threads, so a new event follows three rules: an id goes in as
 * its first 8 characters, a URL or a path never goes in, and any free
 * text (an error's message) goes under `message`, which the report
 * leaves out and only a console read shows. Every other string value is
 * one short token with no spaces; the report prints anything else as
 * "other" (supportReport.ts).
 * Plain localStorage on purpose (not trustAwareStorage): diagnostics
 * must survive a tab close to be useful, and nothing in them is secret.
 */

const LOG_KEY = 'privacynotes.authlog';
const MAX_ENTRIES = 200;

/** The newest `limit` breadcrumbs, oldest first. Read by the support
 *  report, so a device with no console can still hand over its trail. */
export function readAuthLog(limit = 20): Array<{ t: string; event: string } & Record<string, unknown>> {
  try {
    const raw = localStorage.getItem(LOG_KEY);
    const list = raw ? (JSON.parse(raw) as Array<{ t: string; event: string } & Record<string, unknown>>) : [];
    return Array.isArray(list) ? list.slice(-limit) : [];
  } catch {
    return [];
  }
}

export function logAuthEvent(
  event: string,
  detail?: Record<string, unknown>,
): void {
  try {
    const raw = localStorage.getItem(LOG_KEY);
    const list: unknown[] = raw ? (JSON.parse(raw) as unknown[]) : [];
    list.push({
      t: new Date().toISOString(),
      online: navigator.onLine,
      event,
      ...(detail ?? {}),
    });
    while (list.length > MAX_ENTRIES) list.shift();
    localStorage.setItem(LOG_KEY, JSON.stringify(list));
  } catch {
    /* diagnostics must never break auth */
  }
}
