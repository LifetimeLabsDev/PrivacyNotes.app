import type { PushFailureReason } from './pushFailures';
import type { SyncFault } from './syncFaults';
import type { SyncPassEntry } from './syncLog';

/**
 * The text behind the "Support report" button in ID & Sync.
 *
 * People paste it in public threads, so it must be safe to publish as it
 * stands: the account id is shortened, note and file ids are 8-character
 * prefixes, nothing carries free text, and it names no request path, table
 * or function. It stays English on purpose: it is written for whoever reads
 * the thread, and one fixed shape greps well.
 */

type Breadcrumb = { t: string; event: string } & Record<string, unknown>;

// An id inside a breadcrumb value: a run of hex and dashes long enough to
// be more than a prefix.
const ID_RUN = /[0-9a-fA-F-]{9,}/g;

/** A breadcrumb value as the report prints it. A string that is not one
 *  short token becomes "other", so a URL, an email, a path or a run of words
 *  cannot pass; an id inside one is cut to its first 8 characters. */
function cleanValue(v: unknown): unknown {
  if (v === null || typeof v === 'boolean' || typeof v === 'number') return v;
  if (typeof v !== 'string' || !/^[A-Za-z0-9_.:-]{1,40}$/.test(v)) return 'other';
  return v.replace(ID_RUN, (m) => (/\d/.test(m) ? m.slice(0, 8) : m));
}

function breadcrumbLine(b: Breadcrumb): string {
  // `message` is free text by the authDiag.ts rule: a console read shows
  // it, the report never does.
  const { t, event, message: _message, ...rest } = b;
  const clean = Object.fromEntries(Object.entries(rest).map(([k, v]) => [k, cleanValue(v)]));
  const detail = Object.keys(clean).length > 0 ? `  ${JSON.stringify(clean)}` : '';
  return `  ${t}  ${String(cleanValue(event))}${detail}`;
}

function faultLine(f: SyncFault): string {
  const at = new Date(f.at).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const cols = [
    f.step.padEnd(11),
    String(f.status ?? '-').padEnd(4),
    (f.code ?? '-').padEnd(10),
    f.ref ?? '-',
  ];
  return `  ${at}  ${cols.join(' ')}${(f.n ?? 1) > 1 ? `  x${f.n}` : ''}`;
}

export function buildSupportReport(input: {
  pubkey: string;
  device: string;
  version: string;
  unsynced: number;
  pendingUploads: number;
  lastOkAt: number | null;
  /** The notes the last pass could not push. */
  failed: ReadonlyArray<{ id: string; reason: PushFailureReason; chars: number }>;
  /** Oldest first, as syncLog.ts keeps them. */
  passes: SyncPassEntry[];
  /** Oldest first, as syncFaults.ts keeps them. */
  faults: SyncFault[];
  /** Oldest first, as authDiag.ts keeps them. */
  breadcrumbs: Breadcrumb[];
}): string {
  const { pubkey, failed, passes, faults, breadcrumbs } = input;
  // Spec: ops/docs/archive/sync-diagnostics.md (decision D1: first 6, last 4)
  const account = `${pubkey.slice(0, 6)}...${pubkey.slice(-4)}`;
  return [
    'PrivacyNotes support report',
    `Account: ${account}`,
    `Device: ${input.device}`,
    `Version: ${input.version}`,
    `Unsynced notes: ${input.unsynced}`,
    `Pending file uploads: ${input.pendingUploads}`,
    `Last sync: ${input.lastOkAt !== null ? new Date(input.lastOkAt).toISOString() : 'never'}`,
    ...(failed.length > 0
      ? ['', 'Not backed up:', ...failed.map((f) => `  ${f.id.slice(0, 8)}  ${f.reason}  ${f.chars} chars`)]
      : []),
    '',
    'Recent passes (newest first):',
    ...[...passes].reverse().map((e) =>
      `  ${new Date(e.at).toISOString()}  ${e.ok ? 'ok' : 'FAILED'}  up=${e.up} down=${e.down}${e.failed ? ` failed=${e.failed}` : ''}${e.halted ? ` halted=${e.halted.reason}:${e.halted.unreached}` : ''}${(e.n ?? 1) > 1 ? ` x${e.n}` : ''}  ${e.ms}ms`,
    ),
    '',
    'Recent failures (newest first):',
    ...(faults.length > 0 ? [...faults].reverse().map(faultLine) : ['  none']),
    '',
    'Auth breadcrumbs (newest first):',
    ...[...breadcrumbs].reverse().map(breadcrumbLine),
  ].join('\n');
}
