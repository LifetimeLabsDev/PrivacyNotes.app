import { isDemoMode } from './demo';

/**
 * Device-local ring of sync failures, for the support report: the step
 * that failed, the HTTP status and the short error code the client got,
 * and an id prefix when the failure belongs to one note or file.
 *
 * The report is pasted in public threads, so a fault carries no free
 * text at all: a database message can hold ids or values, a storage
 * message can hold a path. Every value is cleaned here, not at the call
 * site, so no caller can hand over more than the shape below allows.
 * Persisted like the pass log, because the failure usually happened
 * before the person opened Settings.
 */

type SyncFaultStep =
  | 'pull' | 'push' | 'settings'
  | 'file-up' | 'file-down' | 'file-delete'
  | 'device'; // registration and heartbeat

export type SyncFault = {
  /** ms epoch of the newest occurrence. */
  at: number;
  step: SyncFaultStep;
  /** HTTP status, when the client returned one. */
  status?: number;
  /** A Postgres or PostgREST code, a storage error name, or one of ours. */
  code?: string;
  /** First 8 characters of the note or file id, never more. */
  ref?: string;
  /** Repeat count: the same fault back to back folds into one entry. */
  n?: number;
};

// Spec: ops/docs/plans/sync-diagnostics.md (the fault record)
const STORAGE_KEY = 'privacynotes.syncFaults';
const MAX_ENTRIES = 20;
const CODE_MAX = 40;
const REF_LEN = 8;

const STEPS: ReadonlySet<string> = new Set<SyncFaultStep>([
  'pull', 'push', 'settings', 'file-up', 'file-down', 'file-delete', 'device',
]);

/** A short code: letters, digits, `_` and `-`, at most 40. A server body can
 *  carry any JSON here, so anything else (a number, a message, a file name,
 *  an id) becomes "other". */
function cleanCode(code: unknown): string | undefined {
  if (code === undefined || code === null || code === '') return undefined;
  if (typeof code !== 'string' || !/^[A-Za-z0-9_-]+$/.test(code)) return 'other';
  // A run of hex long enough to be an id is not a code.
  if (/[0-9a-fA-F-]{9,}/.test(code) && /\d/.test(code)) return 'other';
  return code.slice(0, CODE_MAX);
}

/** An id prefix. The whole value must be id-shaped before it is cut, so a
 *  path or a name is dropped rather than shown in part. */
function cleanRef(ref: unknown): string | undefined {
  if (typeof ref !== 'string' || !/^[A-Za-z0-9-]+$/.test(ref)) return undefined;
  return ref.slice(0, REF_LEN);
}

function cleanStatus(status: unknown): number | undefined {
  return typeof status === 'number' && Number.isInteger(status) && status >= 0 && status < 1000 ? status : undefined;
}

/** The only way a value enters the ring, from a caller or from disk. */
function cleanFault(f: Partial<Record<keyof SyncFault, unknown>>, at: number): SyncFault | null {
  if (typeof f.step !== 'string' || !STEPS.has(f.step)) return null;
  const fault: SyncFault = { at, step: f.step as SyncFaultStep };
  const status = cleanStatus(f.status);
  const code = cleanCode(f.code);
  const ref = cleanRef(f.ref);
  if (status !== undefined) fault.status = status;
  if (code !== undefined) fault.code = code;
  if (ref !== undefined) fault.ref = ref;
  if (typeof f.n === 'number' && Number.isInteger(f.n) && f.n > 1) fault.n = f.n;
  return fault;
}

function readStored(): SyncFault[] {
  try {
    if (typeof localStorage === 'undefined') return [];
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    const out: SyncFault[] = [];
    for (const e of parsed) {
      if (typeof e !== 'object' || e === null) continue;
      const at = (e as { at?: unknown }).at;
      const fault = typeof at === 'number' ? cleanFault(e as Record<string, unknown>, at) : null;
      if (fault) out.push(fault);
    }
    return out.slice(-MAX_ENTRIES);
  } catch {
    return [];
  }
}

let entries: SyncFault[] = readStored();

function persist(): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(entries));
  } catch {
    // Storage blocked: the in-memory ring still serves this session.
  }
}

export function recordSyncFault(f: Omit<SyncFault, 'at' | 'n'>): void {
  // Observe-only: a failure site calls this just before it throws or
  // returns, so nothing in here may throw and replace the real error.
  try {
    if (isDemoMode()) return;
    const fault = cleanFault(f, Date.now());
    if (!fault) return;
    const last = entries[entries.length - 1];
    if (
      last && last.step === fault.step && last.status === fault.status &&
      last.code === fault.code && last.ref === fault.ref
    ) {
      entries = [...entries.slice(0, -1), { ...fault, n: (last.n ?? 1) + 1 }];
    } else {
      entries = [...entries, fault].slice(-MAX_ENTRIES);
    }
    persist();
  } catch {
    // A diagnostic must never break the pass it observes.
  }
}

/** A storage client error as a fault: its HTTP status and the service's
 *  code, or the error's class name when no response came back. */
export function recordStorageFault(
  step: 'file-up' | 'file-down' | 'file-delete',
  error: { name?: string; status?: unknown; code?: unknown },
  ref?: string,
): void {
  recordSyncFault({
    step,
    status: error?.status as number | undefined,
    code: (typeof error?.code === 'string' && error.code ? error.code : error?.name) as string | undefined,
    ref,
  });
}

/** Forget this account's faults, in memory and on disk. Called on
 *  sign-out beside clearSyncLog(), for the same reason. */
export function clearSyncFaults(): void {
  entries = [];
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Storage blocked: the in-memory copy is gone, which is what the report reads.
  }
}

/** The ring, oldest first. */
export function readSyncFaults(): SyncFault[] {
  return entries;
}
