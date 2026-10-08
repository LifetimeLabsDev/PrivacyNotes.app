import Dexie from 'dexie';
import { db } from './db';
import { countWords } from './wordCountUtils';

/**
 * The day ledger: words, edits and creates per local day, and edits per hour
 * of the local clock. A note keeps one word count and one stamp, not a
 * history, so this is the only record of writing over time. Only the note
 * write path (notesRepo createNote and updateNote) records here, so an
 * import, a sync pull, a conflict merge and every other direct row write
 * never count, and a create that brings content in from elsewhere (a
 * conflict copy, a Markdown-folder copy, a share) passes `counted: false`.
 * Local to this device and never synced.
 *
 * Rows hold counts only, never note text, so the table stays outside the
 * at-rest seal (localSeal.ts SEALED_TABLES).
 * Spec: ops/docs/plans/wellness-statistics.md (section 20)
 */
export interface LedgerRow {
  /** Local calendar day, `YYYY-MM-DD`. */
  date: string;
  /** Net words added that day; negative when more were removed. */
  words: number;
  edits: number;
  creates: number;
  /** Edits per hour of the local clock, index 0 to 23. */
  hours: number[];
  /** True on a row the backfill estimated from a note's stamps, not one counted at the keyboard. */
  estimated?: boolean;
}

/** One write, as the repo saw it. Bodies are the plaintext at the call site. */
export type LedgerWrite =
  | { kind: 'create'; body: string }
  | { kind: 'edit'; prevBody: string; nextBody: string };

/** Local calendar day as `YYYY-MM-DD`, the same key as intlFormat.ts
 *  toLocalIso. Not imported from there: that module pulls the i18n runtime
 *  into notesRepo, which the write path must not carry. */
function localDay(d: Date): string {
  const pad = (n: number) => (n < 10 ? `0${n}` : String(n));
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

// Writes run one after another, so a read-modify-write never loses a count,
// and readers wait for the queue so they see every write already recorded.
let tail: Promise<void> = Promise.resolve();

async function apply(write: LedgerWrite, at: Date): Promise<void> {
  const words =
    write.kind === 'create'
      ? countWords(write.body)
      : write.prevBody === write.nextBody
        ? 0
        : countWords(write.nextBody) - countWords(write.prevBody);
  const date = localDay(at);
  // Outside any transaction the caller may be inside: that one does not
  // cover this table.
  await Dexie.ignoreTransaction(() =>
    db.transaction('rw', db.dayLedger, async () => {
      const row: LedgerRow = (await db.dayLedger.get(date)) ?? {
        date,
        words: 0,
        edits: 0,
        creates: 0,
        hours: new Array<number>(24).fill(0),
      };
      // A day the backfill estimated is counted from its first real write.
      delete row.estimated;
      row.words += words;
      row.edits += 1;
      if (write.kind === 'create') row.creates += 1;
      row.hours[at.getHours()] = (row.hours[at.getHours()] ?? 0) + 1;
      await db.dayLedger.put(row);
    }),
  );
}

/**
 * Count one write. Never throws and never makes the caller wait: the note is
 * already stored, and a lost count is better than a failed or slower save.
 */
export function recordLedgerWrite(write: LedgerWrite, at: Date = new Date()): void {
  try {
    tail = tail.then(() => apply(write, at)).catch(() => {});
  } catch {
    /* counting is best-effort */
  }
}

/** The rows from `from` to `to`, both local ISO days, inclusive, oldest first. */
export async function readLedger(from: string, to: string): Promise<LedgerRow[]> {
  await tail;
  return db.dayLedger.where('date').between(from, to, true, true).toArray();
}

/** The first day the ledger holds, estimated or counted, or null when empty. */
export async function firstLedgerDay(): Promise<string | null> {
  await tail;
  const first = await db.dayLedger.orderBy('date').first();
  return first?.date ?? null;
}

/** The first day this device counted at the keyboard, or null before the
 *  first counted write: the day an estimated row is never it. */
export async function firstCountedDay(): Promise<string | null> {
  await tail;
  const first = await db.dayLedger.orderBy('date').filter((r) => !r.estimated).first();
  return first?.date ?? null;
}

/**
 * The one-time estimate of the days before counting started, from the stamps
 * every note already carries: its words on the day it was created, one edit on
 * the day it was last changed, each at the hour of the stamp. Runs only while
 * the ledger is empty, so a device that counts for real is never overwritten.
 * The rows are marked, and the Overview says so.
 * Spec: ops/docs/plans/wellness-statistics.md (section 20)
 */
export async function backfillLedger(notes: ReadonlyArray<{ body: string; createdAt: string; updatedAt: string; deleted: number }>): Promise<boolean> {
  await tail;
  if ((await db.dayLedger.count()) > 0) return false;
  const rows = new Map<string, LedgerRow>();
  const row = (date: string) => {
    const hit = rows.get(date);
    if (hit) return hit;
    const fresh: LedgerRow = { date, words: 0, edits: 0, creates: 0, hours: new Array<number>(24).fill(0), estimated: true };
    rows.set(date, fresh);
    return fresh;
  };
  for (const n of notes) {
    if (n.deleted === 1) continue;
    const created = new Date(n.createdAt);
    const updated = new Date(n.updatedAt);
    if (Number.isNaN(created.getTime())) continue;
    const c = row(localDay(created));
    c.words += countWords(n.body);
    c.creates += 1;
    c.edits += 1;
    c.hours[created.getHours()] = (c.hours[created.getHours()] ?? 0) + 1;
    if (!Number.isNaN(updated.getTime()) && localDay(updated) !== localDay(created)) {
      const u = row(localDay(updated));
      u.edits += 1;
      u.hours[updated.getHours()] = (u.hours[updated.getHours()] ?? 0) + 1;
    }
  }
  if (rows.size === 0) return false;
  await db.dayLedger.bulkPut([...rows.values()]);
  return true;
}
