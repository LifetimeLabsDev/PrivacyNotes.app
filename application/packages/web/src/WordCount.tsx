import { useEffect, useMemo, useRef, useState } from 'react';
import i18n from './i18n';
import { stripMarkdown, countWords, countChars } from './wordCountUtils';
import { intlLocale } from './languages';
import { countTasks } from './tasks';

/** The server rejects any note whose encrypted payload exceeds 1 MB
 *  (schema: notes_ciphertext_max_1mb), and the editor drags well before
 *  that: a ~100k-word note is ~850 KB stored and already stutters. Three
 *  escalating heads-ups, anchored to estimated stored size (not word
 *  count, so non-Latin notes warn accurately too). Word figures assume
 *  ~8.5 stored bytes/word, measured from a lorem note:
 *    - grey  ~50k words (~41%): gentle, slower devices only
 *    - amber ~75k words (~62%): editing drags on any device
 *    - amber from 70%: the share of the 1 MB sync limit, with "Split note";
      red over it: the note stays on this device
 *  Amber is the most severe state - long is a caution, not an error. An
 *  actual over-1 MB sync failure is still surfaced by the "failed to
 *  sync" banner. */
const SYNC_LIMIT_BYTES = 1_048_576;
// From here the line says how much of the 1 MB sync limit the note uses and
// offers "Split note". Spec: ops/docs/plans/note-size-limit.md
const SYNC_FRACTION = 0.7;
const SLOW_FRACTION = 0.62; // amber: ~75k words, editing drags
const INFO_FRACTION = 0.41; // grey: ~50k words, gentle heads-up

/** Debounce interval before re-computing word count. Keeps the
 *  expensive stripMarkdown regex off the hot path while typing. */
const WORD_COUNT_DEBOUNCE_MS = 600;

/** A single table past this many rows makes the editor sluggish: ProseMirror
 *  renders every cell and does not virtualize, so a ~560-row table is already
 *  ~5,800 live DOM nodes and a ~150 ms paste-parse. Past this we surface a
 *  heads-up suggesting the note be split, the editor-perf sibling of the
 *  sync-size warnings above.
 *  Spec: ops/docs/design-decisions.md (large-table editor warning) */
const BIG_TABLE_ROWS = 200;

export function WordCount({
  body,
  sizeOf,
  onSplit,
  onOverLimit,
}: {
  body: string;
  /** The exact stored size of the note with this body (storedNoteBytes);
   *  without it the size is estimated from the body alone. */
  sizeOf?: (body: string) => number;
  /** Offered beside the sync-limit line; left out where a split cannot run. */
  onSplit?: () => void;
  /** Called when the measure finds the note over the sync limit. */
  onOverLimit?: () => void;
}) {
  const sizeRef = useRef(sizeOf);
  sizeRef.current = sizeOf;
  const [display, setDisplay] = useState(() => compute(body, sizeOf));
  const timerRef = useRef<number | null>(null);

  useEffect(() => {
    if (timerRef.current) window.clearTimeout(timerRef.current);
    timerRef.current = window.setTimeout(() => {
      setDisplay(compute(body, sizeRef.current));
    }, WORD_COUNT_DEBOUNCE_MS);
    return () => {
      if (timerRef.current) window.clearTimeout(timerRef.current);
    };
  }, [body]);

  // The task count skips the debounce: a tick should move the number at once,
  // and counting lines is cheap next to stripping the markdown.
  const tasks = useMemo(() => countTasks(body), [body]);

  const over = !!display?.overLimit;
  const overRef = useRef(onOverLimit);
  overRef.current = onOverLimit;
  useEffect(() => {
    if (over) overRef.current?.();
  }, [over]);

  if (!display) return null;

  const taskPart = tasks.total > 0
    ? ' · ' + i18n.t('editor:wordCount.tasksChecked', {
        count: tasks.total,
        done: tasks.done.toLocaleString(intlLocale()),
        formatted: tasks.total.toLocaleString(intlLocale()),
      })
    : '';

  // Spacing is owned by the footer row in NotesView (2-col: counts on the
  // left, editor-mode link on the right).
  // Spec: ops/specs/editor-mode-toggle.md (per-note override is session-scoped, never synced)
  return (
    <div className="select-none space-y-0.5">
      {display.label && (
        <div className={`text-xs ${display.colorClass}`}>
          {display.label + taskPart + display.warning}
          {display.nearLimit && onSplit && (
            <>
              {' '}
              <button type="button" onClick={onSplit} className="underline text-accent hover:text-accent-strong">
                {i18n.t('editor:wordCount.split')}
              </button>
            </>
          )}
        </div>
      )}
      {display.tableWarning && (
        <div className="text-xs text-warning">
          {display.tableWarning}
        </div>
      )}
    </div>
  );
}

/**
 * Largest table in the body, measured in rows. Pipe tables: the longest run of
 * consecutive lines that look like table rows (start with `|`). Non-pipe tables
 * serialize to HTML, so also count `<tr>` tags. Used only to size the editor
 * heads-up, so an approximate count (header + separator rows included) is fine.
 */
function largestTableRows(md: string): number {
  let max = 0;
  let run = 0;
  for (const line of md.split('\n')) {
    if (/^\s*\|.*\|/.test(line)) {
      run += 1;
      if (run > max) max = run;
    } else {
      run = 0;
    }
  }
  const htmlRows = (md.match(/<tr[\s>]/gi) ?? []).length;
  return Math.max(max, htmlRows);
}

/** Heads-up string when the body holds a table big enough to slow the editor. */
function tableSizeWarning(md: string): string | null {
  const rows = largestTableRows(md);
  if (rows <= BIG_TABLE_ROWS) return null;
  return i18n.t('editor:wordCount.largeTableWarning', { rows: rows.toLocaleString(intlLocale()) });
}

function compute(body: string, sizeOf?: (body: string) => number) {
  const tableWarning = tableSizeWarning(body);
  const text = stripMarkdown(body).trim();
  if (!text) {
    // No prose to count, but a giant (mostly empty) table still warrants the
    // editor-perf heads-up. Otherwise render nothing.
    return tableWarning
      ? { label: null as string | null, warning: '', colorClass: '', tableWarning, nearLimit: false, overLimit: false }
      : null;
  }
  const words = countWords(body);
  const chars = countChars(body);

  // Estimate the note's stored size to predict the 1 MB sync ceiling.
  // The whole raw body is encrypted (markdown syntax included), so size
  // it by UTF-8 bytes - not characters - so the warning is accurate for
  // non-Latin scripts too. AEAD nonce/tag add ~28 bytes; base64 inflates
  // the stored ciphertext by 4/3.
  const estStoredBytes = sizeOf
    ? sizeOf(body)
    : Math.ceil(((new TextEncoder().encode(body).length + 28) * 4) / 3);

  let colorClass = 'text-pn-muted';
  const label =
    i18n.t('editor:wordCount.words', { count: words, formatted: words.toLocaleString(intlLocale()) }) +
    ' · ' +
    i18n.t('editor:wordCount.characters', { count: chars, formatted: chars.toLocaleString(intlLocale()) });

  // The size heads-up ends the line, after the task count the component adds.
  let warning = '';
  const nearLimit = estStoredBytes >= SYNC_LIMIT_BYTES * SYNC_FRACTION;
  if (estStoredBytes > SYNC_LIMIT_BYTES) {
    colorClass = 'text-danger';
    warning = i18n.t('editor:wordCount.overSyncLimit');
  } else if (nearLimit) {
    colorClass = 'text-warning';
    const share = Math.min(99, Math.floor((estStoredBytes / SYNC_LIMIT_BYTES) * 100));
    warning = i18n.t('editor:wordCount.syncLimit', {
      share: (share / 100).toLocaleString(intlLocale(), { style: 'percent' }),
    });
  } else if (estStoredBytes >= SYNC_LIMIT_BYTES * SLOW_FRACTION) {
    colorClass = 'text-warning';
    warning = i18n.t('editor:wordCount.veryLong');
  } else if (estStoredBytes >= SYNC_LIMIT_BYTES * INFO_FRACTION) {
    warning = i18n.t('editor:wordCount.gettingLong');
  }

  return { label: label as string | null, warning, colorClass, tableWarning, nearLimit, overLimit: estStoredBytes > SYNC_LIMIT_BYTES };
}
