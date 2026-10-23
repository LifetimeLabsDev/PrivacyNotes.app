import type { JournalEntry } from './trackerStats';
import type { TrackerDescriptor } from './wellnessTypes';

/**
 * The wellness CSV: one row per logged day, one column per tracker in the
 * registry's order, from the same entries the JSON envelope writes. A
 * spreadsheet or a doctor reads it, so every cell is a plain value: a number
 * as typed, a level by its name, a yes or no and a factor as 1 or 0, a dose
 * as taken, skipped or missed, the emotions of a day joined with "; ". A
 * tracker with no value in the rows gets no column, so a journal with mood
 * alone is a two-column sheet.
 * Spec: ops/docs/archive/wellness-statistics.md (section 12)
 */

export interface CsvLabels {
  /** The header of the first column. */
  date: string;
  name: (d: TrackerDescriptor) => string;
  level: (d: TrackerDescriptor, level: string) => string;
}

/** The units a header carries; the others are English words in a translated sheet. */
const HEADER_UNITS = new Set(['h', 'bpm', 'kg', 'lb']);

/**
 * A value cell. A field is quoted only when the grammar needs it, with every
 * inner quote doubled (RFC 4180).
 */
function raw(s: string): string {
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/**
 * A text cell written by the person: a name, a tag, a level. A spreadsheet
 * runs a cell that opens with a formula character, so such a cell gets a
 * leading apostrophe, which the sheet shows as text. Numbers never come here,
 * because a negative one opens with a minus.
 */
function text(s: string): string {
  return raw(/^[=+\-@\t\r]/.test(s) ? `'${s}` : s);
}

interface Column {
  header: string;
  cell: (e: JournalEntry) => string;
  /** A column stays only when one row says something. */
  keep: (cells: string[]) => boolean;
}

const anyFilled = (cells: string[]) => cells.some((c) => c !== '');

function columnsOf(d: TrackerDescriptor, labels: CsvLabels): Column[] {
  const name = labels.name(d);
  const header = d.unit && HEADER_UNITS.has(d.unit) ? `${name} (${d.unit})` : name;
  switch (d.kind) {
    case 'set':
      if (d.id === 'factors') {
        // One column per factor: a logged day either had it or did not.
        return (d.levels ?? []).map((id) => ({
          header: text(labels.level(d, id)),
          cell: (e) => {
            const v = d.read(e.data);
            return Array.isArray(v) && v.includes(id) ? '1' : '0';
          },
          keep: (cells) => cells.includes('1'),
        }));
      }
      return [{
        header: text(header),
        cell: (e) => {
          const v = d.read(e.data);
          return Array.isArray(v) && v.length ? text(v.map((l) => labels.level(d, l)).join('; ')) : '';
        },
        keep: anyFilled,
      }];
    case 'yesno':
      return [{
        header: text(header),
        cell: (e) => {
          const v = d.read(e.data);
          return typeof v === 'boolean' ? (v ? '1' : '0') : '';
        },
        keep: anyFilled,
      }];
    case 'medication':
      return [{
        header: text(header),
        cell: (e) => {
          const v = d.read(e.data);
          return typeof v === 'string' ? v : '';
        },
        keep: anyFilled,
      }];
    case 'ordinal':
      return [{
        header: text(header),
        cell: (e) => {
          const v = d.read(e.data);
          return typeof v === 'string' ? text(labels.level(d, v)) : '';
        },
        keep: anyFilled,
      }];
    default:
      return [{
        header: text(header),
        cell: (e) => {
          const v = d.read(e.data);
          return typeof v === 'number' ? String(v) : '';
        },
        keep: anyFilled,
      }];
  }
}

/** The sheet as text, with a byte order mark so Excel reads it as UTF-8. */
export function trackerCsv(
  entries: readonly JournalEntry[],
  registry: readonly TrackerDescriptor[],
  labels: CsvLabels,
): string {
  const columns = registry
    .flatMap((d) => columnsOf(d, labels))
    .map((col) => ({ col, cells: entries.map((e) => col.cell(e)) }))
    .filter(({ col, cells }) => col.keep(cells));
  const lines = [[text(labels.date), ...columns.map(({ col }) => col.header)].join(',')];
  entries.forEach((e, i) => {
    lines.push([e.date, ...columns.map(({ cells }) => cells[i]!)].join(','));
  });
  return `﻿${lines.join('\r\n')}\r\n`;
}
