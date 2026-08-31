import { domainFromUrl, serializeLoginBody } from '../LoginForm';
import { readArchiveEntry } from './safariArchive';
import type { Importer, ImportedNote, ParsedImport } from './types';

/**
 * Browser password import adapter.
 *
 * Chrome, Edge, Brave, Opera, Vivaldi, Firefox and Safari all export
 * their saved passwords as a flat .csv with one row per login, so one
 * adapter reads all of them: the header row decides which columns to
 * take. Every row becomes a PN 'login' vault item.
 *
 * Two inputs, one parser: the bare .csv, or the .zip Safari's
 * "Export Browsing Data to File" writes around it. That archive can also
 * hold the bookmarks export, so `Passwords.csv` is picked by name.
 *
 * The three header shapes, verbatim:
 *   Chromium  name,url,username,password,note
 *             ("note" arrived in Chrome 108 - older exports have four
 *             columns and still parse)
 *   Firefox   url,username,password,httpRealm,formActionOrigin,guid,
 *             timeCreated,timeLastUsed,timePasswordChanged
 *   Safari    Title,URL,Username,Password,Notes,OTPAuth
 *
 * Firefox is the only one that carries dates (epoch milliseconds) and
 * the only one with no title column, so its titles are derived from the
 * site address. Safari is the only one that carries a TOTP key, as the
 * otpauth:// URI that `parseTotpInput` already reads.
 *
 * Adding another password manager that exports CSV (1Password, KeePass,
 * LastPass) is normally one more alias in COLUMNS, not a new adapter.
 */

/** Header cell names each source writes, lowercased and trimmed. */
const COLUMNS = {
  title: ['name', 'title'],
  url: ['url'],
  username: ['username'],
  password: ['password'],
  notes: ['note', 'notes'],
  totp: ['otpauth'],
  created: ['timecreated'],
  changed: ['timepasswordchanged'],
} as const;

type Field = keyof typeof COLUMNS;

/** Column index per field. -1 when this export has no such column. */
type ColumnMap = Record<Field, number>;

export const passwordCsvImporter: Importer = {
  id: 'browser-passwords',
  label: 'Browser passwords',
  description:
    'The passwords .csv from Chrome, Edge, Brave, Opera, Vivaldi, Firefox, or Safari, or the .zip Safari writes. Each row becomes a login.',
  accept: '.csv,text/csv,.zip',
  enabled: true,
  sourceTag: 'browser',

  async parse(file, onProgress) {
    onProgress?.('Reading file…');
    const text = stripBom(
      /\.zip$/i.test(file.name)
        ? await readArchiveEntry(file, 'Passwords.csv', /\.csv$/i)
        : await file.text()
    );
    if (!text.trim()) {
      throw new Error('That file is empty. Export your passwords again and pick the .csv format.');
    }

    onProgress?.('Reading the columns…');
    const rows = parseCsv(text, sniffDelimiter(firstLine(text)));
    const header = (rows.shift() ?? []).map((c) => c.trim().toLowerCase());
    const columns = resolveColumns(header);

    if (columns.password < 0 || (columns.url < 0 && columns.username < 0)) {
      throw new Error(
        'This .csv has no password column, so it is not a browser password export. In your browser, open the password manager and export again as .csv.'
      );
    }

    onProgress?.('Converting logins…');
    const notes: ImportedNote[] = [];
    const warnings: string[] = [];
    const transforms: string[] = [];

    let derivedTitles = 0;
    let totpCount = 0;
    let datedCount = 0;
    let noPassword = 0;

    for (const row of rows) {
      // Trailing newlines and blank separator lines both land here.
      if (row.every((c) => !c.trim())) continue;

      const url = cell(row, columns.url);
      const username = cell(row, columns.username);
      const password = cell(row, columns.password);
      const totp = cell(row, columns.totp);
      if (!password) noPassword++;
      if (totp) totpCount++;

      let title = cell(row, columns.title);
      if (!title) {
        title = domainFromUrl(url) || username;
        if (title) derivedTitles++;
      }

      const created = isoFromEpoch(cell(row, columns.created));
      const changed = isoFromEpoch(cell(row, columns.changed));
      if (created || changed) datedCount++;
      const now = new Date().toISOString();

      notes.push({
        title,
        body: serializeLoginBody({
          url,
          username,
          password,
          notes: cell(row, columns.notes),
          totp,
        }),
        tags: [],
        createdAt: created ?? changed ?? now,
        updatedAt: changed ?? created ?? now,
        type: 'login',
      });
    }

    if (notes.length === 0) {
      throw new Error('That .csv has a header but no logins under it.');
    }

    const source = detectSource(header);
    if (source) transforms.push(`Read the file as a ${source} passwords export.`);
    transforms.push(`Imported ${notes.length} login${notes.length === 1 ? '' : 's'} as vault items.`);
    if (derivedTitles > 0) {
      transforms.push(
        derivedTitles === 1
          ? 'Named 1 login after its site (this export has no title column).'
          : `Named ${derivedTitles} logins after their sites (this export has no title column).`
      );
    }
    if (datedCount > 0) {
      transforms.push(
        `Kept the original dates for ${datedCount} login${datedCount === 1 ? '' : 's'}.`
      );
    }
    if (totpCount > 0) {
      transforms.push(
        `Kept the 2FA authenticator key for ${totpCount} login${totpCount === 1 ? '' : 's'}.`
      );
    }

    if (noPassword > 0) {
      warnings.push(
        `${noPassword} row${noPassword === 1 ? ' has' : 's have'} no password (browsers write sign-in-with-Google entries that way). They import with the rest, so nothing is dropped.`
      );
    }

    return {
      notes,
      warnings,
      transforms,
      stats: {
        totalNotes: notes.length,
        // A login body is always JSON and these exports carry no tags, so
        // both counts are constant rather than measured.
        emptyNotes: 0,
        untaggedNotes: notes.length,
        uniqueTags: 0,
      },
      source: 'browser-passwords',
    } satisfies ParsedImport;
  },
};

/** Split a CSV document into rows of fields, per RFC 4180: quoted
 *  fields, doubled quotes inside them, and delimiters or newlines
 *  inside them. */
function parseCsv(text: string, delimiter: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];

    if (quoted) {
      if (ch === '"') {
        // A doubled quote is one literal quote; a single one ends the field.
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          quoted = false;
        }
        continue;
      }
      field += ch;
      continue;
    }

    // A quote only opens a field at its start, so an apostrophe inside
    // an unquoted password stays a plain character.
    if (ch === '"' && field === '') {
      quoted = true;
    } else if (ch === delimiter) {
      row.push(field);
      field = '';
    } else if (ch === '\n') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else if (ch !== '\r') {
      field += ch;
    }
  }

  if (field !== '' || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

/** Excel rewrites a .csv with the host locale's list separator, so a
 *  file that was opened and re-saved is not always comma-separated.
 *  Take whichever candidate splits the header into the most columns. */
function sniffDelimiter(headerLine: string): string {
  let best = ',';
  let bestCount = 1;
  for (const candidate of [',', ';', '\t']) {
    const count = headerLine.split(candidate).length;
    if (count > bestCount) {
      best = candidate;
      bestCount = count;
    }
  }
  return best;
}

/** Which browser wrote this, from the columns only it has. Used for the
 *  transform message, so the user can see the file was read as intended. */
function detectSource(header: string[]): string | null {
  if (header.includes('timepasswordchanged')) return 'Firefox';
  if (header.includes('otpauth')) return 'Safari';
  if (header.includes('name') && header.includes('url')) return 'Chrome';
  return null;
}

function resolveColumns(header: string[]): ColumnMap {
  const map = {} as ColumnMap;
  for (const field of Object.keys(COLUMNS) as Field[]) {
    map[field] = header.findIndex((cell) => (COLUMNS[field] as readonly string[]).includes(cell));
  }
  return map;
}

function cell(row: string[], index: number): string {
  if (index < 0) return '';
  return (row[index] ?? '').trim();
}

/** Firefox writes its three timestamps as epoch milliseconds. */
function isoFromEpoch(raw: string): string | null {
  if (!raw) return null;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n <= 0) return null;
  const d = new Date(raw.length <= 10 ? n * 1000 : n);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString();
}

/** Chrome on Windows writes a UTF-8 BOM, which would otherwise become
 *  part of the first header name and hide the "name" column. */
function stripBom(text: string): string {
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

function firstLine(text: string): string {
  const end = text.indexOf('\n');
  return end < 0 ? text : text.slice(0, end);
}
