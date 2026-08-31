import type { Importer, ImporterId } from './types';
import { standardNotesImporter } from './standardNotes';
import { googleKeepImporter } from './googleKeep';
import { parseMarkdown } from './markdown';
import { parseObsidian } from './obsidian';
import { parseNotesnook } from './notesnook';
import { parseUpNote } from './upnote';
import { parseAppleNotes } from './appleNotes';
import { parseAppleJournal } from './appleJournal';
import { parseEvernote } from './evernote';
import { parseSamsungNotes } from './samsungNotes';
import { parsePrivacyNotesBackup } from './privacynotes';
import { bitwardenImporter } from './bitwarden';
import { passwordCsvImporter } from './passwordCsv';
import { simplenoteImporter } from './simplenote';
import { parseBrowserBookmarks } from './browserBookmarks';

/**
 * Registry of available importers, keyed by id at every call site. Each
 * picker owns its own running order (`noteIds` in ImportPickPhase,
 * `vaultIds` in VaultPickPhase), so the order here carries no meaning.
 * An entry with `enabled: false` renders greyed out and unclickable.
 */
/** Display names for the markdown-app aliases below. Brand names, so they are
 *  not translated; the row's DESCRIPTION comes from the catalog. */
const MARKDOWN_APP_LABEL = {
  'typora': 'Typora',
  'ia-writer': 'iA Writer',
  'zettlr': 'Zettlr',
  'nextcloud-notes': 'Nextcloud Notes',
} as const;

const MARKDOWN_ACCEPT = '.md,.markdown,.mdown,.mkd,.txt,.zip';

const MARKDOWN_APP_DESCRIPTION =
  'These notes are already Markdown files in a folder. Drop that folder in as a .zip and its subfolders, images, and #tags come with it.';

export const IMPORTERS: Importer[] = [
  {
    id: 'privacynotes',
    label: 'PrivacyNotes full backup',
    description:
      'Restore a full backup (.zip) including notes, journals, vault, tasks, images, audio, and files.',
    accept: '.zip',
    enabled: true,
    sourceTag: '',
    parse: parsePrivacyNotesBackup,
  },
  googleKeepImporter,
  {
    id: 'browser-bookmarks',
    label: 'Browser bookmarks',
    // Deliberately no sourceTag: the recreated folder tree already answers
    // "where did this come from", so an auto tag would only add noise.
    // Spec: ops/docs/plans/bookmarks-pillar.md (import mapping)
    description:
      'Chrome, Firefox, Safari, or Edge - the bookmarks .html file from "Export bookmarks", or the .zip Safari writes. Folders come along, dates survive, and re-importing the same file skips what you already have.',
    accept: '.html,.htm,.zip',
    enabled: true,
    sourceTag: '',
    parse: parseBrowserBookmarks,
  },
  {
    id: 'evernote',
    label: 'Evernote',
    description:
      'One .enex on its own, or several zipped together. Keeps formatting, tags, attachments, note links, and notebooks. Evernote leaves tasks out of .enex.',
    accept: '.enex,.zip',
    enabled: true,
    sourceTag: 'evernote',
    parse: parseEvernote,
  },
  {
    id: 'apple-notes',
    label: 'Apple Notes',
    description:
      'Import from Apple Notes via the free Exporter app. Export as Markdown, then drop the .zip here.',
    accept: '.zip',
    enabled: true,
    sourceTag: 'apple',
    parse: parseAppleNotes,
  },
  {
    id: 'apple-journal',
    label: 'Apple Journal',
    description:
      'Export from Journal on Mac or iPhone, compress the AppleJournalEntries folder, and drop the .zip. Entries import as journal entries with their photos, videos, voice memos, and locations.',
    accept: '.zip',
    enabled: true,
    sourceTag: 'apple-journal',
    parse: parseAppleJournal,
  },
  {
    id: 'samsung-notes',
    label: 'Samsung Notes',
    description:
      'Export from Samsung Notes as Word (.docx) for rich formatting, or as Text (.txt) for plain text. Zip multiple files for bulk import.',
    accept: '.zip,.txt,.docx',
    enabled: true,
    sourceTag: 'samsung',
    parse: parseSamsungNotes,
  },
  simplenoteImporter,
  standardNotesImporter,
  bitwardenImporter,
  passwordCsvImporter,
  {
    id: 'obsidian',
    label: 'Obsidian',
    description:
      'Import an Obsidian vault (.zip). Preserves tags, [[note links]], folder structure, inline #tags, and embedded images and files.',
    accept: '.zip',
    enabled: true,
    sourceTag: 'obsidian',
    parse: parseObsidian,
  },
  {
    id: 'notesnook',
    label: 'Notesnook',
    description:
      'Export all notes from Notesnook as HTML (.zip). Preserves notebooks as folders, tags, internal links, attachments, and formatting.',
    accept: '.zip,.nnbackupz',
    enabled: true,
    sourceTag: 'notesnook',
    parse: parseNotesnook,
  },
  {
    id: 'upnote',
    label: 'UpNote',
    description:
      'In UpNote: Settings > Backup > Backup now, then zip everything in the backup folder. Keeps notebooks, tags, pins, note links, formatting, and attachments. Per-note exports from the phone apps work too - pick "Export to HTML".',
    accept: '.md,.html,.zip',
    enabled: true,
    sourceTag: 'upnote',
    parse: parseUpNote,
  },
  // Aliases of markdown-folder: one parser, four rows. `parse` is deliberately
  // the same function rather than a wrapper - there is nothing app-specific to
  // do, and a wrapper would invite one to grow. What differs is what the user
  // sees: the app's name, its icon, its guide, and the tag its notes arrive
  // with. Adding a fifth is four lines here plus a row in ImportModal.
  ...(['typora', 'ia-writer', 'zettlr', 'nextcloud-notes'] as const).map((id) => ({
    id,
    label: MARKDOWN_APP_LABEL[id],
    description: MARKDOWN_APP_DESCRIPTION,
    accept: MARKDOWN_ACCEPT,
    enabled: true,
    sourceTag: id,
    parse: parseMarkdown,
  })),
  {
    id: 'markdown-folder',
    label: 'Markdown files',
    description:
      'Import .md or .txt files individually or as a .zip. A zipped folder keeps its subfolders and brings its images and attachments along. Works with PrivacyNotes exports, Obsidian vaults, or any plain markdown.',
    accept: MARKDOWN_ACCEPT,
    enabled: true,
    sourceTag: 'markdown',
    parse: parseMarkdown,
  },
];
