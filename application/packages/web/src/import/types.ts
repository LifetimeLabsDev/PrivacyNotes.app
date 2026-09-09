/**
 * Shared types for the pluggable import system.
 *
 * Each "importer" is an adapter that reads a foreign note-app export
 * (Standard Notes, Obsidian, Apple Notes, plain markdown folder, …) and
 * normalizes it into ImportedNote[]. The apply step is shared - it takes
 * ImportedNote[] and writes them into Dexie with dirty=1, then lets the
 * existing sync pass encrypt + upload them.
 *
 * Adding a new importer:
 *   1. Create a new file in this folder (e.g. `obsidian.ts`) exporting
 *      an object that satisfies the `Importer` interface.
 *   2. Register it in `registry.ts`.
 *   3. Add its id to the list of the tab it belongs under, in
 *      `ImportModal.tsx` (`noteIds` for Import, `vaultIds` for
 *      Passwords). Give it an icon and a description key there too.
 */

import type { FolderDef } from '../folders';

/**
 * Tag applied to notes the source app had archived (Standard Notes,
 * Google Keep). PrivacyNotes has no archive view, and sending them to
 * the trash would hand them to the auto-purge, which permanently deletes
 * anything that outlives the retention window - so an archive would
 * quietly become a 30-day timer. They import as ordinary notes wearing
 * this tag instead, which gives the user a one-click filter that behaves
 * like the archive they came from. Shared so both importers, and the
 * next one that needs it, agree on the name.
 */
export const ARCHIVED_TAG = 'archived';

/** One note, normalized to the shape PrivacyNotes cares about. */
export interface ImportedNote {
  title: string;
  body: string;
  /** Already normalized (lowercase, no #, no weird chars). */
  tags: string[];
  /** ISO 8601 - preserve the original timestamp whenever possible. */
  createdAt: string;
  /** ISO 8601. */
  updatedAt: string;
  /** Optional - only set if the source format has a trash/archive flag. */
  trashed?: boolean;
  /** Optional - only set if the source format has a star/pin flag. */
  starred?: boolean;
  /** Note type - 'note' | 'login' | 'card' | 'ssh-key'. Defaults to 'note'. */
  type?: import('@notes/shared').NoteType;
  /** Pro: prevent accidental edits. */
  locked?: boolean;
  /** Pro: gate this note behind the user's PIN. */
  pinProtected?: boolean;
  /** Mood & wellness tracker data for journal entries. */
  trackers?: Record<string, unknown>;
  /** Folder membership. Set by the PrivacyNotes backup formats and by the
   *  Obsidian importer, which rebuilds the vault's folder tree. */
  folderId?: string | null;
  /** Transient: the note's full original folder path segments (e.g.
   *  ["Work", "Projects", "2026"]). Used at apply time to derive folder
   *  tags and the deep-nesting overflow fallback. Not persisted. */
  folderPath?: string[];
  /** Transient: labels the source app stored alongside the item but that
   *  are NOT tags here until the user opts in - Firefox bookmark tags and
   *  address-bar keywords. `withBrowserTags` merges them into `tags`.
   *  Not persisted. */
  browserTags?: string[];
}

/** What an importer returns after successfully parsing a file. */
/**
 * One blob an importer carries across. `processed` marks a picture the
 * importer already ran through the image switches, so the shared blob
 * import does not shrink it a second time.
 */
export type ImportBlob = {
  data: Uint8Array;
  mime: string;
  name: string;
  processed?: boolean;
  /** A contact photo obeys the contact ceiling on top of the image switches. */
  ceiling?: 'contact';
};

export interface ParsedImport {
  notes: ImportedNote[];
  /** Non-fatal issues worth surfacing in the UI ("3 notes had no title", etc.). */
  warnings: string[];
  /**
   * Positive transforms we applied during import - things like
   * "made URLs clickable in 87 notes". Rendered in accent color, not
   * amber, so the user reads them as upgrades rather than warnings.
   */
  transforms: string[];
  /** Stats for the preview pane. */
  stats: {
    totalNotes: number;
    emptyNotes: number;
    untaggedNotes: number;
    uniqueTags: number;
  };
  /** Machine id of the importer that produced this. */
  source: ImporterId;
  /** Total uncompressed size of image/attachment blobs in the backup.
   *  Only set for importers that restore blobs (privacynotes). Used by
   *  the quota preflight to avoid under-counting. */
  blobBytes?: number;
  /**
   * Attachment/image blobs extracted during parsing.
   * Keyed by the relative path as referenced in the markdown body
   * (e.g. "Attachments/UUID.jpeg" or "images/photo.jpg").
   * Used by post-apply blob import to store and rewrite references.
   */
  blobs?: Map<string, ImportBlob>;
  /**
   * Folder definitions rebuilt from the source's structure (Obsidian
   * subfolders). Merged into the user's settings folder tree at apply
   * time so each note's folderId resolves to a real folder.
   */
  folders?: FolderDef[];
}

/** Importer identifiers - add new ones here as adapters land. */
export type ImporterId =
  | 'standard-notes'
  | 'google-keep'
  | 'obsidian'
  | 'notesnook'
  | 'upnote'
  | 'apple-notes'
  | 'apple-journal'
  | 'evernote'
  | 'samsung-notes'
  | 'simplenote'
  | 'markdown-folder'
  // The four on-disk markdown apps. Each is an ALIAS of markdown-folder: same
  // parser, own row in the picker, own source tag, own guide. They exist
  // because a Typora user scans the list for "Typora", finds nothing, and
  // concludes we cannot read their notes - the one row named after a file
  // format answers a question nobody asks.
  | 'typora'
  | 'ia-writer'
  | 'zettlr'
  | 'nextcloud-notes'
  | 'privacynotes'
  | 'bitwarden'
  | 'browser-bookmarks'
  | 'browser-passwords'
  | 'vcard';

export interface Importer {
  id: ImporterId;
  label: string;
  /** One-line description shown under the importer button. */
  description: string;
  /** HTML file input `accept` attribute (e.g. ".zip,.txt"). */
  accept: string;
  /** Flag for the registry: grey out and disable the row if false. */
  enabled: boolean;
  /** Tag automatically added to every imported note when auto-tagging is on. */
  sourceTag: string;
  /**
   * Read a file and return the normalized notes. Must throw on fatal
   * errors (corrupt file, wrong format) - the UI will catch and display.
   *
   * `onProgress` is optional and called with human-readable status
   * messages during long operations ("Reading zip…", "Parsing JSON…").
   */
  parse(file: File, onProgress?: (msg: string) => void): Promise<ParsedImport>;
}

/** Result of writing a ParsedImport into the local DB. */
export interface ApplyResult {
  imported: number;
  /** Errors encountered per-note, so the user knows if anything was skipped. */
  errors: string[];
  /** IDs of the notes that were created, in the same order as the input. */
  noteIds: string[];
  /** Bookmarks skipped because a bookmark with the same URL already
   *  exists (exact-match, non-trashed). Only ever set for 'link' rows. */
  skippedDuplicates?: number;
}
