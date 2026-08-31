/**
 * Shapes the Markdown panes share.
 *
 * Their own module because the list pane and the file pane both need them, and
 * a type living in one component that the other imports is the shape of an
 * import cycle waiting to happen.
 *
 * Spec: ops/docs/plans/markdown-folder.md (never write a file whose stamp changed underneath us)
 */
import type { AdaptedFile } from './adapter';
import type { DirectoryEntry, FileStamp, OpenedDirectoryRef, OpenedFileRef } from './fileAccess';

export interface OpenedMarkdownFile {
  ref: OpenedFileRef;
  /** The text we last read from or wrote to disk. */
  raw: string;
  /** Fingerprint of the file as we last saw it. Compared before every write. */
  stamp: FileStamp | null;
  adapted: AdaptedFile;
  /**
   * Bumped ONLY when the editor must throw away what it is showing and re-read
   * `raw` from scratch: a different file, or an explicit reload from disk.
   *
   * `MarkdownSourceEditor` is uncontrolled and reads `value` once on mount, so
   * its `key` is the only reload channel. The obvious key - something derived
   * from the file's stamp - remounts the textarea after every successful save,
   * which drops the caret and the user cannot keep typing. Our own writes must
   * never remount the editor; only somebody else's changes may.
   */
  reloadToken: number;
}

export interface OpenedMarkdownDir {
  ref: OpenedDirectoryRef;
  entries: DirectoryEntry[];
}

/**
 * What the header reports, and it has to be able to say "not yet".
 *
 * `dirty` exists because every other state only moves when a save COMPLETES.
 * Without it the label sticks on "Saved to disk" through the debounce window
 * and the write itself, which is precisely the stretch where the file on disk
 * does not match what is on screen. A status that cannot be wrong is worth
 * more than one that is usually right.
 */
export type SaveState =
  | { kind: 'idle' }
  /** Edited, not yet written. The one state the user must be able to see. */
  | { kind: 'dirty' }
  | { kind: 'saving' }
  | { kind: 'saved' }
  /** The file changed underneath us. Blocking: writing now would destroy
   *  whatever the other editor wrote. */
  | { kind: 'stale' }
  | { kind: 'error'; message: string };
