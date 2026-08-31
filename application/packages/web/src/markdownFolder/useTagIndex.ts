/**
 * Tags for a whole folder, read in the background.
 *
 * The directory scan deliberately reads no file contents - it walks names, which
 * is what makes a large vault open instantly. But tags live INSIDE files, in
 * front matter and inline, so the rail cannot show them without reading
 * everything. That read is this hook, and it is a background pass on purpose:
 * the file list is usable immediately and the tag section fills in behind it,
 * rather than the folder appearing to hang on a thousand reads.
 *
 * Results arrive incrementally, so a vault that takes a while still shows its
 * common tags early. Nothing here writes, and nothing blocks the editor.
 *
 * A LATER pass is incremental too. The entry list changes identity on every
 * rescan, so creating or deleting a single file re-runs this hook - and reading
 * the whole folder again for it used to blank every row's tags, excerpt, date
 * and size while it ran. What has already been read therefore survives the
 * re-run: each pass fingerprints what it knows and only reads what is new or
 * has changed underneath us.
 *
 * Spec: ops/docs/plans/markdown-folder.md (section 9)
 */
import { useEffect, useRef, useState } from 'react';
import { adaptFile } from './adapter';
import { countWords } from '../wordCountUtils';
import { stampsMatch, type DirectoryEntry, type FileStamp } from './fileAccess';

/** Files read at once. High enough to keep the disk busy, low enough that the
 *  reads never starve the editor's own saves - both go through the same handle
 *  APIs, and a save that queues behind 2000 reads looks like a hang. */
const CONCURRENCY = 8;
/** Results are published every this many files rather than per file, so a big
 *  vault does not re-render the rail thousands of times. */
const PUBLISH_EVERY = 50;

/** Everything the list needs about a file that only its CONTENTS can answer.
 *  Gathered in the same pass, because having read the file already is what
 *  makes a preview and a real date free rather than a second sweep. */
export interface FileMeta {
  tags: string[];
  /** Enough body for `NoteRow` to derive its excerpt. Truncated because a
   *  thousand full files in memory is a leak wearing a cache's clothes. */
  excerpt: string;
  mtime: number | null;
  /** Bytes on disk, for the size sort. Same read as everything else here. */
  size: number | null;
  /** Words in the WHOLE body, counted here rather than downstream from
   *  `excerpt`. The excerpt is truncated, so counting it would report a
   *  fraction of the folder under a label that means a true total in every
   *  other pillar. This pass has the full text in hand and throws it away, so
   *  the honest number costs nothing but the arithmetic. */
  words: number;
}

export interface TagIndex {
  /** Tag to the number of files carrying it. */
  counts: Map<string, number>;
  /** Relative path to what reading that file told us. */
  byPath: Map<string, FileMeta>;
  /** Entries this pass has been through, against `entries.length`. An entry
   *  already known from an earlier pass counts once it has been fingerprinted,
   *  which is all a pass owes a file that has not changed. */
  scanned: number;
  done: boolean;
}

/** Body kept per file for the row preview. */
const EXCERPT_CHARS = 300;

const EMPTY: TagIndex = { counts: new Map(), byPath: new Map(), scanned: 0, done: false };

/** The fingerprint a previous pass recorded for a file, in the shape
 *  `stampsMatch` compares. Null when the platform could not answer, which that
 *  helper deliberately reads as CHANGED rather than as unchanged. */
function stampOf(meta: FileMeta): FileStamp | null {
  return meta.mtime === null || meta.size === null ? null : { size: meta.size, mtime: meta.mtime };
}

/** Tag counts rebuilt from what has been read so far. Cheaper to recompute per
 *  publish than to keep a running tally in step, because a re-read and a delete
 *  both have to REMOVE a file's previous tags as well as add its new ones. */
function countTags(byPath: Map<string, FileMeta>): Map<string, number> {
  const counts = new Map<string, number>();
  for (const meta of byPath.values()) {
    for (const tag of meta.tags) counts.set(tag, (counts.get(tag) ?? 0) + 1);
  }
  return counts;
}

export function useTagIndex(entries: DirectoryEntry[] | null): TagIndex {
  const [index, setIndex] = useState<TagIndex>(EMPTY);
  /** What every pass so far has read, keyed by path and kept ACROSS effect
   *  runs. This is what makes a rescan incremental instead of a restart. */
  const readRef = useRef(new Map<string, FileMeta>());
  /** Whether a full pass has finished over what is in that cache. Consumers key
   *  their "not read yet" copy off `done` - `MarkdownListPane` hides every
   *  row's preview and date while it is false - so an incremental pass over an
   *  already-read folder must not drop it back to false for the one new file. */
  const doneRef = useRef(false);

  useEffect(() => {
    const read = readRef.current;
    if (!entries || entries.length === 0) {
      read.clear();
      doneRef.current = false;
      setIndex({ ...EMPTY, done: true });
      return;
    }

    // Guards every publish and every cache write below. Without it, switching
    // folders mid-pass lets the old folder's tags land in the new folder's rail,
    // and a superseded pass writes its results over a newer one's.
    let cancelled = false;

    // Files that are gone stop counting straight away: their tags are no longer
    // in the folder, and the rail would otherwise offer a filter matching
    // nothing. Nothing survived means this is a folder we have not read, so
    // `done` starts false again.
    const live = new Set(entries.map((e) => e.relPath));
    for (const relPath of [...read.keys()]) if (!live.has(relPath)) read.delete(relPath);
    if (read.size === 0) doneRef.current = false;

    let scanned = 0;
    let cursor = 0;

    const publish = (done: boolean) => {
      if (cancelled) return;
      if (done) doneRef.current = true;
      setIndex({ counts: countTags(read), byPath: new Map(read), scanned, done: doneRef.current });
    };

    async function worker() {
      while (!cancelled) {
        const i = cursor++;
        const entry = entries![i];
        if (!entry) return;
        try {
          // Fingerprint first. A stat is a fraction of a read, so an unchanged
          // file costs one and keeps the metadata it already has, which is what
          // turns "one file was created" back into one file's worth of work.
          const stamp = await entry.ref.stamp();
          if (cancelled) return;
          const known = read.get(entry.relPath);
          if (!known || !stampsMatch(stampOf(known), stamp)) {
            const raw = await entry.ref.read();
            if (cancelled) return;
            const { tags, body } = adaptFile(entry.ref.name, raw);
            read.set(entry.relPath, {
              tags,
              excerpt: body.slice(0, EXCERPT_CHARS),
              mtime: stamp?.mtime ?? null,
              size: stamp?.size ?? null,
              words: countWords(body),
            });
          }
        } catch {
          // An unreadable file is not worth failing the whole pass over - it
          // simply contributes no tags. It stays listed and openable, where the
          // error can be reported in context.
        }
        scanned++;
        if (scanned % PUBLISH_EVERY === 0) publish(false);
      }
    }

    // Publish what is already known BEFORE reading anything, so the rows carry
    // their metadata through the whole pass rather than emptying and refilling.
    publish(false);
    void Promise.all(Array.from({ length: Math.min(CONCURRENCY, entries.length) }, worker))
      .then(() => publish(true));

    return () => { cancelled = true; };
  }, [entries]);

  return index;
}
