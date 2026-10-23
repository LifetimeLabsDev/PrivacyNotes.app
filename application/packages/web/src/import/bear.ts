import JSZip from 'jszip';
import { zipEntryBytes, zipEntryText } from './zipEntry';
import { normalizeTag, parseYamlTags, TAG_MAX_LENGTH } from '../notesRepo';
import { buildFolderTree } from './folderImport';
import { FRONT_MATTER } from '../markdownFolder/adapter';
import { HIGHLIGHT_COLORS } from '../editorColors';
import { noteLinkTarget } from '../noteLinks';
import { linkifyMarkdown } from './linkify';
import { mapOutsideCode, proseOnly, stripHtmlComments } from './codeSegments';
import { isBlobReferenced, mimeFromExt } from './blobImport';
import type { ImportBlob, ImportedNote, ParsedImport } from './types';

/**
 * Bear importer.
 *
 * Reads the backup (File > Backup Notes..., a `.bear2bk`) and, as the second
 * input, a zipped File > Export Notes... in Markdown or Text Bundle. Both are
 * zips of plain Markdown:
 *
 *   backup / Text Bundle   <title>.textbundle/text.md, info.json, assets/<file>
 *   Markdown export        <title>.md, and its files in <title>/<file>
 *
 * Only the backup's info.json carries the note's state: `archived`,
 * `trashed`, `pinned`, `locked` (Bear's read-only), the two dates and
 * `uniqueIdentifier`. The exports leave archived and trashed notes out.
 *
 * Mapping:
 *   first line `# Title`        -> the title (any first line is the title in Bear)
 *   #tag, #nested/tag, #a b#    -> tags, read with Bear's own rule (bearTags);
 *                                  the text stays as written. Nested tags also
 *                                  rebuild as folders, the note in the folder of
 *                                  its deepest one, as standardNotes.ts does
 *   ==text== / ==🟢text==       -> a highlight; the color emoji becomes our color
 *   ~text~                      -> underline
 *   [[Title/Heading]]           -> [[Title#Heading]] when Title is a note here
 *   bear://...open-note?id=     -> a note-link, when the id is in the backup
 *   <!-- {"fold":true} --> etc. -> dropped: Bear keeps editor state in comments
 *   assets/<file>, <title>/<file> -> imported images and files
 *   YAML front matter           -> removed from the text; its tags kept
 *   a table or $$ right under a line -> a blank line first: Bear draws them,
 *                                  Markdown reads them as part of the paragraph
 */

/** Bear's highlight colors are an emoji after the opening `==`. Yellow is the default mark. */
const HIGHLIGHT_EMOJI: Readonly<Record<string, string | null>> = {
  '🟢': 'Green',
  '🔴': 'Red',
  '🔵': 'Blue',
  '🟡': null,
  '🟣': 'Purple',
};

/**
 * Bear writes editor state as a JSON object in a comment right after the
 * element. Every pattern that reads a stranger's text below is bounded, so no
 * crafted file can make one rescan the rest of a note for each attempt.
 */
const STATE_COMMENT = /<!--\s{0,8}\{[^{}\n]{0,500}\}\s{0,8}-->/g;

const TEXT_NAMES = new Set(['text.md', 'text.markdown', 'text.txt']);

interface RawNote {
  /** Folder the note's relative links resolve against, ending in `/` or ''. */
  base: string;
  text: string;
  info: Record<string, unknown> | null;
  fileDate: Date | null;
}

/**
 * Tags the way Bear reads them, measured against Bear 3's own tag list:
 * a `#` followed by a character that is not a space or `#` opens a tag. If the
 * next `#` on the line comes right after a non-space character, everything
 * between is one multi-word tag (`#multi word tag#`, `#123 and C#`).
 * Otherwise the tag runs to the next space and drops trailing punctuation.
 * A tag holds at least one letter, so `#123` alone is not one. Bear shows
 * tags lowercase. Returns the full paths, lowercased and not yet capped.
 */
export function bearTags(md: string): string[] {
  const text = stripHtmlComments(proseOnly(md))
    .replace(/\]\([^)\n]{0,2048}\)/g, ']()')
    .replace(/\[\[[^\]\n]{0,512}\]\]/g, '[[]]')
    .replace(/(?<![a-z0-9+.-])[a-z][a-z0-9+.-]{0,31}:\/\/\S*/gi, '')
    .replace(/\\#/g, '')
    .replace(/^\s{0,3}#{1,6}(?=\s|$)/gm, '');
  const found = new Set<string>();
  const word = /[^\s#]+/y;
  for (const line of text.split('\n')) {
    let i = 0;
    while ((i = line.indexOf('#', i)) >= 0) {
      const prev = i > 0 ? line[i - 1]! : ' ';
      const next = line[i + 1];
      if (!next || /\s|#/.test(next) || !/[\s([{>*_~=,;]/.test(prev)) {
        i++;
        continue;
      }
      const close = line.indexOf('#', i + 1);
      let raw: string;
      let end: number;
      if (close > 0 && !/\s/.test(line[close - 1]!)) {
        raw = line.slice(i + 1, close);
        end = close + 1;
      } else {
        word.lastIndex = i + 1;
        const m = word.exec(line)!;
        raw = m[0].replace(/[.,;:!?)\]}'"]+$/u, '');
        end = i + 1 + m[0].length;
      }
      // A backward scan, not /\/+$/: that regex retries from every slash of a long run.
      let cut = raw.length;
      while (cut > 0 && raw[cut - 1] === '/') cut--;
      const tag = raw.slice(0, cut).trim().toLowerCase();
      if (/\p{L}/u.test(tag)) found.add(tag);
      i = end;
    }
  }
  return [...found];
}

const TABLE_DELIMITER = /^\s*\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)+\|?\s*$/;

/**
 * Bear starts a table or a `$$` block on the line after text. Markdown needs
 * a blank line there, or the block stays inside the paragraph as plain text.
 */
function separateBlocks(text: string): string {
  const lines = text.split('\n');
  const out: string[] = [];
  let inMath = false;
  lines.forEach((line, i) => {
    const prev = out[out.length - 1];
    const prevIsText = prev !== undefined && prev.trim() !== '' && !prev.trim().startsWith('|');
    const startsTable = line.includes('|') && TABLE_DELIMITER.test(lines[i + 1] ?? '') && !TABLE_DELIMITER.test(line);
    const mathFence = line.trim() === '$$';
    if (prevIsText && ((startsTable && !inMath) || (mathFence && !inMath))) out.push('');
    if (mathFence) inMath = !inMath;
    out.push(line);
  });
  return out.join('\n');
}

/** `%20` and friends in a relative link, read the way a browser would. */
function decodePath(raw: string): string {
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

/** Resolve a relative link against a folder in the zip; null when it leaves the zip. */
function resolvePath(base: string, rel: string): string | null {
  const segs = (base + rel).split('/');
  const out: string[] = [];
  for (const s of segs) {
    if (s === '' || s === '.') continue;
    if (s === '..') {
      if (!out.length) return null;
      out.pop();
    } else out.push(s);
  }
  return out.join('/');
}

function infoDate(info: Record<string, unknown> | null, key: string): string | null {
  const v = info?.[key];
  if (typeof v !== 'string') return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

async function readNotes(file: File): Promise<{ notes: RawNote[]; files: Map<string, JSZip.JSZipObject> }> {
  const zip = await JSZip.loadAsync(file);
  const files = new Map<string, JSZip.JSZipObject>();
  for (const entry of Object.values(zip.files)) {
    if (entry.dir || entry.name.startsWith('__MACOSX/') || /(^|\/)\.[^/]*$/.test(entry.name)) continue;
    files.set(entry.name, entry);
  }
  // The Markdown export puts a note's files in a folder named after the note,
  // so a Markdown file inside `<stem>/` next to `<stem>.md` is an attachment.
  const isAttachmentDir = (segs: string[]) =>
    segs.slice(0, -1).some((_, i) => files.has(`${segs.slice(0, i + 1).join('/')}.md`));
  const notes: RawNote[] = [];
  for (const [path, entry] of files) {
    const segs = path.split('/');
    const name = segs[segs.length - 1]!.toLowerCase();
    const parent = segs.length > 1 ? segs[segs.length - 2]! : '';
    if (TEXT_NAMES.has(name) && parent.toLowerCase().endsWith('.textbundle')) {
      const dir = segs.slice(0, -1).join('/') + '/';
      const infoEntry = files.get(`${dir}info.json`);
      let info: Record<string, unknown> | null = null;
      if (infoEntry) {
        try {
          const json = JSON.parse(await zipEntryText(infoEntry));
          const bear = json?.['net.shinyfrog.bear'];
          info = bear && typeof bear === 'object' ? (bear as Record<string, unknown>) : null;
        } catch {
          info = null;
        }
      }
      notes.push({ base: dir, text: await zipEntryText(entry), info, fileDate: entry.date ?? null });
    } else if (/\.(md|markdown)$/.test(name) && !segs.some((s) => s.toLowerCase().endsWith('.textbundle')) && !isAttachmentDir(segs)) {
      notes.push({
        base: segs.length > 1 ? segs.slice(0, -1).join('/') + '/' : '',
        text: await zipEntryText(entry),
        info: null,
        fileDate: entry.date ?? null,
      });
    }
  }
  return { notes, files };
}

export async function parseBear(file: File, onProgress?: (msg: string) => void): Promise<ParsedImport> {
  onProgress?.('Reading file…');
  const { notes: raws, files } = await readNotes(file);
  if (raws.length === 0) {
    throw new Error('No Bear notes found. In Bear, pick File > Backup Notes..., then drop the .bear2bk file here.');
  }

  onProgress?.('Reading notes…');
  const highlight = new Map(HIGHLIGHT_COLORS.map((c) => [c.name, c.value]));
  const blobs = new Map<string, ImportBlob>();
  const blobKeyOf = new Map<string, string>();
  const now = new Date().toISOString();

  // Pass 1: titles, so note-links can be checked before the bodies are built.
  const split = raws.map((r) => {
    let text = r.text.replace(/^﻿/, '').replace(/\r\n?/g, '\n');
    let fmTags: string[] = [];
    const fm = FRONT_MATTER.exec(text);
    if (fm) {
      fmTags = parseYamlTags(fm[1] ?? '');
      text = fm[2] ?? '';
    }
    // Inline tags may be in the title; read the full text before splitting.
    const paths = bearTags(text);
    const lines = text.split('\n');
    const first = lines.findIndex((l) => l.trim() !== '');
    let title = '';
    if (first >= 0) {
      title = lines[first]!.replace(/^#{1,6}\s+/, '').replace(STATE_COMMENT, '').trim();
      lines.splice(0, first + 1);
      if (lines[0]?.trim() === '') lines.shift();
    }
    return { raw: r, title, body: lines.join('\n'), fmTags, paths };
  });
  const titles = new Set(split.map((s) => s.title));
  const byId = new Map<string, string>();
  for (const s of split) {
    const id = s.raw.info?.uniqueIdentifier;
    if (typeof id === 'string') byId.set(id.toUpperCase(), s.title);
  }

  let colored = 0;
  let underlined = 0;
  let droppedState = 0;
  let missingFiles = 0;
  let linkified = 0;
  let headingLinks = 0;
  let empty = 0;
  let untagged = 0;
  let shortened = 0;
  const out: ImportedNote[] = [];
  const deepest: Array<string | null> = [];

  for (const { raw, title, body: rawBody, fmTags, paths } of split) {
    let body = rawBody;
    const stateCount = (body.match(STATE_COMMENT) ?? []).length;
    droppedState += stateCount;
    const nested = paths
      .map((t) => t.split('/').map((seg) => seg.trim()).filter(Boolean))
      .filter((segs) => segs.length > 1)
      .sort((a, b) => b.length - a.length || a.join('/').localeCompare(b.join('/')));
    deepest.push(nested[0]?.join('/') ?? null);
    const tags = [
      ...fmTags,
      ...paths.map((t) => {
        if (t.length <= TAG_MAX_LENGTH) return normalizeTag(t);
        shortened++;
        return normalizeTag(t.split('/').filter(Boolean).pop() ?? t);
      }),
    ];

    body = mapOutsideCode(body, (t) =>
      separateBlocks(t)
        .replace(STATE_COMMENT, '')
        .replace(/==(🟢|🔴|🔵|🟡|🟣)([^=\n]{1,2000})==/gu, (_m, emoji: string, inner: string) => {
          colored++;
          const name = HIGHLIGHT_EMOJI[emoji];
          const value = name ? highlight.get(name) : null;
          return value ? `<mark style="background-color: ${value}">${inner}</mark>` : `==${inner}==`;
        })
        .replace(/(^|[^\p{L}\p{N}~\\])~(?![\s~])([^~\n]*?[^\s~\\])~(?![~\p{L}\p{N}])/gu, (_m, pre: string, inner: string) => {
          underlined++;
          return `${pre}<u>${inner}</u>`;
        })
        .replace(/\[\[([^\]\n|/]{1,300}(?:\/[^\]\n|/]{1,300}){0,8}?)\/([^\]\n|/]{1,300})(\|[^\]\n]{0,300})?\]\]/g, (whole, note: string, heading: string, alias = '') => {
          if (titles.has(`${note}/${heading}`) || !titles.has(note)) return whole;
          headingLinks++;
          return `[[${note}#${heading}${alias}]]`;
        })
        .replace(/\[([^\]\n]{0,1000})\]\(bear:\/\/x-callback-url\/open-note\?id=([0-9A-Fa-f-]{36})[^)\s]{0,500}\)/g, (whole, label: string, id: string) => {
          const target = byId.get(id.toUpperCase());
          if (target === undefined) return whole;
          const t = noteLinkTarget(target);
          const clean = label.replace(/[[\]]/g, '').trim();
          return !clean || clean === t ? `[[${t}]]` : `[[${t}|${clean}]]`;
        })
        .replace(/(!?)\[([^\]\n]{0,1000})\]\(<?([^)\s>]{1,2048})>?(\s{1,8}"[^"\n]{0,500}")?\)/g, (whole, bang: string, label: string, href: string) => {
          if (/^[a-z][a-z0-9+.-]*:/i.test(href) || href.startsWith('#')) return whole;
          const path = resolvePath(raw.base, decodePath(href));
          const entry = path ? files.get(path) : undefined;
          if (!path || !entry) {
            missingFiles++;
            return whole;
          }
          let key = blobKeyOf.get(path);
          if (!key) {
            key = `bearatt:${String(blobKeyOf.size + 1).padStart(6, '0')}`;
            blobKeyOf.set(path, key);
            const name = path.split('/').pop()!;
            blobs.set(key, { data: new Uint8Array(), mime: mimeFromExt(name), name });
          }
          return `${bang}[${label.replace(/[[\]]/g, '')}](${key})`;
        }),
    );

    const linked = linkifyMarkdown(body.replace(/\n{3,}$/, '\n'));
    if (linked !== body) linkified++;
    const seen = new Set<string>();
    const normTags = tags.filter((t) => t && !seen.has(t.toLowerCase()) && seen.add(t.toLowerCase()));
    if (normTags.length === 0) untagged++;
    if (!linked.trim()) empty++;

    const info = raw.info;
    const createdAt = infoDate(info, 'creationDate') ?? raw.fileDate?.toISOString() ?? now;
    out.push({
      title,
      body: linked,
      tags: normTags,
      createdAt,
      updatedAt: infoDate(info, 'modificationDate') ?? createdAt,
      ...(info?.trashed === 1 ? { trashed: true } : {}),
      ...(info?.archived === 1 ? { archived: true } : {}),
      ...(info?.pinned === 1 ? { starred: true } : {}),
      ...(info?.locked === 1 ? { locked: true } : {}),
    });
  }

  const { folders, dirToFolderId } = buildFolderTree(deepest.filter((d): d is string => d !== null));
  out.forEach((note, i) => {
    const dir = deepest[i];
    if (!dir || !dirToFolderId.has(dir)) return;
    note.folderId = dirToFolderId.get(dir)!;
    note.folderPath = dir.split('/').filter(Boolean);
  });

  onProgress?.('Reading attachments…');
  for (const [path, key] of blobKeyOf) {
    if (!out.some((n) => isBlobReferenced(key, n.body))) {
      blobs.delete(key);
      continue;
    }
    blobs.get(key)!.data = await zipEntryBytes(files.get(path)!, Infinity);
  }

  const s = (n: number, one = '', many = 's') => (n === 1 ? one : many);
  const transforms: string[] = [];
  const warnings: string[] = [];
  const tagged = out.length - untagged;
  if (tagged > 0) transforms.push(`Read Bear's #tags in ${tagged} note${s(tagged)}, nested tags included.`);
  if (folders.length > 0) {
    transforms.push(`Rebuilt your nested tags as ${folders.length} folder${s(folders.length)}, and kept them as tags too.`);
  }
  if (blobs.size > 0) transforms.push(`Imported ${blobs.size} attachment${s(blobs.size)}.`);
  if (colored > 0) transforms.push(`Kept ${colored} highlight${s(colored)} with ${s(colored, 'its', 'their')} Bear color.`);
  if (underlined > 0) transforms.push(`Turned ${underlined} Bear underline${s(underlined)} into underlined text.`);
  if (headingLinks > 0) transforms.push(`Pointed ${headingLinks} note-link${s(headingLinks)} at ${s(headingLinks, 'its', 'their')} heading.`);
  if (linkified > 0) transforms.push(`Made URLs clickable in ${linkified} note${s(linkified)}.`);
  if (droppedState > 0) {
    warnings.push(`Bear's folded headings and custom image sizes do not carry over: ${droppedState} of them open in full.`);
  }
  if (shortened > 0) {
    warnings.push(`${shortened} nested tag${s(shortened)} had a path too long for a tag and kept ${s(shortened, 'its', 'their')} own name. The folder shows the full path.`);
  }
  if (missingFiles > 0) {
    warnings.push(`${missingFiles} link${s(missingFiles)} point${s(missingFiles, 's', '')} at a file that is not in the export. ${s(missingFiles, 'It stays', 'They stay')} as a link.`);
  }

  const parsed: ParsedImport = {
    notes: out,
    warnings,
    transforms,
    stats: {
      totalNotes: out.length,
      emptyNotes: empty,
      untaggedNotes: untagged,
      uniqueTags: new Set(out.flatMap((n) => n.tags)).size,
    },
    source: 'bear',
  };
  if (folders.length > 0) parsed.folders = folders;
  if (blobs.size > 0) {
    parsed.blobs = blobs;
    parsed.blobBytes = [...blobs.values()].reduce((sum, b) => sum + b.data.length, 0);
  }
  return parsed;
}
