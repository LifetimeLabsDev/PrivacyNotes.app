import JSZip from 'jszip';
import { zipEntryText } from './zipEntry';
import type { FolderDef } from '../folders';
import { extractInlineTags, parseYamlTags } from '../notesRepo';
import { FRONT_MATTER } from '../markdownFolder/adapter';
import { ATTACHMENT_EXT, isBlobReferenced, mimeFromExt } from './blobImport';
import { buildFolderTree, commonRootPrefix } from './folderImport';
import { linkifyMarkdown } from './linkify';
import { noteLinkTarget } from '../noteLinks';
import { isUntitledStem } from '../exportNames';
import type { ImportedNote, ParsedImport } from './types';

/**
 * Obsidian vault importer.
 *
 * Obsidian vaults are folders of .md files with optional YAML
 * frontmatter. Users zip their vault folder and drop it here.
 *
 * What we handle:
 *   - YAML frontmatter: tags (array or inline), aliases, created/date
 *   - Subfolder structure rebuilt as real folders at any depth; each
 *     note's folderId points at its folder. Folder tagging is an
 *     apply-time choice (see folderImport.ts), not done here.
 *   - Inline #tags extracted from body and merged into tags field
 *   - [[wiki-links]] preserved as-is (our editor renders them)
 *   - Bare URLs linkified
 *   - .obsidian/ config folder and .trash/ skipped
 *   - Attachments (images, PDFs, audio) imported through the shared blob
 *     pipeline, including `![[embeds]]`; anything no note links to is
 *     skipped and counted, because an orphan blob is pure quota burn
 */

/* ------------------------------------------------------------------ */
/* YAML front-matter parser (Obsidian-aware)                          */
/* ------------------------------------------------------------------ */

interface FrontMatter {
  tags: string[];
  title: string;
  createdAt: string | null;
  updatedAt: string | null;
}

function parseFrontMatter(content: string): {
  meta: FrontMatter;
  body: string;
} {
  const fmMatch = content.match(FRONT_MATTER);
  if (!fmMatch || !fmMatch[1]) {
    return {
      meta: { tags: [], title: '', createdAt: null, updatedAt: null },
      body: content,
    };
  }

  const yaml = fmMatch[1];
  const body = fmMatch[2] ?? '';

  const tags: string[] = [];
  let title = '';
  let createdAt: string | null = null;
  let updatedAt: string | null = null;

  // Tags come from the shared parser in notesRepo - the Markdown folder
  // adapter needs the same grammar and had its own copy until v0.400.0.
  tags.push(...parseYamlTags(yaml));

  const lines = yaml.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const colonIdx = line.indexOf(':');
    if (colonIdx < 0) continue;
    const key = line.slice(0, colonIdx).trim().toLowerCase();
    const rawVal = line.slice(colonIdx + 1).trim();

    if (key === 'title' || key === 'aliases') {
      // Use title if present; aliases as fallback (take first)
      if (key === 'title' && rawVal) {
        title = rawVal.replace(/^["']|["']$/g, '');
      } else if (key === 'aliases' && !title && rawVal) {
        const stripped = rawVal.replace(/^\[/, '').replace(/\]$/, '');
        const first = stripped.split(',')[0]?.trim().replace(/^["']|["']$/g, '');
        if (first) title = first;
      }
    } else if (key === 'created' || key === 'date' || key === 'date created') {
      if (rawVal && !isNaN(Date.parse(rawVal))) createdAt = rawVal;
    } else if (key === 'updated' || key === 'modified' || key === 'date modified') {
      if (rawVal && !isNaN(Date.parse(rawVal))) updatedAt = rawVal;
    }
  }

  return { meta: { tags, title, createdAt, updatedAt }, body };
}

/* ------------------------------------------------------------------ */
/* Obsidian-specific markdown preprocessing                           */
/* ------------------------------------------------------------------ */

/**
 * Convert Obsidian-specific markdown extensions to standard markdown
 * that tiptap-markdown can render. Runs before linkify so we don't
 * accidentally touch URLs or code content.
 *
 * Handles: ==highlight==, $math$, $$math blocks$$, %% comments %%,
 * [^N] footnote refs, [^N]: footnote definitions.
 */
function preprocessObsidianMarkdown(body: string): string {
  // Step 1: Pull fenced code blocks out so we don't mangle them.
  const fences: string[] = [];
  let text = body.replace(/```[\s\S]*?```/g, (m) => {
    const idx = fences.length;
    fences.push(m);
    return `\x00F${idx}\x00`;
  });

  // Step 2: Pull inline code spans out.
  const codeSpans: string[] = [];
  text = text.replace(/`[^`\n]+`/g, (m) => {
    const idx = codeSpans.length;
    codeSpans.push(m);
    return `\x00C${idx}\x00`;
  });

  // Strip multiline %% comments %% (Obsidian comments are invisible).
  text = text.replace(/%%[\s\S]*?%%/g, '');

  // Obsidian's own link syntax, for the targets that name a FILE rather than
  // a note: `![[photo.png]]`, `![[doc.pdf|300]]`, and the non-embedding
  // `[[report.pdf]]`. Those become standard markdown so the shared blob
  // pipeline can find and rewrite them. A target that names a note is left
  // exactly as it is - our editor renders [[note links]] natively.
  //
  // The embedding and non-embedding forms have to convert TOGETHER. The
  // importer only ships a blob it can also rewrite (isBlobReferenced), so
  // converting `![[x.pdf]]` alone would leave `[[x.pdf]]` pointing at a file
  // that never came across, and converting neither would lose both.
  text = text.replace(
    /(!?)\[\[([^\]\n|]+)(?:\|[^\]\n]*)?\]\]/g,
    (whole: string, bang: string, target: string) => {
      const path = target.trim();
      if (!ATTACHMENT_EXT.test(path)) return whole;
      return `${bang}[${path.split('/').pop() ?? path}](${path})`;
    },
  );

  // Obsidian's qualified note targets, which our resolver cannot match: a
  // vault writes `[[folder/Note]]` to disambiguate, `[[Note#Heading]]` to
  // point at a section and `[[Note#^b1c2]]` at a block, while a note here is
  // found by its title alone. Left as they were, every one of those imported
  // as a link that resolves to nothing and offers to create a junk note.
  //
  // The target is reduced to the note name; the text the vault SHOWED is kept
  // as the display label, so the note reads exactly as it did in Obsidian and
  // only the destination changes. `[[#Heading]]`, a link into the same note,
  // has no target left and becomes plain text rather than a dangling link.
  text = text.replace(
    /(?<!!)\[\[([^\]\n]+)\]\]/g,
    (whole: string, inner: string) => {
      const pipe = inner.indexOf('|');
      const path = (pipe >= 0 ? inner.slice(0, pipe) : inner).trim();
      const alias = pipe >= 0 ? inner.slice(pipe + 1).trim() : '';
      const hash = path.indexOf('#');
      const name = noteLinkTarget((hash >= 0 ? path.slice(0, hash) : path).split('/').pop() ?? '');
      if (!name) return alias || path.replace(/^#\^?/, '');
      if (name === path) return whole;
      const label = alias || path;
      return `[[${name}|${label}]]`;
    },
  );

  // Convert $$...$$ display math blocks to fenced code blocks.
  text = text.replace(/\$\$\n([\s\S]*?)\n\$\$/g, '```\n$1\n```');

  // Convert ==highlight== to **bold** (no Highlight extension in editor).
  text = text.replace(/==([^=]+)==/g, '**$1**');

  // Convert $inline math$ to `inline code` (no math renderer).
  // Avoid matching $$ (display math) or $ in isolation.
  text = text.replace(/(?<!\$)\$(?!\$)([^\n$]+?)\$(?!\$)/g, '`$1`');

  // Collect footnote definitions [^N]: text - we'll append them at the end.
  const footnoteDefs = new Map<string, string>();
  text = text.replace(/^\[\^([^\]]+)\]:\s*(.+)$/gm, (_m, id: string, def: string) => {
    footnoteDefs.set(id, def.trim());
    return ''; // remove the definition line
  });

  // Convert footnote references [^N] to (N) inline.
  text = text.replace(/\[\^([^\]]+)\]/g, '($1)');

  // If there were footnote definitions, append them as a numbered section.
  if (footnoteDefs.size > 0) {
    const lines: string[] = ['\n---\n'];
    let i = 1;
    for (const [id, def] of footnoteDefs) {
      lines.push(`${i}. (${id}) ${def}`);
      i++;
    }
    text += lines.join('\n');
  }

  // Restore inline code spans.
  text = text.replace(/\x00C(\d+)\x00/g, (_m, i: string) => codeSpans[Number(i)] ?? '');

  // Restore fenced code blocks.
  text = text.replace(/\x00F(\d+)\x00/g, (_m, i: string) => fences[Number(i)] ?? '');

  // Clean up any runs of 3+ blank lines left by stripping comments.
  text = text.replace(/\n{3,}/g, '\n\n');

  return text;
}

/* ------------------------------------------------------------------ */
/* Single file parser                                                 */
/* ------------------------------------------------------------------ */

function parseOneObsidian(
  content: string,
  relativePath: string,
  fileDate: Date | null,
): ImportedNote {
  const { meta, body } = parseFrontMatter(content);
  // Obsidian vaults don't store creation dates in note content by default
  // (the timestamp lives on the filesystem). When frontmatter has no
  // created/updated, fall back to the file's modified time preserved in
  // the zip entry, matching the Samsung importer. Only if that's missing
  // do we use the import time.
  const fallback =
    fileDate && !Number.isNaN(fileDate.getTime())
      ? fileDate.toISOString()
      : new Date().toISOString();

  // Title: frontmatter > filename
  const filename = relativePath.split('/').pop() ?? '';
  const filenameTitle = filename
    .replace(/\.md$/i, '')
    .trim();
  // An Obsidian note has no title field: the filename IS the name, so it is
  // the right fallback here. The exception is the name Obsidian itself gives
  // a note the user never named - "Untitled", then "Untitled 1" - which is a
  // stand-in rather than a name. See `isUntitledStem`.
  const title = meta.title || (isUntitledStem(filenameTitle) ? '' : filenameTitle);

  // Tags: frontmatter + inline #tags. The subfolder structure becomes
  // real folders in parseZip, not tags (that was the #178 bug).
  // `stripComments`: an Obsidian %%comment%% is removed from the body a few
  // lines below, so a tag inside one must not outlive it (#146).
  const inlineTags = extractInlineTags(body, { stripComments: true });
  const allTags = [...meta.tags];
  for (const t of inlineTags) {
    if (!allTags.includes(t)) allTags.push(t);
  }

  // Dates
  const createdAt = meta.createdAt ?? fallback;
  const updatedAt = meta.updatedAt ?? meta.createdAt ?? fallback;

  // Convert Obsidian-specific syntax, then linkify bare URLs.
  const processedBody = linkifyMarkdown(preprocessObsidianMarkdown(body.trim()));

  return {
    title,
    body: processedBody,
    tags: allTags,
    createdAt,
    updatedAt,
  };
}

/* ------------------------------------------------------------------ */
/* Zip parser                                                         */
/* ------------------------------------------------------------------ */

/** Files/folders to skip entirely. */
function shouldSkip(path: string): boolean {
  const lower = path.toLowerCase();
  // Obsidian config
  if (lower.startsWith('.obsidian/') || lower.includes('/.obsidian/')) return true;
  // Obsidian trash
  if (lower.startsWith('.trash/') || lower.includes('/.trash/')) return true;
  // macOS resource forks
  if (lower.startsWith('__macosx/') || lower.includes('/__macosx/')) return true;
  // Hidden files
  const name = path.split('/').pop() ?? '';
  if (name.startsWith('.')) return true;
  return false;
}

const MD_EXT = /\.md$/i;

async function parseZip(
  file: File,
  onProgress?: (msg: string) => void,
): Promise<{
  notes: ImportedNote[];
  skippedAttachments: number;
  folders: FolderDef[];
  blobs: Map<string, { data: Uint8Array; mime: string; name: string }>;
}> {
  onProgress?.('Reading zip...');
  const buf = await file.arrayBuffer();
  const zip = await JSZip.loadAsync(buf);

  // Find the common root prefix. Many users zip a folder, so paths
  // look like "MyVault/note.md" - strip that prefix for cleaner tags.
  const allPaths: string[] = [];
  zip.forEach((path, entry) => {
    if (!entry.dir && !shouldSkip(path)) allPaths.push(path);
  });

  const prefix = commonRootPrefix(allPaths);

  const mdFiles: [string, JSZip.JSZipObject][] = [];
  const attachments: [string, JSZip.JSZipObject][] = [];

  zip.forEach((path, entry) => {
    if (entry.dir || shouldSkip(path)) return;
    const rel = prefix ? path.slice(prefix.length) : path;
    if (MD_EXT.test(rel)) {
      mdFiles.push([rel, entry]);
    } else if (ATTACHMENT_EXT.test(rel)) {
      attachments.push([rel, entry]);
    }
  });

  onProgress?.(
    `Found ${mdFiles.length} note${mdFiles.length === 1 ? '' : 's'}...`
  );

  // Rebuild the vault's subfolder structure as a real folder tree. Each
  // note's folderId points at the deepest folder created for its path.
  const dirOf = (rel: string) =>
    rel.split('/').slice(0, -1).filter(Boolean).join('/');
  const { folders, dirToFolderId } = buildFolderTree(
    mdFiles.map(([rel]) => dirOf(rel)),
  );

  const notes: ImportedNote[] = [];
  for (let i = 0; i < mdFiles.length; i++) {
    const [rel, entry] = mdFiles[i]!;
    const text = await zipEntryText(entry);
    const note = parseOneObsidian(text, rel, entry.date ?? null);
    const dir = dirOf(rel);
    if (dir) {
      note.folderId = dirToFolderId.get(dir) ?? null;
      note.folderPath = dir.split('/').filter(Boolean);
    }
    notes.push(note);
    if ((i + 1) % 50 === 0) {
      onProgress?.(`Parsed ${i + 1} of ${mdFiles.length}...`);
    }
  }

  // Attachments, read AFTER the notes because only a referenced file is
  // worth carrying: a working vault accumulates images nothing links to any
  // more, and every one of those would be charged against the user's storage
  // quota to render nowhere. The predicate is the shared one the rewrite
  // itself uses, so "shipped" and "rewritten" cannot drift apart.
  const bodies = notes.map((n) => n.body).join('\n');
  const blobs = new Map<string, { data: Uint8Array; mime: string; name: string }>();
  let skippedAttachments = 0;
  for (const [rel, entry] of attachments) {
    if (!isBlobReferenced(rel, bodies)) {
      skippedAttachments++;
      continue;
    }
    if (blobs.size % 10 === 0) {
      onProgress?.(`Reading attachments... ${blobs.size + 1} of ${attachments.length}`);
    }
    blobs.set(rel, {
      data: await entry.async('uint8array'),
      mime: mimeFromExt(rel),
      name: rel.split('/').pop() ?? rel,
    });
  }

  return { notes, skippedAttachments, folders, blobs };
}

/* ------------------------------------------------------------------ */
/* Public importer                                                    */
/* ------------------------------------------------------------------ */

export async function parseObsidian(
  file: File,
  onProgress?: (msg: string) => void,
): Promise<ParsedImport> {
  const { notes, skippedAttachments, folders, blobs } = await parseZip(
    file,
    onProgress
  );

  const uniqueTags = new Set(notes.flatMap((n) => n.tags));
  const emptyNotes = notes.filter(
    (n) => !n.title.trim() && !n.body.trim()
  ).length;
  const untaggedNotes = notes.filter((n) => n.tags.length === 0).length;

  const warnings: string[] = [];
  if (skippedAttachments > 0) {
    warnings.push(
      `Skipped ${skippedAttachments} attachment${skippedAttachments === 1 ? '' : 's'} that none of your notes link to.`
    );
  }
  const transforms: string[] = [];
  if (blobs.size > 0) {
    const images = [...blobs.values()].filter((b) => b.mime.startsWith('image/')).length;
    const files = blobs.size - images;
    const parts: string[] = [];
    if (images > 0) parts.push(`${images} image${images === 1 ? '' : 's'}`);
    if (files > 0) parts.push(`${files} file${files === 1 ? '' : 's'}`);
    transforms.push(`Brought ${parts.join(' and ')} across from your vault.`);
  }
  if (folders.length > 0) {
    const filed = notes.filter((n) => n.folderId).length;
    transforms.push(
      `Rebuilt ${folders.length} folder${folders.length === 1 ? '' : 's'} from your vault (${filed} note${filed === 1 ? '' : 's'} filed).`
    );
  }
  const withFm = notes.filter((n) => n.tags.length > 0).length;
  if (withFm > 0) {
    transforms.push(
      `Extracted tags from ${withFm} note${withFm === 1 ? '' : 's'} (frontmatter and inline #tags).`
    );
  }
  const withLinks = notes.filter((n) => /\[\[.+?\]\]/.test(n.body)).length;
  if (withLinks > 0) {
    transforms.push(
      `Preserved [[note links]] in ${withLinks} note${withLinks === 1 ? '' : 's'}.`
    );
  }
  transforms.push('Made bare URLs clickable.');

  return {
    notes,
    warnings,
    transforms,
    stats: {
      totalNotes: notes.length,
      emptyNotes,
      untaggedNotes,
      uniqueTags: uniqueTags.size,
    },
    source: 'obsidian',
    folders,
    blobs: blobs.size > 0 ? blobs : undefined,
  };
}
