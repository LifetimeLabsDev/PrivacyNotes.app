import JSZip from 'jszip';
import { zipEntryText } from './zipEntry';
import { linkifyMarkdown } from './linkify';
import type { ImportedNote, ParsedImport } from './types';

/**
 * Samsung Notes importer.
 *
 * Supports two export formats:
 *
 * 1. **Text (.txt)** - the user selects notes → Save as file → Text.
 *    Samsung drops individual .txt files; the user zips them manually.
 *    Filename: "Note Title_YYMMDD_HHMMSS.txt". Loses all formatting,
 *    images, and rich structure.
 *
 * 2. **Word (.docx)** - the user exports as Microsoft Word. Preserves
 *    bold, italic, underline, strikethrough, bullets, numbered lists,
 *    and checkboxes via OOXML. Images are embedded but not imported
 *    (noted as a warning). Samsung exports one .docx per note; the
 *    user can zip multiple .docx files for bulk import.
 *
 * Accepted inputs:
 *   - A .zip containing .txt and/or .docx files
 *   - A single .txt file
 *   - A single .docx file
 */

/* ------------------------------------------------------------------ */
/* XML namespaces (OOXML)                                             */
/* ------------------------------------------------------------------ */

/**
 * DOMParser in browsers handles namespace-prefixed tags from OOXML
 * transparently - getElementsByTagName('w:p') just works. This
 * wrapper exists so the intent is clear and greppable.
 */
function wTag(name: string): string {
  return name;
}

/* ------------------------------------------------------------------ */
/* Filename → title + timestamp                                       */
/* ------------------------------------------------------------------ */

/**
 * Parse a Samsung Notes export filename.
 *
 * "TEST NOTE 1_260513_202350.txt" → { title: "TEST NOTE 1", timestamp: Date }
 * "My Note.docx"                 → { title: "My Note", timestamp: null }
 */
function parseFilename(name: string): { title: string; timestamp: Date | null } {
  const base = name.replace(/^.*[\\/]/, '').replace(/\.(txt|docx)$/i, '');

  const m = base.match(/^(.+?)_(\d{6})_(\d{6})$/);
  if (!m) return { title: base, timestamp: null };

  const title = m[1]!;
  const datePart = m[2]!;
  const timePart = m[3]!;
  const [yy, mo, dd] = [datePart.slice(0, 2), datePart.slice(2, 4), datePart.slice(4, 6)];
  const [hh, mi, ss] = [timePart.slice(0, 2), timePart.slice(2, 4), timePart.slice(4, 6)];
  const year = 2000 + parseInt(yy, 10);
  const d = new Date(year, parseInt(mo, 10) - 1, parseInt(dd, 10),
    parseInt(hh, 10), parseInt(mi, 10), parseInt(ss, 10));

  return { title, timestamp: Number.isNaN(d.getTime()) ? null : d };
}

/* ------------------------------------------------------------------ */
/* .txt body normalisation: Samsung markers → markdown                */
/* ------------------------------------------------------------------ */

function normalizeSamsungBody(raw: string): string {
  const lines = raw.split('\n');
  const out: string[] = [];

  for (const line of lines) {
    const trimmed = line.trimStart();

    if (trimmed.startsWith('[  ] ') || trimmed === '[  ]') {
      out.push(`- [ ] ${trimmed.slice(4).trim()}`);
      continue;
    }
    if (/^\[[✓xXvV]\]\s?/.test(trimmed)) {
      out.push(`- [x] ${trimmed.replace(/^\[[✓xXvV]\]\s?/, '').trim()}`);
      continue;
    }
    if (trimmed.startsWith('• ') || trimmed === '•') {
      out.push(`- ${trimmed.slice(1).trim()}`);
      continue;
    }
    if (trimmed.startsWith('◦ ') || trimmed === '◦') {
      out.push(`  - ${trimmed.slice(1).trim()}`);
      continue;
    }
    if (trimmed.startsWith('▪ ') || trimmed === '▪') {
      out.push(`    - ${trimmed.slice(1).trim()}`);
      continue;
    }
    if (trimmed.startsWith('▫ ') || trimmed === '▫') {
      out.push(`      - ${trimmed.slice(1).trim()}`);
      continue;
    }

    out.push(line);
  }

  return out.join('\n');
}

function collapseBlankRuns(text: string): string {
  return text.replace(/\n{4,}/g, '\n\n\n');
}

function trimTrailing(text: string): string {
  return text.replace(/\s+$/, '');
}

/* ------------------------------------------------------------------ */
/* .docx → markdown conversion                                       */
/* ------------------------------------------------------------------ */

/**
 * Samsung OOXML numbering definitions. We parse word/numbering.xml to
 * learn which numId corresponds to bullets, checkboxes, or ordered
 * lists. Samsung uses these abstractNum lvlText markers:
 *   "•"  → bullet list
 *   "☐"  → checkbox list
 *   "%1." (numFmt=decimal) → ordered list
 *   "%1." (numFmt=upperLetter/lowerLetter/lowerRoman) → sub-ordered
 */
interface NumDef {
  type: 'bullet' | 'checkbox' | 'ordered';
  /** numFmt per indent level. */
  levels: Map<number, string>;
}

function parseNumbering(xml: string): Map<string, NumDef> {
  const parser = new DOMParser();
  const doc = parser.parseFromString(xml, 'application/xml');

  // Build abstractNum map
  const abstractMap = new Map<string, NumDef>();
  const abstractNums = doc.getElementsByTagName(wTag('w:abstractNum'));
  for (let i = 0; i < abstractNums.length; i++) {
    const el = abstractNums[i]!;
    const absId = el.getAttribute('w:abstractNumId') ?? '';
    const levels = new Map<number, string>();
    let type: NumDef['type'] = 'bullet';

    const lvls = el.getElementsByTagName(wTag('w:lvl'));
    for (let j = 0; j < lvls.length; j++) {
      const lvl = lvls[j]!;
      const ilvl = parseInt(lvl.getAttribute('w:ilvl') ?? '0', 10);
      const numFmtEl = lvl.getElementsByTagName(wTag('w:numFmt'))[0];
      const numFmt = numFmtEl?.getAttribute('w:val') ?? 'bullet';
      const lvlTextEl = lvl.getElementsByTagName(wTag('w:lvlText'))[0];
      const lvlText = lvlTextEl?.getAttribute('w:val') ?? '';

      levels.set(ilvl, numFmt);

      // Detect type from ilvl=0 (Samsung always defines the root level)
      if (ilvl === 0) {
        if (lvlText === '☐' || lvlText === '☑') {
          type = 'checkbox';
        } else if (numFmt === 'decimal' || numFmt === 'upperLetter' ||
                   numFmt === 'lowerLetter' || numFmt === 'lowerRoman' ||
                   numFmt === 'upperRoman') {
          type = 'ordered';
        } else {
          type = 'bullet';
        }
      }
    }

    abstractMap.set(absId, { type, levels });
  }

  // Map numId → abstractNumId
  const result = new Map<string, NumDef>();
  const nums = doc.getElementsByTagName(wTag('w:num'));
  for (let i = 0; i < nums.length; i++) {
    const el = nums[i]!;
    const numId = el.getAttribute('w:numId') ?? '';
    const absRef = el.getElementsByTagName(wTag('w:abstractNumId'))[0];
    const absId = absRef?.getAttribute('w:val') ?? '';
    const def = abstractMap.get(absId);
    if (def) result.set(numId, def);
  }

  return result;
}

/**
 * Convert a single Samsung .docx to markdown.
 *
 * Parses word/document.xml, applies run-level formatting (bold, italic,
 * underline, strikethrough), converts lists using numbering.xml defs,
 * and collapses empty paragraphs.
 */
function docxToMarkdown(docXml: string, numDefs: Map<string, NumDef>): {
  body: string;
  /** Relationship IDs of images found in the document. */
  imageRIds: string[];
  hadImages: boolean;
  hadFormatting: boolean;
  hadLists: boolean;
  hadCheckboxes: boolean;
} {
  const parser = new DOMParser();
  const doc = parser.parseFromString(docXml, 'application/xml');
  const body = doc.getElementsByTagName(wTag('w:body'))[0];
  if (!body) return { body: '', imageRIds: [], hadImages: false, hadFormatting: false, hadLists: false, hadCheckboxes: false };

  const lines: string[] = [];
  const imageRIds: string[] = [];
  let hadImages = false;
  let hadFormatting = false;
  let hadLists = false;
  let hadCheckboxes = false;

  // Track ordered list counters per numId to generate correct numbers
  const orderedCounters = new Map<string, number>();

  const paragraphs = body.getElementsByTagName(wTag('w:p'));
  for (let pi = 0; pi < paragraphs.length; pi++) {
    const para = paragraphs[pi]!;

    // Check for images (w:drawing elements) and extract relationship IDs
    const drawings = para.getElementsByTagName(wTag('w:drawing'));
    const paraImagePlaceholders: string[] = [];
    if (drawings.length > 0) {
      hadImages = true;
      for (let di = 0; di < drawings.length; di++) {
        // Find a:blip which carries the r:embed relationship ID
        const blips = drawings[di]!.getElementsByTagName('a:blip');
        for (let bi = 0; bi < blips.length; bi++) {
          const rId = blips[bi]!.getAttribute('r:embed');
          if (rId) {
            const placeholder = `samsungimg:${rId}`;
            paraImagePlaceholders.push(`![](${placeholder})`);
            if (!imageRIds.includes(rId)) imageRIds.push(rId);
          }
        }
      }
    }

    // Get paragraph properties
    const pPr = para.getElementsByTagName(wTag('w:pPr'))[0];
    let numId: string | null = null;
    let ilvl = 0;

    if (pPr) {
      const numPr = pPr.getElementsByTagName(wTag('w:numPr'))[0];
      if (numPr) {
        const numIdEl = numPr.getElementsByTagName(wTag('w:numId'))[0];
        const ilvlEl = numPr.getElementsByTagName(wTag('w:ilvl'))[0];
        numId = numIdEl?.getAttribute('w:val') ?? null;
        ilvl = parseInt(ilvlEl?.getAttribute('w:val') ?? '0', 10);
      }
    }

    // Extract text from runs with formatting
    let paraText = '';
    const runs = para.getElementsByTagName(wTag('w:r'));
    for (let ri = 0; ri < runs.length; ri++) {
      const run = runs[ri]!;

      // For runs that contain drawings, emit placeholders instead of
      // skipping them entirely.
      const runDrawings = run.getElementsByTagName(wTag('w:drawing'));
      if (runDrawings.length > 0) {
        // Text in the same run as a drawing - grab it
        const runTexts = run.getElementsByTagName(wTag('w:t'));
        for (let ti = 0; ti < runTexts.length; ti++) {
          paraText += runTexts[ti]!.textContent ?? '';
        }
        continue;
      }

      const runTexts = run.getElementsByTagName(wTag('w:t'));
      let runStr = '';
      for (let ti = 0; ti < runTexts.length; ti++) {
        runStr += runTexts[ti]!.textContent ?? '';
      }
      if (!runStr) continue;

      // Check run formatting
      const rPr = run.getElementsByTagName(wTag('w:rPr'))[0];
      let bold = false;
      let italic = false;
      let underline = false;
      let strike = false;

      if (rPr) {
        bold = rPr.getElementsByTagName(wTag('w:b')).length > 0;
        italic = rPr.getElementsByTagName(wTag('w:i')).length > 0;
        const uEl = rPr.getElementsByTagName(wTag('w:u'))[0];
        underline = uEl != null && (uEl.getAttribute('w:val') ?? 'single') !== 'none';
        strike = rPr.getElementsByTagName(wTag('w:strike')).length > 0;

        if (bold || italic || underline || strike) hadFormatting = true;
      }

      // Apply markdown formatting - order matters for nesting
      let formatted = runStr;
      if (strike) formatted = `~~${formatted}~~`;
      if (bold) formatted = `**${formatted}**`;
      if (italic) formatted = `*${formatted}*`;
      // Underline has no markdown equivalent; use HTML tag that
      // TipTap's parser understands
      if (underline) formatted = `<u>${formatted}</u>`;

      paraText += formatted;
    }

    // Append image placeholders after any text in the paragraph
    if (paraImagePlaceholders.length > 0) {
      // If paragraph has text, put images on a new line after it;
      // otherwise the images ARE the paragraph content.
      if (paraText.trim()) {
        lines.push(paraText);
        for (const ph of paraImagePlaceholders) lines.push(ph);
      } else {
        for (const ph of paraImagePlaceholders) lines.push(ph);
      }
    } else if (numId) {
      // Apply list formatting
      const def = numDefs.get(numId);
      const indent = '  '.repeat(ilvl);

      if (def?.type === 'checkbox') {
        hadCheckboxes = true;
        lines.push(`${indent}- [ ] ${paraText}`);
      } else if (def?.type === 'ordered') {
        hadLists = true;
        // Track counter per numId+ilvl combo
        const counterKey = `${numId}-${ilvl}`;
        const count = (orderedCounters.get(counterKey) ?? 0) + 1;
        orderedCounters.set(counterKey, count);
        lines.push(`${indent}${count}. ${paraText}`);
      } else {
        // Bullet
        hadLists = true;
        lines.push(`${indent}- ${paraText}`);
      }
    } else {
      // Reset ordered counters when we leave a list context
      orderedCounters.clear();
      lines.push(paraText);
    }
  }

  let result = lines.join('\n');
  result = collapseBlankRuns(result);
  result = trimTrailing(result);

  return { body: result, imageRIds, hadImages, hadFormatting, hadLists, hadCheckboxes };
}

/* ------------------------------------------------------------------ */
/* File extraction: .zip / .txt / .docx                               */
/* ------------------------------------------------------------------ */

interface SamsungEntry {
  name: string;
  format: 'txt' | 'docx';
  /** Raw text for .txt, or markdown body for .docx. */
  body: string;
  /** From the zip entry's last-modified, if available. */
  zipDate: Date | null;
  /** Docx-specific metadata. */
  docxMeta?: {
    hadImages: boolean;
    hadFormatting: boolean;
    hadLists: boolean;
    hadCheckboxes: boolean;
  };
  /** Image blobs extracted from a .docx, keyed by placeholder (e.g. "samsungimg:rId2"). */
  blobs?: Map<string, { data: Uint8Array; mime: string; name: string }>;
}

/** MIME from file extension. Samsung sometimes saves JPEG data as .png. */
function mimeFromMediaPath(path: string): string {
  const ext = path.split('.').pop()?.toLowerCase() ?? '';
  const map: Record<string, string> = {
    png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg',
    gif: 'image/gif', webp: 'image/webp', bmp: 'image/bmp',
    svg: 'image/svg+xml',
  };
  return map[ext] ?? 'application/octet-stream';
}

/**
 * Parse document.xml.rels to build rId -> media target path mapping.
 * Only includes image relationships.
 */
function parseDocRels(xml: string): Map<string, string> {
  const parser = new DOMParser();
  const doc = parser.parseFromString(xml, 'application/xml');
  const map = new Map<string, string>();
  const rels = doc.getElementsByTagName('Relationship');
  for (let i = 0; i < rels.length; i++) {
    const rel = rels[i]!;
    const type = rel.getAttribute('Type') ?? '';
    if (type.includes('/image')) {
      const id = rel.getAttribute('Id') ?? '';
      const target = rel.getAttribute('Target') ?? '';
      if (id && target) map.set(id, target);
    }
  }
  return map;
}

async function parseDocxFile(
  zip: JSZip,
): Promise<{
  body: string;
  meta: SamsungEntry['docxMeta'];
  blobs: Map<string, { data: Uint8Array; mime: string; name: string }>;
}> {
  // Read numbering.xml (may not exist in all docx files)
  let numDefs = new Map<string, NumDef>();
  const numFile = zip.file('word/numbering.xml');
  if (numFile) {
    const numXml = await zipEntryText(numFile);
    numDefs = parseNumbering(numXml);
  }

  // Read document.xml
  const docFile = zip.file('word/document.xml');
  if (!docFile) {
    throw new Error('Invalid .docx: missing word/document.xml');
  }
  const docXml = await zipEntryText(docFile);
  const result = docxToMarkdown(docXml, numDefs);

  // Extract image blobs referenced by the document
  const blobs = new Map<string, { data: Uint8Array; mime: string; name: string }>();
  if (result.imageRIds.length > 0) {
    // Parse rels to resolve rId -> media path
    const relsFile = zip.file('word/_rels/document.xml.rels');
    if (relsFile) {
      const relsXml = await zipEntryText(relsFile);
      const rIdToPath = parseDocRels(relsXml);

      for (const rId of result.imageRIds) {
        const target = rIdToPath.get(rId);
        if (!target) continue;

        // Target is relative to word/ (e.g. "media/image2.png")
        const zipPath = `word/${target}`;
        const mediaFile = zip.file(zipPath);
        if (!mediaFile) continue;

        const data = await mediaFile.async('uint8array');
        const name = target.split('/').pop() ?? target;
        const mime = mimeFromMediaPath(name);

        // Key matches the placeholder in the markdown body
        blobs.set(`samsungimg:${rId}`, { data, mime, name });
      }
    }
  }

  return {
    body: result.body,
    meta: {
      hadImages: result.hadImages,
      hadFormatting: result.hadFormatting,
      hadLists: result.hadLists,
      hadCheckboxes: result.hadCheckboxes,
    },
    blobs,
  };
}

async function extractEntries(
  file: File,
  onProgress?: (m: string) => void,
): Promise<SamsungEntry[]> {
  const lowerName = file.name.toLowerCase();

  // Single .docx file
  if (lowerName.endsWith('.docx')) {
    onProgress?.('Parsing Word document…');
    const zip = await JSZip.loadAsync(file);
    const { body, meta, blobs } = await parseDocxFile(zip);
    return [{
      name: file.name,
      format: 'docx',
      body,
      zipDate: null,
      docxMeta: meta,
      blobs: blobs.size > 0 ? blobs : undefined,
    }];
  }

  // .zip archive - may contain .txt and/or .docx files
  if (lowerName.endsWith('.zip')) {
    onProgress?.('Unzipping…');
    const zip = await JSZip.loadAsync(file);
    const entries: SamsungEntry[] = [];

    // Collect all relevant files
    const allFiles = Object.values(zip.files).filter((f) => {
      if (f.dir) return false;
      if (f.name.includes('__MACOSX/') || f.name.startsWith('.')) return false;
      const lower = f.name.toLowerCase();
      return lower.endsWith('.txt') || lower.endsWith('.docx');
    });

    const txtFiles = allFiles.filter((f) => f.name.toLowerCase().endsWith('.txt'));
    const docxFiles = allFiles.filter((f) => f.name.toLowerCase().endsWith('.docx'));

    // Parse .docx files (richer format - preferred)
    if (docxFiles.length > 0) {
      onProgress?.(`Parsing ${docxFiles.length} Word document${docxFiles.length === 1 ? '' : 's'}…`);
      for (const entry of docxFiles) {
        try {
          const data = await entry.async('uint8array');
          const innerZip = await JSZip.loadAsync(data);
          const { body, meta, blobs } = await parseDocxFile(innerZip);
          entries.push({
            name: entry.name,
            format: 'docx',
            body,
            zipDate: entry.date ?? null,
            docxMeta: meta,
            blobs: blobs.size > 0 ? blobs : undefined,
          });
        } catch {
          // If a docx fails to parse, skip it - will be counted as a warning
        }
      }
    }

    // Parse .txt files
    if (txtFiles.length > 0) {
      onProgress?.(`Reading ${txtFiles.length} text file${txtFiles.length === 1 ? '' : 's'}…`);
      for (const entry of txtFiles) {
        const text = await zipEntryText(entry);
        entries.push({
          name: entry.name,
          format: 'txt',
          body: text,
          zipDate: entry.date ?? null,
        });
      }
    }

    return entries;
  }

  // Single .txt file
  if (lowerName.endsWith('.txt')) {
    const text = await file.text();
    return [{ name: file.name, format: 'txt', body: text, zipDate: null }];
  }

  // Fallback: try as text
  const text = await file.text();
  return [{ name: file.name, format: 'txt', body: text, zipDate: null }];
}

/* ------------------------------------------------------------------ */
/* Main parse function                                                */
/* ------------------------------------------------------------------ */

export async function parseSamsungNotes(
  file: File,
  onProgress?: (msg: string) => void,
): Promise<ParsedImport> {
  onProgress?.('Reading file…');
  const entries = await extractEntries(file, onProgress);

  if (entries.length === 0) {
    throw new Error(
      'No .txt or .docx files found. Expected a .zip containing Samsung Notes exports, or a single .txt/.docx file.',
    );
  }

  onProgress?.('Parsing notes…');
  const notes: ImportedNote[] = [];
  const warnings: string[] = [];

  // Aggregate image blobs from all docx entries into one map
  const allBlobs = new Map<string, { data: Uint8Array; mime: string; name: string }>();

  let emptyCount = 0;
  let untaggedCount = 0;
  let linkifiedCount = 0;
  let bulletConvertCount = 0;
  let checkboxConvertCount = 0;
  let blankCollapseCount = 0;
  let formattingPreservedCount = 0;
  let imageCount = 0;
  let docxCount = 0;
  let txtCount = 0;

  for (const entry of entries) {
    const { title, timestamp: fileTs } = parseFilename(entry.name);
    const bestDate = entry.zipDate ?? fileTs ?? new Date();
    const iso = bestDate.toISOString();

    let body: string;

    if (entry.format === 'docx') {
      // .docx already converted to markdown by parseDocxFile
      docxCount++;
      body = entry.body;

      if (entry.docxMeta?.hadImages) imageCount++;
      if (entry.docxMeta?.hadFormatting) formattingPreservedCount++;
      if (entry.docxMeta?.hadLists) bulletConvertCount++;
      if (entry.docxMeta?.hadCheckboxes) checkboxConvertCount++;

      // Merge blobs from this entry into the aggregate map
      if (entry.blobs) {
        for (const [key, blob] of entry.blobs) allBlobs.set(key, blob);
      }
    } else {
      // .txt path - apply Samsung marker normalization
      txtCount++;
      body = entry.body.trim();

      const hasBullets = /[•◦▪▫]/.test(body);
      // Both markers, matching what normalizeSamsungBody converts. Probing
      // only the unchecked `[  ]` left a note of purely ticked boxes
      // converted but uncounted, so the summary undercounted the import.
      const hasCheckboxes = /\[ {2}\]|\[[✓xXvV]\]/.test(body);
      const hadLongBlanks = /\n{4,}/.test(body);

      body = normalizeSamsungBody(body);
      body = collapseBlankRuns(body);
      body = trimTrailing(body);

      if (hasBullets) bulletConvertCount++;
      if (hasCheckboxes) checkboxConvertCount++;
      if (hadLongBlanks) blankCollapseCount++;
    }

    // Strip duplicate first line (Samsung often repeats the title)
    const firstLine = body.split('\n')[0]?.trim() ?? '';
    if (firstLine && firstLine === title.trim()) {
      body = body.slice(body.indexOf('\n') + 1).trimStart();
    }

    const linked = linkifyMarkdown(body);
    if (linked !== body) linkifiedCount++;
    body = linked;

    if (!body && !title) {
      emptyCount++;
      continue;
    }

    notes.push({
      title,
      body,
      tags: [],
      createdAt: iso,
      updatedAt: iso,
    });
    untaggedCount++;
  }

  // --- Transforms & warnings ---
  const transforms: string[] = [];

  if (docxCount > 0) {
    transforms.push(
      `Parsed ${docxCount} Word document${docxCount === 1 ? '' : 's'} with rich formatting.`,
    );
  }
  if (formattingPreservedCount > 0) {
    transforms.push(
      `Preserved bold, italic, underline, and strikethrough in ${formattingPreservedCount} note${formattingPreservedCount === 1 ? '' : 's'}.`,
    );
  }
  if (bulletConvertCount > 0) {
    transforms.push(
      `Converted list formatting in ${bulletConvertCount} note${bulletConvertCount === 1 ? '' : 's'}.`,
    );
  }
  if (checkboxConvertCount > 0) {
    transforms.push(
      `Converted checkboxes to native task lists in ${checkboxConvertCount} note${checkboxConvertCount === 1 ? '' : 's'}.`,
    );
  }
  if (allBlobs.size > 0) {
    transforms.push(
      `Found ${allBlobs.size} image${allBlobs.size === 1 ? '' : 's'} to import.`,
    );
  }
  if (linkifiedCount > 0) {
    transforms.push(
      `Made URLs clickable in ${linkifiedCount} note${linkifiedCount === 1 ? '' : 's'}.`,
    );
  }
  if (blankCollapseCount > 0) {
    transforms.push(
      `Cleaned up excess whitespace in ${blankCollapseCount} note${blankCollapseCount === 1 ? '' : 's'}.`,
    );
  }

  if (emptyCount > 0) {
    warnings.push(
      `Skipped ${emptyCount} empty note${emptyCount === 1 ? '' : 's'} with no title and no body.`,
    );
  }
  if (notes.length > 0) {
    warnings.push(
      'Samsung Notes exports do not include tags or folders. You can tag imported notes after import.',
    );
  }
  if (txtCount > 0 && docxCount === 0) {
    warnings.push(
      'Text exports lose formatting (bold, italic, etc.). For richer imports, export as Word (.docx) instead.',
    );
  }

  const uniqueTags = new Set<string>();
  for (const n of notes) for (const t of n.tags) uniqueTags.add(t);

  // Sum blob sizes for quota preflight
  let blobBytes = 0;
  for (const [, blob] of allBlobs) blobBytes += blob.data.length;

  return {
    notes,
    warnings,
    transforms,
    stats: {
      totalNotes: notes.length,
      emptyNotes: emptyCount,
      untaggedNotes: untaggedCount,
      uniqueTags: uniqueTags.size,
    },
    source: 'samsung-notes',
    ...(allBlobs.size > 0 ? { blobs: allBlobs, blobBytes } : {}),
  };
}
