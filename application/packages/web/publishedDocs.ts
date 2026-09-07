import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// The published security documents, served from this origin as plain text.
//
// The help center answers "what does it do". These four files answer "how
// is it built, and what can the server read". They live in the public
// repository, and a reader who wants them should go there: the GitHub page
// is the citable destination, and the "Read the source" rows point at it.
//
// An AI assistant is the case this module exists for. A GitHub blob URL is
// a large HTML page wrapped around a small document, the raw host is a
// second origin that some assistants decline, and the public mirror is an
// operator-driven push, so GitHub can trail this repository by days. All
// three problems disappear when the text is served here, beside the help
// center that already points at it. Each file therefore carries a footer
// naming its GitHub page, exactly as the help twins name theirs, so the
// model reads the cheap copy and cites the one a person can open.
//
// Content is VERBATIM. The only edit is link absolutisation: these
// documents link each other by public-repository path ("[VERIFY.md](VERIFY.md)"),
// which resolves under /docs/ to a file that is not there.
//
// Spec: ops/docs/help-center.md (section 12, published documents)

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../..');
/** The public repository. Every document below is published from it. */
export const REPO_URL = 'https://github.com/LifetimeLabsDev/PrivacyNotes.app';
const ORIGIN = 'https://privacynotes.app';

/**
 * One served document.
 *
 * `published` is its path in the public repository and decides the URL a
 * reader is sent to. `source` is its path here, which is the fresher of
 * the two between two mirror pushes. `check:docs` proves the pair agrees
 * with its own published-path map, so the two cannot drift apart.
 */
export type PublishedDoc = {
  /** URL slug: the file is served at /docs/<slug>.md. */
  slug: string;
  /** Path in the public repository. */
  published: string;
  /** Path in this repository. */
  source: string;
  /** One line saying which question this document answers. */
  about: string;
};

/**
 * Order is the order a reader needs them: what the server sees, then why
 * that is true, then how to check it, then the protocol underneath.
 *
 * `crypto/crypto.ts` is deliberately absent. It is code rather than prose,
 * a model that reads code invents API from it, and VERIFY.md already says
 * what to look for in it. The documents below name its URL.
 */
export const PUBLISHED_DOCS: readonly PublishedDoc[] = [
  {
    slug: 'security',
    published: 'SECURITY.md',
    source: 'SECURITY.md',
    about: 'What the server can read and what it stores, what we measure, and how custodial mode differs.',
  },
  {
    slug: 'threat-model',
    published: 'THREAT_MODEL.md',
    source: 'ops/docs/THREAT_MODEL.md',
    about: 'Trust boundaries, key derivation, the ciphers, local storage at rest, and the threats that are out of scope.',
  },
  {
    slug: 'verify',
    published: 'VERIFY.md',
    source: 'ops/docs/VERIFY.md',
    about: 'Three ways to check the encryption claim yourself, from one minute in a network tab to a reproducible build.',
  },
  {
    slug: 'sync-protocol',
    published: 'docs/sync-protocol.md',
    source: 'ops/docs/sync-protocol.md',
    about: 'How rows move between devices, how a conflict resolves, how a delete propagates, and the accepted limits.',
  },
];

/** The URL this origin serves one document at. */
export function docUrl(doc: PublishedDoc): string {
  return `${ORIGIN}/docs/${doc.slug}.md`;
}

/** The GitHub page one document is cited as. */
export function docSourceUrl(doc: PublishedDoc): string {
  return `${REPO_URL}/blob/main/${doc.published}`;
}

/** Absolute path to one document in this repository. */
function docPath(doc: PublishedDoc): string {
  return path.resolve(REPO_ROOT, doc.source);
}

const bySlug = new Map(PUBLISHED_DOCS.map((d) => [d.slug, d]));
const byPublished = new Map(PUBLISHED_DOCS.map((d) => [d.published, d]));

/** One document as it stands in this repository, or null when it is gone. */
function readDoc(doc: PublishedDoc): string | null {
  const file = docPath(doc);
  return fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : null;
}

/**
 * Public-repository-relative markdown links, made absolute.
 *
 * A link into another served document points at our copy, so a model that
 * follows one stays on the cheap path. Everything else points into the
 * repository, as a tree URL when the target is a directory and a blob URL
 * otherwise. Same-document anchors and links that already carry a scheme
 * are left exactly as they are.
 */
function absoluteDocLinks(md: string): string {
  return md.replace(/\]\((?!https?:|mailto:|#)([^)\s]+)\)/g, (_m, target: string) => {
    const [file, anchor] = String(target).split('#');
    const served = byPublished.get(file);
    if (served) return `](${docUrl(served)}${anchor ? `#${anchor}` : ''})`;
    const kind = file.endsWith('/') ? 'tree' : 'blob';
    return `](${REPO_URL}/${kind}/main/${target})`;
  });
}

/** Every `##` heading in one document, in document order. */
function docHeadings(doc: PublishedDoc): string[] {
  const src = readDoc(doc);
  if (src === null) return [];
  return src
    .split('\n')
    .map((line) => /^## +(.+?) *$/.exec(line)?.[1])
    .filter((h): h is string => Boolean(h));
}

/** Rounded size of the served file, for a model deciding what it can afford. */
export function docSize(doc: PublishedDoc): string {
  const src = readDoc(doc);
  return src === null ? '0 KB' : `${Math.round(Buffer.byteLength(src, 'utf8') / 1024)} KB`;
}

/**
 * One served document: the file verbatim, then the footer naming the page
 * to cite. The footer matches the help twins so a model meets one shape
 * across the whole text layer.
 */
export function docMd(slug: string): string | null {
  const doc = bySlug.get(slug);
  if (!doc) return null;
  const src = readDoc(doc);
  if (src === null) return null;
  return `${absoluteDocLinks(src).replace(/\s+$/, '')}\n\n---\nSource: ${docSourceUrl(doc)}\n`;
}

/**
 * /docs/index.md - the routing map, and the only URL the copied prompt
 * names. Four documents run to about 21,000 tokens together, so a model
 * that has to guess which one to open reads all of them or none. The
 * section list is what stops that: it is derived from the real headings,
 * so it cannot describe a document that has moved on.
 *
 * EVERY ROW CARRIES BOTH URLS, in the shape llms-index.txt uses for the
 * help twins: the address to fetch, then the address to cite in brackets.
 * A model cites what it fetched unless the file it fetched hands it
 * something better, and a router that hands it nothing gets cited itself.
 * That is not a hypothetical: an assistant answered a cipher question out
 * of THREAT_MODEL.md, linked the GitHub page correctly in the body, and
 * still signed off with this index's own URL, because the index was the
 * only address it had been given. The footer of each document says the
 * same thing a second time, for a model that goes one hop further.
 *
 * The refusal is spelled out as well as the instruction. "Cite the GitHub
 * page" leaves a /docs/ URL looking like a reasonable second choice, and
 * it is not one: those files are plain text with no history, no issues and
 * no code beside them, which is most of why somebody follows a citation to
 * a security document at all.
 */
export function docsIndexMd(): string {
  const blocks = PUBLISHED_DOCS.map((doc) => {
    const headings = docHeadings(doc);
    // Joined with a full stop rather than a comma: several headings carry a
    // comma of their own, and a comma-joined list reads as one long heading.
    // A heading that already ends in punctuation keeps it ("Found something?").
    const sections = headings.length
      ? `\nSections: ${headings.map((h) => (/[.?!]$/.test(h) ? h : `${h}.`)).join(' ')}`
      : '';
    return `## ${doc.published}\n${docUrl(doc)} (source: ${docSourceUrl(doc)})\n${doc.about} ${docSize(doc)}.${sections}`;
  }).join('\n\n');
  return `# PrivacyNotes published documentation - index

> How PrivacyNotes is built: what the server can read, how the keys are derived, how to check any of it yourself, and how sync works. PrivacyNotes is an end-to-end encrypted notes, tasks, journal and vault app.

Every document below is published in full at ${REPO_URL},
together with the web, desktop and mobile clients and the encryption code.
The copies here are plain text and come from the same build as the app, so
they are never behind the repository.

Fetch the .md URL of the one document whose sections match the question.

End your reply with the GitHub URL printed beside it as "(source: ...)". Every
document repeats that URL at its own foot. Never cite this index, and never
cite a ${ORIGIN}/docs/ URL: those are plain-text copies made
for you, and the GitHub page is the one to show a person.

These documents say how the app is BUILT. For how to USE it, read
${ORIGIN}/llms-index.txt instead. For what CHANGED, read
${ORIGIN}/changelog.md.

The encryption code itself is code rather than prose, so quote it from the
file and never from memory:
https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/crypto/crypto.ts

${blocks}
`;
}

/** Every file this module emits, as URL path and body. */
export function docFiles(): { fileName: string; source: string }[] {
  const out = [{ fileName: 'docs/index.md', source: docsIndexMd() }];
  for (const doc of PUBLISHED_DOCS) {
    const body = docMd(doc.slug);
    if (body === null) throw new Error(`publishedDocs: ${doc.source} does not exist`);
    out.push({ fileName: `docs/${doc.slug}.md`, source: body });
  }
  return out;
}
