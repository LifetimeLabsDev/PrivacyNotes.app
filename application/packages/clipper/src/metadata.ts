/**
 * A page's title, author, site, date and description, read from the markup
 * before the page is cleaned (the JSON-LD lives in script elements the
 * cleaning removes). The first source that has a value wins, in this order:
 * `citation_*` tags, Open Graph, schema.org JSON-LD, Dublin Core, then the
 * document title.
 */

export interface PageMeta {
  title: string;
  byline: string;
  siteName: string;
  published: string;
  description: string;
  /** The page's lead picture (Open Graph, Twitter or JSON-LD). */
  image: string;
  /** Whether the page says it is an article, so its lead picture is the
   *  article's own and not a site-wide card. */
  isArticle: boolean;
}

type Source = Partial<Omit<PageMeta, 'isArticle'>>;

export function readMetadata(doc: Document): PageMeta {
  const sources: Source[] = [citation(doc), openGraph(doc), jsonLd(doc), dublinCore(doc), { title: doc.title }];
  const pick = (key: Exclude<keyof PageMeta, 'isArticle'>): string => {
    for (const s of sources) {
      const v = clean(s[key], key === 'image' ? 2000 : 300);
      // A byline that is an address (a profile page) is no name.
      if (v && !(key === 'byline' && /^https?:\/\//i.test(v))) return v;
    }
    return '';
  };
  const ogType = meta(doc, 'og:type').toLowerCase();
  const published = pick('published');
  return {
    title: pick('title'),
    byline: pick('byline'),
    siteName: pick('siteName'),
    published,
    description: pick('description'),
    image: pick('image'),
    isArticle: ogType === 'article' || Boolean(published) || hasArticleLd(doc),
  };
}

/** One line of plain text, at most `max` characters. */
function clean(v: string | undefined, max: number): string {
  return (v ?? '').replace(/\s+/g, ' ').trim().slice(0, max);
}

function meta(doc: Document, ...names: string[]): string {
  for (const name of names) {
    const lower = name.toLowerCase();
    for (const el of Array.from(doc.querySelectorAll('meta'))) {
      const key = (el.getAttribute('name') ?? el.getAttribute('property') ?? '').toLowerCase();
      const content = el.getAttribute('content');
      if (key === lower && content?.trim()) return content;
    }
  }
  return '';
}

function citation(doc: Document): Source {
  return {
    title: meta(doc, 'citation_title'),
    byline: meta(doc, 'citation_author'),
    siteName: meta(doc, 'citation_journal_title', 'citation_publisher'),
    published: meta(doc, 'citation_publication_date', 'citation_date'),
  };
}

function openGraph(doc: Document): Source {
  return {
    title: meta(doc, 'og:title'),
    byline: meta(doc, 'article:author', 'author'),
    siteName: meta(doc, 'og:site_name'),
    published: meta(doc, 'article:published_time', 'date', 'pubdate', 'publishdate', 'publish-date', 'parsely-pub-date', 'sailthru.date'),
    description: meta(doc, 'og:description', 'description'),
    image: meta(doc, 'og:image', 'og:image:url', 'og:image:secure_url', 'twitter:image'),
  };
}

function dublinCore(doc: Document): Source {
  return {
    title: meta(doc, 'dc.title', 'dcterms.title'),
    byline: meta(doc, 'dc.creator', 'dcterms.creator'),
    siteName: meta(doc, 'dc.publisher', 'dcterms.publisher'),
    published: meta(doc, 'dc.date', 'dcterms.date', 'dcterms.issued'),
    description: meta(doc, 'dc.description', 'dcterms.description'),
  };
}

const ARTICLE_TYPES = /^(?:Article|NewsArticle|BlogPosting|Report|ScholarlyArticle|TechArticle|Recipe|WebPage|HowTo)$/;

const NEWS_TYPES = /^(?:Article|NewsArticle|BlogPosting|Report|ScholarlyArticle|TechArticle|Recipe|HowTo|ReportageNewsArticle|AnalysisNewsArticle|OpinionNewsArticle)$/;

function hasArticleLd(doc: Document): boolean {
  for (const script of Array.from(doc.querySelectorAll('script[type="application/ld+json"]'))) {
    try {
      const node = findArticle(JSON.parse(script.textContent ?? ''), 0);
      const types = node ? (Array.isArray(node['@type']) ? node['@type'] : [node['@type']]) : [];
      if (types.some((t) => typeof t === 'string' && NEWS_TYPES.test(t))) return true;
    } catch {
      // Not JSON: the next script.
    }
  }
  return false;
}

function jsonLd(doc: Document): Source {
  for (const script of Array.from(doc.querySelectorAll('script[type="application/ld+json"]'))) {
    let data: unknown;
    try {
      data = JSON.parse(script.textContent ?? '');
    } catch {
      continue;
    }
    const node = findArticle(data, 0);
    if (!node) continue;
    return {
      title: text(node.headline) || text(node.name),
      byline: names(node.author),
      siteName: names(node.publisher),
      published: text(node.datePublished),
      description: text(node.description),
      image: imageUrl(node.image),
    };
  }
  return {};
}

type Obj = Record<string, unknown>;

function findArticle(data: unknown, depth: number): Obj | null {
  if (depth > 4 || !data || typeof data !== 'object') return null;
  if (Array.isArray(data)) {
    for (const item of data) {
      const found = findArticle(item, depth + 1);
      if (found) return found;
    }
    return null;
  }
  const obj = data as Obj;
  const types = Array.isArray(obj['@type']) ? obj['@type'] : [obj['@type']];
  if (types.some((t) => typeof t === 'string' && ARTICLE_TYPES.test(t))) return obj;
  return findArticle(obj['@graph'], depth + 1);
}

function text(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

function imageUrl(v: unknown): string {
  const first = Array.isArray(v) ? v[0] : v;
  if (typeof first === 'string') return first;
  return first && typeof first === 'object' ? text((first as Obj).url) : '';
}

function names(v: unknown): string {
  const list = Array.isArray(v) ? v : [v];
  return list
    .map((item) => (typeof item === 'string' ? item : item && typeof item === 'object' ? text((item as Obj).name) : ''))
    .filter(Boolean)
    .slice(0, 3)
    .join(', ');
}
