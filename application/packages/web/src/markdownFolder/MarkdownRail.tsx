/**
 * The Markdown pillar's own sidebar rail.
 *
 * Deliberately not the encrypted side's `FolderTree` + `TagsRail`. Those read
 * `userSettings.folders`, are synced, and gate every mutation behind the Pro
 * upsell in `useFolderActions`. Reusing them would mean synthesizing fake
 * `FolderDef` records, adding a read-only mode that does not exist, and
 * permanently ensuring `scheduleFolderSync` never fires on a folder that is not
 * real. This component instead derives everything from the scan and can reach
 * nothing else - isolation by construction, which is the whole point.
 *
 * Consequences that fall out for free, rather than needing enforcement:
 *   - No depth limit to enforce. Directories are the data; nothing is
 *     created, validated or synced, so a fifteen-deep vault just works.
 *   - No CRUD. A rename here would mean moving files on disk, which is a
 *     different feature with a different confirm.
 *   - No Pro gate anywhere near it.
 *
 * Spec: ops/docs/plans/markdown-folder.md (section 9)
 */
import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { Folder, Hash } from '../icons';
import { OverflowTip } from '../OverflowTip';
import { SIDEBAR_ACTIVE } from '../sidebarUI';
import type { DirectoryEntry } from './fileAccess';

/**
 * Indentation stops here, the tree does not.
 *
 * At the 240px default sidebar a sixth level of indent leaves no room for a
 * name. Deeper folders keep this indent; a name squeezed past the row's width
 * shows its full path on hover, and the path chips in the list carry it
 * otherwise. The sidebar is also user-resizable to 420px, so the reader has
 * their own answer if they want one. Truncating the tree instead would hide
 * files, which is never acceptable.
 */
const MAX_INDENT_LEVEL = 5;

interface FolderNode {
  /** Path with a trailing slash, matching `DirectoryEntry.dir`. `''` is root. */
  path: string;
  name: string;
  depth: number;
  /** Files at this exact path, not counting descendants - the number that
   *  answers "what will I see if I click this". */
  count: number;
}

/** Every directory that actually contains a file, flattened in display order.
 *
 *  Built from the entry paths rather than from a directory listing: a folder
 *  holding only images or only other folders is not something to offer, since
 *  clicking it would show an empty list. */
function buildTree(entries: DirectoryEntry[]): FolderNode[] {
  const counts = new Map<string, number>();
  for (const e of entries) {
    counts.set(e.dir, (counts.get(e.dir) ?? 0) + 1);
    // Register every ancestor so an intermediate folder that holds no files of
    // its own still appears and keeps the tree connected.
    const parts = e.dir.split('/').filter(Boolean);
    for (let i = 1; i < parts.length; i++) {
      const ancestor = `${parts.slice(0, i).join('/')}/`;
      if (!counts.has(ancestor)) counts.set(ancestor, 0);
    }
  }

  return [...counts.keys()]
    .sort((a, b) => a.localeCompare(b))
    .map((path) => {
      const parts = path.split('/').filter(Boolean);
      return {
        path,
        name: parts[parts.length - 1] ?? '',
        depth: parts.length,
        count: counts.get(path) ?? 0,
      };
    })
    .filter((n) => n.depth > 0);
}

export function MarkdownRail({
  entries,
  tags,
  selectedDir,
  onSelectDir,
  selectedTag,
  onSelectTag,
}: {
  entries: DirectoryEntry[];
  /** Tag to file-count, accumulated by the background index. Empty until it
   *  has read something, which is why the section hides rather than showing a
   *  misleading "no tags". */
  tags: Map<string, number>;
  selectedDir: string | null;
  onSelectDir: (dir: string | null) => void;
  selectedTag: string | null;
  onSelectTag: (tag: string | null) => void;
}) {
  const { t } = useTranslation('shell');
  const nodes = useMemo(() => buildTree(entries), [entries]);
  const sortedTags = useMemo(
    () => [...tags.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])),
    [tags],
  );

  // The encrypted side has TWO row treatments, not one, and this rail owes each
  // half its parity: folder rows are `FolderTree`'s (glyph, count and row height
  // all compact at `lg`), tag rows are `TagsRail`'s (which compacts nothing).
  // Sharing one recipe across both is exactly how this rail drifted from them
  // before. Only the DATA is separate - the design must not be, which is why the
  // selected state comes from the shared `SIDEBAR_ACTIVE` token rather than a
  // copy of it.
  //
  // What differs on purpose, because the encrypted parts have no counterpart
  // here: no caret column (nothing collapses, so the tree is flattened and
  // indent is inline padding rather than a nested guide line), no `...` actions
  // button, and a folder holding no files of its own shows no count at all
  // rather than a "0" that would read as a failed scan.
  const selectedClass = (active: boolean) =>
    active
      ? SIDEBAR_ACTIVE
      : 'text-neutral-900 hover:bg-neutral-200/60 dark:text-white dark:hover:bg-neutral-900/60';
  const folderRowClass = (active: boolean) =>
    `w-full rounded text-[15px] lg:text-[13px] font-medium transition flex items-center group ${selectedClass(active)}`;
  const tagRowClass = (active: boolean) =>
    `w-full rounded text-[15px] font-medium transition flex items-center group ${selectedClass(active)}`;
  const folderInnerClass = 'flex-1 min-w-0 flex items-center gap-2 lg:gap-1.5 px-2 py-2 lg:py-1 text-start';
  const tagInnerClass = 'flex-1 min-w-0 flex items-center gap-2 px-2 py-2 text-start';
  const folderCountClass =
    'shrink-0 text-xs lg:text-[11px] text-neutral-400 dark:text-neutral-600 tabular-nums ms-1 me-2 lg:me-1.5';
  const tagCountClass = 'shrink-0 text-xs text-neutral-400 dark:text-neutral-600 tabular-nums ms-2 me-2';

  return (
    <div className="flex-1 min-h-0 overflow-y-auto px-3 pb-3">
      <p className="text-[11px] uppercase tracking-wide text-pn-muted px-2 pt-3 pb-1">
        {t('markdown.railFolders')}
      </p>
      <button type="button" onClick={() => onSelectDir(null)} className={folderRowClass(selectedDir === null)}>
        <span className={folderInnerClass}>
          <span className={`inline-flex shrink-0 ${selectedDir === null ? 'text-accent' : 'text-amber-600/80 dark:text-amber-500/80'}`}>
            <Folder size={16} className="lg:w-3.5 lg:h-3.5" />
          </span>
          <span className="truncate">{t('markdown.allFiles')}</span>
        </span>
        <span className={folderCountClass}>{entries.length}</span>
      </button>
      {/* `OverflowTip` rather than a native `title`, the same wrapper
          `FolderTree` puts on its row names (ui-patterns section 41). The tip
          carries the full PATH, not the name the row already shows, so it is
          never a repeat of visible text - but it is still gated on the name
          actually truncating, because that is the component's contract and a
          tip on every row of a fully-legible tree is noise. A deep folder whose
          name fits gets its location from the path chip on the list rows. */}
      {nodes.map((node) => (
        <OverflowTip key={node.path} text={node.path} className="block">
          <button
            type="button"
            onClick={() => onSelectDir(node.path)}
            className={folderRowClass(selectedDir === node.path)}
          >
            <span
              className={folderInnerClass}
              style={{ paddingInlineStart: `${8 + Math.min(node.depth - 1, MAX_INDENT_LEVEL) * 14}px` }}
            >
              <span className={`inline-flex shrink-0 ${selectedDir === node.path ? 'text-accent' : 'text-amber-600/80 dark:text-amber-500/80'}`}>
                <Folder size={16} className="lg:w-3.5 lg:h-3.5" />
              </span>
              <span className="truncate">{node.name}</span>
            </span>
            {node.count > 0 && <span className={folderCountClass}>{node.count}</span>}
          </button>
        </OverflowTip>
      ))}

      {sortedTags.length > 0 && (
        <>
          <p className="text-[11px] uppercase tracking-wide text-pn-muted px-2 pt-4 pb-1">
            {t('markdown.railTags')}
          </p>
          {/* Filter only. A rename here would rewrite front matter across every
              file carrying the tag - a bulk write, each subject to the
              never-clobber rule, any of which may have changed since the scan.
              Tag editing belongs per-note, on a file the user is looking at. */}
          {sortedTags.map(([tag, count]) => (
            <button
              key={tag}
              type="button"
              onClick={() => onSelectTag(selectedTag === tag ? null : tag)}
              className={tagRowClass(selectedTag === tag)}
            >
              <span className={tagInnerClass}>
                <span className="inline-flex shrink-0 text-accent">
                  <Hash size={16} />
                </span>
                <span className="truncate">{tag}</span>
              </span>
              <span className={tagCountClass}>{count}</span>
            </button>
          ))}
        </>
      )}
    </div>
  );
}
