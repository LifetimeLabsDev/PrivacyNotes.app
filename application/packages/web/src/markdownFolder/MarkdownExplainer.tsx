/**
 * The one place the plaintext nature is spelled out at length.
 *
 * One entry point: the `?` on the folder row, ending in a single [Got it].
 * It had a second mode until 2026-08-14 - the first-run gate of spec section
 * 12, shown once ahead of the OS picker - removed because the empty state
 * renders `MarkdownPitch` directly, so the gate put a modal in front of the
 * button and filled it with the screen already behind it. Everything else in
 * the feature stays quiet - the open padlock and the folder path do the
 * reminding - because a warning repeated on every surface is a warning people
 * learn to skip.
 *
 * Leads with the sell (an advanced Markdown editor, free, on the user's own
 * files), then the use cases, and states the local/plaintext nature as one
 * visual pair of facts rather than a warning list: these files stay on the
 * device, and they sit outside our encrypted vault. The claim "not even we can
 * read your notes" stays true here and is in a sense more true: nothing about
 * these files ever involves us. What changes is that local threats are the
 * user's to handle, and the honest way to say that is to state where the files
 * are and what we do not do with them.
 *
 * Spec: ops/docs/plans/markdown-folder.md (section 12)
 */
import { useTranslation } from 'react-i18next';
import {
  FileMd,
  X,
  Robot,
  Book,
  GitBranch,
  Sparkle,
  Eye,
  ListChecks,
  Tag,
  Table,
  Laptop,
  CloudSlash,
  Brain,
} from '../icons';
import { useEscapeToClose } from '../useEscapeToClose';
import { MarkdownDefaultAppRow } from './MarkdownDefaultApp';

/**
 * The pitch itself, without any modal chrome.
 *
 * Exported because the empty state shows exactly this - the same banner, chips,
 * use cases and local/plaintext strip - and a second copy of that content is a
 * second copy to keep in step. There is one set of strings and one layout; only
 * the frame around them differs.
 *
 * `actions` rides the last row beside the second-brain line. The modal puts its
 * dismiss/confirm pair there; the empty state passes nothing and lays its two
 * pickers out underneath, where they get a column each.
 */
export function MarkdownPitch({ actions }: { actions?: React.ReactNode }) {
  const { t } = useTranslation('shell');

  const chips: [React.ReactNode, string][] = [
    [<Eye size={13} key="a" />, t('markdown.chipPreview')],
    [<ListChecks size={13} key="b" />, t('markdown.chipTasks')],
    [<Tag size={13} key="c" />, t('markdown.chipTags')],
    [<Table size={13} key="d" />, t('markdown.chipTables')],
  ];
  const uses: [React.ReactNode, string][] = [
    [<Robot size={18} key="a" />, t('markdown.useAgent')],
    [<Book size={18} key="b" />, t('markdown.useObsidian')],
    [<GitBranch size={18} key="c" />, t('markdown.useGit')],
  ];

  return (
    <>
        <div className="flex items-center gap-2.5 rounded-md border border-amber-400/40 bg-amber-50 dark:border-amber-600/30 dark:bg-amber-950/20 px-3 py-2.5 mb-3">
          <Sparkle size={18} className="shrink-0 text-amber-500 dark:text-amber-400" />
          <div className="flex-1 min-w-0">
            <p className="text-[13px] font-semibold text-amber-900 dark:text-amber-300 leading-snug">
              {t('markdown.bannerTitle')}
            </p>
            <p className="text-xs text-amber-700 dark:text-amber-400/80 leading-snug">
              {t('markdown.bannerSub')}
            </p>
          </div>
          <span className="shrink-0 text-[10px] font-semibold uppercase tracking-wide bg-amber-200 dark:bg-amber-800 text-amber-900 dark:text-amber-100 rounded-full px-2 py-0.5">
            {t('markdown.bannerFree')}
          </span>
        </div>

        <p className="text-xs text-pn-muted text-center mb-3">
          {t('markdown.explainIntro')}
        </p>

        <div className="flex flex-wrap justify-center gap-1.5 mb-4">
          {chips.map(([icon, label]) => (
            <span
              key={label}
              className="inline-flex items-center gap-1.5 rounded-full border border-divider px-2.5 py-1 text-xs text-pn-soft"
            >
              <span className="text-pn-muted">{icon}</span>
              {label}
            </span>
          ))}
        </div>

        <div className="grid grid-cols-3 gap-2 mb-3">
          {uses.map(([icon, label]) => (
            <div key={label} className="rounded-md bg-surface-1 px-2 py-2.5 text-center">
              <span className="flex justify-center text-pn-muted">{icon}</span>
              <p className="mt-1.5 text-[11px] leading-snug text-pn-soft">{label}</p>
            </div>
          ))}
        </div>

        {/* The local/plaintext facts as one strip: a positive (your disk, your
            eyes only) beside a negative (outside the vault), replacing the old
            tick/cross warning list. */}
        <div className="flex items-stretch gap-3 rounded-md border border-divider bg-surface-1 px-3 py-2.5 mb-4">
          <div className="flex flex-1 items-center gap-2">
            <Laptop size={18} className="shrink-0 text-green-600 dark:text-green-500" />
            <div className="min-w-0">
              <p className="text-xs font-medium text-pn leading-snug">{t('markdown.localTitle')}</p>
              <p className="text-[11px] text-pn-muted leading-snug">{t('markdown.localSub')}</p>
            </div>
          </div>
          <div className="border-s border-divider" />
          <div className="flex flex-1 items-center gap-2">
            <CloudSlash size={18} className="shrink-0 text-red-600 dark:text-red-500" />
            <div className="min-w-0">
              <p className="text-xs font-medium text-pn leading-snug">{t('markdown.cloudTitle')}</p>
              <p className="text-[11px] text-pn-muted leading-snug">{t('markdown.cloudSub')}</p>
            </div>
          </div>
        </div>

        {/* Two shapes from one row, decided by whether `actions` rides it. With
            a button the line is a left-aligned label and `flex-1` pushes the
            button to the end. Without one it is the last line of a centred card
            - intro, chips and tiles above it are all centred - so it centres
            too rather than sitting alone against the left edge. */}
        <div className={`flex items-center gap-2 ${actions ? '' : 'justify-center'}`}>
          <Brain size={16} className="shrink-0 text-pn-muted" />
          <p className={`min-w-0 text-xs text-pn-muted leading-snug ${actions ? 'flex-1' : 'text-center'}`}>
            {t('markdown.secondBrain')}
          </p>
          {actions}
        </div>

        {/* Which app the OS opens .md files with. Renders nothing outside the
            desktop app, and lands in BOTH of this component's homes for free -
            the explainer modal and the no-folder empty state - which is the
            whole reason it goes here rather than in either of them.
            Below the second-brain line and not above it: everything above is the
            pitch, and this is the one row that changes the machine rather than
            describing the feature.
            Spec: ops/docs/plans/markdown-folder.md (section 11) */}
        <MarkdownDefaultAppRow />
    </>
  );
}

export function MarkdownExplainer({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation('shell');
  useEscapeToClose(onClose);

  return (
    <div
      className="fixed inset-0 z-50 bg-black/50 dark:bg-black/70 flex items-center justify-center p-4 sm:p-6"
      onClick={onClose}
    >
      <div
        className="w-full max-w-md rounded-lg border border-divider bg-surface-2 p-5"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-labelledby="markdown-explainer-title"
      >
        <div className="flex items-center gap-2.5 mb-3">
          <FileMd size={20} className="text-pn-muted shrink-0" />
          <h2 id="markdown-explainer-title" className="flex-1 text-lg font-semibold text-pn">
            {t('markdown.explainTitle')}
          </h2>
          <button
            type="button"
            onClick={onClose}
            aria-label={t('markdown.close')}
            className="shrink-0 text-neutral-400 hover:text-neutral-600 dark:hover:text-neutral-300 transition p-1 -m-1"
          >
            <X size={18} />
          </button>
        </div>

        {/* One dismiss, no confirm. This was also the first-folder-pick gate
            until 2026-08-14, when that mode was removed as redundant - the
            empty state renders this same pitch, so the gate showed the reader
            what was already on screen. Now it is only the reference card. */}
        <MarkdownPitch
          actions={
            <button
              type="button"
              onClick={onClose}
              className="shrink-0 text-[13px] px-3 py-1.5 rounded-md border border-divider hover:bg-surface-1 transition"
            >
              {t('markdown.explainDone')}
            </button>
          }
        />
      </div>
    </div>
  );
}
