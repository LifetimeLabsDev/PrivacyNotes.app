/**
 * What the Markdown pane shows before a folder or file is open.
 *
 * Three states, because "not supported" splits into two genuinely different
 * situations - a desktop browser without the API has a fix worth selling, a
 * phone does not - plus the remembered-folder prompt that only Chromium needs.
 *
 * Spec: ops/docs/archive/markdown-folder.md (sections 5 and 12)
 */
import { useTranslation } from 'react-i18next';
import { Download, SlidersHorizontal, Copy, Check, FileText, FolderOpen } from '../icons';
import { Button } from '../ui';
import { useCopyToClipboard } from '../clipboard';
import { marketingHomeHref } from '../siteLinks';
import { MarkdownPitch } from './MarkdownExplainer';
import { BRAVE_FLAG_NAME, BRAVE_FLAG_URL, type markdownSupport } from './capability';

export function MarkdownEmptyState({
  support,
  error,
  busy,
  reopenName,
  onReopen,
  onOpenFile,
  onOpenFolder,
}: {
  support: ReturnType<typeof markdownSupport>;
  error: string | null;
  busy: boolean;
  /** Set when a folder is remembered but the browser dropped its permission. */
  reopenName: string | null;
  onReopen: () => void;
  onOpenFile: () => void;
  onOpenFolder: () => void;
}) {
  const { t } = useTranslation('shell');
  const { copy, copied } = useCopyToClipboard();

  // Brave is a Chromium that fails the capability check, and the fix is a flag
  // rather than a download - so it gets the flag, and the app pitch drops to a
  // footnote. Selling a 100 MB install to someone twenty seconds from the real
  // feature is the wrong trade.
  if (support === 'needs-brave-flag') {
    return (
      <div className="h-full overflow-y-auto flex flex-col px-6 py-10">
        {/* rtl-ok: every string in this card is forced English (see below), and
            an English sentence inheriting dir=rtl puts its full stop on the
            wrong end - Arabic rendered ".API" to Enabled, then relaunch Brave".
            The card is English, so it is an LTR island, whole. */}
        <div
          dir="ltr"
          className="w-full max-w-sm mx-auto my-auto flex flex-col items-center text-center gap-3"
        >
          <SlidersHorizontal size={26} weight="duotone" className="text-pn-muted" />
          {/* Every string in this card reads English in every catalog, held by
              the verbatim list of tools/lint-locales.mjs. It walks the reader
              through a Chromium flags page, and Chromium ships those pages in
              English everywhere - a card translated around an untranslated
              screen helps nobody. `flag` is a constant for the same reason. */}
          <p className="text-[15px] font-semibold">
            {t('markdown.braveTitle', { flag: BRAVE_FLAG_NAME })}
          </p>
          {/* Text with a copy button, not a link: Chromium blocks page-initiated
              navigation to `brave://`, so an anchor would read as clickable and
              silently do nothing. */}
          <div className="w-full flex items-center gap-2 rounded-md border border-divider bg-surface-1 ps-2.5 pe-1.5 py-1.5">
            {/* `text-start` resolves to left inside the card's LTR island, so
                the URL never needs a physical utility or its own dir. */}
            <code className="flex-1 min-w-0 truncate text-start font-mono text-[12px] text-pn-soft">
              {BRAVE_FLAG_URL}
            </code>
            <button
              type="button"
              onClick={() => copy(BRAVE_FLAG_URL, 'brave-flag')}
              className="shrink-0 inline-flex items-center gap-1 text-[12px] font-medium px-2 py-1 rounded border border-divider hover:bg-surface-2 transition"
            >
              {copied === 'brave-flag' ? <Check size={13} /> : <Copy size={13} />}
              {copied === 'brave-flag'
                ? t('markdown.braveCopied')
                : t('markdown.braveCopy')}
            </button>
          </div>
          {/* Body size, matching the sibling empty state: this line carries the
              whole instruction now, and it is the last thing that should be
              squinted at. The app link stays secondary on colour and underline
              rather than on being smaller. */}
          <p className="text-[13px] text-pn-muted leading-relaxed">
            {t('markdown.braveSteps', { flag: BRAVE_FLAG_NAME })}
          </p>
          <a
            href={`${marketingHomeHref()}#downloads`}
            target="_blank"
            rel="noreferrer"
            className="text-[13px] text-pn-muted underline underline-offset-2 hover:text-pn transition mt-1"
          >
            {t('markdown.braveAppAlternative')}
          </a>
        </div>
      </div>
    );
  }

  if (support === 'needs-desktop-app') {
    return (
      <div className="h-full flex flex-col items-center justify-center text-center px-6 py-10 gap-3">
        <Download size={26} weight="duotone" className="text-pn-muted" />
        <p className="text-[15px] font-semibold">{t('markdown.needsAppTitle')}</p>
        {/* Two sentences, one per line: as a single string it stretched the
            full width of the pane on a desktop window and read as a wall. The
            break sits on the sentence boundary, so it survives translation. */}
        <p className="text-[13px] text-pn-muted leading-relaxed">
          {t('markdown.needsAppBody')}
          <br />
          {t('markdown.needsAppWhere')}
        </p>
        {/* The state exists to sell the app, so it offers the remedy it
            names. Same target as the sidebar's Downloads entry,
            built through `marketingHomeHref()` so it carries the reader's
            locale slug and cannot land on the bare apex, which boots the app
            for a signed-in visitor instead of showing the page. */}
        <a
          href={`${marketingHomeHref()}#downloads`}
          target="_blank"
          rel="noreferrer"
          className="text-[13px] font-medium px-3 py-1.5 rounded-md bg-accent-fill text-white hover:bg-accent-fill-hover transition mt-1"
        >
          {t('markdown.getDesktopApp')}
        </a>
      </div>
    );
  }

  // The same pitch the explainer shows, not a paraphrase of it: `MarkdownPitch`
  // owns the content, so one feature is described in one place and the wording
  // moves in one edit. This owns the two pickers underneath it.
  return (
    // `my-auto` on the child rather than `items-center` on the scroller: an
    // overflowing child of a centred flex container has its top edge pushed out
    // of reach, and this card is taller than a short window. Auto margins
    // collapse to zero once the content overflows, so it centres when it fits
    // and scrolls from the top when it does not.
    <div className="h-full overflow-y-auto flex flex-col px-6 py-10">
      <div className="w-full max-w-md mx-auto my-auto">
        <MarkdownPitch />
        {reopenName && (
          <div className="rounded-lg border border-divider bg-surface-1 p-3 mt-4">
            <p className="text-[12.5px] text-pn-soft mb-2">
              {t('markdown.reopenPrompt', { name: reopenName })}
            </p>
            <button
              type="button"
              onClick={onReopen}
              className="text-[13px] font-medium px-3 py-1.5 rounded-md bg-accent-fill text-white hover:bg-accent-fill-hover transition"
            >
              {t('markdown.reopenFolder', { name: reopenName })}
            </button>
          </div>
        )}
        {/* Two columns rather than a centred pair: these are the only actions on
            the screen, and equal halves make them read as one choice with two
            answers instead of a primary with an afterthought. */}
        <div className="grid grid-cols-2 gap-2 mt-4">
          <Button
            variant="primary"
            icon={<FolderOpen size={15} aria-hidden="true" className="shrink-0" />}
            onClick={onOpenFolder}
            className="w-full justify-center"
          >
            {busy ? t('markdown.scanning') : t('markdown.openFolder')}
          </Button>
          <Button
            icon={<FileText size={15} aria-hidden="true" className="shrink-0" />}
            onClick={onOpenFile}
            className="w-full justify-center"
          >
            {t('markdown.openFile')}
          </Button>
        </div>
        {error && <p className="text-[12px] text-danger mt-2 text-center">{error}</p>}
      </div>
    </div>
  );
}
