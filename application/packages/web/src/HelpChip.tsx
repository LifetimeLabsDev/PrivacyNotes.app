import { useTranslation } from 'react-i18next';
import { BookOpenText } from './icons';
import { activeLocale } from './languages';
import { helpPath } from './localeRoutes';
import { siteHref } from './siteLinks';
import SURFACES from './helpChips.json';

/**
 * A link out of a modal to the /help entry that answers the question this
 * screen raises. Sits under the intro line and above the first section,
 * never in the footer and never between rows.
 *
 * It shows the REAL FAQ question, because that is the payload: the question
 * is written the way a reader types it into a search box. A short category
 * label ("Backup strategy") throws that away.
 *
 * `helpQuestions` is a GENERATED namespace: tools/sync-help-chips.mjs copies
 * the linked questions out of faq.json, which is 1.4 MB across the locales
 * and stays out of the bundle (i18n.ts, ops/docs/bundle-size.md). Riding the
 * normal catalog pipeline rather than a private loader is what keeps it
 * cheap: a separate module tree with its own glob measured 2.32 kB gzipped
 * on the boot path, against roughly 0.2 kB here. `pnpm check:help-chips`
 * fails the build when a copy drifts.
 *
 * Two questions is the maximum. A modal that needs three is doing three
 * jobs, and the chip is not the place to paper over that.
 *
 * Sibling pattern: the guide rail on an importer row (ImportModal), which
 * carries the same mark. Rail means "a guide for THIS ROW", chip means "a
 * page for THIS SCREEN".
 *
 * Spec: ops/docs/help-center.md (section 9 - the in-app help chip)
 */
export function HelpChip({
  surface,
  className,
  columns = 1,
}: {
  surface: keyof typeof SURFACES;
  /** Layout-only classes (spacing), e.g. "mb-3". */
  className?: string;
  /** Two side by side, for a wide surface with room for it (the sign-in
   *  screen). One per line everywhere else: a settings pane is about 400px
   *  wide and a real question wraps there. Below sm the two columns fold
   *  into one, and there the questions align to the start: centring them
   *  reads as misalignment, because a question that wraps fills the line
   *  while a short one sits indented next to it. */
  columns?: 1 | 2;
}) {
  const { t } = useTranslation('helpQuestions');
  const locale = activeLocale();

  return (
    <div
      className={`${
        columns === 2
          ? 'grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1.5 justify-items-start sm:justify-items-center'
          : 'flex flex-col items-start gap-1.5'
      }${className ? ` ${className}` : ''}`}
    >
      {SURFACES[surface].map((id) => (
        <a
          key={id}
          href={siteHref(`${helpPath(locale)}/${id}`)}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-start gap-2 max-w-full text-[13px] text-accent hover:underline"
        >
          {/* Centred inside a 20px box, which is the text's own line height.
              `mt-px` guessed at it and left the mark riding high above the
              first line whenever the question wrapped. */}
          <span className="flex h-5 shrink-0 items-center">
            <BookOpenText size={15} aria-hidden="true" />
          </span>
          {/* No new-tab arrow. It orphaned onto a line of its own whenever the
              question's last line ended near the wrap point, and neither
              placement cured that: beside the text it sat on line one while
              the question wrapped under it, and inline it merely narrowed the
              failure to a band of container widths about 17px wide. The band
              sits wherever a question happens to end, so it moves with the
              translation - measured on the downloads question at 318-334px in
              English, 328-344px in German and 332-348px in French - which
              makes "does this surface orphan" a question with a different
              answer per locale, per surface. Nothing is lost by dropping it:
              the book mark already says "this is a help link", and the link
              still opens in a new tab. */}
          <span>{t(id)}</span>
        </a>
      ))}
    </div>
  );
}
