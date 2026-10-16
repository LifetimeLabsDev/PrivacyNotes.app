import { useTranslation } from 'react-i18next';
import { CaretUp, CaretDown, Swap } from './icons';
import { HoverLabel } from './HoverLabel';
import { ProGlyph } from './UpgradeModal';

/**
 * Button style shared by every icon control in the find and replace bars.
 * One string, so the two bars cannot drift apart by a shade.
 */
export const BAR_BTN =
  'flex items-center justify-center w-7 h-7 rounded text-pn-soft ' +
  '[@media(hover:hover)]:hover:bg-pn/10 ' +
  'disabled:opacity-40 disabled:cursor-not-allowed active:scale-95 transition shrink-0 outline-none';

/** Text buttons (Replace, All): the icon button's style at a label's width. */
export const TEXT_BTN =
  'flex items-center justify-center h-7 px-2 rounded text-xs font-medium text-pn-soft ' +
  '[@media(hover:hover)]:hover:bg-pn/10 ' +
  'disabled:opacity-40 disabled:cursor-not-allowed active:scale-95 transition shrink-0 outline-none';

/** The search and replacement fields of the replace bars. */
export const BAR_INPUT =
  'flex-1 min-w-0 bg-transparent text-sm text-pn ' +
  'placeholder:text-pn-muted outline-none px-1';

type Props = {
  /** Text in the count slot: "2/7", "0/0", a status line, or nothing. */
  count: string;
  /** Paint the count red: a query with nothing found. */
  noHits: boolean;
  canStep: boolean;
  onStep: (dir: 1 | -1) => void;
};

/**
 * The match count and the previous/next arrows, as both bars render them.
 * The buttons swallow mousedown so a click never takes focus away from the
 * input the reader is typing in.
 */
export function MatchNav({ count, noHits, canStep, onStep }: Props) {
  const { t } = useTranslation('editor');
  return (
    <>
      <span
        className={`min-w-[3.5ch] text-center text-xs tabular-nums shrink-0 ${
          noHits ? 'text-danger' : 'text-pn-muted'
        }`}
      >
        {count}
      </span>
      <HoverLabel label={t('find.previousTitle')} position="below">
        <button
          type="button"
          onMouseDown={(e) => e.preventDefault()}
          onClick={() => onStep(-1)}
          disabled={!canStep}
          aria-label={t('find.previous')}
          className={BAR_BTN}
        >
          <CaretUp size={15} />
        </button>
      </HoverLabel>
      <HoverLabel label={t('find.nextTitle')} position="below">
        <button
          type="button"
          onMouseDown={(e) => e.preventDefault()}
          onClick={() => onStep(1)}
          disabled={!canStep}
          aria-label={t('find.next')}
          className={BAR_BTN}
        >
          <CaretDown size={15} />
        </button>
      </HoverLabel>
    </>
  );
}

/**
 * The button that grows the find bar into the replace bar and shrinks it
 * back, in the find row of every bar. The parent carries the search term
 * across and gates the replace half on Pro and on an editable note, so a
 * read-only note never renders this. `pro` puts the rocket on the glyph for
 * a free account, keyed off `!isPro` like every Pro mark.
 */
export function ReplaceToggle({ open, pro, onClick }: { open: boolean; pro: boolean; onClick: () => void }) {
  const { t } = useTranslation('editor');
  const label = open ? t('find.hideReplace') : t('find.showReplace');
  return (
    <HoverLabel label={label} position="below">
      <button
        type="button"
        onMouseDown={(e) => e.preventDefault()}
        onClick={onClick}
        aria-pressed={open}
        aria-label={label}
        className={`${BAR_BTN}${open ? ' bg-pn/10 text-accent' : ''}`}
      >
        <ProGlyph pro={pro}>
          <Swap size={15} />
        </ProGlyph>
      </button>
    </HoverLabel>
  );
}
