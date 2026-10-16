import { Trans, useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { HoverLabel } from './HoverLabel';
import { ProGlyph } from './UpgradeModal';
import { Briefcase, House, Stack, type Icon } from './icons';
import type { Space, SpaceView } from './spaces';

/** The one glyph of each space, wherever a space is named: the switch, the
 *  move rows, the folder picker, the calendar. A house, not a person: the
 *  person glyph is a contact's and the account's. */
export const SPACE_ICONS: Record<Space, Icon> = { personal: House, work: Briefcase };

const MOVE_KEY: Record<Space, string> = { personal: 'shell:spaces.moveToPersonal', work: 'shell:spaces.moveToWork' };

/** "Move to Work" with the space's name in bold, for every menu row that
 *  moves an item or a folder to the other space. */
export function SpaceMoveLabel({ to }: { to: Space }) {
  return <Trans i18nKey={MOVE_KEY[to]} components={{ b: <b className="font-semibold" /> }} />;
}

/** The same words as plain text, where only a string fits (a title). */
export function spaceMoveText(t: TFunction, to: Space): string {
  return t(MOVE_KEY[to]).replace(/<\/?b>/g, '');
}

// All comes first: it is the whole library, and the one segment a free
// account can open.
const VIEWS: readonly { key: SpaceView; icon: Icon; label: 'spaces.all' | 'spaces.personal' | 'spaces.work' }[] = [
  { key: 'all', icon: Stack, label: 'spaces.all' },
  { key: 'personal', icon: SPACE_ICONS.personal, label: 'spaces.personal' },
  { key: 'work', icon: SPACE_ICONS.work, label: 'spaces.work' },
];

/**
 * The space switch: All, Personal and Work on a track, one click each. The
 * track takes the Jump button's tint, so the two read as one row. Open Work
 * takes the accent fill; the open segment shows its name in a sidebar wide
 * enough, otherwise icons with a tooltip in the sidebar, a column on the
 * collapsed rail, and icons with their names in the drawer. `locked` marks
 * Personal and Work as Pro: on a free account, where the parent's `onChange`
 * opens the upgrade window, and in the demo, where both open. Both tips and
 * labels say Pro, but only Work wears the rocket: two rockets side by side
 * crowd a three-segment track. `noAll` leaves All out on a free account,
 * where it is the only view and a click on it does nothing: Personal and
 * Work then stand unpressed, two ways into the upgrade window.
 * Spec: ops/docs/plans/spaces.md (section 6)
 */
export function SpaceSwitch({
  active,
  onChange,
  vertical = false,
  locked = false,
  noAll = false,
  stretch = false,
}: {
  active: SpaceView;
  onChange: (view: SpaceView) => void;
  vertical?: boolean;
  /** Not Pro: Personal and Work carry the Pro mark. */
  locked?: boolean;
  noAll?: boolean;
  /** Fill the row, the segments sharing it, as beside the Jump icon. */
  stretch?: boolean;
}) {
  const { t } = useTranslation('shell');
  return (
    <div
      role="group"
      aria-label={t('spaces.label')}
      className={`flex gap-0.5 rounded-md bg-accent/10 p-0.5 ${vertical ? 'flex-col' : ''} ${stretch ? 'pn-browse pn-browse-roomy flex-1 min-w-0' : 'shrink-0'}`}
    >
      {VIEWS.filter((v) => !noAll || v.key !== 'all').map(({ key, icon: SpaceIcon, label }) => {
        const on = active === key;
        // Open Work takes the New button's fill, so the space that hides the
        // personal items reads at a glance; All and Personal stay quiet.
        const look = `flex items-center justify-center gap-1.5 rounded transition focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent/40 ${
          on
            ? key === 'work' ? 'bg-accent-fill text-white' : 'bg-surface-2 text-accent-strong'
            : 'text-accent-strong/60 hover:text-accent-strong hover:bg-surface-2/60'
        }`;
        // Outline while closed, solid while open: the state reads without color.
        const glyph = <SpaceIcon size={16} weight={on ? 'fill' : 'regular'} aria-hidden="true" />;
        const pro = locked && key !== 'all';
        return (
          // Stretched (beside Jump, and full width in the drawer) the switch
          // works as the Tags and Folders switch does (pn-browse in
          // index.css): the open space shows its name, a closed one shows it
          // on hover, and a sidebar too narrow for names gets tips. Stacked in
          // the collapsed rail it is icons and tips.
          <HoverLabel key={key} label={t(label)} pro={pro} position={vertical ? 'end' : 'below'} className={stretch ? `pn-sb-tip-roomy pn-browse-seg${on ? ' is-open' : ''}` : undefined}>
            <button type="button" onClick={() => onChange(key)} aria-pressed={on} aria-label={pro ? `${t(label)} (Pro)` : t(label)} className={`${look} min-w-8 h-7 ${stretch ? 'group w-full min-w-0 gap-0 px-1.5' : ''}`}>
              <ProGlyph pro={pro && key === 'work'}>{glyph}</ProGlyph>
              {stretch && (
                <span aria-hidden="true" className="pn-sb-roomy pn-browse-name">
                  <span className="text-[13px] font-semibold">{t(label)}</span>
                </span>
              )}
            </button>
          </HoverLabel>
        );
      })}
    </div>
  );
}
