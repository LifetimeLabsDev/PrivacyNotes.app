import { useTranslation } from 'react-i18next';
import { HoverLabel } from './HoverLabel';
import { IconUpgrade } from './UpgradeModal';
import { Briefcase, User, type Icon } from './icons';
import type { Space } from './spaces';

const SPACES: readonly { key: Space; icon: Icon; label: 'spaces.personal' | 'spaces.work' }[] = [
  { key: 'personal', icon: User, label: 'spaces.personal' },
  { key: 'work', icon: Briefcase, label: 'spaces.work' },
];

/**
 * The Personal and Work switch: two icons on a track, one click each. The
 * track takes the Jump to button's tint, so the two read as one row. Icons
 * with a tooltip in the sidebar, a column on the collapsed rail, and icons
 * with their names in the drawer. On a free account (`locked`) Work carries
 * the Pro rocket, and a click on it opens the upgrade window.
 * Spec: ops/docs/plans/spaces.md (section 6)
 */
export function SpaceSwitch({
  active,
  onChange,
  vertical = false,
  labeled = false,
  locked = false,
}: {
  active: Space;
  onChange: (space: Space) => void;
  vertical?: boolean;
  /** Full width, each icon with its name. */
  labeled?: boolean;
  /** Free account: Work is a Pro door. */
  locked?: boolean;
}) {
  const { t } = useTranslation('shell');
  return (
    <div
      role="group"
      aria-label={t('spaces.label')}
      className={`shrink-0 flex gap-0.5 rounded-md bg-accent/10 p-0.5 ${vertical ? 'flex-col' : ''} ${labeled ? 'w-full' : ''}`}
    >
      {SPACES.map(({ key, icon: SpaceIcon, label }) => {
        const on = active === key;
        const look = `flex items-center justify-center gap-1.5 rounded transition focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 ${
          on ? 'bg-surface-2 text-accent-strong' : 'text-accent-strong/60 hover:text-accent-strong'
        }`;
        const glyph = <SpaceIcon size={16} weight="duotone" aria-hidden="true" />;
        const pro = locked && key === 'work';
        return labeled ? (
          <button key={key} type="button" onClick={() => onChange(key)} aria-pressed={on} className={`${look} flex-1 h-8 text-[13px] font-semibold`}>
            {glyph}
            {t(label)}
            {pro && <IconUpgrade size={12} />}
          </button>
        ) : (
          <HoverLabel key={key} label={t(label)} pro={pro} position={vertical ? 'end' : 'below'}>
            <button type="button" onClick={() => onChange(key)} aria-pressed={on} aria-label={pro ? `${t(label)} (Pro)` : t(label)} className={`${look} relative w-8 h-7`}>
              {pro ? (
                <>
                  {/* The briefcase moves back so the rocket fits in
                      the corner without widening the segment. */}
                  <span className="flex -translate-x-1 rtl:translate-x-1">{glyph}</span>
                  <span className="absolute end-0.5 bottom-0.5 flex"><IconUpgrade size={10} /></span>
                </>
              ) : glyph}
            </button>
          </HoverLabel>
        );
      })}
    </div>
  );
}
