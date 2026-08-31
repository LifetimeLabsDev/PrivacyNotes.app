import { useTranslation } from 'react-i18next';
import type { ReactNode } from 'react';
import { PencilSimpleSlash, Shield, ClockCounterClockwise, Copy, Folder, Repeat } from '../icons';
import type { LocalNote } from '../db';
import { HoverLabel } from '../HoverLabel';
import { noteActionGuards, type NoteActionGuardDeps } from '../noteActionGuards';
import { proUnlocked } from '../demo';

/**
 * The per-note actions the editor header shows as bare icons once the
 * header row is wide enough to hold them.
 *
 * These same actions live in the "..." menu at every width, and they stay
 * there. That is the one deliberate difference from the menu's icon strip,
 * which appears only while the header hides burn, pin, share and trash: the
 * strip stands IN FOR a hidden row, so showing both would repeat it, while
 * this row is a shortcut to a menu the user may keep using exactly as
 * before. Nobody's habit breaks when the window gets wider.
 * Spec: ops/docs/ui-patterns.md (section 80)
 *
 * The markdown/formatted switch is deliberately NOT here. Its glyph is the
 * markdown logo, and the tag row one line below wears the same logo for the
 * formatting-bar toggle; two of them a row apart read as one control drawn
 * twice. It keeps its two existing homes, the word-count link and the first
 * row of the "..." menu.
 *
 * Order is by gate, not by menu order: the four Pro actions sit together,
 * then a hairline, then the two anyone can use. A reader who cannot use Pro
 * learns the whole left half in one look instead of hunting dots.
 *
 * Two tiers, because six icons do not fit every pane that fits four.
 * `NotesView.tsx` measures the header row and picks the tier.
 */
export type QuickActionsTier = 0 | 1 | 2;

type Props = {
  note: LocalNote;
  isPro: boolean;
  tier: QuickActionsTier;
  guards: NoteActionGuardDeps;
  onDuplicate: () => void;
  onConvertType?: () => void;
};

export function NoteQuickActions({
  note,
  isPro,
  tier,
  guards,
  onDuplicate,
  onConvertType,
}: Props) {
  const { t } = useTranslation('notes');
  if (tier === 0) return null;

  const act = noteActionGuards(guards);
  const canConvert = !!onConvertType && (note.type === 'note' || note.type === 'journal');

  return (
    <>
      <HeaderDivider />
      <div className="shrink-0 flex items-center gap-0.5">
        <QuickButton
          label={t('shell:noteOptionsMenu.readOnly')}
          onClick={act.toggleLock}
          active={note.locked === 1}
          pro={!isPro}
        >
          <PencilSimpleSlash size={18} aria-hidden="true" />
        </QuickButton>
        <QuickButton
          label={t('shell:noteOptionsMenu.protect')}
          onClick={act.toggleProtect}
          active={note.pinProtected === 1}
          pro={!isPro}
        >
          <Shield size={18} weight={note.pinProtected === 1 ? 'fill' : undefined} aria-hidden="true" />
        </QuickButton>
        {guards.onMoveToFolder && (
          <QuickButton
            label={t('shell:noteOptionsMenu.moveToFolder')}
            onClick={act.moveToFolder}
            pro={!isPro}
          >
            <Folder size={18} aria-hidden="true" />
          </QuickButton>
        )}
        <QuickButton
          label={t('shell:noteOptionsMenu.noteHistory')}
          onClick={act.openHistory}
          pro={!isPro}
          disabled={proUnlocked(isPro) && !guards.onOpenHistory}
        >
          <ClockCounterClockwise size={18} aria-hidden="true" />
        </QuickButton>
      </div>

      {tier === 2 && (
        <>
          <HeaderDivider />
          <div className="shrink-0 flex items-center gap-0.5">
            <QuickButton label={t('shell:noteOptionsMenu.duplicate')} onClick={onDuplicate}>
              <Copy size={18} aria-hidden="true" />
            </QuickButton>
            {canConvert && (
              <QuickButton
                label={note.type === 'note'
                  ? t('shell:noteOptionsMenu.convertToJournal')
                  : t('shell:noteOptionsMenu.convertToNote')}
                onClick={onConvertType}
              >
                <Repeat size={18} aria-hidden="true" />
              </QuickButton>
            )}
          </div>
        </>
      )}
    </>
  );
}

/**
 * The hairline between two groups of header icons. It is what tells the
 * groups apart now that nothing in this row wears a filled container:
 * one button style, one separator, and colour left to mean state.
 * Decorative, so it is hidden from the accessibility tree - every button
 * already names itself, and a rule announced between them is noise.
 */
export function HeaderDivider() {
  return <span aria-hidden="true" className="shrink-0 mx-1 h-4 w-px bg-neutral-300 dark:bg-neutral-700" />;
}

/** One 32px square. Every button in the editor header wears this box. */
function QuickButton({
  label,
  onClick,
  children,
  active,
  pro,
  disabled,
}: {
  label: string;
  onClick: () => void;
  children: ReactNode;
  active?: boolean;
  /** Pro-gated for this user. Marked with a corner dot, not a badge. */
  pro?: boolean;
  disabled?: boolean;
}) {
  return (
    <HoverLabel label={label} position="below">
      <button
        type="button"
        onClick={onClick}
        disabled={disabled}
        aria-label={label}
        aria-pressed={active}
        className={`relative shrink-0 flex items-center justify-center w-8 h-8 rounded-md transition disabled:opacity-40 disabled:cursor-not-allowed ${
          active
            ? 'text-accent bg-accent/15'
            : 'text-neutral-600 dark:text-neutral-300 [@media(hover:hover)]:hover:text-accent [@media(hover:hover)]:hover:bg-neutral-200 [@media(hover:hover)]:dark:hover:bg-neutral-800 active:scale-95'
        }`}
      >
        {children}
        {/* The menu's "Pro" word badge has no room next to a bare glyph, so
            the gate is a corner dot in the same amber the upgrade surfaces
            use. It marks the feature, it does not block the click: the
            action opens the upgrade modal instead of applying. */}
        {pro && (
          <span
            aria-hidden="true"
            className="absolute top-1 end-1 h-1.5 w-1.5 rounded-full bg-amber-500"
          />
        )}
      </button>
    </HoverLabel>
  );
}
