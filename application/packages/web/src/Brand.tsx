/**
 * The PrivacyNotes wordmark. This file is the ONLY place the two-tone markup
 * exists in the app; `check:house` fails on a hand-written copy of it.
 *
 * One weight and one pair of blues, because the wordmark is the logo set in
 * text: the mark beside it is Inter Bold 700, so both halves are bold and the
 * accent span carries color alone. Hand-written copies of the two spans drift
 * apart in weight, in accent class and in the catalog tag name used for the
 * "Notes" half.
 *
 * Spec: ops/docs/design-decisions.md (PrivacyNotes brand spelling)
 */

// The two brand blues are the app's own accent values. `accent` reads the live
// theme token, so the wordmark follows a custom color theme like every other
// accent in the app. The two ink tones cannot: the washi marketing slabs are
// not theme-scoped, and the light theme accent (#1E40AF) sits at about 1.9:1
// on ink. So they name the values the app's dark themes use.
const BRAND_BLUE_ON_INK = 'text-[#4A90D9]';
const BRAND_BLUE_ON_PAPER = 'dark:text-[#1E40AF]';

// Both halves are named per tone, never inherited. The ink half inheriting was
// the bug: on a muted paragraph the blue stayed full strength and the ink went
// grey, so the mark read as two colors of text rather than as one wordmark.
const TONE = {
  // The app, the admin console, the marketing pages, every paper ground.
  // `--brand-ink` resolves to the app ink, or to --wl-ink inside `.pn-washi`.
  accent: { ink: 'text-[var(--brand-ink)]', accent: 'text-accent' },
  // A permanently dark slab: the site footer.
  dark: { ink: 'text-white', accent: BRAND_BLUE_ON_INK },
  // A slab painted `bg-[var(--wl-ink)]`, which INVERTS to cream in dark mode
  // (Spec: ops/docs/design-decisions.md, washi landing palette). Both halves
  // have to invert with it.
  invert: { ink: 'text-[var(--wl-bg)]', accent: `${BRAND_BLUE_ON_INK} ${BRAND_BLUE_ON_PAPER}` },
} as const;

/**
 * @param tone   Which ground the wordmark sits on. Defaults to the theme accent.
 * @param suffix The display domain form, `.app`. Nothing else belongs here.
 */
export function Brand({ tone = 'accent', suffix = '' }: { tone?: keyof typeof TONE; suffix?: string }) {
  const { ink, accent } = TONE[tone];
  return (
    <span className={`font-bold ${ink}`}>
      <span className={accent}>Privacy</span>Notes{suffix}
    </span>
  );
}
