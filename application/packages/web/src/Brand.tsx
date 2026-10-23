/**
 * The PrivacyNotes wordmark. This file is the ONLY place the two-tone markup
 * exists in the app; `check:house` fails on a hand-written copy of it.
 *
 * One weight and one blue, because the wordmark is the logo set in text: the
 * mark beside it is Inter Bold 700, so both halves are bold and the blue span
 * carries color alone. Hand-written copies of the two spans drift apart in
 * weight, in blue and in the catalog tag name used for the "Notes" half.
 *
 * Spec: ops/docs/design-decisions.md (PrivacyNotes brand spelling)
 */

// Fold Blue, the blue of the logo files, on every ground. The one exception is
// the sidebar brand button in a palette other than Default, which tints it
// with the accent until hovered (`pn-brand-blue` and `.pn-logo-host` in
// index.css).
// theme-ok: the wordmark is one fixed blue in every palette
const BRAND_BLUE = 'text-[#4F6BD5] pn-brand-blue';

// Both halves are named per tone, never inherited. The ink half inheriting was
// the bug: on a muted paragraph the blue stayed full strength and the ink went
// grey, so the mark read as two colors of text rather than as one wordmark.
const TONE = {
  // The app, the admin console, the marketing pages, every paper ground.
  // `--brand-ink` resolves to the app ink, or to --wl-ink inside `.pn-washi`.
  paper: 'text-[var(--brand-ink)]',
  // A permanently dark slab: the site footer.
  dark: 'text-white',
  // A homepage slab painted `bg-[var(--wl-slab)]`: ink in light, a raised
  // sumi surface in dark (Spec: ops/docs/design-decisions.md, washi landing
  // palette). The ink half takes the slab's text color.
  invert: 'text-[var(--wl-on-slab)]',
} as const;

/**
 * @param tone   Which ground the wordmark sits on. Defaults to paper.
 * @param suffix The display domain form, `.app`. Nothing else belongs here.
 */
export function Brand({ tone = 'paper', suffix = '' }: { tone?: keyof typeof TONE; suffix?: string }) {
  return (
    <span className={`font-bold ${TONE[tone]}`}>
      <span className={BRAND_BLUE}>Privacy</span>Notes{suffix}
    </span>
  );
}
