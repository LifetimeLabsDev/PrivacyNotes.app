/**
 * The "an update is waiting" dot, shared by the two rails that can show it:
 * the expanded sidebar's Downloads action (TagsRail) and the collapsed rail,
 * where it rides the Downloads link that replaces Help while an update is
 * outstanding. Same mark in both, so the two cannot drift.
 *
 * The parent must be `relative`; the dot is absolute so it never touches the
 * rails' width math. The ring knocks the dot out of the glyph beneath it,
 * which is what keeps an 8px mark legible on a 16px icon - pass the ring
 * colour of the surface it sits on (surface-1 in the sidebar, surface-0 in
 * the collapsed rail), or the halo reads as a smudge.
 *
 * Spec: ops/docs/ui-patterns.md (section 46 - update dot)
 */
export function UpdateDot({ ring = 'ring-surface-1' }: { ring?: string }) {
  return (
    <span
      aria-hidden="true"
      className={`absolute -top-0.5 -end-0.5 w-2 h-2 rounded-full bg-accent ring-2 ${ring}`}
    />
  );
}
