// The Ninja mark: a round face with an eye slit and a bandana whose tails fly
// back. Phosphor has no ninja, so it is drawn here, on Phosphor's 24-unit
// grid, and takes Phosphor's `size` prop.
//
// Two looks, like the logo (index.css, `.pn-ninja`):
// - `theme` (the app): one ink in the theme's accent, the eye slit cut out in
//   the surface color, the bandana a lighter wash of the same ink, so the mark
//   sits in every palette. A pointer over its button (`.pn-jump`) shows the
//   real colors; a custom theme whose code says logo=original keeps them.
// - `real` (the homepage): the real colors always: an ink face, a cream eye
//   slit and the site's amber bandana (#F59E0B), with a light rim in a dark
//   theme so the face does not vanish on a dark surface.
// Used for Ninja, the ⌘K box: the sidebar button, the collapsed rail, the
// list header below lg and the homepage tile.
// Spec: ops/design/patterns/145-150.md section 145

/** The key's memory trick: ⌘K, K for Katana. English in every language on
 *  purpose (owner, 2026-10-23): the K is the key's letter, so a translation
 *  would lose the joke. Never move it into a catalog. */
export const KATANA_LINE = 'K for Katana';

export function NinjaIcon({ size = 16, tone = 'theme', className }: { size?: number; tone?: 'theme' | 'real'; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true" className={`pn-ninja${tone === 'real' ? ' pn-ninja-real' : ''}${className ? ` ${className}` : ''}`}>
      <path className="nj-band" d="M4.2 8.4C2.6 7.2 1.2 7.8.6 9.4c1.3-.5 2.3-.2 3.3.5z" />
      <path className="nj-band" d="M4.3 9.6C2.9 9.8 1.9 11 2 12.6c.9-1 1.9-1.4 2.8-1.4z" />
      <circle className="nj-face" cx="12.5" cy="13" r="9" strokeWidth="1" />
      <path className="nj-band" d="M3.6 8.2 21 6.9l.5 3.1L4 11.4z" />
      <rect className="nj-slit" x="6.3" y="11.6" width="12.4" height="4.6" rx="2.3" />
      <circle className="nj-eye" cx="10.2" cy="13.9" r="1.35" />
      <circle className="nj-eye" cx="14.8" cy="13.9" r="1.35" />
      {/* The catchlights read from about 24 px up; smaller, they are a blur. */}
      {size >= 24 && (
        <>
          <circle className="nj-glint" cx="10.6" cy="13.5" r=".4" />
          <circle className="nj-glint" cx="15.2" cy="13.5" r=".4" />
        </>
      )}
    </svg>
  );
}
