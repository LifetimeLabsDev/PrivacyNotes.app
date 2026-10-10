/**
 * Brand logo icon. Renders the WebP logo at the requested size.
 *
 * `tint` lays the theme accent over the mark in every palette but Default
 * (`--pn-logo-tint` in index.css): a layer cut
 * to the logo's own shape, blended in `color` mode, so the mark keeps its
 * light and dark parts and takes the accent's hue. Hovering the nearest
 * `.pn-logo-host` shows the real colors. Spec: ops/docs/color-themes.md (section 6)
 */
export function LogoIcon({ size = 24, className = '', tint = false }: { size?: number; className?: string; tint?: boolean }) {
  const img = (
    <img
      src="/privacy-notes.webp"
      alt=""
      width={size}
      height={size}
      aria-hidden="true"
      className={tint ? undefined : className}
      draggable={false}
    />
  );
  if (!tint) return img;
  return (
    <span className={`pn-logo relative inline-flex shrink-0 ${className}`} style={{ width: size, height: size }}>
      {img}
      <span className="pn-logo-tint" aria-hidden="true" />
    </span>
  );
}
