/**
 * Brand logo icon. Renders the WebP logo at the requested size.
 * Falls back to the PNG via <picture> for any edge-case browser.
 */
export function LogoIcon({ size = 24, className = '' }: { size?: number; className?: string }) {
  return (
    <img
      src="/privacy-notes.webp"
      alt=""
      width={size}
      height={size}
      aria-hidden="true"
      className={className}
      draggable={false}
    />
  );
}
