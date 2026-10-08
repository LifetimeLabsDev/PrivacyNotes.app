/**
 * The Swiss flag as an inline SVG, never as the U+1F1E8 U+1F1ED emoji pair.
 * WebKitGTK draws color emoji through Skia's COLRv1 path, and with the
 * gradient flags of a current Noto Color Emoji that path fails an assertion
 * and kills the web process, which freezes the whole Linux window.
 * Spec: ops/docs/gotchas.md (color emoji freeze the Linux app)
 */
export function SwissFlag() {
  return (
    <svg
      viewBox="0 0 32 32"
      width="1em"
      height="1em"
      aria-hidden="true"
      className="inline-block shrink-0 align-[-0.125em]"
    >
      <rect width="32" height="32" rx="4" fill="#DA291C" />
      <path fill="#fff" d="M13 6h6v7h7v6h-7v7h-6v-7H6v-6h7z" />
    </svg>
  );
}
