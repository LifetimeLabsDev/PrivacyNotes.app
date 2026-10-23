// The file name of a theme's screenshot: its name as a slug and the first
// ten hex digits of the SHA-256 of its code. Shared by themes-page.ts, which
// refuses a card without one, and the screenshot script that writes them.
import { createHash } from 'node:crypto';

/** Under packages/web/public. */
export const THEME_SHOT_DIR = 'marketing/themes';

export function themeShotFile(code) {
  const name = code.split(':')[1] ?? '';
  const slug = name.toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'theme';
  const hash = createHash('sha256').update(code).digest('hex').slice(0, 10);
  return `${slug}-${hash}.webp`;
}
