import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Plugin } from 'vite';
import { buildClassicScript } from './search-core-script.ts';

// The static pages' footer ends on the app's typewriter line. The build
// bundles src/footerLines.ts (with the shared engine in src/typewriter.ts)
// into one same-origin script, which siteFooterFor() in static-page-chrome.ts
// loads with FOOTER_LINES_SCRIPT_TAG; run that way, the module starts the
// lines itself. A file and not an inline script, because the
// pages run under `script-src 'self'`. Web build only, like the pages.

const ENTRY = path.join(path.dirname(fileURLToPath(import.meta.url)), 'src/footerLines.ts');

export function footerLinesScriptPlugin(): Plugin {
  const code = () => buildClassicScript(ENTRY, 'pnFooterLines', 'footer-lines.js');
  return {
    name: 'pn-footer-lines-script',
    configureServer(server) {
      server.middlewares.use('/footer-lines.js', (_req, res, next) => {
        code().then((js) => {
          res.setHeader('Content-Type', 'text/javascript; charset=utf-8');
          res.end(js);
        }, next);
      });
    },
    async generateBundle() {
      this.emitFile({ type: 'asset', fileName: 'footer-lines.js', source: await code() });
    },
  };
}
