import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build, type Plugin } from 'vite';

// The static pages that search (the help center and the changelog) match with
// the app's own matcher, `textMatcher` in src/textMatch.ts, so a query folds
// there as it does in every list of the app. The build bundles that module
// into one same-origin script that sets `window.pnSearch`, and the pages load
// it before /static-pages.js. It is a file and not an inline script, because
// the pages run under `script-src 'self'`. Web build only, like the pages.
// Spec: ops/docs/design-decisions.md (search core)

const ENTRY = path.join(path.dirname(fileURLToPath(import.meta.url)), 'src/textMatch.ts');

export const SEARCH_CORE_SCRIPT_TAG = '<script src="/search-core.js" defer></script>';

/** The matcher as a classic script that defines the global `pnSearch`. */
export async function buildSearchCoreScript(): Promise<string> {
  const result = await build({
    configFile: false,
    logLevel: 'silent',
    publicDir: false,
    build: {
      write: false,
      minify: true,
      lib: { entry: ENTRY, formats: ['iife'], name: 'pnSearch', fileName: () => 'search-core.js' },
    },
  });
  for (const out of Array.isArray(result) ? result : [result]) {
    if (!('output' in out)) continue;
    const chunk = out.output.find((o) => o.type === 'chunk');
    if (chunk?.type === 'chunk') return chunk.code;
  }
  throw new Error('pn-search-core-script: the build produced no script');
}

export function searchCoreScriptPlugin(): Plugin {
  return {
    name: 'pn-search-core-script',
    configureServer(server) {
      server.middlewares.use('/search-core.js', (_req, res, next) => {
        buildSearchCoreScript().then((code) => {
          res.setHeader('Content-Type', 'text/javascript; charset=utf-8');
          res.end(code);
        }, next);
      });
    },
    async generateBundle() {
      this.emitFile({ type: 'asset', fileName: 'search-core.js', source: await buildSearchCoreScript() });
    },
  };
}
