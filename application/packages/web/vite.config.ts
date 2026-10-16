import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { changelogPagePlugin } from './changelog-page.ts';
import { PUBLIC_CHANGELOG } from './src/publicChangelog.ts';
import { helpPagePlugin } from './help-page.ts';
import { roadmapPagePlugin } from './roadmap-page.ts';
import { themesPagePlugin } from './themes-page.ts';
import { searchCoreScriptPlugin } from './search-core-script.ts';
import { brandPagePlugin } from './brand-page.ts';
import { marketingShellPlugin } from './marketing-shell.ts';
import { landingPagesPlugin } from './landing-pages.ts';
import { authConnectPagePlugin, authDesktopPagePlugin } from './auth-desktop-page.ts';
// @ts-expect-error - plain .mjs tool script, no types; this file is not type-checked
import { syncHelpChips } from '../../tools/sync-help-chips.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Tauri sets TAURI_DEV_HOST to the Mac's LAN IP when building for a
// physical iOS device so the iPhone can reach the Vite dev server over
// Wi-Fi. When that env var is set, bind Vite to 0.0.0.0 and expose HMR
// over the LAN too. For browser/macOS dev, leave the defaults alone.
const host = process.env.TAURI_DEV_HOST;

// The native apps embed the WHOLE dist directory (tauri.conf.json ->
// build.frontendDist), so every file the web build emits for search
// engines rides along in every DMG, AppImage, NSIS installer, APK and IPA.
// The static help + marketing site is 912 files / 46 MB of that, and the
// apps never open it: siteHref() sends every in-app Help, changelog and
// roadmap link to https://privacynotes.app in the system browser.
//
// TAURI_ENV_PLATFORM is exported by the Tauri CLI for beforeDevCommand and
// beforeBuildCommand, so it flags an app build on every platform without a
// shell prefix in tauri.conf.json (Windows CI runs that command through
// cmd, where `FOO=1 pnpm ...` is a syntax error). PN_APP_BUILD=1 forces
// the same path by hand; PN_WEB_BUILD=1 forces the site back in.
// Spec: ops/docs/bundle-size.md (static site out of the app payload)
const isAppBuild =
  process.env.PN_WEB_BUILD !== '1' &&
  (process.env.PN_APP_BUILD === '1' || !!process.env.TAURI_ENV_PLATFORM);

/**
 * Keeps the help chip's questions in step with the FAQ by itself.
 *
 * The chip renders a real /help question, and those get reworded for search.
 * `tools/sync-help-chips.mjs` copies them into the `helpQuestions` catalogs;
 * running it here means nobody has to remember to. `check:help-chips` still
 * guards CI, because the committed files are what ship.
 *
 * Runs for EVERY target, app builds included: the chip is in the app, and
 * unlike the marketing plugins below it is not web-only.
 *
 * Spec: ops/docs/help-center.md (section 9 - the in-app help chip)
 */
function syncHelpQuestions(): Plugin {
  return {
    name: 'sync-help-questions',
    buildStart() {
      syncHelpChips();
    },
    configureServer(server) {
      // Reword a question with the dev server up and the chip follows: the
      // rewritten catalog is itself watched, so HMR carries it the rest of
      // the way.
      server.watcher.on('change', (file) => {
        if (!file.endsWith('faq.json')) return;
        try {
          syncHelpChips();
        } catch (err) {
          server.config.logger.error(`sync-help-questions: ${(err as Error).message}`);
        }
      });
    },
  };
}

function readVersion(caller: string): string {
  const src = fs.readFileSync(path.resolve(__dirname, 'src/version.ts'), 'utf8');
  const m = src.match(/VERSION\s*=\s*['"]([^'"]+)['"]/);
  if (!m) throw new Error(`${caller}: could not parse VERSION from src/version.ts`);
  return m[1];
}

// Emit /version.json into the build output. The client polls this file
// to detect when a newer version has been deployed and prompts the user
// to refresh. Source of truth is `src/version.ts`.
function emitVersionJson(): Plugin {
  return {
    name: 'emit-version-json',
    apply: 'build',
    generateBundle() {
      this.emitFile({
        type: 'asset',
        fileName: 'version.json',
        source: JSON.stringify({ version: readVersion('emit-version-json') }),
      });
    },
  };
}

// Say out loud which of the two builds this is. The app build silently
// producing a web dist would put ~10 MB of static site back into every
// binary, and nothing else in the output would show it, so the one line in
// the CI log is the check.
function announceBuildTarget(): Plugin {
  return {
    name: 'pn-announce-build-target',
    apply: 'build',
    buildStart() {
      this.info(
        isAppBuild
          ? 'building for the native apps: skipping the static help + marketing site'
          : 'building for the web: including the static help + marketing site'
      );
    },
  };
}

// KaTeX declares every font three times in one @font-face src: woff2,
// then woff, then ttf. A browser only ever fetches the first format it
// understands, so the woff and ttf copies (798 KB) are downloaded by
// nobody and embedded in every native app. Our floor is macOS 11 / iOS 15
// and evergreen browsers, all of which read woff2. Drop the legacy pair
// before Vite resolves the url() references, so the files are never
// emitted in the first place.
// Spec: ops/docs/bundle-size.md (KaTeX fonts)
function katexWoff2Only(): Plugin {
  const LEGACY = /,url\(fonts\/[^)]+\.woff\) format\("woff"\),url\(fonts\/[^)]+\.ttf\) format\("truetype"\)/g;
  return {
    name: 'pn-katex-woff2-only',
    enforce: 'pre',
    apply: 'build',
    transform(code, id) {
      if (!id.includes('/katex/dist/katex.min.css')) return null;
      const out = code.replace(LEGACY, '');
      if (out.includes('truetype')) {
        throw new Error(
          'pn-katex-woff2-only: katex.min.css still declares a truetype source after the rewrite. ' +
            'KaTeX changed its @font-face shape - re-check this plugin before shipping.'
        );
      }
      return out === code ? null : out;
    },
  };
}

// Phosphor ships all six icon weights inside every icon's defs module and
// offers no import path that selects one, so 152 icons cost six weights
// each. We render exactly three: `bold` (the sitewide IconDefaults
// default), `fill` and `duotone`. `regular` stays as Phosphor's own
// fallback for anything rendered outside the provider. `thin` and `light`
// are unreachable - no prop, context value or expression in src/ can
// produce them - and they are a third of the icon payload.
//
// This rewrites a third-party module, so it validates the shape on every
// file and throws on a mismatch: a Phosphor bump that changes the defs
// format fails the build instead of silently rendering blank icons. Build
// only, so dev keeps the untouched library.
// Spec: ops/docs/bundle-size.md (Phosphor icon weights)
const PHOSPHOR_WEIGHTS = ['thin', 'light', 'regular', 'bold', 'fill', 'duotone'] as const;
const PHOSPHOR_DROP_WEIGHTS: readonly string[] = ['thin', 'light'];

function phosphorTrimWeights(): Plugin {
  return {
    name: 'pn-phosphor-trim-weights',
    enforce: 'pre',
    apply: 'build',
    transform(code, id) {
      if (!id.includes('@phosphor-icons/react') || !id.includes('/dist/defs/')) return null;
      const fail = (why: string) => {
        throw new Error(
          `pn-phosphor-trim-weights: ${why} in ${id}. ` +
            'Phosphor changed its defs format - re-check this plugin before shipping.'
        );
      };
      const shape = code.match(/^([\s\S]*?new Map\(\[\n)([\s\S]*)(\n\]\);[\s\S]*)$/);
      if (!shape) fail('no weights Map found');
      const [, head, body, tail] = shape!;
      const entries = body.split('\n  ],\n  [\n');
      const first = entries[0];
      const last = entries[entries.length - 1];
      if (!first?.startsWith('  [\n') || !last?.endsWith('\n  ]')) fail('unexpected Map entry framing');
      entries[0] = first!.slice('  [\n'.length);
      entries[entries.length - 1] = last!.slice(0, -'\n  ]'.length);
      const weights = entries.map((entry) => entry.split('"')[1] ?? '');
      const missing = PHOSPHOR_WEIGHTS.filter((w) => !weights.includes(w));
      if (missing.length || weights.length !== PHOSPHOR_WEIGHTS.length) {
        fail(`expected the six Phosphor weights, found [${weights.join(', ')}]`);
      }
      const kept = entries.filter((_, i) => !PHOSPHOR_DROP_WEIGHTS.includes(weights[i]!));
      return head + kept.map((entry) => `  [\n${entry}\n  ]`).join(',\n') + tail;
    },
  };
}

// The files under public/marketing/ (the homepage's live-demo screenshot),
// og-image.png (the social-share preview crawlers fetch from the
// canonical URL in index.html) and the Apple Pay domain association file
// (fetched once by Apple's servers to verify the deployed hosts for
// Paddle checkout) exist for the deployed site only. The native apps
// boot straight into the auth card and never render the marketing page,
// serve social previews or answer .well-known requests, so the files
// would be dead weight in every binary. Vite copies publicDir into
// dist/ after the bundle is written, so the app build removes them
// again in closeBundle.
// Spec: ops/docs/bundle-size.md (static site out of the app payload)
function stripMarketingAssets(): Plugin {
  return {
    name: 'pn-strip-marketing-assets',
    apply: 'build',
    closeBundle() {
      if (!isAppBuild) return;
      fs.rmSync(path.resolve(__dirname, 'dist/marketing'), { recursive: true, force: true });
      fs.rmSync(path.resolve(__dirname, 'dist/og-image.png'), { force: true });
      fs.rmSync(path.resolve(__dirname, 'dist/.well-known/apple-developer-merchantid-domain-association'), {
        force: true,
      });
    },
  };
}

// pdf.js decodes the JBIG2 and JPEG 2000 images that scanned PDFs are made of
// with WebAssembly, which our content security policy does not allow, so it
// falls back to two plain modules it imports by fixed name from its `wasmUrl`
// directory. Fixed names cannot go through the hashed asset pipeline: this
// copies them to pdfjs/<version>/ in the build and serves them there in dev.
// The version in the path keeps a new pdf.js from meeting a cached old decoder.
// Spec: packages/web/src/PdfPages.tsx (header)
const PDFJS_DECODERS = ['openjpeg_nowasm_fallback.js', 'jbig2_nowasm_fallback.js'];

function pdfjsDecoders(): Plugin {
  const pkgFile = path.resolve(__dirname, 'node_modules/pdfjs-dist/package.json');
  const sourceDir = path.join(path.dirname(fs.realpathSync(pkgFile)), 'wasm');
  const version = (JSON.parse(fs.readFileSync(pkgFile, 'utf8')) as { version: string }).version;
  const urlDir = `pdfjs/${version}/`;
  return {
    name: 'pn-pdfjs-decoders',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const pathname = (req.url ?? '').split('?')[0]!;
        const name = pathname.startsWith(`/${urlDir}`) ? pathname.slice(urlDir.length + 1) : '';
        if (!PDFJS_DECODERS.includes(name)) return next();
        res.setHeader('Content-Type', 'text/javascript');
        res.end(fs.readFileSync(path.join(sourceDir, name)));
      });
    },
    generateBundle() {
      for (const name of PDFJS_DECODERS) {
        this.emitFile({
          type: 'asset',
          fileName: `${urlDir}${name}`,
          source: fs.readFileSync(path.join(sourceDir, name)),
        });
      }
    },
  };
}

// The marketing homepage and the auth card live in the lazily imported
// Onboarding chunk: a signed-out visitor's first paint waits on the entry
// graph, and only then discovers and fetches that chunk, one extra
// network round trip on the mobile critical path (measured as most of the
// gap between a 3.6s and a faster first paint on throttled 4G). This
// injects <link rel="modulepreload"> tags for the Onboarding chunk and
// its direct imports into index.html, so the fetch starts with the
// document. Signed-in boots waste the preload (a few KiB, cache-hot on
// repeat visits); signed-out first visits, the ones that can convert,
// save a serial hop. Runs in app builds too, where preloading local
// files costs nothing. Placed BEFORE the static-site plugins in the
// array so the per-locale marketing shells capture the links as well.
function preloadOnboarding(): Plugin {
  return {
    name: 'pn-preload-onboarding',
    transformIndexHtml: {
      order: 'post',
      handler(html, ctx) {
        const bundle = ctx.bundle;
        if (!bundle) return html;
        const files = new Set<string>();
        for (const [file, chunk] of Object.entries(bundle)) {
          if (chunk.type === 'chunk' && chunk.facadeModuleId?.endsWith('src/Onboarding.tsx')) {
            files.add(file);
            for (const imp of chunk.imports) files.add(imp);
          }
        }
        if (!files.size) return html;
        const links = [...files]
          .map((f) => `<link rel="modulepreload" crossorigin href="/${f}">`)
          .join('');
        return html.replace('</head>', `${links}</head>`);
      },
    },
  };
}

// Vite's own chunk-size warning is a fixed 500 kB against RAW minified bytes.
// It knows nothing about gzip or the critical path, and it printed the same
// words at 2,872 kB and at 247 kB, so it was scrolled past while ~2.6 MB of
// eager locale JSON sat in the entry chunk for months. It is switched off
// (chunkSizeWarningLimit below) and replaced by pn-chunk-budgets.
//
// What pn-chunk-budgets defends is the boot path: the gzipped static-import
// closure of the entry chunk plus NotesView, which a first-time visitor
// downloads before the app renders. Two checks fail the build, and nothing else
// does:
//
// 1. A STEP: the boot path grew more than BOOT_PATH_STEP_KB since
//    bundle-baseline.json. That is the accident worth stopping, a heavy module
//    pulled onto the boot path by one static import.
// 2. A CEILING: the boot path crossed BOOT_PATH_CEILING_KB. That number is a
//    product decision taken by a person, never raised to finish a change.
//
// Ordinary growth passes. `pnpm preflight` rewrites the baseline after a
// passing build, so the committed file moves with every release and the slow
// creep is visible in its diff and in `pnpm health`, instead of stopping a
// build every few commits. A per-chunk ratchet just above today's size was
// tried first; it never stopped a byte and cost a round trip on most features.
//
// gzip level 9 is a fixed yardstick for comparing builds, not a prediction of
// what the CDN serves.
// Spec: ops/docs/bundle-size.md (section 6)
const BOOT_PATH_STEP_KB = 5;
const BOOT_PATH_CEILING_KB = 1400;

// Lazy chunks heavy enough to be worth naming in the baseline, so their drift
// is visible in review. They load on demand and do not count toward the boot
// path. Rolldown names a chunk after one of its modules, so if a name flips,
// the entry here has to follow it.
const TRACKED_LAZY_CHUNKS = ['heic-to', 'PdfPages', 'katex', 'EncryptedAttachment'];

// The deploy and the release builds only warn: they run after review, on the
// one build nobody can iterate on. WORKERS_CI and CF_PAGES are Cloudflare's;
// PN_BUDGETS_WARN=1 forces the same path by hand.
const isDeployBuild = Boolean(
  process.env.WORKERS_CI || process.env.CF_PAGES || process.env.PN_BUDGETS_WARN
);

// The baseline is stated in build-smoke's units: ubuntu, with the synthetic
// values from tools/ci-vite-env.mjs. Other builds measure lower, so the plugin
// adds the spread back before it compares and prints both numbers.
//
// 1.5 for the VITE_ values: emptying all of them moves 1.48 kB, because of what
// gzip does with a bundle full of identical empty strings.
const ENV_SPREAD_KB = 1.5;
// Per platform: macOS measures low and the gap grows with the bundle (3.76 at
// commit 5ac8b15e), so take the newest measurement and round up. Windows sits
// at ubuntu parity. A platform nobody has measured corrects by zero, because a
// guess that runs high fails builds for bytes that do not exist.
// Spec: ops/docs/bundle-size.md (section 6)
const PLATFORM_SPREAD_KB: Record<string, number> = {
  darwin: 3.8,
  win32: 0,
};

// PN_BUNDLE_RECORD=1 (set by `pnpm preflight`): check, then rewrite the
// baseline when the checks pass. PN_BUNDLE_BASELINE=1 (`pnpm bundle:baseline`):
// rewrite without checking, which is how a deliberate step is accepted.
const BASELINE_FILE = path.resolve(__dirname, 'bundle-baseline.json');
// Movers under this are not worth a line: the platform spread lands unevenly
// across chunks, so small deltas are environment, not code.
const BASELINE_NOISE_KB = 0.1;

type BundleBaseline = {
  version: string;
  measuredOn: { platform: string; envInlined: boolean };
  bootPathKb: number;
  bootPathCiKb: number;
  bootPathChunks: number;
  chunks: Record<string, number>;
};

function readBaseline(): BundleBaseline | null {
  try {
    return JSON.parse(fs.readFileSync(BASELINE_FILE, 'utf8')) as BundleBaseline;
  } catch {
    return null;
  }
}

/** `+0.41` / `-1.20`, so a list of movers reads without a legend. */
const signed = (kb: number) => `${kb >= 0 ? '+' : ''}${kb.toFixed(2)}`;

function chunkBudgets(): Plugin {
  // A build without the VITE_ values measures low, so it labels its number.
  let envInlined = true;
  return {
    name: 'pn-chunk-budgets',
    apply: 'build',
    configResolved(config) {
      envInlined = Boolean(config.env.VITE_SUPABASE_ANON_KEY && config.env.VITE_PADDLE_CLIENT_TOKEN);
    },
    generateBundle(_options, bundle) {
      const gzByFile = new Map<string, number>();
      const chunkByFile = new Map<
        string,
        { key: string; name: string; isEntry: boolean; imports: string[] }
      >();
      for (const [file, chunk] of Object.entries(bundle)) {
        if (chunk.type !== 'chunk') continue;
        // The entry is keyed on the flag, not the name, so a lazy chunk called
        // "index" is never mistaken for it.
        const key = chunk.isEntry
          ? '(entry)'
          : chunk.name || file.replace(/^assets\//, '').replace(/-[\w-]+\.js$/, '');
        gzByFile.set(file, zlib.gzipSync(chunk.code, { level: 9 }).length / 1000);
        chunkByFile.set(file, { key, name: chunk.name, isEntry: chunk.isEntry, imports: chunk.imports });
      }
      const stack = [...chunkByFile.entries()]
        .filter(([, chunk]) => chunk.isEntry || chunk.name === 'NotesView')
        .map(([file]) => file);
      const boot = new Set<string>();
      while (stack.length) {
        const file = stack.pop()!;
        if (boot.has(file) || !chunkByFile.has(file)) continue;
        boot.add(file);
        stack.push(...chunkByFile.get(file)!.imports);
      }
      let bootPathKb = 0;
      for (const file of boot) bootPathKb += gzByFile.get(file) ?? 0;

      const spread: string[] = [];
      let spreadKb = 0;
      if (!envInlined) {
        spreadKb += ENV_SPREAD_KB;
        spread.push('no VITE_ values inlined');
      }
      const platformSpreadKb = PLATFORM_SPREAD_KB[process.platform] ?? 0;
      if (platformSpreadKb > 0) {
        spreadKb += platformSpreadKb;
        spread.push(process.platform);
      }
      const gatedKb = bootPathKb + spreadKb;

      const current: Record<string, number> = {};
      for (const [file, chunk] of chunkByFile) {
        if (!boot.has(file) && !TRACKED_LAZY_CHUNKS.includes(chunk.key)) continue;
        current[chunk.key] = Number(((current[chunk.key] ?? 0) + (gzByFile.get(file) ?? 0)).toFixed(2));
      }

      const writeBaseline = () => {
        const written: BundleBaseline = {
          version: readVersion('pn-chunk-budgets'),
          measuredOn: { platform: process.platform, envInlined },
          bootPathKb: Number(bootPathKb.toFixed(2)),
          bootPathCiKb: Number(gatedKb.toFixed(2)),
          bootPathChunks: boot.size,
          chunks: Object.fromEntries(Object.entries(current).sort(([a], [b]) => a.localeCompare(b))),
        };
        fs.writeFileSync(BASELINE_FILE, `${JSON.stringify(written, null, 2)}\n`);
        this.info(`bundle-baseline.json rewritten at v${written.version}, boot path ${written.bootPathCiKb} kB.`);
      };

      const baseline = readBaseline();
      const step = baseline ? gatedKb - baseline.bootPathCiKb : 0;
      this.info(
        `boot path (static closure of entry + NotesView, ${boot.size} chunks): ` +
          `${bootPathKb.toFixed(2)} kB gzipped` +
          (spreadKb > 0
            ? `, ${gatedKb.toFixed(2)} as build-smoke measures it (+${spreadKb.toFixed(2)}: ${spread.join(', ')})`
            : '') +
          (baseline ? `, ${signed(step)} since baseline v${baseline.version} (step limit ${BOOT_PATH_STEP_KB})` : '') +
          `, ceiling ${BOOT_PATH_CEILING_KB}`
      );

      if (process.env.PN_BUNDLE_BASELINE) {
        writeBaseline();
        return;
      }

      let movers: string[] = [];
      if (!baseline) {
        this.warn(
          'pn-chunk-budgets: no bundle-baseline.json, so this build cannot measure a step. Run `pnpm bundle:baseline` to write one.'
        );
      } else {
        const moved = [...new Set([...Object.keys(current), ...Object.keys(baseline.chunks)])]
          .map((key) => ({ key, delta: (current[key] ?? 0) - (baseline.chunks[key] ?? 0) }))
          .filter((m) => Math.abs(m.delta) >= BASELINE_NOISE_KB)
          .sort((a, b) => b.delta - a.delta);
        movers = moved.slice(0, 6).map((m) => `${m.key} ${signed(m.delta)}`);
        if (moved.length > movers.length) movers.push(`${moved.length - movers.length} more`);
        if (movers.length > 0) this.info(`moved since baseline: ${movers.join(', ')}`);
      }

      const over: string[] = [];
      if (step > BOOT_PATH_STEP_KB) {
        over.push(
          `boot path grew ${step.toFixed(2)} kB in one step (limit ${BOOT_PATH_STEP_KB}). ` +
            `What moved: ${movers.join(', ') || 'see the list above'}. ` +
            'If a module landed on the boot path by accident, make its import dynamic. ' +
            'If the growth is wanted, accept it with `pnpm bundle:baseline` and say so in the commit message.'
        );
      }
      if (gatedKb > BOOT_PATH_CEILING_KB) {
        over.push(
          `boot path ${gatedKb.toFixed(2)} kB is over the ceiling of ${BOOT_PATH_CEILING_KB} kB. ` +
            'The ceiling is a product decision: ask the owner before raising BOOT_PATH_CEILING_KB, ' +
            'and look for code to move off the boot path first (ops/docs/bundle-size.md section 9).'
        );
      }

      if (over.length === 0) {
        if (process.env.PN_BUNDLE_RECORD) writeBaseline();
        return;
      }
      const report = `pn-chunk-budgets:\n${over.map((l) => `  ${l}`).join('\n')}`;
      if (isDeployBuild) {
        this.warn(`${report}\n\nNOT failing the deploy: build-smoke owns this gate.`);
        return;
      }
      throw new Error(report);
    },
  };
}

// pn-chunk-cycles: fail ANY build that emits a static import cycle between
// chunks - the deploy included. Rolldown groups a module by which entries
// reach it, so an unrelated commit can sever one module from its package and
// land it in a chunk that imports back into the one it left. A cycle between
// chunks is legal ESM, so the bundler emits it without a word and every other
// gate stays green - but module evaluation enters the cycle, one side runs
// against the other side's uninitialised bindings, and any top-level read
// across the boundary throws before first render. 2026-08-20: totp.ts was
// severed from the shared package, noble's SHA1 evaluated `class extends
// HashMD` against an import the cycle had not initialised, and the site
// shipped a white page for six hours across eight deploys. The advancedChunks
// pin in `build` below removed all 45 cycles then in the graph; the baseline
// is ZERO and this plugin keeps it there.
//
// Unlike pn-chunk-budgets above, there is NO deploy carve-out, deliberately:
// a budget is a review gate (size drift can be argued about), a cycle is an
// outage (the page does not boot). Failing the deploy build leaves the
// previous deployment live, which is exactly the wanted outcome. Do not
// harmonize the two. A red here means: fix the graph, usually by keeping the
// severed module with its package via advancedChunks - never silence the
// check. Spec: ops/docs/bundle-size.md (section 10, chunk cycle gate)
function chunkCycles(): Plugin {
  return {
    name: 'pn-chunk-cycles',
    apply: 'build',
    generateBundle(_options, bundle) {
      const imports = new Map<string, string[]>();
      const ownModules = new Map<string, string[]>();
      for (const [file, chunk] of Object.entries(bundle)) {
        if (chunk.type !== 'chunk') continue;
        imports.set(file, chunk.imports);
        // First-party modules name the feature that landed in the chunk;
        // vendor files are noise. moduleIds is guarded because it is not in
        // rolldown's typings contract, only in its rollup-compat surface.
        ownModules.set(
          file,
          (chunk.moduleIds ?? [])
            .filter((id) => !id.includes('node_modules'))
            .map((id) => path.basename(id))
        );
      }
      // Three-color depth-first walk over static imports only: dynamic
      // imports evaluate after the current graph settles, so they cannot
      // form an evaluation-time cycle.
      const color = new Map<string, 'gray' | 'black'>();
      const stack: string[] = [];
      const seen = new Set<string>();
      const cycles: string[][] = [];
      const visit = (file: string) => {
        color.set(file, 'gray');
        stack.push(file);
        for (const dep of imports.get(file) ?? []) {
          if (!imports.has(dep)) continue; // asset or external, not a chunk
          const c = color.get(dep);
          if (c === 'gray') {
            const cycle = stack.slice(stack.indexOf(dep));
            const key = [...cycle].sort().join('|');
            if (!seen.has(key)) {
              seen.add(key);
              cycles.push([...cycle, dep]);
            }
          } else if (c === undefined) {
            visit(dep);
          }
        }
        stack.pop();
        color.set(file, 'black');
      };
      for (const file of imports.keys()) if (!color.has(file)) visit(file);
      if (cycles.length === 0) return;
      const shown = cycles.slice(0, 8).map((cycle) => {
        const route = cycle.join('\n      -> ');
        const members = [...new Set(cycle)]
          .map((f) => {
            const own = ownModules.get(f) ?? [];
            if (own.length === 0) return null;
            const head = own.slice(0, 4).join(', ');
            return `    ${f} holds ${head}${own.length > 4 ? ` +${own.length - 4} more` : ''}`;
          })
          .filter(Boolean)
          .join('\n');
        return `  ${route}${members ? `\n${members}` : ''}`;
      });
      throw new Error(
        `pn-chunk-cycles: ${cycles.length} static import cycle(s) between chunks\n` +
          `${shown.join('\n')}\n` +
          (cycles.length > 8 ? `  ...and ${cycles.length - 8} more\n` : '') +
          '\nA cycle between chunks evaluates one side against the other side\'s ' +
          'uninitialised bindings and throws before first render (2026-08-20: a ' +
          'six-hour white page). Fix the graph - usually keep the severed module ' +
          'with its package via build.rollupOptions.output.advancedChunks - and ' +
          'never silence this check. Recipe: ops/docs/bundle-size.md section 10.'
      );
    },
  };
}

export default defineConfig({
  // The platform the app is being BUILT for, straight from Tauri's own build
  // environment, so the client never has to infer it from a user-agent
  // string. Empty for the web build. This exists because guessing was wrong:
  // an iPad's webview reports a Mac user agent, so detectPlatform() answered
  // 'desktop' there and the iPad got the desktop code paths - the system
  // browser for sign-in and the web checkout for Pro. App Review rejected
  // 0.491.2 on both counts (guideline 4 and 3.1.1, 2026-09-01) after passing
  // on iPhone, because only the iPad hit it.
  // Spec: ops/docs/gotchas.md (an iPad reports a Mac user agent)
  define: {
    __PN_BUILD_PLATFORM__: JSON.stringify(process.env.TAURI_ENV_PLATFORM ?? ''),
    // The About tab shows only the newest release and links to /changelog
    // for the rest, so the app bundle carries one entry, not the history.
    __PN_LATEST_RELEASE__: JSON.stringify((({ version, date, title }) => ({ version, date, title }))(PUBLIC_CHANGELOG[0])),
  },
  plugins: [
    react(),
    syncHelpQuestions(),
    emitVersionJson(),
    katexWoff2Only(),
    phosphorTrimWeights(),
    pdfjsDecoders(),
    // See isAppBuild above: the native apps embed dist/ wholesale, and the
    // static site is web-only.
    announceBuildTarget(),
    stripMarketingAssets(),
    preloadOnboarding(),
    ...(isAppBuild
      ? []
      : [changelogPagePlugin(), helpPagePlugin(), roadmapPagePlugin(), themesPagePlugin(), brandPagePlugin(), marketingShellPlugin(), landingPagesPlugin(), authDesktopPagePlugin(), authConnectPagePlugin(), searchCoreScriptPlugin()]),
    chunkBudgets(),
    chunkCycles(),
  ],
  resolve: {
    alias: {
      // @supabase/supabase-js instantiates a RealtimeClient in its own
      // constructor, so realtime (plus its @supabase/phoenix dependency)
      // would ship in the entry chunk even though nothing here calls
      // supabase.channel(). The stub keeps the constructor happy and
      // throws loudly the moment anything actually reaches for it.
      //
      // Do NOT re-add a storage-js stub. attachmentStore.ts, imageStore.ts
      // and NotesView.tsx hit supabase.storage.from('encrypted-images')
      // directly (no app file imports @supabase/storage-js by name -
      // supabase-js re-exports it, which is how it looked "unused").
      // 0.264.0 stubbed it and every attachment upload/download threw
      // until 0.267.2 (#202).
      // Spec: ops/docs/bundle-size.md (section 5)
      '@supabase/realtime-js': path.resolve(__dirname, 'stubs/realtime-js.js'),
    },
  },
  build: {
    // Vite 8 raised the default transpile target to Baseline Widely Available
    // 2026 (chrome111/safari16.4). Pin vite 7's effective default instead so
    // the bundler swap ships equivalent syntax; moving the floor itself
    // (macOS 11 / iOS 15 WKWebViews, bundle-size.md section 8) is a product
    // decision to take separately, not a side effect of a migration.
    target: ['chrome107', 'edge107', 'firefox104', 'safari16'],
    // Disable the module-preload polyfill - it's an inline script that
    // CSP blocks (script-src has no 'unsafe-inline'). All browsers we
    // support handle <link rel="modulepreload"> natively.
    modulePreload: { polyfill: false },
    // Retire Vite's generic 500 kB raw-bytes warning; pn-chunk-budgets above
    // replaces it with per-chunk gzip budgets that actually fail the build.
    chunkSizeWarningLimit: Infinity,
    rollupOptions: {
      output: {
        // Keep the shared package whole in one chunk. Rolldown groups a module
        // by which entries reach it, so a shared module reached from only one
        // pillar gets severed from the rest of the package - and shared's
        // barrel re-exports it, which puts an import edge BACK from the chunk
        // holding the barrel. That is a cycle between two chunks, and a cycle
        // is fatal the moment anything in it runs at module-evaluation time.
        // It shipped a white page: totp.ts landed alone in the Markdown pillar
        // chunk, dragging noble's legacy.js (sha1) with it while _md.js
        // (HashMD, its base class) stayed with crypto.ts, so `class SHA1
        // extends HashMD` evaluated against a binding the cycle had not
        // initialised yet - "Class extends value undefined is not a
        // constructor or null", thrown before first render.
        //
        // One group fixes both halves: totp.ts rejoins crypto.ts, so the
        // barrel has nothing to import back, and noble's hash modules follow
        // their importers into the same chunk instead of splitting across the
        // boundary. The group is a leaf by construction - shared imports only
        // vendor crypto and never app code - so it cannot form a new cycle.
        // Spec: ops/docs/bundle-size.md (chunk budgets)
        advancedChunks: {
          groups: [
            {
              name: 'shared',
              test: /[\\/](?:packages|node_modules)[\\/]shared[\\/]dist[\\/]/,
            },
          ],
        },
      },
    },
  },
  server: {
    port: 5173,
    strictPort: true,
    host: host || true,
    hmr: host
      ? {
          protocol: 'ws',
          host,
          port: 1421,
        }
      : undefined,
    proxy: {
      // worker.ts serves this from our own origin in production. Dev runs
      // no Worker, so point the same path upstream and the homepage badge
      // stays visible (and verifiable) locally.
      '/badge/privacytools.svg': {
        target: 'https://privacytools.io',
        changeOrigin: true,
        rewrite: () => '/badge/privacynotes/rating-light.svg',
      },
      // Anchored on the query, not the prefix: a bare '/favicon' key also
      // swallows the static /favicon.svg, /favicon.ico and /favicon-32.png
      // that index.html and the app's own rows ask for, and hands back
      // DuckDuckGo's 48px fallback instead. Only the lookup route carries
      // ?domain=, so only it is proxied.
      '^/favicon\\?': {
        target: 'https://icons.duckduckgo.com',
        changeOrigin: true,
        rewrite: (p) => {
          const domain = new URL(p, 'http://localhost').searchParams.get('domain');
          return `/ip3/${encodeURIComponent(domain || '')}.ico`;
        },
      },
    },
  },
});
