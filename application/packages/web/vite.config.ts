import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { changelogPagePlugin } from './changelog-page.ts';
import { helpPagePlugin } from './help-page.ts';
import { roadmapPagePlugin } from './roadmap-page.ts';
import { brandPagePlugin } from './brand-page.ts';
import { marketingShellPlugin } from './marketing-shell.ts';
import { landingPagesPlugin } from './landing-pages.ts';
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
// It knows nothing about gzip, nothing about whether a chunk is on the
// critical path, and nothing about whether a build got better or worse: it
// fired in exactly the same words when the entry chunk was 2,872 kB and at
// today's 247 kB gzipped. A warning that never changes gets scrolled past,
// which is how ~2.6 MB of eager locale JSON sat in the entry chunk for months.
//
// So it is switched off (chunkSizeWarningLimit below) and replaced with
// per-chunk gzip budgets that FAIL the build. Gzip because that is what users
// actually download; level 9 is a fixed yardstick for comparing one build to
// the next, not a prediction of what the CDN serves. Each budget sits a few
// percent above the real number, so tripping one means something genuinely
// grew.
//
// Tripped a budget? Find out WHAT grew first (ops/docs/bundle-size.md section
// 9 has the recipe). Only once the growth is understood and wanted, raise the
// number here in the same commit and say why in the changelog. Raising it to
// make the build green is how the 500 kB warning became useless.
// The deploy is the one build nobody can iterate on, and by the time it runs the
// code has already passed review, so the budgets below WARN there and throw
// everywhere else (see the failure path at the bottom of the plugin). The
// Cloudflare project is Workers-style, which exports WORKERS_CI; CF_PAGES covers
// a classic Pages build, and PN_BUDGETS_WARN=1 forces the same path by hand from
// the dashboard if Cloudflare ever renames both.
// Spec: ops/docs/bundle-size.md (chunk budgets)
const isDeployBuild = Boolean(
  process.env.WORKERS_CI || process.env.CF_PAGES || process.env.PN_BUDGETS_WARN
);

// Spec: ops/docs/bundle-size.md (chunk budgets)
const CHUNK_BUDGET_KB: Record<string, number> = {
  // Re-derived for the rolldown chunk graph when vite 8 landed (bundle-size.md
  // section 6 calls a bundler swap a re-derivation event). Rolldown splits the
  // same boot bytes across many small statically-imported chunks instead of
  // rollup's two fat ones, so the entry pair shrank and Editor/EncryptedImage
  // became their own chunks. Budgets sit a few percent above the measured
  // number, so tripping one means something genuinely grew.
  // The entry is keyed on the ENTRY FLAG, not the name, so a lazy chunk that
  // happens to be called "index" can never inherit the entry's budget.
  // 65.46 kB gz at the vite 8 landing, 2026-08-01. 75.97 once the shared
  // package was pinned to one chunk (2026-08-20, the white-page fix below).
  // NOTHING GREW: the boot path FELL 3.59 kB gz (850.77 -> 847.18) and lost
  // twelve chunks (70 -> 58) in the same change. Pinning shared stopped
  // rolldown scattering it, and the glue it used to hoist into a dozen
  // one-import chunks now sits in the entry once instead of many times. This
  // is a re-derivation, the same kind of event as the bundler swap above, so
  // the number is re-measured rather than defended. Raised to 77.
  // 77.00 on launch day (2026-08-31), which the previous 77 refused with the
  // baseline at 76.98: three og:locale rows and a reworded FAQ answer, about
  // 20 bytes. Raised to 78 so the next copy edit is not a budget question.
  '(entry)': 78,
  // NEW CHUNK, not new bytes: the whole shared package in one piece, 62.91 kB
  // gz. It has to stay one chunk - splitting it is what put a white page in
  // production. See the advancedChunks comment in `build` for the mechanism.
  shared: 65,
  // 130.20 kB gz with the Markdown pillar (107.47 at the vite 8 landing).
  // The pillar's four panes are static imports and must stay that way: making
  // them lazy puts a Suspense boundary above the editor, and TipTap does not
  // survive the disconnect/reconnect React does there (see the import comment
  // in NotesView.tsx). So this growth is paid here rather than deferred.
  // 135.05 kB gz since the `.txt` icon (2026-08-15): the Markdown list and file
  // header pick `FileTxt` or `FileMd` per extension, so a second Phosphor glyph
  // now ships in this chunk (~0.8 kB gz across the boot path, which is what one
  // icon costs). The pillar's panes are static imports for the reason above, so
  // an icon they reference lands here rather than behind a lazy boundary.
  // 136.25 kB gz with the export-fidelity pass (2026-08-19): export.ts's
  // embedded stylesheet gained the code-panel hljs palette and print rules,
  // and markdownRender the editor-style task checkboxes and callout fold
  // handling - stylesheet strings ship as bytes, so the export looking like
  // the editor is paid here. The highlighter itself stays out (dynamic, see
  // markdownHighlight.ts).
  // 137.64 kB gz with TOTP codes in the Vault (2026-08-20). WHAT GREW: the
  // shared package's totp.ts pulls noble's sha1 (legacy.js) and sha512 into
  // the bundle (sha256 and hmac were already there for the crypto core), and
  // VaultItem/LoginForm gained the code row, countdown ring and key field.
  // VaultItem is a static import under NoteEditorPane, so the bytes are
  // boot-path by construction, same as the panes above.
  // 145.91 kB gz with the Bookmarks pillar, final same-day shape
  // (2026-08-22). WHAT GREW: BookmarksList (quick-add bar, derived links,
  // multi-select), BookmarkItem under the standard header (URL field, PIN
  // block, labeled copy/open), linkBody.ts + openExternal.ts, NoteRow's
  // tall favicon chip + trailing-actions slot, the read-only hint for
  // vault/link bodies, and seven pillar-specific Phosphor glyphs
  // (PlusSquare, NotePencil trigger split, CheckFat, Files, Notebook,
  // Bookmarks/Bookmark, ShieldPlus). Static under NotesView like every
  // pillar pane; the importer stays behind the lazy ImportModal boundary.
  // 148.32 kB gz after the tracker data-loss fixes (2026-08-26). WHAT
  // GREW: mergeTrackers/trackersEqual and the template tombstone filters
  // in trackerTypes.ts, the field-level merge at both ConflictModal
  // resolutions, saveWeekReflection (which creates the Monday entry), and
  // the dosage-history writes in MedicationPill. All of it is correctness
  // on paths the boot closure already carried.
  // 149 -> 150 (2026-08-26): the same +1.07 kB gz as the boot path above,
  // measured the same way. `export.ts` is static under NotesView.
  // 150 -> 153 (2026-08-27): 151.95 kB gz with the shared folder tree. WHAT
  // GREW: FolderTreeView, which the sidebar and the Move dialog now both
  // render, carries the pointer-event drag (drop resolution, edge
  // auto-scroll, the capture handlers) and the tinted-branch and caret
  // chrome the dialog never had. The two surfaces' own tree code shrank in
  // return, so the net is the reorder gesture itself.
  // 153 -> 154 (2026-08-28): 153.28 kB gz after the admin console moved out
  // to packages/admin. NOT new bytes, and not growth this chunk caused. The
  // panel was the second consumer of HoverLabel, formatBytes, pricing,
  // LoadingScreen and icons, so rolldown kept those in chunks of their own.
  // With one consumer left it folds them back in, and four chunks disappear
  // (65 -> 61). Measured both ways against HEAD in a worktree: the boot path
  // FELL 883.09 -> 881.67 kB gz. The app is smaller and this chunk carries a
  // little more of it.
  // 154 -> 155 (v0.477.0): 154.00 kB gz. The content-width axis adds the
  // ContentWidthButton and the theme axis it reads to this chunk.
  // 155 -> 156 (2026-08-29): 155.23 kB gz. WHAT GREW: the editor header's
  // quick-action row (notesView/NoteQuickActions.tsx), the shared gates in
  // noteActionGuards.ts, and the previous/next note pair with its shortcut.
  // The "..." menu gave a little back when it stopped carrying its own copy
  // of the Pro and PIN checks.
  // 156 -> 157 (2026-08-31): two same-day causes, merged from parallel
  // branches. The at-rest sweep (localSweep.ts) and its idle trigger -
  // the every-session pass that converts plaintext rows to the sealed
  // format - and the search index now following the notes state
  // (searchIndexSync.ts + the displayNotes wiring), so a note is
  // searchable the moment it exists instead of after the next refresh.
  // 157 -> 158 (2026-08-31, same day): the encrypted full backup's card
  // and prop threading, the trashed-flag wiring, and the blob stores'
  // ownership guard - +0.40 kB measured.
  // 158 -> 159 (2026-09-05): the never-backed-up guards - the notice in
  // the three permanent-delete confirms, the sign-out confirm's list and
  // safer default, and the reveal shared with ID & Sync's Open. +0.51 kB
  // measured against the v0.499.4 baseline drawn the same day.
  NotesView: 159,
  // 209.51 kB gz since katex became its own chunk below (278.11 with it inside,
  // against a 300 budget). Retightened in the same change that moved it: a
  // budget carrying 90 kB of slack is decoration, not a gate.
  Editor: 220, // tiptap/lowlight, a static dep of NotesView now
  // NEW CHUNK, not new bytes: 75.88 kB gz that used to sit inside Editor above.
  // markdownRender.ts imports katex DYNAMICALLY to render math in exports, the
  // burn viewer and print, so katex now has both a static importer (the editor's
  // math extensions) and a dynamic one, and rolldown gives it its own chunk.
  // The boot path is unchanged - the static importer still pulls it in there -
  // and the win is on the burn viewer, which reaches markdownRender without the
  // editor and so fetches this only for a note that actually contains a `$`.
  // Budget set a few percent above the measured number, like its neighbours.
  katex: 80,
  EncryptedImage: 110, // 95.94 kB gz - split out of NotesView by rolldown
  // Lazy, and enormous, but only fetched by someone who drops in a HEIC file.
  // Why it still ships: ops/docs/bundle-size.md section 8.
  'heic-to': 770, // 728.90 kB gz, unchanged by the bundler swap
};

// Everything not named above, including the per-locale catalog chunks. Loose
// enough never to nag, tight enough that a new heavyweight shows up in the
// build log instead of in production.
const DEFAULT_CHUNK_BUDGET_KB = 60;

// The boot path is no longer a nameable pair: rolldown spreads what rollup
// kept in entry+NotesView across ~66 statically-imported chunks that all
// load before first render. The number worth defending is therefore the
// static-import CLOSURE of the entry chunk plus NotesView (which App.tsx
// prefetches immediately), and it carries its own budget.
// 835.13 kB gz with the Markdown pillar (819.58 at v0.309.4, before it landed).
// Raised from 830 because the pillar's four pane components - MarkdownListPane,
// MarkdownFilePane, MarkdownRail, MarkdownExplainer - are STATIC imports in
// NotesView, so they sit in the boot closure whether or not anyone opens the
// pillar. Deliberately tight (about 5 kB of headroom, where the old number
// carried nearly 40) so the next addition has to be argued for rather than
// absorbed.
//
// `lazy()` is NOT the way back under: it was tried and reverted, because a
// Suspense boundary above MarkdownFilePane crashes the app the moment a file is
// opened (NotesView.tsx's import comment has the mechanism). It also bought
// nothing here - splitting the panes out hoisted their shared code into new
// statically-imported chunks, and this number went UP by 0.88 kB. Any real
// reduction has to come from what the pillar's shell-level hooks pull in.
//
// 840.13 kB gz with the default-Markdown-app control (2026-08-14), which tripped
// 840 by 130 bytes. WHAT GREW, since the rule here is to know before raising:
// `defaultApp.ts` (the OS-status seam and its subscriber cache) and
// `MarkdownDefaultApp.tsx` (three frames over one body), reached from
// MarkdownListPane, MarkdownExplainer and NotesView - all three already static
// imports, so this rides in the boot closure exactly as the panes above do. Plus
// the list's auto-open effect. Raised to 845 rather than 841 so the next 130
// bytes are not another build failure, and kept under 1% of headroom so it is
// still a gate rather than a formality. Splitting it out is the same dead end as
// the panes: it is the same shared code that got hoisted last time.
//
// 845.71 kB gz with the editor-syntax-fixture export fixes (2026-08-19), over a
// budget that had 60 bytes of headroom left. WHAT GREW: markdownRender.ts
// learned the syntax the torture-test fixture caught it dropping (pipe-table
// column alignment, two-space hard breaks, email + query-string autolinks,
// indented code blocks, list splitting on marker change), and export.ts's
// embedded stylesheet gained the RTL direction rules and long-word wrapping the
// editor already had. Both are static imports under NotesView, so the bytes are
// boot-path by construction. Raised to 847 for the same reason as the last
// raise: a whisker of margin so the next hundred bytes argue their case in a
// review rather than as a red build.
// Spec: ops/docs/bundle-size.md
//
// 847.07 kB gz with the storage-accounting and equal-stamp sync fixes
// (2026-08-19). WHAT GREW: sync.ts (the pull now tells its own echo from a
// foreign equal-stamp row via the recorded push nonce, #156), notesRepo.ts
// (monotonic edit stamps), and the upload pre-flight gates that now count
// the incoming file (#131) - all static imports on the boot path. Raised to
// 849 so the next small fix in these files is not a build failure, still
// under 0.5% of headroom.
//
// 850.21 kB gz with TOTP codes in the Vault (2026-08-20). WHAT GREW: the
// same bytes as the NotesView raise above - noble's sha1 and sha512 via the
// shared package's new totp.ts, plus the code row, ring and key field in
// VaultItem/LoginForm, all static under NoteEditorPane. Raised to 851,
// keeping under 0.1% of headroom so the gate stays a gate.
//
// 849.32 kB gz once vault items rendered as fields (2026-08-20). WHAT GREW:
// vaultFields.ts, which both export.ts and the burn share read, plus the
// table markup and the markdown writer that go with it - static under
// NotesView like everything above. NOT raised: the line above already covers
// it, and a budget that moves for growth it can absorb stops being a gate.
//
// 853 after the deploy build failed at 851.58 kB gz on the same commit CI called
// 850.10 (2026-08-20). NOTHING GREW: v0.416.0 rebuilt on this machine measures
// 850.78 against HEAD's 850.79, so the gauge was wrong rather than the bundle.
// Every number above was taken in a tree with no VITE_ values to inline (an
// agent sandbox or CI, where .env.local does not exist) and the deploy inlines
// them. Same commit, same machine: 849.31 kB gz with the variables empty, 850.79
// with them set. The gap is not the length of the strings - emptying one group
// at a time moves under 0.5 kB, emptying all of them moves 1.48 - it is what
// gzip does with a bundle full of identical empty strings. Linux adds another
// 0.79 kB on top of macOS, which is how the deploy arrives at 851.58.
//
// So the reference measurement is THE DEPLOY BUILD, not whatever a sandbox
// prints, and 853 sits 1.42 kB (0.17%) above it. That headroom is the spread
// between the three environments, not room for new bytes. To reproduce it,
// build with the real packages/web/.env.local in place; without one the number
// runs about 1.5 kB low and the plugin says so on its own log line.
// 862 with the Bookmarks pillar, final same-day shape (2026-08-22):
// 859.86 kB gz measured on a Mac WITH .env.local inlined (deploy-like), so
// the deploy reference is that plus Linux's ~0.79 - about 860.7 - and 862
// keeps the same ~1.2 kB environment spread the 853 raise established, not
// room for new bytes. WHAT GREW: the NotesView chunk's Bookmarks pillar,
// itemized on its budget above.
// 865 after the five commits that finished the pillar (2026-08-23): 862.29
// kB gz, same machine and same .env.local state as the 859.86 above, so the
// +2.43 is real growth rather than calibration. WHAT GREW: nothing new entered
// the boot path - the closure is the same 59 chunks - it is NotesView.js and
// the entry carrying the pillar's own code (the Bookmarks view, the sidebar
// and All-list view settings, the Netscape writer behind the bookmarks
// export, and the homepage grid card). Deploy reference is 862.29 plus
// Linux's ~0.79, about 863.1, so 865 keeps the same ~1.9 kB environment
// spread, not room for new bytes.
// 868 for the bookmarks import entry and the folder picker's row menu
// (2026-08-23): 865.56 kB gz, same machine and same .env.local state as the
// 862.29 above. Only 0.78 of that is this change - the tree measures 864.78
// with these four files at HEAD - so the gate was already 0.22 kB from
// tripping before it was touched, and whoever next raises this line should
// account for the other 2.49 (the v0.440 public-changelog entry, and the
// importer work that was uncommitted in the tree at the time) rather than
// take it for calibration. WHAT GREW: nothing new entered the boot path -
// the closure is the same 60 chunks - it is BookmarksList's standing import
// row and tile and FolderPicker's row menu, both static under NotesView.
// Deploy reference is 865.56 plus Linux's ~0.79, about 866.35, so 868 keeps
// the same ~1.6 kB environment spread the raises above established, not room
// for new bytes.
// 871 for the in-app help chip (2026-08-24): 868.25 kB gz against 866.09 for
// the same tree with the chip's six call sites stripped, so +2.16 is this
// change and nothing else - both numbers come from one sandbox without
// .env.local, which the note above says runs about 1.5 kB low. WHAT GREW:
// HelpChip.tsx plus the generated `helpQuestions` English catalog, reached
// from ImportModal, SyncOptionsModal, SecurityModal, UpgradeModal,
// DangerZone and BurnShareModal. It is one shared chunk, and the closure goes
// 59 -> 60 because of it. Measured BOTH ways first: a private module tree
// with its own import.meta.glob cost 868.41, so folding the strings into the
// normal i18n namespaces bought 0.16 and one fewer loader, not the 2 kB it
// looked worth - the bytes are the component and the strings themselves.
// Deploy reference is 868.25 plus Linux's ~0.79, about 869.04, so 871 keeps
// the same ~2 kB environment spread the raises above established, not room
// for new bytes. Caveat for whoever raises this next: the tree also carried a
// parallel session's uncommitted import-prompt work at the time, which is in
// both of my numbers and therefore not in the +2.16, but IS in the 868.25.
// 873 after the import prompt and the import-aware milestones (2026-08-24),
// and it corrects the 871 above. That raise added only Linux's 0.79 to a
// sandbox number, but a sandbox has no .env.local, and the note further up
// says an env-less build measures about 1.25 to 1.5 kB low. Its own commit
// (dfc16329) measures 869.50 kB gz on a Mac WITH .env.local, so build-smoke
// was already at about 870.3 the moment the budget went to 871: 0.7 kB of
// headroom, not the 2 the note claimed. HEAD measures 870.33 on that same
// machine and the same .env.local state, so +0.83 is real growth on top of
// it, and build-smoke read 871.40 and failed. WHAT GREW, over the same 60
// chunks: NotesView +0.41 (ImportPrompt.tsx, the shared import row static
// under NotesList, TasksList and BookmarksList), notesRepo +0.21
// (notesCreated.ts and its counter), languages +0.12 and auth +0.08
// (settingsLocalKey.ts and the userSettings split behind the import-aware
// milestones), HelpChip +0.02. The reference here is build-smoke's own
// 871.40, measured on ubuntu with tools/ci-vite-env.mjs values, which
// section 6 puts within 0.1 kB of the deploy - so 873 keeps the same ~1.6 kB
// environment spread the raises above established, not room for new bytes.
// Calibrate the next raise against the second number on the plugin's own log
// line, which is now stated in build-smoke's units from any machine.
// 875 with the auth breadcrumb log (2026-08-25). WHAT GREW: the session
// diagnostics themselves cost 0.33 kB gz on the boot path (authDiag.ts plus
// its call sites in auth.tsx, sync.ts and SessionExpiredModal.tsx; auth
// +0.34, the rest in the NotesView closure), measured as two builds on the
// same tree with only those four files reverted: 872.86 -> 873.19 in
// build-smoke units on this Mac (darwin +1.10 applied). The other growth
// since baseline v0.448.1 (Sun.es +1.22, NotesView +0.92, markdown +0.33,
// markdownRender -0.70, Moon.es -0.73) was already in the tree and had eaten
// the headroom down to 0.14 kB before this change. Caveat for the next
// raise: the tree also carried a parallel session's uncommitted HelpChip,
// LandingPage and Onboarding edits at measurement time, so those bytes are
// in 873.19 and in the re-derived baseline. 875 keeps the same ~1.8 kB
// spread the raises above established, not room for new bytes.
// 877 with the session-stability batch (2026-08-25, the day's second
// raise). WHAT GREW since baseline v0.453.2, in build-smoke units at
// 875.16 measured on this Mac (darwin +1.10 applied): auth +0.34 and
// (entry) +0.29 are the stability hardening (verdict taxonomy, owner
// mirror in db/authStorage, lock-screen sign-in hold, breadcrumbs,
// credential-key bucketing), devices +0.10 is the secret-swap journal;
// NotesView +0.94 and languages +0.20 were the v0.455-v0.456 filter
// feature, already committed and inside the previous headroom. 877
// keeps the same ~1.8 kB spread as the raises above, not room for new
// bytes.
// 879 for the GitHub sign-in button and the privacy ladder (2026-08-26):
// 876.48 kB gz against 875.76 for the identical tree with this session's five
// files restored from HEAD (Onboarding.tsx, HelpChip.tsx, helpChips.json,
// en/auth.json and the 17 generated helpQuestions.json), so +0.72 is this
// change and nothing else. Both numbers come from the same machine with the
// same .env.local. WHAT GREW: almost all of it is one icon. `Password` is a
// three-cluster glyph and lands as its own chunk at +0.80, which takes the
// closure 60 -> 61; the ladder's markup and its English strings are the rest,
// and dropping `signup-options` from the chip map gave a little back. An icon
// costing more than a whole panel is worth knowing before the next one is
// added to a boot-path surface: the cheaper marks measured 2.4-3.6 kB raw
// against Password's 3.9. Deploy reference is 876.48 plus Linux's ~0.79,
// about 877.3, so 879 keeps the same ~1.6 kB environment spread the raises
// above established, not room for new bytes.
// 879 -> 883 (2026-08-26). WHAT GREW: +1.08 kB gz for journal trackers in
// the export formats (`trackerExport.ts` plus the readable block and its
// styles in `buildNoteHtmlDocument`), and ~1.4 kB for the portable folder
// path - `folderNamePath` in folders.ts and `parseFolderPath` in
// import/folderImport.ts, both reached from the boot closure. Each number
// was measured in isolation by building with and without that change on the
// same tree, because several change-sets landed the same day.
//
// It is paid in the BOOT path only because `export.ts` (1347 lines) is a
// static import of NotesView via `notesView/useExports.ts`, so the whole
// export surface loads for everyone whether or not they ever export.
// Making those nine imports dynamic would return far more than these
// changes cost; it is a separate refactor, not a rider on a feature commit.
// 886 -> 887 (2026-08-29). WHAT GREW: +0.74 kB gz in NotesView.js for the
// editor header's quick-action pill - `notesView/NoteQuickActions.tsx` plus
// the shared `noteActionGuards.ts` the "..." menu now calls too, which is
// why the menu itself got a little smaller. The build reported other movers
// on the same tree (EyeSlash, auth, EncryptedImage); those belong to work
// already in progress here, not to this change, so this raise covers the
// 0.74 and nothing else.
// 887 -> 888 (2026-08-30). WHAT GREW: the rest of the editor-chrome pass -
// the previous/next pair and its shortcut, `EditorSlotPill.tsx` shared by
// the four controls in the editor's top-right slot (+0.27 in Editor.js for
// the slot prop), and the demo's local note-history path in
// `noteVersions.ts`. NotesView carries most of it at +1.23 since the
// baseline. The same parallel movers as the line above are still in the
// number and still are not this change.
// 888 -> 889 (2026-08-30). WHAT GREW: +0.55 kB gz for the split colour
// buttons in EditorToolbar.tsx - the second trigger, its label and the
// colour strip on each of the two controls, plus the small localStorage
// pair in editorPrefs.ts. Measured against this same tree at HEAD, which
// sat at 887.45 with 0.55 kB of headroom.
// 889 -> 890 (2026-08-31). WHAT GREW: +0.64 kB gz in icons.js for three
// phosphor glyphs the note menus now draw (a struck pencil, a shield and a
// struck shield), and +0.61 in NotesView.js for the read-only and protect
// entries in the row context menu, the guards behind them and the instant
// gate a fresh protect applies.
// 890 -> 892 (2026-08-31). WHAT GREW: +1.10 kB gz for the local at-rest
// seal layer - the DBCore middleware and key registry in db.js (+0.97),
// the AAD encrypt/decrypt variants in shared (+0.13) and the writer-gen
// listener in the entry (+0.11). The layer must sit on the boot path:
// it wraps the database the first paint reads.
// 892 -> 893 (2026-08-31, the integration merge). WHAT GREW: the sweep
// and its writer-mode plumbing (db +1.71 total with the layer above)
// plus the state-driven search index (NotesView +0.66), which land
// together at 892.16 as build-smoke measures it.
// 893 -> 894 (2026-08-31, same day): the sealed-backup codec in shared,
// the sync push ownership re-checks, and the auth switch suspend - +0.97 kB
// measured across the closure.
// 894 -> 895 (2026-08-31, same day): the announcement banner and its
// registry on the landing and shell boot paths - AnnouncementBanner
// +3.84, openExternal -2.91, net +0.93 kB as the build reports it.
// 895 -> 896 (2026-09-02): the paged blob-size listing in imageStore
// (+0.14 kB gz, measured against HEAD in a worktree). Storage answers a
// listing with one page, so an unpaged call left every blob past the
// first page permanently sizeless. The predecessor landed at 0.02 kB
// headroom, which is why 0.14 needs a raise at all.
// 896 -> 897 (2026-09-02): the recovery-phrase route out of a forgotten
// PIN - pinRecovery.ts, its form, and the strings in every security
// catalog (+0.57 kB gz over the whole boot path). A forgotten PIN had no
// route at all before it, on any device.
// 897 -> 898 (2026-09-02, same day): two phosphor glyphs, FileHtml and
// Printer, for the share menu's new icon column (+0.81 kB gz across the
// closure). The menu lost three whole-vault backup rows in the same
// change and the strings behind them, so the net cost is two icons.
// 898 -> 899 (2026-09-05): the "Not backed up" state - pushFailures.ts,
// the pill and panel branches, the reveal helper NotesView now shares with
// the note-link jump, the bar under the editor header and the row badge.
// The build reports NotesView +0.44 kB gz since the v0.495.0 baseline,
// which the four releases between carried across at 0.02 kB of headroom;
// useOnlineStatus +0.24 and Editor +0.17 are those releases, not this one.
// 899 -> 900 (2026-09-05, same day): the never-backed-up guards, the
// honest sync log and the fuller support report. +0.96 kB since the
// same-day baseline: NotesView +0.70, i18n +0.20, the rest in the panel.
const BOOT_PATH_BUDGET_KB = 900;

// The budget above is stated in ONE environment's units: build-smoke's, which
// is ubuntu with the synthetic values from tools/ci-vite-env.mjs. Every other
// build measures below it, so a Mac that passes says nothing about the gate
// that actually runs. That is not theory - it is how 2026-08-24 shipped a boot
// path 0.40 kB over with a green local preflight, and how the raise before it
// was calibrated 1.25 kB low.
//
// So the plugin adds the spread back before it compares, and prints both
// numbers. A local build now fails where build-smoke fails, and the number a
// future raise quotes is already in the gate's units.
//
// Both constants are measured, not guessed, and both need re-measuring
// whenever section 6's table is re-derived (a bundler swap, a runner image
// change). Re-measure by building the same commit two ways and subtracting.
// Spec: ops/docs/bundle-size.md (section 6)
//
// 1.5 for the VITE_ values: emptying all of them moves 1.48 kB, and it is not
// the length of the strings but what gzip does with a bundle full of identical
// empty ones. A sandbox with no .env.local is the build this corrects.
const ENV_SPREAD_KB = 1.5;
// The spread is per-platform, not "everything that is not Linux". macOS is the
// only builder that measures low, and reading it as a non-Linux constant
// charged Windows 1.1 kB it does not owe: at v0.452.0 the Windows release
// runner measured 872.66 against build-smoke's 872.73 on the same commit, so
// the gate saw 873.76, failed a build that was 0.27 kB UNDER budget, and no
// byte of it was real. Windows sits at ubuntu parity, so it corrects by zero.
//
// macOS: 0.79 at commit 53632f85 (849.31 macOS against 850.10 ubuntu, both
// env-less), 1.05 at v0.448.0 (870.35 against build-smoke's 871.40, both with
// deploy-shaped values), and 1.09 at v0.452.0 (871.64 against 872.73). It
// tracks the bundle, so take the newest and round up rather than average.
//
// A platform nobody has measured corrects by zero, deliberately: an
// unmeasured guess that runs high fails builds for bytes that do not exist,
// while one that runs low only means the gate is no stricter than build-smoke,
// which is the gate that actually runs on every push.
// Spec: ops/docs/bundle-size.md (section 6)
const PLATFORM_SPREAD_KB: Record<string, number> = {
  darwin: 1.1,
  win32: 0,
};

// A build knows what every chunk weighs today. It does not know what they
// weighed last week, so a tripped budget can only say "you are over", and the
// cheapest way out of that sentence is to raise the number. Finding the real
// answer by hand costs two builds and a second checkout of the repo, which is
// why it keeps getting skipped: 853 -> 873 in three weeks, one plausible raise
// at a time.
//
// bundle-baseline.json is last week. It holds what the gated chunks weighed at
// the last deliberate budget change, so EVERY build can name what grew without
// being asked, and the budget error carries the list instead of a recipe. The
// file is committed, so the drift is also visible in review.
//
// It is a report, never a gate (ops/docs/structure-handoff.md: a new check
// ships as a report first). Failing a build for differing from the baseline
// would fail every commit that moves a single byte.
//
// Rewrite it with `pnpm bundle:baseline` in the same commit that raises a
// budget, so the next reader's diff answers "what grew since we last agreed on
// a number" rather than "what grew since some build in July".
// Spec: ops/docs/bundle-size.md (section 6)
const BASELINE_FILE = path.resolve(__dirname, 'bundle-baseline.json');
// Movers under this are not worth a line: the platform spread lands unevenly
// across chunks, so a baseline taken on another machine shows small deltas
// that are environment, not code.
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
  // The budgets are calibrated against the deploy, which inlines the VITE_
  // values. A build without them measures low, so it labels its own number
  // instead of letting the next reader take it for the real one.
  let envInlined = true;
  return {
    name: 'pn-chunk-budgets',
    apply: 'build',
    configResolved(config) {
      envInlined = Boolean(config.env.VITE_SUPABASE_ANON_KEY && config.env.VITE_PADDLE_CLIENT_TOKEN);
    },
    generateBundle(_options, bundle) {
      const over: string[] = [];
      const gzByFile = new Map<string, number>();
      const chunkByFile = new Map<
        string,
        { key: string; name: string; isEntry: boolean; imports: string[] }
      >();
      for (const [file, chunk] of Object.entries(bundle)) {
        if (chunk.type !== 'chunk') continue;
        const key = chunk.isEntry
          ? '(entry)'
          : chunk.name || file.replace(/^assets\//, '').replace(/-[\w-]+\.js$/, '');
        const kb = zlib.gzipSync(chunk.code, { level: 9 }).length / 1000;
        gzByFile.set(file, kb);
        chunkByFile.set(file, { key, name: chunk.name, isEntry: chunk.isEntry, imports: chunk.imports });
        const budget = CHUNK_BUDGET_KB[key] ?? DEFAULT_CHUNK_BUDGET_KB;
        if (kb > budget) {
          over.push(`  ${key} (${file}): ${kb.toFixed(2)} kB gzipped, budget ${budget} kB`);
        }
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
      // Restate the measurement in build-smoke's units before comparing, so
      // this build fails exactly where build-smoke does.
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
      this.info(
        `boot path (static closure of entry + NotesView, ${boot.size} chunks): ` +
          `${bootPathKb.toFixed(2)} kB gzipped` +
          (spreadKb > 0
            ? `, ${gatedKb.toFixed(2)} as build-smoke measures it (+${spreadKb.toFixed(2)}: ${spread.join(', ')})`
            : '') +
          `, budget ${BOOT_PATH_BUDGET_KB} (headroom ${(BOOT_PATH_BUDGET_KB - gatedKb).toFixed(2)} kB)`
      );
      if (gatedKb > BOOT_PATH_BUDGET_KB) {
        over.push(
          `  boot path: ${gatedKb.toFixed(2)} kB gzipped over ${boot.size} chunks, budget ${BOOT_PATH_BUDGET_KB} kB` +
            (spreadKb > 0
              ? ` (measured ${bootPathKb.toFixed(2)} here, plus ${spreadKb.toFixed(2)} for ${spread.join(', ')})`
              : '')
        );
      }

      // Everything the budgets gate, keyed the way they key it, so a mover can
      // be read straight into the budget it belongs to.
      const current: Record<string, number> = {};
      for (const [file, chunk] of chunkByFile) {
        if (!boot.has(file) && !(chunk.key in CHUNK_BUDGET_KB)) continue;
        current[chunk.key] = Number(
          ((current[chunk.key] ?? 0) + (gzByFile.get(file) ?? 0)).toFixed(2)
        );
      }

      if (process.env.PN_BUNDLE_BASELINE) {
        const written: BundleBaseline = {
          version: readVersion('pn-chunk-budgets'),
          measuredOn: { platform: process.platform, envInlined },
          bootPathKb: Number(bootPathKb.toFixed(2)),
          bootPathCiKb: Number(gatedKb.toFixed(2)),
          bootPathChunks: boot.size,
          chunks: Object.fromEntries(Object.entries(current).sort(([a], [b]) => a.localeCompare(b))),
        };
        fs.writeFileSync(BASELINE_FILE, `${JSON.stringify(written, null, 2)}\n`);
        // The budgets are not enforced in this run on purpose: rewriting the
        // baseline is step one of a raise, and failing on the old number would
        // make the command look broken at exactly the moment it is correct.
        this.info(
          `bundle-baseline.json rewritten at v${written.version} (${Object.keys(current).length} gated chunks, boot path ${written.bootPathCiKb} in build-smoke's units). Budgets not enforced in this run.`
        );
        return;
      }

      const baseline = readBaseline();
      let grew: string[] = [];
      if (!baseline) {
        this.warn(
          `pn-chunk-budgets: no bundle-baseline.json, so this build cannot say what grew. Run \`pnpm bundle:baseline\` to write one.`
        );
      } else {
        const movers = [...new Set([...Object.keys(current), ...Object.keys(baseline.chunks)])]
          .map((key) => ({ key, delta: (current[key] ?? 0) - (baseline.chunks[key] ?? 0) }))
          .filter((m) => Math.abs(m.delta) >= BASELINE_NOISE_KB)
          .sort((a, b) => b.delta - a.delta);
        grew = movers.slice(0, 6).map((m) => `${m.key} ${signed(m.delta)}`);
        if (movers.length > grew.length) grew.push(`${movers.length - grew.length} more`);
        const bootDelta = gatedKb - baseline.bootPathCiKb;
        if (Math.abs(bootDelta) >= BASELINE_NOISE_KB || movers.length > 0) {
          this.info(
            `since baseline v${baseline.version}: boot path ${signed(bootDelta)} kB` +
              (grew.length > 0 ? `, ${grew.join(', ')}` : '') +
              (baseline.measuredOn.platform === process.platform
                ? ''
                : ` (baseline measured on ${baseline.measuredOn.platform}: small movers can be environment, not code)`)
          );
        }
      }

      if (over.length > 0) {
        const report =
          `pn-chunk-budgets: ${over.length} chunk(s) over budget\n${over.join('\n')}\n\n` +
          (grew.length > 0
            ? `What moved since baseline v${baseline?.version}: ${grew.join(', ')} (kB gzipped).\n\n`
            : '') +
          'Find what grew before touching these numbers - ops/docs/bundle-size.md ' +
          'section 9 has the recipe. If the growth is intended, raise the budget in ' +
          'vite.config.ts, rewrite the baseline with `pnpm bundle:baseline` in the ' +
          'same commit, and say why in the changelog.';
        if (isDeployBuild) {
          // A budget is a review gate, not a release gate: throwing here blocks
          // shipping code that is already merged, which is what happened on
          // 2026-08-20. build-smoke builds with deploy-shaped VITE_ values
          // (tools/ci-vite-env.mjs), so the same overage fails on the pull
          // request, where it can still be argued about.
          this.warn(`${report}\n\nNOT failing the deploy: build-smoke owns this gate.`);
          return;
        }
        throw new Error(report);
      }
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
  },
  plugins: [
    react(),
    syncHelpQuestions(),
    emitVersionJson(),
    katexWoff2Only(),
    phosphorTrimWeights(),
    // See isAppBuild above: the native apps embed dist/ wholesale, and the
    // static site is web-only.
    announceBuildTarget(),
    stripMarketingAssets(),
    preloadOnboarding(),
    ...(isAppBuild
      ? []
      : [changelogPagePlugin(), helpPagePlugin(), roadmapPagePlugin(), brandPagePlugin(), marketingShellPlugin(), landingPagesPlugin()]),
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
