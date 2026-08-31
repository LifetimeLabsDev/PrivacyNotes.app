/**
 * Public-facing product roadmap.
 *
 * Single source of truth: feeds the in-app Roadmap tab (AboutModal) AND
 * the static /roadmap page (roadmap-page.ts Vite plugin). Both renderers
 * read PUBLIC_ROADMAP and map `status` to its label (ROADMAP_STATUS_LABEL)
 * plus their own badge colors.
 *
 * Ordering: items render top to bottom in array order, oldest/most-done
 * first and furthest-out last. Reorder freely whenever the real timeline
 * says so.
 */

export type RoadmapStatus = 'shipped' | 'in-progress' | 'in-review' | 'up-next' | 'final';

/** Display label per status. Single source for the badge wording. */
export const ROADMAP_STATUS_LABEL: Record<RoadmapStatus, string> = {
  shipped: 'Shipped',
  'in-progress': 'In progress',
  'in-review': 'In Apple review',
  'up-next': 'Up next',
  final: 'After 1.0',
};

/**
 * Which glyph the /roadmap card shows. Keys only - each renderer maps them to
 * its own icon implementation, exactly like FooterIcon in footerData.ts, so
 * this file stays free of markup and the in-app tab can ignore them entirely.
 */
export type RoadmapIcon =
  | 'shield'
  | 'globe'
  | 'download'
  | 'flame'
  | 'unlock'
  | 'bug'
  | 'rocket'
  | 'play'
  | 'desktop'
  | 'windows'
  | 'linux'
  | 'android'
  | 'apple'
  | 'store'
  | 'github'
  | 'certificate'
  | 'folder'
  | 'languages'
  | 'help'
  | 'key'
  | 'pencil'
  | 'grid'
  | 'sync'
  | 'sparkles'
  | 'lock'
  | 'chart'
  | 'check'
  | 'fingerprint'
  | 'qr'
  | 'devices'
  | 'database'
  | 'graph'
  | 'timer'
  | 'bookmark'
  | 'sidebar'
  | 'robot';

export type RoadmapItem = {
  /** Stable slug, used as the anchor id on the /roadmap page. */
  id: string;
  title: string;
  status: RoadmapStatus;
  /** One short paragraph. */
  description: string;
  /** Card glyph on /roadmap. */
  icon: RoadmapIcon;
};

export const PUBLIC_ROADMAP: RoadmapItem[] = [
  {
    id: 'internal-audit',
    title: 'Internal security audit',
    status: 'shipped',
    description: 'A thorough in-house review of the crypto and sync paths.',
    icon: 'shield',
  },
  {
    id: 'web-app',
    title: 'Encrypted web app',
    status: 'shipped',
    description: 'Where it started: zero-knowledge notes, tasks, and journal in the browser.',
    icon: 'globe',
  },
  {
    id: 'tasks',
    title: 'Tasks, not just checkboxes',
    status: 'shipped',
    description:
      'Tasks became their own item type, with their own icon, sorting and views, instead of notes with boxes ticked inside them. Completed ones sink to the bottom so what is left stays together.',
    icon: 'check',
  },
  {
    id: 'journal',
    title: 'Journal and trackers',
    status: 'shipped',
    description:
      'A dated journal with backfill for the days you missed, and built-in trackers for sleep, weight, steps, water, caffeine, screen time and more, charted over any range from a week to a year.',
    icon: 'chart',
  },
  {
    id: 'vault',
    title: 'The vault',
    status: 'shipped',
    description:
      'Logins, cards and files behind the same encryption as your notes, with a password generator, site favicons that work offline, per-item PIN locks, and an export any password manager can read.',
    icon: 'lock',
  },
  {
    id: 'import',
    title: 'Import from other apps',
    status: 'shipped',
    description:
      'One-click migration from Apple Notes, Standard Notes, Google Keep, Obsidian, Bitwarden, and more.',
    icon: 'download',
  },
  {
    id: 'burn-notes',
    title: 'Burn notes',
    status: 'shipped',
    description: "Share a note as a self-destructing, client-encrypted link the server can't read.",
    icon: 'flame',
  },
  {
    id: 'zero-knowledge-signin',
    title: 'Sign in without giving up zero knowledge',
    status: 'shipped',
    description:
      'Google, Apple and GitHub sign-in, with your key generated on your own device either way. Keep it simple and we hold an encrypted copy of your phrase, or take full custody and we hold nothing at all.',
    icon: 'fingerprint',
  },
  {
    id: 'qr-signin',
    title: 'Move to a new device by QR',
    status: 'shipped',
    description:
      'Point a new device at the code on an old one, or upload a photo of it when the camera will not cooperate, and your phrase moves across without ever being typed out.',
    icon: 'qr',
  },
  {
    id: 'devices',
    title: 'Device management',
    status: 'shipped',
    description:
      'See every device on your account and when it last synced, and cut any of them off from a single screen.',
    icon: 'devices',
  },
  {
    id: 'storage',
    title: 'Storage you can buy',
    status: 'shipped',
    description:
      'Any file type in the vault, at 50 MB per file on Pro and 100 MB once you add storage. The extra space comes in 1, 2 or 5 GB add-ons, for when you need more than your plan includes.',
    icon: 'database',
  },
  {
    id: 'encryption-published',
    title: 'Encryption published',
    status: 'shipped',
    description:
      'The encryption layer, the database schema and the threat model went public first, so the claims could be checked before the apps that use them followed.',
    icon: 'unlock',
  },
  {
    id: 'bug-hunt',
    title: 'Bug hunt',
    status: 'shipped',
    description: 'We invited beta testers to break it, and fixed what they found.',
    icon: 'bug',
  },
  {
    id: 'pro',
    title: 'Pro launch',
    status: 'shipped',
    description: 'A one-time purchase unlocks Pro. No subscriptions, just software.',
    icon: 'rocket',
  },
  {
    id: 'demo',
    title: 'Public demo',
    status: 'shipped',
    description: 'try.privacynotes.app: the full app, no signup, nothing saved.',
    icon: 'play',
  },
  {
    id: 'macos',
    title: 'macOS app',
    status: 'shipped',
    description: 'A native, notarized Mac app with offline-first sync.',
    icon: 'desktop',
  },
  {
    id: 'windows',
    title: 'Windows app',
    status: 'shipped',
    description: 'A native desktop app for Windows, built from the same core as macOS.',
    icon: 'windows',
  },
  {
    id: 'linux',
    title: 'Linux app',
    status: 'shipped',
    description: 'A native desktop app for Linux, built from the same core as macOS.',
    icon: 'linux',
  },
  {
    id: 'android',
    title: 'Android app',
    status: 'shipped',
    description:
      'A native Android app with the same end-to-end encryption, available now as a direct download (APK).',
    icon: 'android',
  },
  {
    id: 'grid-view',
    title: 'Grid view',
    status: 'shipped',
    description:
      'Lay any section out as full-width tiles instead of a narrow list, with image previews decrypted as you scroll. Auto picks grid on wide screens and list on narrow ones.',
    icon: 'grid',
  },
  {
    id: 'editor-upgrades',
    title: 'A real writing editor',
    status: 'shipped',
    description:
      'Callouts, tables, math, syntax highlighting in about forty languages, highlights, text color, and a markdown mode for writing in plain source.',
    icon: 'pencil',
  },
  {
    id: 'folders',
    title: 'Folders',
    status: 'shipped',
    description:
      'Organize notes, tasks, journals, and vault items into a nested tree. Folders sync end-to-end encrypted, combine with any view, and deleting one never deletes what is inside it.',
    icon: 'folder',
  },
  {
    id: 'help-center',
    title: 'Help center',
    status: 'shipped',
    description:
      'A searchable help center where every answer has its own page you can link to, and a step-by-step import guide for every app you can move from, in every language we speak.',
    icon: 'help',
  },
  {
    id: 'languages',
    title: 'Your own language',
    status: 'shipped',
    description:
      'The app, the website, and every help center answer, hand-translated into every language we ship. Pick one in settings or let it follow your system.',
    icon: 'languages',
  },
  {
    id: 'key-custody',
    title: 'Switchable key custody',
    status: 'shipped',
    description:
      'Change who keeps your recovery phrase whenever you like. Moving to self-custody deletes our copy for good, so we ask you to retype three of the twelve words first.',
    icon: 'key',
  },
  {
    id: 'more-imports',
    title: 'Apps you can leave behind',
    status: 'shipped',
    description:
      'Evernote, UpNote, Notesnook, Simplenote, Samsung Notes, and any app that keeps its notes as Markdown files on your disk. Your saved passwords come straight out of the browser too, and your own encrypted backup restores everything at once. Every source has its own guide in the help center.',
    icon: 'download',
  },
  {
    id: 'sync-hardening',
    title: 'Sync you can verify',
    status: 'shipped',
    description:
      'Sync now takes its timing from the server rather than each device clock, and Verify sync compares this device against the server so the green tick is something you can confirm instead of trust.',
    icon: 'sync',
  },
  {
    id: 'editor-upgrade',
    title: 'A serious writing surface',
    status: 'shipped',
    description:
      'Alignment, font family and size, block and inline math you can click to edit, and a pilcrow that shows every space and line break while you proofread. Text, images and attachments can all be dragged into place, and every shortcut is listed in the hotkeys panel.',
    icon: 'pencil',
  },
  {
    id: 'more-languages',
    title: 'Arabic, and every screen mirrored',
    status: 'shipped',
    description:
      'Arabic brought the interface across in full: every layout, icon and menu mirrored for right-to-left reading, not just the words swapped out. Turkish and Swedish landed alongside it, and search learned to handle scripts that do not put spaces between words.',
    icon: 'languages',
  },
  {
    id: 'markdown-folder',
    title: 'Your own folder of Markdown files',
    status: 'shipped',
    description:
      'Point the app at a folder of .md files on your disk and edit them in place. Nothing is uploaded, converted or encrypted, so the same files stay readable in Obsidian, in a git repo, or by an AI agent. Free, on the desktop app and in Chromium browsers.',
    icon: 'folder',
  },
  {
    id: 'upnote-import',
    title: 'UpNote importer',
    status: 'shipped',
    description:
      'Move a whole UpNote account over from its free local backup: notebooks become folders, and tags, pins, note links, formatting, images, and attachments come along. Per-note exports from the phone apps import too.',
    icon: 'download',
  },
  {
    id: 'authenticator-codes',
    title: 'Authenticator codes in the vault',
    status: 'shipped',
    description:
      'Keep the two-factor keys for your other accounts beside the passwords they belong to. Paste a setup link or a bare secret, and the rotating code appears with its countdown, so signing in somewhere no longer means reaching for a second app. The keys sync on every plan; Pro turns them into live codes.',
    icon: 'timer',
  },
  {
    id: 'sync-control',
    title: 'Sync on your terms',
    status: 'shipped',
    description:
      'Pause sync on one device whenever you want, and it stays paused until you say otherwise, because a switch that says "this device talks to nobody" must not undo itself. The sync panel says what each pass carried and how long it took, and on Android your files can wait for wifi while your words go now.',
    icon: 'sync',
  },
  {
    id: 'bookmarks',
    title: 'Bookmarks',
    status: 'shipped',
    description:
      'Save links in the same encrypted store as your notes, with the site icon, and with the folders, tags, search and favorites you already use. Your browser writes all of its bookmarks to one file, and the importer rebuilds the whole tree from it. They go back out the same way, so nothing is locked in here.',
    icon: 'bookmark',
  },
  {
    id: 'sidebar-choice',
    title: 'A sidebar you choose',
    status: 'shipped',
    description:
      'Switch off the rows you do not use, and decide which kinds of item the All list collects. Both choices follow your account to every device, and hiding a row only tidies the sidebar: everything it held is still there, and the New menu still makes more of it.',
    icon: 'sidebar',
  },
  {
    id: 'ai-readable-docs',
    title: 'Docs your AI agent can read',
    status: 'shipped',
    description:
      'The help center and the full changelog are published as plain text beside the web pages, so an assistant you ask about the app reads what the app actually does instead of guessing. Every answer carries the address of the page it came from, which is how you check it.',
    icon: 'robot',
  },
  {
    // Sits directly above `open-codebase` because that is the order it happened
    // in: the tree was cleaned, then it was published. A reader who opens the
    // repository is looking at the result of this card.
    id: 'readable-code',
    title: 'Code you can read',
    status: 'shipped',
    description:
      'We cleaned house before the source went public: clearer structure, comments that explain the why, no dead code. Partly pride, mostly because readable code is auditable code.',
    icon: 'pencil',
  },
  {
    id: 'open-codebase',
    title: 'The apps are open source',
    status: 'shipped',
    description:
      'The web, desktop, and mobile clients are published, next to the encryption they use and the database schema behind them.',
    icon: 'github',
  },
  {
    // Last of the `shipped` run, deliberately: renderItems() puts the "You are
    // here" marker at the FIRST non-shipped item, so a shipped card placed
    // below `adding-features` would render green, on the done-colored rail,
    // underneath a marker saying the shipped work is above it. Newest shipped
    // milestone, so it sits at the bottom of the run.
    id: 'ios',
    title: 'iOS app',
    status: 'shipped',
    description:
      'A native iPhone and iPad app with the same end-to-end encryption, on the App Store.',
    icon: 'apple',
  },
  {
    id: 'adding-features',
    title: 'Adding features',
    status: 'in-progress',
    description:
      'A release every week or two, and most of what goes into one started as somebody asking for it. The changelog is the full record.',
    icon: 'sparkles',
  },
  {
    id: 'fixing-bugs',
    title: 'Fixing bugs',
    status: 'in-progress',
    description:
      'Reports get triaged quickly and fixes ship in the next release rather than waiting for a milestone. Found something? The bug tracker is open.',
    icon: 'bug',
  },
  {
    id: 'google-play',
    title: 'Google Play Store',
    status: 'in-progress',
    description: 'The same Android app on Google Play, for one-tap install and automatic updates.',
    icon: 'store',
  },
  {
    id: 'graph-view',
    title: 'Graph view',
    status: 'up-next',
    description:
      'See how your notes connect. Every note-link drawn as a map you can pan and follow, so the shape of what you have written becomes something you can navigate.',
    icon: 'graph',
  },
  {
    id: 'automatic-backups',
    title: 'Automatic backups',
    status: 'up-next',
    description:
      'You can already export everything in one file, but only when you remember to. This makes it automatic: pick a folder and a rhythm, and a fresh copy is written without you thinking about it. Sync is not a backup, it mirrors deletions as faithfully as edits, so a copy on your own disk is the one thing no server event can undo.',
    icon: 'database',
  },
  {
    id: 'app-polish',
    title: 'App polish',
    status: 'up-next',
    description:
      'A stretch aimed at the apps we have already shipped rather than new pillars: platform quirks, rough edges, and everything the bug tracker has collected, until each app feels native to the device it runs on. This is the work the early adopter price waits on.',
    icon: 'sparkles',
  },
  {
    id: 'early-pricing-ends',
    title: 'The early adopter deal retires',
    status: 'up-next',
    description:
      "We keep the launch discount until the native apps are stable everywhere. Then Pro moves to its full price, and the people who trusted us early keep the best deal we'll ever offer.",
    icon: 'chart',
  },
  {
    id: 'fair-pricing',
    title: 'Fair global pricing',
    status: 'up-next',
    description:
      'Arrives together with full pricing: a price that is fair in one country can be a week of pay in another, so Pro will be priced to local purchasing power and shown in your currency, on the website, at checkout, and in the app stores. Buying today still beats waiting - the early adopter price is the lowest Pro will ever cost, in any country.',
    icon: 'globe',
  },
  {
    id: 'faster-everywhere',
    title: 'Faster everywhere',
    status: 'final',
    description:
      'A dedicated pass on speed and size: quicker startup, snappier search, smaller downloads. Tune the machine before the inspection.',
    icon: 'rocket',
  },
  {
    id: 'security-audit',
    title: 'Independent security audit',
    status: 'final',
    description:
      "An independent, end-to-end audit of the entire stack, published in full. We're bootstrapped and a proper audit is a major expense, so we won't put a date on it we can't honor. But the day we can afford to do it right, we do it.",
    icon: 'certificate',
  },
];
