/**
 * Dataset for the /vs/standard-notes comparison page.
 *
 * This file must stay FREE OF IMPORTS of any kind: landing-pages.ts
 * transpiles it standalone and evaluates it as a data-URL module (same as
 * src/guides.ts). Row ids reference VS_ROWS in src/landingData/registry.ts;
 * this file supplies only the COMPETITOR cells. Price tokens: {price},
 * {earlyPrice}, {proPrice}. Never hardcode our prices.
 *
 * Fact discipline: every cell must survive a check against the live
 * standardnotes.com app and pricing page. Update `lastChecked` whenever the
 * cells are re-verified. Their site blocks bots, so re-verification is a
 * human-in-a-browser task.
 * Spec: ops/docs/plans/marketing-pages.md (these landing pages are English only, permanently)
 */
export default {
  kind: 'vs',
  slug: 'standard-notes',
  name: 'Standard Notes',
  seo: {
    title: 'PrivacyNotes vs Standard Notes: The Free-Tier Comparison',
    description:
      'Both encrypt everything. Standard Notes charges ~$90/yr for markdown; PrivacyNotes includes it free, with no account needed. An honest comparison, kept current.',
    breadcrumb: 'vs Standard Notes',
  },
  lastChecked: 'August 2026',
  hero: {
    h1: 'PrivacyNotes vs Standard Notes',
    sub: 'The private Standard Notes alternative with no subscription. Standard Notes gets the encryption right, and this page will not pretend otherwise. The difference is everything around the crypto: PrivacyNotes needs no email address, puts markdown, journal, files and a password vault on the free tier, and Pro costs {price} once instead of roughly $90 every year.',
    cta: 'Try the demo, no signup',
    ctaSecondary: 'Import from Standard Notes',
    micro:
      'The demo runs in your browser and saves nothing. The free tier needs no credit card, and no email if you sign in with a phrase.',
  },
  stats: [
    { big: '{price} once', small: 'vs ~$90 per year, forever. Their year one costs more than our lifetime.' },
    { big: '0 emails', small: 'Sign in with a 12-word phrase. Nothing identity-shaped required.' },
    { big: '7 pillars', small: 'Notes, tasks, journal, files, vault, bookmarks and markdown, all on the free tier.' },
    { big: '.md on disk', small: 'Desktop can work on a folder of plain markdown files, edits save in place.' },
  ],
  pickUs: [
    'markdown without a plan. Their free tier is plain text; the markdown editor with live preview needs the subscription. Ours is markdown-native from the first note.',
    'one app instead of a stack: journal with mood tracking, tasks, encrypted files and a password vault next to your notes.',
    'no account at all. A 12-word phrase is the entire identity. No email to verify, nothing to subpoena out of us.',
    'to pay once: {earlyPrice} during early access, {proPrice} after. Own it, done.',
  ],
  pickThem: [
    'a fully open-source stack, server included, with self-hosting.',
    'four independent security audits on the record, and a ten-year longevity pledge.',
    'the built-in 2FA authenticator, publishing via Listed, and exotic note types like spreadsheets.',
  ],
  tableIntro: {
    kicker: 'Side by side',
    h2: 'PrivacyNotes vs Standard Notes, honestly',
    lead: 'This is the closest comparison we publish: Standard Notes is a serious, well-built encrypted notes app. The rows where the two tie are real ties. The rows where they do not are why this page exists.',
    foot: 'Coarse on purpose: yes, partial, paid, no. Every cell has to survive a fact-check against the other side’s current app and pricing page; the editorial freedom is in which rows exist, and we chose rows we win. When Standard Notes wins a row, the table says so.',
  },
  cells: {
    e2ee: { v: 'yes' },
    'zero-knowledge': { v: 'yes' },
    'no-account': { v: 'no', note: 'Email account required to sync' },
    'verifiable-crypto': { v: 'yes' },
    'open-source': { v: 'yes', note: 'Self-hosting available' },
    notes: { v: 'yes' },
    tasks: { v: 'partial', note: 'Checklist note type, no unified view' },
    journal: { v: 'no' },
    vault: { v: 'partial', note: '2FA tokens, not a password vault' },
    files: { v: 'paid', note: 'Files need a paid plan' },
    burn: { v: 'no' },
    markdown: { v: 'paid', note: 'Typing basic markdown works; the markdown editor with preview needs Productivity' },
    'md-on-disk': { v: 'no' },
    history: { v: 'partial', note: 'Days on the free tier, extended history is paid' },
    'pin-protect': { v: 'partial', note: 'Behind app passcode re-entry' },
    offline: { v: 'yes' },
    platforms: { v: 'yes' },
    'no-subscription': { v: 'no', note: 'Productivity ~$90/yr, Professional ~$120/yr' },
    'free-tier': { v: 'partial', note: 'Plain-text notes and sync' },
    export: { v: 'yes', note: 'Decrypted backup export' },
  },
  wins: {
    kicker: 'Credit where due',
    h2: 'Where Standard Notes genuinely wins',
    lead: 'A comparison page you can trust has to be able to say this part out loud. Three things they do that we do not, today:',
    items: [
      {
        title: 'Audits and longevity',
        body: 'Four independent security audits on the record and a ten-year longevity pledge. Our encryption layer is published and checkable by anyone, but an independent audit is a real credential we do not have yet.',
      },
      {
        title: 'The whole stack is open source',
        body: 'Clients and server, with self-hosting for people who want to run their own sync. Our clients, encryption layer, schema and threat model are published, and this row is still theirs.',
      },
      {
        title: 'More note types',
        body: 'Spreadsheets, code editors, a built-in 2FA authenticator: notes that are little apps. Deliberately not our direction, markdown is. If your workflow leans on those, stay.',
      },
    ],
  },
  model: {
    kicker: 'Same crypto class, different model',
    h2: 'Both encrypt. Almost everything else differs.',
    lead: 'Once two apps both encrypt end-to-end, the comparison moves to what you hand over, what the free tier really is, and what the price buys.',
    us: [
      { dt: 'Identity', dd: 'A 12-word phrase. Optional Google, Apple, or GitHub sign-in, same encryption either way.' },
      { dt: 'Free tier', dd: 'The whole app, smaller. All seven pillars including markdown, 2 devices, files to 5 MB.' },
      { dt: 'Paying', dd: '{price} once: unlimited devices, note history, PIN-protect, 500 MB of encrypted files.' },
      { dt: 'Keys', dd: 'Derived from your phrase on your device. XChaCha20-Poly1305 per note.' },
    ],
    them: [
      { dt: 'Identity', dd: 'Email + password account, standard signup.' },
      { dt: 'Free tier', dd: 'Plain-text notes and sync on unlimited devices. Solid, but the editors that make it pleasant are paid.' },
      { dt: 'Paying', dd: 'Roughly $90 per year, every year, for the editors, files and extended history.' },
      { dt: 'Keys', dd: 'Derived from your account password. Sound design, well documented and audited.' },
    ],
  },
  price: {
    kicker: 'The three-year math',
    h2: 'Their year one costs more than our lifetime',
    lead: 'Subscriptions are a fine model; we just do not use one. Here is the same three years, side by side.',
    theirLabel: 'Standard Notes Productivity',
    theirPerYear: 90,
    note: 'Prices as listed on each site, August 2026. Standard Notes bills yearly on the Productivity plan; Professional is ~$120/yr; regional prices vary. If these numbers drift, the fact-checked date at the top is the tell. Spotted something out of date? Tell us and we fix it.',
  },
  switching: {
    kicker: 'Switching',
    h2: 'Move your notes in about five minutes',
    lead: 'PrivacyNotes reads the official Standard Notes backup directly. Export, drop the zip in, and your notes are re-encrypted under your own phrase.',
    steps: [
      'Open Standard Notes (app.standardnotes.com or the desktop app) and sign in.',
      'Open Preferences, then Backups.',
      'Download a data backup and pick the decrypted format when asked.',
      'In PrivacyNotes: Settings, Import and Export, drop the whole .zip in.',
      'Delete the decrypted export. It contains your notes in plain text.',
    ],
    trap: {
      title: 'The one trap',
      body: 'The encrypted backup variant cannot be imported: it is ciphertext only your Standard Notes password can open. If you grabbed the wrong one, export again and choose decrypted. And because that file is your notes in plain text, delete it once the import is done.',
    },
    guideId: 'standard-notes',
    comes: [
      { label: 'Notes and text', ok: true },
      { label: 'Tags', ok: true },
      { label: 'Archived notes', ok: true },
      { label: 'Note types flatten to markdown', ok: false },
      { label: '2FA tokens: move to an authenticator', ok: false },
    ],
  },
  faqIntro: { kicker: 'Questions', h2: 'Fair questions, straight answers' },
  faq: [
    {
      q: 'Standard Notes is also end-to-end encrypted. Why switch at all?',
      a: 'Because the crypto is where the similarity ends. Day to day you feel the rest: markdown on the free tier instead of behind a plan, a journal and vault built in instead of two more apps, no email address anywhere, and {price} once instead of roughly $90 a year. If none of that moves you, Standard Notes remains a good home.',
    },
    {
      q: 'Is Standard Notes bad now that Proton owns it?',
      a: 'No. The 2024 Proton acquisition put it inside a larger privacy company, and the app remains well built and separately priced. It does mean the subscription model is here to stay. If you would rather pay once to an independent developer, that is us; it is a preference, not an indictment.',
    },
    {
      q: 'What happens to my note types and tags when I import?',
      a: 'Tags come across as tags. Plain and markdown notes import cleanly; rich text, spreadsheet and code notes flatten to markdown text. TokenVault 2FA secrets should move to a dedicated authenticator app, not a notes importer.',
    },
    {
      q: 'Is Standard Notes free?',
      a: 'Yes, genuinely: unlimited plain-text notes, synced and encrypted, on the free tier. What costs ~$90 a year is everything that makes daily writing pleasant: the markdown editor with preview, rich text, files and extended history. That gap is what this page is about.',
    },
    'verify-encryption',
    'export-leave',
  ],
  band: {
    h2: 'Try both. Ours takes one click.',
    sub: 'The demo runs in your browser with example notes, saves nothing, and asks for nothing. Kick the tires, then import your real notes if it fits.',
    cta: 'Open the demo',
    micro: 'Free forever. No credit card. No email needed.',
  },
  sticky: { text: '{price} once vs $90 every year.', cta: 'Try the demo' },
  mesh: {
    features: ['markdown-editor'],
    guides: ['standard-notes', 'evernote', 'obsidian'],
  },
};
